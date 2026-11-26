//! Acceptance tests for real OpenMLS payload encryption in signed envelopes.

#![forbid(unsafe_code)]

use p2p_groups::{GroupError, GroupOperation, MlsConversation};
use p2p_identity::Identity;
use p2p_messaging::{DeliveryState, Envelope, EnvelopeParams, MessageKind, Receipt, ReceiptStatus};

fn pair() -> (Identity, Identity, MlsConversation, MlsConversation) {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");

    let mut alice = MlsConversation::new(&alice_identity).expect("alice MLS conversation");
    let key_package = MlsConversation::key_package(&bob_identity).expect("bob key package");
    let welcome = alice
        .add_member(
            key_package.bytes(),
            bob_identity.peer_id(),
            &bob_identity.public_key_bytes(),
        )
        .expect("add bob");
    let bob =
        MlsConversation::join(&bob_identity, alice.id(), key_package, &welcome).expect("bob join");

    assert_eq!(alice.id(), bob.id());
    assert_eq!(alice.epoch(), bob.epoch());
    (alice_identity, bob_identity, alice, bob)
}

#[test]
fn join_rejects_an_identity_that_does_not_own_the_key_package() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mallory_identity = Identity::generate().expect("mallory identity");
    let mut alice = MlsConversation::new(&alice_identity).expect("alice MLS conversation");
    let key_package = MlsConversation::key_package(&bob_identity).expect("bob key package");
    let welcome = alice
        .add_member(
            key_package.bytes(),
            bob_identity.peer_id(),
            &bob_identity.public_key_bytes(),
        )
        .expect("add bob");

    let error = MlsConversation::join(&mallory_identity, alice.id(), key_package, &welcome)
        .expect_err("mallory must not join with bob's key package");
    assert!(matches!(error, GroupError::WrongLocalIdentity));
}

#[test]
fn two_member_group_encrypts_application_text() {
    let (alice_identity, _bob_identity, mut alice, mut bob) = pair();
    let plaintext = b"message plaintext must never appear on the wire";

    let envelope = alice
        .compose(&alice_identity, MessageKind::Text, plaintext)
        .expect("compose encrypted text");
    assert_ne!(envelope.payload.as_slice(), plaintext.as_slice());
    assert!(
        !envelope
            .payload
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );

    let decrypted = bob.receive(envelope).expect("decrypt encrypted text");
    assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
    assert_eq!(decrypted.metadata.sender, alice_identity.peer_id());
    assert_eq!(decrypted.metadata.receipt, None);
}

#[test]
fn encrypted_receipt_is_the_only_thing_that_advances_delivery_state() {
    let (alice_identity, bob_identity, mut alice, mut bob) = pair();
    let outgoing = alice
        .compose(&alice_identity, MessageKind::Text, b"deliver me")
        .expect("compose outgoing");
    let outgoing_id = outgoing.message_id;
    alice
        .mark_sent_to_peer(&outgoing_id)
        .expect("mark sent to peer");
    assert_eq!(
        alice.delivery_state(&outgoing_id),
        Some(DeliveryState::SentToPeer)
    );

    let received = bob.receive(outgoing).expect("bob decrypts text");
    assert_eq!(received.plaintext.as_slice(), b"deliver me");

    let receipt = Receipt::new(ReceiptStatus::Delivered, outgoing_id);
    let receipt_envelope = bob
        .receipt(&bob_identity, ReceiptStatus::Delivered, outgoing_id)
        .expect("compose encrypted receipt");
    let receipt_body = receipt.to_bytes();
    assert!(
        !receipt_envelope
            .payload
            .windows(receipt_body.len())
            .any(|window| window == receipt_body)
    );

    let verified = alice
        .receive(receipt_envelope)
        .expect("alice decrypts receipt");
    assert_eq!(verified.metadata.receipt, Some(receipt));
    assert_eq!(
        alice.delivery_state(&outgoing_id),
        Some(DeliveryState::Delivered)
    );
}

#[test]
fn resigned_tampered_ciphertext_is_rejected_by_mls() {
    let (alice_identity, _bob_identity, mut alice, mut bob) = pair();
    let original = alice
        .compose(
            &alice_identity,
            MessageKind::Text,
            b"authentic application body",
        )
        .expect("compose outgoing");

    let mut tampered_payload = original.payload.clone();
    let last = tampered_payload
        .last_mut()
        .expect("MLS ciphertext is not empty");
    *last ^= 0x01;

    // Re-sign the modified payload so the outer envelope signature is valid.
    // This isolates MLS ciphertext integrity from envelope authenticity.
    let tampered = Envelope::new(
        &alice_identity,
        EnvelopeParams {
            conversation_id: original.conversation_id,
            epoch: original.epoch,
            message_id: original.message_id,
            sender_sequence: original.sender_sequence,
            created_at: original.created_at,
            kind: original.kind,
        },
        tampered_payload,
    )
    .expect("sign tampered ciphertext");

    assert!(bob.receive(tampered).is_err());
}

#[test]
fn valid_sender_envelope_with_a_different_mls_credential_is_rejected() {
    let (alice_identity, _bob_identity, mut alice, mut bob) = pair();
    let mallory = Identity::generate().expect("mallory identity");
    let outgoing = alice
        .compose(&alice_identity, MessageKind::Text, b"bob-only plaintext")
        .expect("compose outgoing");

    let forged = Envelope::new(
        &mallory,
        EnvelopeParams {
            conversation_id: outgoing.conversation_id,
            epoch: outgoing.epoch,
            message_id: [99u8; 16],
            sender_sequence: 1,
            created_at: outgoing.created_at,
            kind: outgoing.kind,
        },
        outgoing.payload,
    )
    .expect("mallory signs alice ciphertext");

    assert!(matches!(
        bob.receive(forged),
        Err(GroupError::SenderMismatch)
    ));
}

#[test]
fn adding_a_member_rejects_a_mismatched_public_key() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mallory_identity = Identity::generate().expect("mallory identity");
    let mut alice = MlsConversation::new(&alice_identity).expect("alice conversation");
    let key_package = MlsConversation::key_package(&bob_identity).expect("bob key package");

    let error = alice
        .add_member(
            key_package.bytes(),
            bob_identity.peer_id(),
            &mallory_identity.public_key_bytes(),
        )
        .expect_err("mismatched public key must be rejected");
    assert!(matches!(error, GroupError::SenderMismatch));
}

struct Trio {
    alice_identity: Identity,
    bob_identity: Identity,
    charlie_identity: Identity,
    alice: MlsConversation,
    bob: MlsConversation,
    charlie: MlsConversation,
}

fn trio() -> Trio {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let charlie_identity = Identity::generate().expect("charlie identity");

    let mut alice = MlsConversation::new(&alice_identity).expect("alice conversation");
    let bob_package = MlsConversation::key_package(&bob_identity).expect("bob key package");
    let (bob_welcome, _bob_commit) = alice
        .add_member_parts(
            bob_package.bytes(),
            bob_identity.peer_id(),
            &bob_identity.public_key_bytes(),
        )
        .expect("alice adds bob");
    let mut bob = MlsConversation::join(&bob_identity, alice.id(), bob_package, &bob_welcome)
        .expect("bob joins");

    let charlie_package =
        MlsConversation::key_package(&charlie_identity).expect("charlie key package");
    let (charlie_welcome, add_commit) = alice
        .add_member_parts(
            charlie_package.bytes(),
            charlie_identity.peer_id(),
            &charlie_identity.public_key_bytes(),
        )
        .expect("alice adds charlie");
    let outcome = bob
        .process_commit(
            &add_commit,
            &alice_identity.peer_id(),
            &alice_identity.public_key_bytes(),
            GroupOperation::Add,
            Some(charlie_identity.peer_id()),
        )
        .expect("bob applies add commit");
    assert!(!outcome.self_removed);
    let charlie = MlsConversation::join(
        &charlie_identity,
        alice.id(),
        charlie_package,
        &charlie_welcome,
    )
    .expect("charlie joins");

    assert_eq!(alice.epoch(), bob.epoch());
    assert_eq!(bob.epoch(), charlie.epoch());
    Trio {
        alice_identity,
        bob_identity,
        charlie_identity,
        alice,
        bob,
        charlie,
    }
}

#[test]
fn three_member_group_applies_authorized_remove_and_excludes_removed_member() {
    let Trio {
        alice_identity,
        bob_identity,
        charlie_identity,
        mut alice,
        mut bob,
        mut charlie,
    } = trio();

    let commit = alice
        .remove_member(&charlie_identity.peer_id())
        .expect("alice removes charlie");
    let outcome = bob
        .process_commit(
            &commit,
            &alice_identity.peer_id(),
            &alice_identity.public_key_bytes(),
            GroupOperation::Remove,
            Some(charlie_identity.peer_id()),
        )
        .expect("bob applies remove commit");
    assert!(!outcome.self_removed);
    assert_eq!(alice.epoch(), bob.epoch());
    assert_ne!(alice.epoch(), charlie.epoch());
    assert!(
        !bob.members()
            .expect("bob members")
            .contains(&charlie_identity.peer_id())
    );

    let envelope = alice
        .compose(
            &alice_identity,
            MessageKind::Text,
            b"remaining members only",
        )
        .expect("alice composes after removal");
    bob.receive(envelope.clone()).expect("bob still decrypts");
    assert!(
        charlie.receive(envelope).is_err(),
        "removed member must not decrypt the new epoch"
    );
    let mut expected = vec![alice_identity.peer_id(), bob_identity.peer_id()];
    expected.sort();
    assert_eq!(alice.members().expect("alice members"), expected);
}

#[test]
fn three_member_group_applies_authorized_self_update() {
    let Trio {
        alice_identity,
        mut alice,
        mut bob,
        charlie: mut charlie_conversation,
        charlie_identity,
        ..
    } = trio();

    let before = alice.epoch();
    let commit = alice.self_update_commit().expect("alice self update");
    let bob_outcome = bob
        .process_commit(
            &commit,
            &alice_identity.peer_id(),
            &alice_identity.public_key_bytes(),
            GroupOperation::Update,
            None,
        )
        .expect("bob applies update commit");
    let charlie_outcome = charlie_conversation
        .process_commit(
            &commit,
            &alice_identity.peer_id(),
            &alice_identity.public_key_bytes(),
            GroupOperation::Update,
            None,
        )
        .expect("charlie applies update commit");
    assert_eq!(alice.epoch(), before + 1);
    assert_eq!(alice.epoch(), bob_outcome.epoch);
    assert_eq!(alice.epoch(), charlie_outcome.epoch);
    assert_eq!(bob.members().expect("bob members").len(), 3);
    assert_eq!(
        charlie_conversation
            .members()
            .expect("charlie members")
            .len(),
        3
    );
    assert!(charlie_identity.peer_id() == charlie_conversation.local_peer_id());
}

#[test]
fn commit_with_a_different_declared_operation_is_rejected() {
    let Trio {
        alice_identity,
        mut alice,
        mut bob,
        ..
    } = trio();
    let dave = Identity::generate().expect("dave identity");
    let dave_package = MlsConversation::key_package(&dave).expect("dave key package");
    let (_, add_commit) = alice
        .add_member_parts(
            dave_package.bytes(),
            dave.peer_id(),
            &dave.public_key_bytes(),
        )
        .expect("alice adds dave");

    let error = bob
        .process_commit(
            &add_commit,
            &alice_identity.peer_id(),
            &alice_identity.public_key_bytes(),
            GroupOperation::Remove,
            Some(dave.peer_id()),
        )
        .expect_err("declared operation must match the MLS commit");
    assert!(matches!(error, GroupError::UnexpectedCommit));
}
