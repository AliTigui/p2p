//! Adversarial acceptance tests for the bound channel-group lifecycle API.
//!
//! A caller must name both the parent conversation and the logical channel
//! before it can create, add to, or join a channel MLS group. KeyPackages and
//! Welcomes carry that binding; commits are still checked against the derived
//! MLS group ID, sender credential, epoch, and operation.

#![forbid(unsafe_code)]

use p2p_groups::{
    ChannelGroupBinding, GroupError, GroupOperation, MlsChannelGroup, MlsConversation,
    channel_group_id,
};
use p2p_identity::{Identity, IdentityRole};
use p2p_messaging::{Envelope, EnvelopeParams, MessageKind};

fn mls_key(identity: &Identity) -> Vec<u8> {
    identity
        .role_public_bytes(IdentityRole::Mls)
        .expect("certified MLS role key")
        .to_vec()
}

const PARENT_ID: [u8; 16] = [0x11; 16];
const CHANNEL_ID: [u8; 16] = [0x22; 16];
const PLAINTEXT: &[u8] = b"channel lifecycle plaintext stays inside the channel group";

fn binding() -> ChannelGroupBinding {
    ChannelGroupBinding::new(PARENT_ID, CHANNEL_ID)
}

fn pair() -> (
    Identity,
    Identity,
    ChannelGroupBinding,
    MlsChannelGroup,
    MlsChannelGroup,
) {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let binding = binding();

    let mut alice = MlsChannelGroup::create(&alice_identity, binding).expect("alice channel group");
    let bob_key_package =
        MlsChannelGroup::key_package(&bob_identity, binding).expect("bob channel key package");
    let (welcome, _commit) = alice
        .add_member_parts(
            &bob_key_package,
            bob_identity.peer_id(),
            &mls_key(&bob_identity),
        )
        .expect("alice adds bob to channel group");
    let bob = MlsChannelGroup::join(&bob_identity, binding, bob_key_package, &welcome)
        .expect("bob joins channel group");

    assert_eq!(alice.binding(), binding);
    assert_eq!(bob.binding(), binding);
    assert_eq!(alice.id(), binding.group_id());
    assert_eq!(bob.id(), binding.group_id());
    assert_ne!(alice.id(), alice.parent_conversation_id());
    assert_eq!(alice.epoch(), bob.epoch());
    (alice_identity, bob_identity, binding, alice, bob)
}

#[test]
fn binding_derives_and_exposes_the_explicit_group_context() {
    let binding = binding();

    assert_eq!(binding.parent_conversation_id(), PARENT_ID);
    assert_eq!(binding.channel_id(), CHANNEL_ID);
    assert_eq!(binding.group_id(), channel_group_id(PARENT_ID, CHANNEL_ID));
    assert_ne!(binding.group_id(), PARENT_ID);
    assert_ne!(binding.group_id(), CHANNEL_ID);
}

#[test]
fn key_package_with_wrong_parent_or_channel_is_rejected_on_add() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = MlsChannelGroup::create(&alice_identity, binding()).expect("alice channel");

    let wrong_parent = ChannelGroupBinding::new([0x33; 16], CHANNEL_ID);
    let wrong_channel = ChannelGroupBinding::new(PARENT_ID, [0x44; 16]);
    for wrong_binding in [wrong_parent, wrong_channel] {
        let package = MlsChannelGroup::key_package(&bob_identity, wrong_binding)
            .expect("key package declared for a different binding");
        let error = alice
            .add_member(&package, bob_identity.peer_id(), &mls_key(&bob_identity))
            .expect_err("wrong binding must not be added to this channel group");
        assert!(matches!(error, GroupError::WrongChannelBinding));
    }
}

#[test]
fn welcome_with_wrong_parent_or_channel_is_rejected_on_join() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let correct = binding();
    let wrong_parent = ChannelGroupBinding::new([0x33; 16], CHANNEL_ID);
    let wrong_channel = ChannelGroupBinding::new(PARENT_ID, [0x44; 16]);

    let mut alice = MlsChannelGroup::create(&alice_identity, correct).expect("alice channel");
    let correct_package = MlsChannelGroup::key_package(&bob_identity, correct)
        .expect("package declared for correct binding");
    let (correct_welcome, _commit) = alice
        .add_member_parts(
            &correct_package,
            bob_identity.peer_id(),
            &mls_key(&bob_identity),
        )
        .expect("welcome for correct binding");

    let wrong_package = MlsChannelGroup::key_package(&bob_identity, wrong_parent)
        .expect("package declared for wrong parent");
    let error = MlsChannelGroup::join(&bob_identity, wrong_parent, wrong_package, &correct_welcome)
        .expect_err("wrong-parent join must be rejected");
    assert!(matches!(error, GroupError::WrongChannelBinding));

    let wrong_package = MlsChannelGroup::key_package(&bob_identity, wrong_channel)
        .expect("package declared for wrong channel");
    let error = MlsChannelGroup::join(
        &bob_identity,
        wrong_channel,
        wrong_package,
        &correct_welcome,
    )
    .expect_err("wrong-channel join must be rejected");
    assert!(matches!(error, GroupError::WrongChannelBinding));
}

#[test]
fn bound_channel_group_applies_authorized_add_update_and_remove_commits() {
    let (alice_identity, bob_identity, _binding, mut alice, mut bob) = pair();
    let expected_members = {
        let mut members = vec![alice_identity.peer_id(), bob_identity.peer_id()];
        members.sort();
        members
    };
    assert_eq!(alice.members().expect("alice members"), expected_members);
    assert_eq!(bob.members().expect("bob members"), expected_members);

    let before_update = alice.epoch();
    let update_commit = alice.self_update_commit().expect("alice update commit");
    let update_outcome = bob
        .process_commit(
            &update_commit,
            &alice_identity.peer_id(),
            &mls_key(&alice_identity),
            GroupOperation::Update,
            None,
        )
        .expect("bob applies update commit");
    assert!(!update_outcome.self_removed);
    assert_eq!(alice.epoch(), before_update + 1);
    assert_eq!(bob.epoch(), before_update + 1);

    let envelope = alice
        .compose(&alice_identity, MessageKind::Channel, PLAINTEXT)
        .expect("alice composes channel ciphertext");
    assert_eq!(envelope.conversation_id, alice.id());
    let received = bob
        .receive(envelope)
        .expect("bob decrypts channel ciphertext");
    assert_eq!(received.plaintext.as_slice(), PLAINTEXT);

    let remove_commit = alice
        .remove_member(&bob_identity.peer_id())
        .expect("alice removes bob");
    let remove_outcome = bob
        .process_commit(
            &remove_commit,
            &alice_identity.peer_id(),
            &mls_key(&alice_identity),
            GroupOperation::Remove,
            Some(bob_identity.peer_id()),
        )
        .expect("bob applies remove commit");
    assert!(remove_outcome.self_removed);
    assert_eq!(
        alice.members().expect("remaining channel members"),
        vec![alice_identity.peer_id()]
    );

    let after_removal = alice
        .compose(&alice_identity, MessageKind::Channel, PLAINTEXT)
        .expect("alice composes after removal");
    assert!(
        bob.receive(after_removal).is_err(),
        "removed channel member must not decrypt the new channel epoch"
    );
}

#[test]
fn commit_with_a_wrong_sender_is_rejected() {
    let (_alice_identity, _bob_identity, _binding, mut alice, mut bob) = pair();
    let mallory = Identity::generate().expect("mallory identity");
    let commit = alice.self_update_commit().expect("alice update commit");

    let error = bob
        .process_commit(
            &commit,
            &mallory.peer_id(),
            &mls_key(&mallory),
            GroupOperation::Update,
            None,
        )
        .expect_err("wrong sender must not apply a channel commit");
    assert!(matches!(error, GroupError::SenderMismatch));
}

#[test]
fn parent_group_ciphertext_is_rejected_by_the_channel_group() {
    let parent_identity = Identity::generate().expect("parent identity");
    let mut parent = MlsConversation::new(&parent_identity).expect("parent conversation");
    let binding = ChannelGroupBinding::new(parent.id(), CHANNEL_ID);
    let mut channel = MlsChannelGroup::create(&parent_identity, binding).expect("channel group");

    let parent_envelope = parent
        .compose(&parent_identity, MessageKind::Channel, PLAINTEXT)
        .expect("parent ciphertext");
    let relabelled = Envelope::new(
        &parent_identity,
        EnvelopeParams {
            conversation_id: channel.id(),
            epoch: parent_envelope.epoch,
            message_id: parent_envelope.message_id,
            sender_sequence: parent_envelope.sender_sequence,
            created_at: parent_envelope.created_at,
            kind: parent_envelope.kind,
        },
        parent_envelope.payload,
    )
    .expect("re-sign parent ciphertext under channel group id");

    assert!(
        channel.receive(relabelled).is_err(),
        "parent MLS ciphertext must not be accepted as channel ciphertext"
    );
}
