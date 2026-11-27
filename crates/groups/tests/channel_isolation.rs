//! Adversarial acceptance tests for cryptographically isolated channels.
//!
//! A logical channel must not inherit the parent conversation's MLS secrets.
//! These tests give the excluded member both the ciphertext and a locally
//! created group with the same derived group ID; without the Welcome and the
//! matching ratchet state, decryption must still fail.

#![forbid(unsafe_code)]

use p2p_groups::{GroupOperation, MlsConversation, channel_group_id};
use p2p_identity::{Identity, IdentityRole};
use p2p_messaging::MessageKind;

fn mls_key(identity: &Identity) -> Vec<u8> {
    identity
        .role_public_bytes(IdentityRole::Mls)
        .expect("certified MLS role key")
        .to_vec()
}

const CHANNEL_ID: [u8; 16] = [0x42; 16];
const SECRET: &[u8] = b"private channel plaintext must not leak to the parent group";

fn three_member_conversation() -> (
    Identity,
    Identity,
    Identity,
    MlsConversation,
    MlsConversation,
    MlsConversation,
) {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let charlie_identity = Identity::generate().expect("charlie identity");

    let mut alice = MlsConversation::new(&alice_identity).expect("alice conversation");
    let bob_package = MlsConversation::key_package(&bob_identity).expect("bob key package");
    let (bob_welcome, _bob_commit) = alice
        .add_member_parts(
            bob_package.bytes(),
            bob_identity.peer_id(),
            &mls_key(&bob_identity),
        )
        .expect("alice adds bob");
    let mut bob = MlsConversation::join(&bob_identity, alice.id(), bob_package, &bob_welcome)
        .expect("bob joins parent group");

    let charlie_package =
        MlsConversation::key_package(&charlie_identity).expect("charlie key package");
    let (charlie_welcome, add_commit) = alice
        .add_member_parts(
            charlie_package.bytes(),
            charlie_identity.peer_id(),
            &mls_key(&charlie_identity),
        )
        .expect("alice adds charlie");
    bob.process_commit(
        &add_commit,
        &alice_identity.peer_id(),
        &mls_key(&alice_identity),
        GroupOperation::Add,
        Some(charlie_identity.peer_id()),
    )
    .expect("bob applies add commit");
    let charlie = MlsConversation::join(
        &charlie_identity,
        alice.id(),
        charlie_package,
        &charlie_welcome,
    )
    .expect("charlie joins parent group");

    (
        alice_identity,
        bob_identity,
        charlie_identity,
        alice,
        bob,
        charlie,
    )
}

fn isolated_channel(
    alice_identity: &Identity,
    bob_identity: &Identity,
    parent_id: [u8; 16],
) -> (MlsConversation, MlsConversation, [u8; 16]) {
    let group_id = channel_group_id(parent_id, CHANNEL_ID);
    assert_ne!(group_id, parent_id);

    let mut alice_channel = MlsConversation::create(alice_identity, group_id)
        .expect("create independent channel group");
    let bob_package = MlsConversation::key_package(bob_identity).expect("bob channel key package");
    let (welcome, _commit) = alice_channel
        .add_member_parts(
            bob_package.bytes(),
            bob_identity.peer_id(),
            &mls_key(bob_identity),
        )
        .expect("add bob to channel group");
    let bob_channel = MlsConversation::join(bob_identity, group_id, bob_package, &welcome)
        .expect("bob joins channel group");

    assert_eq!(alice_channel.id(), group_id);
    assert_eq!(bob_channel.id(), group_id);
    (alice_channel, bob_channel, group_id)
}

#[test]
fn derived_channel_group_id_is_domain_separated() {
    let alice_identity = Identity::generate().expect("alice identity");
    let parent = MlsConversation::new(&alice_identity).expect("parent group");
    let group_id = channel_group_id(parent.id(), CHANNEL_ID);

    assert_ne!(group_id, parent.id());
    assert_ne!(group_id, [0u8; 16]);
    assert_ne!(
        channel_group_id(parent.id(), CHANNEL_ID),
        channel_group_id(CHANNEL_ID, parent.id())
    );
    assert_eq!(channel_group_id(parent.id(), CHANNEL_ID), group_id);
}

#[test]
fn excluded_member_cannot_decrypt_independent_channel_ciphertext() {
    let (
        alice_identity,
        bob_identity,
        charlie_identity,
        alice_parent,
        _bob_parent,
        mut charlie_parent,
    ) = three_member_conversation();
    let parent_id = alice_parent.id();
    let (mut alice_channel, mut bob_channel, group_id) =
        isolated_channel(&alice_identity, &bob_identity, parent_id);

    let envelope = alice_channel
        .compose(&alice_identity, MessageKind::Channel, SECRET)
        .expect("compose channel ciphertext");
    assert_eq!(envelope.conversation_id, group_id);
    assert_ne!(envelope.payload.as_slice(), SECRET);
    assert!(
        !envelope
            .payload
            .windows(SECRET.len())
            .any(|window| window == SECRET)
    );

    let allowed = bob_channel
        .receive(envelope.clone())
        .expect("channel member decrypts channel ciphertext");
    assert_eq!(allowed.plaintext.as_slice(), SECRET);

    // Charlie has the parent group's secrets and can obtain the ciphertext.
    assert!(charlie_parent.receive(envelope.clone()).is_err());

    // Even a locally created group with the same public ID has different
    // ratchet secrets without the Welcome, so it is not a decryption oracle.
    let mut charlie_fake = MlsConversation::create(&charlie_identity, group_id)
        .expect("charlie creates a group with the same id");
    assert!(
        charlie_fake.receive(envelope).is_err(),
        "excluded member must not decrypt channel ciphertext"
    );
}

#[test]
fn channel_key_update_does_not_grant_parent_group_access() {
    let (
        alice_identity,
        bob_identity,
        _charlie_identity,
        _alice_parent,
        _bob_parent,
        mut charlie_parent,
    ) = three_member_conversation();
    let parent_id = _alice_parent.id();
    let (mut alice_channel, mut bob_channel, group_id) =
        isolated_channel(&alice_identity, &bob_identity, parent_id);

    let before = alice_channel.epoch();
    let commit = alice_channel
        .self_update_commit()
        .expect("refresh channel epoch");
    bob_channel
        .process_commit(
            &commit,
            &alice_identity.peer_id(),
            &mls_key(&alice_identity),
            GroupOperation::Update,
            None,
        )
        .expect("bob applies channel update");
    assert_eq!(alice_channel.epoch(), before + 1);
    assert_eq!(bob_channel.epoch(), before + 1);

    let envelope = alice_channel
        .compose(&alice_identity, MessageKind::Channel, SECRET)
        .expect("compose after channel update");
    assert_eq!(envelope.conversation_id, group_id);
    assert!(charlie_parent.receive(envelope).is_err());
}
