//! Integration tests for authenticated envelopes persisted in the vault.

use std::fs;

use libp2p_identity::PeerId;
use p2p_identity::Identity;
use p2p_messaging::{Conversation, Envelope, EnvelopeParams, MessageKind};
use p2p_storage::Vault;

const USERNAME: &str = "MESSAGE_USER";
const PASSWORD: &str = "MESSAGE_PASSWORD";
const PAYLOAD: &[u8] = b"SECRET_MESSAGE_BODY_SENTINEL";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_no_plaintext(directory: &std::path::Path) {
    for name in ["profile.db", "profile.db-wal", "profile.db-shm"] {
        let bytes = fs::read(directory.join(name)).unwrap_or_default();
        assert!(
            !contains(&bytes, PAYLOAD),
            "{name} contains a plaintext message payload"
        );
    }
}

#[test]
fn envelopes_persist_as_ciphertext_and_rebuild_conversation_state() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("vault");
    let local = Identity::generate().expect("local identity");
    let remote = Identity::generate().expect("remote identity");
    let conversation_id = [11u8; 16];

    {
        let session = vault
            .create(USERNAME, PASSWORD, &local)
            .expect("create vault");
        let mut conversation = Conversation::with_id(local.peer_id(), conversation_id);

        let outgoing = conversation
            .compose(&local, MessageKind::Text, PAYLOAD.to_vec())
            .expect("compose outgoing");
        conversation
            .persist(&session, &outgoing)
            .expect("persist outgoing");

        let incoming = Envelope::new(
            &remote,
            EnvelopeParams {
                conversation_id,
                epoch: 0,
                message_id: [12u8; 16],
                sender_sequence: 1,
                created_at: 1_700_000_000,
                kind: MessageKind::Text,
            },
            PAYLOAD.to_vec(),
        )
        .expect("signed incoming envelope");
        conversation
            .receive(incoming.clone())
            .expect("verify and receive incoming");
        conversation
            .persist(&session, &incoming)
            .expect("persist incoming");
    }

    assert_no_plaintext(directory.path());

    let session = vault.unlock(PASSWORD).expect("unlock");
    let restored = Conversation::load(&session, conversation_id).expect("load conversation");
    assert_eq!(restored.id(), conversation_id);
    assert_eq!(restored.local_peer_id(), local.peer_id());
    assert_eq!(restored.incoming().len(), 1);
    assert_eq!(restored.incoming()[0].sender, remote.peer_id());
    assert_eq!(restored.incoming()[0].payload.as_slice(), PAYLOAD);
}

#[test]
fn another_vault_cannot_read_the_conversation() {
    let first_dir = tempfile::tempdir().expect("first dir");
    let second_dir = tempfile::tempdir().expect("second dir");
    let first_vault = Vault::open(first_dir.path()).expect("first vault");
    let second_vault = Vault::open(second_dir.path()).expect("second vault");
    let local = Identity::generate().expect("identity");
    let conversation_id = [21u8; 16];

    let session = first_vault
        .create(USERNAME, PASSWORD, &local)
        .expect("create first");
    let mut conversation = Conversation::with_id(local.peer_id(), conversation_id);
    let envelope = conversation
        .compose(&local, MessageKind::Text, PAYLOAD.to_vec())
        .expect("compose");
    conversation.persist(&session, &envelope).expect("persist");

    let other_identity = Identity::generate().expect("other identity");
    let other_session = second_vault
        .create(USERNAME, PASSWORD, &other_identity)
        .expect("create second");
    let restored = Conversation::load(&other_session, conversation_id).expect("load other vault");
    assert!(restored.incoming().is_empty());
}

#[test]
fn peer_id_is_public_and_redacted_debug_omits_payload() {
    let local = Identity::generate().expect("identity");
    let conversation = Conversation::with_id(local.peer_id(), [31u8; 16]);
    let debug = format!("{conversation:?}");
    assert!(!debug.contains("SECRET"));
    let peer: PeerId = conversation.local_peer_id();
    assert_eq!(peer.to_string(), local.peer_id().to_string());
}
