//! End-to-end public-API test: generate, share, verify, back up, restore.

use p2p_identity::{ContactPayload, EncryptedIdentity, Identity, IdentityRole};

#[test]
fn two_installations_can_exchange_and_verify_a_contact_without_infrastructure() {
    let alice = Identity::generate().expect("alice identity");
    let bob = Identity::generate().expect("bob identity");

    let alice_qr = ContactPayload::new(
        alice.peer_id(),
        alice.public_key().clone(),
        Some("Alice".to_owned()),
    )
    .expect("alice payload");
    let bob_qr =
        ContactPayload::new(bob.peer_id(), bob.public_key().clone(), None).expect("bob payload");

    let parsed_alice = ContactPayload::parse(&alice_qr.encode()).expect("parse alice");
    let parsed_bob = ContactPayload::parse(&bob_qr.encode()).expect("parse bob");

    assert_eq!(
        parsed_alice.fingerprint().expect("alice fingerprint"),
        *alice.fingerprint()
    );
    assert_eq!(
        parsed_bob.fingerprint().expect("bob fingerprint"),
        *bob.fingerprint()
    );
    assert_ne!(parsed_alice.peer_id, parsed_bob.peer_id);

    let signature = alice.sign(b"hello bob").expect("sign");
    assert!(parsed_alice.public_key.verify(b"hello bob", &signature));
    assert!(!parsed_bob.public_key.verify(b"hello bob", &signature));
}

#[test]
fn encrypted_export_restores_the_exact_same_peer_identity() {
    let original = Identity::generate().expect("identity");
    let backup = EncryptedIdentity::encrypt(&original, "backup passphrase").expect("encrypt");
    let restored = EncryptedIdentity::from_bytes(backup.as_bytes())
        .expect("validate")
        .decrypt("backup passphrase")
        .expect("decrypt");

    assert_eq!(restored.peer_id(), original.peer_id());
    assert_eq!(restored.public_key_bytes(), original.public_key_bytes());
    assert_eq!(restored.fingerprint(), original.fingerprint());
}

#[test]
fn independent_devices_keep_separate_keys_but_portable_export_preserves_a_bundle() {
    let first = Identity::generate().expect("first device");
    let second = Identity::generate().expect("second device");
    assert_ne!(
        first
            .role_public_bytes(IdentityRole::Device)
            .expect("first device key"),
        second
            .role_public_bytes(IdentityRole::Device)
            .expect("second device key")
    );

    let backup = EncryptedIdentity::encrypt(&first, "device backup").expect("encrypt");
    let restored = EncryptedIdentity::from_bytes(backup.as_bytes())
        .expect("validate")
        .decrypt("device backup")
        .expect("decrypt");
    for role in IdentityRole::ALL {
        assert_eq!(
            first.role_public_bytes(role).expect("source role key"),
            restored.role_public_bytes(role).expect("restored role key"),
        );
    }
}
