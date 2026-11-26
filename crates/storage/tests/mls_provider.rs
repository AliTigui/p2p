//! Integration tests for the staged, vault-backed OpenMLS `StorageProvider`
//! adapter (ADR-0014 Phase 3). These exercise staged reads, discard, atomic
//! flush with anchor advancement, bounds rejection, and a real
//! `MlsGroup::new_with_group_id` / `MlsGroup::load` round trip.

use std::fmt;

use openmls::prelude::*;
use openmls::treesync::TreeSync;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::storage::StorageProvider;
use openmls_traits::types::SignatureScheme;
use p2p_identity::Identity;
use p2p_storage::{MlsProviderError, StagedMlsProvider, Vault};

const USERNAME: &str = "MLS_PROVIDER_USER_42";
const PASSWORD: &str = "MLS_PROVIDER_PASSWORD_99";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Signer backed by the device-specific Ed25519 identity, mirroring the
/// application's group layer.
#[derive(Clone)]
struct TestSigner(Identity);

impl Signer for TestSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.0.sign(payload).map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl fmt::Debug for TestSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TestSigner").field(&"<redacted>").finish()
    }
}

/// OpenMLS provider combining the pinned RustCrypto implementation with the
/// vault-backed staged storage adapter.
struct TestProvider {
    crypto: RustCrypto,
    storage: StagedMlsProvider,
}

impl TestProvider {
    fn new(session: p2p_storage::Session) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: StagedMlsProvider::new(session),
        }
    }
}

impl OpenMlsProvider for TestProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = StagedMlsProvider;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn group_id(byte: u8) -> GroupId {
    GroupId::from_slice(&[byte; 16])
}

fn create_group(provider: &TestProvider, identity: &Identity, id: GroupId) -> MlsGroup {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.peer_id().to_bytes()).into(),
        signature_key: identity
            .ed25519_public_bytes()
            .expect("ed25519 public key")
            .to_vec()
            .into(),
    };
    MlsGroup::new_with_group_id(
        provider,
        &TestSigner(identity.clone()),
        &config,
        id,
        credential,
    )
    .expect("create group with vault provider")
}

#[test]
fn staged_writes_are_visible_to_reads_and_discard_leaves_vault_unchanged() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create vault");
    let provider = TestProvider::new(session);
    let id = group_id(31);

    let _group = create_group(&provider, &identity, id.clone());
    assert!(provider.storage().staged_len() > 0);
    assert!(
        provider
            .storage()
            .tree::<GroupId, TreeSync>(&id)
            .expect("staged tree read")
            .is_some(),
        "a staged write must be visible to a later read in the same operation"
    );

    provider.storage().discard();
    assert_eq!(provider.storage().staged_len(), 0);
    assert!(
        provider
            .storage()
            .tree::<GroupId, TreeSync>(&id)
            .expect("empty read")
            .is_none()
    );

    drop(provider);
    let reopened = vault.unlock(PASSWORD).expect("unlock after discard");
    assert!(
        reopened
            .mls_group_ids()
            .expect("no persisted groups")
            .is_empty(),
        "discarded staging must not create a group row"
    );
    reopened.verify_mls_state().expect("empty state verifies");
}

#[test]
fn discard_clears_group_epoch_before_the_next_operation() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create vault");
    let provider = TestProvider::new(session);
    let id = group_id(33);

    let _discarded = create_group(&provider, &identity, id.clone());
    provider
        .storage()
        .set_group_epoch(&[33u8; 16], 7)
        .expect("set epoch");
    provider.storage().discard();

    let _committed = create_group(&provider, &identity, id.clone());
    assert!(provider.storage().staged_len() > 0);
    provider
        .storage()
        .flush()
        .expect("flush after discard clears the stale epoch");

    drop(provider);
    let reopened = vault.unlock(PASSWORD).expect("unlock after flush");
    let entries = reopened
        .load_mls_state_group(&[33u8; 16])
        .expect("persisted group state");
    assert!(!entries.is_empty(), "new operation staged real writes");
    assert!(
        entries.iter().all(|entry| entry.epoch == 0),
        "discard must clear the previous operation's epoch override"
    );
}

#[test]
fn flush_applies_every_staged_write_and_advances_the_anchor() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create vault");
    let provider = TestProvider::new(session);
    let id = group_id(41);

    let _group = create_group(&provider, &identity, id.clone());
    provider
        .storage()
        .set_group_epoch(&[41u8; 16], 4)
        .expect("set epoch");
    assert!(provider.storage().staged_len() > 1);

    provider.storage().flush().expect("flush staged set");
    assert_eq!(provider.storage().staged_len(), 0);

    drop(provider);
    let reopened = vault.unlock(PASSWORD).expect("unlock after flush");
    reopened
        .verify_mls_state()
        .expect("anchor verifies after flush");
    assert_eq!(
        reopened.mls_group_ids().expect("group ids"),
        vec![[41u8; 16]]
    );
    let entries = reopened
        .load_mls_state_group(&[41u8; 16])
        .expect("persisted group state");
    assert!(
        entries.len() > 1,
        "all staged values persisted in one flush"
    );
    assert!(
        entries.iter().all(|entry| entry.epoch == 4),
        "every staged value carries the explicit group epoch"
    );
}

#[test]
fn staged_tombstones_and_writes_flush_in_one_transaction() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create vault");
    let provider = TestProvider::new(session);
    let raw = [53u8; 16];
    let id = group_id(53);

    // Stage a value and a tombstone for distinct keys in one operation, plus a
    // tombstone for the same key that was just written (last write wins).
    provider
        .storage()
        .write_own_leaf_index(&id, &LeafNodeIndex::new(7))
        .expect("stage leaf index");
    provider
        .storage()
        .write_own_leaf_index(&group_id(54), &LeafNodeIndex::new(9))
        .expect("stage second value");
    provider
        .storage()
        .delete_own_leaf_index(&group_id(54))
        .expect("stage tombstone");
    provider.storage().flush().expect("flush mixed set");

    drop(provider);
    let reopened = vault.unlock(PASSWORD).expect("unlock");
    assert_eq!(reopened.mls_group_ids().expect("group ids"), vec![raw]);
    let entries = reopened
        .load_mls_state_group(&raw)
        .expect("persisted group state");
    assert_eq!(
        entries.len(),
        1,
        "the tombstone removed the competing value"
    );
}

#[test]
fn unsupported_group_ids_are_rejected_before_staging() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create vault");
    let provider = TestProvider::new(session);

    let short = GroupId::from_slice(&[3u8; 15]);
    assert!(matches!(
        provider
            .storage()
            .write_own_leaf_index(&short, &LeafNodeIndex::new(0)),
        Err(MlsProviderError::UnsupportedGroupId)
    ));

    let reserved = GroupId::from_slice(b"P2PMLSGLOBALROOT");
    assert!(matches!(
        provider
            .storage()
            .write_own_leaf_index(&reserved, &LeafNodeIndex::new(0)),
        Err(MlsProviderError::UnsupportedGroupId)
    ));

    assert_eq!(provider.storage().staged_len(), 0);
    provider.storage().flush().expect("empty flush is a no-op");
}

#[test]
fn mls_group_loads_from_the_vault_after_reopen() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let id = group_id(61);

    {
        let session = vault
            .create(USERNAME, PASSWORD, &identity)
            .expect("create vault");
        let provider = TestProvider::new(session);
        let group = create_group(&provider, &identity, id.clone());
        assert_eq!(group.group_id(), &id);
        provider.storage().flush().expect("persist group");
    }

    let reopened = vault.unlock(PASSWORD).expect("unlock after restart");
    reopened.verify_mls_state().expect("anchor verifies");
    let restored = TestProvider::new(reopened);
    let loaded = MlsGroup::load(restored.storage(), &id).expect("load group");
    let loaded = loaded.expect("group was persisted");
    assert_eq!(loaded.group_id(), &id);
}
