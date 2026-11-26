//! OpenMLS-backed group encryption for P2P conversations.
//!
//! Every conversation is an MLS group, including a two-member 1:1 group. This
//! crate owns the MLS lifecycle and produces signed envelopes whose payloads
//! are MLS ciphertext. The default constructors keep group state memory-only;
//! the vault-backed constructors flush OpenMLS provider state to encrypted
//! storage and can restore a group through `MlsGroup::load` (ADR-0014 Phase 4).

#![forbid(unsafe_code)]

use std::fmt;

use libp2p_identity::{PeerId, PublicKey};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use p2p_identity::{Identity, raw_ed25519_public_bytes_from_protobuf};
use p2p_messaging::{Conversation, Envelope, MessageKind, Receipt, ReceiptStatus, ReceivedMessage};
use p2p_storage::{MlsProviderError, Session, StagedMlsProvider};
use thiserror::Error;
use zeroize::Zeroizing;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_GROUP_MESSAGE_BYTES: usize = 1024 * 1024;

/// Authorized MLS epoch-changing operations used by group management frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOperation {
    Add,
    Remove,
    Update,
}

impl GroupOperation {
    pub fn code(self) -> u8 {
        match self {
            Self::Add => 1,
            Self::Remove => 2,
            Self::Update => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Add),
            2 => Some(Self::Remove),
            3 => Some(Self::Update),
            _ => None,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Add => "member added",
            Self::Remove => "member removed",
            Self::Update => "member key updated",
        }
    }
}

/// Result of applying a verified MLS commit from another group member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    pub epoch: u64,
    pub self_removed: bool,
}

/// Errors from MLS setup, encryption, and decryption. Messages are static
/// categories; no key material, plaintext, or OpenMLS debug output is retained.
#[derive(Debug, Error)]
pub enum GroupError {
    #[error("MLS operation failed: {0}")]
    Mls(&'static str),
    #[error("MLS group message is {len} bytes (maximum {max})")]
    TooLarge { len: usize, max: usize },
    #[error("MLS application plaintext cannot be empty")]
    EmptyPlaintext,
    #[error("MLS group id does not match the conversation id")]
    WrongConversation,
    #[error("MLS group epoch does not match the envelope epoch")]
    EpochMismatch { expected: u64, actual: u64 },
    #[error("MLS sender credential does not match the envelope sender")]
    SenderMismatch,
    #[error("local identity does not own this MLS group")]
    WrongLocalIdentity,
    #[error("encrypted MLS group state is missing from the vault")]
    MlsStateMissing,
    #[error(transparent)]
    Storage(#[from] MlsProviderError),
    #[error("peer is not an active member of this MLS group")]
    NotMember,
    #[error("self-removal is not allowed by local policy")]
    SelfRemovalDenied,
    #[error("MLS commit did not contain the expected authorized operation")]
    UnexpectedCommit,
    #[error(transparent)]
    Identity(#[from] p2p_identity::IdentityError),
    #[error(transparent)]
    Message(#[from] p2p_messaging::MessageError),
}

/// A signer that uses the vault Ed25519 identity, so the MLS leaf signature key
/// is the same key that signs the outer envelope.
#[derive(Clone)]
struct IdentitySigner(Identity);

impl Signer for IdentitySigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.0.sign(payload).map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl fmt::Debug for IdentitySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IdentitySigner")
            .field(&"<redacted>")
            .finish()
    }
}

fn credential(identity: &Identity) -> Result<CredentialWithKey, GroupError> {
    Ok(CredentialWithKey {
        credential: BasicCredential::new(identity.peer_id().to_bytes()).into(),
        signature_key: identity.ed25519_public_bytes()?.to_vec().into(),
    })
}

fn check_group_message_size(bytes: &[u8]) -> Result<(), GroupError> {
    if bytes.len() > MAX_GROUP_MESSAGE_BYTES {
        Err(GroupError::TooLarge {
            len: bytes.len(),
            max: MAX_GROUP_MESSAGE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

/// OpenMLS provider combining the pinned RustCrypto implementation with the
/// vault-backed staged storage adapter (ADR-0014 Phase 4).
struct VaultProvider {
    crypto: RustCrypto,
    storage: StagedMlsProvider,
}

impl VaultProvider {
    fn new(session: Session) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: StagedMlsProvider::new(session),
        }
    }

    fn storage(&self) -> &StagedMlsProvider {
        &self.storage
    }
}

impl OpenMlsProvider for VaultProvider {
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

impl fmt::Debug for VaultProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultProvider")
            .field("storage", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The application either keeps MLS state in memory (the original no-vault
/// path) or stages every OpenMLS write in the encrypted vault. Both variants
/// implement `OpenMlsProvider`, so group operations dispatch through the same
/// OpenMLS calls without duplicating the MLS logic.
enum MlsProvider {
    Memory(Box<OpenMlsRustCrypto>),
    Vault(Box<VaultProvider>),
}

impl MlsProvider {
    fn persist_group(&self, group_id: &[u8; 16], epoch: u64) -> Result<(), GroupError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Vault(provider) => {
                provider.storage().set_group_epoch(group_id, epoch)?;
                provider.storage().flush()?;
                Ok(())
            }
        }
    }

    fn persist_global(&self) -> Result<(), GroupError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Vault(provider) => {
                provider.storage().flush()?;
                Ok(())
            }
        }
    }

    fn discard(&self) {
        if let Self::Vault(provider) = self {
            provider.storage().discard();
        }
    }
}

/// Dispatch one OpenMLS operation to the active provider variant. The group and
/// provider are borrowed from disjoint fields, so operations that mutate group
/// state can still use the provider immutably.
macro_rules! with_provider {
    ($self:expr, |$provider:ident, $group:ident| $body:block) => {{
        let this: &mut Self = &mut *$self;
        match &this.provider {
            MlsProvider::Memory(provider) => {
                let $provider = provider.as_ref();
                let $group = &mut this.group;
                $body
            }
            MlsProvider::Vault(provider) => {
                let $provider = provider.as_ref();
                let $group = &mut this.group;
                $body
            }
        }
    }};
}

/// A generated KeyPackage plus the provider holding its private material.
/// Welcome messages can only be decrypted by passing this value to
/// [`MlsConversation::join`]; the encoded bytes alone are not sufficient. With
/// a vault session the private material is staged and flushed to encrypted
/// storage before this value is returned.
#[must_use = "the returned KeyPackage owns secrets required for join"]
pub struct MlsKeyPackage {
    provider: MlsProvider,
    bytes: Vec<u8>,
}

impl MlsKeyPackage {
    /// Serialized KeyPackage to send to the group creator.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MlsKeyPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlsKeyPackage")
            .field("bytes_len", &self.bytes.len())
            .field("provider", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// An OpenMLS group session. The provider variants keep the same group logic
/// while choosing memory-only or encrypted-vault persistence.
struct MlsSession {
    provider: MlsProvider,
    group: MlsGroup,
    identity: Identity,
    conversation_id: [u8; 16],
}

impl MlsSession {
    fn create(
        identity: &Identity,
        conversation_id: [u8; 16],
        storage: Option<Session>,
    ) -> Result<Self, GroupError> {
        let provider = match storage {
            Some(session) => MlsProvider::Vault(Box::new(VaultProvider::new(session))),
            None => MlsProvider::Memory(Box::default()),
        };
        let signer = IdentitySigner(identity.clone());
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = match &provider {
            MlsProvider::Memory(provider) => MlsGroup::new_with_group_id(
                provider.as_ref(),
                &signer,
                &config,
                GroupId::from_slice(&conversation_id),
                credential(identity)?,
            )
            .map_err(|_| GroupError::Mls("group creation failed")),
            MlsProvider::Vault(provider) => MlsGroup::new_with_group_id(
                provider.as_ref(),
                &signer,
                &config,
                GroupId::from_slice(&conversation_id),
                credential(identity)?,
            )
            .map_err(|_| GroupError::Mls("group creation failed")),
        }?;
        provider
            .persist_group(&conversation_id, group.epoch().as_u64())
            .inspect_err(|_| provider.discard())?;
        Ok(Self {
            provider,
            group,
            identity: identity.clone(),
            conversation_id,
        })
    }

    /// Reconstruct a group from encrypted provider state. `None` from OpenMLS
    /// is a restore failure, never an empty conversation.
    fn load(
        identity: &Identity,
        conversation_id: [u8; 16],
        storage: Session,
    ) -> Result<Self, GroupError> {
        let provider = MlsProvider::Vault(Box::new(VaultProvider::new(storage)));
        let group_id = GroupId::from_slice(&conversation_id);
        let loaded = match &provider {
            MlsProvider::Memory(_) => unreachable!("load always uses the vault provider"),
            MlsProvider::Vault(provider) => MlsGroup::load(provider.storage(), &group_id)
                .map_err(|_| GroupError::MlsStateMissing)?,
        };
        let group = loaded.ok_or(GroupError::MlsStateMissing)?;
        if group.group_id().as_slice() != conversation_id {
            return Err(GroupError::WrongConversation);
        }
        let local_member = group
            .members()
            .find(|member| {
                PeerId::from_bytes(member.credential.serialized_content()).ok()
                    == Some(identity.peer_id())
            })
            .ok_or(GroupError::WrongLocalIdentity)?;
        if local_member.signature_key.as_slice() != identity.ed25519_public_bytes()? {
            return Err(GroupError::WrongLocalIdentity);
        }
        Ok(Self {
            provider,
            group,
            identity: identity.clone(),
            conversation_id,
        })
    }

    fn key_package(
        identity: &Identity,
        storage: Option<Session>,
    ) -> Result<MlsKeyPackage, GroupError> {
        let provider = match storage {
            Some(session) => MlsProvider::Vault(Box::new(VaultProvider::new(session))),
            None => MlsProvider::Memory(Box::default()),
        };
        let signer = IdentitySigner(identity.clone());
        let bundle = match &provider {
            MlsProvider::Memory(provider) => KeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    provider.as_ref(),
                    &signer,
                    credential(identity)?,
                )
                .map_err(|_| GroupError::Mls("key package generation failed"))?,
            MlsProvider::Vault(provider) => KeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    provider.as_ref(),
                    &signer,
                    credential(identity)?,
                )
                .map_err(|_| GroupError::Mls("key package generation failed"))?,
        };
        provider
            .persist_global()
            .inspect_err(|_| provider.discard())?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| GroupError::Mls("key package encoding failed"))?;
        check_group_message_size(&bytes)?;
        Ok(MlsKeyPackage { provider, bytes })
    }

    fn members(&self) -> Result<Vec<PeerId>, GroupError> {
        let mut members = Vec::new();
        for member in self.group.members() {
            let peer = PeerId::from_bytes(member.credential.serialized_content())
                .map_err(|_| GroupError::Mls("member credential is not a PeerId"))?;
            members.push(peer);
        }
        members.sort();
        Ok(members)
    }

    fn member_leaf(&self, peer: &PeerId) -> Option<LeafNodeIndex> {
        self.group
            .members()
            .find(|member| {
                PeerId::from_bytes(member.credential.serialized_content()).ok() == Some(*peer)
            })
            .map(|member| member.index)
    }

    fn add_member_parts(
        &mut self,
        key_package_bytes: &[u8],
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), GroupError> {
        check_group_message_size(key_package_bytes)?;
        let key_package_in = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|_| GroupError::Mls("key package decoding failed"))?;
        let crypto = match &self.provider {
            MlsProvider::Memory(provider) => provider.crypto(),
            MlsProvider::Vault(provider) => provider.crypto(),
        };
        let key_package = key_package_in
            .validate(crypto, ProtocolVersion::Mls10)
            .map_err(|_| GroupError::Mls("key package validation failed"))?;

        let expected_public = PublicKey::try_decode_protobuf(expected_public_key)
            .map_err(|_| GroupError::Mls("expected public key decode failed"))?;
        if expected_public.to_peer_id() != expected_peer {
            return Err(GroupError::SenderMismatch);
        }
        let expected_raw_key = raw_ed25519_public_bytes_from_protobuf(expected_public_key)?;
        let leaf = key_package.leaf_node();
        if leaf.credential().serialized_content() != expected_peer.to_bytes()
            || leaf.signature_key().as_slice() != expected_raw_key
        {
            return Err(GroupError::SenderMismatch);
        }
        if self.member_leaf(&expected_peer).is_some() {
            return Err(GroupError::NotMember);
        }

        let signer = IdentitySigner(self.identity.clone());
        let added = with_provider!(self, |provider, group| {
            group
                .add_members(provider, &signer, &[key_package])
                .map_err(|_| GroupError::Mls("member add failed"))
        });
        let (commit, welcome, _group_info) = match added {
            Ok(value) => value,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };
        let welcome_bytes = match welcome.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.provider.discard();
                return Err(GroupError::Mls("welcome encoding failed"));
            }
        };
        let commit_bytes = match commit.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.provider.discard();
                return Err(GroupError::Mls("add commit encoding failed"));
            }
        };
        if let Err(error) = check_group_message_size(&welcome_bytes)
            .and_then(|_| check_group_message_size(&commit_bytes))
        {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = with_provider!(self, |provider, group| {
            group
                .merge_pending_commit(provider)
                .map_err(|_| GroupError::Mls("commit merge failed"))
        }) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = self
            .provider
            .persist_group(&self.conversation_id, self.epoch())
        {
            self.provider.discard();
            return Err(error);
        }
        Ok((welcome_bytes, commit_bytes))
    }

    fn add_member(
        &mut self,
        key_package_bytes: &[u8],
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        let (welcome, _commit) =
            self.add_member_parts(key_package_bytes, expected_peer, expected_public_key)?;
        Ok(welcome)
    }

    fn remove_member(&mut self, peer: &PeerId) -> Result<Vec<u8>, GroupError> {
        let leaf = self.member_leaf(peer).ok_or(GroupError::NotMember)?;
        if leaf == self.group.own_leaf_index() {
            return Err(GroupError::SelfRemovalDenied);
        }
        let signer = IdentitySigner(self.identity.clone());
        let removed = with_provider!(self, |provider, group| {
            group
                .remove_members(provider, &signer, &[leaf])
                .map_err(|_| GroupError::Mls("member remove failed"))
        });
        let (commit, welcome, _group_info) = match removed {
            Ok(value) => value,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };
        if welcome.is_some() {
            self.provider.discard();
            return Err(GroupError::UnexpectedCommit);
        }
        let bytes = match commit.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.provider.discard();
                return Err(GroupError::Mls("remove commit encoding failed"));
            }
        };
        if let Err(error) = check_group_message_size(&bytes) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = with_provider!(self, |provider, group| {
            group
                .merge_pending_commit(provider)
                .map_err(|_| GroupError::Mls("commit merge failed"))
        }) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = self
            .provider
            .persist_group(&self.conversation_id, self.epoch())
        {
            self.provider.discard();
            return Err(error);
        }
        Ok(bytes)
    }

    fn self_update_commit(&mut self) -> Result<Vec<u8>, GroupError> {
        let signer = IdentitySigner(self.identity.clone());
        let updated = with_provider!(self, |provider, group| {
            group
                .self_update(provider, &signer, LeafNodeParameters::default())
                .map_err(|_| GroupError::Mls("self update failed"))
        });
        let (commit, welcome, _group_info) = match updated {
            Ok(value) => value.into_contents(),
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };
        if welcome.is_some() {
            self.provider.discard();
            return Err(GroupError::UnexpectedCommit);
        }
        let bytes = match commit.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.provider.discard();
                return Err(GroupError::Mls("update commit encoding failed"));
            }
        };
        if let Err(error) = check_group_message_size(&bytes) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = with_provider!(self, |provider, group| {
            group
                .merge_pending_commit(provider)
                .map_err(|_| GroupError::Mls("commit merge failed"))
        }) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = self
            .provider
            .persist_group(&self.conversation_id, self.epoch())
        {
            self.provider.discard();
            return Err(error);
        }
        Ok(bytes)
    }

    fn join(
        identity: &Identity,
        conversation_id: [u8; 16],
        key_package: MlsKeyPackage,
        welcome_bytes: &[u8],
    ) -> Result<Self, GroupError> {
        check_group_message_size(welcome_bytes)?;
        let MlsKeyPackage { provider, bytes: _ } = key_package;
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|_| GroupError::Mls("welcome decoding failed"))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(GroupError::Mls("message was not a welcome")),
        };
        let staged = match &provider {
            MlsProvider::Memory(p) => {
                StagedWelcome::new_from_welcome(p.as_ref(), &join_config(), welcome, None)
                    .map_err(|_| GroupError::Mls("welcome validation failed"))
            }
            MlsProvider::Vault(p) => {
                StagedWelcome::new_from_welcome(p.as_ref(), &join_config(), welcome, None)
                    .map_err(|_| GroupError::Mls("welcome validation failed"))
            }
        };
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                provider.discard();
                return Err(error);
            }
        };
        let group = match &provider {
            MlsProvider::Memory(p) => staged
                .into_group(p.as_ref())
                .map_err(|_| GroupError::Mls("group join failed")),
            MlsProvider::Vault(p) => staged
                .into_group(p.as_ref())
                .map_err(|_| GroupError::Mls("group join failed")),
        };
        let group = match group {
            Ok(group) => group,
            Err(error) => {
                provider.discard();
                return Err(error);
            }
        };
        if group.group_id().as_slice() != conversation_id {
            provider.discard();
            return Err(GroupError::WrongConversation);
        }
        if let Err(error) = provider.persist_group(&conversation_id, group.epoch().as_u64()) {
            provider.discard();
            return Err(error);
        }
        Ok(Self {
            provider,
            group,
            identity: identity.clone(),
            conversation_id,
        })
    }

    fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
        if plaintext.is_empty() {
            return Err(GroupError::EmptyPlaintext);
        }
        let signer = IdentitySigner(self.identity.clone());
        let created = with_provider!(self, |provider, group| {
            group
                .create_message(provider, &signer, plaintext)
                .map_err(|_| GroupError::Mls("application encryption failed"))
        });
        let message = match created {
            Ok(message) => message,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };
        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.provider.discard();
                return Err(GroupError::Mls("application message encoding failed"));
            }
        };
        if let Err(error) = check_group_message_size(&bytes) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = self
            .provider
            .persist_group(&self.conversation_id, self.epoch())
        {
            self.provider.discard();
            return Err(error);
        }
        Ok(bytes)
    }

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        expected_sender: &PeerId,
        expected_public_key: &[u8],
    ) -> Result<DecryptedApplication, GroupError> {
        check_group_message_size(ciphertext)?;
        let local_epoch = self.epoch();
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|_| GroupError::Mls("application message decoding failed"))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| GroupError::Mls("message was not a protocol message"))?;
        let processed = match with_provider!(self, |provider, group| {
            group
                .process_message(provider, protocol_message)
                .map_err(|_| GroupError::Mls("application decryption failed"))
        }) {
            Ok(processed) => processed,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };

        let validated = (|| {
            if processed.group_id().as_slice() != self.conversation_id {
                return Err(GroupError::WrongConversation);
            }
            let epoch = processed.epoch().as_u64();
            if epoch != local_epoch {
                return Err(GroupError::EpochMismatch {
                    expected: local_epoch,
                    actual: epoch,
                });
            }
            let credential = processed.credential();
            if credential.credential_type() != CredentialType::Basic
                || credential.serialized_content() != expected_sender.to_bytes()
            {
                return Err(GroupError::SenderMismatch);
            }
            let leaf = match processed.sender() {
                Sender::Member(leaf) => leaf,
                _ => return Err(GroupError::SenderMismatch),
            };
            let member = self
                .group
                .members()
                .find(|member| member.index == *leaf)
                .ok_or(GroupError::SenderMismatch)?;
            let expected_raw_key = raw_ed25519_public_bytes_from_protobuf(expected_public_key)?;
            if member.signature_key != expected_raw_key {
                return Err(GroupError::SenderMismatch);
            }
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(application) => {
                    Ok(DecryptedApplication {
                        epoch,
                        plaintext: Zeroizing::new(application.into_bytes()),
                    })
                }
                _ => Err(GroupError::Mls("expected an MLS application message")),
            }
        })();
        match validated {
            Ok(decrypted) => {
                if let Err(error) = self
                    .provider
                    .persist_group(&self.conversation_id, self.epoch())
                {
                    self.provider.discard();
                    return Err(error);
                }
                Ok(decrypted)
            }
            Err(error) => {
                self.provider.discard();
                Err(error)
            }
        }
    }

    fn process_commit(
        &mut self,
        commit_bytes: &[u8],
        expected_sender: &PeerId,
        expected_public_key: &[u8],
        operation: GroupOperation,
        expected_target: Option<PeerId>,
    ) -> Result<CommitOutcome, GroupError> {
        check_group_message_size(commit_bytes)?;
        let local_epoch = self.epoch();
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|_| GroupError::Mls("commit message decoding failed"))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| GroupError::Mls("message was not an MLS commit"))?;
        let processed = match with_provider!(self, |provider, group| {
            group
                .process_message(provider, protocol_message)
                .map_err(|_| GroupError::Mls("commit processing failed"))
        }) {
            Ok(processed) => processed,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };

        let validated = (|| {
            if processed.group_id().as_slice() != self.conversation_id {
                return Err(GroupError::WrongConversation);
            }
            let message_epoch = processed.epoch().as_u64();
            if message_epoch != local_epoch {
                return Err(GroupError::EpochMismatch {
                    expected: local_epoch,
                    actual: message_epoch,
                });
            }
            self.verify_sender(&processed, expected_sender, expected_public_key)?;
            let staged = match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
                _ => return Err(GroupError::UnexpectedCommit),
            };
            let next_epoch = staged.epoch().as_u64();
            if next_epoch != local_epoch.saturating_add(1) {
                return Err(GroupError::EpochMismatch {
                    expected: local_epoch.saturating_add(1),
                    actual: next_epoch,
                });
            }
            self.verify_commit_operation(&staged, operation, expected_target)?;
            let self_removed = staged.self_removed();
            Ok((staged, self_removed))
        })();
        let (staged, self_removed) = match validated {
            Ok(value) => value,
            Err(error) => {
                self.provider.discard();
                return Err(error);
            }
        };
        if let Err(error) = with_provider!(self, |provider, group| {
            group
                .merge_staged_commit(provider, staged)
                .map_err(|_| GroupError::Mls("commit merge failed"))
        }) {
            self.provider.discard();
            return Err(error);
        }
        if let Err(error) = self
            .provider
            .persist_group(&self.conversation_id, self.epoch())
        {
            self.provider.discard();
            return Err(error);
        }
        Ok(CommitOutcome {
            epoch: self.epoch(),
            self_removed,
        })
    }

    fn verify_sender(
        &self,
        processed: &ProcessedMessage,
        expected_sender: &PeerId,
        expected_public_key: &[u8],
    ) -> Result<(), GroupError> {
        let credential = processed.credential();
        if credential.credential_type() != CredentialType::Basic
            || credential.serialized_content() != expected_sender.to_bytes()
        {
            return Err(GroupError::SenderMismatch);
        }
        let leaf = match processed.sender() {
            Sender::Member(leaf) => leaf,
            _ => return Err(GroupError::SenderMismatch),
        };
        let member = self
            .group
            .members()
            .find(|member| member.index == *leaf)
            .ok_or(GroupError::SenderMismatch)?;
        let expected_raw_key = raw_ed25519_public_bytes_from_protobuf(expected_public_key)?;
        if member.signature_key != expected_raw_key {
            return Err(GroupError::SenderMismatch);
        }
        Ok(())
    }

    fn verify_commit_operation(
        &self,
        staged: &StagedCommit,
        operation: GroupOperation,
        expected_target: Option<PeerId>,
    ) -> Result<(), GroupError> {
        let added: Vec<PeerId> = staged
            .add_proposals()
            .filter_map(|proposal| {
                PeerId::from_bytes(
                    proposal
                        .add_proposal()
                        .key_package()
                        .leaf_node()
                        .credential()
                        .serialized_content(),
                )
                .ok()
            })
            .collect();
        let removed: Vec<PeerId> = staged
            .remove_proposals()
            .filter_map(|proposal| {
                let leaf = proposal.remove_proposal().removed();
                self.group
                    .members()
                    .find(|member| member.index == leaf)
                    .and_then(|member| {
                        PeerId::from_bytes(member.credential.serialized_content()).ok()
                    })
            })
            .collect();
        let updated = staged.update_proposals().count();

        let ok = match (operation, expected_target) {
            (GroupOperation::Add, Some(target)) => {
                added.len() == 1 && added[0] == target && removed.is_empty() && updated == 0
            }
            (GroupOperation::Remove, Some(target)) => {
                removed.len() == 1 && removed[0] == target && added.is_empty() && updated == 0
            }
            (GroupOperation::Update, None) => {
                added.is_empty() && removed.is_empty() && staged.update_path_leaf_node().is_some()
            }
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(GroupError::UnexpectedCommit)
        }
    }
}

impl fmt::Debug for MlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlsSession")
            .field("conversation_id", &self.conversation_id)
            .field("epoch", &self.epoch())
            .field("peer", &self.identity.peer_id().to_string())
            .field("group", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct DecryptedApplication {
    epoch: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

/// A decrypted application body paired with the already-verified envelope
/// metadata. Plaintext is zeroized on drop and never included in `Debug`.
pub struct DecryptedMessage {
    pub metadata: ReceivedMessage,
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DecryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedMessage")
            .field("metadata", &self.metadata)
            .field("plaintext_len", &self.plaintext.len())
            .field("plaintext", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// An MLS-encrypted conversation. The outer envelope authenticates the sender
/// identity; the MLS payload authenticates group membership and encrypts the
/// application body, including receipts.
pub struct MlsConversation {
    conversation: Conversation,
    session: MlsSession,
}

impl MlsConversation {
    /// Create a new conversation and its MLS group with a random ID. Group
    /// state remains memory-only; use [`Self::new_with_storage`] for encrypted
    /// persistence.
    pub fn new(identity: &Identity) -> Result<Self, GroupError> {
        let conversation = Conversation::new(identity)?;
        Self::from_parts(identity, conversation, None)
    }

    /// Create a new conversation whose MLS provider state is flushed to the
    /// encrypted vault.
    pub fn new_with_storage(identity: &Identity, storage: Session) -> Result<Self, GroupError> {
        let conversation = Conversation::new(identity)?;
        Self::from_parts(identity, conversation, Some(storage))
    }

    /// Create a conversation with a known ID, used by both peers in a 1:1 setup.
    pub fn create(identity: &Identity, conversation_id: [u8; 16]) -> Result<Self, GroupError> {
        let conversation = Conversation::with_id(identity.peer_id(), conversation_id);
        Self::from_parts(identity, conversation, None)
    }

    /// Vault-backed variant of [`Self::create`].
    pub fn create_with_storage(
        identity: &Identity,
        conversation_id: [u8; 16],
        storage: Session,
    ) -> Result<Self, GroupError> {
        let conversation = Conversation::with_id(identity.peer_id(), conversation_id);
        Self::from_parts(identity, conversation, Some(storage))
    }

    /// Restore a group through `MlsGroup::load` using encrypted provider state.
    /// Missing or inconsistent state is an error, never an empty conversation.
    pub fn load_with_storage(
        identity: &Identity,
        conversation_id: [u8; 16],
        storage: Session,
    ) -> Result<Self, GroupError> {
        let conversation = Conversation::with_id(identity.peer_id(), conversation_id);
        let session = MlsSession::load(identity, conversation_id, storage)?;
        Ok(Self {
            conversation,
            session,
        })
    }

    fn from_parts(
        identity: &Identity,
        conversation: Conversation,
        storage: Option<Session>,
    ) -> Result<Self, GroupError> {
        let session = MlsSession::create(identity, conversation.id(), storage)?;
        Ok(Self {
            conversation,
            session,
        })
    }

    /// Generate a fresh KeyPackage for a peer that wants to join this group.
    /// The returned value must be kept until the Welcome is processed. With a
    /// vault session its private material is written to encrypted storage.
    pub fn key_package(identity: &Identity) -> Result<MlsKeyPackage, GroupError> {
        MlsSession::key_package(identity, None)
    }

    /// Vault-backed variant of [`Self::key_package`].
    pub fn key_package_with_storage(
        identity: &Identity,
        storage: Session,
    ) -> Result<MlsKeyPackage, GroupError> {
        MlsSession::key_package(identity, Some(storage))
    }

    /// Add a peer from its KeyPackage and return the Welcome for that peer.
    /// Both the claimed PeerId and its protobuf public key are bound to the
    /// KeyPackage credential and MLS leaf signature key.
    pub fn add_member(
        &mut self,
        key_package_bytes: &[u8],
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        self.session
            .add_member(key_package_bytes, expected_peer, expected_public_key)
    }

    /// Add a peer and return both the new member's Welcome and the signed MLS
    /// commit that advances every existing member to the new epoch.
    pub fn add_member_parts(
        &mut self,
        key_package_bytes: &[u8],
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), GroupError> {
        self.session
            .add_member_parts(key_package_bytes, expected_peer, expected_public_key)
    }

    /// Active members of this MLS group, sorted by PeerId.
    pub fn members(&self) -> Result<Vec<PeerId>, GroupError> {
        self.session.members()
    }

    /// Create a signed Remove commit for one active member. The local member
    /// cannot remove itself through this path.
    pub fn remove_member(&mut self, peer: &PeerId) -> Result<Vec<u8>, GroupError> {
        self.session.remove_member(peer)
    }

    /// Refresh the local leaf with a signed Update commit.
    pub fn self_update_commit(&mut self) -> Result<Vec<u8>, GroupError> {
        self.session.self_update_commit()
    }

    /// Apply an authenticated epoch-changing commit from another member. The
    /// expected operation and target are supplied by the signed control frame,
    /// so a commit containing a different change is rejected before merge.
    pub fn process_commit(
        &mut self,
        commit_bytes: &[u8],
        expected_sender: &PeerId,
        expected_public_key: &[u8],
        operation: GroupOperation,
        expected_target: Option<PeerId>,
    ) -> Result<CommitOutcome, GroupError> {
        self.session.process_commit(
            commit_bytes,
            expected_sender,
            expected_public_key,
            operation,
            expected_target,
        )
    }

    /// Join a group from a Welcome issued by an existing member. The original
    /// [`MlsKeyPackage`] is consumed because its provider holds the private
    /// material needed to decrypt that Welcome.
    pub fn join(
        identity: &Identity,
        conversation_id: [u8; 16],
        key_package: MlsKeyPackage,
        welcome_bytes: &[u8],
    ) -> Result<Self, GroupError> {
        let conversation = Conversation::with_id(identity.peer_id(), conversation_id);
        let session = MlsSession::join(identity, conversation_id, key_package, welcome_bytes)?;
        Ok(Self {
            conversation,
            session,
        })
    }

    pub fn id(&self) -> [u8; 16] {
        self.conversation.id()
    }

    pub fn epoch(&self) -> u64 {
        self.session.epoch()
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.conversation.local_peer_id()
    }

    pub fn conversation(&self) -> &Conversation {
        &self.conversation
    }

    pub fn delivery_state(&self, message_id: &[u8; 16]) -> Option<p2p_messaging::DeliveryState> {
        self.conversation.delivery_state(message_id)
    }

    /// Local offline queue accepted the message; no network send has occurred.
    pub fn mark_queued(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_queued(message_id)?;
        Ok(())
    }

    pub fn mark_sent_to_peer(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_sent_to_peer(message_id)?;
        Ok(())
    }

    pub fn mark_failed(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_failed(message_id)?;
        Ok(())
    }

    /// Encrypt an application body into `Envelope.payload` and sign the envelope.
    pub fn compose(
        &mut self,
        identity: &Identity,
        kind: MessageKind,
        plaintext: &[u8],
    ) -> Result<Envelope, GroupError> {
        self.check_identity(identity)?;
        let ciphertext = self.session.encrypt(plaintext)?;
        self.conversation.advance_epoch(self.session.epoch())?;
        Ok(self.conversation.compose(identity, kind, ciphertext)?)
    }

    /// Compose an MLS-encrypted receipt. Delivery state still changes only when
    /// the peer's receipt envelope is received and verified.
    pub fn receipt(
        &mut self,
        identity: &Identity,
        status: ReceiptStatus,
        message_id: [u8; 16],
    ) -> Result<Envelope, GroupError> {
        let body = Receipt::new(status, message_id).to_bytes();
        self.compose(identity, MessageKind::Receipt, &body)
    }

    /// Verify, decrypt, and record an incoming envelope. No plaintext is stored.
    pub fn receive(&mut self, envelope: Envelope) -> Result<DecryptedMessage, GroupError> {
        self.conversation.advance_epoch(self.session.epoch())?;
        self.conversation.verify_envelope(&envelope)?;
        let decrypted = self.session.decrypt(
            &envelope.payload,
            &envelope.sender,
            &envelope.sender_public_key,
        )?;
        if decrypted.epoch != envelope.epoch {
            return Err(GroupError::EpochMismatch {
                expected: envelope.epoch,
                actual: decrypted.epoch,
            });
        }
        let metadata = self
            .conversation
            .receive_with_plaintext(envelope, decrypted.plaintext.as_slice())?;
        Ok(DecryptedMessage {
            metadata,
            plaintext: decrypted.plaintext,
        })
    }

    fn check_identity(&self, identity: &Identity) -> Result<(), GroupError> {
        if identity.peer_id() != self.session.identity.peer_id()
            || self.session.conversation_id != self.conversation.id()
        {
            return Err(GroupError::WrongLocalIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for MlsConversation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlsConversation")
            .field("conversation", &self.conversation)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}
