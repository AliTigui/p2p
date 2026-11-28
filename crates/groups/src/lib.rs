//! OpenMLS-backed group encryption for P2P conversations.
//!
//! Every conversation is an MLS group, including a two-member 1:1 group. This
//! crate owns the MLS lifecycle and produces signed envelopes whose payloads
//! are MLS ciphertext. The default constructors keep group state memory-only;
//! the vault-backed constructors flush OpenMLS provider state to encrypted
//! storage and can restore a group through `MlsGroup::load` (ADR-0014 Phase 4).

#![forbid(unsafe_code)]

use std::fmt;

use libp2p_identity::PeerId;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use p2p_crypto::{CryptoError, NONCE_LEN, TAG_LEN, decrypt_bytes, encrypt_bytes};
use p2p_identity::{Identity, IdentityRole, PQ_PUBLIC_KEY_BYTES};
use p2p_messaging::{
    Conversation, DeliveryState, Envelope, EnvelopeV3, MessageError, MessageKind, Receipt,
    ReceiptStatus, ReceivedMessage, V3_MAC_LEN, V3InnerFrame,
};
use p2p_storage::{MlsProviderError, Session, StagedMlsProvider};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Pure ML-KEM768 + ML-DSA-65 suite from the pinned draft OpenMLS feature.
/// MLS content encryption and all group authentication signatures use PQ
/// primitives. The libp2p transport still authenticates its PeerId classically;
/// the application layer binds setup authors with ML-DSA-65 separately.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65;
pub const CIPHERSUITE_ID: u16 = 0x0051;

/// Fail closed when a setup frame advertises any suite other than the fixed
/// ML-KEM/ML-DSA suite compiled into this build.
pub fn is_supported_ciphersuite_id(id: u16) -> bool {
    id == CIPHERSUITE_ID && Ciphersuite::try_from(id).ok() == Some(CIPHERSUITE)
}
const MAX_GROUP_MESSAGE_BYTES: usize = 1024 * 1024;
const CHANNEL_GROUP_ID_DOMAIN: &[u8] = b"p2p.mls-channel-group/v1";
const V3_ROUTE_TAG_DOMAIN: &[u8] = b"p2p-messenger/v3-route-tag";
const V3_MAC_LABEL: &str = "p2p-messenger/envelope-v3/mac";
const V3_BODY_LABEL: &str = "p2p-messenger/envelope-v3/body";
const V3_BODY_AAD_DOMAIN: &[u8] = b"p2p-messenger/v3-wrapped-mls-body";

fn v3_body_aad(route_tag: &[u8; 32], wrapped_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(V3_BODY_AAD_DOMAIN.len() + 40);
    aad.extend_from_slice(V3_BODY_AAD_DOMAIN);
    aad.extend_from_slice(route_tag);
    aad.extend_from_slice(&(wrapped_len as u64).to_le_bytes());
    aad
}

/// Derive the outer v3 routing tag for one MLS group epoch. This is a
/// local/transport selection hint, not a secret, not a proof, and not a
/// privacy-preserving unlinkability mechanism.
#[must_use = "a route tag must be checked against the local group epoch"]
pub fn v3_route_tag(group_id: [u8; 16], epoch: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(V3_ROUTE_TAG_DOMAIN);
    digest.update(group_id);
    digest.update(epoch.to_le_bytes());
    let bytes = digest.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&bytes);
    tag
}

/// Derive the independent MLS group ID for one logical channel.
///
/// This is an identifier derivation, not key derivation: the resulting bytes
/// select a separate OpenMLS group whose key schedule, epoch, ratchet state,
/// membership, and replay state are independent of the parent conversation.
/// The domain separator prevents a channel group from colliding with a
/// conversation group or with a future derivation format.
#[must_use = "a channel group id must be used to create a distinct MLS group"]
pub fn channel_group_id(conversation_id: [u8; 16], channel_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(CHANNEL_GROUP_ID_DOMAIN);
    digest.update(conversation_id);
    digest.update(channel_id);
    let bytes = digest.finalize();
    let mut group_id = [0u8; 16];
    group_id.copy_from_slice(&bytes[..16]);
    group_id
}

/// Explicit parent/channel identity for an independent MLS channel group.
///
/// The derived group ID is the only MLS group ID this binding authorizes. The
/// binding does not encode an inverse mapping back to the parent or channel;
/// callers must supply those values themselves, and P1c must sign them before
/// the application can claim cryptographic channel ACLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelGroupBinding {
    parent_conversation_id: [u8; 16],
    channel_id: [u8; 16],
    group_id: [u8; 16],
}

impl ChannelGroupBinding {
    /// Bind a logical channel to its parent conversation and derived MLS group.
    pub fn new(parent_conversation_id: [u8; 16], channel_id: [u8; 16]) -> Self {
        Self {
            parent_conversation_id,
            channel_id,
            group_id: channel_group_id(parent_conversation_id, channel_id),
        }
    }

    pub fn parent_conversation_id(self) -> [u8; 16] {
        self.parent_conversation_id
    }

    pub fn channel_id(self) -> [u8; 16] {
        self.channel_id
    }

    pub fn group_id(self) -> [u8; 16] {
        self.group_id
    }
}

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
    #[error("MLS application plaintext is {len} bytes (maximum {max})")]
    PlaintextTooLarge { len: usize, max: usize },
    #[error("MLS application padding is malformed")]
    InvalidPadding,
    #[error("MLS group id does not match the conversation id")]
    WrongConversation,
    #[error("MLS channel group does not match its parent conversation and channel binding")]
    WrongChannelBinding,
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
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A signer that uses the certified ML-DSA-65 MLS role key. MLS signatures
/// cover the exact MLS payload bytes; role separation comes from the independent
/// seed in the encrypted identity bundle.
#[derive(Clone)]
struct IdentitySigner(Identity);

impl Signer for IdentitySigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        let seed = self
            .0
            .pq_role_seed(IdentityRole::Mls)
            .map_err(|_| SignerError::SigningError)?;
        p2p_identity::pq_sign_for_mls(&seed, payload).map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA65
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
        signature_key: identity.pq_role_public_bytes(IdentityRole::Mls)?.into(),
    })
}

/// MLS leaf signature keys are encoded ML-DSA-65 public keys. The expected key
/// is supplied by the certified PQ identity proof in the signed setup frame.
fn expected_mls_key(expected_public_key: &[u8]) -> Result<Vec<u8>, GroupError> {
    if expected_public_key.len() != PQ_PUBLIC_KEY_BYTES {
        return Err(GroupError::SenderMismatch);
    }
    Ok(expected_public_key.to_vec())
}

/// Application plaintexts are padded inside the MLS ciphertext so observers
/// see fixed-size buckets instead of exact frame lengths. This is a coarse
/// length-hiding measure only: it does not hide timing, direction, or volume.
const PADDING_TAG: u8 = 1;
const PADDING_HEADER_LEN: usize = 5;
const PADDING_BUCKETS: [usize; 15] = [
    64, 128, 256, 512, 1_024, 2_048, 4_096, 8_192, 16_384, 32_768, 65_536, 131_072, 262_144,
    524_288, 786_432,
];
const MAX_PADDED_PLAINTEXT: usize = PADDING_BUCKETS[PADDING_BUCKETS.len() - 1] - PADDING_HEADER_LEN;

fn pad_application_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
    if plaintext.is_empty() {
        return Err(GroupError::EmptyPlaintext);
    }
    let needed = plaintext.len().saturating_add(PADDING_HEADER_LEN);
    let bucket = PADDING_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= needed)
        .ok_or(GroupError::PlaintextTooLarge {
            len: plaintext.len(),
            max: MAX_PADDED_PLAINTEXT,
        })?;
    let original_len =
        u32::try_from(plaintext.len()).map_err(|_| GroupError::PlaintextTooLarge {
            len: plaintext.len(),
            max: MAX_PADDED_PLAINTEXT,
        })?;
    let mut padded = vec![0u8; bucket];
    padded[0] = PADDING_TAG;
    padded[1..PADDING_HEADER_LEN].copy_from_slice(&original_len.to_le_bytes());
    padded[PADDING_HEADER_LEN..PADDING_HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);
    Ok(padded)
}

fn strip_application_padding(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, GroupError> {
    if !PADDING_BUCKETS.contains(&padded.len())
        || padded.first().copied() != Some(PADDING_TAG)
        || padded.len() <= PADDING_HEADER_LEN
    {
        return Err(GroupError::InvalidPadding);
    }
    let original_len = u32::from_le_bytes(
        padded[1..PADDING_HEADER_LEN]
            .try_into()
            .map_err(|_| GroupError::InvalidPadding)?,
    ) as usize;
    if original_len == 0
        || PADDING_HEADER_LEN
            .checked_add(original_len)
            .is_none_or(|end| end > padded.len())
        || padded[PADDING_HEADER_LEN + original_len..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(GroupError::InvalidPadding);
    }
    Ok(Zeroizing::new(
        padded[PADDING_HEADER_LEN..PADDING_HEADER_LEN + original_len].to_vec(),
    ))
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

/// A KeyPackage with an explicit channel binding. The binding is checked when
/// the package is added to a [`MlsChannelGroup`] and when its Welcome is used
/// to join; P1c must sign the binding before it is authenticated as setup data.
#[must_use = "the returned KeyPackage owns secrets required for join"]
pub struct ChannelKeyPackage {
    binding: ChannelGroupBinding,
    inner: MlsKeyPackage,
}

impl ChannelKeyPackage {
    pub fn binding(&self) -> ChannelGroupBinding {
        self.binding
    }

    pub fn bytes(&self) -> &[u8] {
        self.inner.bytes()
    }

    /// Wrap a received public KeyPackage with the binding proven by its signed
    /// setup frame. This value can be added to a group, but it owns no private
    /// join material and must never be used to join.
    pub fn from_public_bytes(binding: ChannelGroupBinding, bytes: Vec<u8>) -> Self {
        Self {
            binding,
            inner: MlsKeyPackage {
                provider: MlsProvider::Memory(Box::default()),
                bytes,
            },
        }
    }
}

impl fmt::Debug for ChannelKeyPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelKeyPackage")
            .field("binding", &self.binding)
            .field("bytes_len", &self.inner.bytes.len())
            .field("provider", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A Welcome with the channel binding of the group that issued it.
#[must_use = "a Welcome is required to join the bound channel group"]
pub struct ChannelWelcome {
    binding: ChannelGroupBinding,
    bytes: Vec<u8>,
}

impl ChannelWelcome {
    pub fn binding(&self) -> ChannelGroupBinding {
        self.binding
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Wrap a received Welcome whose signed setup frame proved this binding.
    pub fn from_bytes(binding: ChannelGroupBinding, bytes: Vec<u8>) -> Self {
        Self { binding, bytes }
    }
}

impl fmt::Debug for ChannelWelcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelWelcome")
            .field("binding", &self.binding)
            .field("bytes_len", &self.bytes.len())
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

    fn ensure_local_identity(group: &MlsGroup, identity: &Identity) -> Result<(), GroupError> {
        let local_member = group
            .members()
            .find(|member| {
                PeerId::from_bytes(member.credential.serialized_content()).ok()
                    == Some(identity.peer_id())
            })
            .ok_or(GroupError::WrongLocalIdentity)?;
        if local_member.signature_key.as_slice()
            != identity.pq_role_public_bytes(IdentityRole::Mls)?
        {
            return Err(GroupError::WrongLocalIdentity);
        }
        Ok(())
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
        Self::ensure_local_identity(&group, identity)?;
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

    /// Certified MLS leaf key already bound to a PeerId when that member joined
    /// the group. The legacy signed-v2 envelope carries only a classical
    /// application key, so it cannot supply an ML-DSA-65 MLS key; legacy `receive`
    /// uses the group's own authenticated leaf instead. Production uses v3.
    fn member_signature_key(&self, peer: &PeerId) -> Result<Vec<u8>, GroupError> {
        self.group
            .members()
            .find(|member| {
                PeerId::from_bytes(member.credential.serialized_content()).ok() == Some(*peer)
            })
            .map(|member| member.signature_key.to_vec())
            .ok_or(GroupError::SenderMismatch)
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

        let expected_raw_key = expected_mls_key(expected_public_key)?;
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
        if let Err(error) = Self::ensure_local_identity(&group, identity) {
            provider.discard();
            return Err(error);
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
        let padded = pad_application_plaintext(plaintext)?;
        let signer = IdentitySigner(self.identity.clone());
        let created = with_provider!(self, |provider, group| {
            group
                .create_message(provider, &signer, &padded)
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
            let expected_raw_key = expected_mls_key(expected_public_key)?;
            if member.signature_key.as_slice() != expected_raw_key.as_slice() {
                return Err(GroupError::SenderMismatch);
            }
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(application) => {
                    let padded = Zeroizing::new(application.into_bytes());
                    Ok(DecryptedApplication {
                        epoch,
                        plaintext: strip_application_padding(&padded)?,
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

    /// Derive a purpose-separated key from the current MLS epoch. The exporter
    /// context binds the key to this group ID and epoch; no application-defined
    /// primitive is used.
    fn export_v3_key(&self, label: &str) -> Result<Zeroizing<[u8; V3_MAC_LEN]>, GroupError> {
        let mut context = Vec::with_capacity(24);
        context.extend_from_slice(&self.conversation_id);
        context.extend_from_slice(&self.epoch().to_le_bytes());
        let exported = match &self.provider {
            MlsProvider::Memory(provider) => {
                self.group
                    .export_secret(provider.as_ref().crypto(), label, &context, V3_MAC_LEN)
            }
            MlsProvider::Vault(provider) => {
                self.group
                    .export_secret(provider.crypto(), label, &context, V3_MAC_LEN)
            }
        }
        .map_err(|_| GroupError::Mls("MLS exporter failed"))?;
        let bytes: [u8; V3_MAC_LEN] = exported
            .as_ref()
            .try_into()
            .map_err(|_| GroupError::Mls("MLS exporter returned an invalid key length"))?;
        Ok(Zeroizing::new(bytes))
    }

    /// MLS-decrypt a v3 body without any outer identity proof. The sender is
    /// recovered from the MLS leaf credential after authenticated decryption;
    /// no third party holding only wire bytes can verify or learn it.
    fn decrypt_v3(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<(PeerId, Zeroizing<Vec<u8>>), GroupError> {
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
            let sender = PeerId::from_bytes(processed.credential().serialized_content())
                .map_err(|_| GroupError::SenderMismatch)?;
            if processed.credential().credential_type() != CredentialType::Basic {
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
            if member.credential.serialized_content() != sender.to_bytes() {
                return Err(GroupError::SenderMismatch);
            }
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(application) => {
                    let padded = Zeroizing::new(application.into_bytes());
                    Ok((sender, strip_application_padding(&padded)?))
                }
                _ => Err(GroupError::Mls("expected an MLS application message")),
            }
        })();
        match validated {
            Ok(value) => {
                if let Err(error) = self
                    .provider
                    .persist_group(&self.conversation_id, self.epoch())
                {
                    self.provider.discard();
                    return Err(error);
                }
                Ok(value)
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
        let expected_raw_key = expected_mls_key(expected_public_key)?;
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

    pub fn delivery_state(&self, message_id: &[u8; 16]) -> Option<DeliveryState> {
        self.conversation.delivery_state(message_id)
    }

    /// Next local message sequence, restored from the encrypted snapshot.
    pub fn next_sequence(&self) -> u64 {
        self.conversation.next_sequence()
    }

    /// Set the local epoch from an authenticated restore record. The inner
    /// conversation starts at epoch zero after `MlsGroup::load`; without this a
    /// valid receipt at the loaded MLS epoch would be rejected.
    pub fn restore_epoch(&mut self, epoch: u64) -> Result<(), GroupError> {
        self.conversation.advance_epoch(epoch)?;
        Ok(())
    }

    /// Restore the local sequence counter from an authenticated restore record.
    pub fn restore_sequence(&mut self, sequence: u64) -> Result<(), GroupError> {
        self.conversation.restore_sequence(sequence)?;
        Ok(())
    }

    /// Rebuild one outbound state from an authenticated restore record. Only
    /// `Queued` and `SentToPeer` are accepted; a verified receipt is still
    /// required before delivery can advance.
    pub fn restore_outgoing(
        &mut self,
        message_id: &[u8; 16],
        state: DeliveryState,
    ) -> Result<(), GroupError> {
        self.conversation.restore_outgoing(message_id, state)?;
        Ok(())
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
        let mls_key = self.session.member_signature_key(&envelope.sender)?;
        let decrypted = self
            .session
            .decrypt(&envelope.payload, &envelope.sender, &mls_key)?;
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

    /// Compose a v3 envelope whose stable metadata is inside the MLS body.
    /// The returned message ID is local state for receipts and delivery; it is
    /// not present in the exported wire bytes.
    pub fn compose_v3(
        &mut self,
        identity: &Identity,
        kind: MessageKind,
        plaintext: &[u8],
    ) -> Result<(EnvelopeV3, [u8; 16]), GroupError> {
        self.check_identity(identity)?;
        let inner = self
            .conversation
            .prepare_v3_inner(identity, kind, plaintext)?;
        let inner_bytes = inner.to_bytes()?;
        let ciphertext = self.session.encrypt(&inner_bytes)?;
        let mac_key = self.session.export_v3_key(V3_MAC_LABEL)?;
        let body_key = self.session.export_v3_key(V3_BODY_LABEL)?;
        let route_tag = v3_route_tag(self.id(), self.session.epoch());
        let wrapped_len = ciphertext.len().saturating_add(NONCE_LEN + TAG_LEN);
        let wrapped = encrypt_bytes(
            &body_key,
            &ciphertext,
            &v3_body_aad(&route_tag, wrapped_len),
        )?;
        let envelope = EnvelopeV3::new(route_tag, wrapped, &mac_key)?;
        self.conversation.record_outgoing_v3(&inner)?;
        self.conversation.advance_epoch(self.session.epoch())?;
        Ok((envelope, inner.message_id))
    }

    /// Compose an MLS-encrypted v3 receipt. Delivery state still changes only
    /// when the peer's receipt is received, MAC-verified, and MLS-decrypted.
    pub fn receipt_v3(
        &mut self,
        identity: &Identity,
        status: ReceiptStatus,
        message_id: [u8; 16],
    ) -> Result<(EnvelopeV3, [u8; 16]), GroupError> {
        let body = Receipt::new(status, message_id).to_bytes();
        self.compose_v3(identity, MessageKind::Receipt, &body)
    }

    /// Verify the group route and exporter MAC, MLS-decrypt the body, bind the
    /// inner sender to the MLS leaf, then apply replay/receipt policy.
    pub fn receive_v3(&mut self, envelope: EnvelopeV3) -> Result<DecryptedMessage, GroupError> {
        self.conversation.advance_epoch(self.session.epoch())?;
        let expected_route = v3_route_tag(self.id(), self.epoch());
        if envelope.route_tag != expected_route {
            return Err(MessageError::BadRouteTag.into());
        }
        let mac_key = self.session.export_v3_key(V3_MAC_LABEL)?;
        envelope.verify_mac(&mac_key)?;
        let body_key = self.session.export_v3_key(V3_BODY_LABEL)?;
        let mls_ciphertext = decrypt_bytes(
            &body_key,
            &envelope.body,
            &v3_body_aad(&envelope.route_tag, envelope.body.len()),
        )?;
        let (mls_sender, plaintext) = self.session.decrypt_v3(&mls_ciphertext)?;
        let inner = V3InnerFrame::from_bytes(&plaintext)?;
        if inner.sender != mls_sender {
            return Err(GroupError::SenderMismatch);
        }
        if inner.conversation_id != self.id() {
            return Err(GroupError::WrongConversation);
        }
        let application_body = Zeroizing::new(inner.body.clone());
        let metadata = self.conversation.receive_v3(inner)?;
        Ok(DecryptedMessage {
            metadata,
            plaintext: application_body,
        })
    }

    /// Validate a locally persisted queued v3 frame against this group's
    /// current route and exporter key. The queue record itself is authenticated
    /// vault ciphertext; this check prevents a stale or foreign frame from
    /// being replayed after restart. Legacy v2 queue bytes are rejected.
    pub fn verify_queued_v3(&self, bytes: &[u8]) -> Result<(), GroupError> {
        let envelope = EnvelopeV3::from_bytes(bytes)?;
        let expected_route = v3_route_tag(self.id(), self.epoch());
        if envelope.route_tag != expected_route {
            return Err(MessageError::BadRouteTag.into());
        }
        let mac_key = self.session.export_v3_key(V3_MAC_LABEL)?;
        envelope.verify_mac(&mac_key)?;
        Ok(())
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

/// An MLS group whose every lifecycle operation carries an explicit
/// parent/channel binding. The wrapped [`MlsConversation`] is private and is
/// never exposed mutably, so callers cannot substitute a parent group or a
/// different channel group through this API.
///
/// This is a group-layer API boundary, not application-level channel ACLs:
/// setup frames, envelope routing, persistence labels, and GUI claims remain
/// legacy until P1c–P1f are implemented.
pub struct MlsChannelGroup {
    binding: ChannelGroupBinding,
    conversation: MlsConversation,
}

impl MlsChannelGroup {
    /// Create the independent MLS group for one bound logical channel.
    pub fn create(identity: &Identity, binding: ChannelGroupBinding) -> Result<Self, GroupError> {
        let conversation = MlsConversation::create(identity, binding.group_id())?;
        Self::from_conversation(binding, conversation)
    }

    /// Vault-backed variant of [`Self::create`].
    pub fn create_with_storage(
        identity: &Identity,
        binding: ChannelGroupBinding,
        storage: Session,
    ) -> Result<Self, GroupError> {
        let conversation =
            MlsConversation::create_with_storage(identity, binding.group_id(), storage)?;
        Self::from_conversation(binding, conversation)
    }

    /// Restore a channel group through encrypted provider state. The caller's
    /// parent/channel binding selects the group ID; a wrong binding selects a
    /// different group and fails closed when that state is absent.
    pub fn load_with_storage(
        identity: &Identity,
        binding: ChannelGroupBinding,
        storage: Session,
    ) -> Result<Self, GroupError> {
        let conversation =
            MlsConversation::load_with_storage(identity, binding.group_id(), storage)?;
        Self::from_conversation(binding, conversation)
    }

    /// Generate a KeyPackage declared for this parent/channel binding.
    pub fn key_package(
        identity: &Identity,
        binding: ChannelGroupBinding,
    ) -> Result<ChannelKeyPackage, GroupError> {
        Ok(ChannelKeyPackage {
            binding,
            inner: MlsConversation::key_package(identity)?,
        })
    }

    /// Vault-backed variant of [`Self::key_package`].
    pub fn key_package_with_storage(
        identity: &Identity,
        binding: ChannelGroupBinding,
        storage: Session,
    ) -> Result<ChannelKeyPackage, GroupError> {
        Ok(ChannelKeyPackage {
            binding,
            inner: MlsConversation::key_package_with_storage(identity, storage)?,
        })
    }

    /// Add a peer whose KeyPackage declares the same binding as this group.
    pub fn add_member(
        &mut self,
        key_package: &ChannelKeyPackage,
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<ChannelWelcome, GroupError> {
        let (welcome, _commit) =
            self.add_member_parts(key_package, expected_peer, expected_public_key)?;
        Ok(welcome)
    }

    /// Add a peer and return its bound Welcome plus the signed MLS commit.
    pub fn add_member_parts(
        &mut self,
        key_package: &ChannelKeyPackage,
        expected_peer: PeerId,
        expected_public_key: &[u8],
    ) -> Result<(ChannelWelcome, Vec<u8>), GroupError> {
        self.check_key_package_binding(key_package)?;
        let (welcome, commit) = self.conversation.add_member_parts(
            key_package.bytes(),
            expected_peer,
            expected_public_key,
        )?;
        Ok((
            ChannelWelcome {
                binding: self.binding,
                bytes: welcome,
            },
            commit,
        ))
    }

    /// Join using a KeyPackage and Welcome that both declare the same binding.
    pub fn join(
        identity: &Identity,
        binding: ChannelGroupBinding,
        key_package: ChannelKeyPackage,
        welcome: &ChannelWelcome,
    ) -> Result<Self, GroupError> {
        if key_package.binding() != binding || welcome.binding() != binding {
            return Err(GroupError::WrongChannelBinding);
        }
        let conversation = MlsConversation::join(
            identity,
            binding.group_id(),
            key_package.inner,
            welcome.bytes(),
        )?;
        Self::from_conversation(binding, conversation)
    }

    pub fn binding(&self) -> ChannelGroupBinding {
        self.binding
    }

    pub fn parent_conversation_id(&self) -> [u8; 16] {
        self.binding.parent_conversation_id()
    }

    pub fn channel_id(&self) -> [u8; 16] {
        self.binding.channel_id()
    }

    /// MLS group ID for this channel, not the parent conversation ID.
    pub fn id(&self) -> [u8; 16] {
        self.conversation.id()
    }

    pub fn epoch(&self) -> u64 {
        self.conversation.epoch()
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.conversation.local_peer_id()
    }

    pub fn conversation(&self) -> &Conversation {
        self.conversation.conversation()
    }

    pub fn members(&self) -> Result<Vec<PeerId>, GroupError> {
        self.conversation.members()
    }

    pub fn remove_member(&mut self, peer: &PeerId) -> Result<Vec<u8>, GroupError> {
        self.conversation.remove_member(peer)
    }

    pub fn self_update_commit(&mut self) -> Result<Vec<u8>, GroupError> {
        self.conversation.self_update_commit()
    }

    pub fn process_commit(
        &mut self,
        commit_bytes: &[u8],
        expected_sender: &PeerId,
        expected_public_key: &[u8],
        operation: GroupOperation,
        expected_target: Option<PeerId>,
    ) -> Result<CommitOutcome, GroupError> {
        self.conversation.process_commit(
            commit_bytes,
            expected_sender,
            expected_public_key,
            operation,
            expected_target,
        )
    }

    pub fn delivery_state(&self, message_id: &[u8; 16]) -> Option<DeliveryState> {
        self.conversation.delivery_state(message_id)
    }

    pub fn next_sequence(&self) -> u64 {
        self.conversation.next_sequence()
    }

    pub fn restore_epoch(&mut self, epoch: u64) -> Result<(), GroupError> {
        self.conversation.restore_epoch(epoch)
    }

    pub fn restore_sequence(&mut self, sequence: u64) -> Result<(), GroupError> {
        self.conversation.restore_sequence(sequence)
    }

    pub fn restore_outgoing(
        &mut self,
        message_id: &[u8; 16],
        state: DeliveryState,
    ) -> Result<(), GroupError> {
        self.conversation.restore_outgoing(message_id, state)
    }

    pub fn mark_queued(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_queued(message_id)
    }

    pub fn mark_sent_to_peer(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_sent_to_peer(message_id)
    }

    pub fn mark_failed(&mut self, message_id: &[u8; 16]) -> Result<(), GroupError> {
        self.conversation.mark_failed(message_id)
    }

    pub fn compose(
        &mut self,
        identity: &Identity,
        kind: MessageKind,
        plaintext: &[u8],
    ) -> Result<Envelope, GroupError> {
        self.conversation.compose(identity, kind, plaintext)
    }

    pub fn receipt(
        &mut self,
        identity: &Identity,
        status: ReceiptStatus,
        message_id: [u8; 16],
    ) -> Result<Envelope, GroupError> {
        self.conversation.receipt(identity, status, message_id)
    }

    pub fn receive(&mut self, envelope: Envelope) -> Result<DecryptedMessage, GroupError> {
        self.conversation.receive(envelope)
    }

    pub fn compose_v3(
        &mut self,
        identity: &Identity,
        kind: MessageKind,
        plaintext: &[u8],
    ) -> Result<(EnvelopeV3, [u8; 16]), GroupError> {
        self.conversation.compose_v3(identity, kind, plaintext)
    }

    pub fn receipt_v3(
        &mut self,
        identity: &Identity,
        status: ReceiptStatus,
        message_id: [u8; 16],
    ) -> Result<(EnvelopeV3, [u8; 16]), GroupError> {
        self.conversation.receipt_v3(identity, status, message_id)
    }

    pub fn receive_v3(&mut self, envelope: EnvelopeV3) -> Result<DecryptedMessage, GroupError> {
        self.conversation.receive_v3(envelope)
    }

    pub fn verify_queued_v3(&self, bytes: &[u8]) -> Result<(), GroupError> {
        self.conversation.verify_queued_v3(bytes)
    }

    fn from_conversation(
        binding: ChannelGroupBinding,
        conversation: MlsConversation,
    ) -> Result<Self, GroupError> {
        if conversation.id() != binding.group_id() {
            return Err(GroupError::WrongChannelBinding);
        }
        Ok(Self {
            binding,
            conversation,
        })
    }

    fn check_key_package_binding(&self, key_package: &ChannelKeyPackage) -> Result<(), GroupError> {
        if key_package.binding() != self.binding {
            return Err(GroupError::WrongChannelBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for MlsChannelGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlsChannelGroup")
            .field("binding", &self.binding)
            .field("group", &self.conversation)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod post_quantum_evaluation {
    use super::*;
    use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto};

    const PINNED_OPENMLS_VERSION: &str = "0.10.0-rc.1";
    const LOCKFILE: &str = include_str!("../../../Cargo.lock");

    /// Capability check only: the pinned provider must support the enabled
    /// hybrid KEM suite. This is not a quantum-resistance or migration claim.
    #[test]
    fn pinned_openmls_advertises_the_enabled_hybrid_ciphersuite() {
        let package = LOCKFILE
            .split("[[package]]")
            .find(|block| block.contains("name = \"openmls\""))
            .expect("openmls lockfile entry");
        assert!(package.contains(&format!("version = \"{PINNED_OPENMLS_VERSION}\"")));

        let provider = OpenMlsRustCrypto::default();
        let supported = provider.crypto().supported_ciphersuites();
        assert!(
            supported.contains(&CIPHERSUITE),
            "pinned RustCrypto provider does not support the hybrid suite"
        );
        assert_eq!(u16::from(CIPHERSUITE), CIPHERSUITE_ID);
        assert_eq!(
            Ciphersuite::try_from(CIPHERSUITE_ID).expect("known hybrid suite"),
            CIPHERSUITE
        );
    }

    #[test]
    fn hybrid_key_packages_and_welcomes_round_trip() {
        let alice = Identity::generate().expect("alice");
        let bob = Identity::generate().expect("bob");
        let conversation_id = [52u8; 16];
        let mut creator = MlsConversation::create(&alice, conversation_id).expect("creator group");
        let key_package = MlsConversation::key_package(&bob).expect("hybrid key package");

        assert!(
            key_package.bytes().len() > 256,
            "hybrid KEM key package should be larger than the classical form"
        );
        let welcome = creator
            .add_member(
                key_package.bytes(),
                bob.peer_id(),
                &bob.pq_role_public_bytes(IdentityRole::Mls)
                    .expect("bob PQ mls key"),
            )
            .expect("hybrid welcome");
        assert!(
            welcome.len() > 512,
            "hybrid KEM welcome should be larger than the classical form"
        );

        let mut joined = MlsConversation::join(&bob, conversation_id, key_package, &welcome)
            .expect("join hybrid group");
        assert_eq!(joined.epoch(), creator.epoch());
        assert_eq!(
            creator.members().expect("members"),
            joined.members().expect("members")
        );

        let ciphertext = creator
            .compose(&alice, MessageKind::Text, b"hybrid payload")
            .expect("compose hybrid");
        let decoded =
            Envelope::from_bytes(&ciphertext.to_bytes().expect("encoded")).expect("decode");
        let plaintext = joined.receive(decoded).expect("receive hybrid");
        assert_eq!(plaintext.plaintext.as_slice(), b"hybrid payload");
    }
}

#[cfg(test)]
mod v3_wire_tests {
    use super::*;

    fn pair(conversation_id: [u8; 16]) -> (Identity, MlsConversation, MlsConversation) {
        let alice = Identity::generate().expect("alice");
        let bob = Identity::generate().expect("bob");
        let mut creator = MlsConversation::create(&alice, conversation_id).expect("creator");
        let key_package = MlsConversation::key_package(&bob).expect("key package");
        let bob_key = bob
            .pq_role_public_bytes(IdentityRole::Mls)
            .expect("bob PQ MLS key");
        let welcome = creator
            .add_member(key_package.bytes(), bob.peer_id(), &bob_key)
            .expect("welcome");
        let joiner =
            MlsConversation::join(&bob, conversation_id, key_package, &welcome).expect("join");
        (alice, creator, joiner)
    }

    #[test]
    fn v3_round_trip_hides_stable_metadata_from_third_parties() {
        let (alice, mut sender, mut receiver) = pair([61u8; 16]);
        let secret = b"SECRET_V3_APPLICATION_BODY";
        let (envelope, message_id) = sender
            .compose_v3(&alice, MessageKind::Text, secret)
            .expect("compose v3");
        let wire = envelope.to_bytes().expect("encoded v3");

        assert_eq!(
            envelope.route_tag,
            v3_route_tag(sender.id(), sender.epoch())
        );
        assert!(!wire.windows(16).any(|w| w == sender.id()));
        assert!(!wire.windows(16).any(|w| w == message_id));
        assert!(
            !wire
                .windows(alice.peer_id().to_bytes().len())
                .any(|w| w == alice.peer_id().to_bytes())
        );
        assert!(!wire.windows(secret.len()).any(|w| w == secret));
        assert_eq!(&wire[..4], p2p_messaging::V3_MAGIC);

        let decoded = EnvelopeV3::from_bytes(&wire).expect("decode v3");
        let received = receiver.receive_v3(decoded).expect("receive v3");
        assert_eq!(received.plaintext.as_slice(), secret);
        assert_eq!(received.metadata.message_id, message_id);
        assert_eq!(received.metadata.sender, alice.peer_id());
        assert_eq!(received.metadata.kind, MessageKind::Text);
        assert_eq!(received.metadata.sender_sequence, 1);
        assert!(!format!("{received:?}").contains("SECRET_V3"));
    }

    #[test]
    fn v3_rejects_tampering_wrong_route_legacy_wire_and_foreign_groups() {
        let (alice, mut sender, mut receiver) = pair([62u8; 16]);
        let (envelope, _) = sender
            .compose_v3(&alice, MessageKind::Text, b"authenticated body")
            .expect("compose v3");
        let wire = envelope.to_bytes().expect("encoded v3");

        sender.verify_queued_v3(&wire).expect("local queue check");

        let mut body_tampered = envelope.clone();
        body_tampered.body[0] ^= 0x01;
        assert!(matches!(
            receiver.receive_v3(body_tampered),
            Err(GroupError::Message(MessageError::BadMac))
        ));

        let mut wrong_route = envelope.clone();
        wrong_route.route_tag[0] ^= 0x01;
        assert!(matches!(
            receiver.receive_v3(wrong_route),
            Err(GroupError::Message(MessageError::BadRouteTag))
        ));

        let legacy = sender
            .compose(&alice, MessageKind::Text, b"legacy v2")
            .expect("legacy compose");
        let legacy_bytes = legacy.to_bytes().expect("legacy bytes");
        assert!(EnvelopeV3::from_bytes(&legacy_bytes).is_err());
        assert!(sender.verify_queued_v3(&legacy_bytes).is_err());

        let (_other_alice, mut foreign, _foreign_peer) = pair([63u8; 16]);
        assert!(matches!(
            foreign.receive_v3(envelope),
            Err(GroupError::Message(MessageError::BadRouteTag))
        ));
    }

    #[test]
    fn v3_replay_and_sequence_regression_fail_after_decryption() {
        let (alice, mut sender, mut receiver) = pair([64u8; 16]);
        let (first, _) = sender
            .compose_v3(&alice, MessageKind::Text, b"first")
            .expect("first");
        let (second, _) = sender
            .compose_v3(&alice, MessageKind::Text, b"second")
            .expect("second");
        let first_bytes = first.to_bytes().expect("first bytes");
        let second_bytes = second.to_bytes().expect("second bytes");

        receiver
            .receive_v3(EnvelopeV3::from_bytes(&second_bytes).expect("decode second"))
            .expect("receive second");
        // MLS ratchet state rejects an already-processed ciphertext; the
        // conversation layer independently rejects replay and regression for
        // freshly encrypted frames (covered in p2p-messaging tests).
        let replay = receiver
            .receive_v3(EnvelopeV3::from_bytes(&second_bytes).expect("decode replay"))
            .expect_err("an exact v3 replay must fail closed");
        assert!(
            matches!(replay, GroupError::Mls(_) | GroupError::Message(_)),
            "unexpected replay error: {replay:?}"
        );
        let regression = receiver
            .receive_v3(EnvelopeV3::from_bytes(&first_bytes).expect("decode first"))
            .expect_err("an older v3 frame must fail closed");
        assert!(
            matches!(regression, GroupError::Mls(_) | GroupError::Message(_)),
            "unexpected regression error: {regression:?}"
        );
    }

    #[test]
    fn v3_route_tag_and_exporter_keys_are_epoch_bound() {
        let (_alice, sender, _receiver) = pair([65u8; 16]);
        let epoch = sender.epoch();
        let tag = v3_route_tag(sender.id(), epoch);
        assert_ne!(tag, v3_route_tag(sender.id(), epoch + 1));
        assert_ne!(tag, v3_route_tag([0xff; 16], epoch));

        let mac = sender.session.export_v3_key(V3_MAC_LABEL).expect("mac key");
        let body = sender
            .session
            .export_v3_key(V3_BODY_LABEL)
            .expect("body key");
        assert_ne!(mac.as_slice(), body.as_slice());
    }
}

#[cfg(test)]
mod padding_tests {
    use super::*;

    #[test]
    fn application_plaintext_is_padded_to_a_fixed_bucket() {
        let padded =
            pad_application_plaintext(b"short").expect("short plaintext fits the smallest bucket");
        assert_eq!(padded.len(), PADDING_BUCKETS[0]);
        assert_eq!(padded[0], PADDING_TAG);
        assert!(
            padded[PADDING_HEADER_LEN + 5..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            strip_application_padding(&padded)
                .expect("valid padding")
                .as_slice(),
            b"short"
        );

        let exact = vec![7u8; PADDING_BUCKETS[0] - PADDING_HEADER_LEN];
        assert_eq!(
            pad_application_plaintext(&exact).expect("exact fit").len(),
            PADDING_BUCKETS[0]
        );
        let one_over = vec![7u8; PADDING_BUCKETS[0] - PADDING_HEADER_LEN + 1];
        assert_eq!(
            pad_application_plaintext(&one_over)
                .expect("next bucket")
                .len(),
            PADDING_BUCKETS[1]
        );
    }

    #[test]
    fn hostile_padding_is_rejected_before_returning_plaintext() {
        let valid = pad_application_plaintext(b"payload").expect("valid padding");
        assert!(strip_application_padding(&[]).is_err());
        assert!(strip_application_padding(&vec![0u8; PADDING_BUCKETS[0]]).is_err());
        assert!(strip_application_padding(&vec![PADDING_TAG; PADDING_BUCKETS[0]]).is_err());

        let mut wrong_length = valid.clone();
        wrong_length[1..PADDING_HEADER_LEN].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            strip_application_padding(&wrong_length),
            Err(GroupError::InvalidPadding)
        ));

        let mut extended_length = valid.clone();
        let claimed = (valid.len() - PADDING_HEADER_LEN + 1) as u32;
        extended_length[1..PADDING_HEADER_LEN].copy_from_slice(&claimed.to_le_bytes());
        assert!(matches!(
            strip_application_padding(&extended_length),
            Err(GroupError::InvalidPadding)
        ));

        let mut dirty_tail = valid.clone();
        *dirty_tail.last_mut().expect("non-empty bucket") = 1;
        assert!(matches!(
            strip_application_padding(&dirty_tail),
            Err(GroupError::InvalidPadding)
        ));
    }

    #[test]
    fn oversized_plaintext_fails_closed_before_mls_encryption() {
        let oversized = vec![1u8; MAX_PADDED_PLAINTEXT + 1];
        assert!(matches!(
            pad_application_plaintext(&oversized),
            Err(GroupError::PlaintextTooLarge { .. })
        ));
        assert!(matches!(
            pad_application_plaintext(&[]),
            Err(GroupError::EmptyPlaintext)
        ));
    }
}
