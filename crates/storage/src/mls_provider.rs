//! Vault-backed OpenMLS `StorageProvider` adapter (ADR-0014 Phase 3).
//!
//! This adapter never writes to SQLite directly from a provider method. Every
//! getter and setter works against an in-memory staging set: writes are
//! visible to later reads in the same MLS operation, and a caller that drops
//! or discards the operation leaves the vault untouched. `flush` applies the
//! whole staged set as one SQLite transaction, recomputes the affected group
//! chains, advances the v2 anchor, and commits atomically.
//!
//! This phase does **not** implement `MlsGroup::load` wiring, controller
//! restore, or any GUI change. Runtime MLS state stays memory-only until the
//! application explicitly uses this adapter and flushes it.

use std::cell::RefCell;
use std::collections::BTreeMap;

use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use super::mls_state::StagedMlsWrite;
use super::{Session, StorageError};

/// Reserved group id used for provider entries that are not scoped to a group
/// (signature keys, KeyPackages, epoch key pairs, and PSKs). The messenger
/// generates 16-byte conversation ids randomly; an application must never use
/// this value as a real group id, and group-scoped methods reject it.
const GLOBAL_GROUP: [u8; 16] = *b"P2PMLSGLOBALROOT";

const JOIN_CONFIG_LABEL: &str = "MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &str = "OwnLeafNodes";
const GROUP_STATE_LABEL: &str = "GroupState";
const QUEUED_PROPOSAL_LABEL: &str = "QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &str = "ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &str = "OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &str = "EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &str = "ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &str = "MessageSecrets";
const TREE_LABEL: &str = "Tree";
const GROUP_CONTEXT_LABEL: &str = "GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &str = "InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &str = "ConfirmationTag";
const SIGNATURE_KEY_PAIR_LABEL: &str = "SignatureKeyPair";
const ENCRYPTION_KEY_PAIR_LABEL: &str = "EncryptionKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &str = "EpochKeyPairs";
const KEY_PACKAGE_LABEL: &str = "KeyPackage";
const PSK_LABEL: &str = "Psk";

/// Errors from the vault-backed provider. Serialization failures are folded
/// into a generic category so serialized OpenMLS bytes never reach logs.
#[derive(Debug, Error)]
pub enum MlsProviderError {
    #[error("MLS provider storage error: {0}")]
    Vault(#[from] StorageError),
    #[error("MLS provider could not serialize or deserialize a value")]
    Serialization,
    #[error("OpenMLS group id is not a supported 16-byte conversation id")]
    UnsupportedGroupId,
    #[error("MLS provider value is outside the configured bounds")]
    OutOfBounds,
}

impl From<serde_json::Error> for MlsProviderError {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}

/// Extract raw bytes from a serialized OpenMLS key. Tolerates the nested
/// `{"value":{"vec":[...]}}` form used by `VLBytes` as well as a plain array.
/// Returns an empty vector for any element outside the byte range.
fn extract_bytes(value: &serde_json::Value) -> Vec<u8> {
    match value {
        serde_json::Value::Array(items) => {
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                match item.as_u64() {
                    Some(number) if number <= u8::MAX as u64 => bytes.push(number as u8),
                    _ => return Vec::new(),
                }
            }
            bytes
        }
        serde_json::Value::Object(map) => {
            for key in ["vec", "value", "bytes"] {
                if let Some(inner) = map.get(key) {
                    let bytes = extract_bytes(inner);
                    if !bytes.is_empty() {
                        return bytes;
                    }
                }
            }
            Vec::new()
        }
        serde_json::Value::String(text) => text.as_bytes().to_vec(),
        _ => Vec::new(),
    }
}

type StageKey = ([u8; 16], String, Vec<u8>);

enum StagedValue {
    Put(Zeroizing<Vec<u8>>),
    Delete,
}

/// A single-operation, transactionally flushed OpenMLS storage provider.
pub struct StagedMlsProvider {
    session: RefCell<Session>,
    staged: RefCell<BTreeMap<StageKey, StagedValue>>,
    epochs: RefCell<BTreeMap<[u8; 16], u64>>,
}

impl StagedMlsProvider {
    /// Create a provider over an unlocked vault session.
    pub fn new(session: Session) -> Self {
        Self {
            session: RefCell::new(session),
            staged: RefCell::new(BTreeMap::new()),
            epochs: RefCell::new(BTreeMap::new()),
        }
    }

    /// Set the MLS epoch used for subsequent writes to one group. The
    /// application advances this when OpenMLS successfully commits an epoch;
    /// until then the group starts at epoch 0.
    pub fn set_group_epoch(&self, group_id: &[u8; 16], epoch: u64) -> Result<(), MlsProviderError> {
        if *group_id == GLOBAL_GROUP {
            return Err(MlsProviderError::UnsupportedGroupId);
        }
        self.epochs.borrow_mut().insert(*group_id, epoch);
        Ok(())
    }

    /// Number of staged writes and tombstones in the current operation.
    pub fn staged_len(&self) -> usize {
        self.staged.borrow().len()
    }

    /// Discard every staged change and epoch override. Call this when an MLS
    /// operation fails or validation rejects the result; no vault write has
    /// happened at that point.
    pub fn discard(&self) {
        self.staged.borrow_mut().clear();
        self.epochs.borrow_mut().clear();
    }

    /// Flush the whole staged set as one SQLite transaction and advance the
    /// anchor. On any error the transaction is rolled back and the staged set
    /// is retained so the caller may retry or discard it explicitly.
    pub fn flush(&self) -> Result<(), MlsProviderError> {
        let staged = self.staged.borrow();
        let epochs = self.epochs.borrow();
        let mut writes = Vec::with_capacity(staged.len());
        for ((group_id, label, key), value) in staged.iter() {
            let epoch = if *group_id == GLOBAL_GROUP {
                0
            } else {
                epochs.get(group_id).copied().unwrap_or(0)
            };
            writes.push(StagedMlsWrite {
                group_id: *group_id,
                label: label.clone(),
                key: key.clone(),
                epoch,
                value: match value {
                    StagedValue::Put(value) => Some(value.clone()),
                    StagedValue::Delete => None,
                },
            });
        }
        self.session.borrow_mut().apply_staged_writes(&writes)?;
        drop(staged);
        self.staged.borrow_mut().clear();
        Ok(())
    }

    fn group_bytes(
        group_id: &impl traits::GroupId<CURRENT_VERSION>,
    ) -> Result<[u8; 16], MlsProviderError> {
        // OpenMLS serializes `GroupId` as `{"value":{"vec":[...]}}`. Walk the
        // tagged structure so this works for both the pinned `VLBytes` form and
        // the newer compact byte-vector form.
        let raw = extract_bytes(&serde_json::to_value(group_id)?);
        if raw.len() != 16 || raw.as_slice() == GLOBAL_GROUP {
            return Err(MlsProviderError::UnsupportedGroupId);
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&raw);
        Ok(bytes)
    }

    fn key_bytes<K: Serialize>(key: &K) -> Result<Vec<u8>, MlsProviderError> {
        Ok(serde_json::to_vec(key)?)
    }

    fn value_bytes<E: Serialize + ?Sized>(
        value: &E,
    ) -> Result<Zeroizing<Vec<u8>>, MlsProviderError> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.is_empty() || bytes.len() > super::mls_state::MAX_MLS_STATE_BYTES {
            return Err(MlsProviderError::OutOfBounds);
        }
        Ok(Zeroizing::new(bytes))
    }

    fn stage_put(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: Vec<u8>,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), MlsProviderError> {
        if label.is_empty() || label.len() > 64 || key.len() > 256 {
            return Err(MlsProviderError::OutOfBounds);
        }
        self.staged
            .borrow_mut()
            .insert((group_id, label.to_owned(), key), StagedValue::Put(value));
        Ok(())
    }

    fn stage_delete(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: Vec<u8>,
    ) -> Result<(), MlsProviderError> {
        if label.is_empty() || label.len() > 64 || key.len() > 256 {
            return Err(MlsProviderError::OutOfBounds);
        }
        self.staged
            .borrow_mut()
            .insert((group_id, label.to_owned(), key), StagedValue::Delete);
        Ok(())
    }

    /// Read a staged or persisted value as raw serialized bytes.
    fn read_raw(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, MlsProviderError> {
        if let Some(value) = self
            .staged
            .borrow()
            .get(&(group_id, label.to_owned(), key.to_vec()))
        {
            return Ok(match value {
                StagedValue::Put(value) => Some(value.to_vec()),
                StagedValue::Delete => None,
            });
        }
        let loaded = self
            .session
            .borrow()
            .load_mls_state(&group_id, label, key)?;
        Ok(loaded.map(|value| value.to_vec()))
    }

    /// Read a staged or persisted list of serialized values.
    fn read_list_raw(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: &[u8],
    ) -> Result<Vec<Vec<u8>>, MlsProviderError> {
        match self.read_raw(group_id, label, key)? {
            Some(bytes) => {
                let list: Vec<Vec<u8>> = serde_json::from_slice(&bytes)?;
                Ok(list)
            }
            None => Ok(Vec::new()),
        }
    }

    fn append_raw(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: Vec<u8>,
        item: Vec<u8>,
    ) -> Result<(), MlsProviderError> {
        let mut list = self.read_list_raw(group_id, label, &key)?;
        list.push(item);
        let bytes = Zeroizing::new(serde_json::to_vec(&list)?);
        self.stage_put(group_id, label, key, bytes)
    }

    fn remove_item_raw(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: Vec<u8>,
        item: &[u8],
    ) -> Result<(), MlsProviderError> {
        let mut list = self.read_list_raw(group_id, label, &key)?;
        if let Some(position) = list.iter().position(|value| value.as_slice() == item) {
            list.remove(position);
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&list)?);
        self.stage_put(group_id, label, key, bytes)
    }

    fn read_entity<E: openmls_traits::storage::Entity<CURRENT_VERSION>>(
        &self,
        group_id: [u8; 16],
        label: &str,
        key: &[u8],
    ) -> Result<Option<E>, MlsProviderError> {
        match self.read_raw(group_id, label, key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[openmls_traits::maybe_async(AFIT)]
impl StorageProvider<CURRENT_VERSION> for StagedMlsProvider {
    type Error = MlsProviderError;

    // --- group state writers ---

    async fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(group, JOIN_CONFIG_LABEL, key, Self::value_bytes(config)?)
    }

    async fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.append_raw(
            group,
            OWN_LEAF_NODES_LABEL,
            key,
            Self::value_bytes(leaf_node)?.to_vec(),
        )
    }

    async fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let proposal_key = Self::key_bytes(&(group_id, proposal_ref))?;
        self.stage_put(
            group,
            QUEUED_PROPOSAL_LABEL,
            proposal_key,
            Self::value_bytes(proposal)?,
        )?;
        let refs_key = Self::key_bytes(group_id)?;
        self.append_raw(
            group,
            PROPOSAL_QUEUE_REFS_LABEL,
            refs_key,
            Self::value_bytes(proposal_ref)?.to_vec(),
        )
    }

    async fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(group, TREE_LABEL, key, Self::value_bytes(tree)?)
    }

    async fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            INTERIM_TRANSCRIPT_HASH_LABEL,
            key,
            Self::value_bytes(interim_transcript_hash)?,
        )
    }

    async fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            GROUP_CONTEXT_LABEL,
            key,
            Self::value_bytes(group_context)?,
        )
    }

    async fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            CONFIRMATION_TAG_LABEL,
            key,
            Self::value_bytes(confirmation_tag)?,
        )
    }

    async fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            GROUP_STATE_LABEL,
            key,
            Self::value_bytes(group_state)?,
        )
    }

    async fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            MESSAGE_SECRETS_LABEL,
            key,
            Self::value_bytes(message_secrets)?,
        )
    }

    async fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            RESUMPTION_PSK_STORE_LABEL,
            key,
            Self::value_bytes(resumption_psk_store)?,
        )
    }

    async fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            OWN_LEAF_NODE_INDEX_LABEL,
            key,
            Self::value_bytes(own_leaf_index)?,
        )
    }

    async fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let key = Self::key_bytes(group_id)?;
        self.stage_put(
            group,
            EPOCH_SECRETS_LABEL,
            key,
            Self::value_bytes(group_epoch_secrets)?,
        )
    }

    // --- crypto object writers (global scope) ---

    async fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let key = Self::key_bytes(public_key)?;
        self.stage_put(
            GLOBAL_GROUP,
            SIGNATURE_KEY_PAIR_LABEL,
            key,
            Self::value_bytes(signature_key_pair)?,
        )
    }

    async fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        let key = Self::key_bytes(public_key)?;
        self.stage_put(
            GLOBAL_GROUP,
            ENCRYPTION_KEY_PAIR_LABEL,
            key,
            Self::value_bytes(key_pair)?,
        )
    }

    async fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let mut key = Self::key_bytes(group_id)?;
        key.extend_from_slice(&Self::key_bytes(epoch)?);
        key.extend_from_slice(&Self::key_bytes(&leaf_index)?);
        self.stage_put(
            group,
            EPOCH_KEY_PAIRS_LABEL,
            key,
            Self::value_bytes(key_pairs)?,
        )
    }

    async fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = Self::key_bytes(hash_ref)?;
        self.stage_put(
            GLOBAL_GROUP,
            KEY_PACKAGE_LABEL,
            key,
            Self::value_bytes(key_package)?,
        )
    }

    async fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        let key = Self::key_bytes(psk_id)?;
        self.stage_put(GLOBAL_GROUP, PSK_LABEL, key, Self::value_bytes(psk)?)
    }

    // --- group state readers ---

    async fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, JOIN_CONFIG_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let raw = self.read_list_raw(group, OWN_LEAF_NODES_LABEL, &Self::key_bytes(group_id)?)?;
        raw.iter()
            .map(|bytes| serde_json::from_slice(bytes).map_err(MlsProviderError::from))
            .collect()
    }

    async fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let raw = self.read_list_raw(
            group,
            PROPOSAL_QUEUE_REFS_LABEL,
            &Self::key_bytes(group_id)?,
        )?;
        raw.iter()
            .map(|bytes| serde_json::from_slice(bytes).map_err(MlsProviderError::from))
            .collect()
    }

    async fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.queued_proposal_refs(group_id).await?;
        let group = Self::group_bytes(group_id)?;
        let mut out = Vec::with_capacity(refs.len());
        for proposal_ref in refs {
            let key = Self::key_bytes(&(group_id, &proposal_ref))?;
            let proposal: QueuedProposal = self
                .read_entity(group, QUEUED_PROPOSAL_LABEL, &key)?
                .ok_or(MlsProviderError::Serialization)?;
            out.push((proposal_ref, proposal));
        }
        Ok(out)
    }

    async fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, TREE_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, GROUP_CONTEXT_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(
            group,
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &Self::key_bytes(group_id)?,
        )
    }

    async fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, CONFIRMATION_TAG_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, GROUP_STATE_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, MESSAGE_SECRETS_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(
            group,
            RESUMPTION_PSK_STORE_LABEL,
            &Self::key_bytes(group_id)?,
        )
    }

    async fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(
            group,
            OWN_LEAF_NODE_INDEX_LABEL,
            &Self::key_bytes(group_id)?,
        )
    }

    async fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.read_entity(group, EPOCH_SECRETS_LABEL, &Self::key_bytes(group_id)?)
    }

    async fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read_entity(
            GLOBAL_GROUP,
            SIGNATURE_KEY_PAIR_LABEL,
            &Self::key_bytes(public_key)?,
        )
    }

    async fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_entity(
            GLOBAL_GROUP,
            ENCRYPTION_KEY_PAIR_LABEL,
            &Self::key_bytes(public_key)?,
        )
    }

    async fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let mut key = Self::key_bytes(group_id)?;
        key.extend_from_slice(&Self::key_bytes(epoch)?);
        key.extend_from_slice(&Self::key_bytes(&leaf_index)?);
        let raw = self.read_raw(group, EPOCH_KEY_PAIRS_LABEL, &key)?;
        match raw {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    async fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read_entity(GLOBAL_GROUP, KEY_PACKAGE_LABEL, &Self::key_bytes(hash_ref)?)
    }

    async fn psk<
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
        PskId: traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_entity(GLOBAL_GROUP, PSK_LABEL, &Self::key_bytes(psk_id)?)
    }

    // --- deleters ---

    async fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let ref_bytes = Self::value_bytes(proposal_ref)?;
        self.remove_item_raw(
            group,
            PROPOSAL_QUEUE_REFS_LABEL,
            Self::key_bytes(group_id)?,
            &ref_bytes,
        )?;
        self.stage_delete(
            group,
            QUEUED_PROPOSAL_LABEL,
            Self::key_bytes(&(group_id, proposal_ref))?,
        )
    }

    async fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, OWN_LEAF_NODES_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, JOIN_CONFIG_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, TREE_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, CONFIRMATION_TAG_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, GROUP_STATE_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, GROUP_CONTEXT_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(
            group,
            INTERIM_TRANSCRIPT_HASH_LABEL,
            Self::key_bytes(group_id)?,
        )
    }

    async fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, MESSAGE_SECRETS_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(
            group,
            RESUMPTION_PSK_STORE_LABEL,
            Self::key_bytes(group_id)?,
        )
    }

    async fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, OWN_LEAF_NODE_INDEX_LABEL, Self::key_bytes(group_id)?)
    }

    async fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        self.stage_delete(group, EPOCH_SECRETS_LABEL, Self::key_bytes(group_id)?)
    }

    async fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let refs_key = Self::key_bytes(group_id)?;
        let refs = self.read_list_raw(group, PROPOSAL_QUEUE_REFS_LABEL, &refs_key)?;
        for bytes in refs {
            let proposal_ref: ProposalRef = serde_json::from_slice(&bytes)?;
            self.stage_delete(
                group,
                QUEUED_PROPOSAL_LABEL,
                Self::key_bytes(&(group_id, &proposal_ref))?,
            )?;
        }
        self.stage_delete(group, PROPOSAL_QUEUE_REFS_LABEL, refs_key)
    }

    async fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.stage_delete(
            GLOBAL_GROUP,
            SIGNATURE_KEY_PAIR_LABEL,
            Self::key_bytes(public_key)?,
        )
    }

    async fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.stage_delete(
            GLOBAL_GROUP,
            ENCRYPTION_KEY_PAIR_LABEL,
            Self::key_bytes(public_key)?,
        )
    }

    async fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let group = Self::group_bytes(group_id)?;
        let mut key = Self::key_bytes(group_id)?;
        key.extend_from_slice(&Self::key_bytes(epoch)?);
        key.extend_from_slice(&Self::key_bytes(&leaf_index)?);
        self.stage_delete(group, EPOCH_KEY_PAIRS_LABEL, key)
    }

    async fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.stage_delete(GLOBAL_GROUP, KEY_PACKAGE_LABEL, Self::key_bytes(hash_ref)?)
    }

    async fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.stage_delete(GLOBAL_GROUP, PSK_LABEL, Self::key_bytes(psk_id)?)
    }
}
