//! Application-level controller for MLS setup and messaging.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use libp2p::PeerId as SwarmPeerId;
use libp2p::multiaddr::Protocol;
use libp2p_identity::PeerId;
use p2p_files::{
    FileConfig, FileEnvelope, FileMessage, FileTransferInfo, IncomingFile, OutgoingFile,
    ReleaseApproval, ReleasedFile, TransferDirection,
};
use p2p_groups::{
    ChannelGroupBinding, ChannelKeyPackage, ChannelWelcome, GroupOperation, MlsChannelGroup,
    MlsConversation, MlsKeyPackage, channel_group_id,
};
use p2p_identity::Identity;
use p2p_messaging::{DeliveryState, EnvelopeV4, MessageKind, ReceiptStatus, random_id};
use p2p_network::{
    ConnectionState, FileEvent, FileRequestId, FileResponseId, MessageEvent, MessageRequestId,
    Network, NetworkConfig, NetworkPrivacyStatus, SetupEvent, SetupResponseId,
};
use p2p_security::{ScanRequest, ScanStatus, SecurityConfig};
use p2p_storage::{ControlRecordOutcome, GLOBAL_PROVIDER_GROUP, Session};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::channel::{
    ChannelFrame, ChannelFrameKind, DEFAULT_CHANNEL_ID, MAX_CHANNEL_MEMBERS,
    MAX_CHANNEL_NAME_BYTES, MAX_CHANNELS_PER_GROUP,
};
use crate::setup::{ChannelScope, TransactionId};
use crate::{ChatError, SetupEnvelope, SetupMessage};

/// Default maximum quiet period for one active file transfer. The timer is
/// reset by authenticated progress, so a slow transfer with steady
/// acknowledgements is not interrupted.
pub const DEFAULT_FILE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound accepted by [`MessengerController::start_with_transfer_timeout`].
pub const MAX_FILE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(3600);

/// How far a 1:1 MLS setup has progressed. A `Joined` status on the inviter
/// requires a verified WelcomeAck; on the joiner it requires a verified
/// Welcome that OpenMLS accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationStatus {
    KeyPackageRequested,
    KeyPackageReceived,
    WelcomeSent,
    Joined,
    Failed(String),
}

impl ConversationStatus {
    /// Honest, user-facing text. It never claims verification or delivery.
    pub fn description(&self) -> &str {
        match self {
            Self::KeyPackageRequested => "KeyPackage requested (not joined)",
            Self::KeyPackageReceived => "KeyPackage received (not joined)",
            Self::WelcomeSent => "Welcome sent (join not acknowledged)",
            Self::Joined => "MLS group joined",
            Self::Failed(reason) => reason,
        }
    }
}

/// Honest redial intent for one saved user address. This is never a connection
/// claim; only [`MessengerController::connection_state`] reports observed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedialState {
    /// No user-supplied address is saved for this peer.
    NoSavedAddress,
    /// An address is saved, but no retry is pending or in progress.
    Idle,
    /// The user disconnected; no automatic redial will run.
    Suppressed,
    /// A bounded automatic retry is waiting for its delay.
    Scheduled {
        attempt: u32,
        delay: Duration,
        remaining: Duration,
    },
    /// A bounded automatic retry was handed to the dial queue.
    Dialing { attempt: u32 },
    /// The configured retry limit was reached.
    Exhausted { attempts: u32 },
}

impl RedialState {
    pub fn description(&self) -> String {
        match self {
            Self::NoSavedAddress => "No saved address".to_owned(),
            Self::Idle => "Address saved (no retry pending)".to_owned(),
            Self::Suppressed => "Automatic redial stopped by user disconnect".to_owned(),
            Self::Scheduled {
                attempt, remaining, ..
            } => format!("Redial {attempt} scheduled in {} ms", remaining.as_millis()),
            Self::Dialing { attempt } => format!("Redial {attempt} in progress"),
            Self::Exhausted { attempts } => {
                format!("Redial limit reached ({attempts} attempts)")
            }
        }
    }
}

/// Public snapshot of one local MLS conversation. `peer` remains the single
/// remote peer shown by the legacy 1:1 view; `members` and `admin` describe the
/// real MLS group. Every field is observed local state, never a delivery claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationInfo {
    pub conversation_id: [u8; 16],
    pub peer: PeerId,
    pub admin: PeerId,
    pub members: Vec<PeerId>,
    pub epoch: u64,
    pub status: ConversationStatus,
    pub pending_operation: Option<GroupOperation>,
    pub channels: Vec<ChannelInfo>,
    pub active_channel: Option<[u8; 16]>,
}

/// Where a channel's text and delivery receipts are encrypted. This is a
/// transport observation, not a complete channel access-control claim: policy
/// frames and the default channel always stay on the parent MLS group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelGroupStatus {
    /// The default channel uses the parent MLS group; all parent members have
    /// its keys.
    DefaultOnParent,
    /// A non-default channel's bound derived MLS group has converged.
    DerivedReady,
    /// A derived group exists but bound setup is not complete.
    DerivedSettingUp { awaited: usize },
    /// A non-default channel has no derived group yet.
    Missing,
}

impl ChannelGroupStatus {
    /// Whether text and receipts for this channel are currently encryptable by
    /// the controller. This says nothing about parent policy confidentiality.
    pub fn is_ready_for_text(self) -> bool {
        matches!(self, Self::DefaultOnParent | Self::DerivedReady)
    }
}

/// Public snapshot of one channel inside a joined MLS group. Parent policy
/// receipts and derived text-group readiness are deliberately separate: the
/// first is an application-policy observation, the second is the actual
/// transport boundary for non-default text. Neither is a complete ACL claim.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    pub channel_id: [u8; 16],
    pub name: String,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
    pub revision: u32,
    /// False while a local policy change is waiting for member receipts.
    pub policy_acknowledged: bool,
    /// Where channel text/receipts are encrypted and whether that group is
    /// ready. Default traffic remains on the parent group.
    pub group_status: ChannelGroupStatus,
}

impl fmt::Debug for ChannelInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelInfo")
            .field("channel_id", &hex(&self.channel_id))
            .field("name_len", &self.name.len())
            .field("name", &"<redacted>")
            .field("creator", &self.creator.to_string())
            .field("members", &self.members.len())
            .field("revision", &self.revision)
            .field("policy_acknowledged", &self.policy_acknowledged)
            .field("group_status", &self.group_status)
            .finish_non_exhaustive()
    }
}

/// Encrypted application-policy snapshot for one joined conversation. This is
/// `CHN1` application state, not an OpenMLS provider entry; it is stored under
/// the group blind index with a distinct authenticated label. The label remains
/// `/v1` so existing records stay readable; the authenticated record version is
/// `/v2` and adds pending receipts, queued ciphertext, and sequence state.
const PERSISTED_CONVERSATION_LABEL: &str = "p2p.app.conversation/v1";
const PERSISTED_CONVERSATION_V1: u8 = 1;
const PERSISTED_CONVERSATION_VERSION: u8 = 2;
/// Durable replay outcomes for non-repeatable group requests. These live in
/// the reserved global provider bucket so they survive restart without being
/// mistaken for a conversation by `mls_group_ids()`.
const PERSISTED_GROUP_ACK_LABEL: &str = "p2p.app.group-ack/v1";
const GROUP_ACK_VERSION: u8 = 2;
const GROUP_ACK_COMMIT_CODE: u8 = 1;
const GROUP_ACK_WELCOME_CODE: u8 = 2;
const GROUP_ACK_CHANNEL_COMMIT_CODE: u8 = 3;
const GROUP_ACK_CHANNEL_WELCOME_CODE: u8 = 4;
/// Encrypted application binding for one derived channel group. It is stored
/// under the derived group ID with a distinct authenticated label, so parent
/// policy restore and channel-group restore cannot consume each other's record.
const PERSISTED_CHANNEL_GROUP_LABEL: &str = "p2p.app.channel-group/v1";
const PERSISTED_CHANNEL_GROUP_VERSION: u8 = 1;

const MAX_PENDING_RECEIPTS: usize = 64;
const MAX_OFFLINE_QUEUE: usize = 16;
const MAX_QUEUED_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_PENDING_OPERATION_BYTES: usize = 16 * 1024;

const OUTGOING_QUEUED_CODE: u8 = 2;
const OUTGOING_SENT_CODE: u8 = 3;

fn default_next_sequence() -> u64 {
    1
}

#[derive(Serialize, Deserialize)]
struct PersistedChannel {
    id: [u8; 16],
    name: String,
    creator: Vec<u8>,
    members: Vec<Vec<u8>>,
    revision: u32,
    #[serde(default)]
    last_frame_id: Option<[u8; 16]>,
}

#[derive(Serialize, Deserialize)]
struct PersistedReceiptExpectation {
    message_id: [u8; 16],
    peers: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct PersistedOutgoing {
    message_id: [u8; 16],
    state_code: u8,
}

#[derive(Serialize, Deserialize)]
struct PersistedQueuedMessage {
    peer: Vec<u8>,
    conversation_id: [u8; 16],
    message_id: [u8; 16],
    envelope_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PersistedPendingDetail {
    transaction_id: [u8; 16],
    operation: u8,
    target: Option<Vec<u8>>,
    commit: Vec<u8>,
    awaited: Vec<(Vec<u8>, bool)>,
    welcome_target: Option<Vec<u8>>,
    welcome: Option<Vec<u8>>,
    welcome_acked: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedPendingOperation {
    Flag(bool),
    Detail(PersistedPendingDetail),
}

impl PersistedPendingOperation {
    fn is_pending(&self) -> bool {
        match self {
            Self::Flag(pending) => *pending,
            Self::Detail(_) => true,
        }
    }
}

/// Encrypted outcome of one already-applied group request. A replayed commit or
/// Welcome is answered from this record without touching MLS state again.
#[derive(Serialize, Deserialize)]
struct PersistedGroupAck {
    version: u8,
    response: u8,
    conversation_id: [u8; 16],
    transaction_id: [u8; 16],
    operation: u8,
    accepted: bool,
    /// Present in version 2 records. A parent group ack and a channel ack are
    /// never interchangeable, even when all other fields are identical.
    #[serde(default)]
    channel_id: Option<[u8; 16]>,
}

#[derive(Serialize, Deserialize)]
struct PersistedConversation {
    version: u8,
    conversation_id: [u8; 16],
    peer: Vec<u8>,
    admin: Vec<u8>,
    members: Vec<Vec<u8>>,
    status_code: u8,
    status_reason: Option<String>,
    channels: Vec<PersistedChannel>,
    active_channel: Option<[u8; 16]>,
    /// v1 stores only a flag; v2 stores the authenticated operation payload.
    pending_operation: PersistedPendingOperation,
    /// Present only in v2. A missing epoch on a v2 record fails decode.
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default = "default_next_sequence")]
    next_sequence: u64,
    #[serde(default)]
    outgoing: Vec<PersistedOutgoing>,
    #[serde(default)]
    receipts: Vec<PersistedReceiptExpectation>,
    #[serde(default)]
    queued: Vec<PersistedQueuedMessage>,
}

/// Encrypted snapshot for one non-default channel group. It binds the derived
/// group ID to its parent conversation, channel ID, policy revision, MLS epoch,
/// membership, and pending ciphertext state. Decrypted text is never stored.
#[derive(Serialize, Deserialize)]
struct PersistedChannelGroup {
    version: u8,
    group_id: [u8; 16],
    parent_conversation_id: [u8; 16],
    channel_id: [u8; 16],
    channel_revision: u32,
    epoch: u64,
    next_sequence: u64,
    /// Members present in the derived MLS group.
    members: Vec<Vec<u8>>,
    /// Members allowed by the parent `CHN1` policy.
    allowed_members: Vec<Vec<u8>>,
    awaited: Vec<Vec<u8>>,
    ready: bool,
    outgoing: Vec<PersistedOutgoing>,
    receipts: Vec<PersistedReceiptExpectation>,
    queued: Vec<PersistedChannelQueuedMessage>,
}

#[derive(Serialize, Deserialize)]
struct PersistedChannelQueuedMessage {
    peer: Vec<u8>,
    conversation_id: [u8; 16],
    channel_id: [u8; 16],
    message_id: [u8; 16],
    envelope_bytes: Vec<u8>,
}

struct RestoredConversations {
    conversations: HashMap<[u8; 16], ConversationState>,
    peer_conversations: HashMap<PeerId, [u8; 16]>,
    active_channel: HashMap<[u8; 16], [u8; 16]>,
    active: Option<[u8; 16]>,
    pending_receipts: HashMap<[u8; 16], BTreeSet<PeerId>>,
    message_conversations: HashMap<[u8; 16], [u8; 16]>,
    message_channel_routes: HashMap<[u8; 16], [u8; 16]>,
    channel_groups: HashMap<[u8; 16], ChannelGroupState>,
    offline_queue: VecDeque<QueuedMessage>,
}

impl RestoredConversations {
    fn empty() -> Self {
        Self {
            conversations: HashMap::new(),
            peer_conversations: HashMap::new(),
            active_channel: HashMap::new(),
            active: None,
            pending_receipts: HashMap::new(),
            message_conversations: HashMap::new(),
            message_channel_routes: HashMap::new(),
            channel_groups: HashMap::new(),
            offline_queue: VecDeque::new(),
        }
    }
}

impl PersistedConversation {
    fn from_state(
        state: &ConversationState,
        peer: PeerId,
        active_channel: Option<[u8; 16]>,
        pending_receipts: &HashMap<[u8; 16], BTreeSet<PeerId>>,
        message_conversations: &HashMap<[u8; 16], [u8; 16]>,
        message_channel_routes: &HashMap<[u8; 16], [u8; 16]>,
        offline_queue: &VecDeque<QueuedMessage>,
    ) -> Self {
        let (status_code, status_reason) = status_code(&state.status);
        let conversation_id = state.conversation.id();
        let queued_ids: HashSet<[u8; 16]> = offline_queue
            .iter()
            .filter(|item| {
                item.conversation_id == conversation_id && item.channel_id == DEFAULT_CHANNEL_ID
            })
            .map(|item| item.message_id)
            .collect();
        let mut outgoing = Vec::new();
        let mut receipts = Vec::new();
        for (message_id, peers) in pending_receipts {
            // Non-default channel state belongs to the derived group record.
            if message_conversations.get(message_id) != Some(&conversation_id)
                || message_channel_routes.contains_key(message_id)
                || !matches!(
                    state.conversation.delivery_state(message_id),
                    Some(DeliveryState::Queued)
                        | Some(DeliveryState::SentToPeer)
                        | Some(DeliveryState::Composed)
                )
            {
                continue;
            }
            outgoing.push(PersistedOutgoing {
                message_id: *message_id,
                state_code: if queued_ids.contains(message_id) {
                    OUTGOING_QUEUED_CODE
                } else {
                    OUTGOING_SENT_CODE
                },
            });
            receipts.push(PersistedReceiptExpectation {
                message_id: *message_id,
                peers: peers.iter().map(|peer| peer.to_bytes().to_vec()).collect(),
            });
        }
        outgoing.sort_by_key(|item| item.message_id);
        receipts.sort_by_key(|item| item.message_id);
        let pending_operation = match &state.pending_operation {
            None => PersistedPendingOperation::Flag(false),
            Some(operation) => PersistedPendingOperation::Detail(PersistedPendingDetail {
                transaction_id: operation.transaction_id,
                operation: operation.operation.code(),
                target: operation.target.map(|peer| peer.to_bytes().to_vec()),
                commit: operation.commit.clone(),
                awaited: operation
                    .awaited
                    .iter()
                    .map(|(peer, acked)| (peer.to_bytes().to_vec(), *acked))
                    .collect(),
                welcome_target: operation
                    .welcome_target
                    .map(|peer| peer.to_bytes().to_vec()),
                welcome: operation.welcome.clone(),
                welcome_acked: operation.welcome_acked,
            }),
        };
        Self {
            version: PERSISTED_CONVERSATION_VERSION,
            conversation_id,
            peer: peer.to_bytes().to_vec(),
            admin: state.admin.to_bytes().to_vec(),
            members: state
                .members
                .iter()
                .map(|peer| peer.to_bytes().to_vec())
                .collect(),
            status_code,
            status_reason,
            channels: state
                .channels
                .iter()
                .map(|(id, channel)| PersistedChannel {
                    id: *id,
                    name: channel.name.clone(),
                    creator: channel.creator.to_bytes().to_vec(),
                    members: channel
                        .members
                        .iter()
                        .map(|peer| peer.to_bytes().to_vec())
                        .collect(),
                    revision: channel.revision,
                    last_frame_id: channel.last_frame_id,
                })
                .collect(),
            active_channel,
            pending_operation,
            epoch: Some(state.conversation.epoch()),
            next_sequence: state.conversation.next_sequence(),
            outgoing,
            receipts,
            queued: offline_queue
                .iter()
                .filter(|item| {
                    item.conversation_id == conversation_id && item.channel_id == DEFAULT_CHANNEL_ID
                })
                .map(|item| PersistedQueuedMessage {
                    peer: item.peer.to_bytes().to_vec(),
                    conversation_id: item.conversation_id,
                    message_id: item.message_id,
                    envelope_bytes: item.envelope_bytes.clone(),
                })
                .collect(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ChatError> {
        let decoded: Self = serde_json::from_slice(bytes)
            .map_err(|_| ChatError::MlsRestore("invalid encrypted conversation metadata"))?;
        if !(decoded.version == PERSISTED_CONVERSATION_V1
            || decoded.version == PERSISTED_CONVERSATION_VERSION)
            || decoded.version == PERSISTED_CONVERSATION_V1 && decoded.epoch.is_some()
            || decoded.version == PERSISTED_CONVERSATION_VERSION && decoded.epoch.is_none()
            || decoded.next_sequence == 0
            || decoded.channels.len() > MAX_CHANNELS_PER_GROUP
            || decoded.members.len() > MAX_CHANNEL_MEMBERS
            || decoded.receipts.len() > MAX_PENDING_RECEIPTS
            || decoded.outgoing.len() > MAX_PENDING_RECEIPTS
            || decoded.queued.len() > MAX_OFFLINE_QUEUE
        {
            return Err(ChatError::MlsRestore(
                "unsupported restored conversation metadata",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for channel in &decoded.channels {
            if !ids.insert(channel.id)
                || channel.name.len() > MAX_CHANNEL_NAME_BYTES
                || channel.members.len() > MAX_CHANNEL_MEMBERS
            {
                return Err(ChatError::MlsRestore("invalid restored channel metadata"));
            }
        }
        if decoded
            .queued
            .iter()
            .any(|item| item.envelope_bytes.len() > MAX_QUEUED_ENVELOPE_BYTES)
        {
            return Err(ChatError::MlsRestore(
                "restored queued envelope is too large",
            ));
        }
        Ok(decoded)
    }
}

impl PersistedChannelGroup {
    #[allow(clippy::too_many_arguments)]
    fn from_state(
        state: &ConversationState,
        group_state: &ChannelGroupState,
        pending_receipts: &HashMap<[u8; 16], BTreeSet<PeerId>>,
        message_conversations: &HashMap<[u8; 16], [u8; 16]>,
        message_channel_routes: &HashMap<[u8; 16], [u8; 16]>,
        offline_queue: &VecDeque<QueuedMessage>,
    ) -> Result<Self, ChatError> {
        let parent_conversation_id = state.conversation.id();
        let channel_id = group_state.binding.channel_id();
        let channel = state
            .channels
            .get(&channel_id)
            .ok_or(ChatError::ChannelNotFound)?;
        let group_id = group_state.binding.group_id();
        let queued_ids: HashSet<[u8; 16]> = offline_queue
            .iter()
            .filter(|item| {
                item.conversation_id == parent_conversation_id && item.channel_id == channel_id
            })
            .map(|item| item.message_id)
            .collect();
        let mut outgoing = Vec::new();
        let mut receipts = Vec::new();
        for (message_id, peers) in pending_receipts {
            if message_conversations.get(message_id) != Some(&parent_conversation_id)
                || message_channel_routes.get(message_id) != Some(&channel_id)
                || !matches!(
                    group_state.group.delivery_state(message_id),
                    Some(DeliveryState::Queued)
                        | Some(DeliveryState::SentToPeer)
                        | Some(DeliveryState::Composed)
                )
            {
                continue;
            }
            outgoing.push(PersistedOutgoing {
                message_id: *message_id,
                state_code: if queued_ids.contains(message_id) {
                    OUTGOING_QUEUED_CODE
                } else {
                    OUTGOING_SENT_CODE
                },
            });
            receipts.push(PersistedReceiptExpectation {
                message_id: *message_id,
                peers: peers.iter().map(|peer| peer.to_bytes().to_vec()).collect(),
            });
        }
        outgoing.sort_by_key(|item| item.message_id);
        receipts.sort_by_key(|item| item.message_id);
        let queued = offline_queue
            .iter()
            .filter(|item| {
                item.conversation_id == parent_conversation_id && item.channel_id == channel_id
            })
            .map(|item| PersistedChannelQueuedMessage {
                peer: item.peer.to_bytes().to_vec(),
                conversation_id: item.conversation_id,
                channel_id: item.channel_id,
                message_id: item.message_id,
                envelope_bytes: item.envelope_bytes.clone(),
            })
            .collect();
        Ok(Self {
            version: PERSISTED_CHANNEL_GROUP_VERSION,
            group_id,
            parent_conversation_id,
            channel_id,
            channel_revision: channel.revision,
            epoch: group_state.group.epoch(),
            next_sequence: group_state.group.next_sequence(),
            members: group_state
                .group
                .members()?
                .into_iter()
                .map(|peer| peer.to_bytes().to_vec())
                .collect(),
            allowed_members: channel
                .members
                .iter()
                .map(|peer| peer.to_bytes().to_vec())
                .collect(),
            awaited: group_state
                .awaited
                .iter()
                .map(|peer| peer.to_bytes().to_vec())
                .collect(),
            ready: group_state.ready,
            outgoing,
            receipts,
            queued,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, ChatError> {
        let decoded: Self = serde_json::from_slice(bytes)
            .map_err(|_| ChatError::MlsRestore("invalid encrypted channel group metadata"))?;
        if decoded.version != PERSISTED_CHANNEL_GROUP_VERSION
            || decoded.next_sequence == 0
            || decoded.members.is_empty()
            || decoded.members.len() > MAX_CHANNEL_MEMBERS
            || decoded.allowed_members.is_empty()
            || decoded.allowed_members.len() > MAX_CHANNEL_MEMBERS
            || decoded.awaited.len() > MAX_CHANNEL_MEMBERS
            || decoded.outgoing.len() > MAX_PENDING_RECEIPTS
            || decoded.receipts.len() > MAX_PENDING_RECEIPTS
            || decoded.queued.len() > MAX_OFFLINE_QUEUE
            || decoded
                .queued
                .iter()
                .any(|item| item.envelope_bytes.len() > MAX_QUEUED_ENVELOPE_BYTES)
        {
            return Err(ChatError::MlsRestore(
                "unsupported restored channel group metadata",
            ));
        }
        Ok(decoded)
    }
}

fn parse_persisted_peer(bytes: &[u8]) -> Result<PeerId, ChatError> {
    PeerId::from_bytes(bytes).map_err(|_| ChatError::MlsRestore("invalid restored peer id"))
}

/// Rebuild a pending MLS operation only if every field agrees with the restored
/// group. Removed targets are intentionally absent from `members`; added
/// targets are present because the member was inserted before the snapshot.
fn restore_pending_operation(
    detail: &PersistedPendingDetail,
    members: &BTreeSet<PeerId>,
    local: &PeerId,
) -> Result<PendingOperation, ChatError> {
    let operation = GroupOperation::from_code(detail.operation).ok_or(ChatError::MlsRestore(
        "restored group operation code is invalid",
    ))?;
    if detail.commit.is_empty() || detail.commit.len() > MAX_PENDING_OPERATION_BYTES {
        return Err(ChatError::MlsRestore("restored MLS commit is invalid"));
    }
    if detail
        .welcome
        .as_ref()
        .is_some_and(|welcome| welcome.is_empty() || welcome.len() > MAX_PENDING_OPERATION_BYTES)
    {
        return Err(ChatError::MlsRestore("restored MLS Welcome is invalid"));
    }
    if detail.awaited.len() > MAX_CHANNEL_MEMBERS {
        return Err(ChatError::MlsRestore(
            "restored acknowledgement set is too large",
        ));
    }
    let target = detail
        .target
        .as_ref()
        .map(|bytes| parse_persisted_peer(bytes))
        .transpose()?;
    let welcome_target = detail
        .welcome_target
        .as_ref()
        .map(|bytes| parse_persisted_peer(bytes))
        .transpose()?;
    let mut awaited = BTreeMap::new();
    for (encoded, acked) in &detail.awaited {
        let peer = parse_persisted_peer(encoded)?;
        if peer == *local || !members.contains(&peer) || awaited.insert(peer, *acked).is_some() {
            return Err(ChatError::MlsRestore(
                "restored acknowledgement peer is inconsistent",
            ));
        }
    }

    match operation {
        GroupOperation::Add => {
            let target = target.ok_or(ChatError::MlsRestore(
                "restored add operation has no target",
            ))?;
            if target == *local
                || !members.contains(&target)
                || welcome_target != Some(target)
                || awaited.contains_key(&target)
                || (!detail.welcome_acked && detail.welcome.is_none())
            {
                return Err(ChatError::MlsRestore(
                    "restored add operation is inconsistent",
                ));
            }
        }
        GroupOperation::Remove => {
            let target = target.ok_or(ChatError::MlsRestore(
                "restored remove operation has no target",
            ))?;
            if target == *local
                || members.contains(&target)
                || welcome_target.is_some()
                || detail.welcome.is_some()
                || !detail.welcome_acked
            {
                return Err(ChatError::MlsRestore(
                    "restored remove operation is inconsistent",
                ));
            }
        }
        GroupOperation::Update => {
            if target.is_some()
                || welcome_target.is_some()
                || detail.welcome.is_some()
                || !detail.welcome_acked
            {
                return Err(ChatError::MlsRestore(
                    "restored update operation is inconsistent",
                ));
            }
        }
    }
    if detail.welcome_acked && awaited.values().all(|acked| *acked) {
        return Err(ChatError::MlsRestore(
            "restored operation was already complete",
        ));
    }
    Ok(PendingOperation {
        transaction_id: detail.transaction_id,
        operation,
        target,
        commit: detail.commit.clone(),
        awaited,
        welcome_target,
        welcome: detail.welcome.clone(),
        welcome_acked: detail.welcome_acked,
    })
}

fn status_code(status: &ConversationStatus) -> (u8, Option<String>) {
    match status {
        ConversationStatus::KeyPackageRequested => (1, None),
        ConversationStatus::KeyPackageReceived => (2, None),
        ConversationStatus::WelcomeSent => (3, None),
        ConversationStatus::Joined => (4, None),
        ConversationStatus::Failed(reason) => (5, Some(reason.clone())),
    }
}

fn status_from_code(code: u8, reason: Option<String>) -> Result<ConversationStatus, ChatError> {
    match (code, reason) {
        (1, None) => Ok(ConversationStatus::KeyPackageRequested),
        (2, None) => Ok(ConversationStatus::KeyPackageReceived),
        (3, None) => Ok(ConversationStatus::WelcomeSent),
        (4, None) => Ok(ConversationStatus::Joined),
        (5, Some(reason)) if !reason.is_empty() => Ok(ConversationStatus::Failed(reason)),
        _ => Err(ChatError::MlsRestore(
            "invalid restored conversation status",
        )),
    }
}

/// Whether a displayed line was composed locally or received from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageOrigin {
    Local,
    Remote,
}

/// A decrypted text message held only in memory for display. Plaintext is
/// redacted from `Debug` so logs and diagnostics cannot leak message bodies.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub message_id: [u8; 16],
    pub channel_id: [u8; 16],
    pub peer: PeerId,
    pub text: String,
    pub origin: MessageOrigin,
    /// `None` for incoming messages. `SentToPeer` is never shown as delivered.
    pub delivery: Option<DeliveryState>,
}

impl fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatMessage")
            .field("message_id", &hex(&self.message_id))
            .field("channel_id", &hex(&self.channel_id))
            .field("peer", &self.peer.to_string())
            .field("origin", &self.origin)
            .field("delivery", &self.delivery)
            .field("text_len", &self.text.len())
            .field("text", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct PendingOperation {
    /// Fresh random ID chosen by the local admin; every request, Welcome,
    /// commit, and acknowledgement for this operation carries it.
    transaction_id: TransactionId,
    operation: GroupOperation,
    target: Option<PeerId>,
    commit: Vec<u8>,
    awaited: BTreeMap<PeerId, bool>,
    welcome_target: Option<PeerId>,
    welcome: Option<Vec<u8>>,
    welcome_acked: bool,
}

impl fmt::Debug for PendingOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOperation")
            .field("transaction_id", &hex(&self.transaction_id))
            .field("operation", &self.operation)
            .field("target", &self.target)
            .field("awaited", &self.awaited)
            .field("welcome_target", &self.welcome_target)
            .field("welcome_acked", &self.welcome_acked)
            .field("commit_len", &self.commit.len())
            .field("commit", &"<mls-commit>")
            .finish_non_exhaustive()
    }
}

struct ChannelState {
    name: String,
    creator: PeerId,
    members: BTreeSet<PeerId>,
    revision: u32,
    /// Last locally composed policy frame; receipts clear this pending state.
    last_frame_id: Option<[u8; 16]>,
}

/// An independent MLS group for one non-default channel. `awaited` tracks the
/// peers whose bound setup has not been acknowledged yet; `ready` gates channel
/// ciphertext until the local group contains every allowed member.
#[derive(Debug)]
struct ChannelGroupState {
    binding: ChannelGroupBinding,
    group: MlsChannelGroup,
    awaited: BTreeSet<PeerId>,
    ready: bool,
}

/// How far one allowed peer's channel-group setup has progressed. The admin
/// adds peers sequentially so every member converges on the same epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelMemberSetupStage {
    KeyPackageRequested,
    WelcomeSent,
}

/// No derived `Debug`: Welcome and commit bytes are sensitive setup state and
/// must never enter diagnostics through a container dump.
struct PendingChannelMemberSetup {
    channel_id: [u8; 16],
    peer: PeerId,
    scope: ChannelScope,
    stage: ChannelMemberSetupStage,
    welcome: Vec<u8>,
    commit: Vec<u8>,
    welcome_acked: bool,
    commit_acks: BTreeSet<PeerId>,
    required_commit_acks: BTreeSet<PeerId>,
}

/// A policy frame whose receipts gate creation or recreation of a channel MLS
/// group. Setup starts only after every parent-group member has acknowledged
/// the policy, so a member cannot receive a channel request before it knows the
/// channel exists.
#[derive(Debug, Clone, Copy)]
struct PendingChannelPolicyAck {
    conversation_id: [u8; 16],
    channel_id: [u8; 16],
    recreate: bool,
}

impl ConversationState {
    fn new(conversation: MlsConversation, admin: PeerId, members: BTreeSet<PeerId>) -> Self {
        let mut state = Self {
            conversation,
            admin,
            members,
            status: ConversationStatus::Joined,
            pending_operation: None,
            channels: BTreeMap::new(),
        };
        state.channels.insert(
            DEFAULT_CHANNEL_ID,
            ChannelState {
                name: "general".to_owned(),
                creator: admin,
                members: state.members.clone(),
                revision: 0,
                last_frame_id: None,
            },
        );
        state
    }

    fn sync_default_channel(&mut self) {
        if let Some(channel) = self.channels.get_mut(&DEFAULT_CHANNEL_ID) {
            channel.members = self.members.clone();
        }
    }

    fn prune_removed_members(&mut self) {
        for channel in self.channels.values_mut() {
            channel
                .members
                .retain(|member| self.members.contains(member));
        }
    }

    fn apply_channel_frame(
        &mut self,
        sender: PeerId,
        frame: ChannelFrame,
    ) -> Result<Option<([u8; 16], String)>, ChatError> {
        let channel_id = frame.channel_id;
        match frame.kind {
            ChannelFrameKind::Text { text } => {
                let channel = self
                    .channels
                    .get(&channel_id)
                    .ok_or(ChatError::ChannelNotFound)?;
                if !self.members.contains(&sender) || !channel.members.contains(&sender) {
                    return Err(ChatError::NotChannelMember);
                }
                Ok(Some((channel_id, text)))
            }
            ChannelFrameKind::Create { name, members } => {
                if sender != self.admin {
                    return Err(ChatError::NotAdmin);
                }
                if self.channels.contains_key(&channel_id) {
                    return Err(ChatError::ChannelAlreadyExists);
                }
                if self.channels.len() >= MAX_CHANNELS_PER_GROUP {
                    return Err(ChatError::ChannelLimit);
                }
                if frame.revision != 1 || !members.iter().all(|peer| self.members.contains(peer)) {
                    return Err(ChatError::ChannelRevisionConflict);
                }
                self.channels.insert(
                    channel_id,
                    ChannelState {
                        name,
                        creator: sender,
                        members: members.into_iter().collect(),
                        revision: frame.revision,
                        last_frame_id: None,
                    },
                );
                Ok(None)
            }
            ChannelFrameKind::Rename { name } => {
                if sender != self.admin {
                    return Err(ChatError::NotAdmin);
                }
                let channel = self
                    .channels
                    .get_mut(&channel_id)
                    .ok_or(ChatError::ChannelNotFound)?;
                if frame.revision != channel.revision.saturating_add(1) {
                    return Err(ChatError::ChannelRevisionConflict);
                }
                channel.name = name;
                channel.revision = frame.revision;
                channel.last_frame_id = None;
                Ok(None)
            }
            ChannelFrameKind::SetMembers { members } => {
                if sender != self.admin {
                    return Err(ChatError::NotAdmin);
                }
                if !members.iter().all(|peer| self.members.contains(peer)) {
                    return Err(ChatError::NotChannelMember);
                }
                let channel = self
                    .channels
                    .get_mut(&channel_id)
                    .ok_or(ChatError::ChannelNotFound)?;
                if frame.revision != channel.revision.saturating_add(1) {
                    return Err(ChatError::ChannelRevisionConflict);
                }
                channel.members = members.into_iter().collect();
                channel.revision = frame.revision;
                channel.last_frame_id = None;
                Ok(None)
            }
        }
    }
}

struct ConversationState {
    conversation: MlsConversation,
    admin: PeerId,
    members: BTreeSet<PeerId>,
    status: ConversationStatus,
    pending_operation: Option<PendingOperation>,
    channels: BTreeMap<[u8; 16], ChannelState>,
}

impl fmt::Debug for ConversationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationState")
            .field("conversation", &self.conversation)
            .field("admin", &self.admin.to_string())
            .field("members", &self.members)
            .field("channel_count", &self.channels.len())
            .field("status", &self.status)
            .field("pending_operation", &self.pending_operation)
            .finish_non_exhaustive()
    }
}

/// Which setup request produced a retained KeyPackage provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKeyPackageKind {
    Conversation,
    GroupJoin,
}

struct PendingKeyPackage {
    peer: PeerId,
    kind: PendingKeyPackageKind,
    key_package: MlsKeyPackage,
    /// Keep the exact encoded response so an identical duplicate request can
    /// be answered idempotently without regenerating or replacing the provider.
    response_bytes: Vec<u8>,
}

/// A channel KeyPackage retained until its bound Welcome arrives. The scope is
/// the map key, so a response or Welcome from another channel cannot reach it.
/// No derived `Debug`: the retained package and response bytes are sensitive.
struct PendingChannelKeyPackage {
    peer: PeerId,
    key_package: ChannelKeyPackage,
    response_bytes: Vec<u8>,
}

/// What kind of response completes one locally initiated setup request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutgoingSetupKind {
    KeyPackageRequest,
    Welcome,
    GroupJoinRequest,
    ChannelKeyPackageRequest,
    ChannelWelcome,
}

#[derive(Debug, Clone)]
struct OutgoingSetup {
    conversation_id: [u8; 16],
    transaction_id: TransactionId,
    kind: OutgoingSetupKind,
    scope: Option<ChannelScope>,
}

impl OutgoingSetupKind {
    fn from_message(message: &SetupMessage) -> Result<Self, ChatError> {
        match message {
            SetupMessage::KeyPackageRequest { .. } => Ok(Self::KeyPackageRequest),
            SetupMessage::Welcome { .. } => Ok(Self::Welcome),
            SetupMessage::GroupJoinRequest { .. } => Ok(Self::GroupJoinRequest),
            SetupMessage::ChannelKeyPackageRequest { .. } => Ok(Self::ChannelKeyPackageRequest),
            SetupMessage::ChannelWelcome { .. } => Ok(Self::ChannelWelcome),
            _ => Err(ChatError::InvalidSetup(
                "unexpected outbound setup request type",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupRequestKind {
    Welcome,
    Commit,
}

#[derive(Debug, Clone, Copy)]
struct GroupRequest {
    conversation_id: [u8; 16],
    channel_scope: Option<ChannelScope>,
    transaction_id: TransactionId,
    peer: PeerId,
    operation: GroupOperation,
    kind: GroupRequestKind,
}

/// State change from an inbound setup request plus the response to hand back
/// to the transport. Keeping these together lets validation reject a frame
/// before any group state is touched while still sending rejection acks.
struct RequestOutcome {
    response: Option<SetupMessage>,
    rejection: Option<ChatError>,
}

impl RequestOutcome {
    fn respond(message: SetupMessage) -> Self {
        Self {
            response: Some(message),
            rejection: None,
        }
    }

    fn respond_and_reject(message: SetupMessage, error: ChatError) -> Self {
        Self {
            response: Some(message),
            rejection: Some(error),
        }
    }
}

/// One signed MLS ciphertext envelope waiting for a reconnect. The plaintext
/// display text lives only in `ChatMessage`; this queue never copies it.
#[derive(Clone, PartialEq, Eq)]
struct QueuedMessage {
    peer: PeerId,
    conversation_id: [u8; 16],
    channel_id: [u8; 16],
    message_id: [u8; 16],
    envelope_bytes: Vec<u8>,
}

impl fmt::Debug for QueuedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedMessage")
            .field("peer", &self.peer.to_string())
            .field("conversation_id", &hex(&self.conversation_id))
            .field("channel_id", &hex(&self.channel_id))
            .field("message_id", &hex(&self.message_id))
            .field("envelope_len", &self.envelope_bytes.len())
            .field("envelope_bytes", &"<mls-ciphertext>")
            .finish_non_exhaustive()
    }
}

/// How to interpret a transport response for one outbound file frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileRequestKind {
    Offer {
        peer: PeerId,
        transfer_id: [u8; 16],
    },
    Chunk {
        peer: PeerId,
        transfer_id: [u8; 16],
        index: u32,
    },
    Manifest {
        peer: PeerId,
        transfer_id: [u8; 16],
    },
}

/// Inactivity deadline for one active file transfer. Only the public transfer
/// ID and a monotonic deadline are retained; no file bytes or keys are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransferDeadline {
    transfer_id: [u8; 16],
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct RedialConfig {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl From<&NetworkConfig> for RedialConfig {
    fn from(config: &NetworkConfig) -> Self {
        Self {
            max_attempts: config.max_redial_attempts,
            base_delay: config.redial_base_delay,
            max_delay: config.redial_max_delay,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ConnectionAction {
    Connected(PeerId),
    Disconnected(PeerId),
    DialFailed(PeerId),
}

#[derive(Debug, Clone)]
enum RedialSlot {
    Idle,
    Suppressed,
    Scheduled {
        attempt: u32,
        delay: Duration,
        deadline: Instant,
    },
    Dialing {
        attempt: u32,
    },
    Exhausted {
        attempts: u32,
    },
}

/// Bounded in-memory replay guard for verified setup and group-control frames.
/// Only `(PeerId, SHA-256 digest)` pairs are retained; no KeyPackage, Welcome,
/// commit, signature, or other frame bytes are stored.
const MAX_SETUP_REPLAY_ENTRIES: usize = 512;

#[derive(Debug, Default)]
struct SetupReplayCache {
    seen: HashSet<(PeerId, [u8; 32])>,
    order: VecDeque<(PeerId, [u8; 32])>,
}

impl SetupReplayCache {
    /// Record one authenticated frame. Returns `false` when the exact frame
    /// from the same authenticated peer was already seen in the current window.
    fn remember(&mut self, peer: PeerId, bytes: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let key = (peer, digest);
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > MAX_SETUP_REPLAY_ENTRIES {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }
}

/// Owns the Swarm, MLS sessions, and decrypted view model for the application.
/// Public methods are safe to call from a GUI frame; all blocking libp2p work
/// stays inside the network worker thread.
pub struct MessengerController {
    identity: Identity,
    network: Network,
    conversations: HashMap<[u8; 16], ConversationState>,
    peer_conversations: HashMap<PeerId, [u8; 16]>,
    pending_key_packages: HashMap<([u8; 16], TransactionId), PendingKeyPackage>,
    pending_channel_key_packages: HashMap<ChannelScope, PendingChannelKeyPackage>,
    channel_groups: HashMap<[u8; 16], ChannelGroupState>,
    pending_channel_setups: HashMap<ChannelScope, PendingChannelMemberSetup>,
    pending_channel_policy_acks: HashMap<[u8; 16], PendingChannelPolicyAck>,
    outstanding_setup: HashMap<p2p_network::SetupRequestId, OutgoingSetup>,
    group_requests: HashMap<p2p_network::SetupRequestId, GroupRequest>,
    outstanding_messages: HashMap<MessageRequestId, [u8; 16]>,
    message_conversations: HashMap<[u8; 16], [u8; 16]>,
    /// Non-default channel messages are composed in a derived group, so their
    /// message IDs map back to the parent channel for display and receipts.
    message_channel_routes: HashMap<[u8; 16], [u8; 16]>,
    pending_receipts: HashMap<[u8; 16], BTreeSet<PeerId>>,
    applied_commits: HashMap<[u8; 16], HashSet<Vec<u8>>>,
    setup_replay: SetupReplayCache,
    offline_queue: VecDeque<QueuedMessage>,
    redial_config: RedialConfig,
    dialed_addresses: HashMap<PeerId, Multiaddr>,
    redial: HashMap<PeerId, RedialSlot>,
    connected_peers: BTreeSet<PeerId>,
    messages: Vec<ChatMessage>,
    active: Option<[u8; 16]>,
    active_channel: HashMap<[u8; 16], [u8; 16]>,
    file_config: FileConfig,
    security_config: SecurityConfig,
    outgoing_files: HashMap<PeerId, OutgoingFile>,
    incoming_files: HashMap<PeerId, IncomingFile>,
    file_requests: HashMap<FileRequestId, FileRequestKind>,
    transfer_timeout: Duration,
    transfer_deadlines: HashMap<PeerId, TransferDeadline>,
    storage: Option<Session>,
    last_error: Option<String>,
}

impl MessengerController {
    /// Start the direct-connect worker with the vault identity and default
    /// file quarantine/security policy. No peer is contacted until an explicit
    /// address is dialed. With no scanner configured, file scans report
    /// `Unavailable` and release is denied.
    pub fn start(identity: &Identity, config: NetworkConfig) -> Result<Self, ChatError> {
        Self::start_with_file_config(identity, config, FileConfig::default())
    }

    /// Start with an independent connection to the unlocked vault so already
    /// authenticated setup/group-control frames are rejected durably, including
    /// after an application restart. The vault identity must be this session's
    /// identity. This does not restore MLS group state.
    pub fn start_with_control_log(
        identity: &Identity,
        config: NetworkConfig,
        storage: Session,
    ) -> Result<Self, ChatError> {
        Self::build(
            identity,
            config,
            FileConfig::default(),
            SecurityConfig::default(),
            DEFAULT_FILE_TRANSFER_TIMEOUT,
            Some(storage),
        )
    }

    /// Start with an explicit file-transfer inactivity timeout. Values below
    /// 1 ms or above [`MAX_FILE_TRANSFER_TIMEOUT`] are rejected so a caller
    /// cannot accidentally disable the lifetime bound or make it unusably
    /// short. Existing constructors use
    /// [`DEFAULT_FILE_TRANSFER_TIMEOUT`].
    pub fn start_with_transfer_timeout(
        identity: &Identity,
        config: NetworkConfig,
        file_config: FileConfig,
        security_config: SecurityConfig,
        transfer_timeout: Duration,
    ) -> Result<Self, ChatError> {
        Self::build(
            identity,
            config,
            file_config,
            security_config,
            transfer_timeout,
            None,
        )
    }

    /// Restore joined conversations and their authenticated pending state. Every
    /// restored item is bound to the loaded MLS group, epoch, membership, and
    /// encrypted record; anything inconsistent fails startup.
    fn restore_joined_conversations(
        identity: &Identity,
        storage: &Session,
    ) -> Result<RestoredConversations, ChatError> {
        let local = identity.peer_id();
        let mut restored = RestoredConversations::empty();
        let mut first_joined = None;
        let mut parent_ids = Vec::new();
        let mut channel_records = Vec::new();
        for group_id in storage.mls_group_ids()? {
            let parent_bytes = storage.load_mls_state(
                &group_id,
                PERSISTED_CONVERSATION_LABEL,
                PERSISTED_CONVERSATION_LABEL.as_bytes(),
            )?;
            let channel_bytes = storage.load_mls_state(
                &group_id,
                PERSISTED_CHANNEL_GROUP_LABEL,
                PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
            )?;
            match (parent_bytes, channel_bytes) {
                (Some(_), Some(_)) => {
                    return Err(ChatError::MlsRestore(
                        "one MLS group has both parent and channel metadata",
                    ));
                }
                (Some(_), None) => parent_ids.push(group_id),
                (None, Some(bytes)) => {
                    channel_records.push((group_id, PersistedChannelGroup::decode(&bytes)?));
                }
                (None, None) => {
                    return Err(ChatError::MlsRestore(
                        "encrypted conversation metadata is missing",
                    ));
                }
            }
        }
        for conversation_id in parent_ids {
            let bytes = storage
                .load_mls_state(
                    &conversation_id,
                    PERSISTED_CONVERSATION_LABEL,
                    PERSISTED_CONVERSATION_LABEL.as_bytes(),
                )?
                .ok_or(ChatError::MlsRestore(
                    "encrypted conversation metadata is missing",
                ))?;
            let record = PersistedConversation::decode(&bytes)?;
            if record.conversation_id != conversation_id {
                return Err(ChatError::MlsRestore(
                    "restored conversation id does not match its group",
                ));
            }
            if record.version == PERSISTED_CONVERSATION_V1 && record.pending_operation.is_pending()
            {
                // A v1 record has no authenticated operation payload, so a
                // pending flag can only be cleared without lying.
                return Err(ChatError::MlsRestore(
                    "a group operation was pending at shutdown",
                ));
            }
            let status = status_from_code(record.status_code, record.status_reason)?;
            if status != ConversationStatus::Joined {
                // Setup and failed conversations remain encrypted but are not
                // reconstructed as joined groups.
                continue;
            }

            let peer = parse_persisted_peer(&record.peer)?;
            let admin = parse_persisted_peer(&record.admin)?;
            if peer == local {
                return Err(ChatError::MlsRestore(
                    "restored conversation has no remote peer",
                ));
            }
            let mut members = BTreeSet::new();
            for encoded in &record.members {
                if !members.insert(parse_persisted_peer(encoded)?) {
                    return Err(ChatError::MlsRestore(
                        "restored member list contains a duplicate",
                    ));
                }
            }
            if !members.contains(&local) || !members.contains(&admin) || !members.contains(&peer) {
                return Err(ChatError::MlsRestore(
                    "restored group policy is inconsistent",
                ));
            }

            let conversation = MlsConversation::load_with_storage(
                identity,
                conversation_id,
                storage.try_clone()?,
            )?;
            let group_members: BTreeSet<PeerId> = conversation.members()?.into_iter().collect();
            if group_members != members {
                return Err(ChatError::MlsRestore(
                    "restored membership does not match MLS group state",
                ));
            }
            let epoch = match record.epoch {
                Some(epoch) if epoch == conversation.epoch() => epoch,
                Some(_) => {
                    return Err(ChatError::MlsRestore(
                        "restored record epoch does not match MLS group state",
                    ));
                }
                None => conversation.epoch(),
            };

            let mut state = ConversationState::new(conversation, admin, members.clone());
            state.conversation.restore_epoch(epoch)?;
            // Every still-pending outgoing message consumed a distinct local
            // sequence, and a queued frame proves at least one compose. A
            // restored snapshot that understates the sequence could reuse it
            // after restart, so fail closed. Version 1 lacks authenticated
            // outgoing history and is checked by its legacy rules above.
            if record.version == PERSISTED_CONVERSATION_VERSION
                && (record.next_sequence < (record.outgoing.len() as u64).saturating_add(1)
                    || (!record.queued.is_empty() && record.next_sequence < 2))
            {
                return Err(ChatError::MlsRestore(
                    "restored conversation sequence predates its outgoing history",
                ));
            }
            state.conversation.restore_sequence(record.next_sequence)?;
            state.channels.clear();
            for channel in record.channels {
                let creator = parse_persisted_peer(&channel.creator)?;
                if !members.contains(&creator) {
                    return Err(ChatError::MlsRestore(
                        "restored channel creator is not a group member",
                    ));
                }
                let mut channel_members = BTreeSet::new();
                for encoded in &channel.members {
                    let member = parse_persisted_peer(encoded)?;
                    if !members.contains(&member) || !channel_members.insert(member) {
                        return Err(ChatError::MlsRestore(
                            "restored channel membership is inconsistent",
                        ));
                    }
                }
                if channel.id == DEFAULT_CHANNEL_ID && channel_members != members {
                    return Err(ChatError::MlsRestore(
                        "restored default channel membership is inconsistent",
                    ));
                }
                if channel.id != DEFAULT_CHANNEL_ID && channel.revision == 0 {
                    return Err(ChatError::MlsRestore(
                        "restored channel revision is invalid",
                    ));
                }
                state.channels.insert(
                    channel.id,
                    ChannelState {
                        name: channel.name,
                        creator,
                        members: channel_members,
                        revision: channel.revision,
                        last_frame_id: channel.last_frame_id,
                    },
                );
            }
            if !state.channels.contains_key(&DEFAULT_CHANNEL_ID) {
                return Err(ChatError::MlsRestore("restored default channel is missing"));
            }
            let selected = match record.active_channel {
                Some(id) if state.channels.contains_key(&id) => id,
                None => DEFAULT_CHANNEL_ID,
                Some(_) => {
                    return Err(ChatError::MlsRestore("restored active channel is unknown"));
                }
            };

            let mut receipt_expectations = HashMap::new();
            for item in &record.receipts {
                if item.peers.is_empty() || receipt_expectations.contains_key(&item.message_id) {
                    return Err(ChatError::MlsRestore(
                        "restored receipt expectation is invalid",
                    ));
                }
                let mut peers = BTreeSet::new();
                for encoded in &item.peers {
                    let expected = parse_persisted_peer(encoded)?;
                    if expected == local || !members.contains(&expected) || !peers.insert(expected)
                    {
                        return Err(ChatError::MlsRestore(
                            "restored receipt peer is inconsistent",
                        ));
                    }
                }
                receipt_expectations.insert(item.message_id, peers);
            }

            let mut queued_messages = VecDeque::new();
            let mut queued_ids = HashSet::new();
            for item in &record.queued {
                let queued_peer = parse_persisted_peer(&item.peer)?;
                if queued_peer == local
                    || !members.contains(&queued_peer)
                    || item.conversation_id != conversation_id
                    || !queued_ids.insert((queued_peer, item.message_id))
                {
                    return Err(ChatError::MlsRestore(
                        "restored queued message is inconsistent",
                    ));
                }
                state
                    .conversation
                    .verify_queued_v4(&item.envelope_bytes)
                    .map_err(|_| {
                        ChatError::MlsRestore("restored v4 queue frame is not group-authenticated")
                    })?;
                queued_messages.push_back(QueuedMessage {
                    peer: queued_peer,
                    conversation_id,
                    channel_id: DEFAULT_CHANNEL_ID,
                    message_id: item.message_id,
                    envelope_bytes: item.envelope_bytes.clone(),
                });
            }

            let queued_message_ids: HashSet<[u8; 16]> =
                queued_messages.iter().map(|item| item.message_id).collect();
            let mut restored_outgoing = HashSet::new();
            for item in &record.outgoing {
                if !restored_outgoing.insert(item.message_id)
                    || !receipt_expectations.contains_key(&item.message_id)
                {
                    return Err(ChatError::MlsRestore(
                        "restored outgoing state has no receipt expectation",
                    ));
                }
                let delivery = if queued_message_ids.contains(&item.message_id) {
                    match item.state_code {
                        OUTGOING_QUEUED_CODE => DeliveryState::Queued,
                        _ => {
                            return Err(ChatError::MlsRestore(
                                "restored queued message has an invalid state",
                            ));
                        }
                    }
                } else {
                    match item.state_code {
                        OUTGOING_SENT_CODE => DeliveryState::SentToPeer,
                        _ => {
                            return Err(ChatError::MlsRestore(
                                "restored receipt expectation has an invalid state",
                            ));
                        }
                    }
                };
                state
                    .conversation
                    .restore_outgoing(&item.message_id, delivery)?;
            }
            if receipt_expectations
                .keys()
                .any(|id| !restored_outgoing.contains(id))
                || queued_message_ids
                    .iter()
                    .any(|id| !receipt_expectations.contains_key(id))
            {
                return Err(ChatError::MlsRestore(
                    "restored pending state is incomplete",
                ));
            }

            state.pending_operation = match &record.pending_operation {
                PersistedPendingOperation::Flag(false) => None,
                PersistedPendingOperation::Flag(true) => {
                    return Err(ChatError::MlsRestore(
                        "a group operation was pending at shutdown",
                    ));
                }
                PersistedPendingOperation::Detail(detail) => {
                    Some(restore_pending_operation(detail, &members, &local)?)
                }
            };
            state.status = ConversationStatus::Joined;
            for member in &members {
                if *member != local {
                    restored.peer_conversations.insert(*member, conversation_id);
                }
            }
            for message_id in receipt_expectations.keys() {
                match restored.message_conversations.get(message_id) {
                    Some(existing) if existing != &conversation_id => {
                        return Err(ChatError::MlsRestore(
                            "restored message id is bound to two conversations",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        restored
                            .message_conversations
                            .insert(*message_id, conversation_id);
                    }
                }
            }
            restored.pending_receipts.extend(receipt_expectations);
            restored.offline_queue.extend(queued_messages);
            restored.active_channel.insert(conversation_id, selected);
            restored.conversations.insert(conversation_id, state);
            if first_joined.is_none() {
                first_joined = Some(conversation_id);
            }
        }

        for (group_id, record) in channel_records {
            let binding =
                ChannelGroupBinding::new(record.parent_conversation_id, record.channel_id);
            if binding.group_id() != group_id
                || record.group_id != group_id
                || record.parent_conversation_id == group_id
                || record.channel_id == DEFAULT_CHANNEL_ID
            {
                return Err(ChatError::MlsRestore(
                    "restored channel group binding is inconsistent",
                ));
            }
            let allowed =
                {
                    let parent_state = restored
                        .conversations
                        .get(&record.parent_conversation_id)
                        .ok_or(ChatError::MlsRestore(
                        "restored channel group has no parent conversation",
                    ))?;
                    if parent_state.status != ConversationStatus::Joined {
                        return Err(ChatError::MlsRestore(
                            "restored channel group parent is not joined",
                        ));
                    }
                    let channel = parent_state.channels.get(&record.channel_id).ok_or(
                        ChatError::MlsRestore("restored channel group has no parent channel"),
                    )?;
                    let mut allowed = BTreeSet::new();
                    for encoded in &record.allowed_members {
                        let member = parse_persisted_peer(encoded)?;
                        if !parent_state.members.contains(&member) || !allowed.insert(member) {
                            return Err(ChatError::MlsRestore(
                                "restored channel allowed membership is inconsistent",
                            ));
                        }
                    }
                    if allowed != channel.members || channel.revision != record.channel_revision {
                        return Err(ChatError::MlsRestore(
                            "restored channel group does not match channel policy",
                        ));
                    }
                    allowed
                };
            // The local admin is always in the derived MLS group even when the
            // channel policy lists only remote peers.
            let mut expected_group_members = allowed.clone();
            expected_group_members.insert(local);
            let mut group_members = BTreeSet::new();
            for encoded in &record.members {
                let member = parse_persisted_peer(encoded)?;
                if !expected_group_members.contains(&member) || !group_members.insert(member) {
                    return Err(ChatError::MlsRestore(
                        "restored channel group membership is inconsistent",
                    ));
                }
            }
            if group_members != expected_group_members {
                return Err(ChatError::MlsRestore(
                    "restored channel group membership does not match policy",
                ));
            }
            let mut awaited = BTreeSet::new();
            for encoded in &record.awaited {
                if !awaited.insert(parse_persisted_peer(encoded)?) {
                    return Err(ChatError::MlsRestore(
                        "restored channel acknowledgement peer is duplicated",
                    ));
                }
            }
            if !record.ready || !awaited.is_empty() {
                return Err(ChatError::MlsRestore(
                    "a channel group setup was pending at shutdown",
                ));
            }
            let mut group =
                MlsChannelGroup::load_with_storage(identity, binding, storage.try_clone()?)?;
            if group.id() != group_id || group.epoch() != record.epoch {
                return Err(ChatError::MlsRestore(
                    "restored channel MLS epoch does not match its record",
                ));
            }
            group.restore_epoch(record.epoch)?;
            if record.next_sequence < (record.outgoing.len() as u64).saturating_add(1)
                || (!record.queued.is_empty() && record.next_sequence < 2)
            {
                return Err(ChatError::MlsRestore(
                    "restored channel sequence predates its outgoing history",
                ));
            }
            group.restore_sequence(record.next_sequence)?;
            let mls_members: BTreeSet<PeerId> = group.members()?.into_iter().collect();
            if mls_members != group_members {
                return Err(ChatError::MlsRestore(
                    "restored channel MLS membership does not match its record",
                ));
            }

            let mut receipt_expectations = HashMap::new();
            for item in &record.receipts {
                if item.peers.is_empty() || receipt_expectations.contains_key(&item.message_id) {
                    return Err(ChatError::MlsRestore(
                        "restored channel receipt expectation is invalid",
                    ));
                }
                let mut peers = BTreeSet::new();
                for encoded in &item.peers {
                    let expected = parse_persisted_peer(encoded)?;
                    if expected == local || !allowed.contains(&expected) || !peers.insert(expected)
                    {
                        return Err(ChatError::MlsRestore(
                            "restored channel receipt peer is inconsistent",
                        ));
                    }
                }
                receipt_expectations.insert(item.message_id, peers);
            }
            let mut queued_messages = VecDeque::new();
            let mut queued_ids = HashSet::new();
            for item in &record.queued {
                let queued_peer = parse_persisted_peer(&item.peer)?;
                if queued_peer == local
                    || !allowed.contains(&queued_peer)
                    || item.conversation_id != record.parent_conversation_id
                    || item.channel_id != record.channel_id
                    || !queued_ids.insert((queued_peer, item.message_id))
                {
                    return Err(ChatError::MlsRestore(
                        "restored channel queued message is inconsistent",
                    ));
                }
                group.verify_queued_v4(&item.envelope_bytes).map_err(|_| {
                    ChatError::MlsRestore(
                        "restored channel v4 queue frame is not group-authenticated",
                    )
                })?;
                queued_messages.push_back(QueuedMessage {
                    peer: queued_peer,
                    conversation_id: record.parent_conversation_id,
                    channel_id: record.channel_id,
                    message_id: item.message_id,
                    envelope_bytes: item.envelope_bytes.clone(),
                });
            }
            let queued_message_ids: HashSet<[u8; 16]> =
                queued_messages.iter().map(|item| item.message_id).collect();
            let mut restored_outgoing = HashSet::new();
            for item in &record.outgoing {
                if !restored_outgoing.insert(item.message_id)
                    || !receipt_expectations.contains_key(&item.message_id)
                {
                    return Err(ChatError::MlsRestore(
                        "restored channel outgoing state has no receipt expectation",
                    ));
                }
                let delivery = if queued_message_ids.contains(&item.message_id) {
                    match item.state_code {
                        OUTGOING_QUEUED_CODE => DeliveryState::Queued,
                        _ => {
                            return Err(ChatError::MlsRestore(
                                "restored queued channel message has an invalid state",
                            ));
                        }
                    }
                } else {
                    match item.state_code {
                        OUTGOING_SENT_CODE => DeliveryState::SentToPeer,
                        _ => {
                            return Err(ChatError::MlsRestore(
                                "restored channel receipt expectation has an invalid state",
                            ));
                        }
                    }
                };
                group.restore_outgoing(&item.message_id, delivery)?;
            }
            if receipt_expectations
                .keys()
                .any(|id| !restored_outgoing.contains(id))
                || queued_message_ids
                    .iter()
                    .any(|id| !receipt_expectations.contains_key(id))
            {
                return Err(ChatError::MlsRestore(
                    "restored channel pending state is incomplete",
                ));
            }
            if record
                .receipts
                .iter()
                .any(|item| queued_message_ids.contains(&item.message_id))
                && record.outgoing.iter().any(|item| {
                    queued_message_ids.contains(&item.message_id)
                        && item.state_code != OUTGOING_QUEUED_CODE
                })
            {
                return Err(ChatError::MlsRestore(
                    "restored channel queue state is inconsistent",
                ));
            }
            for message_id in receipt_expectations.keys() {
                match restored.message_conversations.get(message_id) {
                    Some(existing) if existing != &record.parent_conversation_id => {
                        return Err(ChatError::MlsRestore(
                            "restored message id is bound to two conversations",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        restored
                            .message_conversations
                            .insert(*message_id, record.parent_conversation_id);
                    }
                }
                match restored.message_channel_routes.get(message_id) {
                    Some(existing) if existing != &record.channel_id => {
                        return Err(ChatError::MlsRestore(
                            "restored message id is bound to two channel groups",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        restored
                            .message_channel_routes
                            .insert(*message_id, record.channel_id);
                    }
                }
            }
            restored.pending_receipts.extend(receipt_expectations);
            restored.offline_queue.extend(queued_messages);
            restored.channel_groups.insert(
                group_id,
                ChannelGroupState {
                    binding,
                    group,
                    awaited: BTreeSet::new(),
                    ready: true,
                },
            );
        }
        restored.active = first_joined;
        Ok(restored)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        identity: &Identity,
        config: NetworkConfig,
        file_config: FileConfig,
        security_config: SecurityConfig,
        transfer_timeout: Duration,
        storage: Option<Session>,
    ) -> Result<Self, ChatError> {
        if transfer_timeout < Duration::from_millis(1)
            || transfer_timeout > MAX_FILE_TRANSFER_TIMEOUT
        {
            return Err(ChatError::InvalidTransferTimeout);
        }
        if storage
            .as_ref()
            .is_some_and(|vault| vault.identity().peer_id() != identity.peer_id())
        {
            return Err(ChatError::ControlLogIdentityMismatch);
        }
        let restored = match storage.as_ref() {
            Some(storage) => Self::restore_joined_conversations(identity, storage)?,
            None => RestoredConversations::empty(),
        };
        let redial_config = RedialConfig::from(&config);
        let network = Network::start(identity, config)?;
        Ok(Self {
            identity: identity.clone(),
            network,
            conversations: restored.conversations,
            peer_conversations: restored.peer_conversations,
            pending_key_packages: HashMap::new(),
            pending_channel_key_packages: HashMap::new(),
            channel_groups: restored.channel_groups,
            pending_channel_setups: HashMap::new(),
            pending_channel_policy_acks: HashMap::new(),
            outstanding_setup: HashMap::new(),
            group_requests: HashMap::new(),
            outstanding_messages: HashMap::new(),
            message_conversations: restored.message_conversations,
            message_channel_routes: restored.message_channel_routes,
            pending_receipts: restored.pending_receipts,
            applied_commits: HashMap::new(),
            setup_replay: SetupReplayCache::default(),
            offline_queue: restored.offline_queue,
            redial_config,
            dialed_addresses: HashMap::new(),
            redial: HashMap::new(),
            connected_peers: BTreeSet::new(),
            messages: Vec::new(),
            active: restored.active,
            active_channel: restored.active_channel,
            file_config,
            security_config,
            outgoing_files: HashMap::new(),
            incoming_files: HashMap::new(),
            file_requests: HashMap::new(),
            transfer_timeout,
            transfer_deadlines: HashMap::new(),
            storage,
            last_error: None,
        })
    }

    /// Start with an explicit quarantine directory. Tests and installers can
    /// place ciphertext-only quarantine outside any executable directory. The
    /// default security config has no scanner and denies every release.
    pub fn start_with_file_config(
        identity: &Identity,
        config: NetworkConfig,
        file_config: FileConfig,
    ) -> Result<Self, ChatError> {
        Self::start_with_security_config(identity, config, file_config, SecurityConfig::default())
    }

    /// Start with an explicit quarantine directory and an independent scanner
    /// plus release policy supplied by the application.
    pub fn start_with_security_config(
        identity: &Identity,
        config: NetworkConfig,
        file_config: FileConfig,
        security_config: SecurityConfig,
    ) -> Result<Self, ChatError> {
        Self::start_with_transfer_timeout(
            identity,
            config,
            file_config,
            security_config,
            DEFAULT_FILE_TRANSFER_TIMEOUT,
        )
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn connection_state(&self) -> &ConnectionState {
        self.network.state()
    }

    pub fn listen_addresses(&self) -> Vec<libp2p::Multiaddr> {
        self.network.listen_addresses()
    }

    /// Snapshot of configured optional network capabilities and observed facts.
    /// Configuration fields are local settings; observed fields change only
    /// after the worker receives the corresponding libp2p event.
    pub fn network_privacy_status(&self) -> &NetworkPrivacyStatus {
        self.network.privacy_status()
    }

    /// Dial an address the user supplied and remember it for bounded redial.
    /// The initial dial does not count against the automatic retry limit.
    pub fn connect(&mut self, address: Multiaddr) -> Result<(), ChatError> {
        let peer = address_peer(&address)?;
        self.network.dial(address.clone())?;
        self.dialed_addresses.insert(peer, address);
        self.redial.insert(peer, RedialSlot::Dialing { attempt: 0 });
        Ok(())
    }

    /// Connect to a PeerId through the configured relay-only route. The user
    /// supplies only a destination PeerId; the worker builds the circuit from
    /// configured relays and rejects any direct fallback path.
    pub fn connect_relayed(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let address = self.network.relayed_address(peer)?;
        self.network.dial_relayed(peer)?;
        self.dialed_addresses.insert(peer, address);
        self.redial.insert(peer, RedialSlot::Dialing { attempt: 0 });
        Ok(())
    }

    /// Drop every live connection and suppress automatic redial until the user
    /// supplies a fresh explicit address.
    pub fn disconnect_all(&mut self) -> Result<(), ChatError> {
        self.network.disconnect_all()?;
        for slot in self.redial.values_mut() {
            *slot = RedialSlot::Suppressed;
        }
        self.connected_peers.clear();
        Ok(())
    }

    /// Drain all pending transport events. Invalid or rejected events are
    /// surfaced through [`Self::last_error`]; they never create fake state.
    pub fn poll(&mut self) {
        self.sweep_transfer_timeouts();
        let mut actions = Vec::new();
        while let Some(state) = self.network.poll_event() {
            match state {
                ConnectionState::Connected { peers } => {
                    let observed: BTreeSet<PeerId> = peers
                        .into_iter()
                        .filter_map(|peer| identity_peer(peer).ok())
                        .collect();
                    self.connected_peers = observed.clone();
                    actions.extend(observed.into_iter().map(ConnectionAction::Connected));
                }
                ConnectionState::Disconnected { peer } => {
                    if let Ok(peer) = identity_peer(peer) {
                        self.connected_peers.remove(&peer);
                        actions.push(ConnectionAction::Disconnected(peer));
                    }
                }
                ConnectionState::Failed {
                    peer: Some(peer), ..
                } => {
                    if let Ok(peer) = identity_peer(peer) {
                        actions.push(ConnectionAction::DialFailed(peer));
                    }
                }
                _ => {}
            }
        }
        while let Some(event) = self.network.poll_setup_event() {
            if let Err(error) = self.handle_setup_event(event) {
                self.last_error = Some(error.to_string());
            }
        }
        while let Some(event) = self.network.poll_message_event() {
            if let Err(error) = self.handle_message_event(event) {
                self.last_error = Some(error.to_string());
            }
        }
        while let Some(event) = self.network.poll_file_event() {
            if let Err(error) = self.handle_file_event(event) {
                self.last_error = Some(error.to_string());
            }
        }
        // Control frames have no application semantics yet. Drain the bounded
        // queue so transport health cannot stall, but never invent a capability
        // or delivery state from an opaque control frame.
        while self.network.poll_control_event().is_some() {}
        // Discovery, relay, NAT, and identify observations only update the
        // network's cached privacy snapshot. They are never promoted to saved
        // contacts, verified peers, connections, or NAT reachability claims.
        while self.network.poll_discovery_event().is_some() {}
        while self.network.poll_relay_event().is_some() {}
        while self.network.poll_nat_event().is_some() {}
        while self.network.poll_identify_event().is_some() {}
        for action in actions {
            match action {
                ConnectionAction::Connected(peer) => {
                    if self.redial.contains_key(&peer) {
                        self.redial.insert(peer, RedialSlot::Idle);
                    }
                    // Retry only after an observed Connected event for that
                    // peer. `retry_queued` rechecks the cached network state in
                    // case a Disconnected event arrived later in this batch.
                    if let Err(error) = self.retry_queued(&peer) {
                        self.last_error = Some(error.to_string());
                    }
                    self.retry_group_requests(&peer);
                }
                ConnectionAction::Disconnected(peer) => self.schedule_retry(&peer),
                ConnectionAction::DialFailed(peer) => {
                    if !self.is_connected(&peer) {
                        self.schedule_retry(&peer);
                    }
                }
            }
        }
        self.update_redial();
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    /// Honest redial intent for a saved peer address. This is local scheduler
    /// state and never substitutes for an observed `ConnectionState`.
    pub fn redial_state(&self, peer: &PeerId) -> RedialState {
        let Some(slot) = self.redial.get(peer) else {
            return RedialState::NoSavedAddress;
        };
        match slot {
            RedialSlot::Idle => RedialState::Idle,
            RedialSlot::Suppressed => RedialState::Suppressed,
            RedialSlot::Scheduled {
                attempt,
                delay,
                deadline,
            } => RedialState::Scheduled {
                attempt: *attempt,
                delay: *delay,
                remaining: deadline.saturating_duration_since(Instant::now()),
            },
            RedialSlot::Dialing { attempt } => RedialState::Dialing { attempt: *attempt },
            RedialSlot::Exhausted { attempts } => RedialState::Exhausted {
                attempts: *attempts,
            },
        }
    }

    /// Peers whose addresses were explicitly supplied by the user. No address
    /// is added by discovery, defaults, or redial itself.
    pub fn redial_peers(&self) -> Vec<PeerId> {
        self.dialed_addresses.keys().copied().collect()
    }

    fn schedule_retry(&mut self, peer: &PeerId) {
        if self.redial_config.max_attempts == 0 || !self.dialed_addresses.contains_key(peer) {
            return;
        }
        let slot = self.redial.get(peer).cloned().unwrap_or(RedialSlot::Idle);
        let attempt = match slot {
            RedialSlot::Idle => 1,
            RedialSlot::Dialing { attempt } => attempt.saturating_add(1),
            RedialSlot::Scheduled { .. }
            | RedialSlot::Suppressed
            | RedialSlot::Exhausted { .. } => return,
        };
        if attempt > self.redial_config.max_attempts {
            self.redial.insert(
                *peer,
                RedialSlot::Exhausted {
                    attempts: self.redial_config.max_attempts,
                },
            );
            return;
        }
        let delay = backoff_delay(&self.redial_config, attempt);
        self.redial.insert(
            *peer,
            RedialSlot::Scheduled {
                attempt,
                delay,
                deadline: Instant::now() + delay,
            },
        );
    }

    fn update_redial(&mut self) {
        let now = Instant::now();
        let peers: Vec<PeerId> = self.redial.keys().copied().collect();
        for peer in peers {
            let attempt = match self.redial.get(&peer).cloned() {
                Some(RedialSlot::Scheduled {
                    attempt, deadline, ..
                }) if now >= deadline => attempt,
                _ => continue,
            };
            if self.is_connected(&peer) {
                self.redial.insert(peer, RedialSlot::Idle);
                continue;
            }
            let Some(address) = self.dialed_addresses.get(&peer).cloned() else {
                continue;
            };
            self.redial.insert(peer, RedialSlot::Dialing { attempt });
            if let Err(error) = self.network.dial(address) {
                // Keep the attempt number so the next scheduling step advances
                // instead of restarting at attempt one forever.
                self.redial.insert(peer, RedialSlot::Dialing { attempt });
                self.last_error = Some(error.to_string());
                self.schedule_retry(&peer);
            }
        }
    }

    /// Begin a 1:1 MLS setup with an already connected peer. The returned
    /// status remains unjoined until the signed Welcome exchange completes.
    pub fn start_conversation(&mut self, peer: PeerId) -> Result<[u8; 16], ChatError> {
        if peer == self.identity.peer_id() {
            return Err(ChatError::InvalidPeerId(
                "cannot start a conversation with yourself".to_owned(),
            ));
        }
        if !self.is_connected(&peer) {
            return Err(ChatError::PeerNotConnected);
        }
        if self.peer_conversations.contains_key(&peer) {
            return Err(ChatError::AlreadyEstablished);
        }

        let conversation = match self.storage.as_ref() {
            Some(storage) => {
                MlsConversation::new_with_storage(&self.identity, storage.try_clone()?)?
            }
            None => MlsConversation::new(&self.identity)?,
        };
        let conversation_id = conversation.id();
        let transaction_id = random_id()?;
        self.send_setup(
            &peer,
            SetupMessage::KeyPackageRequest {
                conversation_id,
                transaction_id,
            },
            conversation_id,
            transaction_id,
        )?;
        let members = BTreeSet::from([self.identity.peer_id(), peer]);
        let mut state = ConversationState::new(conversation, self.identity.peer_id(), members);
        state.status = ConversationStatus::KeyPackageRequested;
        self.conversations.insert(conversation_id, state);
        self.peer_conversations.insert(peer, conversation_id);
        self.active = Some(conversation_id);
        self.active_channel
            .insert(conversation_id, DEFAULT_CHANNEL_ID);
        self.persist_conversation(conversation_id)?;
        Ok(conversation_id)
    }

    /// Compose, encrypt, and sign text in the default channel. This remains the
    /// compatibility entry point; all channel text uses the same signed MLS
    /// envelope path.
    pub fn send_text(&mut self, peer: PeerId, text: &str) -> Result<[u8; 16], ChatError> {
        self.send_channel_text(peer, DEFAULT_CHANNEL_ID, text)
    }

    /// Compose, encrypt, and sign text in one channel of the peer's MLS group.
    /// `channel_id` is inside the MLS application plaintext, not the envelope
    /// header. While a recipient is disconnected, only signed MLS ciphertext
    /// enters the in-memory queue; delivery still requires every expected
    /// verified receipt.
    pub fn send_channel_text(
        &mut self,
        peer: PeerId,
        channel_id: [u8; 16],
        text: &str,
    ) -> Result<[u8; 16], ChatError> {
        if text.trim().is_empty() {
            return Err(ChatError::EmptyMessage);
        }
        let conversation_id = *self
            .peer_conversations
            .get(&peer)
            .ok_or(ChatError::NoActiveConversation)?;
        let local = self.identity.peer_id();
        let (frame, recipients) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if state.status != ConversationStatus::Joined {
                return Err(ChatError::ConversationNotReady);
            }
            if state.pending_operation.is_some() {
                return Err(ChatError::GroupOperationPending);
            }
            let channel = state
                .channels
                .get(&channel_id)
                .ok_or(ChatError::ChannelNotFound)?;
            if !state.members.contains(&peer)
                || !state.members.contains(&local)
                || !channel.members.contains(&peer)
                || !channel.members.contains(&local)
            {
                return Err(ChatError::NotChannelMember);
            }
            (
                ChannelFrame::text(channel_id, channel.revision, text)?,
                channel
                    .members
                    .iter()
                    .copied()
                    .filter(|member| *member != local)
                    .collect::<Vec<_>>(),
            )
        };
        if channel_id != DEFAULT_CHANNEL_ID
            && !self
                .channel_groups
                .get(&channel_group_id(conversation_id, channel_id))
                .is_some_and(|state| state.ready)
        {
            return Err(ChatError::ChannelGroupNotReady);
        }
        self.broadcast_channel_frame(
            conversation_id,
            channel_id,
            frame,
            recipients,
            Some(text.to_owned()),
        )
    }

    /// Create a channel in a joined MLS group. Only the group admin may do this,
    /// and every listed member must already be in the MLS group. An empty
    /// member list means all current group members. The returned ID is random;
    /// the name is held only in memory and sent inside MLS ciphertext.
    pub fn create_channel(
        &mut self,
        conversation_id: [u8; 16],
        name: &str,
        members: Vec<PeerId>,
    ) -> Result<[u8; 16], ChatError> {
        let local = self.identity.peer_id();
        let (channel_id, frame, recipients) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                &state.status,
                state.pending_operation.is_some(),
            )?;
            if state.channels.len() >= MAX_CHANNELS_PER_GROUP {
                return Err(ChatError::ChannelLimit);
            }
            let members = if members.is_empty() {
                state.members.iter().copied().collect::<Vec<_>>()
            } else {
                members
            };
            let mut channel_id = random_id()?;
            let mut attempts = 0;
            while state.channels.contains_key(&channel_id) {
                channel_id = random_id()?;
                attempts += 1;
                if attempts >= 8 {
                    return Err(ChatError::ChannelLimit);
                }
            }
            let frame = ChannelFrame::create(channel_id, name, &members)?;
            if !members.iter().all(|peer| state.members.contains(peer)) {
                return Err(ChatError::NotChannelMember);
            }
            let recipients = state
                .members
                .iter()
                .copied()
                .filter(|member| *member != local)
                .collect::<Vec<_>>();
            (channel_id, frame, recipients)
        };
        let no_policy_recipients = recipients.is_empty();
        let message_id = self.broadcast_channel_frame(
            conversation_id,
            channel_id,
            frame.clone(),
            recipients,
            None,
        )?;
        let state = self
            .conversations
            .get_mut(&conversation_id)
            .ok_or(ChatError::UnknownConversation)?;
        state.channels.insert(
            channel_id,
            ChannelState {
                name: name.trim().to_owned(),
                creator: local,
                members: frame_members(&frame)?,
                revision: frame.revision,
                last_frame_id: Some(message_id),
            },
        );
        self.pending_channel_policy_acks.insert(
            message_id,
            PendingChannelPolicyAck {
                conversation_id,
                channel_id,
                recreate: false,
            },
        );
        if no_policy_recipients
            && let Some(trigger) = self.pending_channel_policy_acks.remove(&message_id)
        {
            self.start_channel_setup_for_channel(
                trigger.conversation_id,
                trigger.channel_id,
                trigger.recreate,
            )?;
        }
        self.persist_conversation(conversation_id)?;
        Ok(channel_id)
    }

    /// Rename a channel. Only the group admin may change channel metadata.
    pub fn rename_channel(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
        name: &str,
    ) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        let (frame, recipients) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                &state.status,
                state.pending_operation.is_some(),
            )?;
            let channel = state
                .channels
                .get(&channel_id)
                .ok_or(ChatError::ChannelNotFound)?;
            let frame = ChannelFrame::rename(channel_id, channel.revision.saturating_add(1), name)?;
            let recipients = state
                .members
                .iter()
                .copied()
                .filter(|member| *member != local)
                .collect::<Vec<_>>();
            (frame, recipients)
        };
        let message_id = self.broadcast_channel_frame(
            conversation_id,
            channel_id,
            frame.clone(),
            recipients,
            None,
        )?;
        if let Some(state) = self.conversations.get_mut(&conversation_id)
            && let Some(channel) = state.channels.get_mut(&channel_id)
        {
            channel.name = name.trim().to_owned();
            channel.revision = frame.revision;
            channel.last_frame_id = Some(message_id);
        }
        self.persist_conversation(conversation_id)?;
        Ok(())
    }

    /// Replace a channel's allowed-member set. Only the group admin may do this
    /// and every listed peer must be an active MLS group member.
    pub fn set_channel_members(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
        members: Vec<PeerId>,
    ) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        let (frame, recipients, members_changed) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                &state.status,
                state.pending_operation.is_some(),
            )?;
            let channel = state
                .channels
                .get(&channel_id)
                .ok_or(ChatError::ChannelNotFound)?;
            let frame = ChannelFrame::set_members(
                channel_id,
                channel.revision.saturating_add(1),
                &members,
            )?;
            if !members.iter().all(|peer| state.members.contains(peer)) {
                return Err(ChatError::NotChannelMember);
            }
            let recipients = state
                .members
                .iter()
                .copied()
                .filter(|member| *member != local)
                .collect::<Vec<_>>();
            let next_members = members.iter().copied().collect::<BTreeSet<_>>();
            let members_changed = channel.members != next_members;
            (frame, recipients, members_changed)
        };
        let no_policy_recipients = recipients.is_empty();
        let message_id = self.broadcast_channel_frame(
            conversation_id,
            channel_id,
            frame.clone(),
            recipients,
            None,
        )?;
        if let Some(state) = self.conversations.get_mut(&conversation_id)
            && let Some(channel) = state.channels.get_mut(&channel_id)
        {
            channel.members = members.into_iter().collect();
            channel.revision = frame.revision;
            channel.last_frame_id = Some(message_id);
        }
        if members_changed {
            // Fail closed immediately: no ciphertext from the old group is
            // reused under the new policy. Setup resumes after the policy is
            // acknowledged by every parent-group member.
            self.drop_channel_group(conversation_id, channel_id)?;
            self.pending_channel_policy_acks.insert(
                message_id,
                PendingChannelPolicyAck {
                    conversation_id,
                    channel_id,
                    recreate: true,
                },
            );
            if no_policy_recipients
                && let Some(trigger) = self.pending_channel_policy_acks.remove(&message_id)
            {
                self.start_channel_setup_for_channel(
                    trigger.conversation_id,
                    trigger.channel_id,
                    trigger.recreate,
                )?;
            }
        }
        self.persist_conversation(conversation_id)?;
        Ok(())
    }

    /// Ask a connected peer to join an existing MLS group. Only the group
    /// administrator may start this exchange, and no other operation may be
    /// pending. The group changes only after a signed KeyPackage response.
    pub fn add_member(&mut self, conversation_id: [u8; 16], peer: PeerId) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        if peer == local {
            return Err(ChatError::InvalidGroupTarget("cannot add the local peer"));
        }
        if !self.is_connected(&peer) {
            return Err(ChatError::PeerNotConnected);
        }
        let state = self
            .conversations
            .get(&conversation_id)
            .ok_or(ChatError::UnknownConversation)?;
        Self::check_admin(
            state.admin,
            local,
            &state.status,
            state.pending_operation.is_some(),
        )?;
        if state.members.contains(&peer) {
            return Err(ChatError::AlreadyEstablished);
        }
        let transaction_id = random_id()?;
        self.send_setup(
            &peer,
            SetupMessage::GroupJoinRequest {
                conversation_id,
                transaction_id,
            },
            conversation_id,
            transaction_id,
        )
    }

    /// Remove one member with a signed MLS commit. Only the administrator may
    /// do this, self-removal is denied, and remaining members must acknowledge
    /// the commit before the operation is considered complete.
    pub fn remove_member(
        &mut self,
        conversation_id: [u8; 16],
        peer: PeerId,
    ) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        let transaction_id = random_id()?;
        if peer == local {
            return Err(ChatError::InvalidGroupTarget("self-removal is not allowed"));
        }
        {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                &state.status,
                state.pending_operation.is_some(),
            )?;
            if !state.members.contains(&peer) {
                return Err(ChatError::NotGroupMember);
            }
            let commit = state.conversation.remove_member(&peer)?;
            state.members.remove(&peer);
            state.prune_removed_members();
            state.sync_default_channel();
            self.peer_conversations.remove(&peer);
            let awaited = state
                .members
                .iter()
                .copied()
                .filter(|member| *member != local)
                .map(|member| (member, false))
                .collect();
            state.pending_operation = Some(PendingOperation {
                transaction_id,
                operation: GroupOperation::Remove,
                target: Some(peer),
                commit,
                awaited,
                welcome_target: None,
                welcome: None,
                welcome_acked: true,
            });
        }
        self.drop_all_channel_groups(conversation_id)?;
        self.prune_removed_peer_state(conversation_id, &peer);
        self.persist_conversation(conversation_id)?;
        self.dispatch_group_operation(conversation_id)
    }

    /// Refresh the administrator's MLS leaf key with a signed Update commit.
    /// Every other member must acknowledge it before the operation completes.
    pub fn update_member_key(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        let transaction_id = random_id()?;
        {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                &state.status,
                state.pending_operation.is_some(),
            )?;
            let commit = state.conversation.self_update_commit()?;
            let awaited = state
                .members
                .iter()
                .copied()
                .filter(|member| *member != local)
                .map(|member| (member, false))
                .collect();
            state.pending_operation = Some(PendingOperation {
                transaction_id,
                operation: GroupOperation::Update,
                target: None,
                commit,
                awaited,
                welcome_target: None,
                welcome: None,
                welcome_acked: true,
            });
        }
        self.persist_conversation(conversation_id)?;
        self.dispatch_group_operation(conversation_id)
    }

    /// Select a conversation for the GUI. This changes only local view state;
    /// an unavailable channel selection falls back to the default channel.
    pub fn select_conversation(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let state = self
            .conversations
            .get(&conversation_id)
            .ok_or(ChatError::UnknownConversation)?;
        let selected = self
            .active_channel
            .get(&conversation_id)
            .copied()
            .unwrap_or(DEFAULT_CHANNEL_ID);
        if !state.channels.contains_key(&selected) {
            self.active_channel
                .insert(conversation_id, DEFAULT_CHANNEL_ID);
        }
        self.active = Some(conversation_id);
        Ok(())
    }

    /// Select one channel in a joined conversation for the local GUI. This
    /// changes only view state and never sends a frame or changes MLS state.
    pub fn select_channel(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
    ) -> Result<(), ChatError> {
        let state = self
            .conversations
            .get(&conversation_id)
            .ok_or(ChatError::UnknownConversation)?;
        if !state.channels.contains_key(&channel_id) {
            return Err(ChatError::ChannelNotFound);
        }
        self.active = Some(conversation_id);
        self.active_channel.insert(conversation_id, channel_id);
        self.persist_conversation(conversation_id)?;
        Ok(())
    }

    /// Number of outbound file frames whose transport responses are still
    /// being tracked. This is a public count only; no file bytes or keys are
    /// exposed. It returns to zero on completion, failure, timeout, or abort.
    pub fn pending_file_requests(&self) -> usize {
        self.file_requests.len()
    }

    /// Number of signed ciphertext envelopes waiting for a reconnect with the
    /// given peer. This count is public metadata; no text or ciphertext is
    /// exposed through this accessor.
    pub fn queued_count(&self, peer: &PeerId) -> usize {
        self.offline_queue
            .iter()
            .filter(|item| item.peer == *peer)
            .count()
    }

    /// Offer one local file to a connected peer with a joined MLS conversation.
    /// The file is encrypted with a fresh content key and chunked before any
    /// frame is sent. This does not claim that the peer received or accepted it.
    pub fn send_file(&mut self, peer: PeerId, path: &Path) -> Result<[u8; 16], ChatError> {
        if !self.is_connected(&peer) {
            return Err(ChatError::PeerNotConnected);
        }
        if !self.conversation_ready(&peer) {
            return Err(ChatError::ConversationNotReady);
        }
        if self
            .outgoing_files
            .get(&peer)
            .is_some_and(|transfer| transfer.status().active())
            || self
                .incoming_files
                .get(&peer)
                .is_some_and(|transfer| transfer.status().active())
        {
            return Err(ChatError::FileTransferLimit);
        }
        self.outgoing_files.remove(&peer);
        self.incoming_files.remove(&peer);

        let outgoing = OutgoingFile::new(path)?;
        let transfer_id = *outgoing.transfer_id();
        let frame = outgoing.offer_frame(&self.identity)?;
        let request_id = self
            .network
            .send_file(swarm_peer(&peer)?, frame.to_bytes()?)?;
        self.file_requests
            .insert(request_id, FileRequestKind::Offer { peer, transfer_id });
        self.outgoing_files.insert(peer, outgoing);
        self.start_transfer_deadline(peer, transfer_id);
        Ok(transfer_id)
    }

    /// Public status for every file transfer tracked in this session. A
    /// completed integrity check starts as `Unavailable` until an independent
    /// scanner is invoked, and `released` only becomes true after policy-gated
    /// release.
    pub fn file_transfers(&self) -> Vec<FileTransferInfo> {
        let mut transfers =
            Vec::with_capacity(self.outgoing_files.len() + self.incoming_files.len());
        for (peer, outgoing) in &self.outgoing_files {
            transfers.push(FileTransferInfo {
                transfer_id: *outgoing.transfer_id(),
                peer: *peer,
                direction: TransferDirection::Outgoing,
                name: outgoing.name().to_owned(),
                size: outgoing.size(),
                chunks_done: match outgoing.status() {
                    p2p_files::TransferStatus::Sending { acked } => acked,
                    p2p_files::TransferStatus::IntegrityVerified => outgoing.chunk_count(),
                    _ => 0,
                },
                chunks_total: outgoing.chunk_count(),
                status: outgoing.status(),
                scan: outgoing.scan_status(),
                approval: ReleaseApproval::NotApplicable,
                format: None,
                released: false,
                quarantine_deleted: false,
            });
        }
        for (peer, incoming) in &self.incoming_files {
            transfers.push(FileTransferInfo {
                transfer_id: *incoming.transfer_id(),
                peer: *peer,
                direction: TransferDirection::Incoming,
                name: incoming.name().to_owned(),
                size: incoming.size(),
                chunks_done: match incoming.status() {
                    p2p_files::TransferStatus::Receiving { received } => received,
                    p2p_files::TransferStatus::IntegrityVerified => incoming.chunk_count(),
                    _ => 0,
                },
                chunks_total: incoming.chunk_count(),
                status: incoming.status(),
                scan: incoming.scan_status(),
                approval: incoming.approval(),
                format: incoming.format(),
                released: incoming.released(),
                quarantine_deleted: incoming.quarantine_deleted(),
            });
        }
        transfers
    }

    /// The scanner/release policy attached to this controller. The default
    /// reports no scanner and denies every release.
    pub fn security_config(&self) -> &SecurityConfig {
        &self.security_config
    }

    /// Whether this controller permits explicit quarantine deletion. The
    /// default is `Retain`, so no deletion action is offered by the UI.
    pub fn quarantine_deletion_policy(&self) -> p2p_files::QuarantineDeletionPolicy {
        self.file_config.quarantine_deletion
    }

    /// Ask the configured independent scanner to inspect one integrity-verified
    /// incoming transfer. Plaintext exists only in a zeroizing memory buffer
    /// for the duration of this call. With no scanner configured this records
    /// `Unavailable`; it never records a clean result.
    pub fn scan_file(&mut self, peer: PeerId) -> Result<ScanStatus, ChatError> {
        let config = self.security_config.clone();
        let outcome = {
            let incoming = self
                .incoming_files
                .get(&peer)
                .ok_or(ChatError::FileTransferMissing)?;
            let bytes = incoming.plaintext_for_scan()?;
            config.scan(&ScanRequest {
                name: incoming.name(),
                bytes: bytes.as_slice(),
            })
        };
        let policy = config.release_policy().clone();
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        incoming.apply_scan(outcome)?;
        incoming.refresh_approval(&policy);
        Ok(incoming.scan_status())
    }

    /// Record explicit user approval for one incoming transfer. Approval is
    /// available only after a clean independent scan, validated format, and
    /// policy check; cancellation is terminal for that transfer.
    pub fn approve_file(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let policy = self.security_config.release_policy().clone();
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        Ok(incoming.approve(&policy)?)
    }

    /// Cancel a pending or approved in-memory release for a completed transfer.
    /// This is deliberately separate from aborting a transfer: it does not
    /// delete quarantine ciphertext and does not affect an active transfer.
    pub fn cancel_file(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        if !incoming.status().completed() {
            return Err(ChatError::FileTransferNotComplete);
        }
        Ok(incoming.cancel()?)
    }

    /// Abort the active transfer with one peer. This stops new file frames,
    /// drops pending response bookkeeping, clears the in-memory key, and
    /// removes incomplete quarantine ciphertext. A transport request already
    /// queued in the worker cannot be withdrawn through the pinned
    /// request-response API, so any late response is ignored rather than
    /// applied. A completed transfer is not abortable; use `cancel_file` for
    /// its release decision.
    pub fn abort_file(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let deadline = self
            .transfer_deadlines
            .get(&peer)
            .copied()
            .ok_or(ChatError::FileTransferNotActive)?;
        self.abort_transfer(peer, deadline.transfer_id, "Transfer aborted by user")
    }

    /// Explicitly delete one incoming transfer's quarantine ciphertext after a
    /// verified transfer has been released or its release was cancelled. This
    /// is denied under the default `Retain` policy and never deletes plaintext
    /// or aborts an active transfer. Filesystem deletion is not secure erasure
    /// on SSD/CoW storage.
    pub fn delete_file_quarantine(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        Ok(incoming.delete_quarantine()?)
    }

    /// Explicit user approval followed immediately by in-memory release. The
    /// returned buffer is zeroized when dropped; no plaintext file is written.
    pub fn approve_and_release_file(&mut self, peer: PeerId) -> Result<ReleasedFile, ChatError> {
        self.approve_file(peer)?;
        self.release_file(peer)
    }

    /// Release an incoming transfer into a zeroizing in-memory buffer after a
    /// clean independent scan, validated format, policy check, and explicit
    /// user approval. This deliberately does not write plaintext to disk.
    pub fn release_file(&mut self, peer: PeerId) -> Result<ReleasedFile, ChatError> {
        let policy = self.security_config.release_policy().clone();
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        Ok(incoming.release(&policy)?)
    }

    fn conversation_ready(&self, peer: &PeerId) -> bool {
        self.peer_conversations
            .get(peer)
            .and_then(|id| self.conversations.get(id))
            .is_some_and(|state| {
                state.status == ConversationStatus::Joined && state.members.contains(peer)
            })
    }

    /// Resend queued ciphertext only after the caller has observed a Connected
    /// event for this peer. Queue entries stay untouched on transport errors so
    /// they can be tried on the next observed reconnect.
    fn retry_queued(&mut self, peer: &PeerId) -> Result<(), ChatError> {
        let mut remaining = VecDeque::new();
        let mut last_error = None;
        let mut changed = HashSet::new();
        while let Some(item) = self.offline_queue.pop_front() {
            if item.peer != *peer {
                remaining.push_back(item);
                continue;
            }
            match self.try_send_queued(&item) {
                Ok(()) => {
                    changed.insert(item.conversation_id);
                }
                Err(error) => {
                    remaining.push_back(item);
                    last_error = Some(error);
                }
            }
        }
        self.offline_queue = remaining;
        for conversation_id in changed {
            self.persist_conversation(conversation_id)?;
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn try_send_queued(&mut self, item: &QueuedMessage) -> Result<(), ChatError> {
        if !self.is_connected(&item.peer) {
            return Err(ChatError::PeerNotConnected);
        }
        let ready = self
            .conversations
            .get(&item.conversation_id)
            .is_some_and(|state| {
                state.members.contains(&item.peer)
                    && state.status == ConversationStatus::Joined
                    && state.pending_operation.is_none()
            })
            && (item.channel_id == DEFAULT_CHANNEL_ID
                || self
                    .channel_groups
                    .get(&channel_group_id(item.conversation_id, item.channel_id))
                    .is_some_and(|state| state.ready));
        if !ready {
            return Err(ChatError::ConversationNotReady);
        }

        let request_id = self
            .network
            .send_message(swarm_peer(&item.peer)?, item.envelope_bytes.clone())?;
        let channel_route = (item.channel_id != DEFAULT_CHANNEL_ID).then_some(item.channel_id);
        let transition = match self.message_group_delivery_state(
            item.conversation_id,
            channel_route,
            &item.message_id,
        ) {
            Some(DeliveryState::SentToPeer)
            | Some(DeliveryState::Delivered)
            | Some(DeliveryState::Read)
            | Some(DeliveryState::Failed) => Ok(()),
            _ => self.mark_message_group(
                item.conversation_id,
                channel_route,
                item.message_id,
                DeliveryState::SentToPeer,
            ),
        };
        if let Err(error) = transition {
            let _ = self.outstanding_messages.remove(&request_id);
            let _ = self.mark_message_group(
                item.conversation_id,
                channel_route,
                item.message_id,
                DeliveryState::Failed,
            );
            self.set_line_delivery(item.message_id, DeliveryState::Failed);
            self.last_error = Some(error.to_string());
            self.persist_conversation(item.conversation_id)?;
            return Ok(());
        }

        self.outstanding_messages
            .insert(request_id, item.message_id);
        self.set_line_delivery(item.message_id, DeliveryState::SentToPeer);
        Ok(())
    }

    pub fn active_info(&self) -> Option<ConversationInfo> {
        self.active.and_then(|id| self.info(id))
    }

    pub fn conversation_infos(&self) -> Vec<ConversationInfo> {
        self.conversations
            .keys()
            .filter_map(|id| self.info(*id))
            .collect()
    }

    pub fn active_peer(&self) -> Option<PeerId> {
        self.active
            .and_then(|id| self.conversations.get(&id))
            .and_then(|state| Self::display_peer(state, &self.identity.peer_id()))
    }

    /// Decrypted text for the active conversation and channel, in
    /// receive/compose order. Other channels remain in memory but are hidden.
    pub fn active_messages(&self) -> Vec<ChatMessage> {
        let Some(active) = self.active else {
            return Vec::new();
        };
        let channel = self
            .active_channel
            .get(&active)
            .copied()
            .unwrap_or(DEFAULT_CHANNEL_ID);
        self.messages
            .iter()
            .filter(|message| {
                message.channel_id == channel
                    && self.message_conversations.get(&message.message_id) == Some(&active)
            })
            .cloned()
            .collect()
    }

    fn info(&self, conversation_id: [u8; 16]) -> Option<ConversationInfo> {
        let state = self.conversations.get(&conversation_id)?;
        let channels = state
            .channels
            .iter()
            .map(|(id, channel)| {
                let policy_acknowledged = channel
                    .last_frame_id
                    .is_none_or(|message_id| !self.pending_receipts.contains_key(&message_id));
                let group_status = if *id == DEFAULT_CHANNEL_ID {
                    ChannelGroupStatus::DefaultOnParent
                } else {
                    match self
                        .channel_groups
                        .get(&channel_group_id(conversation_id, *id))
                    {
                        Some(state) if state.ready => ChannelGroupStatus::DerivedReady,
                        Some(state) => ChannelGroupStatus::DerivedSettingUp {
                            awaited: state.awaited.len(),
                        },
                        None => ChannelGroupStatus::Missing,
                    }
                };
                ChannelInfo {
                    channel_id: *id,
                    name: channel.name.clone(),
                    creator: channel.creator,
                    members: channel.members.iter().copied().collect(),
                    revision: channel.revision,
                    policy_acknowledged,
                    group_status,
                }
            })
            .collect();
        let active_channel = self
            .active_channel
            .get(&conversation_id)
            .copied()
            .filter(|id| state.channels.contains_key(id));
        Some(ConversationInfo {
            conversation_id,
            peer: Self::display_peer(state, &self.identity.peer_id())?,
            admin: state.admin,
            members: state.members.iter().copied().collect(),
            epoch: state.conversation.epoch(),
            status: state.status.clone(),
            pending_operation: state.pending_operation.as_ref().map(|op| op.operation),
            channels,
            active_channel,
        })
    }

    fn display_peer(state: &ConversationState, local: &PeerId) -> Option<PeerId> {
        state
            .members
            .iter()
            .copied()
            .find(|member| member != local)
            .or_else(|| state.members.iter().copied().next())
    }

    fn is_connected(&self, peer: &PeerId) -> bool {
        // Use the controller's own projection of observed Connected events.
        // A transient peerless transport failure is advisory and must not make
        // already-authenticated peers look offline.
        self.connected_peers.contains(peer)
    }

    /// Persist the encrypted application-policy snapshot for one conversation.
    /// Memory-only controllers are a no-op; vault-backed controllers write the
    /// snapshot under the group blind index at the group's current epoch.
    fn persist_conversation(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let (epoch, bytes) = {
            let Some(state) = self.conversations.get(&conversation_id) else {
                return Ok(());
            };
            let peer = Self::display_peer(state, &self.identity.peer_id())
                .ok_or(ChatError::MlsRestore("conversation has no display peer"))?;
            let active_channel = self.active_channel.get(&conversation_id).copied();
            let record = PersistedConversation::from_state(
                state,
                peer,
                active_channel,
                &self.pending_receipts,
                &self.message_conversations,
                &self.message_channel_routes,
                &self.offline_queue,
            );
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| ChatError::MlsRestore("conversation metadata encoding failed"))?;
            (state.conversation.epoch(), bytes)
        };
        // A not-yet-ready channel group has no authenticated application
        // record. Its MLS provider state may already be staged or flushed, so
        // restart fails closed instead of reviving an incomplete setup.
        let mut channel_records: Vec<([u8; 16], u64, Vec<u8>)> = Vec::new();
        {
            let groups: Vec<&ChannelGroupState> = self
                .channel_groups
                .values()
                .filter(|group| {
                    group.ready
                        && group.binding.parent_conversation_id() == conversation_id
                        && self
                            .conversations
                            .get(&conversation_id)
                            .is_some_and(|state| {
                                state.channels.contains_key(&group.binding.channel_id())
                            })
                })
                .collect();
            let Some(state) = self.conversations.get(&conversation_id) else {
                return Ok(());
            };
            for group in groups {
                let record = PersistedChannelGroup::from_state(
                    state,
                    group,
                    &self.pending_receipts,
                    &self.message_conversations,
                    &self.message_channel_routes,
                    &self.offline_queue,
                )?;
                let bytes = serde_json::to_vec(&record)
                    .map_err(|_| ChatError::MlsRestore("channel group metadata encoding failed"))?;
                channel_records.push((group.binding.group_id(), group.group.epoch(), bytes));
            }
        }
        if let Some(storage) = self.storage.as_mut() {
            storage.store_mls_state(
                &conversation_id,
                PERSISTED_CONVERSATION_LABEL,
                PERSISTED_CONVERSATION_LABEL.as_bytes(),
                epoch,
                &bytes,
            )?;
            for (group_id, group_epoch, bytes) in channel_records {
                storage.store_mls_state(
                    &group_id,
                    PERSISTED_CHANNEL_GROUP_LABEL,
                    PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
                    group_epoch,
                    &bytes,
                )?;
            }
        }
        Ok(())
    }

    fn set_status(
        &mut self,
        conversation_id: [u8; 16],
        status: ConversationStatus,
    ) -> Result<(), ChatError> {
        if let Some(state) = self.conversations.get_mut(&conversation_id) {
            state.status = status;
            self.persist_conversation(conversation_id)?;
        }
        Ok(())
    }

    fn check_admin(
        admin: PeerId,
        local: PeerId,
        status: &ConversationStatus,
        pending: bool,
    ) -> Result<(), ChatError> {
        if admin != local {
            return Err(ChatError::NotAdmin);
        }
        if *status != ConversationStatus::Joined {
            return Err(ChatError::ConversationNotReady);
        }
        if pending {
            return Err(ChatError::GroupOperationPending);
        }
        Ok(())
    }

    fn send_group_request(
        &mut self,
        peer: &PeerId,
        message: SetupMessage,
        request: GroupRequest,
    ) -> Result<(), ChatError> {
        if message.transaction_id() != &request.transaction_id {
            return Err(ChatError::InvalidSetup(
                "group request transaction ID mismatch",
            ));
        }
        let frame = SetupEnvelope::new(&self.identity, message)?;
        let request_id = self
            .network
            .send_setup(swarm_peer(peer)?, frame.to_bytes()?)?;
        self.group_requests.insert(request_id, request);
        Ok(())
    }

    fn dispatch_group_operation(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let Some(state) = self.conversations.get(&conversation_id) else {
            return Err(ChatError::UnknownConversation);
        };
        let Some(operation) = state.pending_operation.as_ref() else {
            return Ok(());
        };
        let (transaction_id, op, target, commit, awaited, welcome_target, welcome) = (
            operation.transaction_id,
            operation.operation,
            operation.target,
            operation.commit.clone(),
            operation.awaited.clone(),
            operation.welcome_target,
            operation.welcome.clone(),
        );

        if let Some(joiner) = welcome_target {
            if let Some(welcome) = welcome {
                if self.is_connected(&joiner) {
                    let request = GroupRequest {
                        conversation_id,
                        channel_scope: None,
                        transaction_id,
                        peer: joiner,
                        operation: GroupOperation::Add,
                        kind: GroupRequestKind::Welcome,
                    };
                    if let Err(error) = self.send_group_request(
                        &joiner,
                        SetupMessage::GroupWelcome {
                            conversation_id,
                            transaction_id,
                            welcome,
                        },
                        request,
                    ) {
                        self.last_error = Some(error.to_string());
                    }
                } else {
                    self.last_error =
                        Some("group join is pending until the new member reconnects".to_owned());
                }
            } else {
                self.last_error = Some("group Welcome is missing".to_owned());
            }
        }

        for peer in awaited.keys().copied() {
            if peer == self.identity.peer_id() {
                continue;
            }
            if !self.is_connected(&peer) {
                self.last_error =
                    Some("group operation is pending until every member reconnects".to_owned());
                continue;
            }
            let request = GroupRequest {
                conversation_id,
                channel_scope: None,
                transaction_id,
                peer,
                operation: op,
                kind: GroupRequestKind::Commit,
            };
            if let Err(error) = self.send_group_request(
                &peer,
                SetupMessage::GroupCommit {
                    conversation_id,
                    transaction_id,
                    operation: op,
                    target,
                    commit: commit.clone(),
                },
                request,
            ) {
                self.last_error = Some(error.to_string());
            }
        }
        Ok(())
    }

    fn retry_group_requests(&mut self, peer: &PeerId) {
        let conversations: Vec<[u8; 16]> = self.conversations.keys().copied().collect();
        for conversation_id in conversations {
            let snapshot = {
                let Some(state) = self.conversations.get(&conversation_id) else {
                    continue;
                };
                let Some(operation) = state.pending_operation.as_ref() else {
                    continue;
                };
                (
                    operation.transaction_id,
                    operation.operation,
                    operation.target,
                    operation.commit.clone(),
                    operation.awaited.get(peer).copied(),
                    operation.welcome_target,
                    operation.welcome.clone(),
                    operation.welcome_acked,
                )
            };
            let (
                transaction_id,
                op,
                target,
                commit,
                awaited,
                welcome_target,
                welcome,
                welcome_acked,
            ) = snapshot;
            if welcome_target == Some(*peer)
                && !welcome_acked
                && let Some(welcome) = welcome
            {
                let request = GroupRequest {
                    conversation_id,
                    channel_scope: None,
                    transaction_id,
                    peer: *peer,
                    operation: GroupOperation::Add,
                    kind: GroupRequestKind::Welcome,
                };
                if let Err(error) = self.send_group_request(
                    peer,
                    SetupMessage::GroupWelcome {
                        conversation_id,
                        transaction_id,
                        welcome,
                    },
                    request,
                ) {
                    self.last_error = Some(error.to_string());
                }
            }
            if awaited == Some(false) {
                let request = GroupRequest {
                    conversation_id,
                    channel_scope: None,
                    transaction_id,
                    peer: *peer,
                    operation: op,
                    kind: GroupRequestKind::Commit,
                };
                if let Err(error) = self.send_group_request(
                    peer,
                    SetupMessage::GroupCommit {
                        conversation_id,
                        transaction_id,
                        operation: op,
                        target,
                        commit,
                    },
                    request,
                ) {
                    self.last_error = Some(error.to_string());
                }
            }
        }
    }

    fn finish_operation_if_ready(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let ready = self
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pending_operation.as_ref())
            .is_some_and(|operation| {
                operation.welcome_acked && operation.awaited.values().all(|acked| *acked)
            });
        if ready && let Some(state) = self.conversations.get_mut(&conversation_id) {
            state.pending_operation = None;
            self.persist_conversation(conversation_id)?;
        }
        Ok(())
    }

    fn refresh_peer_conversations(&mut self, conversation_id: [u8; 16], local: &PeerId) {
        self.peer_conversations
            .retain(|peer, id| *id != conversation_id || peer == local);
        let members: Vec<PeerId> = self
            .conversations
            .get(&conversation_id)
            .map(|state| state.members.iter().copied().collect())
            .unwrap_or_default();
        for member in members {
            if member != *local {
                self.peer_conversations.insert(member, conversation_id);
            }
        }
    }

    /// Drop controller state that is no longer meaningful once a peer leaves
    /// the MLS group. Without this, a receipt expectation or offline queue item
    /// for the removed member would be persisted and then rejected as
    /// inconsistent when the vault is restored.
    fn prune_removed_peer_state(&mut self, conversation_id: [u8; 16], removed: &PeerId) {
        let mut empty_messages = Vec::new();
        for (message_id, peers) in &mut self.pending_receipts {
            if self.message_conversations.get(message_id) != Some(&conversation_id) {
                continue;
            }
            peers.remove(removed);
            if peers.is_empty() {
                empty_messages.push(*message_id);
            }
        }
        for message_id in empty_messages {
            self.pending_receipts.remove(&message_id);
            self.message_conversations.remove(&message_id);
            self.message_channel_routes.remove(&message_id);
        }
        self.offline_queue
            .retain(|item| item.conversation_id != conversation_id || item.peer != *removed);
    }

    fn remove_local_conversation(&mut self, conversation_id: [u8; 16]) {
        // Collect every derived group before dropping in-memory state so the
        // encrypted records are deleted too. A removed parent must never be
        // restored with stale channel ciphertext. Storage is authoritative
        // here: a persisted group that is not currently loaded still belongs
        // to this parent.
        let mut derived_group_ids: BTreeSet<[u8; 16]> = self
            .channel_groups
            .values()
            .filter(|state| state.binding.parent_conversation_id() == conversation_id)
            .map(|state| state.binding.group_id())
            .collect();
        let mut derivation_error = None;
        if let Some(storage) = self.storage.as_ref() {
            match storage.mls_group_ids() {
                Ok(group_ids) => {
                    for group_id in group_ids {
                        match storage.load_mls_state(
                            &group_id,
                            PERSISTED_CHANNEL_GROUP_LABEL,
                            PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
                        ) {
                            Ok(Some(bytes)) => match PersistedChannelGroup::decode(&bytes) {
                                Ok(record) if record.parent_conversation_id == conversation_id => {
                                    derived_group_ids.insert(group_id);
                                }
                                Ok(_) => {}
                                Err(error) => derivation_error = Some(error.to_string()),
                            },
                            Ok(None) => {}
                            Err(error) => derivation_error = Some(error.to_string()),
                        }
                    }
                }
                Err(error) => derivation_error = Some(error.to_string()),
            }
        }
        let derived_group_ids: Vec<[u8; 16]> = derived_group_ids.into_iter().collect();
        self.conversations.remove(&conversation_id);
        self.pending_key_packages
            .retain(|(id, _), _| *id != conversation_id);
        self.pending_channel_key_packages
            .retain(|scope, _| scope.parent_conversation_id != conversation_id);
        self.channel_groups
            .retain(|_, state| state.binding.parent_conversation_id() != conversation_id);
        self.pending_channel_setups
            .retain(|_, setup| setup.scope.parent_conversation_id != conversation_id);
        self.pending_channel_policy_acks
            .retain(|_, trigger| trigger.conversation_id != conversation_id);
        self.outstanding_setup
            .retain(|_, setup| setup.conversation_id != conversation_id);
        self.group_requests
            .retain(|_, request| request.conversation_id != conversation_id);
        self.applied_commits.remove(&conversation_id);
        self.active_channel.remove(&conversation_id);
        self.peer_conversations
            .retain(|_, id| *id != conversation_id);
        self.offline_queue
            .retain(|item| item.conversation_id != conversation_id);
        let affected: Vec<[u8; 16]> = self
            .message_conversations
            .iter()
            .filter_map(|(message_id, id)| (*id == conversation_id).then_some(*message_id))
            .collect();
        for message_id in affected {
            self.message_conversations.remove(&message_id);
            self.message_channel_routes.remove(&message_id);
            self.pending_receipts.remove(&message_id);
        }
        if self.active == Some(conversation_id) {
            self.active = None;
        }
        if let Some(error) = derivation_error {
            self.last_error = Some(error);
        }
        let deletions = self
            .storage
            .as_mut()
            .map(|storage| storage.delete_mls_state_group(&conversation_id));
        if let Some(Err(error)) = deletions {
            self.last_error = Some(error.to_string());
        }
        if let Some(storage) = self.storage.as_mut() {
            for group_id in derived_group_ids {
                if let Err(error) = storage.delete_mls_state_group(&group_id) {
                    self.last_error = Some(error.to_string());
                    break;
                }
            }
        }
    }

    fn send_setup(
        &mut self,
        peer: &PeerId,
        message: SetupMessage,
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
    ) -> Result<(), ChatError> {
        if message.conversation_id() != &conversation_id
            || message.transaction_id() != &transaction_id
        {
            return Err(ChatError::InvalidSetup("outbound setup IDs mismatch"));
        }
        let kind = OutgoingSetupKind::from_message(&message)?;
        let scope = message.channel_scope();
        let frame = SetupEnvelope::new(&self.identity, message)?;
        let request_id = self
            .network
            .send_setup(swarm_peer(peer)?, frame.to_bytes()?)?;
        self.outstanding_setup.insert(
            request_id,
            OutgoingSetup {
                conversation_id,
                transaction_id,
                kind,
                scope,
            },
        );
        Ok(())
    }

    fn respond_setup(
        &self,
        response_id: SetupResponseId,
        message: SetupMessage,
    ) -> Result<(), ChatError> {
        let frame = SetupEnvelope::new(&self.identity, message)?;
        Ok(self
            .network
            .respond_to_setup(response_id, frame.to_bytes()?)?)
    }

    fn decode_setup(
        swarm_peer: SwarmPeerId,
        bytes: &[u8],
    ) -> Result<(PeerId, SetupEnvelope), ChatError> {
        let peer = identity_peer(swarm_peer)?;
        let frame = SetupEnvelope::from_bytes(bytes)?;
        frame.require_pq()?;
        frame.verify(&peer)?;
        Ok((peer, frame))
    }

    /// Validate the exact `(parent conversation, channel, transaction, peer)`
    /// scope of an inbound channel setup frame before any KeyPackage, Welcome,
    /// or commit bytes are used. P1d drives the bound `MlsChannelGroup` through
    /// this gate; it does not make the GUI's default-channel traffic special.
    pub fn validate_channel_setup_scope(
        &self,
        expected_peer: &PeerId,
        frame: &SetupEnvelope,
        expected_scope: &ChannelScope,
    ) -> Result<ChannelGroupBinding, ChatError> {
        frame.verify_channel_scope(expected_peer, expected_scope)?;
        let state = self
            .conversations
            .get(&expected_scope.parent_conversation_id)
            .ok_or(ChatError::UnknownConversation)?;
        if state.status != ConversationStatus::Joined {
            return Err(ChatError::ConversationNotReady);
        }
        let channel = state
            .channels
            .get(&expected_scope.channel_id)
            .ok_or(ChatError::ChannelNotFound)?;
        if !state.members.contains(expected_peer) || !channel.members.contains(expected_peer) {
            return Err(ChatError::NotChannelMember);
        }
        Ok(ChannelGroupBinding::new(
            expected_scope.parent_conversation_id,
            expected_scope.channel_id,
        ))
    }

    /// Only requests that can be retried after a lost response remain
    /// idempotent. Terminal frames and every acknowledgement are one-shot.
    fn is_repeatable_setup_message(message: &SetupMessage) -> bool {
        matches!(
            message,
            SetupMessage::KeyPackageRequest { .. }
                | SetupMessage::GroupJoinRequest { .. }
                | SetupMessage::ChannelKeyPackageRequest { .. }
        )
    }

    /// Bind a replay response to the exact group request, including its peer,
    /// transaction, target, and MLS payload. Re-signing the same message does
    /// not change this key; changing any payload byte does.
    fn group_request_outcome_key(peer: &PeerId, message: &SetupMessage) -> Option<[u8; 32]> {
        let mut hasher = Sha256::new();
        match message {
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id,
                operation,
                target,
                commit,
            } => {
                hasher.update(b"p2p.app.group-commit-outcome/v1");
                hasher.update(peer.to_bytes());
                hasher.update(conversation_id);
                hasher.update(transaction_id);
                hasher.update([operation.code()]);
                hasher.update([u8::from(target.is_some())]);
                if let Some(target) = target {
                    hasher.update(target.to_bytes());
                }
                hasher.update(commit);
            }
            SetupMessage::GroupWelcome {
                conversation_id,
                transaction_id,
                welcome,
            } => {
                hasher.update(b"p2p.app.group-welcome-outcome/v1");
                hasher.update(peer.to_bytes());
                hasher.update(conversation_id);
                hasher.update(transaction_id);
                hasher.update(welcome);
            }
            SetupMessage::ChannelCommit {
                conversation_id,
                channel_id,
                transaction_id,
                operation,
                target,
                commit,
            } => {
                hasher.update(b"p2p.app.channel-commit-outcome/v2");
                hasher.update(peer.to_bytes());
                hasher.update(conversation_id);
                hasher.update(channel_id);
                hasher.update(transaction_id);
                hasher.update([operation.code()]);
                hasher.update([u8::from(target.is_some())]);
                if let Some(target) = target {
                    hasher.update(target.to_bytes());
                }
                hasher.update(commit);
            }
            SetupMessage::ChannelWelcome {
                conversation_id,
                channel_id,
                transaction_id,
                welcome,
            } => {
                hasher.update(b"p2p.app.channel-welcome-outcome/v2");
                hasher.update(peer.to_bytes());
                hasher.update(conversation_id);
                hasher.update(channel_id);
                hasher.update(transaction_id);
                hasher.update(welcome);
            }
            _ => return None,
        }
        Some(hasher.finalize().into())
    }

    /// Look up a previously applied group request. Only an exact payload match
    /// can produce a stored ack, so this never re-applies an epoch transition.
    fn durable_group_ack(&self, key: &[u8; 32]) -> Result<Option<SetupMessage>, ChatError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(None);
        };
        let Some(bytes) =
            storage.load_mls_state(&GLOBAL_PROVIDER_GROUP, PERSISTED_GROUP_ACK_LABEL, key)?
        else {
            return Ok(None);
        };
        let record: PersistedGroupAck = serde_json::from_slice(&bytes)
            .map_err(|_| ChatError::MlsRestore("stored group ack is invalid"))?;
        if record.version == 0 || record.version > GROUP_ACK_VERSION {
            return Err(ChatError::MlsRestore(
                "stored group ack version is unsupported",
            ));
        }
        match record.response {
            GROUP_ACK_COMMIT_CODE if record.channel_id.is_none() => {
                let operation = GroupOperation::from_code(record.operation).ok_or(
                    ChatError::MlsRestore("stored group ack operation is invalid"),
                )?;
                Ok(Some(SetupMessage::GroupCommitAck {
                    conversation_id: record.conversation_id,
                    transaction_id: record.transaction_id,
                    operation,
                    accepted: record.accepted,
                }))
            }
            GROUP_ACK_WELCOME_CODE if record.channel_id.is_none() => {
                Ok(Some(SetupMessage::GroupWelcomeAck {
                    conversation_id: record.conversation_id,
                    transaction_id: record.transaction_id,
                    accepted: record.accepted,
                }))
            }
            GROUP_ACK_CHANNEL_COMMIT_CODE => {
                let operation = GroupOperation::from_code(record.operation).ok_or(
                    ChatError::MlsRestore("stored channel ack operation is invalid"),
                )?;
                let channel_id = record.channel_id.ok_or(ChatError::MlsRestore(
                    "stored channel ack has no channel binding",
                ))?;
                Ok(Some(SetupMessage::ChannelCommitAck {
                    conversation_id: record.conversation_id,
                    channel_id,
                    transaction_id: record.transaction_id,
                    operation,
                    accepted: record.accepted,
                }))
            }
            GROUP_ACK_CHANNEL_WELCOME_CODE => {
                let channel_id = record.channel_id.ok_or(ChatError::MlsRestore(
                    "stored channel ack has no channel binding",
                ))?;
                Ok(Some(SetupMessage::ChannelWelcomeAck {
                    conversation_id: record.conversation_id,
                    channel_id,
                    transaction_id: record.transaction_id,
                    accepted: record.accepted,
                }))
            }
            _ => Err(ChatError::MlsRestore("stored group ack type is invalid")),
        }
    }

    /// Save the first ack for a non-repeatable group request so a restart can
    /// answer an exact retry without replaying the request itself.
    fn persist_group_ack(
        &mut self,
        key: &[u8; 32],
        outcome: &RequestOutcome,
    ) -> Result<(), ChatError> {
        let (Some(storage), Some(response)) = (self.storage.as_mut(), &outcome.response) else {
            return Ok(());
        };
        let record = match response {
            SetupMessage::GroupCommitAck {
                conversation_id,
                transaction_id,
                operation,
                accepted,
            } => PersistedGroupAck {
                version: GROUP_ACK_VERSION,
                response: GROUP_ACK_COMMIT_CODE,
                conversation_id: *conversation_id,
                transaction_id: *transaction_id,
                operation: operation.code(),
                accepted: *accepted,
                channel_id: None,
            },
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                transaction_id,
                accepted,
            } => PersistedGroupAck {
                version: GROUP_ACK_VERSION,
                response: GROUP_ACK_WELCOME_CODE,
                conversation_id: *conversation_id,
                transaction_id: *transaction_id,
                operation: GroupOperation::Add.code(),
                accepted: *accepted,
                channel_id: None,
            },
            SetupMessage::ChannelCommitAck {
                conversation_id,
                channel_id,
                transaction_id,
                operation,
                accepted,
            } => PersistedGroupAck {
                version: GROUP_ACK_VERSION,
                response: GROUP_ACK_CHANNEL_COMMIT_CODE,
                conversation_id: *conversation_id,
                transaction_id: *transaction_id,
                operation: operation.code(),
                accepted: *accepted,
                channel_id: Some(*channel_id),
            },
            SetupMessage::ChannelWelcomeAck {
                conversation_id,
                channel_id,
                transaction_id,
                accepted,
            } => PersistedGroupAck {
                version: GROUP_ACK_VERSION,
                response: GROUP_ACK_CHANNEL_WELCOME_CODE,
                conversation_id: *conversation_id,
                transaction_id: *transaction_id,
                operation: GroupOperation::Add.code(),
                accepted: *accepted,
                channel_id: Some(*channel_id),
            },
            _ => return Ok(()),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| ChatError::MlsRestore("group ack encoding failed"))?;
        storage.store_mls_state(
            &GLOBAL_PROVIDER_GROUP,
            PERSISTED_GROUP_ACK_LABEL,
            key,
            0,
            &bytes,
        )?;
        Ok(())
    }

    /// Consult the durable control log before mutating any controller state.
    /// Without an attached vault the existing in-memory cache remains the only
    /// replay boundary; with one, a non-repeatable replay is ignored before it
    /// can clear correlation or enter the in-memory cache.
    fn durable_control_allows(
        &mut self,
        peer: PeerId,
        bytes: &[u8],
        repeatable: bool,
    ) -> Result<bool, ChatError> {
        let Some(storage) = self.storage.as_mut() else {
            return Ok(true);
        };
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        Ok(
            match storage.record_control_frame(&peer.to_bytes(), &digest, repeatable)? {
                ControlRecordOutcome::Appended(_) | ControlRecordOutcome::Idempotent(_) => true,
                ControlRecordOutcome::Replay(_) => false,
            },
        )
    }

    fn handle_setup_event(&mut self, event: SetupEvent) -> Result<(), ChatError> {
        match event {
            SetupEvent::RequestReceived {
                response_id,
                peer,
                bytes,
            } => {
                let (peer, frame) = Self::decode_setup(peer, &bytes)?;
                // A non-repeatable group request that was already applied has a
                // durable ack. Answer the exact retry without re-applying the
                // epoch transition or asking the control log to record it again.
                if let Some(key) = Self::group_request_outcome_key(&peer, &frame.message)
                    && let Some(response) = self.durable_group_ack(&key)?
                {
                    return self.respond_setup(response_id, response);
                }
                let repeatable = Self::is_repeatable_setup_message(&frame.message);
                if !self.durable_control_allows(peer, &bytes, repeatable)? {
                    return Ok(());
                }
                let duplicate = !self.setup_replay.remember(peer, &bytes);
                // KeyPackage requests intentionally answer an exact repeat
                // idempotently from retained response bytes; all other exact
                // replays are terminal state transitions or acknowledgements
                // and must not be re-applied.
                if duplicate && !repeatable {
                    return Ok(());
                }
                self.handle_setup_request(response_id, peer, frame)
            }
            SetupEvent::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => {
                // Decode and verify before removing correlation state, so a
                // malformed or replayed response cannot clear a live request.
                let (peer, frame) = Self::decode_setup(peer, &bytes)?;
                if !self.durable_control_allows(peer, &bytes, false)? {
                    return Ok(());
                }
                if !self.setup_replay.remember(peer, &bytes) {
                    return Ok(());
                }
                let group_request = self.group_requests.remove(&request_id);
                let outgoing_setup = self.outstanding_setup.remove(&request_id);
                if let Some(request) = group_request {
                    if request.channel_scope.is_some() {
                        return self.handle_channel_group_ack(peer, &frame, request);
                    }
                    return self.handle_group_ack(peer, frame.message, request);
                }
                self.process_setup_response(peer, frame, outgoing_setup)
            }
            SetupEvent::Failed { request_id, .. } => {
                if let Some(request_id) = request_id {
                    if let Some(request) = self.group_requests.remove(&request_id) {
                        self.last_error = Some(match request.kind {
                            GroupRequestKind::Welcome => {
                                "group Welcome request failed (operation still pending)".to_owned()
                            }
                            GroupRequestKind::Commit => {
                                "group commit request failed (operation still pending)".to_owned()
                            }
                        });
                    } else if let Some(setup) = self.outstanding_setup.remove(&request_id) {
                        self.set_status(
                            setup.conversation_id,
                            ConversationStatus::Failed("setup request failed".to_owned()),
                        )?;
                    }
                }
                Ok(())
            }
            SetupEvent::SentToPeer { .. } => Ok(()),
        }
    }

    fn handle_setup_request(
        &mut self,
        response_id: SetupResponseId,
        peer: PeerId,
        frame: SetupEnvelope,
    ) -> Result<(), ChatError> {
        let outcome = self.process_setup_request(peer, frame)?;
        if let Some(message) = outcome.response {
            self.respond_setup(response_id, message)?;
        }
        match outcome.rejection {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Validate and apply one inbound setup request. Every state change is
    /// gated on the signed transaction ID matching the locally owned pending
    /// state for that conversation and peer.
    fn process_setup_request(
        &mut self,
        peer: PeerId,
        frame: SetupEnvelope,
    ) -> Result<RequestOutcome, ChatError> {
        let public_key = frame.sender_mls_public_key()?.to_vec();
        let outcome_key = Self::group_request_outcome_key(&peer, &frame.message);
        if let Some(scope) = frame.message.channel_scope() {
            match &frame.message {
                SetupMessage::ChannelKeyPackageRequest { .. } => {
                    return self.register_pending_channel_key_package(peer, &frame, scope);
                }
                SetupMessage::ChannelWelcome { welcome, .. } => {
                    let ack =
                        self.join_channel_from_welcome(peer, &frame, scope, welcome.clone())?;
                    let outcome = RequestOutcome::respond(ack);
                    if let Some(key) = &outcome_key {
                        self.persist_group_ack(key, &outcome)?;
                    }
                    return Ok(outcome);
                }
                SetupMessage::ChannelCommit {
                    operation,
                    target,
                    commit,
                    ..
                } => {
                    let outcome = self.process_channel_commit_request(
                        peer,
                        &frame,
                        scope,
                        *operation,
                        *target,
                        commit.clone(),
                    )?;
                    if let Some(key) = &outcome_key {
                        self.persist_group_ack(key, &outcome)?;
                    }
                    return Ok(outcome);
                }
                _ => {}
            }
        }
        match frame.message {
            SetupMessage::KeyPackageRequest {
                conversation_id,
                transaction_id,
            } => self.register_pending_key_package(
                peer,
                conversation_id,
                transaction_id,
                PendingKeyPackageKind::Conversation,
            ),
            SetupMessage::Welcome {
                conversation_id,
                transaction_id,
                welcome,
            } => {
                let ack =
                    self.join_from_welcome(peer, conversation_id, transaction_id, welcome, false)?;
                Ok(RequestOutcome::respond(ack))
            }
            SetupMessage::GroupJoinRequest {
                conversation_id,
                transaction_id,
            } => self.register_pending_key_package(
                peer,
                conversation_id,
                transaction_id,
                PendingKeyPackageKind::GroupJoin,
            ),
            SetupMessage::GroupWelcome {
                conversation_id,
                transaction_id,
                welcome,
            } => {
                let ack =
                    self.join_from_welcome(peer, conversation_id, transaction_id, welcome, true)?;
                let outcome = RequestOutcome::respond(ack);
                if let Some(key) = &outcome_key {
                    self.persist_group_ack(key, &outcome)?;
                }
                Ok(outcome)
            }
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id,
                operation,
                target,
                commit,
            } => {
                // A peer with its own pending operation must not accept a
                // commit from a different transaction.
                if self
                    .conversations
                    .get(&conversation_id)
                    .and_then(|state| state.pending_operation.as_ref())
                    .is_some_and(|pending| pending.transaction_id != transaction_id)
                {
                    return Err(ChatError::InvalidSetup(
                        "group commit transaction does not match pending operation",
                    ));
                }
                let (accepted, self_removed, refresh_members, removed_members) = {
                    let state = self
                        .conversations
                        .get_mut(&conversation_id)
                        .ok_or(ChatError::UnknownConversation)?;
                    if state.status != ConversationStatus::Joined {
                        return Err(ChatError::ConversationNotReady);
                    }
                    if !state.members.contains(&peer) {
                        return Err(ChatError::NotGroupMember);
                    }
                    if peer != state.admin {
                        return Err(ChatError::NotAdmin);
                    }
                    let already_applied = self
                        .applied_commits
                        .get(&conversation_id)
                        .is_some_and(|applied| applied.contains(&commit));
                    if already_applied {
                        (true, false, false, Vec::new())
                    } else {
                        let previous_members = state.members.clone();
                        match state.conversation.process_commit(
                            &commit,
                            &peer,
                            &public_key,
                            operation,
                            target,
                        ) {
                            Ok(outcome) => {
                                let applied =
                                    self.applied_commits.entry(conversation_id).or_default();
                                if applied.len() >= 32 && !applied.contains(&commit) {
                                    applied.clear();
                                }
                                applied.insert(commit.clone());
                                if outcome.self_removed {
                                    (true, true, false, Vec::new())
                                } else {
                                    let members = state.conversation.members()?;
                                    let removed = previous_members
                                        .iter()
                                        .copied()
                                        .filter(|member| !members.contains(member))
                                        .collect::<Vec<_>>();
                                    state.members = members.into_iter().collect();
                                    state.sync_default_channel();
                                    state.prune_removed_members();
                                    (true, false, true, removed)
                                }
                            }
                            Err(error) => {
                                self.last_error = Some(error.to_string());
                                (false, false, false, Vec::new())
                            }
                        }
                    }
                };
                if self_removed {
                    self.remove_local_conversation(conversation_id);
                } else if refresh_members {
                    let local = self.identity.peer_id();
                    self.refresh_peer_conversations(conversation_id, &local);
                    for removed in removed_members {
                        self.drop_all_channel_groups(conversation_id)?;
                        self.prune_removed_peer_state(conversation_id, &removed);
                    }
                    self.persist_conversation(conversation_id)?;
                }
                let ack = SetupMessage::GroupCommitAck {
                    conversation_id,
                    transaction_id,
                    operation,
                    accepted,
                };
                let outcome = if accepted {
                    RequestOutcome::respond(ack)
                } else {
                    RequestOutcome::respond_and_reject(ack, ChatError::GroupOperationRejected)
                };
                if let Some(key) = &outcome_key {
                    self.persist_group_ack(key, &outcome)?;
                }
                Ok(outcome)
            }
            _ => Err(ChatError::InvalidSetup("unexpected setup request type")),
        }
    }

    /// Retain one KeyPackage provider per `(conversation, transaction)`. An
    /// identical duplicate from the same peer is answered with the same
    /// response; a different transaction for a pending conversation is rejected
    /// instead of displacing the original provider.
    fn register_pending_key_package(
        &mut self,
        peer: PeerId,
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        kind: PendingKeyPackageKind,
    ) -> Result<RequestOutcome, ChatError> {
        if self.conversations.contains_key(&conversation_id) {
            return Err(ChatError::AlreadyEstablished);
        }
        let key = (conversation_id, transaction_id);
        if let Some(pending) = self.pending_key_packages.get(&key) {
            if pending.peer != peer {
                return Err(ChatError::UnexpectedSender);
            }
            if pending.kind != kind {
                return Err(ChatError::InvalidSetup(
                    "setup request kind does not match pending KeyPackage",
                ));
            }
            let response = match kind {
                PendingKeyPackageKind::Conversation => SetupMessage::KeyPackageResponse {
                    conversation_id,
                    transaction_id,
                    key_package: pending.response_bytes.clone(),
                },
                PendingKeyPackageKind::GroupJoin => SetupMessage::GroupKeyPackageResponse {
                    conversation_id,
                    transaction_id,
                    key_package: pending.response_bytes.clone(),
                },
            };
            return Ok(RequestOutcome::respond(response));
        }
        if self
            .pending_key_packages
            .keys()
            .any(|(id, _)| *id == conversation_id)
        {
            return Err(ChatError::InvalidSetup(
                "another setup transaction is already pending for this conversation",
            ));
        }
        let key_package = match self.storage.as_ref() {
            Some(storage) => {
                MlsConversation::key_package_with_storage(&self.identity, storage.try_clone()?)?
            }
            None => MlsConversation::key_package(&self.identity)?,
        };
        let bytes = key_package.bytes().to_vec();
        self.pending_key_packages.insert(
            key,
            PendingKeyPackage {
                peer,
                kind,
                key_package,
                response_bytes: bytes.clone(),
            },
        );
        let response = match kind {
            PendingKeyPackageKind::Conversation => SetupMessage::KeyPackageResponse {
                conversation_id,
                transaction_id,
                key_package: bytes,
            },
            PendingKeyPackageKind::GroupJoin => SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                transaction_id,
                key_package: bytes,
            },
        };
        Ok(RequestOutcome::respond(response))
    }

    /// Join a conversation from a Welcome bound to the pending transaction and
    /// return the acknowledgement carrying that same transaction ID.
    fn join_from_welcome(
        &mut self,
        peer: PeerId,
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        welcome: Vec<u8>,
        group_control: bool,
    ) -> Result<SetupMessage, ChatError> {
        if self.conversations.contains_key(&conversation_id) {
            return Err(ChatError::AlreadyEstablished);
        }
        let key = (conversation_id, transaction_id);
        let Some(pending) = self.pending_key_packages.get(&key) else {
            return Err(ChatError::PendingKeyPackageMissing);
        };
        if pending.peer != peer {
            return Err(ChatError::UnexpectedSender);
        }
        let expected_kind = if group_control {
            PendingKeyPackageKind::GroupJoin
        } else {
            PendingKeyPackageKind::Conversation
        };
        if pending.kind != expected_kind {
            return Err(ChatError::InvalidSetup(
                "welcome type does not match pending KeyPackage",
            ));
        }
        let pending = self
            .pending_key_packages
            .remove(&key)
            .ok_or(ChatError::PendingKeyPackageMissing)?;
        let ack = |accepted: bool| {
            if group_control {
                SetupMessage::GroupWelcomeAck {
                    conversation_id,
                    transaction_id,
                    accepted,
                }
            } else {
                SetupMessage::WelcomeAck {
                    conversation_id,
                    transaction_id,
                    accepted,
                }
            }
        };
        match MlsConversation::join(
            &self.identity,
            conversation_id,
            pending.key_package,
            &welcome,
        ) {
            Ok(conversation) => {
                let members = conversation.members()?.into_iter().collect();
                let state = ConversationState::new(conversation, peer, members);
                self.conversations.insert(conversation_id, state);
                self.active_channel
                    .insert(conversation_id, DEFAULT_CHANNEL_ID);
                self.refresh_peer_conversations(conversation_id, &self.identity.peer_id());
                self.active = Some(conversation_id);
                self.persist_conversation(conversation_id)?;
                Ok(ack(true))
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Ok(ack(false))
            }
        }
    }

    /// Drop the independent group for one channel, including its authenticated
    /// encrypted record. This is the conservative response to a changed channel
    /// member set: ciphertext from an older group is never reused with a newer
    /// policy, and restart cannot revive the older group.
    fn drop_channel_group(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
    ) -> Result<(), ChatError> {
        let group_id = channel_group_id(conversation_id, channel_id);
        self.channel_groups.remove(&group_id);
        self.pending_channel_setups
            .retain(|_, setup| setup.channel_id != channel_id);
        self.pending_channel_key_packages.retain(|scope, _| {
            scope.parent_conversation_id != conversation_id || scope.channel_id != channel_id
        });
        self.pending_channel_policy_acks.retain(|_, trigger| {
            trigger.conversation_id != conversation_id || trigger.channel_id != channel_id
        });
        let affected: Vec<[u8; 16]> = self
            .message_channel_routes
            .iter()
            .filter_map(|(message_id, routed)| {
                (*routed == channel_id
                    && self.message_conversations.get(message_id) == Some(&conversation_id))
                .then_some(*message_id)
            })
            .collect();
        for message_id in affected {
            self.pending_receipts.remove(&message_id);
            self.message_conversations.remove(&message_id);
            self.message_channel_routes.remove(&message_id);
        }
        self.offline_queue.retain(|item| {
            item.conversation_id != conversation_id || item.channel_id != channel_id
        });
        if let Some(storage) = self.storage.as_mut() {
            storage.delete_mls_state_group(&group_id)?;
        }
        Ok(())
    }

    /// A parent-group removal invalidates every channel group in that
    /// conversation. No removed peer can remain in an active channel group.
    fn drop_all_channel_groups(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let channels: Vec<[u8; 16]> = self
            .conversations
            .get(&conversation_id)
            .map(|state| state.channels.keys().copied().collect())
            .unwrap_or_default();
        for channel_id in channels {
            self.drop_channel_group(conversation_id, channel_id)?;
        }
        // Also drop any persisted derived group whose parent policy has already
        // been removed from the in-memory conversation list.
        let group_ids: Vec<[u8; 16]> = self
            .channel_groups
            .values()
            .filter(|state| state.binding.parent_conversation_id() == conversation_id)
            .map(|state| state.binding.group_id())
            .collect();
        for group_id in group_ids {
            if let Some(storage) = self.storage.as_mut() {
                storage.delete_mls_state_group(&group_id)?;
            }
        }
        self.channel_groups
            .retain(|_, state| state.binding.parent_conversation_id() != conversation_id);
        self.message_channel_routes
            .retain(|_, routed| self.message_conversations.get(routed) != Some(&conversation_id));
        Ok(())
    }

    /// Delivery state for one composed frame lives in the group that produced
    /// its ciphertext: the parent for policy/default traffic, the derived group
    /// for non-default channel text.
    fn message_group_delivery_state(
        &self,
        conversation_id: [u8; 16],
        channel_id: Option<[u8; 16]>,
        message_id: &[u8; 16],
    ) -> Option<DeliveryState> {
        match channel_id {
            Some(channel_id) => self
                .channel_groups
                .get(&channel_group_id(conversation_id, channel_id))
                .and_then(|state| state.group.delivery_state(message_id)),
            None => self
                .conversations
                .get(&conversation_id)
                .and_then(|state| state.conversation.delivery_state(message_id)),
        }
    }

    fn mark_message_group(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: Option<[u8; 16]>,
        message_id: [u8; 16],
        delivery: DeliveryState,
    ) -> Result<(), ChatError> {
        match channel_id {
            Some(channel_id) => {
                let state = self
                    .channel_groups
                    .get_mut(&channel_group_id(conversation_id, channel_id))
                    .ok_or(ChatError::ChannelGroupNotReady)?;
                match delivery {
                    DeliveryState::Queued => state.group.mark_queued(&message_id)?,
                    DeliveryState::SentToPeer => state.group.mark_sent_to_peer(&message_id)?,
                    DeliveryState::Failed => state.group.mark_failed(&message_id)?,
                    _ => return Err(ChatError::InvalidSetup("invalid message transition")),
                }
            }
            None => {
                let state = self
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                match delivery {
                    DeliveryState::Queued => state.conversation.mark_queued(&message_id)?,
                    DeliveryState::SentToPeer => {
                        state.conversation.mark_sent_to_peer(&message_id)?
                    }
                    DeliveryState::Failed => state.conversation.mark_failed(&message_id)?,
                    _ => return Err(ChatError::InvalidSetup("invalid message transition")),
                }
            }
        }
        Ok(())
    }

    /// Register the signed channel KeyPackage request. The exact scope is the
    /// map key, so an exact retry returns the same bytes and a different
    /// channel or transaction cannot reach this provider.
    fn register_pending_channel_key_package(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        scope: ChannelScope,
    ) -> Result<RequestOutcome, ChatError> {
        let binding = self.validate_channel_setup_scope(&peer, frame, &scope)?;
        if let Some(pending) = self.pending_channel_key_packages.get(&scope) {
            if pending.peer != peer {
                return Err(ChatError::UnexpectedSender);
            }
            return Ok(RequestOutcome::respond(
                SetupMessage::ChannelKeyPackageResponse {
                    conversation_id: scope.parent_conversation_id,
                    channel_id: scope.channel_id,
                    transaction_id: scope.transaction_id,
                    key_package: pending.response_bytes.clone(),
                },
            ));
        }
        let key_package = match self.storage.as_ref() {
            Some(storage) => MlsChannelGroup::key_package_with_storage(
                &self.identity,
                binding,
                storage.try_clone()?,
            )?,
            None => MlsChannelGroup::key_package(&self.identity, binding)?,
        };
        let bytes = key_package.bytes().to_vec();
        self.pending_channel_key_packages.insert(
            scope,
            PendingChannelKeyPackage {
                peer,
                key_package,
                response_bytes: bytes.clone(),
            },
        );
        Ok(RequestOutcome::respond(
            SetupMessage::ChannelKeyPackageResponse {
                conversation_id: scope.parent_conversation_id,
                channel_id: scope.channel_id,
                transaction_id: scope.transaction_id,
                key_package: bytes,
            },
        ))
    }

    /// Join a bound channel group from a signed Welcome and acknowledge the
    /// exact scope that produced the KeyPackage.
    fn join_channel_from_welcome(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        scope: ChannelScope,
        welcome: Vec<u8>,
    ) -> Result<SetupMessage, ChatError> {
        let binding = self.validate_channel_setup_scope(&peer, frame, &scope)?;
        let pending = self
            .pending_channel_key_packages
            .remove(&scope)
            .ok_or(ChatError::PendingKeyPackageMissing)?;
        if pending.peer != peer {
            return Err(ChatError::UnexpectedSender);
        }
        let ack = |accepted| SetupMessage::ChannelWelcomeAck {
            conversation_id: scope.parent_conversation_id,
            channel_id: scope.channel_id,
            transaction_id: scope.transaction_id,
            accepted,
        };
        let channel_welcome = ChannelWelcome::from_bytes(binding, welcome);
        match MlsChannelGroup::join(
            &self.identity,
            binding,
            pending.key_package,
            &channel_welcome,
        ) {
            Ok(group) => {
                self.channel_groups.insert(
                    binding.group_id(),
                    ChannelGroupState {
                        binding,
                        group,
                        awaited: BTreeSet::new(),
                        ready: true,
                    },
                );
                self.persist_conversation(scope.parent_conversation_id)?;
                Ok(ack(true))
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Ok(ack(false))
            }
        }
    }

    /// Apply a signed channel commit in the derived group. Only the parent
    /// administrator may drive channel membership transitions.
    fn process_channel_commit_request(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        scope: ChannelScope,
        operation: GroupOperation,
        target: Option<PeerId>,
        commit: Vec<u8>,
    ) -> Result<RequestOutcome, ChatError> {
        let binding = self.validate_channel_setup_scope(&peer, frame, &scope)?;
        let admin = self
            .conversations
            .get(&scope.parent_conversation_id)
            .ok_or(ChatError::UnknownConversation)?
            .admin;
        if peer != admin {
            return Err(ChatError::NotAdmin);
        }
        let applied = {
            let Some(state) = self.channel_groups.get_mut(&binding.group_id()) else {
                return Err(ChatError::ChannelGroupNotReady);
            };
            let mls_key = frame.sender_mls_public_key()?;
            state
                .group
                .process_commit(&commit, &peer, &mls_key, operation, target)
        };
        let ack = SetupMessage::ChannelCommitAck {
            conversation_id: scope.parent_conversation_id,
            channel_id: scope.channel_id,
            transaction_id: scope.transaction_id,
            operation,
            accepted: applied.is_ok(),
        };
        match applied {
            Ok(outcome) => {
                if outcome.self_removed {
                    self.drop_channel_group(scope.parent_conversation_id, scope.channel_id)?;
                }
                self.persist_conversation(scope.parent_conversation_id)?;
                Ok(RequestOutcome::respond(ack))
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Ok(RequestOutcome::respond_and_reject(
                    ack,
                    ChatError::GroupOperationRejected,
                ))
            }
        }
    }

    /// Create or recreate the derived MLS group and start the first allowed
    /// peer's setup. Called only after the parent-group policy is acknowledged.
    fn start_channel_setup_for_channel(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
        recreate: bool,
    ) -> Result<(), ChatError> {
        let binding = ChannelGroupBinding::new(conversation_id, channel_id);
        if recreate {
            self.drop_channel_group(conversation_id, channel_id)?;
        }
        if !self.channel_groups.contains_key(&binding.group_id()) {
            let group = match self.storage.as_ref() {
                Some(storage) => MlsChannelGroup::create_with_storage(
                    &self.identity,
                    binding,
                    storage.try_clone()?,
                )?,
                None => MlsChannelGroup::create(&self.identity, binding)?,
            };
            self.channel_groups.insert(
                binding.group_id(),
                ChannelGroupState {
                    binding,
                    group,
                    awaited: BTreeSet::new(),
                    ready: false,
                },
            );
        }
        self.advance_channel_setup(conversation_id, channel_id)
    }

    /// Start the next not-yet-added allowed peer, or mark the channel group
    /// ready when every allowed peer has converged on the same epoch.
    fn advance_channel_setup(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
    ) -> Result<(), ChatError> {
        let binding = ChannelGroupBinding::new(conversation_id, channel_id);
        if self
            .pending_channel_setups
            .values()
            .any(|setup| setup.channel_id == channel_id)
        {
            return Ok(());
        }
        let (allowed, group_members) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            let channel = state
                .channels
                .get(&channel_id)
                .ok_or(ChatError::ChannelNotFound)?;
            let members = self
                .channel_groups
                .get(&binding.group_id())
                .ok_or(ChatError::ChannelGroupNotReady)?
                .group
                .members()?;
            (
                channel.members.clone(),
                members.into_iter().collect::<BTreeSet<_>>(),
            )
        };
        let local = self.identity.peer_id();
        let Some(peer) = allowed
            .iter()
            .copied()
            .find(|peer| *peer != local && !group_members.contains(peer))
        else {
            if let Some(state) = self.channel_groups.get_mut(&binding.group_id()) {
                state.ready = true;
                state.awaited.clear();
            }
            return Ok(());
        };
        if !self.is_connected(&peer) {
            self.last_error =
                Some("channel setup is pending until every member reconnects".to_owned());
            return Ok(());
        }
        let transaction_id = random_id()?;
        let scope = ChannelScope {
            parent_conversation_id: conversation_id,
            channel_id,
            transaction_id,
        };
        self.send_setup(
            &peer,
            SetupMessage::ChannelKeyPackageRequest {
                conversation_id,
                channel_id,
                transaction_id,
            },
            conversation_id,
            transaction_id,
        )?;
        self.pending_channel_setups.insert(
            scope,
            PendingChannelMemberSetup {
                channel_id,
                peer,
                scope,
                stage: ChannelMemberSetupStage::KeyPackageRequested,
                welcome: Vec::new(),
                commit: Vec::new(),
                welcome_acked: false,
                commit_acks: BTreeSet::new(),
                required_commit_acks: BTreeSet::new(),
            },
        );
        if let Some(state) = self.channel_groups.get_mut(&binding.group_id()) {
            state.ready = false;
            state.awaited.insert(peer);
        }
        Ok(())
    }

    /// Complete one peer's setup and advance to the next allowed peer. A
    /// rejected acknowledgement fails the whole channel group closed.
    fn finish_channel_member_setup(
        &mut self,
        scope: ChannelScope,
        accepted: bool,
    ) -> Result<(), ChatError> {
        let pending = self
            .pending_channel_setups
            .remove(&scope)
            .ok_or(ChatError::InvalidSetup("no channel setup is pending"))?;
        if !accepted {
            self.drop_channel_group(scope.parent_conversation_id, scope.channel_id)?;
            self.last_error = Some("channel setup was rejected by a member".to_owned());
            return Ok(());
        }
        let group_id = channel_group_id(scope.parent_conversation_id, scope.channel_id);
        if let Some(state) = self.channel_groups.get_mut(&group_id) {
            state.awaited.remove(&pending.peer);
        }
        self.advance_channel_setup(scope.parent_conversation_id, scope.channel_id)?;
        // Persist only when setup actually converged. `advance_channel_setup`
        // leaves `ready=false` while another peer or commit ack is missing, so
        // an incomplete group still has no authenticated application record.
        let ready = self
            .channel_groups
            .get(&group_id)
            .is_some_and(|state| state.ready);
        if ready {
            self.persist_conversation(scope.parent_conversation_id)?;
        }
        Ok(())
    }

    /// Add one allowed peer to the derived group after its signed KeyPackage
    /// response. Existing members receive the matching channel commit; the new
    /// member receives the Welcome. No channel text is sent until both acks.
    #[allow(clippy::too_many_arguments)]
    fn process_channel_key_package_response(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        scope: ChannelScope,
        public_key: Vec<u8>,
        key_package: Vec<u8>,
        outgoing: Option<OutgoingSetup>,
    ) -> Result<(), ChatError> {
        let outgoing = outgoing.ok_or(ChatError::InvalidSetup("untracked setup response"))?;
        if outgoing.kind != OutgoingSetupKind::ChannelKeyPackageRequest
            || outgoing.conversation_id != scope.parent_conversation_id
            || outgoing.transaction_id != scope.transaction_id
            || outgoing.scope != Some(scope)
        {
            return Err(ChatError::InvalidSetup(
                "unexpected channel KeyPackage response transaction",
            ));
        }
        let binding = self.validate_channel_setup_scope(&peer, frame, &scope)?;
        {
            let pending = self
                .pending_channel_setups
                .get_mut(&scope)
                .ok_or(ChatError::InvalidSetup("no channel setup is pending"))?;
            if pending.peer != peer || pending.stage != ChannelMemberSetupStage::KeyPackageRequested
            {
                return Err(ChatError::InvalidSetup(
                    "channel KeyPackage response does not match pending member",
                ));
            }
        }
        let required_commit_acks = {
            let state = self
                .conversations
                .get(&scope.parent_conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            let allowed = &state
                .channels
                .get(&scope.channel_id)
                .ok_or(ChatError::ChannelNotFound)?
                .members;
            let group_members = self
                .channel_groups
                .get(&binding.group_id())
                .ok_or(ChatError::ChannelGroupNotReady)?
                .group
                .members()?
                .into_iter()
                .collect::<BTreeSet<_>>();
            allowed
                .iter()
                .copied()
                .filter(|member| {
                    *member != self.identity.peer_id()
                        && *member != peer
                        && group_members.contains(member)
                })
                .collect::<BTreeSet<_>>()
        };
        let (welcome, commit) = {
            let state = self
                .channel_groups
                .get_mut(&binding.group_id())
                .ok_or(ChatError::ChannelGroupNotReady)?;
            let key_package = ChannelKeyPackage::from_public_bytes(binding, key_package);
            state
                .group
                .add_member_parts(&key_package, peer, &public_key)?
        };
        let welcome_bytes = welcome.bytes().to_vec();
        self.send_setup(
            &peer,
            SetupMessage::ChannelWelcome {
                conversation_id: scope.parent_conversation_id,
                channel_id: scope.channel_id,
                transaction_id: scope.transaction_id,
                welcome: welcome_bytes.clone(),
            },
            scope.parent_conversation_id,
            scope.transaction_id,
        )?;
        for member in required_commit_acks.iter().copied() {
            if !self.is_connected(&member) {
                self.last_error =
                    Some("channel commit is pending until every member reconnects".to_owned());
                continue;
            }
            let request = GroupRequest {
                conversation_id: scope.parent_conversation_id,
                channel_scope: Some(scope),
                transaction_id: scope.transaction_id,
                peer: member,
                operation: GroupOperation::Add,
                kind: GroupRequestKind::Commit,
            };
            if let Err(error) = self.send_group_request(
                &member,
                SetupMessage::ChannelCommit {
                    conversation_id: scope.parent_conversation_id,
                    channel_id: scope.channel_id,
                    transaction_id: scope.transaction_id,
                    operation: GroupOperation::Add,
                    target: Some(peer),
                    commit: commit.clone(),
                },
                request,
            ) {
                self.last_error = Some(error.to_string());
            }
        }
        let pending = self
            .pending_channel_setups
            .get_mut(&scope)
            .ok_or(ChatError::InvalidSetup("no channel setup is pending"))?;
        pending.stage = ChannelMemberSetupStage::WelcomeSent;
        pending.welcome = welcome_bytes;
        pending.commit = commit;
        pending.required_commit_acks = required_commit_acks.clone();
        if let Some(state) = self.channel_groups.get_mut(&binding.group_id()) {
            for member in required_commit_acks {
                state.awaited.insert(member);
            }
        }
        Ok(())
    }

    /// Mark a bound Welcome acknowledgement and advance when every required
    /// commit acknowledgement has also arrived.
    fn process_channel_welcome_ack(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        scope: ChannelScope,
        accepted: bool,
        outgoing: Option<OutgoingSetup>,
    ) -> Result<(), ChatError> {
        let outgoing = outgoing.ok_or(ChatError::InvalidSetup("untracked setup response"))?;
        if outgoing.kind != OutgoingSetupKind::ChannelWelcome
            || outgoing.conversation_id != scope.parent_conversation_id
            || outgoing.transaction_id != scope.transaction_id
            || outgoing.scope != Some(scope)
        {
            return Err(ChatError::InvalidSetup(
                "unexpected channel Welcome acknowledgement",
            ));
        }
        self.validate_channel_setup_scope(&peer, frame, &scope)?;
        if !accepted {
            return self.finish_channel_member_setup(scope, false);
        }
        let complete = {
            let pending = self
                .pending_channel_setups
                .get_mut(&scope)
                .ok_or(ChatError::InvalidSetup("no channel setup is pending"))?;
            if pending.peer != peer || pending.stage != ChannelMemberSetupStage::WelcomeSent {
                return Err(ChatError::InvalidSetup(
                    "channel Welcome acknowledgement does not match pending member",
                ));
            }
            pending.welcome_acked = true;
            pending.commit_acks == pending.required_commit_acks
        };
        if complete {
            self.finish_channel_member_setup(scope, true)?;
        }
        Ok(())
    }

    /// Handle a channel commit acknowledgement routed through the existing
    /// group-request correlation map.
    fn handle_channel_group_ack(
        &mut self,
        peer: PeerId,
        frame: &SetupEnvelope,
        request: GroupRequest,
    ) -> Result<(), ChatError> {
        let (conversation_id, channel_id, transaction_id, operation, accepted) =
            match &frame.message {
                SetupMessage::ChannelCommitAck {
                    conversation_id,
                    channel_id,
                    transaction_id,
                    operation,
                    accepted,
                } => (
                    *conversation_id,
                    *channel_id,
                    *transaction_id,
                    *operation,
                    *accepted,
                ),
                _ => {
                    return Err(ChatError::InvalidSetup(
                        "unexpected channel acknowledgement",
                    ));
                }
            };
        if peer != request.peer {
            return Err(ChatError::UnexpectedSender);
        }
        let scope = ChannelScope {
            parent_conversation_id: conversation_id,
            channel_id,
            transaction_id,
        };
        if request.channel_scope != Some(scope)
            || request.transaction_id != transaction_id
            || request.operation != operation
        {
            return Err(ChatError::InvalidSetup(
                "channel acknowledgement does not match its request",
            ));
        }
        self.validate_channel_setup_scope(&peer, frame, &scope)?;
        if !accepted {
            return self.finish_channel_member_setup(scope, false);
        }
        let complete = {
            let pending = self
                .pending_channel_setups
                .get_mut(&scope)
                .ok_or(ChatError::InvalidSetup("no channel setup is pending"))?;
            if !pending.required_commit_acks.contains(&peer) || !pending.commit_acks.insert(peer) {
                return Err(ChatError::UnexpectedSender);
            }
            pending.welcome_acked && pending.commit_acks == pending.required_commit_acks
        };
        if complete {
            self.finish_channel_member_setup(scope, true)?;
        }
        Ok(())
    }

    fn process_setup_response(
        &mut self,
        peer: PeerId,
        frame: SetupEnvelope,
        outgoing: Option<OutgoingSetup>,
    ) -> Result<(), ChatError> {
        let public_key = frame.sender_mls_public_key()?.to_vec();
        let channel_scope = frame.message.channel_scope();
        if let Some(scope) = channel_scope {
            match &frame.message {
                SetupMessage::ChannelKeyPackageResponse { key_package, .. } => {
                    return self.process_channel_key_package_response(
                        peer,
                        &frame,
                        scope,
                        public_key,
                        key_package.clone(),
                        outgoing,
                    );
                }
                SetupMessage::ChannelWelcomeAck { accepted, .. } => {
                    return self
                        .process_channel_welcome_ack(peer, &frame, scope, *accepted, outgoing);
                }
                _ => {}
            }
        }
        match frame.message {
            SetupMessage::KeyPackageResponse {
                conversation_id,
                transaction_id,
                key_package,
            } => {
                let outgoing =
                    outgoing.ok_or(ChatError::InvalidSetup("untracked setup response"))?;
                if outgoing.kind != OutgoingSetupKind::KeyPackageRequest
                    || outgoing.conversation_id != conversation_id
                    || outgoing.transaction_id != transaction_id
                {
                    return Err(ChatError::InvalidSetup(
                        "unexpected KeyPackage response transaction",
                    ));
                }
                let welcome = {
                    let state = self
                        .conversations
                        .get_mut(&conversation_id)
                        .ok_or(ChatError::UnknownConversation)?;
                    if !state.members.contains(&peer)
                        || state.status != ConversationStatus::KeyPackageRequested
                    {
                        return Err(ChatError::UnexpectedSender);
                    }
                    let welcome = state
                        .conversation
                        .add_member(&key_package, peer, &public_key)?;
                    state.status = ConversationStatus::WelcomeSent;
                    welcome
                };
                self.persist_conversation(conversation_id)?;
                self.send_setup(
                    &peer,
                    SetupMessage::Welcome {
                        conversation_id,
                        transaction_id,
                        welcome,
                    },
                    conversation_id,
                    transaction_id,
                )
            }
            SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                transaction_id,
                key_package,
            } => {
                let outgoing =
                    outgoing.ok_or(ChatError::InvalidSetup("untracked setup response"))?;
                if outgoing.kind != OutgoingSetupKind::GroupJoinRequest
                    || outgoing.conversation_id != conversation_id
                    || outgoing.transaction_id != transaction_id
                {
                    return Err(ChatError::InvalidSetup(
                        "unexpected group KeyPackage response transaction",
                    ));
                }
                let local = self.identity.peer_id();
                {
                    let state = self
                        .conversations
                        .get_mut(&conversation_id)
                        .ok_or(ChatError::UnknownConversation)?;
                    Self::check_admin(
                        state.admin,
                        local,
                        &state.status,
                        state.pending_operation.is_some(),
                    )?;
                    if state.members.contains(&peer) {
                        return Err(ChatError::AlreadyEstablished);
                    }
                    let (welcome, commit) =
                        state
                            .conversation
                            .add_member_parts(&key_package, peer, &public_key)?;
                    // The new member joins at the commit's new epoch through
                    // the Welcome; it must not also apply that commit.
                    let mut awaited = BTreeMap::new();
                    for member in state.members.iter().copied() {
                        if member != local && member != peer {
                            awaited.insert(member, false);
                        }
                    }
                    state.members.insert(peer);
                    state.sync_default_channel();
                    state.pending_operation = Some(PendingOperation {
                        transaction_id,
                        operation: GroupOperation::Add,
                        target: Some(peer),
                        commit,
                        awaited,
                        welcome_target: Some(peer),
                        welcome: Some(welcome),
                        welcome_acked: false,
                    });
                }
                self.persist_conversation(conversation_id)?;
                self.refresh_peer_conversations(conversation_id, &local);
                self.dispatch_group_operation(conversation_id)
            }
            SetupMessage::WelcomeAck {
                conversation_id,
                transaction_id,
                accepted,
            } => {
                let outgoing =
                    outgoing.ok_or(ChatError::InvalidSetup("untracked setup response"))?;
                if outgoing.kind != OutgoingSetupKind::Welcome
                    || outgoing.conversation_id != conversation_id
                    || outgoing.transaction_id != transaction_id
                {
                    return Err(ChatError::InvalidSetup(
                        "unexpected welcome acknowledgement transaction",
                    ));
                }
                let state = self
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                if !state.members.contains(&peer) {
                    return Err(ChatError::UnexpectedSender);
                }
                // A late or duplicate acknowledgement from an older setup
                // must not overwrite a terminal setup result.
                if state.status != ConversationStatus::WelcomeSent {
                    return Err(ChatError::InvalidSetup(
                        "unexpected welcome acknowledgement",
                    ));
                }
                state.status = if accepted {
                    ConversationStatus::Joined
                } else {
                    ConversationStatus::Failed("setup rejected by peer".to_owned())
                };
                self.persist_conversation(conversation_id)?;
                Ok(())
            }
            _ => Err(ChatError::InvalidSetup("unexpected setup response type")),
        }
    }

    fn handle_group_ack(
        &mut self,
        peer: PeerId,
        message: SetupMessage,
        request: GroupRequest,
    ) -> Result<(), ChatError> {
        if peer != request.peer {
            return Err(ChatError::UnexpectedSender);
        }
        let conversation_id = request.conversation_id;
        let transaction_id = request.transaction_id;
        match (message, request.kind) {
            (
                SetupMessage::GroupWelcomeAck {
                    conversation_id: ack_id,
                    transaction_id: ack_transaction,
                    accepted,
                },
                GroupRequestKind::Welcome,
            ) => {
                if ack_id != conversation_id
                    || ack_transaction != transaction_id
                    || request.operation != GroupOperation::Add
                {
                    return Err(ChatError::InvalidSetup(
                        "unexpected group Welcome acknowledgement",
                    ));
                }
                let Some(operation) = self
                    .conversations
                    .get(&conversation_id)
                    .and_then(|state| state.pending_operation.as_ref())
                else {
                    return Err(ChatError::InvalidSetup("no group operation is pending"));
                };
                if operation.transaction_id != transaction_id {
                    return Err(ChatError::InvalidSetup(
                        "group Welcome acknowledgement belongs to a different transaction",
                    ));
                }
                if !accepted {
                    self.last_error = Some("group Welcome was rejected".to_owned());
                    return Ok(());
                }
                self.conversations
                    .get_mut(&conversation_id)
                    .and_then(|state| state.pending_operation.as_mut())
                    .ok_or(ChatError::InvalidSetup("no group operation is pending"))?
                    .welcome_acked = true;
                self.persist_conversation(conversation_id)?;
                self.finish_operation_if_ready(conversation_id)?;
                Ok(())
            }
            (
                SetupMessage::GroupCommitAck {
                    conversation_id: ack_id,
                    transaction_id: ack_transaction,
                    operation: acked_operation,
                    accepted,
                },
                GroupRequestKind::Commit,
            ) => {
                if ack_id != conversation_id
                    || ack_transaction != transaction_id
                    || acked_operation != request.operation
                {
                    return Err(ChatError::InvalidSetup(
                        "unexpected group commit acknowledgement",
                    ));
                }
                let Some(operation) = self
                    .conversations
                    .get(&conversation_id)
                    .and_then(|state| state.pending_operation.as_ref())
                else {
                    return Err(ChatError::InvalidSetup("no group operation is pending"));
                };
                if operation.transaction_id != transaction_id {
                    return Err(ChatError::InvalidSetup(
                        "group commit acknowledgement belongs to a different transaction",
                    ));
                }
                if !accepted {
                    self.last_error = Some("group commit was rejected by a member".to_owned());
                    return Err(ChatError::GroupOperationRejected);
                }
                let awaited = self
                    .conversations
                    .get_mut(&conversation_id)
                    .and_then(|state| state.pending_operation.as_mut())
                    .ok_or(ChatError::InvalidSetup("no group operation is pending"))?
                    .awaited
                    .get_mut(&peer)
                    .ok_or(ChatError::UnexpectedSender)?;
                *awaited = true;
                self.persist_conversation(conversation_id)?;
                self.finish_operation_if_ready(conversation_id)?;
                Ok(())
            }
            _ => Err(ChatError::InvalidSetup("unexpected group acknowledgement")),
        }
    }

    fn handle_file_event(&mut self, event: FileEvent) -> Result<(), ChatError> {
        match event {
            FileEvent::SentToPeer { .. } => Ok(()),
            FileEvent::RequestReceived {
                response_id,
                peer,
                bytes,
            } => self.handle_file_request(response_id, identity_peer(peer)?, &bytes),
            FileEvent::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => self.handle_file_response(request_id, identity_peer(peer)?, &bytes),
            FileEvent::Failed {
                request_id: Some(request_id),
                ..
            } => {
                if let Some(kind) = self.file_requests.remove(&request_id) {
                    match kind {
                        FileRequestKind::Offer { peer, transfer_id }
                        | FileRequestKind::Chunk {
                            peer, transfer_id, ..
                        }
                        | FileRequestKind::Manifest { peer, transfer_id } => {
                            self.fail_file_transfer(&peer, &transfer_id, "File request failed");
                        }
                    }
                }
                Ok(())
            }
            FileEvent::Failed {
                response_id: Some(_),
                ..
            } => {
                self.last_error = Some("file response could not be sent".to_owned());
                Ok(())
            }
            FileEvent::Failed { .. } => Ok(()),
        }
    }

    fn handle_file_request(
        &mut self,
        response_id: FileResponseId,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let frame = FileEnvelope::from_bytes(bytes)?;
        frame.require_pq()?;
        frame.verify(&peer)?;
        let transfer_id = *frame.transfer_id();

        match &frame.message {
            FileMessage::Offer { .. } => {
                if peer == self.identity.peer_id() {
                    self.respond_file(response_id, FileMessage::Reject { transfer_id })?;
                    return Err(ChatError::UnexpectedSender);
                }
                if !self.conversation_ready(&peer) {
                    self.respond_file(response_id, FileMessage::Reject { transfer_id })?;
                    return Err(ChatError::ConversationNotReady);
                }
                if self
                    .incoming_files
                    .get(&peer)
                    .is_some_and(|transfer| transfer.status().active())
                    || self
                        .outgoing_files
                        .get(&peer)
                        .is_some_and(|transfer| transfer.status().active())
                {
                    self.respond_file(response_id, FileMessage::Reject { transfer_id })?;
                    return Err(ChatError::FileTransferLimit);
                }
                self.incoming_files.remove(&peer);
                self.outgoing_files.remove(&peer);
                let incoming = IncomingFile::new(&frame, peer, &self.file_config)?;
                self.respond_file(
                    response_id,
                    FileMessage::Accept {
                        transfer_id,
                        accepted: true,
                    },
                )?;
                self.incoming_files.insert(peer, incoming);
                self.start_transfer_deadline(peer, transfer_id);
                Ok(())
            }
            FileMessage::Chunk { index, .. } => {
                let (accepted, error, progressed) = match self.incoming_files.get_mut(&peer) {
                    Some(incoming)
                        if *incoming.transfer_id() == transfer_id && incoming.status().active() =>
                    {
                        match incoming.accept_chunk(&frame) {
                            Ok(()) => (true, None, true),
                            Err(p2p_files::FileError::DuplicateChunk) => (true, None, false),
                            Err(error) => {
                                incoming.mark_failed("Incoming chunk failed");
                                (false, Some(error.to_string()), false)
                            }
                        }
                    }
                    _ => (false, Some("inactive file chunk".to_owned()), false),
                };
                self.respond_file(
                    response_id,
                    FileMessage::ChunkAck {
                        transfer_id,
                        index: *index,
                        accepted,
                    },
                )?;
                if progressed {
                    self.touch_transfer_deadline(peer, transfer_id);
                } else if error.is_some() {
                    self.clear_transfer_deadline(peer, transfer_id);
                }
                if let Some(error) = error {
                    self.last_error = Some(error);
                }
                Ok(())
            }
            FileMessage::Manifest { .. } => {
                let (accepted, error) = match self.incoming_files.get_mut(&peer) {
                    Some(incoming)
                        if *incoming.transfer_id() == transfer_id && incoming.status().active() =>
                    {
                        match incoming.verify_manifest(&frame) {
                            Ok(_) => (true, None),
                            Err(error) => (false, Some(error.to_string())),
                        }
                    }
                    _ => (false, Some("inactive file manifest".to_owned())),
                };
                self.respond_file(
                    response_id,
                    FileMessage::ManifestAck {
                        transfer_id,
                        accepted,
                    },
                )?;
                self.clear_transfer_deadline(peer, transfer_id);
                if let Some(error) = error {
                    self.last_error = Some(error);
                }
                Ok(())
            }
            FileMessage::Reject { .. } => {
                self.fail_file_transfer(&peer, &transfer_id, "File transfer rejected by peer");
                self.respond_file(response_id, FileMessage::Reject { transfer_id })
            }
            FileMessage::Accept { .. }
            | FileMessage::ChunkAck { .. }
            | FileMessage::ManifestAck { .. } => {
                self.respond_file(response_id, FileMessage::Reject { transfer_id })?;
                Err(ChatError::InvalidFileFrame("unexpected file request type"))
            }
        }
    }

    fn handle_file_response(
        &mut self,
        request_id: FileRequestId,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let Some(kind) = self.file_requests.remove(&request_id) else {
            return Ok(());
        };
        let frame = FileEnvelope::from_bytes(bytes)?;
        frame.require_pq()?;
        frame.verify(&peer)?;

        if let FileMessage::Reject { transfer_id } = &frame.message {
            self.fail_file_transfer(&peer, transfer_id, "File transfer rejected by peer");
            return Ok(());
        }

        match (kind, &frame.message) {
            (
                FileRequestKind::Offer {
                    peer: expected,
                    transfer_id: expected_id,
                },
                FileMessage::Accept {
                    transfer_id,
                    accepted,
                },
            ) => {
                if peer != expected || *transfer_id != expected_id {
                    return Err(ChatError::UnexpectedSender);
                }
                if !accepted {
                    self.fail_file_transfer(&peer, &expected_id, "File offer rejected by peer");
                    return Ok(());
                }
                if let Some(outgoing) = self.outgoing_files.get_mut(&peer)
                    && *outgoing.transfer_id() == expected_id
                {
                    outgoing.mark_accepted();
                }
                self.touch_transfer_deadline(peer, expected_id);
                self.send_next_outgoing_frame(peer, expected_id)
            }
            (
                FileRequestKind::Chunk {
                    peer: expected,
                    transfer_id: expected_id,
                    index,
                },
                FileMessage::ChunkAck {
                    transfer_id,
                    index: ack_index,
                    accepted,
                },
            ) => {
                if peer != expected || *transfer_id != expected_id || *ack_index != index {
                    return Err(ChatError::UnexpectedSender);
                }
                if !accepted {
                    self.fail_file_transfer(&peer, &expected_id, "Chunk rejected by peer");
                    return Ok(());
                }
                let should_continue = {
                    let Some(outgoing) = self.outgoing_files.get_mut(&peer) else {
                        return Err(ChatError::FileTransferMissing);
                    };
                    if *outgoing.transfer_id() != expected_id {
                        return Err(ChatError::UnexpectedSender);
                    }
                    outgoing.mark_acked(index, true)?;
                    outgoing.has_more_chunks()
                        || (outgoing.all_chunks_acked() && !outgoing.manifest_sent())
                };
                self.touch_transfer_deadline(peer, expected_id);
                if should_continue {
                    self.send_next_outgoing_frame(peer, expected_id)?;
                }
                Ok(())
            }
            (
                FileRequestKind::Manifest {
                    peer: expected,
                    transfer_id: expected_id,
                },
                FileMessage::ManifestAck {
                    transfer_id,
                    accepted,
                },
            ) => {
                if peer != expected || *transfer_id != expected_id {
                    return Err(ChatError::UnexpectedSender);
                }
                if let Some(outgoing) = self.outgoing_files.get_mut(&peer)
                    && *outgoing.transfer_id() == expected_id
                {
                    outgoing.mark_manifest_ack(*accepted);
                }
                if *accepted {
                    self.clear_transfer_deadline(peer, expected_id);
                } else {
                    self.fail_file_transfer(&peer, &expected_id, "Manifest rejected by peer");
                }
                Ok(())
            }
            _ => Err(ChatError::InvalidFileFrame("unexpected file response type")),
        }
    }

    fn respond_file(
        &self,
        response_id: FileResponseId,
        message: FileMessage,
    ) -> Result<(), ChatError> {
        let frame = FileEnvelope::new(&self.identity, message)?;
        Ok(self
            .network
            .respond_to_file(response_id, frame.to_bytes()?)?)
    }

    fn send_next_outgoing_frame(
        &mut self,
        peer: PeerId,
        transfer_id: [u8; 16],
    ) -> Result<(), ChatError> {
        let step: Option<(Vec<u8>, FileRequestKind)> = {
            let Some(outgoing) = self.outgoing_files.get_mut(&peer) else {
                return Err(ChatError::FileTransferMissing);
            };
            if *outgoing.transfer_id() != transfer_id
                || matches!(
                    outgoing.status(),
                    p2p_files::TransferStatus::Failed(_)
                        | p2p_files::TransferStatus::IntegrityVerified
                )
            {
                return Ok(());
            }
            if let Some(chunk) = outgoing.next_chunk_frame(&self.identity)? {
                let index = match &chunk.message {
                    FileMessage::Chunk { index, .. } => *index,
                    _ => return Err(ChatError::InvalidFileFrame("expected a chunk frame")),
                };
                Some((
                    chunk.to_bytes()?,
                    FileRequestKind::Chunk {
                        peer,
                        transfer_id,
                        index,
                    },
                ))
            } else if outgoing.all_chunks_acked() && !outgoing.manifest_sent() {
                let manifest = outgoing.manifest_frame(&self.identity)?;
                outgoing.mark_manifest_sent();
                Some((
                    manifest.to_bytes()?,
                    FileRequestKind::Manifest { peer, transfer_id },
                ))
            } else {
                None
            }
        };
        if let Some((bytes, kind)) = step {
            let request_id = self.network.send_file(swarm_peer(&peer)?, bytes)?;
            self.file_requests.insert(request_id, kind);
        }
        Ok(())
    }

    fn fail_file_transfer(&mut self, peer: &PeerId, transfer_id: &[u8; 16], reason: &'static str) {
        if let Some(outgoing) = self.outgoing_files.get_mut(peer)
            && outgoing.transfer_id() == transfer_id
        {
            outgoing.mark_failed(reason);
        }
        if let Some(incoming) = self.incoming_files.get_mut(peer)
            && incoming.transfer_id() == transfer_id
        {
            incoming.mark_failed(reason);
        }
        self.clear_transfer_deadline(*peer, *transfer_id);
    }

    fn start_transfer_deadline(&mut self, peer: PeerId, transfer_id: [u8; 16]) {
        self.transfer_deadlines.insert(
            peer,
            TransferDeadline {
                transfer_id,
                expires_at: Instant::now() + self.transfer_timeout,
            },
        );
    }

    fn touch_transfer_deadline(&mut self, peer: PeerId, transfer_id: [u8; 16]) {
        if let Some(deadline) = self.transfer_deadlines.get_mut(&peer)
            && deadline.transfer_id == transfer_id
        {
            deadline.expires_at = Instant::now() + self.transfer_timeout;
        }
    }

    fn clear_transfer_deadline(&mut self, peer: PeerId, transfer_id: [u8; 16]) {
        if self
            .transfer_deadlines
            .get(&peer)
            .is_some_and(|deadline| deadline.transfer_id == transfer_id)
        {
            self.transfer_deadlines.remove(&peer);
        }
    }

    fn sweep_transfer_timeouts(&mut self) {
        let now = Instant::now();
        let expired: Vec<(PeerId, [u8; 16])> = self
            .transfer_deadlines
            .iter()
            .filter(|(_, deadline)| deadline.expires_at <= now)
            .map(|(peer, deadline)| (*peer, deadline.transfer_id))
            .collect();
        for (peer, transfer_id) in expired {
            let _ = self.abort_transfer(peer, transfer_id, "Transfer timed out");
        }
    }

    fn abort_transfer(
        &mut self,
        peer: PeerId,
        transfer_id: [u8; 16],
        reason: &'static str,
    ) -> Result<(), ChatError> {
        let Some(deadline) = self.transfer_deadlines.get(&peer).copied() else {
            return Err(ChatError::FileTransferNotActive);
        };
        if deadline.transfer_id != transfer_id {
            return Err(ChatError::FileTransferNotActive);
        }
        let outgoing_active = self.outgoing_files.get(&peer).is_some_and(|transfer| {
            *transfer.transfer_id() == transfer_id && transfer.status().active()
        });
        let incoming_active = self.incoming_files.get(&peer).is_some_and(|transfer| {
            *transfer.transfer_id() == transfer_id && transfer.status().active()
        });
        if !outgoing_active && !incoming_active {
            self.transfer_deadlines.remove(&peer);
            return Err(ChatError::FileTransferNotActive);
        }

        self.file_requests.retain(|_, kind| match kind {
            FileRequestKind::Offer {
                peer: p,
                transfer_id: id,
            }
            | FileRequestKind::Chunk {
                peer: p,
                transfer_id: id,
                ..
            }
            | FileRequestKind::Manifest {
                peer: p,
                transfer_id: id,
            } => *p != peer || *id != transfer_id,
        });
        if outgoing_active {
            self.outgoing_files
                .get_mut(&peer)
                .expect("checked outgoing transfer")
                .abort(reason)?;
        }
        if incoming_active {
            self.incoming_files
                .get_mut(&peer)
                .expect("checked incoming transfer")
                .abort(reason)?;
        }
        self.transfer_deadlines.remove(&peer);
        Ok(())
    }

    fn handle_message_event(&mut self, event: MessageEvent) -> Result<(), ChatError> {
        match event {
            MessageEvent::SentToPeer { request_id, .. } => {
                self.mark_outgoing(request_id, DeliveryState::SentToPeer)
            }
            MessageEvent::Failed {
                request_id: Some(request_id),
                ..
            } => self.mark_outgoing(request_id, DeliveryState::Failed),
            MessageEvent::Failed { .. } => Ok(()),
            MessageEvent::RequestReceived {
                response_id,
                peer,
                bytes,
            } => self.handle_message_request(response_id, peer, &bytes),
            MessageEvent::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => self.handle_message_response(request_id, peer, &bytes),
        }
    }

    fn mark_outgoing(
        &mut self,
        request_id: MessageRequestId,
        delivery: DeliveryState,
    ) -> Result<(), ChatError> {
        // Keep the request-id mapping after SentToPeer: the same identifier is
        // needed to match the later response and apply its verified receipt.
        let Some(message_id) = (match delivery {
            DeliveryState::SentToPeer => self.outstanding_messages.get(&request_id).copied(),
            DeliveryState::Failed => {
                let message_id = self.outstanding_messages.remove(&request_id);
                // A group broadcast has one transport request per recipient;
                // one failure must not be shown as a failed message while other
                // recipients are still pending.
                if message_id
                    .is_some_and(|id| self.outstanding_messages.values().any(|other| *other == id))
                {
                    None
                } else {
                    message_id
                }
            }
            _ => None,
        }) else {
            return Ok(());
        };
        let mut persist_conversation = None;
        if let Some(conversation_id) = self.message_conversations.get(&message_id).copied() {
            let channel_id = self.message_channel_routes.get(&message_id).copied();
            match delivery {
                DeliveryState::SentToPeer => {
                    if self.message_group_delivery_state(conversation_id, channel_id, &message_id)
                        != Some(DeliveryState::SentToPeer)
                    {
                        self.mark_message_group(
                            conversation_id,
                            channel_id,
                            message_id,
                            DeliveryState::SentToPeer,
                        )?;
                    }
                    persist_conversation = Some(conversation_id);
                }
                DeliveryState::Failed => self.mark_message_group(
                    conversation_id,
                    channel_id,
                    message_id,
                    DeliveryState::Failed,
                )?,
                _ => return Err(ChatError::InvalidSetup("invalid outgoing transition")),
            }
        }
        self.set_line_delivery(message_id, delivery);
        if let Some(conversation_id) = persist_conversation {
            self.persist_conversation(conversation_id)?;
        }
        Ok(())
    }

    fn set_line_delivery(&mut self, message_id: [u8; 16], delivery: DeliveryState) {
        if let Some(line) = self
            .messages
            .iter_mut()
            .find(|line| line.message_id == message_id && line.origin == MessageOrigin::Local)
        {
            line.delivery = Some(delivery);
        }
    }

    /// Compose one MLS-encrypted channel frame, send it to every listed
    /// recipient, and track its receipts. Text also adds a local display line;
    /// metadata is represented only by channel state and acknowledgement.
    fn broadcast_channel_frame(
        &mut self,
        conversation_id: [u8; 16],
        channel_id: [u8; 16],
        frame: ChannelFrame,
        recipients: Vec<PeerId>,
        display_text: Option<String>,
    ) -> Result<[u8; 16], ChatError> {
        let body = frame.to_bytes()?;
        let derived =
            channel_id != DEFAULT_CHANNEL_ID && matches!(frame.kind, ChannelFrameKind::Text { .. });
        let channel_route = derived.then_some(channel_id);
        {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if state.status != ConversationStatus::Joined {
                return Err(ChatError::ConversationNotReady);
            }
            if state.pending_operation.is_some() {
                return Err(ChatError::GroupOperationPending);
            }
        }
        // Only ciphertext is queued, and the queue must stay bounded even for
        // a hostile peer that never reconnects. Check before composing so a
        // rejected send cannot leave a half-tracked message behind.
        let would_queue = recipients
            .iter()
            .filter(|peer| !self.is_connected(peer))
            .count();
        if self.offline_queue.len().saturating_add(would_queue) > MAX_OFFLINE_QUEUE {
            return Err(ChatError::OfflineQueueFull);
        }
        let (message_id, envelope_bytes) = if derived {
            let state = self
                .channel_groups
                .get_mut(&channel_group_id(conversation_id, channel_id))
                .ok_or(ChatError::ChannelGroupNotReady)?;
            if !state.ready {
                return Err(ChatError::ChannelGroupNotReady);
            }
            let (envelope, message_id) =
                state
                    .group
                    .compose_v4(&self.identity, MessageKind::Channel, &body)?;
            (message_id, envelope.to_bytes()?)
        } else {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            let (envelope, message_id) =
                state
                    .conversation
                    .compose_v4(&self.identity, MessageKind::Channel, &body)?;
            (message_id, envelope.to_bytes()?)
        };

        let has_offline = recipients
            .iter()
            .any(|recipient| !self.is_connected(recipient));
        if has_offline {
            self.mark_message_group(
                conversation_id,
                channel_route,
                message_id,
                DeliveryState::Queued,
            )?;
        }

        let mut sent_error = None;
        for recipient in &recipients {
            if self.is_connected(recipient) {
                match self
                    .network
                    .send_message(swarm_peer(recipient)?, envelope_bytes.clone())
                {
                    Ok(request_id) => {
                        self.outstanding_messages.insert(request_id, message_id);
                    }
                    Err(error) => sent_error = Some(ChatError::Network(error)),
                }
            } else {
                self.offline_queue.push_back(QueuedMessage {
                    peer: *recipient,
                    conversation_id,
                    channel_id: channel_route.unwrap_or(DEFAULT_CHANNEL_ID),
                    message_id,
                    envelope_bytes: envelope_bytes.clone(),
                });
            }
        }
        if let Some(error) = sent_error {
            let _ = self.mark_message_group(
                conversation_id,
                channel_route,
                message_id,
                DeliveryState::Failed,
            );
            return Err(error);
        }

        if derived {
            self.message_channel_routes.insert(message_id, channel_id);
        }
        self.message_conversations
            .insert(message_id, conversation_id);
        self.pending_receipts
            .insert(message_id, recipients.into_iter().collect());
        if let Some(text) = display_text {
            self.messages.push(ChatMessage {
                message_id,
                channel_id,
                peer: self.identity.peer_id(),
                text,
                origin: MessageOrigin::Local,
                delivery: Some(if has_offline {
                    DeliveryState::Queued
                } else {
                    DeliveryState::Composed
                }),
            });
        }
        self.persist_conversation(conversation_id)?;
        Ok(message_id)
    }

    fn handle_message_request(
        &mut self,
        response_id: p2p_network::MessageResponseId,
        swarm_peer: SwarmPeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let peer = identity_peer(swarm_peer)?;
        let receipt_bytes = self.receive_message(peer, bytes)?;
        if let Some(receipt_bytes) = receipt_bytes {
            self.network
                .respond_to_message(response_id, receipt_bytes)?;
        }
        Ok(())
    }

    /// Verify, decrypt, and apply one inbound application envelope. The
    /// returned receipt bytes belong to the same MLS group as the ciphertext;
    /// the transport wrapper sends them after this function has finished.
    fn receive_message(
        &mut self,
        peer: PeerId,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, ChatError> {
        let envelope = EnvelopeV4::from_bytes(bytes)?;

        // The outer tag is random per frame and is never matched as a stable
        // route value. Every current parent and derived group is offered the
        // frame; only a group whose exporter key verifies the MAC is a route.
        // Ambiguity or absence fails closed rather than guessing a group.
        let mut routes = Vec::new();
        for (id, state) in &self.conversations {
            if state.conversation.verify_v4_route(&envelope).is_ok() {
                if !state.members.contains(&peer) {
                    return Err(ChatError::NotGroupMember);
                }
                routes.push((*id, None, *id));
            }
        }
        for (group_id, state) in &self.channel_groups {
            if state.group.verify_v4_route(&envelope).is_ok() {
                let parent = state.binding.parent_conversation_id();
                let channel = state.binding.channel_id();
                let parent_state = self
                    .conversations
                    .get(&parent)
                    .ok_or(ChatError::UnknownConversation)?;
                if !parent_state.members.contains(&peer) {
                    return Err(ChatError::NotGroupMember);
                }
                if !parent_state
                    .channels
                    .get(&channel)
                    .is_some_and(|channel_state| channel_state.members.contains(&peer))
                {
                    return Err(ChatError::NotChannelMember);
                }
                routes.push((parent, Some(channel), *group_id));
            }
        }
        let (parent_conversation_id, derived_channel, group_id) = match routes.as_slice() {
            [] => return Err(ChatError::UnknownMessageRoute),
            [route] => *route,
            _ => return Err(ChatError::AmbiguousMessageRoute),
        };

        let (message_id, plaintext, receipt_bytes, channel_text, apply_error, kind) = {
            if let Some(channel_id) = derived_channel {
                let received = self
                    .channel_groups
                    .get_mut(&group_id)
                    .ok_or(ChatError::ChannelGroupNotReady)?
                    .group
                    .receive_v4(envelope)?;
                if received.metadata.sender != peer {
                    return Err(ChatError::UnexpectedSender);
                }
                if received.metadata.kind != MessageKind::Channel {
                    return Err(ChatError::InvalidChannelFrame(
                        "derived channel group accepted a non-channel frame",
                    ));
                }
                let kind = received.metadata.kind;
                let message_id = received.metadata.message_id;
                let plaintext = received.plaintext.to_vec();
                let mut channel_text = None;
                let mut apply_error = None;
                match ChannelFrame::from_bytes(&plaintext) {
                    Ok(frame) => {
                        if frame.channel_id != channel_id {
                            apply_error = Some(
                                "channel frame ID does not match the derived MLS group".to_owned(),
                            );
                        } else if !matches!(frame.kind, ChannelFrameKind::Text { .. }) {
                            apply_error =
                                Some("derived channel group accepted a policy frame".to_owned());
                        } else {
                            let applied = self
                                .conversations
                                .get_mut(&parent_conversation_id)
                                .ok_or(ChatError::UnknownConversation)?
                                .apply_channel_frame(peer, frame);
                            match applied {
                                Ok(text) => channel_text = text,
                                Err(error) => apply_error = Some(error.to_string()),
                            }
                        }
                    }
                    Err(error) => apply_error = Some(error.to_string()),
                }
                let receipt_bytes = if apply_error.is_some() {
                    None
                } else {
                    let receipt = self
                        .channel_groups
                        .get_mut(&group_id)
                        .ok_or(ChatError::ChannelGroupNotReady)?
                        .group
                        .receipt_v4(&self.identity, ReceiptStatus::Delivered, message_id)?
                        .0;
                    Some(receipt.to_bytes()?)
                };
                (
                    message_id,
                    plaintext,
                    receipt_bytes,
                    channel_text,
                    apply_error,
                    kind,
                )
            } else {
                let state = self
                    .conversations
                    .get_mut(&parent_conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                let received = state.conversation.receive_v4(envelope)?;
                if received.metadata.sender != peer {
                    return Err(ChatError::UnexpectedSender);
                }
                let kind = received.metadata.kind;
                let message_id = received.metadata.message_id;
                let plaintext = received.plaintext.to_vec();
                if kind == MessageKind::Receipt {
                    (message_id, plaintext, None, None, None, kind)
                } else {
                    let mut channel_text = None;
                    let mut apply_error = None;
                    if kind == MessageKind::Channel {
                        match ChannelFrame::from_bytes(&plaintext) {
                            Ok(frame) => {
                                if matches!(frame.kind, ChannelFrameKind::Text { .. })
                                    && frame.channel_id != DEFAULT_CHANNEL_ID
                                {
                                    apply_error = Some(
                                        "non-default channel text must use a derived MLS group"
                                            .to_owned(),
                                    );
                                } else {
                                    match state.apply_channel_frame(peer, frame) {
                                        Ok(text) => channel_text = text,
                                        Err(error) => apply_error = Some(error.to_string()),
                                    }
                                }
                            }
                            Err(error) => apply_error = Some(error.to_string()),
                        }
                    }
                    if apply_error.is_some() {
                        (message_id, plaintext, None, None, apply_error, kind)
                    } else {
                        let receipt = state
                            .conversation
                            .receipt_v4(&self.identity, ReceiptStatus::Delivered, message_id)?
                            .0;
                        (
                            message_id,
                            plaintext,
                            Some(receipt.to_bytes()?),
                            channel_text,
                            None,
                            kind,
                        )
                    }
                }
            }
        };

        if let Some(reason) = apply_error {
            // An unauthorised or malformed channel frame gets no delivery
            // receipt: that would falsely acknowledge a policy change.
            self.last_error = Some(reason);
            return Ok(None);
        }

        if kind == MessageKind::Text {
            match String::from_utf8(plaintext) {
                Ok(text) => {
                    self.message_conversations
                        .insert(message_id, parent_conversation_id);
                    self.messages.push(ChatMessage {
                        message_id,
                        channel_id: DEFAULT_CHANNEL_ID,
                        peer,
                        text,
                        origin: MessageOrigin::Remote,
                        delivery: None,
                    });
                }
                Err(_) => {
                    self.last_error = Some("received text was not valid UTF-8".to_owned());
                }
            }
        } else if let Some((channel_id, text)) = channel_text {
            self.message_conversations
                .insert(message_id, parent_conversation_id);
            self.messages.push(ChatMessage {
                message_id,
                channel_id,
                peer,
                text,
                origin: MessageOrigin::Remote,
                delivery: None,
            });
        }
        if kind == MessageKind::Channel {
            self.persist_conversation(parent_conversation_id)?;
        }
        Ok(receipt_bytes)
    }

    fn handle_message_response(
        &mut self,
        request_id: MessageRequestId,
        swarm_peer: SwarmPeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let Some(local_message_id) = self.outstanding_messages.remove(&request_id) else {
            return Ok(());
        };
        let peer = identity_peer(swarm_peer)?;
        let envelope = EnvelopeV4::from_bytes(bytes)?;
        let parent_conversation_id = *self
            .message_conversations
            .get(&local_message_id)
            .ok_or(ChatError::UnknownConversation)?;
        let channel_id = self.message_channel_routes.get(&local_message_id).copied();
        let expected_group_id = match channel_id {
            Some(channel_id) => channel_group_id(parent_conversation_id, channel_id),
            None => parent_conversation_id,
        };
        // `receive_v4` verifies the group-keyed MAC over the random tag,
        // MLS-decrypts the body in the expected group, and binds the inner
        // sender before the receipt body is parsed.
        let received = if let Some(channel_id) = channel_id {
            let parent_state = self
                .conversations
                .get(&parent_conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if !parent_state.members.contains(&peer) {
                return Err(ChatError::NotGroupMember);
            }
            if !parent_state
                .channels
                .get(&channel_id)
                .is_some_and(|state| state.members.contains(&peer))
            {
                return Err(ChatError::NotChannelMember);
            }
            let Some(state) = self.channel_groups.get_mut(&expected_group_id) else {
                return Ok(());
            };
            state.group.receive_v4(envelope)?
        } else {
            let state = self
                .conversations
                .get_mut(&parent_conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if !state.members.contains(&peer) {
                return Err(ChatError::NotGroupMember);
            }
            state.conversation.receive_v4(envelope)?
        };
        if received.metadata.sender != peer {
            return Err(ChatError::UnexpectedSender);
        }
        if received.metadata.kind != MessageKind::Receipt {
            return Err(ChatError::InvalidChannelFrame(
                "v4 response was not an MLS-protected receipt",
            ));
        }
        let mut setup_trigger = None;
        if let Some(receipt) = received.metadata.receipt {
            if receipt.message_id != local_message_id {
                return Err(ChatError::InvalidChannelFrame(
                    "receipt message ID does not match the request",
                ));
            }
            let complete = match self.pending_receipts.get_mut(&receipt.message_id) {
                Some(expected) => {
                    expected.remove(&peer);
                    let complete = expected.is_empty();
                    if complete {
                        self.pending_receipts.remove(&receipt.message_id);
                    }
                    complete
                }
                None => true,
            };
            if complete {
                setup_trigger = self.pending_channel_policy_acks.remove(&receipt.message_id);
            }
            self.set_line_delivery(
                receipt.message_id,
                if complete {
                    DeliveryState::Delivered
                } else {
                    DeliveryState::SentToPeer
                },
            );
        }
        if let Some(trigger) = setup_trigger {
            self.start_channel_setup_for_channel(
                trigger.conversation_id,
                trigger.channel_id,
                trigger.recreate,
            )?;
        }
        self.persist_conversation(parent_conversation_id)?;
        Ok(())
    }
}

impl fmt::Debug for MessengerController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerController")
            .field("peer", &self.identity.peer_id().to_string())
            .field("connection", self.network.state())
            .field("conversations", &self.conversations)
            .field("pending_key_packages", &self.pending_key_packages.len())
            .field("messages", &self.messages.len())
            .field("offline_queue", &self.offline_queue.len())
            .field("saved_addresses", &self.dialed_addresses.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

fn backoff_delay(config: &RedialConfig, attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(32);
    (0..exponent).fold(config.base_delay, |delay, _| {
        delay.saturating_mul(2).min(config.max_delay)
    })
}

fn address_peer(address: &Multiaddr) -> Result<PeerId, ChatError> {
    let swarm_peer = address
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .ok_or_else(|| ChatError::InvalidPeerId("address must end in /p2p/<peer-id>".to_owned()))?;
    identity_peer(swarm_peer)
}

fn identity_peer(peer: SwarmPeerId) -> Result<PeerId, ChatError> {
    peer.to_string()
        .parse::<PeerId>()
        .map_err(|error| ChatError::InvalidPeerId(error.to_string()))
}

fn swarm_peer(peer: &PeerId) -> Result<SwarmPeerId, ChatError> {
    peer.to_string()
        .parse::<SwarmPeerId>()
        .map_err(|error| ChatError::InvalidPeerId(error.to_string()))
}

fn frame_members(frame: &ChannelFrame) -> Result<BTreeSet<PeerId>, ChatError> {
    match &frame.kind {
        ChannelFrameKind::Create { members, .. } | ChannelFrameKind::SetMembers { members } => {
            Ok(members.iter().copied().collect())
        }
        _ => Err(ChatError::InvalidChannelFrame("frame has no member set")),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_groups::GroupError;
    use p2p_identity::IdentityRole;
    use p2p_messaging::MessageError;
    use p2p_storage::Vault;

    fn mls_public_key(identity: &Identity) -> Vec<u8> {
        identity
            .pq_role_public_bytes(IdentityRole::Mls)
            .expect("certified ML-DSA-65 MLS role key")
    }

    #[test]
    fn legacy_v4_setup_frames_fail_the_controller_decode_gate() {
        let sender = Identity::generate().expect("sender");
        let frame = SetupEnvelope::legacy_v4_frame_for_tests(
            &sender,
            SetupMessage::WelcomeAck {
                conversation_id: [7; 16],
                transaction_id: [8; 16],
                accepted: true,
            },
        )
        .expect("valid classical frame");
        frame
            .verify(&sender.peer_id())
            .expect("legacy codec still verifies as a frame");
        let bytes = frame.to_bytes().expect("encoded legacy setup frame");

        let error = MessengerController::decode_setup(
            swarm_peer(&sender.peer_id()).expect("swarm peer"),
            &bytes,
        )
        .expect_err("a classical v4 setup frame must never enter the controller");
        assert!(error.to_string().contains("post-quantum"));
    }

    #[test]
    fn legacy_v2_file_frames_fail_the_controller_receive_gate() {
        let (_, mut controller) = test_controller();
        let sender = Identity::generate().expect("sender");
        let frame = FileEnvelope::legacy_v2_frame_for_tests(
            &sender,
            FileMessage::Accept {
                transfer_id: [7; 16],
                accepted: true,
            },
        )
        .expect("valid classical frame");
        frame
            .verify(&sender.peer_id())
            .expect("legacy codec still verifies as a frame");
        let bytes = frame.to_bytes().expect("encoded legacy file frame");

        let error = controller
            .handle_file_request(FileResponseId::for_tests(1), sender.peer_id(), &bytes)
            .expect_err("a classical v2 file frame must never enter the controller");
        assert!(error.to_string().contains("version"));
    }

    #[test]
    fn legacy_v3_application_frames_fail_the_controller_receive_gate() {
        let parent = [0x75u8; 16];
        let channel = [0x76u8; 16];
        let (admin, allowed, binding, mut admin_group, allowed_group) =
            bound_channel_pair(parent, channel);
        let frame = ChannelFrame::text(channel, 1, "legacy v3 payload").expect("channel frame");
        let (envelope, _message_id) = admin_group
            .compose_v3(
                &admin,
                MessageKind::Channel,
                &frame.to_bytes().expect("frame bytes"),
            )
            .expect("legacy v3 compose");
        let bytes = envelope.to_bytes().expect("encoded v3");

        let mut controller =
            MessengerController::start(&allowed, NetworkConfig::direct()).expect("controller");
        let members = [admin.peer_id(), allowed.peer_id()];
        controller.conversations.insert(
            parent,
            channel_parent_state(&allowed, admin.peer_id(), channel, &members),
        );
        controller.channel_groups.insert(
            binding.group_id(),
            ChannelGroupState {
                binding,
                group: allowed_group,
                awaited: BTreeSet::new(),
                ready: true,
            },
        );

        let error = controller
            .receive_message(admin.peer_id(), &bytes)
            .expect_err("v3 wire must not enter the v4 controller receive gate");
        assert!(matches!(
            error,
            ChatError::Message(MessageError::BadProtocol)
        ));
        assert!(controller.messages.is_empty());
    }

    #[test]
    fn default_controller_privacy_status_is_all_off_and_unobserved() {
        let identity = Identity::generate().expect("identity");
        let controller =
            MessengerController::start(&identity, NetworkConfig::direct()).expect("controller");
        let status = controller.network_privacy_status();

        assert!(!status.identify_enabled);
        assert!(!status.ping_enabled);
        assert!(!status.mdns_enabled);
        assert!(!status.kad_enabled);
        assert_eq!(status.kad_bootstrap_peers, 0);
        assert_eq!(status.relay_mode, p2p_network::RelayMode::Off);
        assert_eq!(status.relay_servers, 0);
        assert!(!status.autonat_enabled);
        assert!(!status.dcutr_enabled);
        assert_eq!(status.discovered_candidates, 0);
        assert_eq!(status.kad_routes, 0);
        assert_eq!(status.relay_reservations, 0);
        assert_eq!(status.relay_circuits, 0);
        assert_eq!(status.nat_status, "Unknown");
        assert_eq!(status.identified_peers, 0);
        assert_eq!(status.relayed_connections, 0);
        assert!(status.nat_description().contains("no AutoNAT observation"));
    }

    fn test_controller() -> (Identity, MessengerController) {
        let identity = Identity::generate().expect("identity");
        let controller =
            MessengerController::start(&identity, NetworkConfig::direct()).expect("controller");
        (identity, controller)
    }

    #[test]
    fn offline_queue_rejects_a_full_queue_before_composing_ciphertext() {
        let (local, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let conversation = MlsConversation::new(&local).expect("joined group");
        let conversation_id = conversation.id();
        let members = BTreeSet::from([local.peer_id(), peer.peer_id()]);
        let state = ConversationState::new(conversation, local.peer_id(), members);
        controller.conversations.insert(conversation_id, state);
        controller
            .peer_conversations
            .insert(peer.peer_id(), conversation_id);
        controller.active = Some(conversation_id);
        controller
            .active_channel
            .insert(conversation_id, DEFAULT_CHANNEL_ID);
        for index in 0..MAX_OFFLINE_QUEUE {
            controller.offline_queue.push_back(QueuedMessage {
                peer: peer.peer_id(),
                conversation_id,
                channel_id: DEFAULT_CHANNEL_ID,
                message_id: [index as u8; 16],
                envelope_bytes: vec![0u8; 4],
            });
        }

        let before = controller.offline_queue.len();
        let error = controller
            .send_text(peer.peer_id(), "must not be queued")
            .expect_err("a full offline queue must fail closed");
        assert!(matches!(error, ChatError::OfflineQueueFull));
        assert_eq!(controller.offline_queue.len(), before);
        assert!(controller.messages.is_empty());
    }

    fn signed(identity: &Identity, message: SetupMessage) -> SetupEnvelope {
        SetupEnvelope::new(identity, message).expect("signed setup frame")
    }

    fn controller_with_restricted_channel(
        allowed: PeerId,
        excluded: PeerId,
    ) -> (
        Identity,
        MessengerController,
        [u8; 16],
        [u8; 16],
        ChannelScope,
    ) {
        let local = Identity::generate().expect("local identity");
        let conversation = MlsConversation::new(&local).expect("joined parent MLS group");
        let parent = conversation.id();
        let channel = [0x51u8; 16];
        let transaction_id = [0x52u8; 16];
        let mut members = BTreeSet::new();
        members.insert(local.peer_id());
        members.insert(allowed);
        members.insert(excluded);
        let mut state = ConversationState::new(conversation, local.peer_id(), members);
        let allowed_members = [local.peer_id(), allowed].into_iter().collect();
        state.channels.insert(
            channel,
            ChannelState {
                name: "private".to_owned(),
                creator: local.peer_id(),
                members: allowed_members,
                revision: 1,
                last_frame_id: None,
            },
        );
        let (_, mut controller) = test_controller();
        controller.conversations.insert(parent, state);
        (
            local,
            controller,
            parent,
            channel,
            ChannelScope {
                parent_conversation_id: parent,
                channel_id: channel,
                transaction_id,
            },
        )
    }

    #[test]
    fn channel_setup_scope_binds_parent_channel_transaction_and_peer() {
        let allowed = Identity::generate().expect("allowed peer");
        let excluded = Identity::generate().expect("excluded peer");
        let (_local, controller, parent, channel, scope) =
            controller_with_restricted_channel(allowed.peer_id(), excluded.peer_id());
        let frame = signed(
            &allowed,
            SetupMessage::ChannelKeyPackageRequest {
                conversation_id: parent,
                channel_id: channel,
                transaction_id: scope.transaction_id,
            },
        );

        let binding = controller
            .validate_channel_setup_scope(&allowed.peer_id(), &frame, &scope)
            .expect("allowed member has a valid channel scope");
        assert_eq!(binding.parent_conversation_id(), parent);
        assert_eq!(binding.channel_id(), channel);
        assert_eq!(
            binding.group_id(),
            p2p_groups::channel_group_id(parent, channel)
        );

        let wrong_parent = ChannelScope {
            parent_conversation_id: [0x61u8; 16],
            ..scope
        };
        let wrong_channel = ChannelScope {
            channel_id: [0x62u8; 16],
            ..scope
        };
        let wrong_transaction = ChannelScope {
            transaction_id: [0x63u8; 16],
            ..scope
        };
        for wrong in [wrong_parent, wrong_channel, wrong_transaction] {
            assert!(matches!(
                controller.validate_channel_setup_scope(&allowed.peer_id(), &frame, &wrong),
                Err(ChatError::InvalidSetup(_))
            ));
        }
        assert!(matches!(
            controller.validate_channel_setup_scope(&excluded.peer_id(), &frame, &scope),
            Err(ChatError::UnexpectedSender)
        ));
    }

    #[test]
    fn excluded_parent_member_cannot_validate_a_channel_setup_scope() {
        let allowed = Identity::generate().expect("allowed peer");
        let excluded = Identity::generate().expect("excluded parent member");
        let (_local, controller, parent, channel, scope) =
            controller_with_restricted_channel(allowed.peer_id(), excluded.peer_id());
        let frame = signed(
            &excluded,
            SetupMessage::ChannelWelcome {
                conversation_id: parent,
                channel_id: channel,
                transaction_id: scope.transaction_id,
                welcome: vec![1, 2, 3],
            },
        );

        let error = controller
            .validate_channel_setup_scope(&excluded.peer_id(), &frame, &scope)
            .expect_err("excluded parent member must not open channel setup");
        assert!(matches!(error, ChatError::NotChannelMember));
        let state = controller
            .conversations
            .get(&parent)
            .expect("parent conversation remains");
        assert!(
            !state
                .channels
                .get(&channel)
                .expect("restricted channel remains")
                .members
                .contains(&excluded.peer_id())
        );
    }

    fn bound_channel_pair(
        parent: [u8; 16],
        channel: [u8; 16],
    ) -> (
        Identity,
        Identity,
        ChannelGroupBinding,
        MlsChannelGroup,
        MlsChannelGroup,
    ) {
        let admin = Identity::generate().expect("channel admin");
        let allowed = Identity::generate().expect("allowed member");
        let binding = ChannelGroupBinding::new(parent, channel);
        let mut admin_group =
            MlsChannelGroup::create(&admin, binding).expect("admin channel group");
        let package = MlsChannelGroup::key_package(&allowed, binding).expect("allowed key package");
        let (welcome, _commit) = admin_group
            .add_member_parts(&package, allowed.peer_id(), &mls_public_key(&allowed))
            .expect("admin adds allowed member");
        let allowed_group =
            MlsChannelGroup::join(&allowed, binding, package, &welcome).expect("allowed joins");
        (admin, allowed, binding, admin_group, allowed_group)
    }

    fn channel_parent_state(
        local: &Identity,
        peer: PeerId,
        channel: [u8; 16],
        members: &[PeerId],
    ) -> ConversationState {
        let mut state = joined_state(local, peer, local.peer_id());
        state.channels.insert(
            channel,
            ChannelState {
                name: "private".to_owned(),
                creator: local.peer_id(),
                members: members.iter().copied().collect(),
                revision: 1,
                last_frame_id: None,
            },
        );
        state
    }

    #[test]
    fn excluded_parent_member_cannot_decrypt_injected_channel_ciphertext() {
        let parent = [0x71u8; 16];
        let channel = [0x72u8; 16];
        let secret = "excluded member must not decrypt this";
        let (admin, allowed, binding, mut admin_group, _allowed_group) =
            bound_channel_pair(parent, channel);
        let frame = ChannelFrame::text(channel, 1, secret).expect("channel text frame");
        let (envelope, _message_id) = admin_group
            .compose_v4(
                &admin,
                MessageKind::Channel,
                &frame.to_bytes().expect("frame bytes"),
            )
            .expect("compose channel ciphertext");
        let ciphertext = envelope.to_bytes().expect("encode channel ciphertext");

        let (excluded, mut controller) = test_controller();
        let allowed_members = [admin.peer_id(), allowed.peer_id()];
        let state = channel_parent_state(&excluded, admin.peer_id(), channel, &allowed_members);
        controller.conversations.insert(parent, state);

        let error = controller
            .receive_message(admin.peer_id(), &ciphertext)
            .expect_err("excluded member has no bound channel group");
        assert!(matches!(error, ChatError::UnknownMessageRoute));
        assert!(controller.messages.is_empty());
        assert_eq!(controller.last_error, None);
        assert!(binding.group_id() != parent);
    }

    #[test]
    fn allowed_member_decrypts_channel_ciphertext_and_receipt_uses_the_bound_group() {
        let parent = [0x73u8; 16];
        let channel = [0x74u8; 16];
        let secret = "bound group decrypts this";
        let (admin, allowed, binding, mut admin_group, allowed_group) =
            bound_channel_pair(parent, channel);
        let frame = ChannelFrame::text(channel, 1, secret).expect("channel text frame");
        let (envelope, message_id) = admin_group
            .compose_v4(
                &admin,
                MessageKind::Channel,
                &frame.to_bytes().expect("frame bytes"),
            )
            .expect("compose channel ciphertext");
        let ciphertext = envelope.to_bytes().expect("encode channel ciphertext");

        let mut controller =
            MessengerController::start(&allowed, NetworkConfig::direct()).expect("controller");
        let allowed_members = [admin.peer_id(), allowed.peer_id()];
        let state = channel_parent_state(&allowed, admin.peer_id(), channel, &allowed_members);
        controller.conversations.insert(parent, state);
        controller.channel_groups.insert(
            binding.group_id(),
            ChannelGroupState {
                binding,
                group: allowed_group,
                awaited: BTreeSet::new(),
                ready: true,
            },
        );

        let receipt_bytes = controller
            .receive_message(admin.peer_id(), &ciphertext)
            .expect("bound member decrypts channel ciphertext")
            .expect("delivery receipt");
        let receipt = EnvelopeV4::from_bytes(&receipt_bytes).expect("decode receipt");
        let verified = admin_group
            .receive_v4(receipt)
            .expect("receipt is in admin group");
        assert_eq!(verified.metadata.sender, allowed.peer_id());
        assert_eq!(verified.metadata.kind, MessageKind::Receipt);
        assert_eq!(
            verified.metadata.receipt.expect("receipt body").message_id,
            message_id
        );
        assert_eq!(controller.messages.len(), 1);
        assert_eq!(controller.messages[0].channel_id, channel);
        assert_eq!(controller.messages[0].text, secret);
    }

    #[test]
    fn non_default_channel_text_on_the_parent_group_is_rejected() {
        let admin = Identity::generate().expect("admin");
        let member = Identity::generate().expect("parent member");
        let mut admin_parent = MlsConversation::new(&admin).expect("admin parent group");
        let member_package =
            MlsConversation::key_package(&member).expect("member parent key package");
        let (welcome, _commit) = admin_parent
            .add_member_parts(
                member_package.bytes(),
                member.peer_id(),
                &mls_public_key(&member),
            )
            .expect("admin adds parent member");
        let member_parent =
            MlsConversation::join(&member, admin_parent.id(), member_package, &welcome)
                .expect("member joins parent group");

        let channel = [0x75u8; 16];
        let secret = "parent group must not carry this";
        let mut state = ConversationState::new(
            member_parent,
            admin.peer_id(),
            BTreeSet::from([admin.peer_id(), member.peer_id()]),
        );
        state.channels.insert(
            channel,
            ChannelState {
                name: "private".to_owned(),
                creator: admin.peer_id(),
                members: [admin.peer_id(), member.peer_id()].into_iter().collect(),
                revision: 1,
                last_frame_id: None,
            },
        );
        let frame = ChannelFrame::text(channel, 1, secret).expect("channel text frame");
        let parent = admin_parent.id();
        let (envelope, _message_id) = admin_parent
            .compose_v4(
                &admin,
                MessageKind::Channel,
                &frame.to_bytes().expect("frame bytes"),
            )
            .expect("compose parent-group frame");
        let ciphertext = envelope.to_bytes().expect("encode parent-group frame");
        let mut controller =
            MessengerController::start(&member, NetworkConfig::direct()).expect("controller");
        controller.conversations.insert(parent, state);

        let receipt = controller
            .receive_message(admin.peer_id(), &ciphertext)
            .expect("invalid placement is rejected without a transport error");
        assert!(receipt.is_none());
        assert!(controller.last_error.is_some());
        assert!(controller.messages.is_empty());
    }

    #[test]
    fn setup_replay_cache_is_bounded_and_keyed_by_peer_and_digest() {
        let (_, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let other_peer = Identity::generate().expect("other peer");
        let first = 0u64.to_le_bytes();

        assert!(controller.setup_replay.remember(peer.peer_id(), &first));
        assert!(!controller.setup_replay.remember(peer.peer_id(), &first));
        assert!(
            controller
                .setup_replay
                .remember(other_peer.peer_id(), &first),
            "the same bytes from another authenticated peer are a distinct key"
        );
        assert_eq!(controller.setup_replay.seen.len(), 2);

        let second = 1u64.to_le_bytes();
        assert!(controller.setup_replay.remember(peer.peer_id(), &second));
        for value in 2..MAX_SETUP_REPLAY_ENTRIES as u64 {
            assert!(
                controller
                    .setup_replay
                    .remember(peer.peer_id(), &value.to_le_bytes())
            );
        }
        assert!(controller.setup_replay.remember(
            peer.peer_id(),
            &(MAX_SETUP_REPLAY_ENTRIES as u64).to_le_bytes()
        ));
        assert_eq!(controller.setup_replay.seen.len(), MAX_SETUP_REPLAY_ENTRIES);
        assert_eq!(
            controller.setup_replay.order.len(),
            MAX_SETUP_REPLAY_ENTRIES
        );
        assert!(
            controller.setup_replay.remember(peer.peer_id(), &first),
            "the oldest entry must be evicted once the bound is reached"
        );
    }

    #[test]
    fn exact_setup_request_replay_is_ignored_after_verification() {
        let (_, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let bytes = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id: [7u8; 16],
                transaction_id: [8u8; 16],
                accepted: true,
            },
        )
        .to_bytes()
        .expect("encoded setup frame");
        let event = || SetupEvent::RequestReceived {
            response_id: SetupResponseId::new(11),
            peer: swarm_peer(&peer.peer_id()).expect("swarm peer"),
            bytes: bytes.clone(),
        };

        assert!(controller.handle_setup_event(event()).is_err());
        assert!(
            controller.handle_setup_event(event()).is_ok(),
            "an exact replay must not be re-applied or re-reported"
        );
        assert_eq!(controller.setup_replay.seen.len(), 1);
    }

    #[test]
    fn exact_setup_response_replay_is_ignored_after_verification() {
        let (_, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let bytes = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id: [9u8; 16],
                transaction_id: [10u8; 16],
                accepted: false,
            },
        )
        .to_bytes()
        .expect("encoded setup frame");
        let event = || SetupEvent::ResponseReceived {
            request_id: p2p_network::SetupRequestId::new(12),
            peer: swarm_peer(&peer.peer_id()).expect("swarm peer"),
            bytes: bytes.clone(),
        };

        assert!(controller.handle_setup_event(event()).is_err());
        assert!(
            controller.handle_setup_event(event()).is_ok(),
            "an exact response replay must not be re-applied"
        );
        assert_eq!(controller.setup_replay.seen.len(), 1);
    }

    #[test]
    fn durable_control_log_rejects_exact_authenticated_frame_after_reopen() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let peer = Identity::generate().expect("peer");
        let vault = Vault::open(directory.path()).expect("open vault");
        let bytes = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id: [17u8; 16],
                transaction_id: [18u8; 16],
                accepted: true,
            },
        )
        .to_bytes()
        .expect("encoded setup frame");
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let mut session = vault
            .create("controller", "vault-password", &identity)
            .expect("create vault");
        assert_eq!(
            session
                .record_control_frame(&peer.peer_id().to_bytes(), &digest, false)
                .expect("record authenticated frame"),
            ControlRecordOutcome::Appended(1)
        );
        drop(session);

        let storage = vault.unlock("vault-password").expect("reopen vault");
        let mut controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("controller with durable replay log");
        let event = SetupEvent::RequestReceived {
            response_id: SetupResponseId::new(13),
            peer: swarm_peer(&peer.peer_id()).expect("swarm peer"),
            bytes: bytes.clone(),
        };
        assert!(
            controller.handle_setup_event(event).is_ok(),
            "a durable replay is ignored rather than re-applied"
        );
        assert!(
            controller.setup_replay.seen.is_empty(),
            "a durable replay must be rejected before entering the in-memory cache"
        );
        assert!(controller.last_error().is_none());
    }

    #[test]
    fn durable_channel_acks_are_separate_from_parent_group_acks() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, session) = vault_session(directory.path());
        let admin = Identity::generate().expect("admin");
        let conversation_id = [71u8; 16];
        let channel_id = [72u8; 16];
        let transaction_id = [73u8; 16];
        let payload = b"identical-looking MLS commit".to_vec();

        let parent_key = MessengerController::group_request_outcome_key(
            &admin.peer_id(),
            &SetupMessage::GroupCommit {
                conversation_id,
                transaction_id,
                operation: GroupOperation::Update,
                target: None,
                commit: payload.clone(),
            },
        )
        .expect("parent outcome key");
        let channel_key = MessengerController::group_request_outcome_key(
            &admin.peer_id(),
            &SetupMessage::ChannelCommit {
                conversation_id,
                channel_id,
                transaction_id,
                operation: GroupOperation::Update,
                target: None,
                commit: payload,
            },
        )
        .expect("channel outcome key");
        assert_ne!(parent_key, channel_key);

        let ack = SetupMessage::ChannelCommitAck {
            conversation_id,
            channel_id,
            transaction_id,
            operation: GroupOperation::Update,
            accepted: true,
        };
        {
            let mut controller = MessengerController::start_with_control_log(
                &identity,
                NetworkConfig::direct(),
                session,
            )
            .expect("controller with vault");
            controller
                .persist_group_ack(&channel_key, &RequestOutcome::respond(ack.clone()))
                .expect("persist channel ack");
        }

        let storage = vault.unlock("phase4-password").expect("reopen vault");
        let controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restored controller");
        assert_eq!(
            controller
                .durable_group_ack(&channel_key)
                .expect("channel ack"),
            Some(ack)
        );
        assert_eq!(
            controller
                .durable_group_ack(&parent_key)
                .expect("parent ack"),
            None
        );
    }

    #[test]
    fn restored_group_commit_replay_returns_the_original_ack_without_reapplying() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let admin = Identity::generate().expect("admin");
        let conversation_id = [58u8; 16];
        let members = BTreeSet::from([admin.peer_id(), identity.peer_id()]);

        let mut admin_conversation =
            MlsConversation::create(&admin, conversation_id).expect("admin group");
        let key_package = MlsConversation::key_package_with_storage(
            &identity,
            session.try_clone().expect("clone session for key package"),
        )
        .expect("vault-backed recipient key package");
        let welcome = admin_conversation
            .add_member(
                key_package.bytes(),
                identity.peer_id(),
                &mls_public_key(&identity),
            )
            .expect("add recipient");
        let conversation = MlsConversation::join(&identity, conversation_id, key_package, &welcome)
            .expect("recipient joins group");
        let before_epoch = conversation.epoch();
        let commit = admin_conversation
            .self_update_commit()
            .expect("admin update commit");
        let state = ConversationState::new(conversation, admin.peer_id(), members);
        let display_peer =
            MessengerController::display_peer(&state, &identity.peer_id()).expect("display peer");
        let record = PersistedConversation::from_state(
            &state,
            display_peer,
            None,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &VecDeque::new(),
        );
        store_record(&mut session, conversation_id, before_epoch, &record);
        let frame = signed(
            &admin,
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id: [59u8; 16],
                operation: GroupOperation::Update,
                target: None,
                commit,
            },
        );
        let bytes = frame.to_bytes().expect("encoded group commit");
        let outcome_key =
            MessengerController::group_request_outcome_key(&admin.peer_id(), &frame.message)
                .expect("group commit outcome key");

        let mut controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            session.try_clone().expect("controller session"),
        )
        .expect("controller");
        assert!(
            controller
                .durable_control_allows(admin.peer_id(), &bytes, false)
                .expect("first commit passes durable gate"),
            "the first authenticated commit must pass the durable gate"
        );
        let outcome = controller
            .process_setup_request(admin.peer_id(), frame.clone())
            .expect("apply group commit");
        assert!(
            matches!(
                &outcome.response,
                Some(SetupMessage::GroupCommitAck { accepted: true, .. })
            ),
            "the first commit must be acknowledged; last_error={:?}, response={:?}",
            controller.last_error(),
            outcome.response.as_ref().map(|_| "<setup message>")
        );
        let applied_epoch = controller.active_info().expect("active conversation").epoch;
        assert_eq!(applied_epoch, before_epoch + 1);
        drop(controller);
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let mut restored = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restored controller");
        let replay_ack = restored
            .durable_group_ack(&outcome_key)
            .expect("load durable group ack")
            .expect("stored group ack");
        assert!(
            matches!(
                replay_ack,
                SetupMessage::GroupCommitAck { accepted: true, .. }
            ),
            "the original ack must be recoverable after restart"
        );
        assert!(
            restored
                .handle_setup_event(SetupEvent::RequestReceived {
                    response_id: SetupResponseId::new(15),
                    peer: swarm_peer(&admin.peer_id()).expect("swarm peer"),
                    bytes,
                })
                .is_ok(),
            "an exact replay must be answered from the durable outcome"
        );
        assert_eq!(
            restored.active_info().expect("still active").epoch,
            applied_epoch,
            "a replay must not advance the MLS epoch again"
        );
    }

    #[test]
    fn restored_group_welcome_replay_returns_the_original_ack_without_rejoining() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, session) = vault_session(directory.path());
        let admin = Identity::generate().expect("admin");
        let conversation_id = [60u8; 16];
        let transaction_id = [61u8; 16];

        let mut admin_conversation =
            MlsConversation::create(&admin, conversation_id).expect("admin group");
        let key_package = MlsConversation::key_package_with_storage(
            &identity,
            session.try_clone().expect("clone session for key package"),
        )
        .expect("vault-backed group key package");
        let welcome = admin_conversation
            .add_member(
                key_package.bytes(),
                identity.peer_id(),
                &mls_public_key(&identity),
            )
            .expect("create group Welcome");

        let mut controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            session.try_clone().expect("controller session"),
        )
        .expect("controller");
        let response_bytes = signed(
            &admin,
            SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                transaction_id,
                key_package: key_package.bytes().to_vec(),
            },
        )
        .to_bytes()
        .expect("encoded group key package response");
        controller.pending_key_packages.insert(
            (conversation_id, transaction_id),
            PendingKeyPackage {
                peer: admin.peer_id(),
                kind: PendingKeyPackageKind::GroupJoin,
                key_package,
                response_bytes,
            },
        );
        let frame = signed(
            &admin,
            SetupMessage::GroupWelcome {
                conversation_id,
                transaction_id,
                welcome,
            },
        );
        let bytes = frame.to_bytes().expect("encoded group welcome");
        let outcome_key =
            MessengerController::group_request_outcome_key(&admin.peer_id(), &frame.message)
                .expect("group welcome outcome key");
        assert!(
            controller
                .durable_control_allows(admin.peer_id(), &bytes, false)
                .expect("first welcome passes durable gate"),
            "the first authenticated welcome must pass the durable gate"
        );
        let outcome = controller
            .process_setup_request(admin.peer_id(), frame.clone())
            .expect("apply group welcome");
        assert!(
            matches!(
                &outcome.response,
                Some(SetupMessage::GroupWelcomeAck { accepted: true, .. })
            ),
            "the first welcome must be acknowledged; last_error={:?}",
            controller.last_error()
        );
        let applied_epoch = controller.active_info().expect("joined conversation").epoch;
        drop(controller);
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let mut restored = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restored controller");
        let replay_ack = restored
            .durable_group_ack(&outcome_key)
            .expect("load durable group ack")
            .expect("stored group ack");
        assert!(
            matches!(
                replay_ack,
                SetupMessage::GroupWelcomeAck { accepted: true, .. }
            ),
            "the original welcome ack must be recoverable after restart"
        );
        assert!(
            restored
                .handle_setup_event(SetupEvent::RequestReceived {
                    response_id: SetupResponseId::new(16),
                    peer: swarm_peer(&admin.peer_id()).expect("swarm peer"),
                    bytes,
                })
                .is_ok(),
            "an exact welcome replay must be answered from the durable outcome"
        );
        assert_eq!(
            restored.active_info().expect("still active").epoch,
            applied_epoch,
            "a welcome replay must not rejoin or advance the MLS epoch"
        );
    }

    #[test]
    fn durable_control_log_keeps_request_retries_idempotent_after_reopen() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let peer = Identity::generate().expect("peer");
        let vault = Vault::open(directory.path()).expect("open vault");
        let bytes = signed(
            &peer,
            SetupMessage::KeyPackageRequest {
                conversation_id: [19u8; 16],
                transaction_id: [20u8; 16],
            },
        )
        .to_bytes()
        .expect("encoded setup frame");
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let mut session = vault
            .create("controller", "vault-password", &identity)
            .expect("create vault");
        assert_eq!(
            session
                .record_control_frame(&peer.peer_id().to_bytes(), &digest, true)
                .expect("record retryable request"),
            ControlRecordOutcome::Appended(1)
        );
        drop(session);

        let storage = vault.unlock("vault-password").expect("reopen vault");
        let mut controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("controller with durable replay log");
        controller
            .handle_setup_event(SetupEvent::RequestReceived {
                response_id: SetupResponseId::new(14),
                peer: swarm_peer(&peer.peer_id()).expect("swarm peer"),
                bytes,
            })
            .expect("idempotent request retry");

        assert_eq!(controller.pending_key_packages.len(), 1);
        assert_eq!(controller.setup_replay.seen.len(), 1);
    }

    fn vault_session(directory: &Path) -> (Identity, Vault, Session) {
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory).expect("vault");
        let session = vault
            .create("phase4", "phase4-password", &identity)
            .expect("vault session");
        (identity, vault, session)
    }

    #[test]
    fn start_with_control_log_rejects_a_wrong_vault_identity() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (_identity, vault, session) = vault_session(directory.path());
        drop(session);
        let wrong = Identity::generate().expect("wrong identity");
        let storage = vault.unlock("phase4-password").expect("unlock vault");

        let error =
            MessengerController::start_with_control_log(&wrong, NetworkConfig::direct(), storage)
                .expect_err("wrong vault identity must fail startup");
        assert!(matches!(error, ChatError::ControlLogIdentityMismatch));
    }

    #[test]
    fn load_with_storage_rejects_a_wrong_local_identity() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [57u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().expect("clone session"),
        );
        drop(conversation);
        drop(session);
        let wrong = Identity::generate().expect("wrong identity");
        let storage = vault.unlock("phase4-password").expect("unlock vault");

        let error = MlsConversation::load_with_storage(&wrong, conversation_id, storage)
            .expect_err("wrong local identity must not restore the group");
        assert!(matches!(error, GroupError::WrongLocalIdentity));
    }

    fn group_with_peer(
        identity: &Identity,
        peer: &Identity,
        conversation_id: [u8; 16],
        storage: Session,
    ) -> MlsConversation {
        let mut conversation =
            MlsConversation::create_with_storage(identity, conversation_id, storage)
                .expect("vault-backed MLS group");
        let key_package = MlsConversation::key_package(peer).expect("peer key package");
        let public_key = mls_public_key(peer);
        conversation
            .add_member(key_package.bytes(), peer.peer_id(), &public_key)
            .expect("add peer to MLS group");
        conversation
    }

    fn persist_state(
        identity: &Identity,
        session: &mut Session,
        conversation_id: [u8; 16],
        state: ConversationState,
        active_channel: Option<[u8; 16]>,
    ) {
        let peer =
            MessengerController::display_peer(&state, &identity.peer_id()).expect("display peer");
        let pending_receipts: HashMap<[u8; 16], BTreeSet<PeerId>> = HashMap::new();
        let message_conversations: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        let message_channel_routes: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
        let offline_queue: VecDeque<QueuedMessage> = VecDeque::new();
        let record = PersistedConversation::from_state(
            &state,
            peer,
            active_channel,
            &pending_receipts,
            &message_conversations,
            &message_channel_routes,
            &offline_queue,
        );
        let bytes = serde_json::to_vec(&record).expect("encode conversation policy");
        session
            .store_mls_state(
                &conversation_id,
                PERSISTED_CONVERSATION_LABEL,
                PERSISTED_CONVERSATION_LABEL.as_bytes(),
                state.conversation.epoch(),
                &bytes,
            )
            .expect("store conversation policy");
    }

    fn store_record(
        session: &mut Session,
        conversation_id: [u8; 16],
        epoch: u64,
        record: &PersistedConversation,
    ) {
        let bytes = serde_json::to_vec(record).expect("encode conversation policy");
        session
            .store_mls_state(
                &conversation_id,
                PERSISTED_CONVERSATION_LABEL,
                PERSISTED_CONVERSATION_LABEL.as_bytes(),
                epoch,
                &bytes,
            )
            .expect("store conversation policy");
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_full_state(
        identity: &Identity,
        session: &mut Session,
        conversation_id: [u8; 16],
        state: &ConversationState,
        active_channel: Option<[u8; 16]>,
        pending_receipts: &HashMap<[u8; 16], BTreeSet<PeerId>>,
        message_conversations: &HashMap<[u8; 16], [u8; 16]>,
        message_channel_routes: &HashMap<[u8; 16], [u8; 16]>,
        offline_queue: &VecDeque<QueuedMessage>,
    ) {
        let peer =
            MessengerController::display_peer(state, &identity.peer_id()).expect("display peer");
        let record = PersistedConversation::from_state(
            state,
            peer,
            active_channel,
            pending_receipts,
            message_conversations,
            message_channel_routes,
            offline_queue,
        );
        store_record(
            session,
            conversation_id,
            state.conversation.epoch(),
            &record,
        );
    }

    fn queued_message(
        identity: &Identity,
        state: &mut ConversationState,
        peer: PeerId,
        secret: &str,
    ) -> QueuedMessage {
        let conversation_id = state.conversation.id();
        let (envelope, message_id) = state
            .conversation
            .compose_v4(identity, MessageKind::Channel, secret.as_bytes())
            .expect("compose queued frame");
        state
            .conversation
            .mark_queued(&message_id)
            .expect("mark queued");
        QueuedMessage {
            peer,
            conversation_id,
            channel_id: DEFAULT_CHANNEL_ID,
            message_id,
            envelope_bytes: envelope.to_bytes().expect("encode queued envelope"),
        }
    }

    fn assert_restore_fails_with_record_mutation(
        mutate: impl FnOnce(&mut PersistedConversation),
    ) -> Result<(), ChatError> {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [61u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        let epoch = state.conversation.epoch();
        persist_state(&identity, &mut session, conversation_id, state, None);
        let bytes = session
            .load_mls_state(
                &conversation_id,
                PERSISTED_CONVERSATION_LABEL,
                PERSISTED_CONVERSATION_LABEL.as_bytes(),
            )?
            .expect("persisted record");
        let mut record = PersistedConversation::decode(&bytes)?;
        mutate(&mut record);
        store_record(&mut session, conversation_id, epoch, &record);
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        MessengerController::start_with_control_log(&identity, NetworkConfig::direct(), storage)
            .map(|_| ())
    }

    #[test]
    fn joined_conversation_and_channel_policy_restore_after_restart() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [41u8; 16];
        let channel_id = [42u8; 16];
        let members = BTreeSet::from([identity.peer_id(), peer.peer_id()]);
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let mut state = ConversationState::new(conversation, identity.peer_id(), members);
        state.channels.insert(
            channel_id,
            ChannelState {
                name: "room".to_owned(),
                creator: identity.peer_id(),
                members: state.members.clone(),
                revision: 3,
                last_frame_id: None,
            },
        );
        persist_state(
            &identity,
            &mut session,
            conversation_id,
            state,
            Some(channel_id),
        );
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restore controller");
        let infos = controller.conversation_infos();
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert_eq!(info.conversation_id, conversation_id);
        assert_eq!(info.status, ConversationStatus::Joined);
        assert_eq!(info.admin, identity.peer_id());
        assert_eq!(
            info.members,
            vec![identity.peer_id(), peer.peer_id()]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(info.channels.len(), 2);
        let restored_channel = info
            .channels
            .iter()
            .find(|channel| channel.channel_id == channel_id)
            .expect("restored channel");
        assert_eq!(restored_channel.name, "room");
        assert_eq!(restored_channel.revision, 3);
        assert_eq!(restored_channel.members.len(), 2);
        assert_eq!(info.active_channel, Some(channel_id));
    }

    #[test]
    fn restart_fails_when_joined_metadata_is_missing() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [43u8; 16];
        let _conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        assert!(matches!(
            MessengerController::start_with_control_log(
                &identity,
                NetworkConfig::direct(),
                storage
            ),
            Err(ChatError::MlsRestore(_))
        ));
    }

    #[test]
    fn restart_fails_when_restored_membership_disagrees_with_mls_state() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let outsider = Identity::generate().expect("outsider");
        let conversation_id = [44u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let members = BTreeSet::from([identity.peer_id(), peer.peer_id(), outsider.peer_id()]);
        let state = ConversationState::new(conversation, identity.peer_id(), members);
        persist_state(&identity, &mut session, conversation_id, state, None);
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        assert!(matches!(
            MessengerController::start_with_control_log(
                &identity,
                NetworkConfig::direct(),
                storage
            ),
            Err(ChatError::MlsRestore(_))
        ));
    }

    #[test]
    fn pending_group_operation_restores_after_restart() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [45u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let mut state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        state.pending_operation = Some(PendingOperation {
            transaction_id: [46u8; 16],
            operation: GroupOperation::Add,
            target: Some(peer.peer_id()),
            commit: vec![1, 2, 3],
            awaited: BTreeMap::new(),
            welcome_target: Some(peer.peer_id()),
            welcome: Some(vec![4, 5, 6]),
            welcome_acked: false,
        });
        persist_state(&identity, &mut session, conversation_id, state, None);
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restore controller");
        let info = controller
            .info(conversation_id)
            .expect("restored conversation");
        assert_eq!(info.pending_operation, Some(GroupOperation::Add));
        let restored = controller
            .conversations
            .get(&conversation_id)
            .expect("restored state");
        let operation = restored
            .pending_operation
            .as_ref()
            .expect("pending operation");
        assert_eq!(operation.transaction_id, [46u8; 16]);
        assert_eq!(operation.target, Some(peer.peer_id()));
        assert_eq!(operation.welcome_target, Some(peer.peer_id()));
        assert!(!operation.welcome_acked);
    }

    #[test]
    fn pruning_a_removed_peer_drops_only_that_peers_pending_state() {
        let (_, mut controller) = test_controller();
        let conversation_id = [63u8; 16];
        let other_conversation = [64u8; 16];
        let removed = Identity::generate().expect("removed").peer_id();
        let kept = Identity::generate().expect("kept").peer_id();
        let removed_only_message = [65u8; 16];
        let shared_message = [66u8; 16];
        let other_message = [67u8; 16];

        controller
            .message_conversations
            .insert(removed_only_message, conversation_id);
        controller
            .message_conversations
            .insert(shared_message, conversation_id);
        controller
            .message_conversations
            .insert(other_message, other_conversation);
        controller
            .pending_receipts
            .insert(removed_only_message, BTreeSet::from([removed]));
        controller
            .pending_receipts
            .insert(shared_message, BTreeSet::from([removed, kept]));
        controller
            .pending_receipts
            .insert(other_message, BTreeSet::from([removed]));
        controller.offline_queue.push_back(QueuedMessage {
            peer: removed,
            conversation_id,
            channel_id: DEFAULT_CHANNEL_ID,
            message_id: removed_only_message,
            envelope_bytes: vec![1],
        });
        controller.offline_queue.push_back(QueuedMessage {
            peer: kept,
            conversation_id,
            channel_id: DEFAULT_CHANNEL_ID,
            message_id: shared_message,
            envelope_bytes: vec![2],
        });

        controller.prune_removed_peer_state(conversation_id, &removed);

        assert!(
            !controller
                .pending_receipts
                .contains_key(&removed_only_message)
        );
        assert!(
            !controller
                .message_conversations
                .contains_key(&removed_only_message)
        );
        assert_eq!(
            controller.pending_receipts.get(&shared_message),
            Some(&BTreeSet::from([kept]))
        );
        assert_eq!(
            controller.pending_receipts.get(&other_message),
            Some(&BTreeSet::from([removed]))
        );
        assert_eq!(
            controller.message_conversations.get(&other_message),
            Some(&other_conversation)
        );
        assert_eq!(controller.offline_queue.len(), 1);
        assert_eq!(controller.offline_queue[0].peer, kept);
    }

    #[test]
    fn receipt_expectations_and_channel_pending_state_restore_after_restart() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [62u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let mut state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        let (_envelope, message_id) = state
            .conversation
            .compose_v4(&identity, MessageKind::Channel, b"ciphertext")
            .expect("compose outgoing frame");
        state
            .conversation
            .mark_sent_to_peer(&message_id)
            .expect("mark sent to peer");
        state
            .channels
            .get_mut(&DEFAULT_CHANNEL_ID)
            .expect("default channel")
            .last_frame_id = Some(message_id);
        let mut pending_receipts = HashMap::new();
        pending_receipts.insert(message_id, BTreeSet::from([peer.peer_id()]));
        let mut message_conversations = HashMap::new();
        message_conversations.insert(message_id, conversation_id);
        persist_full_state(
            &identity,
            &mut session,
            conversation_id,
            &state,
            None,
            &pending_receipts,
            &message_conversations,
            &HashMap::new(),
            &VecDeque::new(),
        );
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restore controller");
        assert_eq!(
            controller.pending_receipts.get(&message_id),
            Some(&BTreeSet::from([peer.peer_id()]))
        );
        let restored = controller
            .conversations
            .get(&conversation_id)
            .expect("restored state");
        assert_eq!(
            restored.conversation.delivery_state(&message_id),
            Some(DeliveryState::SentToPeer)
        );
        assert_ne!(
            restored.conversation.delivery_state(&message_id),
            Some(DeliveryState::Delivered)
        );
        let info = controller.info(conversation_id).expect("conversation info");
        let default_channel = info
            .channels
            .iter()
            .find(|channel| channel.channel_id == DEFAULT_CHANNEL_ID)
            .expect("default channel");
        assert!(!default_channel.policy_acknowledged);
        assert_eq!(
            default_channel.group_status,
            ChannelGroupStatus::DefaultOnParent
        );
    }

    #[test]
    fn queued_ciphertext_restores_without_persisting_plaintext() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [63u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let mut state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        let secret = "PENDING_QUEUE_SENTINEL_88";
        let queued = queued_message(&identity, &mut state, peer.peer_id(), secret);
        let message_id = queued.message_id;
        let mut pending_receipts = HashMap::new();
        pending_receipts.insert(message_id, BTreeSet::from([peer.peer_id()]));
        let mut message_conversations = HashMap::new();
        message_conversations.insert(message_id, conversation_id);
        let mut offline_queue = VecDeque::new();
        offline_queue.push_back(queued);
        persist_full_state(
            &identity,
            &mut session,
            conversation_id,
            &state,
            None,
            &pending_receipts,
            &message_conversations,
            &HashMap::new(),
            &offline_queue,
        );
        drop(session);

        for name in ["profile.db", "profile.db-wal", "profile.db-shm"] {
            let bytes = std::fs::read(directory.path().join(name)).unwrap_or_default();
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "{name} contains queued plaintext"
            );
        }

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        let controller = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect("restore controller");
        assert_eq!(controller.queued_count(&peer.peer_id()), 1);
        assert_eq!(
            controller.pending_receipts.get(&message_id),
            Some(&BTreeSet::from([peer.peer_id()]))
        );
        let restored = controller
            .conversations
            .get(&conversation_id)
            .expect("restored state");
        assert_eq!(
            restored.conversation.delivery_state(&message_id),
            Some(DeliveryState::Queued)
        );
        assert!(!format!("{controller:?}").contains(secret));
    }

    #[test]
    fn restore_fails_when_record_epoch_disagrees_with_mls_state() {
        let result = assert_restore_fails_with_record_mutation(|record| {
            let epoch = record.epoch.expect("v2 epoch");
            record.epoch = Some(epoch.saturating_add(1));
        });
        assert!(matches!(result, Err(ChatError::MlsRestore(_))));
    }

    #[test]
    fn restore_fails_when_record_group_id_is_tampered() {
        let result = assert_restore_fails_with_record_mutation(|record| {
            record.conversation_id = [99u8; 16];
        });
        assert!(matches!(result, Err(ChatError::MlsRestore(_))));
    }

    #[test]
    fn restore_fails_when_record_peer_is_tampered() {
        let result = assert_restore_fails_with_record_mutation(|record| {
            record.peer = Identity::generate()
                .expect("outsider")
                .peer_id()
                .to_bytes()
                .to_vec();
        });
        assert!(matches!(result, Err(ChatError::MlsRestore(_))));
    }

    #[test]
    fn restore_fails_when_pending_operation_target_is_inconsistent() {
        let result = assert_restore_fails_with_record_mutation(|record| {
            let outsider = Identity::generate().expect("outsider");
            record.pending_operation = PersistedPendingOperation::Detail(PersistedPendingDetail {
                transaction_id: [64u8; 16],
                operation: GroupOperation::Add.code(),
                target: Some(outsider.peer_id().to_bytes().to_vec()),
                commit: vec![1, 2, 3],
                awaited: Vec::new(),
                welcome_target: Some(outsider.peer_id().to_bytes().to_vec()),
                welcome: Some(vec![4, 5, 6]),
                welcome_acked: false,
            });
        });
        assert!(matches!(result, Err(ChatError::MlsRestore(_))));
    }

    #[test]
    fn restore_fails_when_v1_record_had_a_pending_operation() {
        let result = assert_restore_fails_with_record_mutation(|record| {
            record.version = PERSISTED_CONVERSATION_V1;
            record.epoch = None;
            record.pending_operation = PersistedPendingOperation::Flag(true);
            record.outgoing.clear();
            record.receipts.clear();
            record.queued.clear();
        });
        assert!(matches!(result, Err(ChatError::MlsRestore(_))));
    }

    #[test]
    fn restore_fails_when_queued_envelope_signature_is_tampered() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [65u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let mut state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        let mut queued = queued_message(&identity, &mut state, peer.peer_id(), "ciphertext");
        let last = queued.envelope_bytes.len() - 1;
        queued.envelope_bytes[last] ^= 0x01;
        let message_id = queued.message_id;
        let mut pending_receipts = HashMap::new();
        pending_receipts.insert(message_id, BTreeSet::from([peer.peer_id()]));
        let mut message_conversations = HashMap::new();
        message_conversations.insert(message_id, conversation_id);
        let mut offline_queue = VecDeque::new();
        offline_queue.push_back(queued);
        persist_full_state(
            &identity,
            &mut session,
            conversation_id,
            &state,
            None,
            &pending_receipts,
            &message_conversations,
            &HashMap::new(),
            &offline_queue,
        );
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        assert!(matches!(
            MessengerController::start_with_control_log(
                &identity,
                NetworkConfig::direct(),
                storage
            ),
            Err(ChatError::MlsRestore(_))
        ));
    }

    #[test]
    fn restart_fails_when_restored_active_channel_is_unknown() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (identity, vault, mut session) = vault_session(directory.path());
        let peer = Identity::generate().expect("peer");
        let conversation_id = [47u8; 16];
        let conversation = group_with_peer(
            &identity,
            &peer,
            conversation_id,
            session.try_clone().unwrap(),
        );
        let state = ConversationState::new(
            conversation,
            identity.peer_id(),
            BTreeSet::from([identity.peer_id(), peer.peer_id()]),
        );
        persist_state(
            &identity,
            &mut session,
            conversation_id,
            state,
            Some([48u8; 16]),
        );
        drop(session);

        let storage = vault
            .unlock("phase4-password")
            .expect("unlock after restart");
        assert!(matches!(
            MessengerController::start_with_control_log(
                &identity,
                NetworkConfig::direct(),
                storage
            ),
            Err(ChatError::MlsRestore(_))
        ));
    }

    fn joined_state(identity: &Identity, peer: PeerId, admin: PeerId) -> ConversationState {
        let conversation = MlsConversation::new(identity).expect("MLS conversation");
        ConversationState::new(
            conversation,
            admin,
            BTreeSet::from([identity.peer_id(), peer]),
        )
    }

    #[test]
    fn duplicate_key_package_requests_cannot_replace_a_pending_transaction() {
        let (_local, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let other_peer = Identity::generate().expect("other peer");
        let conversation_id = [31u8; 16];
        let first = [32u8; 16];
        let second = [33u8; 16];

        let first_outcome = controller
            .process_setup_request(
                peer.peer_id(),
                signed(
                    &peer,
                    SetupMessage::KeyPackageRequest {
                        conversation_id,
                        transaction_id: first,
                    },
                ),
            )
            .expect("first request");
        let first_key_package = match first_outcome.response.expect("response") {
            SetupMessage::KeyPackageResponse {
                transaction_id,
                key_package,
                ..
            } => {
                assert_eq!(transaction_id, first);
                key_package
            }
            _ => panic!("unexpected response type"),
        };
        assert_eq!(controller.pending_key_packages.len(), 1);
        assert_eq!(
            controller
                .pending_key_packages
                .get(&(conversation_id, first))
                .map(|pending| pending.peer),
            Some(peer.peer_id())
        );

        let conflicting = signed(
            &peer,
            SetupMessage::KeyPackageRequest {
                conversation_id,
                transaction_id: second,
            },
        );
        assert!(matches!(
            controller.process_setup_request(peer.peer_id(), conflicting),
            Err(ChatError::InvalidSetup(_))
        ));
        let from_other_peer = signed(
            &other_peer,
            SetupMessage::KeyPackageRequest {
                conversation_id,
                transaction_id: second,
            },
        );
        assert!(matches!(
            controller.process_setup_request(other_peer.peer_id(), from_other_peer),
            Err(ChatError::InvalidSetup(_))
        ));
        let wrong_kind = signed(
            &peer,
            SetupMessage::GroupJoinRequest {
                conversation_id,
                transaction_id: first,
            },
        );
        assert!(matches!(
            controller.process_setup_request(peer.peer_id(), wrong_kind),
            Err(ChatError::InvalidSetup(_))
        ));
        assert_eq!(controller.pending_key_packages.len(), 1);
        assert!(
            controller
                .pending_key_packages
                .contains_key(&(conversation_id, first))
        );
        assert!(
            !controller
                .pending_key_packages
                .contains_key(&(conversation_id, second))
        );

        let duplicate = signed(
            &peer,
            SetupMessage::KeyPackageRequest {
                conversation_id,
                transaction_id: first,
            },
        );
        let duplicate_outcome = controller
            .process_setup_request(peer.peer_id(), duplicate)
            .expect("idempotent duplicate request");
        match duplicate_outcome.response.expect("response") {
            SetupMessage::KeyPackageResponse {
                transaction_id,
                key_package,
                ..
            } => {
                assert_eq!(transaction_id, first);
                assert_eq!(key_package, first_key_package);
            }
            _ => panic!("unexpected duplicate response type"),
        }
        assert_eq!(controller.pending_key_packages.len(), 1);
        assert_eq!(
            controller
                .pending_key_packages
                .get(&(conversation_id, first))
                .map(|pending| pending.response_bytes.clone()),
            Some(first_key_package)
        );
    }

    #[test]
    fn stale_welcome_acknowledgements_are_rejected() {
        let (identity, mut controller) = test_controller();
        let peer = Identity::generate().expect("peer");
        let conversation_id = [34u8; 16];
        let current = [35u8; 16];
        let stale = [36u8; 16];
        let mut state = joined_state(&identity, peer.peer_id(), identity.peer_id());
        state.status = ConversationStatus::WelcomeSent;
        controller.conversations.insert(conversation_id, state);

        let outgoing = OutgoingSetup {
            conversation_id,
            transaction_id: current,
            kind: OutgoingSetupKind::Welcome,
            scope: None,
        };
        let stale_frame = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id,
                transaction_id: stale,
                accepted: true,
            },
        );
        assert!(matches!(
            controller.process_setup_response(peer.peer_id(), stale_frame, Some(outgoing.clone())),
            Err(ChatError::InvalidSetup(_))
        ));
        assert_eq!(
            controller.conversations[&conversation_id].status,
            ConversationStatus::WelcomeSent
        );

        let wrong_conversation = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id: [37u8; 16],
                transaction_id: current,
                accepted: true,
            },
        );
        assert!(matches!(
            controller.process_setup_response(
                peer.peer_id(),
                wrong_conversation,
                Some(outgoing.clone())
            ),
            Err(ChatError::InvalidSetup(_))
        ));
        assert_eq!(
            controller.conversations[&conversation_id].status,
            ConversationStatus::WelcomeSent
        );

        let valid = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id,
                transaction_id: current,
                accepted: true,
            },
        );
        controller
            .process_setup_response(peer.peer_id(), valid, Some(outgoing))
            .expect("valid welcome ack");
        assert_eq!(
            controller.conversations[&conversation_id].status,
            ConversationStatus::Joined
        );

        let duplicate = signed(
            &peer,
            SetupMessage::WelcomeAck {
                conversation_id,
                transaction_id: current,
                accepted: true,
            },
        );
        assert!(
            controller
                .process_setup_response(peer.peer_id(), duplicate, None)
                .is_err()
        );
        assert_eq!(
            controller.conversations[&conversation_id].status,
            ConversationStatus::Joined
        );
    }

    #[test]
    fn stale_group_commit_and_welcome_acks_are_rejected() {
        let (identity, mut controller) = test_controller();
        let member = Identity::generate().expect("member");
        let conversation_id = [38u8; 16];
        let current = [39u8; 16];
        let stale = [40u8; 16];
        let mut state = joined_state(&identity, member.peer_id(), identity.peer_id());
        state.pending_operation = Some(PendingOperation {
            transaction_id: current,
            operation: GroupOperation::Add,
            target: Some(member.peer_id()),
            commit: vec![1, 2, 3],
            awaited: BTreeMap::from([(member.peer_id(), false)]),
            welcome_target: Some(member.peer_id()),
            welcome: Some(vec![9]),
            welcome_acked: false,
        });
        controller.conversations.insert(conversation_id, state);
        let welcome_request = GroupRequest {
            conversation_id,
            channel_scope: None,
            transaction_id: current,
            peer: member.peer_id(),
            operation: GroupOperation::Add,
            kind: GroupRequestKind::Welcome,
        };
        let commit_request = GroupRequest {
            conversation_id,
            channel_scope: None,
            transaction_id: current,
            peer: member.peer_id(),
            operation: GroupOperation::Add,
            kind: GroupRequestKind::Commit,
        };

        let stale_welcome_ack = signed(
            &member,
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                transaction_id: stale,
                accepted: true,
            },
        );
        assert!(matches!(
            controller.handle_group_ack(
                member.peer_id(),
                stale_welcome_ack.message,
                welcome_request
            ),
            Err(ChatError::InvalidSetup(_))
        ));
        let stale_commit_ack = signed(
            &member,
            SetupMessage::GroupCommitAck {
                conversation_id,
                transaction_id: stale,
                operation: GroupOperation::Add,
                accepted: true,
            },
        );
        assert!(matches!(
            controller.handle_group_ack(member.peer_id(), stale_commit_ack.message, commit_request),
            Err(ChatError::InvalidSetup(_))
        ));
        let cross_conversation = signed(
            &member,
            SetupMessage::GroupCommitAck {
                conversation_id: [41u8; 16],
                transaction_id: current,
                operation: GroupOperation::Add,
                accepted: true,
            },
        );
        assert!(matches!(
            controller.handle_group_ack(
                member.peer_id(),
                cross_conversation.message,
                commit_request
            ),
            Err(ChatError::InvalidSetup(_))
        ));
        let operation = controller.conversations[&conversation_id]
            .pending_operation
            .as_ref()
            .expect("pending operation");
        assert!(!operation.welcome_acked);
        assert_eq!(operation.awaited.get(&member.peer_id()), Some(&false));

        let valid_welcome_ack = signed(
            &member,
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                transaction_id: current,
                accepted: true,
            },
        );
        controller
            .handle_group_ack(member.peer_id(), valid_welcome_ack.message, welcome_request)
            .expect("valid welcome ack");
        let valid_commit_ack = signed(
            &member,
            SetupMessage::GroupCommitAck {
                conversation_id,
                transaction_id: current,
                operation: GroupOperation::Add,
                accepted: true,
            },
        );
        controller
            .handle_group_ack(member.peer_id(), valid_commit_ack.message, commit_request)
            .expect("valid commit ack");
        assert!(
            controller.conversations[&conversation_id]
                .pending_operation
                .is_none()
        );
    }

    #[test]
    fn cross_conversation_and_transaction_substitution_is_rejected() {
        let (identity, mut controller) = test_controller();
        let admin = Identity::generate().expect("admin");
        let conversation_id = [42u8; 16];
        let other_conversation = [43u8; 16];
        let transaction_id = [44u8; 16];
        let other_transaction = [45u8; 16];

        let key_package = MlsConversation::key_package(&identity).expect("key package");
        controller.pending_key_packages.insert(
            (conversation_id, transaction_id),
            PendingKeyPackage {
                peer: admin.peer_id(),
                kind: PendingKeyPackageKind::GroupJoin,
                key_package,
                response_bytes: b"key package bytes".to_vec(),
            },
        );
        let wrong_conversation = signed(
            &admin,
            SetupMessage::GroupWelcome {
                conversation_id: other_conversation,
                transaction_id,
                welcome: b"welcome".to_vec(),
            },
        );
        assert!(matches!(
            controller.process_setup_request(admin.peer_id(), wrong_conversation),
            Err(ChatError::PendingKeyPackageMissing)
        ));
        let wrong_transaction = signed(
            &admin,
            SetupMessage::GroupWelcome {
                conversation_id,
                transaction_id: other_transaction,
                welcome: b"welcome".to_vec(),
            },
        );
        assert!(matches!(
            controller.process_setup_request(admin.peer_id(), wrong_transaction),
            Err(ChatError::PendingKeyPackageMissing)
        ));
        let wrong_welcome_kind = signed(
            &admin,
            SetupMessage::Welcome {
                conversation_id,
                transaction_id,
                welcome: b"welcome".to_vec(),
            },
        );
        assert!(matches!(
            controller.process_setup_request(admin.peer_id(), wrong_welcome_kind),
            Err(ChatError::InvalidSetup(_))
        ));
        assert_eq!(controller.pending_key_packages.len(), 1);
        assert!(
            controller
                .pending_key_packages
                .contains_key(&(conversation_id, transaction_id))
        );

        let mut state = joined_state(&identity, admin.peer_id(), admin.peer_id());
        state.pending_operation = Some(PendingOperation {
            transaction_id,
            operation: GroupOperation::Update,
            target: None,
            commit: vec![1, 2, 3],
            awaited: BTreeMap::from([(admin.peer_id(), false)]),
            welcome_target: None,
            welcome: None,
            welcome_acked: true,
        });
        controller.conversations.insert(conversation_id, state);
        let substituted_commit = signed(
            &admin,
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id: other_transaction,
                operation: GroupOperation::Update,
                target: None,
                commit: b"substituted commit".to_vec(),
            },
        );
        assert!(matches!(
            controller.process_setup_request(admin.peer_id(), substituted_commit),
            Err(ChatError::InvalidSetup(
                "group commit transaction does not match pending operation"
            ))
        ));
        assert!(controller.applied_commits.is_empty());
        let operation = controller.conversations[&conversation_id]
            .pending_operation
            .as_ref()
            .expect("pending operation");
        assert_eq!(operation.transaction_id, transaction_id);
        assert_eq!(operation.awaited.get(&admin.peer_id()), Some(&false));
    }

    /// A vault with one joined parent conversation and one ready derived
    /// channel group, plus one queued ciphertext and its outstanding receipt.
    struct ChannelVaultFixture {
        identity: Identity,
        peer: Identity,
        vault: Vault,
        parent: [u8; 16],
        channel: [u8; 16],
        group_id: [u8; 16],
        message_id: [u8; 16],
        peer_parent: MlsConversation,
        peer_group: MlsChannelGroup,
    }

    fn ready_channel_vault(directory: &Path, secret: &str) -> ChannelVaultFixture {
        let identity = Identity::generate().expect("local identity");
        let peer = Identity::generate().expect("channel peer");
        let vault = Vault::open(directory).expect("vault");
        let session = vault
            .create("phase4", "phase4-password", &identity)
            .expect("vault session");
        let parent = [0x91u8; 16];
        let channel = [0x92u8; 16];
        let binding = ChannelGroupBinding::new(parent, channel);
        let group_id = binding.group_id();

        let mut admin_parent = MlsConversation::create_with_storage(
            &identity,
            parent,
            session.try_clone().expect("clone session"),
        )
        .expect("vault-backed parent group");
        let parent_package = MlsConversation::key_package(&peer).expect("peer parent key package");
        let (parent_welcome, _parent_commit) = admin_parent
            .add_member_parts(
                parent_package.bytes(),
                peer.peer_id(),
                &mls_public_key(&peer),
            )
            .expect("admin adds peer to parent");
        let peer_parent = MlsConversation::join(&peer, parent, parent_package, &parent_welcome)
            .expect("peer joins parent");
        let members = BTreeSet::from([identity.peer_id(), peer.peer_id()]);

        let mut admin_group = MlsChannelGroup::create_with_storage(
            &identity,
            binding,
            session.try_clone().expect("clone session"),
        )
        .expect("vault-backed channel group");
        let channel_package =
            MlsChannelGroup::key_package(&peer, binding).expect("peer channel key package");
        let (welcome, _commit) = admin_group
            .add_member_parts(&channel_package, peer.peer_id(), &mls_public_key(&peer))
            .expect("admin adds peer to channel group");
        let peer_group = MlsChannelGroup::join(&peer, binding, channel_package, &welcome)
            .expect("peer joins channel group");

        let frame = ChannelFrame::text(channel, 1, secret).expect("channel text frame");
        let (envelope, message_id) = admin_group
            .compose_v4(
                &identity,
                MessageKind::Channel,
                &frame.to_bytes().expect("frame bytes"),
            )
            .expect("compose queued channel ciphertext");
        admin_group
            .mark_queued(&message_id)
            .expect("mark queued ciphertext");
        let queued = QueuedMessage {
            peer: peer.peer_id(),
            conversation_id: parent,
            channel_id: channel,
            message_id,
            envelope_bytes: envelope.to_bytes().expect("encode ciphertext"),
        };

        let mut state = ConversationState::new(admin_parent, identity.peer_id(), members.clone());
        state.channels.insert(
            channel,
            ChannelState {
                name: "private".to_owned(),
                creator: identity.peer_id(),
                members,
                revision: 1,
                last_frame_id: None,
            },
        );
        // Use the no-restore constructor because this fixture creates its MLS
        // state before an application record exists. The controller identity
        // must still match the vault identity: `persist_conversation` derives
        // the display peer by excluding the controller's local peer.
        let (_, mut controller) = test_controller();
        controller.identity = identity.clone();
        controller.storage = Some(session.try_clone().expect("clone session"));
        controller.conversations.insert(parent, state);
        controller.channel_groups.insert(
            group_id,
            ChannelGroupState {
                binding,
                group: admin_group,
                awaited: BTreeSet::new(),
                ready: true,
            },
        );
        controller
            .pending_receipts
            .insert(message_id, BTreeSet::from([peer.peer_id()]));
        controller.message_conversations.insert(message_id, parent);
        controller
            .message_channel_routes
            .insert(message_id, channel);
        controller.offline_queue.push_back(queued);
        controller
            .persist_conversation(parent)
            .expect("persist parent and channel records");
        drop(controller);
        drop(session);

        ChannelVaultFixture {
            identity,
            peer,
            vault,
            parent,
            channel,
            group_id,
            message_id,
            peer_parent,
            peer_group,
        }
    }

    fn reopen_vault(vault: &Vault, identity: &Identity) -> Result<MessengerController, ChatError> {
        let storage = vault.unlock("phase4-password")?;
        MessengerController::start_with_control_log(identity, NetworkConfig::direct(), storage)
    }

    /// A vault where MLS state for a derived channel exists but its
    /// authenticated application record was never written. This models a
    /// shutdown during channel setup, before the group became ready.
    fn pending_channel_vault(directory: &Path) -> (Vault, Identity) {
        let identity = Identity::generate().expect("local identity");
        let peer = Identity::generate().expect("channel peer");
        let vault = Vault::open(directory).expect("vault");
        let session = vault
            .create("phase4", "phase4-password", &identity)
            .expect("vault session");
        let parent = [0x97u8; 16];
        let channel = [0x98u8; 16];
        let binding = ChannelGroupBinding::new(parent, channel);

        let mut admin_parent = MlsConversation::create_with_storage(
            &identity,
            parent,
            session.try_clone().expect("clone session"),
        )
        .expect("vault-backed parent group");
        let parent_package = MlsConversation::key_package(&peer).expect("peer parent key package");
        let (parent_welcome, _parent_commit) = admin_parent
            .add_member_parts(
                parent_package.bytes(),
                peer.peer_id(),
                &mls_public_key(&peer),
            )
            .expect("admin adds peer to parent");
        let _peer_parent = MlsConversation::join(&peer, parent, parent_package, &parent_welcome)
            .expect("peer joins parent");

        let mut admin_group = MlsChannelGroup::create_with_storage(
            &identity,
            binding,
            session.try_clone().expect("clone session"),
        )
        .expect("vault-backed channel group");
        let channel_package =
            MlsChannelGroup::key_package(&peer, binding).expect("peer channel key package");
        let (_welcome, _commit) = admin_group
            .add_member_parts(&channel_package, peer.peer_id(), &mls_public_key(&peer))
            .expect("admin adds peer to channel group");

        let members = BTreeSet::from([identity.peer_id(), peer.peer_id()]);
        let mut state = ConversationState::new(admin_parent, identity.peer_id(), members.clone());
        state.channels.insert(
            channel,
            ChannelState {
                name: "private".to_owned(),
                creator: identity.peer_id(),
                members,
                revision: 1,
                last_frame_id: None,
            },
        );
        let (_, mut controller) = test_controller();
        controller.identity = identity.clone();
        controller.storage = Some(session.try_clone().expect("clone session"));
        controller.conversations.insert(parent, state);
        controller
            .persist_conversation(parent)
            .expect("persist parent record only");
        drop(controller);
        drop(session);
        (vault, identity)
    }

    fn mutate_channel_record(
        vault: &Vault,
        group_id: [u8; 16],
        mutate: impl FnOnce(&mut PersistedChannelGroup),
    ) {
        let mut storage = vault.unlock("phase4-password").expect("unlock vault");
        let bytes = storage
            .load_mls_state(
                &group_id,
                PERSISTED_CHANNEL_GROUP_LABEL,
                PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
            )
            .expect("load channel record")
            .expect("channel record exists");
        let mut record = PersistedChannelGroup::decode(&bytes).expect("decode channel record");
        mutate(&mut record);
        let epoch = record.epoch;
        let bytes = serde_json::to_vec(&record).expect("encode channel record");
        storage
            .store_mls_state(
                &group_id,
                PERSISTED_CHANNEL_GROUP_LABEL,
                PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
                epoch,
                &bytes,
            )
            .expect("store mutated channel record");
    }

    fn assert_channel_restore_fails(mutate: impl FnOnce(&mut PersistedChannelGroup)) {
        let directory = tempfile::tempdir().expect("temp dir");
        let fixture = ready_channel_vault(directory.path(), "restore must fail closed");
        mutate_channel_record(&fixture.vault, fixture.group_id, mutate);
        let error = reopen_vault(&fixture.vault, &fixture.identity)
            .expect_err("tampered channel metadata must fail startup");
        assert!(
            matches!(error, ChatError::MlsRestore(_) | ChatError::ControlLog(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn channel_group_and_queued_ciphertext_restore_without_plaintext() {
        let directory = tempfile::tempdir().expect("temp dir");
        let secret = "P1e plaintext must never be persisted";
        let fixture = ready_channel_vault(directory.path(), secret);
        let controller = reopen_vault(&fixture.vault, &fixture.identity).expect("restart restores");

        assert_eq!(controller.conversations.len(), 1);
        let state = controller
            .channel_groups
            .get(&fixture.group_id)
            .expect("derived channel group restored");
        assert!(state.ready);
        assert!(state.awaited.is_empty());
        assert_eq!(state.binding.parent_conversation_id(), fixture.parent);
        assert_eq!(state.binding.channel_id(), fixture.channel);
        assert_eq!(
            state.group.delivery_state(&fixture.message_id),
            Some(DeliveryState::Queued)
        );
        assert!(state.group.next_sequence() > 1);
        assert!(
            controller
                .pending_receipts
                .contains_key(&fixture.message_id)
        );
        assert_eq!(
            controller.message_channel_routes.get(&fixture.message_id),
            Some(&fixture.channel)
        );
        assert_eq!(controller.offline_queue.len(), 1);
        assert_eq!(controller.offline_queue[0].channel_id, fixture.channel);
        assert_eq!(controller.offline_queue[0].message_id, fixture.message_id);
        assert!(controller.messages.is_empty());

        let storage = controller.storage.as_ref().expect("storage is attached");
        for group_id in storage.mls_group_ids().expect("encrypted group ids") {
            for entry in storage
                .load_mls_state_group(&group_id)
                .expect("encrypted group state")
            {
                assert!(
                    !entry
                        .value
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes()),
                    "decrypted text appeared in a persisted record"
                );
            }
        }
    }

    #[test]
    fn restored_channel_group_routes_a_bound_receipt_and_rejects_parent_group_receipt() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut fixture = ready_channel_vault(directory.path(), "receipt routing secret");
        let mut controller = reopen_vault(&fixture.vault, &fixture.identity).expect("restart");
        let swarm_peer = swarm_peer(&fixture.peer.peer_id()).expect("swarm peer id");

        let parent_receipt = fixture
            .peer_parent
            .receipt_v4(&fixture.peer, ReceiptStatus::Delivered, fixture.message_id)
            .expect("peer parent receipt")
            .0
            .to_bytes()
            .expect("encode parent receipt");
        let first_request = controller
            .network
            .send_message(swarm_peer, parent_receipt.clone())
            .expect("track parent receipt request");
        controller
            .outstanding_messages
            .insert(first_request, fixture.message_id);
        assert!(matches!(
            controller.handle_message_response(first_request, swarm_peer, &parent_receipt),
            Err(ChatError::Group(GroupError::Message(MessageError::BadMac)))
        ));
        assert!(
            controller
                .pending_receipts
                .contains_key(&fixture.message_id)
        );

        let channel_receipt = fixture
            .peer_group
            .receipt_v4(&fixture.peer, ReceiptStatus::Delivered, fixture.message_id)
            .expect("peer channel receipt")
            .0
            .to_bytes()
            .expect("encode channel receipt");
        let second_request = controller
            .network
            .send_message(swarm_peer, channel_receipt.clone())
            .expect("track channel receipt request");
        controller
            .outstanding_messages
            .insert(second_request, fixture.message_id);
        controller
            .handle_message_response(second_request, swarm_peer, &channel_receipt)
            .expect("bound channel receipt is accepted after restart");
        assert!(
            !controller
                .pending_receipts
                .contains_key(&fixture.message_id)
        );
        assert_eq!(controller.last_error, None);
    }

    #[test]
    fn tampered_channel_binding_or_policy_fails_startup() {
        assert_channel_restore_fails(|record| {
            record.parent_conversation_id = [0x93u8; 16];
        });
        assert_channel_restore_fails(|record| {
            record.channel_id = [0x94u8; 16];
        });
        assert_channel_restore_fails(|record| {
            record.group_id = [0x95u8; 16];
        });
        assert_channel_restore_fails(|record| {
            record.channel_revision = record.channel_revision.saturating_add(1);
        });
    }

    #[test]
    fn tampered_channel_epoch_membership_or_pending_state_fails_startup() {
        assert_channel_restore_fails(|record| {
            record.epoch = record.epoch.saturating_add(1);
        });
        assert_channel_restore_fails(|record| {
            record.next_sequence = 1;
        });
        assert_channel_restore_fails(|record| {
            record.members.pop();
        });
        assert_channel_restore_fails(|record| {
            record.allowed_members.pop();
        });
        assert_channel_restore_fails(|record| {
            record.ready = false;
        });
        assert_channel_restore_fails(|record| {
            record.awaited.push(record.allowed_members[0].clone());
        });
        assert_channel_restore_fails(|record| {
            record.queued[0].conversation_id = [0x96u8; 16];
        });
        assert_channel_restore_fails(|record| {
            record.receipts[0].peers.clear();
        });
    }

    #[test]
    fn changed_channel_members_delete_persisted_channel_group() {
        let directory = tempfile::tempdir().expect("temp dir");
        let fixture = ready_channel_vault(directory.path(), "policy change deletes group");
        let mut controller = reopen_vault(&fixture.vault, &fixture.identity).expect("restart");
        assert!(controller.channel_groups.contains_key(&fixture.group_id));

        controller
            .set_channel_members(
                fixture.parent,
                fixture.channel,
                vec![fixture.peer.peer_id()],
            )
            .expect("channel policy update");

        assert!(!controller.channel_groups.contains_key(&fixture.group_id));
        assert!(
            !controller
                .storage
                .as_ref()
                .expect("storage is attached")
                .mls_group_ids()
                .expect("encrypted group ids")
                .contains(&fixture.group_id)
        );
        drop(controller);

        let restored = reopen_vault(&fixture.vault, &fixture.identity)
            .expect("restart after channel policy change");
        assert!(restored.channel_groups.is_empty());
        assert!(restored.conversations.contains_key(&fixture.parent));
    }

    #[test]
    fn removed_parent_member_deletes_all_channel_groups() {
        let directory = tempfile::tempdir().expect("temp dir");
        let fixture = ready_channel_vault(directory.path(), "parent removal deletes group");
        let mut controller = reopen_vault(&fixture.vault, &fixture.identity).expect("restart");
        assert!(controller.channel_groups.contains_key(&fixture.group_id));

        controller
            .remove_member(fixture.parent, fixture.peer.peer_id())
            .expect("remove parent member");

        assert!(!controller.channel_groups.contains_key(&fixture.group_id));
        assert!(
            !controller
                .storage
                .as_ref()
                .expect("storage is attached")
                .mls_group_ids()
                .expect("encrypted group ids")
                .contains(&fixture.group_id)
        );
    }

    #[test]
    fn remove_local_conversation_deletes_parent_and_derived_groups() {
        let directory = tempfile::tempdir().expect("temp dir");
        let fixture = ready_channel_vault(directory.path(), "local removal deletes groups");
        let mut controller = reopen_vault(&fixture.vault, &fixture.identity).expect("restart");

        controller.remove_local_conversation(fixture.parent);

        assert!(controller.conversations.is_empty());
        assert!(controller.channel_groups.is_empty());
        let group_ids = controller
            .storage
            .as_ref()
            .expect("storage is attached")
            .mls_group_ids()
            .expect("encrypted group ids");
        assert!(!group_ids.contains(&fixture.parent));
        assert!(!group_ids.contains(&fixture.group_id));
        drop(controller);

        let restored = reopen_vault(&fixture.vault, &fixture.identity)
            .expect("restart after local conversation removal");
        assert!(restored.conversations.is_empty());
        assert!(restored.channel_groups.is_empty());
    }

    #[test]
    fn pending_channel_setup_without_application_record_fails_startup() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (vault, identity) = pending_channel_vault(directory.path());
        let storage = vault.unlock("phase4-password").expect("unlock vault");

        let error = MessengerController::start_with_control_log(
            &identity,
            NetworkConfig::direct(),
            storage,
        )
        .expect_err("an incomplete channel group must not be revived");
        assert!(
            matches!(error, ChatError::MlsRestore(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parent_and_channel_labels_on_one_group_fail_startup() {
        let directory = tempfile::tempdir().expect("temp dir");
        let fixture = ready_channel_vault(directory.path(), "conflicting labels fail startup");
        {
            let mut storage = fixture
                .vault
                .unlock("phase4-password")
                .expect("unlock vault");
            let parent_bytes = storage
                .load_mls_state(
                    &fixture.parent,
                    PERSISTED_CONVERSATION_LABEL,
                    PERSISTED_CONVERSATION_LABEL.as_bytes(),
                )
                .expect("load parent record")
                .expect("parent record exists");
            let channel_bytes = storage
                .load_mls_state(
                    &fixture.group_id,
                    PERSISTED_CHANNEL_GROUP_LABEL,
                    PERSISTED_CHANNEL_GROUP_LABEL.as_bytes(),
                )
                .expect("load channel record")
                .expect("channel record exists");
            let channel = PersistedChannelGroup::decode(&channel_bytes).expect("decode channel");
            storage
                .store_mls_state(
                    &fixture.group_id,
                    PERSISTED_CONVERSATION_LABEL,
                    PERSISTED_CONVERSATION_LABEL.as_bytes(),
                    channel.epoch,
                    &parent_bytes,
                )
                .expect("store conflicting parent label");
        }

        let error = reopen_vault(&fixture.vault, &fixture.identity)
            .expect_err("conflicting labels must fail startup");
        assert!(
            matches!(error, ChatError::MlsRestore(_)),
            "unexpected error: {error}"
        );
    }
}
