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
use p2p_groups::{GroupOperation, MlsConversation, MlsKeyPackage};
use p2p_identity::Identity;
use p2p_messaging::{DeliveryState, Envelope, MessageKind, ReceiptStatus, random_id};
use p2p_network::{
    ConnectionState, FileEvent, FileRequestId, FileResponseId, MessageEvent, MessageRequestId,
    Network, NetworkConfig, NetworkPrivacyStatus, SetupEvent, SetupResponseId,
};
use p2p_security::{ScanRequest, ScanStatus, SecurityConfig};

use crate::channel::{ChannelFrame, ChannelFrameKind, DEFAULT_CHANNEL_ID, MAX_CHANNELS_PER_GROUP};
use crate::{ChatError, SetupEnvelope, SetupMessage};

/// How far a 1:1 MLS setup has progressed. A `Joined` status on the inviter
/// requires a verified WelcomeAck; on the joiner it requires a verified
/// Welcome that OpenMLS accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationStatus {
    KeyPackageRequested,
    KeyPackageReceived,
    WelcomeSent,
    Joined,
    Failed(&'static str),
}

impl ConversationStatus {
    /// Honest, user-facing text. It never claims verification or delivery.
    pub fn description(self) -> &'static str {
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

/// Public snapshot of one channel inside a joined MLS group. Channel membership
/// is local application policy; every MLS group member can still decrypt the
/// ciphertext, so this is never a cryptographic access-control claim.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    pub channel_id: [u8; 16],
    pub name: String,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
    pub revision: u32,
    /// False while a local policy change is waiting for member receipts.
    pub acknowledged: bool,
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
            .field("acknowledged", &self.acknowledged)
            .finish_non_exhaustive()
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

struct PendingKeyPackage {
    peer: PeerId,
    key_package: MlsKeyPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupRequestKind {
    Welcome,
    Commit,
}

#[derive(Debug, Clone, Copy)]
struct GroupRequest {
    conversation_id: [u8; 16],
    peer: PeerId,
    operation: GroupOperation,
    kind: GroupRequestKind,
}

/// One signed MLS ciphertext envelope waiting for a reconnect. The plaintext
/// display text lives only in `ChatMessage`; this queue never copies it.
#[derive(Clone, PartialEq, Eq)]
struct QueuedMessage {
    peer: PeerId,
    conversation_id: [u8; 16],
    message_id: [u8; 16],
    envelope_bytes: Vec<u8>,
}

impl fmt::Debug for QueuedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedMessage")
            .field("peer", &self.peer.to_string())
            .field("conversation_id", &hex(&self.conversation_id))
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

/// Owns the Swarm, MLS sessions, and decrypted view model for the application.
/// Public methods are safe to call from a GUI frame; all blocking libp2p work
/// stays inside the network worker thread.
pub struct MessengerController {
    identity: Identity,
    network: Network,
    conversations: HashMap<[u8; 16], ConversationState>,
    peer_conversations: HashMap<PeerId, [u8; 16]>,
    pending_key_packages: HashMap<[u8; 16], PendingKeyPackage>,
    outstanding_setup: HashMap<p2p_network::SetupRequestId, [u8; 16]>,
    group_requests: HashMap<p2p_network::SetupRequestId, GroupRequest>,
    outstanding_messages: HashMap<MessageRequestId, [u8; 16]>,
    message_conversations: HashMap<[u8; 16], [u8; 16]>,
    pending_receipts: HashMap<[u8; 16], BTreeSet<PeerId>>,
    applied_commits: HashMap<[u8; 16], HashSet<Vec<u8>>>,
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
        let redial_config = RedialConfig::from(&config);
        let network = Network::start(identity, config)?;
        Ok(Self {
            identity: identity.clone(),
            network,
            conversations: HashMap::new(),
            peer_conversations: HashMap::new(),
            pending_key_packages: HashMap::new(),
            outstanding_setup: HashMap::new(),
            group_requests: HashMap::new(),
            outstanding_messages: HashMap::new(),
            message_conversations: HashMap::new(),
            pending_receipts: HashMap::new(),
            applied_commits: HashMap::new(),
            offline_queue: VecDeque::new(),
            redial_config,
            dialed_addresses: HashMap::new(),
            redial: HashMap::new(),
            connected_peers: BTreeSet::new(),
            messages: Vec::new(),
            active: None,
            active_channel: HashMap::new(),
            file_config,
            security_config,
            outgoing_files: HashMap::new(),
            incoming_files: HashMap::new(),
            file_requests: HashMap::new(),
            last_error: None,
        })
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

        let conversation = MlsConversation::new(&self.identity)?;
        let conversation_id = conversation.id();
        self.send_setup(
            &peer,
            SetupMessage::KeyPackageRequest { conversation_id },
            conversation_id,
        )?;
        let members = BTreeSet::from([self.identity.peer_id(), peer]);
        let mut state = ConversationState::new(conversation, self.identity.peer_id(), members);
        state.status = ConversationStatus::KeyPackageRequested;
        self.conversations.insert(conversation_id, state);
        self.peer_conversations.insert(peer, conversation_id);
        self.active = Some(conversation_id);
        self.active_channel
            .insert(conversation_id, DEFAULT_CHANNEL_ID);
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
                state.status,
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
                state.status,
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
        let (frame, recipients) = {
            let state = self
                .conversations
                .get(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                state.status,
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
            channel.members = members.into_iter().collect();
            channel.revision = frame.revision;
            channel.last_frame_id = Some(message_id);
        }
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
            state.status,
            state.pending_operation.is_some(),
        )?;
        if state.members.contains(&peer) {
            return Err(ChatError::AlreadyEstablished);
        }
        self.send_setup(
            &peer,
            SetupMessage::GroupJoinRequest { conversation_id },
            conversation_id,
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
                state.status,
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
                operation: GroupOperation::Remove,
                target: Some(peer),
                commit,
                awaited,
                welcome_target: None,
                welcome: None,
                welcome_acked: true,
            });
        }
        self.dispatch_group_operation(conversation_id)
    }

    /// Refresh the administrator's MLS leaf key with a signed Update commit.
    /// Every other member must acknowledge it before the operation completes.
    pub fn update_member_key(&mut self, conversation_id: [u8; 16]) -> Result<(), ChatError> {
        let local = self.identity.peer_id();
        {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            Self::check_admin(
                state.admin,
                local,
                state.status,
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
                operation: GroupOperation::Update,
                target: None,
                commit,
                awaited,
                welcome_target: None,
                welcome: None,
                welcome_acked: true,
            });
        }
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
        Ok(())
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
            .is_some_and(|transfer| !transfer.status().completed())
            || self
                .incoming_files
                .get(&peer)
                .is_some_and(|transfer| !transfer.status().completed())
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

    /// Cancel a pending or approved in-memory release. This does not delete
    /// quarantine ciphertext and does not cancel the network transfer itself.
    pub fn cancel_file(&mut self, peer: PeerId) -> Result<(), ChatError> {
        let incoming = self
            .incoming_files
            .get_mut(&peer)
            .ok_or(ChatError::FileTransferMissing)?;
        Ok(incoming.cancel()?)
    }

    /// Explicitly delete one incoming transfer's quarantine ciphertext after a
    /// verified transfer has been released or its release was cancelled. This
    /// is denied under the default `Retain` policy and never deletes plaintext
    /// or cancels the network transfer. Filesystem deletion is not secure
    /// erasure on SSD/CoW storage.
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
        while let Some(item) = self.offline_queue.pop_front() {
            if item.peer != *peer {
                remaining.push_back(item);
                continue;
            }
            match self.try_send_queued(&item) {
                Ok(()) => {}
                Err(error) => {
                    remaining.push_back(item);
                    last_error = Some(error);
                }
            }
        }
        self.offline_queue = remaining;
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
            });
        if !ready {
            self.last_error = Some(ChatError::ConversationNotReady.to_string());
            return Ok(());
        }

        let request_id = self
            .network
            .send_message(swarm_peer(&item.peer)?, item.envelope_bytes.clone())?;
        let transition = {
            let Some(state) = self.conversations.get_mut(&item.conversation_id) else {
                let _ = self.outstanding_messages.remove(&request_id);
                return Err(ChatError::UnknownConversation);
            };
            match state.conversation.delivery_state(&item.message_id) {
                Some(DeliveryState::SentToPeer)
                | Some(DeliveryState::Delivered)
                | Some(DeliveryState::Read)
                | Some(DeliveryState::Failed) => Ok(()),
                _ => state.conversation.mark_sent_to_peer(&item.message_id),
            }
        };
        if let Err(error) = transition {
            let _ = self.outstanding_messages.remove(&request_id);
            if let Some(state) = self.conversations.get_mut(&item.conversation_id) {
                let _ = state.conversation.mark_failed(&item.message_id);
            }
            self.set_line_delivery(item.message_id, DeliveryState::Failed);
            self.last_error = Some(error.to_string());
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
                let acknowledged = channel
                    .last_frame_id
                    .is_none_or(|message_id| !self.pending_receipts.contains_key(&message_id));
                ChannelInfo {
                    channel_id: *id,
                    name: channel.name.clone(),
                    creator: channel.creator,
                    members: channel.members.iter().copied().collect(),
                    revision: channel.revision,
                    acknowledged,
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
            status: state.status,
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
        let Ok(swarm_peer) = swarm_peer(peer) else {
            return false;
        };
        matches!(
            self.network.state(),
            ConnectionState::Connected { peers } if peers.contains(&swarm_peer)
        )
    }

    fn set_status(&mut self, conversation_id: [u8; 16], status: ConversationStatus) {
        if let Some(state) = self.conversations.get_mut(&conversation_id) {
            state.status = status;
        }
    }

    fn check_admin(
        admin: PeerId,
        local: PeerId,
        status: ConversationStatus,
        pending: bool,
    ) -> Result<(), ChatError> {
        if admin != local {
            return Err(ChatError::NotAdmin);
        }
        if status != ConversationStatus::Joined {
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
        let (op, target, commit, awaited, welcome_target, welcome) = (
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
                        peer: joiner,
                        operation: GroupOperation::Add,
                        kind: GroupRequestKind::Welcome,
                    };
                    if let Err(error) = self.send_group_request(
                        &joiner,
                        SetupMessage::GroupWelcome {
                            conversation_id,
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
                peer,
                operation: op,
                kind: GroupRequestKind::Commit,
            };
            if let Err(error) = self.send_group_request(
                &peer,
                SetupMessage::GroupCommit {
                    conversation_id,
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
                    operation.operation,
                    operation.target,
                    operation.commit.clone(),
                    operation.awaited.get(peer).copied(),
                    operation.welcome_target,
                    operation.welcome.clone(),
                    operation.welcome_acked,
                )
            };
            let (op, target, commit, awaited, welcome_target, welcome, welcome_acked) = snapshot;
            if welcome_target == Some(*peer)
                && !welcome_acked
                && let Some(welcome) = welcome
            {
                let request = GroupRequest {
                    conversation_id,
                    peer: *peer,
                    operation: GroupOperation::Add,
                    kind: GroupRequestKind::Welcome,
                };
                if let Err(error) = self.send_group_request(
                    peer,
                    SetupMessage::GroupWelcome {
                        conversation_id,
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
                    peer: *peer,
                    operation: op,
                    kind: GroupRequestKind::Commit,
                };
                if let Err(error) = self.send_group_request(
                    peer,
                    SetupMessage::GroupCommit {
                        conversation_id,
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

    fn finish_operation_if_ready(&mut self, conversation_id: [u8; 16]) {
        let ready = self
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pending_operation.as_ref())
            .is_some_and(|operation| {
                operation.welcome_acked && operation.awaited.values().all(|acked| *acked)
            });
        if ready && let Some(state) = self.conversations.get_mut(&conversation_id) {
            state.pending_operation = None;
        }
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

    fn remove_local_conversation(&mut self, conversation_id: [u8; 16]) {
        self.conversations.remove(&conversation_id);
        self.pending_key_packages.remove(&conversation_id);
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
            self.pending_receipts.remove(&message_id);
        }
        if self.active == Some(conversation_id) {
            self.active = None;
        }
    }

    fn send_setup(
        &mut self,
        peer: &PeerId,
        message: SetupMessage,
        conversation_id: [u8; 16],
    ) -> Result<(), ChatError> {
        let frame = SetupEnvelope::new(&self.identity, message)?;
        let request_id = self
            .network
            .send_setup(swarm_peer(peer)?, frame.to_bytes()?)?;
        self.outstanding_setup.insert(request_id, conversation_id);
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
        frame.verify(&peer)?;
        Ok((peer, frame))
    }

    fn handle_setup_event(&mut self, event: SetupEvent) -> Result<(), ChatError> {
        match event {
            SetupEvent::RequestReceived {
                response_id,
                peer,
                bytes,
            } => {
                let (peer, frame) = Self::decode_setup(peer, &bytes)?;
                self.handle_setup_request(response_id, peer, frame)
            }
            SetupEvent::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => {
                let group_request = self.group_requests.remove(&request_id);
                self.outstanding_setup.remove(&request_id);
                let (peer, frame) = Self::decode_setup(peer, &bytes)?;
                if let Some(request) = group_request {
                    return self.handle_group_ack(peer, frame.message, request);
                }
                self.handle_setup_response(peer, frame)
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
                    } else if let Some(conversation_id) = self.outstanding_setup.remove(&request_id)
                    {
                        self.set_status(
                            conversation_id,
                            ConversationStatus::Failed("setup request failed"),
                        );
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
        let public_key = frame.sender_public_key;
        match frame.message {
            SetupMessage::KeyPackageRequest { conversation_id } => {
                // A 1:1 invitation is for a conversation the responder does not
                // have yet. The signed frame still binds the requester, and the
                // inviter validates the returned KeyPackage before adding it.
                if self.conversations.contains_key(&conversation_id) {
                    return Err(ChatError::AlreadyEstablished);
                }
                let key_package = MlsConversation::key_package(&self.identity)?;
                let bytes = key_package.bytes().to_vec();
                self.pending_key_packages
                    .insert(conversation_id, PendingKeyPackage { peer, key_package });
                self.respond_setup(
                    response_id,
                    SetupMessage::KeyPackageResponse {
                        conversation_id,
                        key_package: bytes,
                    },
                )
            }
            SetupMessage::Welcome {
                conversation_id,
                welcome,
            } => self.join_from_welcome(response_id, peer, conversation_id, welcome, false),
            SetupMessage::GroupJoinRequest { conversation_id } => {
                // The invitee does not have the group yet. The signed frame
                // binds the inviting peer; the admin validates this KeyPackage
                // before creating the Welcome and epoch-changing commit.
                if self.conversations.contains_key(&conversation_id) {
                    return Err(ChatError::AlreadyEstablished);
                }
                let key_package = MlsConversation::key_package(&self.identity)?;
                let bytes = key_package.bytes().to_vec();
                self.pending_key_packages
                    .insert(conversation_id, PendingKeyPackage { peer, key_package });
                self.respond_setup(
                    response_id,
                    SetupMessage::GroupKeyPackageResponse {
                        conversation_id,
                        key_package: bytes,
                    },
                )
            }
            SetupMessage::GroupWelcome {
                conversation_id,
                welcome,
            } => self.join_from_welcome(response_id, peer, conversation_id, welcome, true),
            SetupMessage::GroupCommit {
                conversation_id,
                operation,
                target,
                commit,
            } => {
                let (accepted, self_removed, refresh_members) = {
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
                        (true, false, false)
                    } else {
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
                                    (true, true, false)
                                } else {
                                    let members = state.conversation.members()?;
                                    state.members = members.into_iter().collect();
                                    state.sync_default_channel();
                                    state.prune_removed_members();
                                    (true, false, true)
                                }
                            }
                            Err(error) => {
                                self.last_error = Some(error.to_string());
                                (false, false, false)
                            }
                        }
                    }
                };
                if self_removed {
                    self.remove_local_conversation(conversation_id);
                } else if refresh_members {
                    let local = self.identity.peer_id();
                    self.refresh_peer_conversations(conversation_id, &local);
                }
                self.respond_setup(
                    response_id,
                    SetupMessage::GroupCommitAck {
                        conversation_id,
                        operation,
                        accepted,
                    },
                )?;
                if accepted {
                    Ok(())
                } else {
                    Err(ChatError::GroupOperationRejected)
                }
            }
            _ => Err(ChatError::InvalidSetup("unexpected setup request type")),
        }
    }

    fn join_from_welcome(
        &mut self,
        response_id: SetupResponseId,
        peer: PeerId,
        conversation_id: [u8; 16],
        welcome: Vec<u8>,
        group_control: bool,
    ) -> Result<(), ChatError> {
        if self.conversations.contains_key(&conversation_id) {
            return Err(ChatError::AlreadyEstablished);
        }
        let pending = self
            .pending_key_packages
            .remove(&conversation_id)
            .ok_or(ChatError::PendingKeyPackageMissing)?;
        if pending.peer != peer {
            return Err(ChatError::UnexpectedSender);
        }
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
                let ack = if group_control {
                    SetupMessage::GroupWelcomeAck {
                        conversation_id,
                        accepted: true,
                    }
                } else {
                    SetupMessage::WelcomeAck {
                        conversation_id,
                        accepted: true,
                    }
                };
                self.respond_setup(response_id, ack)
            }
            Err(error) => {
                let ack = if group_control {
                    SetupMessage::GroupWelcomeAck {
                        conversation_id,
                        accepted: false,
                    }
                } else {
                    SetupMessage::WelcomeAck {
                        conversation_id,
                        accepted: false,
                    }
                };
                let _ = self.respond_setup(response_id, ack);
                self.last_error = Some(error.to_string());
                Ok(())
            }
        }
    }

    fn handle_setup_response(
        &mut self,
        peer: PeerId,
        frame: SetupEnvelope,
    ) -> Result<(), ChatError> {
        let public_key = frame.sender_public_key;
        match frame.message {
            SetupMessage::KeyPackageResponse {
                conversation_id,
                key_package,
            } => {
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
                self.send_setup(
                    &peer,
                    SetupMessage::Welcome {
                        conversation_id,
                        welcome,
                    },
                    conversation_id,
                )
            }
            SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                key_package,
            } => {
                let local = self.identity.peer_id();
                {
                    let state = self
                        .conversations
                        .get_mut(&conversation_id)
                        .ok_or(ChatError::UnknownConversation)?;
                    Self::check_admin(
                        state.admin,
                        local,
                        state.status,
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
                        operation: GroupOperation::Add,
                        target: Some(peer),
                        commit,
                        awaited,
                        welcome_target: Some(peer),
                        welcome: Some(welcome),
                        welcome_acked: false,
                    });
                }
                self.refresh_peer_conversations(conversation_id, &local);
                self.dispatch_group_operation(conversation_id)
            }
            SetupMessage::WelcomeAck {
                conversation_id,
                accepted,
            } => {
                let state = self
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                if !state.members.contains(&peer) {
                    return Err(ChatError::UnexpectedSender);
                }
                // A late or duplicate acknowledgement must not overwrite a
                // terminal setup result.
                if state.status != ConversationStatus::WelcomeSent {
                    return Err(ChatError::InvalidSetup(
                        "unexpected welcome acknowledgement",
                    ));
                }
                state.status = if accepted {
                    ConversationStatus::Joined
                } else {
                    ConversationStatus::Failed("setup rejected by peer")
                };
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
        match (message, request.kind) {
            (
                SetupMessage::GroupWelcomeAck {
                    conversation_id: ack_id,
                    accepted,
                },
                GroupRequestKind::Welcome,
            ) => {
                if ack_id != conversation_id || request.operation != GroupOperation::Add {
                    return Err(ChatError::InvalidSetup(
                        "unexpected group Welcome acknowledgement",
                    ));
                }
                if !accepted {
                    self.last_error = Some("group Welcome was rejected".to_owned());
                    return Ok(());
                }
                let state = self
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                let Some(operation) = state.pending_operation.as_mut() else {
                    return Err(ChatError::InvalidSetup("no group operation is pending"));
                };
                operation.welcome_acked = true;
                self.finish_operation_if_ready(conversation_id);
                Ok(())
            }
            (
                SetupMessage::GroupCommitAck {
                    conversation_id: ack_id,
                    operation: acked_operation,
                    accepted,
                },
                GroupRequestKind::Commit,
            ) => {
                if ack_id != conversation_id || acked_operation != request.operation {
                    return Err(ChatError::InvalidSetup(
                        "unexpected group commit acknowledgement",
                    ));
                }
                if !accepted {
                    self.last_error = Some("group commit was rejected by a member".to_owned());
                    return Err(ChatError::GroupOperationRejected);
                }
                let state = self
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or(ChatError::UnknownConversation)?;
                let Some(operation) = state.pending_operation.as_mut() else {
                    return Err(ChatError::InvalidSetup("no group operation is pending"));
                };
                let awaited = operation
                    .awaited
                    .get_mut(&peer)
                    .ok_or(ChatError::UnexpectedSender)?;
                *awaited = true;
                self.finish_operation_if_ready(conversation_id);
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
                    .is_some_and(|transfer| !transfer.status().completed())
                    || self
                        .outgoing_files
                        .get(&peer)
                        .is_some_and(|transfer| !transfer.status().completed())
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
                Ok(())
            }
            FileMessage::Chunk { index, .. } => {
                let (accepted, error) = match self.incoming_files.get_mut(&peer) {
                    Some(incoming) if *incoming.transfer_id() == transfer_id => {
                        match incoming.accept_chunk(&frame) {
                            Ok(()) => (true, None),
                            Err(p2p_files::FileError::DuplicateChunk) => (true, None),
                            Err(error) => {
                                incoming.mark_failed("Incoming chunk failed");
                                (false, Some(error.to_string()))
                            }
                        }
                    }
                    _ => (false, Some("untracked file chunk".to_owned())),
                };
                self.respond_file(
                    response_id,
                    FileMessage::ChunkAck {
                        transfer_id,
                        index: *index,
                        accepted,
                    },
                )?;
                if let Some(error) = error {
                    self.last_error = Some(error);
                }
                Ok(())
            }
            FileMessage::Manifest { .. } => {
                let (accepted, error) = match self.incoming_files.get_mut(&peer) {
                    Some(incoming) if *incoming.transfer_id() == transfer_id => {
                        match incoming.verify_manifest(&frame) {
                            Ok(_) => (true, None),
                            Err(error) => (false, Some(error.to_string())),
                        }
                    }
                    _ => (false, Some("untracked file manifest".to_owned())),
                };
                self.respond_file(
                    response_id,
                    FileMessage::ManifestAck {
                        transfer_id,
                        accepted,
                    },
                )?;
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
        if let Some(conversation_id) = self.message_conversations.get(&message_id).copied()
            && let Some(state) = self.conversations.get_mut(&conversation_id)
        {
            match delivery {
                DeliveryState::SentToPeer => {
                    if state.conversation.delivery_state(&message_id)
                        != Some(DeliveryState::SentToPeer)
                    {
                        state.conversation.mark_sent_to_peer(&message_id)?;
                    }
                }
                DeliveryState::Failed => state.conversation.mark_failed(&message_id)?,
                _ => return Err(ChatError::InvalidSetup("invalid outgoing transition")),
            }
        }
        self.set_line_delivery(message_id, delivery);
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
        let (message_id, envelope_bytes) = {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if state.status != ConversationStatus::Joined {
                return Err(ChatError::ConversationNotReady);
            }
            if state.pending_operation.is_some() {
                return Err(ChatError::GroupOperationPending);
            }
            let envelope =
                state
                    .conversation
                    .compose(&self.identity, MessageKind::Channel, &body)?;
            (envelope.message_id, envelope.to_bytes()?)
        };

        let has_offline = recipients
            .iter()
            .any(|recipient| !self.is_connected(recipient));
        if has_offline {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            state.conversation.mark_queued(&message_id)?;
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
                    message_id,
                    envelope_bytes: envelope_bytes.clone(),
                });
            }
        }
        if let Some(error) = sent_error {
            if let Some(state) = self.conversations.get_mut(&conversation_id) {
                let _ = state.conversation.mark_failed(&message_id);
            }
            return Err(error);
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
        Ok(message_id)
    }

    fn handle_message_request(
        &mut self,
        response_id: p2p_network::MessageResponseId,
        swarm_peer: SwarmPeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let peer = identity_peer(swarm_peer)?;
        let envelope = Envelope::from_bytes(bytes)?;
        let conversation_id = envelope.conversation_id;
        let kind = envelope.kind;

        let (message_id, plaintext, receipt_bytes, channel_text, apply_error) = {
            let state = self
                .conversations
                .get_mut(&conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if !state.members.contains(&peer) {
                return Err(ChatError::NotGroupMember);
            }
            let received = state.conversation.receive(envelope)?;
            let message_id = received.metadata.message_id;
            let plaintext = received.plaintext.to_vec();
            if received.metadata.kind == MessageKind::Receipt {
                (message_id, plaintext, None, None, None)
            } else {
                let mut channel_text = None;
                let mut apply_error = None;
                if received.metadata.kind == MessageKind::Channel {
                    match ChannelFrame::from_bytes(&plaintext) {
                        Ok(frame) => match state.apply_channel_frame(peer, frame) {
                            Ok(text) => channel_text = text,
                            Err(error) => apply_error = Some(error.to_string()),
                        },
                        Err(error) => apply_error = Some(error.to_string()),
                    }
                }
                if apply_error.is_some() {
                    (message_id, plaintext, None, None, apply_error)
                } else {
                    let receipt = state.conversation.receipt(
                        &self.identity,
                        ReceiptStatus::Delivered,
                        message_id,
                    )?;
                    (
                        message_id,
                        plaintext,
                        Some(receipt.to_bytes()?),
                        channel_text,
                        None,
                    )
                }
            }
        };

        if let Some(reason) = apply_error {
            // An unauthorised or malformed channel frame gets no delivery
            // receipt: that would falsely acknowledge a policy change.
            self.last_error = Some(reason);
            return Ok(());
        }

        if let Some(receipt_bytes) = receipt_bytes {
            self.network
                .respond_to_message(response_id, receipt_bytes)?;
        }

        if kind == MessageKind::Text {
            match String::from_utf8(plaintext) {
                Ok(text) => {
                    self.message_conversations
                        .insert(message_id, conversation_id);
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
                .insert(message_id, conversation_id);
            self.messages.push(ChatMessage {
                message_id,
                channel_id,
                peer,
                text,
                origin: MessageOrigin::Remote,
                delivery: None,
            });
        }
        Ok(())
    }

    fn handle_message_response(
        &mut self,
        request_id: MessageRequestId,
        swarm_peer: SwarmPeerId,
        bytes: &[u8],
    ) -> Result<(), ChatError> {
        let Some(_local_message_id) = self.outstanding_messages.remove(&request_id) else {
            return Ok(());
        };
        let peer = identity_peer(swarm_peer)?;
        let envelope = Envelope::from_bytes(bytes)?;
        let received = {
            let state = self
                .conversations
                .get_mut(&envelope.conversation_id)
                .ok_or(ChatError::UnknownConversation)?;
            if !state.members.contains(&peer) {
                return Err(ChatError::NotGroupMember);
            }
            state.conversation.receive(envelope)?
        };
        if let Some(receipt) = received.metadata.receipt {
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
            self.set_line_delivery(
                receipt.message_id,
                if complete {
                    DeliveryState::Delivered
                } else {
                    DeliveryState::SentToPeer
                },
            );
        }
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

    #[test]
    fn default_controller_privacy_status_is_all_off_and_unobserved() {
        let identity = Identity::generate().expect("identity");
        let controller =
            MessengerController::start(&identity, NetworkConfig::default()).expect("controller");
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
}
