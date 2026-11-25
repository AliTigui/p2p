//! Direct peer-to-peer networking with zero mandatory infrastructure.
//!
//! A [`Network`] owns a libp2p Swarm on a dedicated Tokio runtime thread. It
//! listens on a local address and dials only addresses the user supplies. No
//! bootstrap nodes, DHT servers, relays, or developer-operated services are
//! configured by default. Noise authenticates the remote PeerId; the caller's
//! identity keypair is reused so the network identity matches the vault.
//!
//! Three explicit protocols share the Noise-authenticated connection: message
//! delivery, MLS setup, and encrypted file transfer. All carry
//! application-authenticated opaque bytes; the transport never composes,
//! decrypts, or accepts application state.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, dcutr, identify, kad, mdns, ping, relay,
};
use libp2p_request_response as request_response;
use libp2p_request_response::{
    InboundRequestId, OutboundRequestId, ProtocolSupport, ResponseChannel,
};
use p2p_identity::Identity;
use thiserror::Error;
use tokio::sync::mpsc as tokio_mpsc;

mod privacy;
mod protocol;

pub use privacy::{
    DiscoveryEvent, DiscoverySource, IdentifyEvent, NatEvent, NetworkPrivacyStatus, RelayEvent,
    RelayMode,
};
pub use protocol::{
    CONTROL_PROTOCOL, FILE_PROTOCOL, MAX_MESSAGE_BYTES, MESSAGE_PROTOCOL, MLS_SETUP_PROTOCOL,
    MessageCodec,
};

/// Combined libp2p behaviour. The four application protocols are always present;
/// discovery, identify, NAT, and relay behaviours are wrapped in `Toggle` and
/// disabled unless the local user explicitly opts in at `Network::start`.
#[derive(NetworkBehaviour)]
struct Behaviour {
    messages: request_response::Behaviour<MessageCodec>,
    setup: request_response::Behaviour<MessageCodec>,
    files: request_response::Behaviour<MessageCodec>,
    control: request_response::Behaviour<MessageCodec>,
    identify: Toggle<identify::Behaviour>,
    ping: Toggle<ping::Behaviour>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    kad: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
    relay_client: Toggle<relay::client::Behaviour>,
    relay_server: Toggle<relay::Behaviour>,
    autonat: Toggle<autonat::v1::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
}

/// Errors from the direct-connect network layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network runtime failed to start: {0}")]
    Runtime(String),
    #[error("libp2p transport setup failed: {0}")]
    Transport(String),
    #[error("invalid peer address: {0}")]
    InvalidAddress(String),
    #[error("network worker is not running")]
    Stopped,
    #[error("dial request could not be queued: {0}")]
    Dial(String),
    #[error("address is already queued for dialing")]
    DuplicateAddress,
    #[error("message bytes cannot be empty")]
    EmptyMessage,
    #[error("message bytes exceed {max} bytes")]
    MessageTooLarge { max: usize },
    #[error("unknown message response identifier")]
    UnknownResponse,
    #[error("message request could not be queued: {0}")]
    Message(String),
    #[error("file request could not be queued: {0}")]
    File(String),
    #[error("control request could not be queued: {0}")]
    Control(String),
    #[error("file transfer over a relay is disabled by policy")]
    FileOverRelay,
}

/// Observed connection state. Every variant comes from a real Swarm event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// The worker has not reported anything yet.
    Unknown,
    /// The runtime is being created.
    Starting,
    /// One or more listeners are live; no peers connected yet.
    Listening { addresses: Vec<Multiaddr> },
    /// An outbound dial is in progress.
    Connecting { peer: PeerId },
    /// At least one authenticated connection is live.
    Connected { peers: Vec<PeerId> },
    /// The last known peer disconnected and none remain.
    Disconnected { peer: PeerId },
    /// A transport or dial failure occurred. `peer` is present when the Swarm
    /// could attribute the failure to an expected PeerId.
    Failed {
        peer: Option<PeerId>,
        reason: String,
    },
}

impl ConnectionState {
    /// Number of currently connected peers, from the last observed event.
    pub fn connected_count(&self) -> usize {
        match self {
            Self::Connected { peers } => peers.len(),
            _ => 0,
        }
    }

    /// Honest, user-facing text. It never says "connected" unless the Swarm
    /// reported a live authenticated connection.
    pub fn description(&self) -> String {
        match self {
            Self::Unknown => "Unknown".to_owned(),
            Self::Starting => "Starting".to_owned(),
            Self::Listening { .. } => "Listening (no peers connected)".to_owned(),
            Self::Connecting { peer } => format!("Connecting to {}", short_peer(peer)),
            Self::Connected { peers } => format!("Connected ({})", peers.len()),
            Self::Disconnected { peer } => format!("Disconnected from {}", short_peer(peer)),
            Self::Failed { reason, .. } => format!("Failed: {reason}"),
        }
    }

    fn listen_addresses(&self) -> Vec<Multiaddr> {
        match self {
            Self::Listening { addresses } => addresses.clone(),
            _ => Vec::new(),
        }
    }
}

fn short_peer(peer: &PeerId) -> String {
    let text = peer.to_string();
    text.chars().take(12).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpKey {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

fn ip_key(address: &Multiaddr) -> Option<IpKey> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpKey::V4(ip)),
        Protocol::Ip6(ip) => Some(IpKey::V6(ip)),
        _ => None,
    })
}

/// Admission counters for established connections. They are checked at the
/// authenticated `ConnectionEstablished` event, not at the raw socket layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionLimits {
    max_total: usize,
    max_per_peer: usize,
    max_per_ip: usize,
}

impl ConnectionLimits {
    fn from_config(config: &NetworkConfig) -> Self {
        Self {
            max_total: config.max_total_connections,
            max_per_peer: config.max_connections_per_peer,
            max_per_ip: config.max_connections_per_ip,
        }
    }

    fn exceeded(&self, total: usize, peer: usize, ip: Option<usize>) -> bool {
        total > self.max_total
            || peer > self.max_per_peer
            || ip.is_some_and(|count| count > self.max_per_ip)
    }
}

/// Sliding-window budget for inbound application requests. It counts opaque
/// request bytes before the application decodes them; responses and transport
/// handshake bytes are not counted.
#[derive(Debug)]
struct RateLimiter {
    window: Duration,
    max_bytes: usize,
    max_requests: u32,
    entries: HashMap<PeerId, VecDeque<(Instant, usize)>>,
}

impl RateLimiter {
    fn new(config: &NetworkConfig) -> Self {
        Self {
            window: config.rate_window,
            max_bytes: config.max_request_bytes_per_peer_per_window,
            max_requests: config.max_requests_per_peer_per_window,
            entries: HashMap::new(),
        }
    }

    fn allow(&mut self, peer: PeerId, bytes: usize, now: Instant) -> bool {
        let entry = self.entries.entry(peer).or_default();
        entry.retain(|(seen, _)| now.saturating_duration_since(*seen) < self.window);
        let seen_bytes = entry
            .iter()
            .fold(0usize, |sum, (_, bytes)| sum.saturating_add(*bytes));
        if entry.len() as u32 >= self.max_requests
            || seen_bytes.saturating_add(bytes) > self.max_bytes
        {
            return false;
        }
        entry.push_back((now, bytes));
        true
    }
}

/// Local identifier for one outbound message request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageRequestId(u64);

/// Local identifier for one inbound message request awaiting a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageResponseId(u64);

impl std::fmt::Display for MessageRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "msg-req-{}", self.0)
    }
}

impl std::fmt::Display for MessageResponseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "msg-resp-{}", self.0)
    }
}

/// Local identifier for one outbound MLS setup request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupRequestId(u64);

/// Local identifier for one inbound MLS setup request awaiting a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupResponseId(u64);

impl std::fmt::Display for SetupRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "setup-req-{}", self.0)
    }
}

impl std::fmt::Display for SetupResponseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "setup-resp-{}", self.0)
    }
}

/// Local identifier for one outbound file-protocol request. It tracks a
/// transport frame only, never a completed transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileRequestId(u64);

/// Local identifier for one inbound file-protocol request awaiting a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileResponseId(u64);

impl std::fmt::Display for FileRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "file-req-{}", self.0)
    }
}

impl std::fmt::Display for FileResponseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "file-resp-{}", self.0)
    }
}

/// Local identifier for one outbound control-protocol request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControlRequestId(u64);

/// Local identifier for one inbound control-protocol request awaiting a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControlResponseId(u64);

impl std::fmt::Display for ControlRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ctrl-req-{}", self.0)
    }
}

impl std::fmt::Display for ControlResponseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ctrl-resp-{}", self.0)
    }
}

/// Transport observations for the message protocol. These events deliberately
/// do not claim message delivery or application-level acceptance.
#[derive(Clone, PartialEq, Eq)]
pub enum MessageEvent {
    /// The request was handed to the Noise-protected libp2p behaviour. This is
    /// not proof that the peer received, accepted, or read it.
    SentToPeer {
        request_id: MessageRequestId,
        peer: PeerId,
    },
    /// A request arrived from an authenticated peer. The application must
    /// decode and verify it before calling [`Network::respond_to_message`].
    RequestReceived {
        response_id: MessageResponseId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A response arrived for a previously sent request. The application must
    /// verify its contents before changing any delivery state.
    ResponseReceived {
        request_id: MessageRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A request, response, or scheduled response failed.
    Failed {
        request_id: Option<MessageRequestId>,
        response_id: Option<MessageResponseId>,
        peer: PeerId,
        reason: String,
    },
}

/// Transport observations for the MLS setup protocol. These events carry
/// opaque frames and never claim that a group was created or joined; only the
/// application's verified setup state may make that claim.
#[derive(Clone, PartialEq, Eq)]
pub enum SetupEvent {
    /// A signed setup request was handed to the Noise-protected behaviour.
    SentToPeer {
        request_id: SetupRequestId,
        peer: PeerId,
    },
    /// A setup request arrived. The application must verify its signature and
    /// expected peer before calling [`Network::respond_to_setup`].
    RequestReceived {
        response_id: SetupResponseId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A response arrived for a previously sent setup request. Its contents
    /// must be verified before changing any conversation state.
    ResponseReceived {
        request_id: SetupRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A setup request, response, or scheduled response failed.
    Failed {
        request_id: Option<SetupRequestId>,
        response_id: Option<SetupResponseId>,
        peer: PeerId,
        reason: String,
    },
}

/// Transport observations for the encrypted file protocol. These events carry
/// opaque signed frames and never claim a completed, scanned, or safe file.
#[derive(Clone, PartialEq, Eq)]
pub enum FileEvent {
    /// A file frame was handed to the Noise-protected behaviour. This is not
    /// proof of chunk acceptance or transfer completion.
    SentToPeer {
        request_id: FileRequestId,
        peer: PeerId,
    },
    /// A file frame arrived. The application must verify its signature and
    /// expected peer before calling [`Network::respond_to_file`].
    RequestReceived {
        response_id: FileResponseId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A response arrived for a previously sent file frame. Its contents must
    /// be verified before changing transfer state.
    ResponseReceived {
        request_id: FileRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A file request, response, or scheduled response failed.
    Failed {
        request_id: Option<FileRequestId>,
        response_id: Option<FileResponseId>,
        peer: PeerId,
        reason: String,
    },
}

/// Transport observations for the versioned control protocol. Control frames
/// are opaque here; the application must define and verify their semantics.
#[derive(Clone, PartialEq, Eq)]
pub enum ControlEvent {
    /// A control request was handed to the Noise-protected behaviour.
    SentToPeer {
        request_id: ControlRequestId,
        peer: PeerId,
    },
    /// A control request arrived from an authenticated peer.
    RequestReceived {
        response_id: ControlResponseId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A control response arrived for a previously sent request.
    ResponseReceived {
        request_id: ControlRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    /// A control request, response, or scheduled response failed.
    Failed {
        request_id: Option<ControlRequestId>,
        response_id: Option<ControlResponseId>,
        peer: PeerId,
        reason: String,
    },
}

// Opaque frames are redacted from Debug output. Events may be logged by the
// application, so printing them could leak MLS ciphertext, setup payloads, or
// encrypted file chunks even though the transport itself cannot decrypt them.
impl std::fmt::Debug for MessageEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentToPeer { request_id, peer } => f
                .debug_struct("MessageEvent::SentToPeer")
                .field("request_id", request_id)
                .field("peer", peer)
                .finish_non_exhaustive(),
            Self::RequestReceived {
                response_id,
                peer,
                bytes,
            } => f
                .debug_struct("MessageEvent::RequestReceived")
                .field("response_id", response_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => f
                .debug_struct("MessageEvent::ResponseReceived")
                .field("request_id", request_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Failed {
                request_id,
                response_id,
                peer,
                reason,
            } => f
                .debug_struct("MessageEvent::Failed")
                .field("request_id", request_id)
                .field("response_id", response_id)
                .field("peer", peer)
                .field("reason", reason)
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Debug for SetupEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentToPeer { request_id, peer } => f
                .debug_struct("SetupEvent::SentToPeer")
                .field("request_id", request_id)
                .field("peer", peer)
                .finish_non_exhaustive(),
            Self::RequestReceived {
                response_id,
                peer,
                bytes,
            } => f
                .debug_struct("SetupEvent::RequestReceived")
                .field("response_id", response_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => f
                .debug_struct("SetupEvent::ResponseReceived")
                .field("request_id", request_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Failed {
                request_id,
                response_id,
                peer,
                reason,
            } => f
                .debug_struct("SetupEvent::Failed")
                .field("request_id", request_id)
                .field("response_id", response_id)
                .field("peer", peer)
                .field("reason", reason)
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Debug for FileEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentToPeer { request_id, peer } => f
                .debug_struct("FileEvent::SentToPeer")
                .field("request_id", request_id)
                .field("peer", peer)
                .finish_non_exhaustive(),
            Self::RequestReceived {
                response_id,
                peer,
                bytes,
            } => f
                .debug_struct("FileEvent::RequestReceived")
                .field("response_id", response_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => f
                .debug_struct("FileEvent::ResponseReceived")
                .field("request_id", request_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Failed {
                request_id,
                response_id,
                peer,
                reason,
            } => f
                .debug_struct("FileEvent::Failed")
                .field("request_id", request_id)
                .field("response_id", response_id)
                .field("peer", peer)
                .field("reason", reason)
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Debug for ControlEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentToPeer { request_id, peer } => f
                .debug_struct("ControlEvent::SentToPeer")
                .field("request_id", request_id)
                .field("peer", peer)
                .finish_non_exhaustive(),
            Self::RequestReceived {
                response_id,
                peer,
                bytes,
            } => f
                .debug_struct("ControlEvent::RequestReceived")
                .field("response_id", response_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::ResponseReceived {
                request_id,
                peer,
                bytes,
            } => f
                .debug_struct("ControlEvent::ResponseReceived")
                .field("request_id", request_id)
                .field("peer", peer)
                .field("bytes_len", &bytes.len())
                .field("bytes", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Failed {
                request_id,
                response_id,
                peer,
                reason,
            } => f
                .debug_struct("ControlEvent::Failed")
                .field("request_id", request_id)
                .field("response_id", response_id)
                .field("peer", peer)
                .field("reason", reason)
                .finish_non_exhaustive(),
        }
    }
}

/// Configuration for a direct-connect network worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Address to listen on. Ephemeral TCP ports are allowed.
    pub listen_addr: Multiaddr,
    /// Maximum time for a transport upgrade or dial.
    pub connection_timeout: Duration,
    /// Automatic redial attempts after an observed disconnect or failed dial.
    /// Zero disables automatic redial; the initial user dial does not count.
    pub max_redial_attempts: u32,
    /// First automatic redial delay; each attempt doubles until the cap.
    pub redial_base_delay: Duration,
    /// Upper bound for the exponential redial delay.
    pub redial_max_delay: Duration,
    /// Hard cap on simultaneously established connections.
    pub max_total_connections: usize,
    /// Hard cap on simultaneous connections to one authenticated PeerId.
    pub max_connections_per_peer: usize,
    /// Hard cap on simultaneous connections from one observed IP address.
    pub max_connections_per_ip: usize,
    /// Maximum inbound application requests from one peer per rate window.
    pub max_requests_per_peer_per_window: u32,
    /// Maximum inbound application request bytes from one peer per rate window.
    pub max_request_bytes_per_peer_per_window: usize,
    /// Sliding window used by the per-peer request and byte limits.
    pub rate_window: Duration,

    /// Enable privacy-hardened libp2p identify. Disabled by default because it
    /// reveals a protocol list even when listen addresses are hidden.
    pub enable_identify: bool,
    /// Enable low-frequency libp2p ping. Disabled by default to avoid periodic
    /// traffic on connections that do not need health checks.
    pub enable_ping: bool,
    /// Enable mDNS local-network discovery. Discovery emits candidates only;
    /// it never auto-dials or authenticates a human identity.
    pub enable_mdns: bool,
    /// Enable Kademlia discovery. Requires explicit bootstrap peers below.
    pub enable_kad: bool,
    /// User-supplied DHT bootstrap addresses. Every address must end in
    /// `/p2p/<peer-id>` and contain no `/p2p-circuit`.
    pub kad_bootstrap_peers: Vec<Multiaddr>,
    /// Optional peer-operated relay mode. Off by default.
    pub relay_mode: RelayMode,
    /// User-supplied relay server addresses for relay-client mode.
    pub relay_servers: Vec<Multiaddr>,
    /// Enable best-effort AutoNAT status probing. Disabled by default.
    pub enable_autonat: bool,
    /// Enable DCUtR hole punching when a relayed connection exists.
    pub enable_dcutr: bool,
    /// Hard cap on simultaneously established relayed connections.
    pub max_relayed_connections: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: Multiaddr::from_str("/ip4/0.0.0.0/tcp/0")
                .expect("literal multiaddr is valid"),
            connection_timeout: Duration::from_secs(10),
            max_redial_attempts: 3,
            redial_base_delay: Duration::from_millis(500),
            redial_max_delay: Duration::from_secs(8),
            max_total_connections: 16,
            max_connections_per_peer: 1,
            max_connections_per_ip: 4,
            max_requests_per_peer_per_window: 64,
            max_request_bytes_per_peer_per_window: 16 * MAX_MESSAGE_BYTES,
            rate_window: Duration::from_secs(1),
            enable_identify: false,
            enable_ping: false,
            enable_mdns: false,
            enable_kad: false,
            kad_bootstrap_peers: Vec::new(),
            relay_mode: RelayMode::Off,
            relay_servers: Vec::new(),
            enable_autonat: false,
            enable_dcutr: false,
            max_relayed_connections: 4,
        }
    }
}

enum Command {
    Dial {
        address: Multiaddr,
        expected: PeerId,
    },
    SendMessage {
        id: MessageRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    RespondMessage {
        id: MessageResponseId,
        bytes: Vec<u8>,
    },
    SendSetup {
        id: SetupRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    RespondSetup {
        id: SetupResponseId,
        bytes: Vec<u8>,
    },
    SendFile {
        id: FileRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    RespondFile {
        id: FileResponseId,
        bytes: Vec<u8>,
    },
    SendControl {
        id: ControlRequestId,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    RespondControl {
        id: ControlResponseId,
        bytes: Vec<u8>,
    },
    DisconnectAll,
    Shutdown,
}

enum Startup {
    Ready,
    Error(String),
}

/// A running direct-connect worker. Dropping it shuts the Swarm down.
pub struct Network {
    commands: tokio_mpsc::Sender<Command>,
    events: tokio_mpsc::Receiver<ConnectionState>,
    message_events: tokio_mpsc::Receiver<MessageEvent>,
    setup_events: tokio_mpsc::Receiver<SetupEvent>,
    file_events: tokio_mpsc::Receiver<FileEvent>,
    control_events: tokio_mpsc::Receiver<ControlEvent>,
    discovery_events: tokio_mpsc::Receiver<DiscoveryEvent>,
    relay_events: tokio_mpsc::Receiver<RelayEvent>,
    nat_events: tokio_mpsc::Receiver<NatEvent>,
    identify_events: tokio_mpsc::Receiver<IdentifyEvent>,
    state: ConnectionState,
    privacy_status: NetworkPrivacyStatus,
    pending_addresses: HashMap<Multiaddr, PeerId>,
    next_request_id: AtomicU64,
    next_setup_request_id: AtomicU64,
    next_file_request_id: AtomicU64,
    next_control_request_id: AtomicU64,
    worker: Option<thread::JoinHandle<()>>,
}

impl Network {
    /// Parse a user-supplied multiaddr. The `/p2p/<peer-id>` suffix is required
    /// so the expected remote identity is known before dialing.
    pub fn parse_address(input: &str) -> Result<Multiaddr, NetworkError> {
        let address = Multiaddr::from_str(input.trim())
            .map_err(|error| NetworkError::InvalidAddress(error.to_string()))?;
        validate_direct_peer_address(&address)?;
        Ok(address)
    }

    /// Start listening with the vault identity.
    ///
    /// With the default configuration this contacts no peer; dialing requires
    /// an explicit address from the user. If the user explicitly configures
    /// DHT bootstrap peers or relay servers, those user-supplied peers may be
    /// contacted during startup. No developer-operated default exists.
    pub fn start(identity: &Identity, config: NetworkConfig) -> Result<Self, NetworkError> {
        validate_config(&config)?;
        let privacy_status = privacy_status_from_config(&config);
        // libp2p 0.56 uses an older `libp2p-identity` than the identity crate.
        // The protobuf keypair encoding is a stable, version-independent
        // boundary; importing it preserves the exact vault PeerId.
        let keypair =
            libp2p::identity::Keypair::from_protobuf_encoding(&identity.export_keypair_bytes())
                .map_err(|error| {
                    NetworkError::Runtime(format!("identity key import failed: {error}"))
                })?;
        let (command_tx, command_rx) = tokio_mpsc::channel(16);
        let (event_tx, event_rx) = tokio_mpsc::channel(32);
        let (message_event_tx, message_event_rx) = tokio_mpsc::channel(64);
        let (setup_event_tx, setup_event_rx) = tokio_mpsc::channel(64);
        let (file_event_tx, file_event_rx) = tokio_mpsc::channel(64);
        let (control_event_tx, control_event_rx) = tokio_mpsc::channel(64);
        let (discovery_event_tx, discovery_event_rx) = tokio_mpsc::channel(64);
        let (relay_event_tx, relay_event_rx) = tokio_mpsc::channel(64);
        let (nat_event_tx, nat_event_rx) = tokio_mpsc::channel(64);
        let (identify_event_tx, identify_event_rx) = tokio_mpsc::channel(64);
        let (startup_tx, startup_rx) = mpsc::channel();

        let worker = thread::Builder::new()
            .name("p2p-network".to_owned())
            .spawn(move || {
                run_worker(
                    keypair,
                    config,
                    command_rx,
                    event_tx,
                    message_event_tx,
                    setup_event_tx,
                    file_event_tx,
                    control_event_tx,
                    discovery_event_tx,
                    relay_event_tx,
                    nat_event_tx,
                    identify_event_tx,
                    startup_tx,
                );
            })
            .map_err(|error| NetworkError::Runtime(error.to_string()))?;

        match startup_rx.recv() {
            Ok(Startup::Ready) => Ok(Self {
                commands: command_tx,
                events: event_rx,
                message_events: message_event_rx,
                setup_events: setup_event_rx,
                file_events: file_event_rx,
                control_events: control_event_rx,
                discovery_events: discovery_event_rx,
                relay_events: relay_event_rx,
                nat_events: nat_event_rx,
                identify_events: identify_event_rx,
                state: ConnectionState::Unknown,
                privacy_status,
                pending_addresses: HashMap::new(),
                next_request_id: AtomicU64::new(1),
                next_setup_request_id: AtomicU64::new(1),
                next_file_request_id: AtomicU64::new(1),
                next_control_request_id: AtomicU64::new(1),
                worker: Some(worker),
            }),
            Ok(Startup::Error(reason)) => {
                let _ = command_tx.try_send(Command::Shutdown);
                let _ = worker.join();
                Err(NetworkError::Runtime(reason))
            }
            Err(_) => {
                let _ = worker.join();
                Err(NetworkError::Runtime(
                    "network worker exited before reporting readiness".to_owned(),
                ))
            }
        }
    }

    /// Queue a dial to a user-supplied address with a known PeerId. An address
    /// already awaiting a dial, connection, or failure is rejected so repeated
    /// button presses or retry loops cannot stack duplicate dials.
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), NetworkError> {
        let expected = peer_from_address(&address).ok_or_else(|| {
            NetworkError::InvalidAddress("address has no /p2p/<peer-id>".to_owned())
        })?;
        if self
            .pending_addresses
            .insert(address.clone(), expected)
            .is_some()
        {
            return Err(NetworkError::DuplicateAddress);
        }
        if let Err(error) = self.commands.try_send(Command::Dial {
            address: address.clone(),
            expected,
        }) {
            self.pending_addresses.remove(&address);
            return Err(NetworkError::Dial(error.to_string()));
        }
        Ok(())
    }

    /// Drop every live connection and clear pending dial addresses. Listening
    /// continues. Callers that want a different peer must dial explicitly.
    pub fn disconnect_all(&mut self) -> Result<(), NetworkError> {
        self.commands
            .try_send(Command::DisconnectAll)
            .map_err(|error| NetworkError::Dial(error.to_string()))?;
        self.pending_addresses.clear();
        Ok(())
    }

    /// Hand an already-encoded envelope to the message protocol for one
    /// authenticated peer. The returned ID tracks the transport request only;
    /// it is not a delivery receipt.
    pub fn send_message(
        &self,
        peer: PeerId,
        bytes: Vec<u8>,
    ) -> Result<MessageRequestId, NetworkError> {
        validate_message_bytes(&bytes)?;
        let id = MessageRequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed));
        self.commands
            .try_send(Command::SendMessage { id, peer, bytes })
            .map_err(|error| NetworkError::Message(error.to_string()))?;
        Ok(id)
    }

    /// Send the application's response to a previously received message
    /// request. Validation and signing must happen before this call.
    pub fn respond_to_message(
        &self,
        id: MessageResponseId,
        bytes: Vec<u8>,
    ) -> Result<(), NetworkError> {
        validate_message_bytes(&bytes)?;
        self.commands
            .try_send(Command::RespondMessage { id, bytes })
            .map_err(|error| NetworkError::Message(error.to_string()))
    }

    /// Hand a signed MLS setup frame to the setup protocol. The returned ID
    /// tracks the transport request only; it does not mean the peer joined.
    pub fn send_setup(&self, peer: PeerId, bytes: Vec<u8>) -> Result<SetupRequestId, NetworkError> {
        validate_message_bytes(&bytes)?;
        let id = SetupRequestId(self.next_setup_request_id.fetch_add(1, Ordering::Relaxed));
        self.commands
            .try_send(Command::SendSetup { id, peer, bytes })
            .map_err(|error| NetworkError::Message(error.to_string()))?;
        Ok(id)
    }

    /// Send the application's response to a previously received setup request.
    /// Signature verification and MLS validation must happen before this call.
    pub fn respond_to_setup(
        &self,
        id: SetupResponseId,
        bytes: Vec<u8>,
    ) -> Result<(), NetworkError> {
        validate_message_bytes(&bytes)?;
        self.commands
            .try_send(Command::RespondSetup { id, bytes })
            .map_err(|error| NetworkError::Message(error.to_string()))
    }

    /// Hand a signed file frame to the file protocol for one authenticated
    /// peer. The returned ID tracks a transport request; it never means the
    /// file was received, verified, scanned, or safe.
    pub fn send_file(&self, peer: PeerId, bytes: Vec<u8>) -> Result<FileRequestId, NetworkError> {
        validate_message_bytes(&bytes)?;
        let id = FileRequestId(self.next_file_request_id.fetch_add(1, Ordering::Relaxed));
        self.commands
            .try_send(Command::SendFile { id, peer, bytes })
            .map_err(|error| NetworkError::File(error.to_string()))?;
        Ok(id)
    }

    /// Send the application's response to a previously received file frame.
    /// Signature and peer verification must happen before this call.
    pub fn respond_to_file(&self, id: FileResponseId, bytes: Vec<u8>) -> Result<(), NetworkError> {
        validate_message_bytes(&bytes)?;
        self.commands
            .try_send(Command::RespondFile { id, bytes })
            .map_err(|error| NetworkError::File(error.to_string()))
    }

    /// Hand an opaque capability/control frame to the versioned control
    /// protocol. The returned ID tracks the transport request only; it does
    /// not mean the peer supports or accepted the application semantics.
    pub fn send_control(
        &self,
        peer: PeerId,
        bytes: Vec<u8>,
    ) -> Result<ControlRequestId, NetworkError> {
        validate_message_bytes(&bytes)?;
        let id = ControlRequestId(self.next_control_request_id.fetch_add(1, Ordering::Relaxed));
        self.commands
            .try_send(Command::SendControl { id, peer, bytes })
            .map_err(|error| NetworkError::Control(error.to_string()))?;
        Ok(id)
    }

    /// Respond to a previously received control frame. Application-level
    /// validation must happen before this call.
    pub fn respond_to_control(
        &self,
        id: ControlResponseId,
        bytes: Vec<u8>,
    ) -> Result<(), NetworkError> {
        validate_message_bytes(&bytes)?;
        self.commands
            .try_send(Command::RespondControl { id, bytes })
            .map_err(|error| NetworkError::Control(error.to_string()))
    }

    /// Drain one pending message-protocol event.
    pub fn poll_message_event(&mut self) -> Option<MessageEvent> {
        match self.message_events.try_recv() {
            Ok(event) => Some(event),
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => None,
        }
    }

    /// Drain one pending MLS setup-protocol event.
    pub fn poll_setup_event(&mut self) -> Option<SetupEvent> {
        match self.setup_events.try_recv() {
            Ok(event) => Some(event),
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => None,
        }
    }

    /// Drain one pending file-protocol event.
    pub fn poll_file_event(&mut self) -> Option<FileEvent> {
        match self.file_events.try_recv() {
            Ok(event) => Some(event),
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => None,
        }
    }

    /// Drain one pending control-protocol event.
    pub fn poll_control_event(&mut self) -> Option<ControlEvent> {
        match self.control_events.try_recv() {
            Ok(event) => Some(event),
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => None,
        }
    }

    /// Drain one pending discovery observation and update the cached snapshot.
    pub fn poll_discovery_event(&mut self) -> Option<DiscoveryEvent> {
        let event = match self.discovery_events.try_recv() {
            Ok(event) => event,
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => return None,
        };
        match &event {
            DiscoveryEvent::Discovered {
                source: DiscoverySource::Mdns,
                ..
            } => {
                self.privacy_status.discovered_candidates =
                    self.privacy_status.discovered_candidates.saturating_add(1)
            }
            DiscoveryEvent::Expired {
                source: DiscoverySource::Mdns,
                ..
            } => {
                self.privacy_status.discovered_candidates =
                    self.privacy_status.discovered_candidates.saturating_sub(1)
            }
            DiscoveryEvent::Discovered {
                source: DiscoverySource::Kad,
                ..
            } => self.privacy_status.kad_routes = self.privacy_status.kad_routes.saturating_add(1),
            DiscoveryEvent::Expired {
                source: DiscoverySource::Kad,
                ..
            } => self.privacy_status.kad_routes = self.privacy_status.kad_routes.saturating_sub(1),
            _ => {}
        }
        Some(event)
    }

    /// Drain one pending relay observation and update the cached snapshot.
    pub fn poll_relay_event(&mut self) -> Option<RelayEvent> {
        let event = match self.relay_events.try_recv() {
            Ok(event) => event,
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => return None,
        };
        match &event {
            RelayEvent::ReservationAccepted { .. } => {
                self.privacy_status.relay_reservations =
                    self.privacy_status.relay_reservations.saturating_add(1)
            }
            RelayEvent::OutboundCircuitEstablished { .. }
            | RelayEvent::ServerCircuitAccepted { .. } => {
                self.privacy_status.relay_circuits =
                    self.privacy_status.relay_circuits.saturating_add(1)
            }
            RelayEvent::RelayedConnectionsChanged { count } => {
                self.privacy_status.relayed_connections = *count
            }
            _ => {}
        }
        Some(event)
    }

    /// Drain one pending NAT observation and update the cached snapshot.
    pub fn poll_nat_event(&mut self) -> Option<NatEvent> {
        let event = match self.nat_events.try_recv() {
            Ok(event) => event,
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => return None,
        };
        if let NatEvent::StatusChanged { status, .. } = &event {
            self.privacy_status.nat_status = status.clone();
        }
        Some(event)
    }

    /// Drain one pending identify observation and update the cached snapshot.
    pub fn poll_identify_event(&mut self) -> Option<IdentifyEvent> {
        let event = match self.identify_events.try_recv() {
            Ok(event) => event,
            Err(tokio_mpsc::error::TryRecvError::Empty)
            | Err(tokio_mpsc::error::TryRecvError::Disconnected) => return None,
        };
        if matches!(event, IdentifyEvent::Identified { .. }) {
            self.privacy_status.identified_peers =
                self.privacy_status.identified_peers.saturating_add(1);
        }
        Some(event)
    }

    /// Snapshot of configured capabilities and observed optional-network facts.
    /// Callers must drain the privacy event queues to keep observations current.
    pub fn privacy_status(&self) -> &NetworkPrivacyStatus {
        &self.privacy_status
    }

    /// Latest observed state.
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// Listener addresses reported by the Swarm.
    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.state.listen_addresses()
    }

    /// Drain one pending state event, updating the cached state and clearing
    /// dial addresses that reached a terminal dial or connection outcome.
    pub fn poll_event(&mut self) -> Option<ConnectionState> {
        match self.events.try_recv() {
            Ok(state) => {
                self.clear_settled_addresses(&state);
                self.state = state.clone();
                Some(state)
            }
            Err(tokio_mpsc::error::TryRecvError::Empty) => None,
            Err(tokio_mpsc::error::TryRecvError::Disconnected) => {
                self.state = ConnectionState::Failed {
                    peer: None,
                    reason: "network worker stopped".to_owned(),
                };
                Some(self.state.clone())
            }
        }
    }

    fn clear_settled_addresses(&mut self, state: &ConnectionState) {
        let peer: &PeerId = match state {
            ConnectionState::Connected { peers } => {
                let peers: HashSet<String> = peers.iter().map(ToString::to_string).collect();
                self.pending_addresses
                    .retain(|address, _| !peers.contains(&expected_peer_key(address)));
                return;
            }
            ConnectionState::Disconnected { peer } => peer,
            ConnectionState::Failed {
                peer: Some(peer), ..
            } => peer,
            _ => return,
        };
        let key = peer.to_string();
        self.pending_addresses
            .retain(|address, _| expected_peer_key(address) != key);
    }

    /// Stop the worker and wait for it to exit.
    pub fn shutdown(mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn peer_from_address(address: &Multiaddr) -> Option<PeerId> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

fn validate_direct_peer_address(address: &Multiaddr) -> Result<(), NetworkError> {
    if peer_from_address(address).is_none() {
        return Err(NetworkError::InvalidAddress(
            "address must end in /p2p/<peer-id>".to_owned(),
        ));
    }
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return Err(NetworkError::InvalidAddress(
            "address must be direct, not /p2p-circuit".to_owned(),
        ));
    }
    Ok(())
}

fn privacy_status_from_config(config: &NetworkConfig) -> NetworkPrivacyStatus {
    NetworkPrivacyStatus {
        identify_enabled: config.enable_identify,
        ping_enabled: config.enable_ping,
        mdns_enabled: config.enable_mdns,
        kad_enabled: config.enable_kad,
        kad_bootstrap_peers: config.kad_bootstrap_peers.len(),
        relay_mode: config.relay_mode,
        relay_servers: config.relay_servers.len(),
        autonat_enabled: config.enable_autonat,
        dcutr_enabled: config.enable_dcutr,
        discovered_candidates: 0,
        kad_routes: 0,
        relay_reservations: 0,
        relay_circuits: 0,
        nat_status: "Unknown".to_owned(),
        identified_peers: 0,
        relayed_connections: 0,
    }
}

fn validate_config(config: &NetworkConfig) -> Result<(), NetworkError> {
    if config.enable_kad && config.kad_bootstrap_peers.is_empty() {
        return Err(NetworkError::InvalidAddress(
            "Kademlia requires at least one user-supplied bootstrap address".to_owned(),
        ));
    }
    if config.relay_mode == RelayMode::Client && config.relay_servers.is_empty() {
        return Err(NetworkError::InvalidAddress(
            "relay-client mode requires at least one user-supplied relay address".to_owned(),
        ));
    }
    if config.relay_mode == RelayMode::Client && config.max_relayed_connections == 0 {
        return Err(NetworkError::InvalidAddress(
            "relay-client mode requires at least one allowed relayed connection".to_owned(),
        ));
    }
    for address in &config.kad_bootstrap_peers {
        validate_direct_peer_address(address)?;
    }
    for address in &config.relay_servers {
        validate_direct_peer_address(address)?;
    }
    Ok(())
}

fn expected_peer_key(address: &Multiaddr) -> String {
    peer_from_address(address)
        .map(|peer| peer.to_string())
        .unwrap_or_default()
}

fn validate_message_bytes(bytes: &[u8]) -> Result<(), NetworkError> {
    if bytes.is_empty() {
        Err(NetworkError::EmptyMessage)
    } else if bytes.len() > MAX_MESSAGE_BYTES {
        Err(NetworkError::MessageTooLarge {
            max: MAX_MESSAGE_BYTES,
        })
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    keypair: libp2p::identity::Keypair,
    config: NetworkConfig,
    mut commands: tokio_mpsc::Receiver<Command>,
    events: tokio_mpsc::Sender<ConnectionState>,
    message_events: tokio_mpsc::Sender<MessageEvent>,
    setup_events: tokio_mpsc::Sender<SetupEvent>,
    file_events: tokio_mpsc::Sender<FileEvent>,
    control_events: tokio_mpsc::Sender<ControlEvent>,
    discovery_events: tokio_mpsc::Sender<DiscoveryEvent>,
    relay_events: tokio_mpsc::Sender<RelayEvent>,
    nat_events: tokio_mpsc::Sender<NatEvent>,
    identify_events: tokio_mpsc::Sender<IdentifyEvent>,
    startup: mpsc::Sender<Startup>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = startup.send(Startup::Error(error.to_string()));
            return;
        }
    };

    runtime.block_on(async move {
        let mut swarm = match build_swarm(&keypair, &config, &discovery_events) {
            Ok(swarm) => swarm,
            Err(error) => {
                let _ = startup.send(Startup::Error(error));
                return;
            }
        };

        if let Err(error) = swarm.listen_on(config.listen_addr.clone()) {
            let _ = startup.send(Startup::Error(error.to_string()));
            return;
        }

        // Optional capabilities are applied only at worker startup. Only peers
        // whose addresses the local user supplied may be contacted here.
        if config.enable_kad
            && let Some(kad) = swarm.behaviour_mut().kad.as_mut()
        {
            for address in &config.kad_bootstrap_peers {
                if let Some(peer) = peer_from_address(address) {
                    kad.add_address(&peer, address.clone());
                }
            }
            match kad.bootstrap() {
                Ok(query) => emit_discovery(
                    &discovery_events,
                    DiscoveryEvent::KadBootstrapStarted {
                        query_id: query.to_string().parse().unwrap_or(0),
                    },
                ),
                Err(_) => emit_discovery(
                    &discovery_events,
                    DiscoveryEvent::Failed {
                        source: DiscoverySource::Kad,
                        reason: "bootstrap could not start".to_owned(),
                    },
                ),
            }
        }
        if config.relay_mode == RelayMode::Client {
            for address in &config.relay_servers {
                let mut circuit_address = address.clone();
                circuit_address.push(Protocol::P2pCircuit);
                if let Err(error) = swarm.listen_on(circuit_address) {
                    let _ = error;
                    emit_relay(
                        &relay_events,
                        RelayEvent::Failed {
                            reason: "relay reservation could not start".to_owned(),
                        },
                    );
                }
            }
        }

        let limits = ConnectionLimits::from_config(&config);
        let mut rate_limiter = RateLimiter::new(&config);
        let mut addresses = Vec::new();
        let mut connected: BTreeSet<PeerId> = BTreeSet::new();
        let mut expected_peers: BTreeSet<PeerId> = BTreeSet::new();
        let mut total_connections = 0usize;
        let mut ip_connections: HashMap<IpKey, usize> = HashMap::new();
        let mut rejected_connections: HashSet<ConnectionId> = HashSet::new();
        let mut relayed_connections: HashSet<ConnectionId> = HashSet::new();
        let mut relayed_peers: HashMap<PeerId, usize> = HashMap::new();
        let mut next_response_id = 1u64;
        let mut outbound_ids: HashMap<MessageRequestId, OutboundRequestId> = HashMap::new();
        let mut outbound_by_swarm: HashMap<OutboundRequestId, MessageRequestId> = HashMap::new();
        let mut pending_responses: HashMap<
            MessageResponseId,
            (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
        > = HashMap::new();
        let mut inbound_by_swarm: HashMap<InboundRequestId, MessageResponseId> = HashMap::new();

        let mut next_setup_response_id = 1u64;
        let mut setup_outbound_ids: HashMap<SetupRequestId, OutboundRequestId> = HashMap::new();
        let mut setup_outbound_by_swarm: HashMap<OutboundRequestId, SetupRequestId> =
            HashMap::new();
        let mut pending_setup_responses: HashMap<
            SetupResponseId,
            (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
        > = HashMap::new();
        let mut setup_inbound_by_swarm: HashMap<InboundRequestId, SetupResponseId> = HashMap::new();

        let mut next_file_response_id = 1u64;
        let mut file_outbound_ids: HashMap<FileRequestId, OutboundRequestId> = HashMap::new();
        let mut file_outbound_by_swarm: HashMap<OutboundRequestId, FileRequestId> = HashMap::new();
        let mut pending_file_responses: HashMap<
            FileResponseId,
            (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
        > = HashMap::new();
        let mut file_inbound_by_swarm: HashMap<InboundRequestId, FileResponseId> = HashMap::new();

        let mut next_control_response_id = 1u64;
        let mut control_outbound_ids: HashMap<ControlRequestId, OutboundRequestId> = HashMap::new();
        let mut control_outbound_by_swarm: HashMap<OutboundRequestId, ControlRequestId> =
            HashMap::new();
        let mut pending_control_responses: HashMap<
            ControlResponseId,
            (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
        > = HashMap::new();
        let mut control_inbound_by_swarm: HashMap<InboundRequestId, ControlResponseId> =
            HashMap::new();

        let _ = startup.send(Startup::Ready);

        loop {
            tokio::select! {
                event = swarm.next() => {
                    let Some(event) = event else { break };
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            if !addresses.contains(&address) {
                                addresses.push(address);
                            }
                            emit(&events, ConnectionState::Listening {
                                addresses: addresses.clone(),
                            });
                        }
                        SwarmEvent::Dialing {
                            peer_id: Some(peer),
                            ..
                        } => {
                            emit(&events, ConnectionState::Connecting { peer });
                        }
                        SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            num_established,
                            ..
                        } => {
                            let remote_ip = ip_key(endpoint.get_remote_address());
                            let peer_count = num_established.get() as usize;
                            let ip_count = remote_ip
                                .map(|key| ip_connections.get(&key).copied().unwrap_or(0) + 1);
                            let relayed = endpoint.is_relayed();
                            if (relayed && relayed_connections.len() >= config.max_relayed_connections)
                                || limits.exceeded(total_connections + 1, peer_count, ip_count)
                            {
                                rejected_connections.insert(connection_id);
                                let _ = swarm.close_connection(connection_id);
                                emit(&events, ConnectionState::Failed {
                                    peer: Some(peer_id),
                                    reason: if relayed {
                                        "relayed connection limit exceeded".to_owned()
                                    } else {
                                        "connection limit exceeded".to_owned()
                                    },
                                });
                                if relayed {
                                    emit_relay(&relay_events, RelayEvent::Failed {
                                        reason: "relayed connection limit exceeded".to_owned(),
                                    });
                                }
                                continue;
                            }
                            expected_peers.remove(&peer_id);
                            total_connections += 1;
                            if let Some(key) = remote_ip {
                                *ip_connections.entry(key).or_default() += 1;
                            }
                            connected.insert(peer_id);
                            if relayed {
                                relayed_connections.insert(connection_id);
                                let count = relayed_peers.entry(peer_id).or_default();
                                *count = count.saturating_add(1);
                                emit_relay(&relay_events, RelayEvent::RelayedConnectionsChanged {
                                    count: relayed_connections.len(),
                                });
                            }
                            emit_connected(&events, &connected);
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            connection_id,
                            endpoint,
                            num_established,
                            ..
                        } => {
                            if relayed_connections.remove(&connection_id) {
                                let entry = relayed_peers.entry(peer_id).or_default();
                                *entry = entry.saturating_sub(1);
                                if *entry == 0 {
                                    relayed_peers.remove(&peer_id);
                                }
                                emit_relay(&relay_events, RelayEvent::RelayedConnectionsChanged {
                                    count: relayed_connections.len(),
                                });
                            }
                            if rejected_connections.remove(&connection_id) {
                                continue;
                            }
                            total_connections = total_connections.saturating_sub(1);
                            if let Some(key) = ip_key(endpoint.get_remote_address()) {
                                let entry = ip_connections.entry(key).or_default();
                                *entry = entry.saturating_sub(1);
                                if *entry == 0 {
                                    ip_connections.remove(&key);
                                }
                            }
                            if num_established == 0 {
                                connected.remove(&peer_id);
                            }
                            if connected.is_empty() {
                                emit(&events, ConnectionState::Disconnected { peer: peer_id });
                            } else {
                                emit_connected(&events, &connected);
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            if let Some(peer) = peer_id {
                                expected_peers.remove(&peer);
                            }
                            emit(&events, ConnectionState::Failed {
                                peer: peer_id,
                                reason: truncate_reason(&error.to_string()),
                            });
                        }
                        SwarmEvent::ListenerError { error, .. } => {
                            emit(&events, ConnectionState::Failed {
                                peer: None,
                                reason: truncate_reason(&error.to_string()),
                            });
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Messages(event)) => {
                            if let Some((peer, bytes)) = denied_request(&event)
                                && !rate_limiter.allow(peer, bytes, Instant::now())
                            {
                                let raw = next_response_id;
                                next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                                emit_message(&message_events, MessageEvent::Failed {
                                    request_id: None,
                                    response_id: Some(MessageResponseId(raw)),
                                    peer,
                                    reason: "peer request rate limit exceeded".to_owned(),
                                });
                                continue;
                            }
                            handle_message_event(
                                event,
                                &mut next_response_id,
                                &mut outbound_ids,
                                &mut outbound_by_swarm,
                                &mut pending_responses,
                                &mut inbound_by_swarm,
                                &message_events,
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Setup(event)) => {
                            if let Some((peer, bytes)) = denied_request(&event)
                                && !rate_limiter.allow(peer, bytes, Instant::now())
                            {
                                let raw = next_setup_response_id;
                                next_setup_response_id =
                                    next_setup_response_id.checked_add(1).unwrap_or(1);
                                emit_setup(&setup_events, SetupEvent::Failed {
                                    request_id: None,
                                    response_id: Some(SetupResponseId(raw)),
                                    peer,
                                    reason: "peer request rate limit exceeded".to_owned(),
                                });
                                continue;
                            }
                            handle_setup_event(
                                event,
                                &mut next_setup_response_id,
                                &mut setup_outbound_ids,
                                &mut setup_outbound_by_swarm,
                                &mut pending_setup_responses,
                                &mut setup_inbound_by_swarm,
                                &setup_events,
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Files(event)) => {
                            if let Some((peer, bytes)) = denied_request(&event)
                                && !rate_limiter.allow(peer, bytes, Instant::now())
                            {
                                let raw = next_file_response_id;
                                next_file_response_id =
                                    next_file_response_id.checked_add(1).unwrap_or(1);
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: None,
                                    response_id: Some(FileResponseId(raw)),
                                    peer,
                                    reason: "peer request rate limit exceeded".to_owned(),
                                });
                                continue;
                            }
                            handle_file_event(
                                event,
                                &mut next_file_response_id,
                                &mut file_outbound_ids,
                                &mut file_outbound_by_swarm,
                                &mut pending_file_responses,
                                &mut file_inbound_by_swarm,
                                &file_events,
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Control(event)) => {
                            if let Some((peer, bytes)) = denied_request(&event)
                                && !rate_limiter.allow(peer, bytes, Instant::now())
                            {
                                let raw = next_control_response_id;
                                next_control_response_id =
                                    next_control_response_id.checked_add(1).unwrap_or(1);
                                emit_control(&control_events, ControlEvent::Failed {
                                    request_id: None,
                                    response_id: Some(ControlResponseId(raw)),
                                    peer,
                                    reason: "peer request rate limit exceeded".to_owned(),
                                });
                                continue;
                            }
                            handle_control_event(
                                event,
                                &mut next_control_response_id,
                                &mut control_outbound_ids,
                                &mut control_outbound_by_swarm,
                                &mut pending_control_responses,
                                &mut control_inbound_by_swarm,
                                &control_events,
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => match event {
                            identify::Event::Received {
                                peer_id, info, ..
                            } => emit_identify(
                                &identify_events,
                                IdentifyEvent::Identified {
                                    peer: peer_id,
                                    protocol_version: privacy::bounded_text(
                                        &info.protocol_version,
                                        64,
                                    ),
                                    agent_version: privacy::bounded_text(&info.agent_version, 64),
                                    protocol_count: info.protocols.len(),
                                    listen_address_count: info.listen_addrs.len(),
                                },
                            ),
                            identify::Event::Error { peer_id, .. } => emit_identify(
                                &identify_events,
                                IdentifyEvent::Failed {
                                    peer: peer_id,
                                    reason: "identify exchange failed".to_owned(),
                                },
                            ),
                            _ => {}
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Ping(_)) => {}
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(event)) => match event {
                            mdns::Event::Discovered(peers) => {
                                for (peer, address) in peers {
                                    emit_discovery(
                                        &discovery_events,
                                        DiscoveryEvent::Discovered {
                                            source: DiscoverySource::Mdns,
                                            peer,
                                            address,
                                        },
                                    );
                                }
                            }
                            mdns::Event::Expired(peers) => {
                                for (peer, address) in peers {
                                    emit_discovery(
                                        &discovery_events,
                                        DiscoveryEvent::Expired {
                                            source: DiscoverySource::Mdns,
                                            peer,
                                            address,
                                        },
                                    );
                                }
                            }
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => match event {
                            kad::Event::OutboundQueryProgressed { id, result, .. }
                                if matches!(result, kad::QueryResult::Bootstrap(_)) =>
                            {
                                let outcome = match result {
                                    kad::QueryResult::Bootstrap(Ok(_)) => "ok",
                                    kad::QueryResult::Bootstrap(Err(_)) => "timeout",
                                    _ => unreachable!(),
                                };
                                emit_discovery(
                                    &discovery_events,
                                    DiscoveryEvent::KadBootstrapFinished {
                                        query_id: id.to_string().parse().unwrap_or(0),
                                        result: outcome.to_owned(),
                                    },
                                );
                            }
                            kad::Event::RoutingUpdated {
                                peer, addresses, ..
                            } => emit_discovery(
                                &discovery_events,
                                DiscoveryEvent::Discovered {
                                    source: DiscoverySource::Kad,
                                    peer,
                                    address: addresses.first().clone(),
                                },
                            ),
                            kad::Event::UnroutablePeer { .. } | kad::Event::ModeChanged { .. } => {}
                            _ => {}
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => match event {
                            relay::client::Event::ReservationReqAccepted {
                                relay_peer_id, ..
                            } => emit_relay(
                                &relay_events,
                                RelayEvent::ReservationAccepted { relay: relay_peer_id },
                            ),
                            relay::client::Event::OutboundCircuitEstablished {
                                relay_peer_id, ..
                            } => emit_relay(
                                &relay_events,
                                RelayEvent::OutboundCircuitEstablished { relay: relay_peer_id },
                            ),
                            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                                emit_relay(
                                    &relay_events,
                                    RelayEvent::InboundCircuitEstablished {
                                        source: src_peer_id,
                                    },
                                )
                            }
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::RelayServer(event)) => match event {
                            relay::Event::ReservationReqAccepted { src_peer_id, .. } => emit_relay(
                                &relay_events,
                                RelayEvent::ServerReservationAccepted { source: src_peer_id },
                            ),
                            relay::Event::CircuitReqAccepted {
                                src_peer_id,
                                dst_peer_id,
                            } => emit_relay(
                                &relay_events,
                                RelayEvent::ServerCircuitAccepted {
                                    source: src_peer_id,
                                    destination: dst_peer_id,
                                },
                            ),
                            _ => {}
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Autonat(
                            autonat::v1::Event::StatusChanged { new, .. },
                        )) => {
                            let (status, address) = match new {
                                autonat::v1::NatStatus::Public(address) => {
                                    ("Public".to_owned(), Some(address))
                                }
                                autonat::v1::NatStatus::Private => ("Private".to_owned(), None),
                                autonat::v1::NatStatus::Unknown => ("Unknown".to_owned(), None),
                            };
                            emit_nat(
                                &nat_events,
                                NatEvent::StatusChanged {
                                    status,
                                    address,
                                    confidence: 0,
                                },
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => emit_nat(
                            &nat_events,
                            NatEvent::HolePunch {
                                peer: event.remote_peer_id,
                                succeeded: event.result.is_ok(),
                                reason: if event.result.is_ok() {
                                    "hole punch established a direct connection".to_owned()
                                } else {
                                    "hole punch did not establish a direct connection".to_owned()
                                },
                            },
                        ),
                        _ => {}
                    }
                }
                command = commands.recv() => {
                    match command {
                        Some(Command::Dial { address, expected }) => {
                            expected_peers.insert(expected);
                            match swarm.dial(address) {
                                Ok(()) => {}
                                Err(error) => {
                                    expected_peers.remove(&expected);
                                    emit(&events, ConnectionState::Failed {
                                        peer: Some(expected),
                                        reason: truncate_reason(&error.to_string()),
                                    });
                                }
                            }
                        }
                        Some(Command::SendMessage { id, peer, bytes }) => {
                            if !connected.contains(&peer) {
                                emit_message(&message_events, MessageEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "peer is not connected".to_owned(),
                                });
                                continue;
                            }
                            let swarm_id =
                                swarm.behaviour_mut().messages.send_request(&peer, bytes);
                            outbound_ids.insert(id, swarm_id);
                            outbound_by_swarm.insert(swarm_id, id);
                            emit_message(&message_events, MessageEvent::SentToPeer {
                                request_id: id,
                                peer,
                            });
                        }
                        Some(Command::RespondMessage { id, bytes }) => {
                            match pending_responses.remove(&id) {
                                Some((peer, inbound_id, channel)) => {
                                    inbound_by_swarm.remove(&inbound_id);
                                    if swarm
                                        .behaviour_mut()
                                        .messages
                                        .send_response(channel, bytes)
                                        .is_err()
                                    {
                                        emit_message(&message_events, MessageEvent::Failed {
                                            request_id: None,
                                            response_id: Some(id),
                                            peer,
                                            reason: "response channel is closed".to_owned(),
                                        });
                                    }
                                }
                                None => {
                                    emit_message(&message_events, MessageEvent::Failed {
                                        request_id: None,
                                        response_id: Some(id),
                                        peer: *swarm.local_peer_id(),
                                        reason: "unknown response identifier".to_owned(),
                                    });
                                }
                            }
                        }
                        Some(Command::SendSetup { id, peer, bytes }) => {
                            if !connected.contains(&peer) {
                                emit_setup(&setup_events, SetupEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "peer is not connected".to_owned(),
                                });
                                continue;
                            }
                            let swarm_id =
                                swarm.behaviour_mut().setup.send_request(&peer, bytes);
                            setup_outbound_ids.insert(id, swarm_id);
                            setup_outbound_by_swarm.insert(swarm_id, id);
                            emit_setup(&setup_events, SetupEvent::SentToPeer {
                                request_id: id,
                                peer,
                            });
                        }
                        Some(Command::RespondSetup { id, bytes }) => {
                            match pending_setup_responses.remove(&id) {
                                Some((peer, inbound_id, channel)) => {
                                    setup_inbound_by_swarm.remove(&inbound_id);
                                    if swarm
                                        .behaviour_mut()
                                        .setup
                                        .send_response(channel, bytes)
                                        .is_err()
                                    {
                                        emit_setup(&setup_events, SetupEvent::Failed {
                                            request_id: None,
                                            response_id: Some(id),
                                            peer,
                                            reason: "response channel is closed".to_owned(),
                                        });
                                    }
                                }
                                None => {
                                    emit_setup(&setup_events, SetupEvent::Failed {
                                        request_id: None,
                                        response_id: Some(id),
                                        peer: *swarm.local_peer_id(),
                                        reason: "unknown response identifier".to_owned(),
                                    });
                                }
                            }
                        }
                        Some(Command::SendFile { id, peer, bytes }) => {
                            if !connected.contains(&peer) {
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "peer is not connected".to_owned(),
                                });
                                continue;
                            }
                            // The signed file offer currently carries the fresh
                            // content key. A relay operator would see that
                            // offer, so file transfer is refused on relayed
                            // paths until a separate E2E key exchange exists.
                            if relayed_peers.get(&peer).copied().unwrap_or(0) > 0 {
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "file transfer over a relay is disabled by policy"
                                        .to_owned(),
                                });
                                continue;
                            }
                            let swarm_id =
                                swarm.behaviour_mut().files.send_request(&peer, bytes);
                            file_outbound_ids.insert(id, swarm_id);
                            file_outbound_by_swarm.insert(swarm_id, id);
                            emit_file(&file_events, FileEvent::SentToPeer {
                                request_id: id,
                                peer,
                            });
                        }
                        Some(Command::RespondFile { id, bytes }) => {
                            match pending_file_responses.remove(&id) {
                                Some((peer, inbound_id, channel)) => {
                                    file_inbound_by_swarm.remove(&inbound_id);
                                    if swarm
                                        .behaviour_mut()
                                        .files
                                        .send_response(channel, bytes)
                                        .is_err()
                                    {
                                        emit_file(&file_events, FileEvent::Failed {
                                            request_id: None,
                                            response_id: Some(id),
                                            peer,
                                            reason: "response channel is closed".to_owned(),
                                        });
                                    }
                                }
                                None => {
                                    emit_file(&file_events, FileEvent::Failed {
                                        request_id: None,
                                        response_id: Some(id),
                                        peer: *swarm.local_peer_id(),
                                        reason: "unknown response identifier".to_owned(),
                                    });
                                }
                            }
                        }
                        Some(Command::SendControl { id, peer, bytes }) => {
                            if !connected.contains(&peer) {
                                emit_control(&control_events, ControlEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "peer is not connected".to_owned(),
                                });
                                continue;
                            }
                            let swarm_id =
                                swarm.behaviour_mut().control.send_request(&peer, bytes);
                            control_outbound_ids.insert(id, swarm_id);
                            control_outbound_by_swarm.insert(swarm_id, id);
                            emit_control(&control_events, ControlEvent::SentToPeer {
                                request_id: id,
                                peer,
                            });
                        }
                        Some(Command::RespondControl { id, bytes }) => {
                            match pending_control_responses.remove(&id) {
                                Some((peer, inbound_id, channel)) => {
                                    control_inbound_by_swarm.remove(&inbound_id);
                                    if swarm
                                        .behaviour_mut()
                                        .control
                                        .send_response(channel, bytes)
                                        .is_err()
                                    {
                                        emit_control(&control_events, ControlEvent::Failed {
                                            request_id: None,
                                            response_id: Some(id),
                                            peer,
                                            reason: "response channel is closed".to_owned(),
                                        });
                                    }
                                }
                                None => {
                                    emit_control(&control_events, ControlEvent::Failed {
                                        request_id: None,
                                        response_id: Some(id),
                                        peer: *swarm.local_peer_id(),
                                        reason: "unknown response identifier".to_owned(),
                                    });
                                }
                            }
                        }
                        Some(Command::DisconnectAll) => {
                            for peer in connected.iter().copied().collect::<Vec<_>>() {
                                let _ = swarm.disconnect_peer_id(peer);
                            }
                        }
                        Some(Command::Shutdown) | None => break,
                    }
                }
            }
        }
    });
}

fn build_swarm(
    keypair: &libp2p::identity::Keypair,
    config: &NetworkConfig,
    discovery_events: &tokio_mpsc::Sender<DiscoveryEvent>,
) -> Result<Swarm<Behaviour>, String> {
    let local_peer_id = keypair.public().to_peer_id();
    let connection_timeout = config.connection_timeout;

    let mdns = if config.enable_mdns {
        match mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id) {
            Ok(behaviour) => Some(behaviour),
            Err(_) => {
                emit_discovery(
                    discovery_events,
                    DiscoveryEvent::Failed {
                        source: DiscoverySource::Mdns,
                        reason: "mDNS initialization failed".to_owned(),
                    },
                );
                None
            }
        }
    } else {
        None
    };

    let mut kad_config = kad::Config::default();
    kad_config.set_publication_interval(None);
    kad_config.set_provider_publication_interval(None);
    kad_config.set_replication_interval(None);
    kad_config.set_periodic_bootstrap_interval(None);
    kad_config.set_caching(kad::Caching::Disabled);

    let relay_config = relay::Config {
        max_circuits: config.max_relayed_connections,
        max_circuits_per_peer: config.max_relayed_connections.max(1),
        max_circuit_bytes: (MAX_MESSAGE_BYTES * 8) as u64,
        ..Default::default()
    }
    .reservation_rate_per_peer(
        NonZeroU32::new(2).expect("literal is non-zero"),
        Duration::from_secs(60),
    )
    .circuit_src_per_peer(
        NonZeroU32::new(2).expect("literal is non-zero"),
        Duration::from_secs(60),
    );

    let autonat_config = autonat::v1::Config {
        boot_delay: Duration::from_secs(30),
        retry_interval: Duration::from_secs(300),
        refresh_interval: Duration::from_secs(15 * 60),
        use_connected: true,
        confidence_max: 2,
        ..autonat::v1::Config::default()
    };

    let identify_config = config.enable_identify.then(|| {
        identify::Config::new("p2p-messenger/1".to_owned(), keypair.public())
            .with_agent_version("p2p-messenger".to_owned())
            .with_interval(Duration::from_secs(60 * 60))
            .with_push_listen_addr_updates(false)
            .with_hide_listen_addrs(true)
    });
    let ping_config = ping::Config::default()
        .with_interval(Duration::from_secs(60))
        .with_timeout(Duration::from_secs(10));

    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|error| error.to_string())?
        // The relay transport is present so client behaviour can be opted in.
        // With the behaviour toggled off it never dials or listens on a relay.
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .map_err(|error| error.to_string())?
        .with_behaviour(|key, relay_client| Behaviour {
            messages: request_response::Behaviour::new(
                [(MESSAGE_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(connection_timeout)
                    .with_max_concurrent_streams(4),
            ),
            setup: request_response::Behaviour::new(
                [(MLS_SETUP_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(connection_timeout)
                    .with_max_concurrent_streams(4),
            ),
            files: request_response::Behaviour::new(
                [(FILE_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(connection_timeout)
                    .with_max_concurrent_streams(4),
            ),
            control: request_response::Behaviour::new(
                [(CONTROL_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(connection_timeout)
                    .with_max_concurrent_streams(4),
            ),
            identify: identify_config.map(identify::Behaviour::new).into(),
            ping: config
                .enable_ping
                .then(|| ping::Behaviour::new(ping_config))
                .into(),
            mdns: mdns.into(),
            kad: config
                .enable_kad
                .then(|| {
                    kad::Behaviour::with_config(
                        local_peer_id,
                        kad::store::MemoryStore::new(local_peer_id),
                        kad_config,
                    )
                })
                .into(),
            relay_client: (config.relay_mode == RelayMode::Client)
                .then_some(relay_client)
                .into(),
            relay_server: (config.relay_mode == RelayMode::Server)
                .then(|| relay::Behaviour::new(key.public().to_peer_id(), relay_config))
                .into(),
            autonat: config
                .enable_autonat
                .then(|| autonat::v1::Behaviour::new(local_peer_id, autonat_config))
                .into(),
            dcutr: config
                .enable_dcutr
                .then(|| dcutr::Behaviour::new(local_peer_id))
                .into(),
        })
        .map_err(|error| error.to_string())?
        .with_swarm_config(std::convert::identity)
        .with_connection_timeout(connection_timeout)
        .build();
    Ok(swarm)
}

#[allow(clippy::too_many_arguments)]
fn handle_message_event(
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    next_response_id: &mut u64,
    outbound_ids: &mut HashMap<MessageRequestId, OutboundRequestId>,
    outbound_by_swarm: &mut HashMap<OutboundRequestId, MessageRequestId>,
    pending_responses: &mut HashMap<
        MessageResponseId,
        (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
    >,
    inbound_by_swarm: &mut HashMap<InboundRequestId, MessageResponseId>,
    events: &tokio_mpsc::Sender<MessageEvent>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request_id,
                request,
                channel,
            } => {
                let raw = *next_response_id;
                *next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                let response_id = MessageResponseId(raw);
                pending_responses.insert(response_id, (peer, request_id, channel));
                inbound_by_swarm.insert(request_id, response_id);
                emit_message(
                    events,
                    MessageEvent::RequestReceived {
                        response_id,
                        peer,
                        bytes: request,
                    },
                );
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(id) = outbound_by_swarm.remove(&request_id) {
                    outbound_ids.remove(&id);
                    emit_message(
                        events,
                        MessageEvent::ResponseReceived {
                            request_id: id,
                            peer,
                            bytes: response,
                        },
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = outbound_by_swarm.remove(&request_id) {
                outbound_ids.remove(&id);
                emit_message(
                    events,
                    MessageEvent::Failed {
                        request_id: Some(id),
                        response_id: None,
                        peer,
                        reason: outbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = inbound_by_swarm.remove(&request_id) {
                pending_responses.remove(&id);
                emit_message(
                    events,
                    MessageEvent::Failed {
                        request_id: None,
                        response_id: Some(id),
                        peer,
                        reason: inbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_setup_event(
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    next_response_id: &mut u64,
    outbound_ids: &mut HashMap<SetupRequestId, OutboundRequestId>,
    outbound_by_swarm: &mut HashMap<OutboundRequestId, SetupRequestId>,
    pending_responses: &mut HashMap<
        SetupResponseId,
        (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
    >,
    inbound_by_swarm: &mut HashMap<InboundRequestId, SetupResponseId>,
    events: &tokio_mpsc::Sender<SetupEvent>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request_id,
                request,
                channel,
            } => {
                let raw = *next_response_id;
                *next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                let response_id = SetupResponseId(raw);
                pending_responses.insert(response_id, (peer, request_id, channel));
                inbound_by_swarm.insert(request_id, response_id);
                emit_setup(
                    events,
                    SetupEvent::RequestReceived {
                        response_id,
                        peer,
                        bytes: request,
                    },
                );
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(id) = outbound_by_swarm.remove(&request_id) {
                    outbound_ids.remove(&id);
                    emit_setup(
                        events,
                        SetupEvent::ResponseReceived {
                            request_id: id,
                            peer,
                            bytes: response,
                        },
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = outbound_by_swarm.remove(&request_id) {
                outbound_ids.remove(&id);
                emit_setup(
                    events,
                    SetupEvent::Failed {
                        request_id: Some(id),
                        response_id: None,
                        peer,
                        reason: outbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = inbound_by_swarm.remove(&request_id) {
                pending_responses.remove(&id);
                emit_setup(
                    events,
                    SetupEvent::Failed {
                        request_id: None,
                        response_id: Some(id),
                        peer,
                        reason: inbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_file_event(
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    next_response_id: &mut u64,
    outbound_ids: &mut HashMap<FileRequestId, OutboundRequestId>,
    outbound_by_swarm: &mut HashMap<OutboundRequestId, FileRequestId>,
    pending_responses: &mut HashMap<
        FileResponseId,
        (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
    >,
    inbound_by_swarm: &mut HashMap<InboundRequestId, FileResponseId>,
    events: &tokio_mpsc::Sender<FileEvent>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request_id,
                request,
                channel,
            } => {
                let raw = *next_response_id;
                *next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                let response_id = FileResponseId(raw);
                pending_responses.insert(response_id, (peer, request_id, channel));
                inbound_by_swarm.insert(request_id, response_id);
                emit_file(
                    events,
                    FileEvent::RequestReceived {
                        response_id,
                        peer,
                        bytes: request,
                    },
                );
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(id) = outbound_by_swarm.remove(&request_id) {
                    outbound_ids.remove(&id);
                    emit_file(
                        events,
                        FileEvent::ResponseReceived {
                            request_id: id,
                            peer,
                            bytes: response,
                        },
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = outbound_by_swarm.remove(&request_id) {
                outbound_ids.remove(&id);
                emit_file(
                    events,
                    FileEvent::Failed {
                        request_id: Some(id),
                        response_id: None,
                        peer,
                        reason: outbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = inbound_by_swarm.remove(&request_id) {
                pending_responses.remove(&id);
                emit_file(
                    events,
                    FileEvent::Failed {
                        request_id: None,
                        response_id: Some(id),
                        peer,
                        reason: inbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_control_event(
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    next_response_id: &mut u64,
    outbound_ids: &mut HashMap<ControlRequestId, OutboundRequestId>,
    outbound_by_swarm: &mut HashMap<OutboundRequestId, ControlRequestId>,
    pending_responses: &mut HashMap<
        ControlResponseId,
        (PeerId, InboundRequestId, ResponseChannel<Vec<u8>>),
    >,
    inbound_by_swarm: &mut HashMap<InboundRequestId, ControlResponseId>,
    events: &tokio_mpsc::Sender<ControlEvent>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request_id,
                request,
                channel,
            } => {
                let raw = *next_response_id;
                *next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                let response_id = ControlResponseId(raw);
                pending_responses.insert(response_id, (peer, request_id, channel));
                inbound_by_swarm.insert(request_id, response_id);
                emit_control(
                    events,
                    ControlEvent::RequestReceived {
                        response_id,
                        peer,
                        bytes: request,
                    },
                );
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                if let Some(id) = outbound_by_swarm.remove(&request_id) {
                    outbound_ids.remove(&id);
                    emit_control(
                        events,
                        ControlEvent::ResponseReceived {
                            request_id: id,
                            peer,
                            bytes: response,
                        },
                    );
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = outbound_by_swarm.remove(&request_id) {
                outbound_ids.remove(&id);
                emit_control(
                    events,
                    ControlEvent::Failed {
                        request_id: Some(id),
                        response_id: None,
                        peer,
                        reason: outbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(id) = inbound_by_swarm.remove(&request_id) {
                pending_responses.remove(&id);
                emit_control(
                    events,
                    ControlEvent::Failed {
                        request_id: None,
                        response_id: Some(id),
                        peer,
                        reason: inbound_failure_reason(&error).to_owned(),
                    },
                );
            }
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn outbound_failure_reason(error: &request_response::OutboundFailure) -> &'static str {
    match error {
        request_response::OutboundFailure::DialFailure => "dial failed",
        request_response::OutboundFailure::Timeout => "request timed out",
        request_response::OutboundFailure::ConnectionClosed => "connection closed",
        request_response::OutboundFailure::UnsupportedProtocols => {
            "remote does not support the requested application protocol"
        }
        request_response::OutboundFailure::Io(_) => "transport I/O error",
    }
}

fn inbound_failure_reason(error: &request_response::InboundFailure) -> &'static str {
    match error {
        request_response::InboundFailure::Timeout => "inbound request timed out",
        request_response::InboundFailure::ConnectionClosed => "connection closed",
        request_response::InboundFailure::UnsupportedProtocols => "unsupported inbound protocol",
        request_response::InboundFailure::ResponseOmission => "response was not sent",
        request_response::InboundFailure::Io(_) => "transport I/O error",
    }
}

fn denied_request(event: &request_response::Event<Vec<u8>, Vec<u8>>) -> Option<(PeerId, usize)> {
    match event {
        request_response::Event::Message {
            peer,
            message: request_response::Message::Request { request, .. },
            ..
        } => Some((*peer, request.len())),
        _ => None,
    }
}

fn emit_message(events: &tokio_mpsc::Sender<MessageEvent>, event: MessageEvent) {
    // Dropping a stale projection is safe; the GUI or application can poll for
    // the latest protocol state. No message bytes are logged here.
    let _ = events.try_send(event);
}

fn emit_setup(events: &tokio_mpsc::Sender<SetupEvent>, event: SetupEvent) {
    // Dropping a stale projection is safe; setup requests are retried by the
    // application, which polls for the latest protocol state. No KeyPackage,
    // Welcome, or signature bytes are logged here.
    let _ = events.try_send(event);
}

fn emit_file(events: &tokio_mpsc::Sender<FileEvent>, event: FileEvent) {
    // Dropping a stale file projection is safe; transfer state is driven by
    // authenticated frames and local acknowledgements, not by queue pressure.
    // No file bytes or content keys are logged here.
    let _ = events.try_send(event);
}

fn emit_control(events: &tokio_mpsc::Sender<ControlEvent>, event: ControlEvent) {
    // Control frames are opaque and never written to logs by the worker.
    let _ = events.try_send(event);
}

fn emit_discovery(events: &tokio_mpsc::Sender<DiscoveryEvent>, event: DiscoveryEvent) {
    // Discovery is advisory only. Dropping an observation cannot create a
    // connection, a verified contact, or a delivery claim.
    let _ = events.try_send(event);
}

fn emit_relay(events: &tokio_mpsc::Sender<RelayEvent>, event: RelayEvent) {
    // Cache the latest observable relay facts without blocking the Swarm.
    let _ = events.try_send(event);
}

fn emit_nat(events: &tokio_mpsc::Sender<NatEvent>, event: NatEvent) {
    // NAT status is best effort. Dropping a probe result never implies reachability.
    let _ = events.try_send(event);
}

fn emit_identify(events: &tokio_mpsc::Sender<IdentifyEvent>, event: IdentifyEvent) {
    // Only bounded strings and counts are emitted; peer-provided addresses are
    // deliberately discarded.
    let _ = events.try_send(event);
}

fn emit_connected(events: &tokio_mpsc::Sender<ConnectionState>, peers: &BTreeSet<PeerId>) {
    emit(
        events,
        ConnectionState::Connected {
            peers: peers.iter().copied().collect(),
        },
    );
}

fn emit(events: &tokio_mpsc::Sender<ConnectionState>, state: ConnectionState) {
    // State is a projection; dropping stale updates is safe and prevents a
    // slow GUI from blocking the Swarm event loop.
    let _ = events.try_send(state);
}

fn truncate_reason(reason: &str) -> String {
    const MAX: usize = 160;
    match reason.char_indices().nth(MAX) {
        Some((index, _)) => format!("{}…", &reason[..index]),
        None => reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_no_bootstrap_or_relay() {
        let config = NetworkConfig::default();
        assert!(config.listen_addr.to_string().starts_with("/ip4/"));
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        assert_eq!(config.max_redial_attempts, 3);
        assert_eq!(config.max_connections_per_peer, 1);
        assert!(config.max_request_bytes_per_peer_per_window > MAX_MESSAGE_BYTES);
        assert!(!config.enable_identify);
        assert!(!config.enable_ping);
        assert!(!config.enable_mdns);
        assert!(!config.enable_kad);
        assert!(!config.enable_autonat);
        assert!(!config.enable_dcutr);
        assert!(config.kad_bootstrap_peers.is_empty());
        assert!(config.relay_servers.is_empty());
        assert_eq!(config.relay_mode, RelayMode::Off);
        assert_eq!(config.max_relayed_connections, 4);
    }

    #[test]
    fn optional_config_validation_rejects_missing_or_indirect_peers() {
        let identity = Identity::generate().expect("identity");
        let peer =
            libp2p::identity::Keypair::from_protobuf_encoding(&identity.export_keypair_bytes())
                .expect("stable keypair encoding")
                .public()
                .to_peer_id();
        let direct =
            Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")).expect("address");
        let mut circuit = direct.clone();
        circuit.push(Protocol::P2pCircuit);

        assert!(validate_config(&NetworkConfig::default()).is_ok());
        assert!(
            validate_config(&NetworkConfig {
                enable_kad: true,
                ..NetworkConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(&NetworkConfig {
                relay_mode: RelayMode::Client,
                ..NetworkConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(&NetworkConfig {
                kad_bootstrap_peers: vec![
                    Multiaddr::from_str("/ip4/127.0.0.1/tcp/4001")
                        .expect("address without peer id")
                ],
                ..NetworkConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(&NetworkConfig {
                relay_servers: vec![circuit],
                ..NetworkConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(&NetworkConfig {
                relay_mode: RelayMode::Client,
                relay_servers: vec![direct.clone()],
                max_relayed_connections: 0,
                ..NetworkConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(&NetworkConfig {
                relay_mode: RelayMode::Client,
                relay_servers: vec![direct],
                ..NetworkConfig::default()
            })
            .is_ok()
        );
        assert!(
            validate_config(&NetworkConfig {
                relay_mode: RelayMode::Server,
                ..NetworkConfig::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn connection_limits_reject_over_admission() {
        let limits = ConnectionLimits {
            max_total: 2,
            max_per_peer: 1,
            max_per_ip: 1,
        };
        assert!(!limits.exceeded(2, 1, Some(1)));
        assert!(limits.exceeded(3, 1, Some(1)));
        assert!(limits.exceeded(2, 2, Some(1)));
        assert!(limits.exceeded(2, 1, Some(2)));
        assert!(!limits.exceeded(2, 1, None));
    }

    #[test]
    fn rate_limiter_tracks_both_requests_and_bytes_per_peer() {
        let config = NetworkConfig {
            rate_window: Duration::from_secs(1),
            max_requests_per_peer_per_window: 2,
            max_request_bytes_per_peer_per_window: 10,
            ..NetworkConfig::default()
        };
        let mut limiter = RateLimiter::new(&config);
        let peer = Identity::generate().expect("identity");
        let peer_id =
            libp2p::identity::Keypair::from_protobuf_encoding(&peer.export_keypair_bytes())
                .expect("stable keypair encoding")
                .public()
                .to_peer_id();
        let now = Instant::now();

        assert!(limiter.allow(peer_id, 6, now));
        assert!(limiter.allow(peer_id, 4, now));
        assert!(!limiter.allow(peer_id, 1, now), "byte cap must be enforced");
        assert!(
            !limiter.allow(peer_id, 0, now + Duration::from_millis(500)),
            "request count cap must be enforced"
        );
        assert!(
            limiter.allow(peer_id, 1, now + Duration::from_secs(2)),
            "old entries must leave the sliding window"
        );
    }

    #[test]
    fn address_parsing_requires_a_direct_peer_id() {
        assert!(Network::parse_address("/ip4/127.0.0.1/tcp/4001").is_err());
        let identity = Identity::generate().expect("identity");
        let address = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", identity.peer_id());
        assert!(Network::parse_address(&address).is_ok());
        assert!(Network::parse_address(&format!("{address}/p2p-circuit")).is_err());
    }

    #[test]
    fn imported_keypair_preserves_the_vault_peer_id() {
        let identity = Identity::generate().expect("identity");
        let bytes = identity.export_keypair_bytes();
        let imported = libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
            .expect("stable protobuf keypair encoding");
        assert_eq!(
            imported.public().to_peer_id().to_string(),
            identity.peer_id().to_string()
        );
    }

    #[test]
    fn message_frame_bounds_are_checked_before_queueing() {
        assert_eq!(MESSAGE_PROTOCOL, "/p2p-messenger/message/1");
        assert_eq!(MLS_SETUP_PROTOCOL, "/p2p-messenger/mls-setup/1");
        assert_eq!(FILE_PROTOCOL, "/p2p-messenger/file/1");
        assert!(matches!(
            validate_message_bytes(&[]),
            Err(NetworkError::EmptyMessage)
        ));
        assert!(matches!(
            validate_message_bytes(&vec![0u8; MAX_MESSAGE_BYTES + 1]),
            Err(NetworkError::MessageTooLarge { .. })
        ));
        assert!(validate_message_bytes(b"opaque envelope").is_ok());
    }

    #[test]
    fn state_descriptions_never_claim_a_fake_connection() {
        let listening = ConnectionState::Listening { addresses: vec![] };
        assert!(listening.description().contains("no peers connected"));
        assert_eq!(ConnectionState::Unknown.connected_count(), 0);
        assert_eq!(ConnectionState::Starting.connected_count(), 0);
        let failed = ConnectionState::Failed {
            peer: None,
            reason: "dial failed".to_owned(),
        };
        assert!(failed.description().starts_with("Failed:"));
    }

    #[test]
    fn transport_event_debug_never_prints_frame_bytes() {
        let identity = Identity::generate().expect("identity");
        let peer = PeerId::from_str(&identity.peer_id().to_string()).expect("peer id");
        let bytes = vec![0xa5, 0x5a, 0xff];
        let bytes_debug = format!("{bytes:?}");

        let received = [
            format!(
                "{:?}",
                MessageEvent::RequestReceived {
                    response_id: MessageResponseId(1),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                MessageEvent::ResponseReceived {
                    request_id: MessageRequestId(2),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                SetupEvent::RequestReceived {
                    response_id: SetupResponseId(3),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                SetupEvent::ResponseReceived {
                    request_id: SetupRequestId(4),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                FileEvent::RequestReceived {
                    response_id: FileResponseId(5),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                FileEvent::ResponseReceived {
                    request_id: FileRequestId(6),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                ControlEvent::RequestReceived {
                    response_id: ControlResponseId(7),
                    peer,
                    bytes: bytes.clone(),
                }
            ),
            format!(
                "{:?}",
                ControlEvent::ResponseReceived {
                    request_id: ControlRequestId(8),
                    peer,
                    bytes,
                }
            ),
        ];

        for debug in received {
            assert!(debug.contains("bytes_len"), "{debug}");
            assert!(debug.contains("<redacted>"), "{debug}");
            assert!(!debug.contains(&bytes_debug), "{debug}");
        }
    }
}
