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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::connection_limits::{
    Behaviour as ConnectionLimitBehaviour, ConnectionLimits as Libp2pConnectionLimits,
};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Transport;
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

mod pending_admission;
mod privacy;
mod protocol;
mod socks5;

use pending_admission::PerIpPendingTransport;

pub use privacy::{
    DialPolicy, DiscoveryEvent, DiscoverySource, IdentifyEvent, NatEvent, NetworkPrivacyStatus,
    RelayEvent, RelayMode, TransportPrivacyMode,
};
pub use protocol::{
    CONTROL_PROTOCOL, FILE_PROTOCOL, LEGACY_MLS_SETUP_PROTOCOL, MAX_MESSAGE_BYTES,
    MESSAGE_PROTOCOL, MLS_SETUP_PROTOCOL, MessageCodec,
};

// The derive emits an `unreachable!()` arm for event variants that cannot occur
// with the selected behaviour set. Keep the lint allowance module-local so it
// covers the generated impls without hiding unreachable code in the rest of the
// network crate.
mod behaviour {
    #![allow(unreachable_code)]

    use super::*;

    /// Combined libp2p behaviour. The four application protocols are always
    /// present; discovery, identify, NAT, and relay behaviours are wrapped in
    /// `Toggle` and disabled unless the local user explicitly opts in at
    /// `Network::start`.
    #[derive(NetworkBehaviour)]
    pub(super) struct Behaviour {
        pub(super) messages: request_response::Behaviour<MessageCodec>,
        pub(super) setup: request_response::Behaviour<MessageCodec>,
        pub(super) files: request_response::Behaviour<MessageCodec>,
        pub(super) control: request_response::Behaviour<MessageCodec>,
        pub(super) identify: Toggle<identify::Behaviour>,
        pub(super) ping: Toggle<ping::Behaviour>,
        pub(super) mdns: Toggle<mdns::tokio::Behaviour>,
        pub(super) kad: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
        pub(super) relay_client: Toggle<relay::client::Behaviour>,
        pub(super) relay_server: Toggle<relay::Behaviour>,
        pub(super) autonat: Toggle<autonat::v1::Behaviour>,
        pub(super) dcutr: Toggle<dcutr::Behaviour>,
        // Enforces socket admission limits before Noise authentication. The
        // established-connection counters below remain authoritative for
        // per-peer/per-IP policy and relayed-path accounting.
        pub(super) connection_limits: ConnectionLimitBehaviour,
    }
}

use behaviour::{Behaviour, BehaviourEvent};

/// Errors from the direct-connect network layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network runtime failed to start: {0}")]
    Runtime(String),
    #[error("libp2p transport setup failed: {0}")]
    Transport(String),
    #[error("invalid peer address: {0}")]
    InvalidAddress(String),
    #[error("invalid network configuration: {0}")]
    InvalidConfig(String),
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

/// Shared, static reason for the conservative file-over-relay policy. It is a
/// metadata/policy choice, not a claim that a relay sees file keys or plaintext.
const FILE_RELAY_POLICY_REASON: &str = "file transfer over a relay is disabled by policy";

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
/// authenticated `ConnectionEstablished` event; raw pre-authentication sockets
/// are bounded by [`TransportLimits`] and `PerIpPendingTransport`.
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

/// Explicit libp2p pending-socket limits enforced before Noise authentication.
/// `PerIpPendingTransport` adds a per-source-IP pre-auth cap; the worker-side
/// [`ConnectionLimits`] owns established per-IP and relayed-path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransportLimits {
    max_pending_incoming: u32,
    max_pending_outgoing: u32,
    max_established_total: u32,
    max_established_per_peer: u32,
}

impl TransportLimits {
    fn from_config(config: &NetworkConfig) -> Result<Self, String> {
        let u32_value = |value: usize, name: &str| {
            u32::try_from(value).map_err(|_| format!("{name} exceeds the libp2p u32 limit"))
        };
        Ok(Self {
            max_pending_incoming: config.max_pending_incoming_connections,
            max_pending_outgoing: config.max_pending_outgoing_connections,
            max_established_total: u32_value(
                config.max_total_connections,
                "max_total_connections",
            )?,
            max_established_per_peer: u32_value(
                config.max_connections_per_peer,
                "max_connections_per_peer",
            )?,
        })
    }

    fn libp2p(self) -> Libp2pConnectionLimits {
        Libp2pConnectionLimits::default()
            .with_max_pending_incoming(Some(self.max_pending_incoming))
            .with_max_pending_outgoing(Some(self.max_pending_outgoing))
            .with_max_established(Some(self.max_established_total))
            .with_max_established_per_peer(Some(self.max_established_per_peer))
    }
}

/// Inbound application protocol family used for fair-share rate limiting.
/// Each family gets a reserved sliding window inside the aggregate per-peer
/// budget, so one saturated protocol cannot consume another protocol's share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestProtocol {
    Message,
    Setup,
    File,
    Control,
}

impl RequestProtocol {
    const ALL: [Self; 4] = [Self::Message, Self::Setup, Self::File, Self::Control];
}

/// Sliding-window budget for inbound application requests. It counts opaque
/// request bytes before the application decodes them; responses and transport
/// handshake bytes are not counted. An aggregate per-peer window remains the
/// hard ceiling, with a derived per-protocol reservation inside it.
#[derive(Debug)]
struct RateLimiter {
    window: Duration,
    max_bytes: usize,
    max_requests: u32,
    max_protocol_bytes: usize,
    max_protocol_requests: u32,
    entries: HashMap<PeerId, VecDeque<(Instant, usize)>>,
    protocol_entries: HashMap<(PeerId, RequestProtocol), VecDeque<(Instant, usize)>>,
}

impl RateLimiter {
    fn new(config: &NetworkConfig) -> Self {
        let protocol_count = RequestProtocol::ALL.len();
        let protocol_count_u32 = protocol_count as u32;
        let max_protocol_requests = if config.max_requests_per_peer_per_window == 0 {
            0
        } else {
            let requested = config.max_requests_per_peer_per_window;
            // Preserve a small meaningful burst for each protocol even when
            // the aggregate ceiling is below four requests; never let the
            // reservation exceed that ceiling.
            let minimum = requested.min(2);
            requested
                .saturating_add(protocol_count_u32 - 1)
                .saturating_div(protocol_count_u32)
                .max(minimum)
                .min(requested)
        };
        // Keep a full frame available per protocol whenever the configured
        // aggregate ceiling is large enough. Small custom ceilings fall back
        // to the aggregate byte cap; the aggregate window is always enforced.
        let max_protocol_bytes = (config.max_request_bytes_per_peer_per_window / protocol_count)
            .max(MAX_MESSAGE_BYTES)
            .min(config.max_request_bytes_per_peer_per_window);
        Self {
            window: config.rate_window,
            max_bytes: config.max_request_bytes_per_peer_per_window,
            max_requests: config.max_requests_per_peer_per_window,
            max_protocol_bytes,
            max_protocol_requests,
            entries: HashMap::new(),
            protocol_entries: HashMap::new(),
        }
    }

    fn allow(
        &mut self,
        peer: PeerId,
        protocol: RequestProtocol,
        bytes: usize,
        now: Instant,
    ) -> bool {
        // Sweep every expired history, not only the current peer's: otherwise
        // distinct-peer churn could grow either map forever. A peer whose
        // window has fully elapsed has no effect on any current limit, and an
        // empty entry must never remain after `retain`.
        for entry in self.entries.values_mut() {
            entry.retain(|(seen, _)| now.saturating_duration_since(*seen) < self.window);
        }
        for entry in self.protocol_entries.values_mut() {
            entry.retain(|(seen, _)| now.saturating_duration_since(*seen) < self.window);
        }
        self.entries.retain(|_, entry| !entry.is_empty());
        self.protocol_entries.retain(|_, entry| !entry.is_empty());

        let protocol_key = (peer, protocol);
        // Check both windows before recording either one. A rejected request
        // must not consume another protocol's aggregate capacity.
        if !Self::fits(
            self.entries.get(&peer),
            bytes,
            self.max_requests,
            self.max_bytes,
        ) || !Self::fits(
            self.protocol_entries.get(&protocol_key),
            bytes,
            self.max_protocol_requests,
            self.max_protocol_bytes,
        ) {
            return false;
        }
        Self::record(&mut self.entries, peer, bytes, now);
        Self::record(&mut self.protocol_entries, protocol_key, bytes, now);
        true
    }

    fn fits(
        entry: Option<&VecDeque<(Instant, usize)>>,
        bytes: usize,
        max_requests: u32,
        max_bytes: usize,
    ) -> bool {
        let Some(entry) = entry else {
            return max_requests > 0 && bytes <= max_bytes;
        };
        let seen_bytes = entry
            .iter()
            .fold(0usize, |sum, (_, bytes)| sum.saturating_add(*bytes));
        (entry.len() as u32) < max_requests && seen_bytes.saturating_add(bytes) <= max_bytes
    }

    fn record<K: Eq + std::hash::Hash>(
        entries: &mut HashMap<K, VecDeque<(Instant, usize)>>,
        key: K,
        bytes: usize,
        now: Instant,
    ) {
        entries.entry(key).or_default().push_back((now, bytes));
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

impl SetupRequestId {
    /// Construct a local transport request identifier. Inbound identifiers are
    /// normally produced by the swarm worker; this supports explicit event
    /// construction in tests and adapters.
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }
}

/// Local identifier for one inbound MLS setup request awaiting a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetupResponseId(u64);

impl SetupResponseId {
    /// Construct a local transport response identifier. Inbound identifiers
    /// are normally produced by the swarm worker; this supports explicit event
    /// construction in tests and adapters.
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }
}

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
    /// Hard cap on simultaneous established or pre-authentication connections
    /// from one observed IP address. Pre-auth slots are released when the
    /// Noise/Yamux upgrade completes or is dropped.
    pub max_connections_per_ip: usize,
    /// Hard cap on concurrent inbound sockets before Noise authentication.
    pub max_pending_incoming_connections: u32,
    /// Hard cap on concurrent outbound sockets before Noise authentication.
    pub max_pending_outgoing_connections: u32,
    /// Maximum inbound application requests from one peer per rate window.
    pub max_requests_per_peer_per_window: u32,
    /// Maximum inbound application request bytes from one peer per rate window.
    pub max_request_bytes_per_peer_per_window: usize,
    /// Sliding window used by the per-peer request and byte limits.
    pub rate_window: Duration,

    /// Requested transport route. `TorRequired` means all dials go through the
    /// configured SOCKS5 proxy; startup fails closed without one.
    pub transport_mode: TransportPrivacyMode,
    /// IP literal and port of a local SOCKS5 proxy. Hostnames are rejected so
    /// proxy selection cannot trigger a local DNS lookup.
    pub socks5_proxy: Option<SocketAddr>,
    /// Route classes allowed for application traffic. `RelayOnly` rejects
    /// direct dials and direct inbound application connections; it is a local
    /// policy, not proof that a relay path exists.
    pub dial_policy: DialPolicy,
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
            max_pending_incoming_connections: 16,
            max_pending_outgoing_connections: 16,
            max_requests_per_peer_per_window: 64,
            max_request_bytes_per_peer_per_window: 16 * MAX_MESSAGE_BYTES,
            rate_window: Duration::from_secs(1),
            transport_mode: TransportPrivacyMode::Direct,
            socks5_proxy: None,
            dial_policy: DialPolicy::DirectAllowed,
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
    dial_policy: DialPolicy,
    relay_servers: Vec<Multiaddr>,
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
        let dial_policy = config.dial_policy;
        let relay_servers = config.relay_servers.clone();
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
                dial_policy,
                relay_servers,
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
    ///
    /// Under `DialPolicy::DirectAllowed` this accepts only direct addresses.
    /// Under `DialPolicy::RelayOnly` it accepts only circuit addresses built
    /// from a configured relay; direct application dials fail closed.
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), NetworkError> {
        let expected = match self.dial_policy {
            DialPolicy::DirectAllowed => {
                validate_direct_peer_address(&address)?;
                peer_from_address(&address).ok_or_else(|| {
                    NetworkError::InvalidAddress("address has no /p2p/<peer-id>".to_owned())
                })?
            }
            DialPolicy::RelayOnly => {
                if !address
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
                {
                    return Err(NetworkError::InvalidConfig(
                        "relay-only policy rejects direct dials".to_owned(),
                    ));
                }
                validate_relayed_peer_address(&address, &self.relay_servers)?
            }
        };
        self.queue_dial(address, expected)
    }

    /// Address used to reach a PeerId through the first configured relay. This
    /// never proves the destination is reachable or that a relay is online.
    pub fn relayed_address(&self, peer: PeerId) -> Result<Multiaddr, NetworkError> {
        if self.dial_policy != DialPolicy::RelayOnly {
            return Err(NetworkError::InvalidConfig(
                "relayed addresses require relay-only policy".to_owned(),
            ));
        }
        let relay = self.relay_servers.first().ok_or_else(|| {
            NetworkError::InvalidConfig("relay-only policy requires a configured relay".to_owned())
        })?;
        Ok(relayed_peer_address(relay, peer))
    }

    /// Queue a dial through a configured relay to a destination PeerId. This
    /// avoids asking the user to hand-assemble a circuit multiaddr.
    pub fn dial_relayed(&mut self, peer: PeerId) -> Result<(), NetworkError> {
        let address = self.relayed_address(peer)?;
        self.queue_dial(address, peer)
    }

    fn queue_dial(&mut self, address: Multiaddr, expected: PeerId) -> Result<(), NetworkError> {
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
    ///
    /// With pinned libp2p 0.56 the relay client transport uses the same Noise
    /// security upgrade as direct TCP, so a relay forwards opaque Noise bytes
    /// and cannot read application plaintext or the file content key. It can
    /// still observe PeerIds, IPs, timing, and sizes. File transfer is
    /// conservatively disabled on observed relayed paths pending a dedicated
    /// relay-safe file-key/transport design.
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
                // A peerless transport failure (for example a rejected inbound
                // socket) is advisory: the caller still receives it, but it
                // must not erase live authenticated connections from the
                // cached state used to decide whether peers are reachable.
                if !matches!(&state, ConnectionState::Failed { peer: None, .. }) {
                    self.state = state.clone();
                }
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

/// Split a libp2p circuit address into its configured relay prefix and the
/// destination PeerId after `/p2p-circuit`. Exactly one circuit marker and one
/// destination component are accepted; anything else fails closed.
fn relay_circuit_parts(address: &Multiaddr) -> Result<(Multiaddr, PeerId), NetworkError> {
    let protocols: Vec<_> = address.iter().collect();
    let circuit_positions: Vec<_> = protocols
        .iter()
        .enumerate()
        .filter_map(|(index, protocol)| matches!(protocol, Protocol::P2pCircuit).then_some(index))
        .collect();
    if circuit_positions.len() != 1 {
        return Err(NetworkError::InvalidAddress(
            "circuit address must contain exactly one /p2p-circuit".to_owned(),
        ));
    }
    let circuit_index = circuit_positions[0];
    let mut relay = Multiaddr::empty();
    for protocol in &protocols[..circuit_index] {
        relay.push(protocol.clone());
    }
    validate_direct_peer_address(&relay)?;
    let destination = &protocols[circuit_index + 1..];
    match destination {
        [Protocol::P2p(peer)] => Ok((relay, *peer)),
        _ => Err(NetworkError::InvalidAddress(
            "circuit address must end in exactly one destination /p2p/<peer-id>".to_owned(),
        )),
    }
}

/// Validate a relayed dial address against the relays the user configured.
fn validate_relayed_peer_address(
    address: &Multiaddr,
    relay_servers: &[Multiaddr],
) -> Result<PeerId, NetworkError> {
    let (relay, destination) = relay_circuit_parts(address)?;
    if !relay_servers.iter().any(|configured| configured == &relay) {
        return Err(NetworkError::InvalidAddress(
            "circuit relay is not in the configured relay address list".to_owned(),
        ));
    }
    Ok(destination)
}

/// Build `relay + /p2p-circuit + destination` for a configured relay.
fn relayed_peer_address(relay: &Multiaddr, destination: PeerId) -> Multiaddr {
    let mut address = relay.clone();
    address.push(Protocol::P2pCircuit);
    address.push(Protocol::P2p(destination));
    address
}

fn application_route_allowed(
    peer: PeerId,
    relayed_peers: &HashMap<PeerId, usize>,
    policy: DialPolicy,
) -> bool {
    match policy {
        DialPolicy::DirectAllowed => true,
        DialPolicy::RelayOnly => relayed_peers.get(&peer).copied().unwrap_or(0) > 0,
    }
}

fn privacy_status_from_config(config: &NetworkConfig) -> NetworkPrivacyStatus {
    NetworkPrivacyStatus {
        transport_mode: config.transport_mode,
        socks5_proxy_configured: config.socks5_proxy.is_some(),
        dial_policy: config.dial_policy,
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
    if config.transport_mode == TransportPrivacyMode::TorRequired {
        if config.socks5_proxy.is_none() {
            return Err(NetworkError::InvalidConfig(
                "SOCKS5/Tor route requires a user-supplied proxy address; direct fallback is disabled"
                    .to_owned(),
            ));
        }
        if config.enable_mdns || config.enable_autonat || config.enable_dcutr {
            return Err(NetworkError::InvalidConfig(
                "SOCKS5/Tor route disables mDNS, AutoNAT and DCUtR".to_owned(),
            ));
        }
    } else if config.socks5_proxy.is_some() {
        return Err(NetworkError::InvalidConfig(
            "SOCKS5 proxy address requires SOCKS5/Tor route mode".to_owned(),
        ));
    }
    if config.max_total_connections == 0
        || config.max_connections_per_peer == 0
        || config.max_connections_per_ip == 0
    {
        return Err(NetworkError::InvalidConfig(
            "connection limits must be at least one".to_owned(),
        ));
    }
    if config.max_pending_incoming_connections == 0 || config.max_pending_outgoing_connections == 0
    {
        return Err(NetworkError::InvalidConfig(
            "pending connection limits must be at least one".to_owned(),
        ));
    }
    TransportLimits::from_config(config).map_err(NetworkError::InvalidConfig)?;
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
    if config.dial_policy == DialPolicy::RelayOnly {
        if config.relay_mode != RelayMode::Client {
            return Err(NetworkError::InvalidConfig(
                "relay-only routing requires relay-client mode".to_owned(),
            ));
        }
        if config.enable_dcutr {
            return Err(NetworkError::InvalidConfig(
                "relay-only routing disables DCUtR hole punching".to_owned(),
            ));
        }
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

        // Neither relay-only nor SOCKS5/Tor route mode advertises a direct TCP
        // listener. Relay clients still create circuit listeners below, and
        // those reservation dials use the selected transport.
        if config.transport_mode != TransportPrivacyMode::TorRequired
            && config.dial_policy != DialPolicy::RelayOnly
            && let Err(error) = swarm.listen_on(config.listen_addr.clone())
        {
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
                    emit_relay(
                        &relay_events,
                        RelayEvent::Failed {
                            reason: format!(
                                "relay reservation could not start: {}",
                                truncate_reason(&error.to_string())
                            ),
                        },
                    );
                }
            }
        }

        let relay_peers: BTreeSet<PeerId> = config
            .relay_servers
            .iter()
            .filter_map(peer_from_address)
            .collect();
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
                            // libp2p only puts confirmed external addresses in
                            // relay reservations. An explicitly configured
                            // relay server confirms each concrete local listen
                            // address so clients receive a dialable relay
                            // address without AutoNAT or a public discovery
                            // service. Wildcard/unspecified addresses are not
                            // dialable and are not advertised.
                            if config.relay_mode == RelayMode::Server
                                && !address.iter().any(|protocol| match protocol {
                                    Protocol::Ip4(ip) => ip.is_unspecified(),
                                    Protocol::Ip6(ip) => ip.is_unspecified(),
                                    _ => false,
                                })
                            {
                                swarm.add_external_address(address.clone());
                            }
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
                            // Relay-only accepts direct TCP only to configured
                            // relays for reservation signalling. Every other
                            // direct connection is closed before application
                            // protocols can observe or send traffic.
                            if config.dial_policy == DialPolicy::RelayOnly
                                && !relayed
                                && !relay_peers.contains(&peer_id)
                            {
                                rejected_connections.insert(connection_id);
                                let _ = swarm.close_connection(connection_id);
                                emit(&events, ConnectionState::Failed {
                                    peer: Some(peer_id),
                                    reason: "relay-only policy rejected a direct connection"
                                        .to_owned(),
                                });
                                continue;
                            }
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
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            // Transport-level rejections (including connection-limit
                            // denials) are reported as failures, never as connections.
                            emit(&events, ConnectionState::Failed {
                                peer: None,
                                reason: incoming_error_reason(&error),
                            });
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
                            if let Some((peer, bytes, route_denied)) =
                                denied_request(&event, config.dial_policy, &relayed_peers)
                                && (route_denied
                                    || !rate_limiter.allow(
                                        peer,
                                        RequestProtocol::Message,
                                        bytes,
                                        Instant::now(),
                                    ))
                            {
                                let raw = next_response_id;
                                next_response_id = next_response_id.checked_add(1).unwrap_or(1);
                                emit_message(&message_events, MessageEvent::Failed {
                                    request_id: None,
                                    response_id: Some(MessageResponseId(raw)),
                                    peer,
                                    reason: if route_denied {
                                        "relay-only policy rejected a direct application request"
                                            .to_owned()
                                    } else {
                                        "peer request rate limit exceeded".to_owned()
                                    },
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
                            if let Some((peer, bytes, route_denied)) =
                                denied_request(&event, config.dial_policy, &relayed_peers)
                                && (route_denied
                                    || !rate_limiter.allow(
                                        peer,
                                        RequestProtocol::Setup,
                                        bytes,
                                        Instant::now(),
                                    ))
                            {
                                let raw = next_setup_response_id;
                                next_setup_response_id =
                                    next_setup_response_id.checked_add(1).unwrap_or(1);
                                emit_setup(&setup_events, SetupEvent::Failed {
                                    request_id: None,
                                    response_id: Some(SetupResponseId(raw)),
                                    peer,
                                    reason: if route_denied {
                                        "relay-only policy rejected a direct application request"
                                            .to_owned()
                                    } else {
                                        "peer request rate limit exceeded".to_owned()
                                    },
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
                            if let Some((peer, bytes, route_denied)) =
                                denied_request(&event, config.dial_policy, &relayed_peers)
                                && (route_denied
                                    || !rate_limiter.allow(
                                        peer,
                                        RequestProtocol::File,
                                        bytes,
                                        Instant::now(),
                                    ))
                            {
                                let raw = next_file_response_id;
                                next_file_response_id =
                                    next_file_response_id.checked_add(1).unwrap_or(1);
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: None,
                                    response_id: Some(FileResponseId(raw)),
                                    peer,
                                    reason: if route_denied {
                                        "relay-only policy rejected a direct application request"
                                            .to_owned()
                                    } else {
                                        "peer request rate limit exceeded".to_owned()
                                    },
                                });
                                continue;
                            }
                            handle_file_event(
                                event,
                                &relayed_peers,
                                &mut next_file_response_id,
                                &mut file_outbound_ids,
                                &mut file_outbound_by_swarm,
                                &mut pending_file_responses,
                                &mut file_inbound_by_swarm,
                                &file_events,
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Control(event)) => {
                            if let Some((peer, bytes, route_denied)) =
                                denied_request(&event, config.dial_policy, &relayed_peers)
                                && (route_denied
                                    || !rate_limiter.allow(
                                        peer,
                                        RequestProtocol::Control,
                                        bytes,
                                        Instant::now(),
                                    ))
                            {
                                let raw = next_control_response_id;
                                next_control_response_id =
                                    next_control_response_id.checked_add(1).unwrap_or(1);
                                emit_control(&control_events, ControlEvent::Failed {
                                    request_id: None,
                                    response_id: Some(ControlResponseId(raw)),
                                    peer,
                                    reason: if route_denied {
                                        "relay-only policy rejected a direct application request"
                                            .to_owned()
                                    } else {
                                        "peer request rate limit exceeded".to_owned()
                                    },
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
                            } => {
                                emit_relay(
                                    &relay_events,
                                    RelayEvent::ReservationAccepted { relay: relay_peer_id },
                                );
                                // A circuit listener only exists after the relay
                                // confirms the reservation. Advertise that
                                // address as observed state; never replace it
                                // with a direct listener under relay-only mode.
                                if let Some(relay_address) = config
                                    .relay_servers
                                    .iter()
                                    .find(|address| peer_from_address(address) == Some(relay_peer_id))
                                {
                                    let mut circuit_address = relay_address.clone();
                                    circuit_address.push(Protocol::P2pCircuit);
                                    circuit_address.push(Protocol::P2p(*swarm.local_peer_id()));
                                    if !addresses.contains(&circuit_address) {
                                        addresses.push(circuit_address);
                                        emit(
                                            &events,
                                            ConnectionState::Listening {
                                                addresses: addresses.clone(),
                                            },
                                        );
                                    }
                                }
                            }
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
                                NatEvent::StatusChanged { status, address },
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
                            if !application_route_allowed(peer, &relayed_peers, config.dial_policy) {
                                emit_message(&message_events, MessageEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "relay-only policy requires a relayed path".to_owned(),
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
                            if !application_route_allowed(peer, &relayed_peers, config.dial_policy) {
                                emit_setup(&setup_events, SetupEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "relay-only policy requires a relayed path".to_owned(),
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
                            if !application_route_allowed(peer, &relayed_peers, config.dial_policy) {
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "relay-only policy requires a relayed path".to_owned(),
                                });
                                continue;
                            }
                            // libp2p 0.56 upgrades the relay client transport
                            // with the same Noise upgrade used for direct TCP:
                            // the relay forwards opaque Noise bytes, so it sees
                            // PeerIds/IPs/timing/sizes but not application
                            // plaintext or the file content key. This remains
                            // a conservative metadata/policy restriction until
                            // a dedicated relay-safe file-key/transport design
                            // exists; it is not a claim that the relay can
                            // read the offer.
                            if !outbound_file_request_allowed(peer, &relayed_peers) {
                                emit_file(&file_events, FileEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: FILE_RELAY_POLICY_REASON.to_owned(),
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
                            if !application_route_allowed(peer, &relayed_peers, config.dial_policy) {
                                emit_control(&control_events, ControlEvent::Failed {
                                    request_id: Some(id),
                                    response_id: None,
                                    peer,
                                    reason: "relay-only policy requires a relayed path".to_owned(),
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
    let transport_limits = TransportLimits::from_config(config)?;

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
            .with_hide_listen_addrs(config.relay_mode != RelayMode::Server)
    });
    let ping_config = ping::Config::default()
        .with_interval(Duration::from_secs(60))
        .with_timeout(Duration::from_secs(10));

    // The standard builder applies libp2p's connection limits only after the
    // transport emits an inbound connection. Wrap the upgraded TCP transport
    // so a single source IP cannot occupy the whole pre-authentication budget
    // with stalled sockets before Noise authentication.
    let noise_direct = libp2p::noise::Config::new(keypair).map_err(|error| error.to_string())?;
    let direct_transport = PerIpPendingTransport::new(
        libp2p::tcp::tokio::Transport::new(Default::default())
            .upgrade(libp2p::core::upgrade::Version::V1Lazy)
            .authenticate(noise_direct)
            .multiplex(libp2p::yamux::Config::default())
            .map(|(peer, connection), _| (peer, StreamMuxerBox::new(connection))),
        config.max_connections_per_ip,
    )
    .boxed();

    let transport: libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> =
        if config.transport_mode == TransportPrivacyMode::TorRequired {
            // Fail closed on a missing proxy in `validate_config`; never build
            // a direct TCP fallback transport in SOCKS5/Tor route mode.
            let proxy = config
                .socks5_proxy
                .ok_or_else(|| "SOCKS5/Tor route requires a proxy address".to_owned())?;
            let noise_proxy =
                libp2p::noise::Config::new(keypair).map_err(|error| error.to_string())?;
            socks5::Socks5OnlyTransport::new(proxy)
                .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                .authenticate(noise_proxy)
                .multiplex(libp2p::yamux::Config::default())
                .map(|(peer, connection), _| (peer, StreamMuxerBox::new(connection)))
                .boxed()
        } else {
            direct_transport
        };

    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_other_transport(move |_| transport)
        // `with_other_transport` is infallible for a ready-made transport.
        // Matching `Infallible` avoids an unreachable `Display` call that
        // newer Clippy versions reject under `-D warnings`.
        .map_err(|never| -> String { match never {} })?
        // The relay transport is present so client behaviour can be opted in.
        // With the behaviour toggled off it never dials or listens on a relay.
        // Relay upgrades are composed around the wrapped direct transport, so
        // this per-IP rule applies only to raw inbound TCP sockets.
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
                .then(|| {
                    let mut behaviour =
                        relay::Behaviour::new(key.public().to_peer_id(), relay_config);
                    // A user who explicitly enables RelayMode::Server is asking
                    // this node to relay. libp2p's automatic status keeps the
                    // HOP protocol disabled until it observes a confirmed
                    // external address, which prevents a local/on-LAN relay
                    // from accepting reservations at all. Explicit opt-in is
                    // enough here; the capability remains off by default.
                    behaviour.set_status(Some(relay::Status::Enable));
                    behaviour
                })
                .into(),
            autonat: config
                .enable_autonat
                .then(|| autonat::v1::Behaviour::new(local_peer_id, autonat_config))
                .into(),
            dcutr: config
                .enable_dcutr
                .then(|| dcutr::Behaviour::new(local_peer_id))
                .into(),
            connection_limits: ConnectionLimitBehaviour::new(transport_limits.libp2p()),
        })
        // `with_behaviour` is infallible when given a ready-made behaviour;
        // see the `Infallible` note on `with_other_transport` above.
        .map_err(|never| -> String { match never {} })?
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

/// Refuse outbound file offers on an observed relayed path. The same policy
/// applies to inbound requests in `file_request_policy_response_id`; neither
/// direction depends on an application-level claim about the relay.
fn outbound_file_request_allowed(peer: PeerId, relayed_peers: &HashMap<PeerId, usize>) -> bool {
    relayed_peers.get(&peer).copied().unwrap_or(0) == 0
}

/// Allocate a response ID for an inbound file request unless the peer is on an
/// observed relayed path. Rejection emits one `FileEvent::Failed` and allocates
/// no pending response slot. This helper is separate from the libp2p event
/// handler so the policy can be tested without constructing a private
/// `ResponseChannel`.
fn file_request_policy_response_id(
    peer: PeerId,
    relayed_peers: &HashMap<PeerId, usize>,
    next_response_id: &mut u64,
    events: &tokio_mpsc::Sender<FileEvent>,
) -> Option<FileResponseId> {
    let raw = *next_response_id;
    *next_response_id = next_response_id.checked_add(1).unwrap_or(1);
    if relayed_peers.get(&peer).copied().unwrap_or(0) > 0 {
        emit_file(
            events,
            FileEvent::Failed {
                request_id: None,
                response_id: Some(FileResponseId(raw)),
                peer,
                reason: FILE_RELAY_POLICY_REASON.to_owned(),
            },
        );
        return None;
    }
    Some(FileResponseId(raw))
}

#[allow(clippy::too_many_arguments)]
fn handle_file_event(
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    relayed_peers: &HashMap<PeerId, usize>,
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
                let Some(response_id) =
                    file_request_policy_response_id(peer, relayed_peers, next_response_id, events)
                else {
                    // Drop the inbound channel without creating a response
                    // slot or emitting RequestReceived. The behaviour sees a
                    // response omission; the application sees only the Failed
                    // event emitted by the policy helper.
                    drop(channel);
                    return;
                };
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

/// Inbound application request denied by the selected route policy. The
/// boolean marks a relay-only policy rejection; rate-limit rejection is decided
/// separately by the caller.
fn denied_request(
    event: &request_response::Event<Vec<u8>, Vec<u8>>,
    policy: DialPolicy,
    relayed_peers: &HashMap<PeerId, usize>,
) -> Option<(PeerId, usize, bool)> {
    match event {
        request_response::Event::Message {
            peer,
            message: request_response::Message::Request { request, .. },
            ..
        } => Some((
            *peer,
            request.len(),
            !application_route_allowed(*peer, relayed_peers, policy),
        )),
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

fn incoming_error_reason(error: &libp2p::swarm::ListenError) -> String {
    if let libp2p::swarm::ListenError::Denied { cause } = error
        && let Some(exceeded) = cause.downcast_ref::<libp2p::connection_limits::Exceeded>()
    {
        return truncate_reason(&exceeded.to_string());
    }
    truncate_reason(&error.to_string())
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
        assert_eq!(config.max_pending_incoming_connections, 16);
        assert_eq!(config.max_pending_outgoing_connections, 16);
        assert!(config.max_request_bytes_per_peer_per_window > MAX_MESSAGE_BYTES);
        assert!(!config.enable_identify);
        assert!(!config.enable_ping);
        assert!(!config.enable_mdns);
        assert!(!config.enable_kad);
        assert!(!config.enable_autonat);
        assert!(!config.enable_dcutr);
        assert!(config.kad_bootstrap_peers.is_empty());
        assert!(config.relay_servers.is_empty());
        assert!(config.socks5_proxy.is_none());
        assert_eq!(config.relay_mode, RelayMode::Off);
        assert_eq!(config.max_relayed_connections, 4);
    }

    #[test]
    fn transport_limits_map_config_to_explicit_libp2p_bounds() {
        let config = NetworkConfig::default();
        assert_eq!(
            TransportLimits::from_config(&config).expect("transport limits"),
            TransportLimits {
                max_pending_incoming: 16,
                max_pending_outgoing: 16,
                max_established_total: 16,
                max_established_per_peer: 1,
            }
        );
    }

    #[test]
    fn config_validation_rejects_zero_or_oversized_connection_limits() {
        assert!(matches!(
            validate_config(&NetworkConfig {
                max_pending_incoming_connections: 0,
                ..NetworkConfig::default()
            }),
            Err(NetworkError::InvalidConfig(_))
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                max_pending_outgoing_connections: 0,
                ..NetworkConfig::default()
            }),
            Err(NetworkError::InvalidConfig(_))
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                max_total_connections: 0,
                ..NetworkConfig::default()
            }),
            Err(NetworkError::InvalidConfig(_))
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                max_total_connections: usize::MAX,
                ..NetworkConfig::default()
            }),
            Err(NetworkError::InvalidConfig(_))
        ));
    }

    #[test]
    fn tor_required_fails_closed_without_direct_fallback() {
        let identity = Identity::generate().expect("identity");
        let config = NetworkConfig {
            transport_mode: TransportPrivacyMode::TorRequired,
            ..NetworkConfig::default()
        };
        assert!(matches!(
            validate_config(&config),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("direct fallback is disabled")
        ));
        assert!(matches!(
            Network::start(&identity, config),
            Err(NetworkError::InvalidConfig(_))
        ));
        assert_eq!(
            privacy_status_from_config(&NetworkConfig::default()).transport_mode,
            TransportPrivacyMode::Direct
        );
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
    fn socks5_route_requires_a_proxy_and_disables_direct_discovery() {
        let proxy = "127.0.0.1:9050".parse().expect("proxy address");
        let base = NetworkConfig {
            transport_mode: TransportPrivacyMode::TorRequired,
            socks5_proxy: Some(proxy),
            ..NetworkConfig::default()
        };
        assert!(validate_config(&base).is_ok());
        assert!(
            privacy_status_from_config(&base).socks5_proxy_configured,
            "configured proxy must be reported without claiming it works"
        );
        assert!(matches!(
            validate_config(&NetworkConfig {
                enable_mdns: true,
                ..base.clone()
            }),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("mDNS")
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                enable_autonat: true,
                ..base.clone()
            }),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("AutoNAT")
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                transport_mode: TransportPrivacyMode::Direct,
                ..base
            }),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("requires SOCKS5/Tor route mode")
        ));
    }

    fn relay_only_config(relay: Multiaddr) -> NetworkConfig {
        NetworkConfig {
            dial_policy: DialPolicy::RelayOnly,
            relay_mode: RelayMode::Client,
            relay_servers: vec![relay],
            ..NetworkConfig::default()
        }
    }

    #[test]
    fn relay_only_config_fails_closed_on_conflicting_policy() {
        let peer = generated_peer_id();
        let relay =
            Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")).expect("relay");

        assert!(validate_config(&relay_only_config(relay.clone())).is_ok());
        assert!(matches!(
            validate_config(&NetworkConfig {
                dial_policy: DialPolicy::RelayOnly,
                relay_mode: RelayMode::Off,
                relay_servers: vec![relay.clone()],
                ..NetworkConfig::default()
            }),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("relay-client mode")
        ));
        assert!(matches!(
            validate_config(&NetworkConfig {
                enable_dcutr: true,
                ..relay_only_config(relay)
            }),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("DCUtR")
        ));
    }

    #[test]
    fn circuit_address_validation_rejects_unconfigured_or_malformed_paths() {
        let relay_peer = generated_peer_id();
        let destination = generated_peer_id();
        let relay = Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer}"))
            .expect("relay address");
        let circuit = relayed_peer_address(&relay, destination);
        assert_eq!(
            validate_relayed_peer_address(&circuit, std::slice::from_ref(&relay))
                .expect("destination"),
            destination
        );

        let other_relay = Multiaddr::from_str(&format!(
            "/ip4/127.0.0.1/tcp/4002/p2p/{}",
            generated_peer_id()
        ))
        .expect("other relay");
        assert!(validate_relayed_peer_address(&circuit, &[other_relay]).is_err());

        let mut doubled = circuit.clone();
        doubled.push(Protocol::P2pCircuit);
        doubled.push(Protocol::P2p(destination));
        assert!(validate_relayed_peer_address(&doubled, std::slice::from_ref(&relay)).is_err());

        let mut extra_suffix = circuit.clone();
        extra_suffix.push(Protocol::P2p(generated_peer_id()));
        assert!(
            validate_relayed_peer_address(&extra_suffix, std::slice::from_ref(&relay)).is_err()
        );

        let mut destination_missing = relay.clone();
        destination_missing.push(Protocol::P2pCircuit);
        assert!(validate_relayed_peer_address(&destination_missing, &[relay]).is_err());
    }

    #[test]
    fn relay_only_dial_rejects_direct_paths_and_queues_configured_circuits() {
        let relay_peer = generated_peer_id();
        let destination = generated_peer_id();
        let relay = Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer}"))
            .expect("relay address");
        let (mut network, _events, mut commands) = network_with_test_channels();
        network.dial_policy = DialPolicy::RelayOnly;
        network.relay_servers = vec![relay.clone()];

        let direct = Multiaddr::from_str(&format!("/ip4/127.0.0.1/tcp/4002/p2p/{destination}"))
            .expect("direct destination");
        assert!(matches!(
            network.dial(direct),
            Err(NetworkError::InvalidConfig(reason))
                if reason.contains("rejects direct dials")
        ));
        assert!(network.pending_addresses.is_empty());
        assert!(matches!(
            commands.try_recv(),
            Err(tokio_mpsc::error::TryRecvError::Empty)
        ));

        network
            .dial_relayed(destination)
            .expect("relayed dial queued");
        assert_eq!(network.pending_addresses.len(), 1);
        match commands.try_recv() {
            Ok(Command::Dial { address, expected }) => {
                assert_eq!(expected, destination);
                assert_eq!(address, relayed_peer_address(&relay, destination));
            }
            _ => panic!("expected a queued relayed dial"),
        }
    }

    #[test]
    fn application_route_requires_observed_relay_under_relay_only_policy() {
        let peer = generated_peer_id();
        let empty = HashMap::new();
        let relayed = HashMap::from([(peer, 1usize)]);
        assert!(application_route_allowed(
            peer,
            &empty,
            DialPolicy::DirectAllowed
        ));
        assert!(!application_route_allowed(
            peer,
            &empty,
            DialPolicy::RelayOnly
        ));
        assert!(application_route_allowed(
            peer,
            &relayed,
            DialPolicy::RelayOnly
        ));
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

        assert!(limiter.allow(peer_id, RequestProtocol::Message, 6, now));
        assert!(limiter.allow(peer_id, RequestProtocol::Message, 4, now));
        assert!(
            !limiter.allow(peer_id, RequestProtocol::Message, 1, now),
            "byte cap must be enforced"
        );
        assert!(
            !limiter.allow(
                peer_id,
                RequestProtocol::Message,
                0,
                now + Duration::from_millis(500)
            ),
            "request count cap must be enforced"
        );
        assert!(
            limiter.allow(
                peer_id,
                RequestProtocol::Message,
                1,
                now + Duration::from_secs(2)
            ),
            "old entries must leave the sliding window"
        );
    }

    #[test]
    fn rate_limiter_reserves_protocol_shares_inside_the_aggregate_ceiling() {
        let config = NetworkConfig {
            rate_window: Duration::from_secs(1),
            max_requests_per_peer_per_window: 8,
            max_request_bytes_per_peer_per_window: 8 * MAX_MESSAGE_BYTES,
            ..NetworkConfig::default()
        };
        let mut limiter = RateLimiter::new(&config);
        assert_eq!(limiter.max_protocol_requests, 2);
        assert_eq!(limiter.max_protocol_bytes, 2 * MAX_MESSAGE_BYTES);
        let peer = generated_peer_id();
        let now = Instant::now();
        let frame = MAX_MESSAGE_BYTES;

        assert!(limiter.allow(peer, RequestProtocol::Control, frame, now));
        assert!(limiter.allow(peer, RequestProtocol::Control, frame, now));
        assert!(
            !limiter.allow(peer, RequestProtocol::Control, frame, now),
            "control must not exceed its reserved byte share"
        );
        assert!(
            limiter.allow(peer, RequestProtocol::Message, frame, now),
            "saturated control traffic must not block messages"
        );
        assert!(limiter.allow(peer, RequestProtocol::Setup, frame, now));
        assert!(limiter.allow(peer, RequestProtocol::File, frame, now));
        assert!(limiter.allow(peer, RequestProtocol::Message, frame, now));
        assert!(
            !limiter.allow(peer, RequestProtocol::Message, frame, now),
            "messages must not exceed their reserved byte share"
        );
        assert_eq!(limiter.entries.len(), 1);
        assert_eq!(limiter.protocol_entries.len(), 4);
    }

    #[test]
    fn rate_limiter_denied_request_does_not_charge_the_aggregate_budget() {
        let config = NetworkConfig {
            rate_window: Duration::from_secs(1),
            max_requests_per_peer_per_window: 3,
            max_request_bytes_per_peer_per_window: 64,
            ..NetworkConfig::default()
        };
        let mut limiter = RateLimiter::new(&config);
        assert_eq!(limiter.max_protocol_requests, 2);
        let peer = generated_peer_id();
        let now = Instant::now();

        assert!(limiter.allow(peer, RequestProtocol::Message, 1, now));
        assert!(limiter.allow(peer, RequestProtocol::Message, 1, now));
        assert!(!limiter.allow(peer, RequestProtocol::Message, 1, now));
        assert!(
            limiter.allow(peer, RequestProtocol::Setup, 1, now),
            "a per-protocol denial must not consume the aggregate request budget"
        );
        assert!(
            !limiter.allow(peer, RequestProtocol::File, 1, now),
            "the aggregate request ceiling must still apply"
        );
    }

    #[test]
    fn hostile_peer_matrix_cannot_bypass_the_aggregate_byte_ceiling() {
        let config = NetworkConfig {
            rate_window: Duration::from_secs(1),
            max_requests_per_peer_per_window: 64,
            max_request_bytes_per_peer_per_window: 128,
            ..NetworkConfig::default()
        };
        let mut limiter = RateLimiter::new(&config);
        let peer = generated_peer_id();
        let now = Instant::now();

        for protocol in RequestProtocol::ALL {
            assert!(
                !limiter.allow(peer, protocol, 129, now),
                "oversized request must be denied on every protocol"
            );
        }
        assert!(
            limiter.entries.is_empty() && limiter.protocol_entries.is_empty(),
            "denied hostile requests must not reserve accounting state"
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
        assert_eq!(MLS_SETUP_PROTOCOL, "/p2p-messenger/mls-setup/2");
        assert_eq!(LEGACY_MLS_SETUP_PROTOCOL, "/p2p-messenger/mls-setup/1");
        assert_ne!(MLS_SETUP_PROTOCOL, LEGACY_MLS_SETUP_PROTOCOL);
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
    fn peerless_failure_event_does_not_erase_live_connections() {
        let (mut network, events, _commands) = network_with_test_channels();
        let peer = generated_peer_id();
        let connected = ConnectionState::Connected { peers: vec![peer] };
        events
            .try_send(connected.clone())
            .expect("connected event queued");
        events
            .try_send(ConnectionState::Failed {
                peer: None,
                reason: "connection limit exceeded".to_owned(),
            })
            .expect("advisory failure event queued");

        assert_eq!(network.poll_event(), Some(connected.clone()));
        assert_eq!(network.state(), &connected);
        let advisory = network.poll_event().expect("advisory failure event");
        assert!(matches!(
            advisory,
            ConnectionState::Failed { peer: None, .. }
        ));
        assert_eq!(network.state(), &connected);
    }

    /// A `Network` whose command and event receivers stay in the test, so queue
    /// writes and cached-state transitions can be observed without a worker.
    fn network_with_test_channels() -> (
        Network,
        tokio_mpsc::Sender<ConnectionState>,
        tokio_mpsc::Receiver<Command>,
    ) {
        let (commands, command_rx) = tokio_mpsc::channel(16);
        let (events, events_rx) = tokio_mpsc::channel(4);
        let (_message_events, message_rx) = tokio_mpsc::channel(4);
        let (_setup_events, setup_rx) = tokio_mpsc::channel(4);
        let (_file_events, file_rx) = tokio_mpsc::channel(4);
        let (_control_events, control_rx) = tokio_mpsc::channel(4);
        let (_discovery_events, discovery_rx) = tokio_mpsc::channel(4);
        let (_relay_events, relay_rx) = tokio_mpsc::channel(4);
        let (_nat_events, nat_rx) = tokio_mpsc::channel(4);
        let (_identify_events, identify_rx) = tokio_mpsc::channel(4);
        let network = Network {
            commands,
            events: events_rx,
            message_events: message_rx,
            setup_events: setup_rx,
            file_events: file_rx,
            control_events: control_rx,
            discovery_events: discovery_rx,
            relay_events: relay_rx,
            nat_events: nat_rx,
            identify_events: identify_rx,
            state: ConnectionState::Unknown,
            privacy_status: NetworkPrivacyStatus::default(),
            dial_policy: DialPolicy::DirectAllowed,
            relay_servers: Vec::new(),
            pending_addresses: HashMap::new(),
            next_request_id: AtomicU64::new(1),
            next_setup_request_id: AtomicU64::new(1),
            next_file_request_id: AtomicU64::new(1),
            next_control_request_id: AtomicU64::new(1),
            worker: None,
        };
        (network, events, command_rx)
    }

    fn generated_peer_id() -> PeerId {
        let identity = Identity::generate().expect("identity");
        PeerId::from_str(&identity.peer_id().to_string()).expect("peer id")
    }

    #[test]
    fn dial_rejects_circuit_address_before_queue_or_pending_insert() {
        let (mut network, _events, mut commands) = network_with_test_channels();
        let identity = Identity::generate().expect("identity");
        let direct = Multiaddr::from_str(&format!(
            "/ip4/127.0.0.1/tcp/4001/p2p/{}",
            identity.peer_id()
        ))
        .expect("direct address");
        let mut circuit = direct.clone();
        circuit.push(Protocol::P2pCircuit);

        assert!(matches!(
            network.dial(circuit),
            Err(NetworkError::InvalidAddress(_))
        ));
        assert!(network.pending_addresses.is_empty());
        assert!(
            matches!(
                commands.try_recv(),
                Err(tokio_mpsc::error::TryRecvError::Empty)
            ),
            "a circuit address must not reach the command queue"
        );

        assert!(network.dial(direct).is_ok());
        assert_eq!(network.pending_addresses.len(), 1);
        assert!(matches!(commands.try_recv(), Ok(Command::Dial { .. })));
    }

    #[test]
    fn rate_limiter_removes_peer_entries_after_expiry() {
        let config = NetworkConfig {
            rate_window: Duration::from_secs(1),
            max_requests_per_peer_per_window: 2,
            max_request_bytes_per_peer_per_window: 10,
            ..NetworkConfig::default()
        };
        let mut limiter = RateLimiter::new(&config);
        let peers = [
            generated_peer_id(),
            generated_peer_id(),
            generated_peer_id(),
        ];
        let now = Instant::now();

        for peer in peers {
            assert!(limiter.allow(peer, RequestProtocol::Message, 1, now));
        }
        assert_eq!(limiter.entries.len(), 3);
        assert_eq!(limiter.protocol_entries.len(), 3);

        let later = now + Duration::from_secs(2);
        assert!(limiter.allow(peers[0], RequestProtocol::Message, 1, later));
        assert_eq!(
            limiter.entries.len(),
            1,
            "expired peer entries must be removed after retain"
        );
        assert_eq!(limiter.protocol_entries.len(), 1);
        assert!(limiter.allow(peers[1], RequestProtocol::Message, 1, later));
        assert_eq!(limiter.entries.len(), 2);
        assert!(limiter.allow(peers[2], RequestProtocol::Message, 1, later));
        assert_eq!(limiter.entries.len(), 3);

        let zero_window = NetworkConfig {
            max_requests_per_peer_per_window: 0,
            ..config
        };
        let mut limiter = RateLimiter::new(&zero_window);
        assert!(!limiter.allow(peers[0], RequestProtocol::Message, 1, now));
        assert!(
            limiter.entries.is_empty(),
            "a rejected peer must not leave an empty entry behind"
        );
        assert!(limiter.protocol_entries.is_empty());
    }

    #[test]
    fn relayed_inbound_file_request_emits_only_a_failed_event() {
        let (events, mut received) = tokio_mpsc::channel(4);
        let peer = generated_peer_id();
        let relayed_peers = HashMap::from([(peer, 1usize)]);
        let mut next_response_id = 7;

        assert_eq!(
            file_request_policy_response_id(peer, &relayed_peers, &mut next_response_id, &events),
            None
        );
        assert_eq!(next_response_id, 8);
        let event = received.try_recv().expect("failed event");
        assert!(
            matches!(
                &event,
                FileEvent::Failed {
                    request_id: None,
                    response_id: Some(FileResponseId(7)),
                    ..
                }
            ),
            "{event:?}"
        );
        assert!(matches!(
            &event,
            FileEvent::Failed { reason, .. } if reason == FILE_RELAY_POLICY_REASON
        ));
        assert!(
            received.try_recv().is_err(),
            "no RequestReceived event may be emitted for a relayed peer"
        );

        let direct_peers: HashMap<PeerId, usize> = HashMap::new();
        assert_eq!(
            file_request_policy_response_id(peer, &direct_peers, &mut next_response_id, &events),
            Some(FileResponseId(8))
        );
        assert_eq!(next_response_id, 9);
        assert!(
            received.try_recv().is_err(),
            "a direct peer must not produce a policy failure"
        );
    }

    #[test]
    fn outbound_file_requests_use_the_same_relay_policy_as_inbound() {
        let peer = generated_peer_id();
        let relayed = HashMap::from([(peer, 2usize)]);
        assert!(!outbound_file_request_allowed(peer, &relayed));
        let direct = HashMap::new();
        assert!(outbound_file_request_allowed(peer, &direct));
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
