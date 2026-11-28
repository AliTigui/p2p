//! Optional discovery, relay, NAT, and metadata/status types.
//!
//! Every capability in this module is disabled by default. Enabled means only
//! that the local user configured the capability; observed fields are changed
//! exclusively from real libp2p events in the network worker. No type here
//! claims anonymity, verified contact identity, delivery, or a working NAT
//! traversal.

use libp2p::{Multiaddr, PeerId};

/// Requested transport privacy mode. This is configuration only: it never
/// claims that a requested hidden route was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPrivacyMode {
    /// Direct TCP + Noise or direct QUIC hybrid key exchange. This is the
    /// implemented default and is not anonymous; peers can observe addresses
    /// and timing, and TLS/libp2p PeerId authentication remains classical.
    #[default]
    Direct,
    /// A user-configured SOCKS5 proxy route is required, typically a local Tor
    /// SOCKS5 service. No direct dial or listener is used. This does not verify
    /// that the proxy is Tor or that traffic is anonymous.
    TorRequired,
}

impl TransportPrivacyMode {
    /// Honest description. It does not claim anonymity or an active route.
    pub fn description(self) -> &'static str {
        match self {
            Self::Direct => {
                "Direct TCP + Noise or QUIC hybrid KEX (not anonymous; PeerId auth classical)"
            }
            Self::TorRequired => {
                "SOCKS5/Tor route required (proxy not verified; no direct fallback)"
            }
        }
    }
}

/// Which route classes the application may use for peer traffic.
///
/// This is a local policy, not an observation that a route was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialPolicy {
    /// Direct dials are allowed when the user supplies a direct address.
    #[default]
    DirectAllowed,
    /// Peer traffic must use a relayed path. Direct application dials and
    /// direct inbound application connections are rejected. The configured
    /// relay still observes source IP, destination PeerId, timing and sizes.
    RelayOnly,
}

impl DialPolicy {
    /// Honest user-facing description. It does not claim anonymity.
    pub fn description(self) -> &'static str {
        match self {
            Self::DirectAllowed => "Direct allowed (not anonymous)",
            Self::RelayOnly => "Relay only (relay sees IP and timing; not anonymous)",
        }
    }
}

/// Operational mode for optional peer-operated circuit relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayMode {
    /// No relay behaviour is active. This is the default and the only mode
    /// used by the zero-infrastructure direct-connect path.
    #[default]
    Off,
    /// Use only relay servers explicitly configured by the local user.
    Client,
    /// Serve as a bounded relay for other peers. The relay sees IPs, timing,
    /// and sizes, but never receives message keys, plaintext, or file keys.
    Server,
}

impl RelayMode {
    /// True when any relay behaviour is configured.
    pub fn is_enabled(self) -> bool {
        self != Self::Off
    }

    /// Honest user-facing description. It does not claim an active reservation
    /// or an established circuit.
    pub fn description(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Client => "Client configured (reservation not implied)",
            Self::Server => "Server configured (active circuits not implied)",
        }
    }
}

/// Source of a discovery observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Local-network mDNS observation.
    Mdns,
    /// Kademlia observation using user-configured bootstrap peers.
    Kad,
}

impl DiscoverySource {
    /// Short stable label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mdns => "mdns",
            Self::Kad => "kad",
        }
    }
}

/// Observed discovery facts. A discovered address is a candidate only: no
/// dial, trust, or contact claim is made from these events. Peer-scoped
/// Kademlia observations are released only after PQ admission; mDNS facts
/// remain advisory without full peer-admission context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A peer/address pair was observed by an enabled discovery behaviour.
    Discovered {
        source: DiscoverySource,
        peer: PeerId,
        address: Multiaddr,
    },
    /// A previously observed address expired.
    Expired {
        source: DiscoverySource,
        peer: PeerId,
        address: Multiaddr,
    },
    /// A Kademlia bootstrap query started.
    KadBootstrapStarted { query_id: u64 },
    /// A Kademlia bootstrap query finished. `result` is a static category, not
    /// peer-provided text.
    KadBootstrapFinished { query_id: u64, result: String },
    /// A discovery behaviour failed. `reason` is a static category.
    Failed {
        source: DiscoverySource,
        reason: String,
    },
}

/// Observed relay facts. `Reservation` and `Circuit` events are not trust or
/// identity claims; the remote PeerId was authenticated by Noise or by the
/// relay protocol as appropriate. Peer-scoped observations are released only
/// after PQ admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    /// The local client obtained a relay reservation.
    ReservationAccepted { relay: PeerId },
    /// An outbound relayed circuit was established.
    OutboundCircuitEstablished { relay: PeerId },
    /// A remote peer reached this node through this node's relay service.
    InboundCircuitEstablished { source: PeerId },
    /// A remote peer obtained a reservation on this node's relay service.
    ServerReservationAccepted { source: PeerId },
    /// This node accepted a circuit for another peer.
    ServerCircuitAccepted { source: PeerId, destination: PeerId },
    /// The number of live relayed connections changed. This is a transport
    /// observation, not a trust or identity claim.
    RelayedConnectionsChanged { count: usize },
    /// A relay operation failed. `reason` is a static category.
    Failed { reason: String },
}

/// Observed NAT-status facts. All variants are best-effort and never claim
/// universal reachability. DCUtR hole-punch observations are released only
/// after PQ admission; AutoNAT status is advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatEvent {
    /// AutoNAT reported a status change. libp2p 0.56's AutoNAT v1
    /// `StatusChanged` event has no confidence value; none is synthesized here.
    StatusChanged {
        status: String,
        address: Option<Multiaddr>,
    },
    /// DCUtR reported a hole-punch attempt outcome.
    HolePunch {
        peer: PeerId,
        succeeded: bool,
        reason: String,
    },
}

/// Observed identify facts. Peer-provided strings are length-bounded and no
/// peer-provided addresses are retained in this event. Results and errors are
/// released only after PQ admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyEvent {
    /// A peer completed identify. The peer's protocol list may still contain
    /// protocol names that were not cross-checked by the application.
    Identified {
        peer: PeerId,
        protocol_version: String,
        agent_version: String,
        protocol_count: usize,
        listen_address_count: usize,
    },
    /// Identify failed for a peer. `reason` is a static category.
    Failed { peer: PeerId, reason: String },
}

/// Snapshot of configured capabilities and observed optional-network facts.
///
/// Configuration fields describe local settings only. Observed fields change
/// only after the corresponding libp2p behaviour emits a real event;
/// peer-scoped counters advance only when the observation is released after
/// PQ admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPrivacyStatus {
    /// Requested mode, not an observed anonymity property.
    pub transport_mode: TransportPrivacyMode,
    /// Whether a proxy address was configured, not whether the proxy works.
    pub socks5_proxy_configured: bool,
    /// Requested route policy, not an observed relayed path.
    pub dial_policy: DialPolicy,
    pub identify_enabled: bool,
    pub ping_enabled: bool,
    pub mdns_enabled: bool,
    pub kad_enabled: bool,
    pub kad_bootstrap_peers: usize,
    pub relay_mode: RelayMode,
    pub relay_servers: usize,
    pub autonat_enabled: bool,
    pub dcutr_enabled: bool,
    /// Latest advisory candidate count from discovery events.
    pub discovered_candidates: usize,
    /// Latest advisory Kademlia route count from discovery events.
    pub kad_routes: usize,
    /// Cumulative reservation events observed since worker startup, not the
    /// number of currently held reservations.
    pub relay_reservations: usize,
    /// Cumulative circuit events observed since worker startup, not the number
    /// of currently live circuits.
    pub relay_circuits: usize,
    pub nat_status: String,
    /// Cumulative identify events observed since worker startup, not the number
    /// of currently identified or connected peers.
    pub identified_peers: usize,
    /// Latest live relayed-connection count reported by a transport event.
    pub relayed_connections: usize,
}

impl Default for NetworkPrivacyStatus {
    fn default() -> Self {
        Self {
            transport_mode: TransportPrivacyMode::Direct,
            socks5_proxy_configured: false,
            dial_policy: DialPolicy::DirectAllowed,
            identify_enabled: false,
            ping_enabled: false,
            mdns_enabled: false,
            kad_enabled: false,
            kad_bootstrap_peers: 0,
            relay_mode: RelayMode::Off,
            relay_servers: 0,
            autonat_enabled: false,
            dcutr_enabled: false,
            discovered_candidates: 0,
            kad_routes: 0,
            relay_reservations: 0,
            relay_circuits: 0,
            nat_status: "Unknown".to_owned(),
            identified_peers: 0,
            relayed_connections: 0,
        }
    }
}

impl NetworkPrivacyStatus {
    /// Honest NAT description with no reachability promise.
    pub fn nat_description(&self) -> &str {
        match self.nat_status.as_str() {
            "Public" => "Public address observed by AutoNAT (best effort)",
            "Private" => "Private address observed by AutoNAT",
            _ => "Unknown (no AutoNAT observation)",
        }
    }
}

/// Bound untrusted text before it can reach diagnostics or the GUI.
pub(crate) fn bounded_text(value: &str, limit: usize) -> String {
    let mut output: String = value.chars().take(limit).collect();
    if value.chars().count() > limit {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_mode_default_is_direct_without_an_anonymity_claim() {
        assert_eq!(
            TransportPrivacyMode::default(),
            TransportPrivacyMode::Direct
        );
        assert!(
            TransportPrivacyMode::Direct
                .description()
                .contains("not anonymous")
        );
        assert!(
            TransportPrivacyMode::TorRequired
                .description()
                .contains("no direct fallback")
        );
    }

    #[test]
    fn dial_policy_default_is_direct_without_anonymity_claim() {
        assert_eq!(DialPolicy::default(), DialPolicy::DirectAllowed);
        assert!(
            DialPolicy::DirectAllowed
                .description()
                .contains("not anonymous")
        );
        assert!(
            DialPolicy::RelayOnly
                .description()
                .contains("relay sees IP")
        );
        assert!(
            DialPolicy::RelayOnly
                .description()
                .contains("not anonymous")
        );
    }

    #[test]
    fn relay_mode_default_is_off() {
        assert_eq!(RelayMode::default(), RelayMode::Off);
        assert!(!RelayMode::Off.is_enabled());
        assert!(RelayMode::Client.is_enabled());
        assert!(RelayMode::Server.is_enabled());
    }

    #[test]
    fn bounded_text_caps_untrusted_strings() {
        let value = "x".repeat(200);
        let bounded = bounded_text(&value, 32);
        assert_eq!(bounded.chars().count(), 35);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn nat_status_change_has_no_fabricated_confidence() {
        // AutoNAT v1 StatusChanged in libp2p 0.56 exposes no confidence value.
        let event = NatEvent::StatusChanged {
            status: "Private".to_owned(),
            address: None,
        };
        assert!(matches!(event, NatEvent::StatusChanged { .. }));
    }

    #[test]
    fn nat_description_never_claims_connectivity() {
        let mut status = NetworkPrivacyStatus {
            transport_mode: TransportPrivacyMode::Direct,
            socks5_proxy_configured: false,
            dial_policy: DialPolicy::DirectAllowed,
            identify_enabled: false,
            ping_enabled: false,
            mdns_enabled: false,
            kad_enabled: false,
            kad_bootstrap_peers: 0,
            relay_mode: RelayMode::Off,
            relay_servers: 0,
            autonat_enabled: false,
            dcutr_enabled: false,
            discovered_candidates: 0,
            kad_routes: 0,
            relay_reservations: 0,
            relay_circuits: 0,
            nat_status: "Public".to_owned(),
            identified_peers: 0,
            relayed_connections: 0,
        };
        assert!(status.nat_description().contains("best effort"));
        status.nat_status = "Unknown".to_owned();
        assert!(status.nat_description().contains("no AutoNAT observation"));
    }
}
