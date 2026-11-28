//! UI state and pure helpers. This module has no GUI-toolkit dependency so it
//! can be unit-tested on any host, including machines without display libraries.

use std::net::SocketAddr;
use std::str::FromStr;

use p2p_chat::{ChannelGroupStatus, ConversationInfo, parse_address};
use p2p_core::AppInfo;
use p2p_network::{
    DialPolicy, NetworkConfig, NetworkPrivacyStatus, RelayMode, TransportPrivacyMode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
}

pub fn next_theme(current: Theme) -> Theme {
    match current {
        Theme::Light => Theme::Dark,
        Theme::Dark => Theme::Light,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRow {
    pub label: &'static str,
    pub value: String,
}

/// The only operation allowed to run during a frame. Argon2id runs on a worker
/// thread so the GUI never blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOperation {
    Creating,
    Unlocking,
}

/// Public-only snapshot of an unlocked vault. No passwords, private keys, or
/// other private material ever cross into the view model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedInfo {
    pub peer_id: String,
    pub fingerprint: String,
    pub profile_id: String,
    pub kdf_summary: String,
}

/// Observed state of the local encrypted vault. This projects real storage
/// state; it never implies that networking or messaging is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultState {
    Missing,
    Locked,
    Busy(VaultOperation),
    Unlocked(UnlockedInfo),
    Failed {
        operation: VaultOperation,
        message: String,
    },
}

/// User-editable network settings. The default requires a user-supplied SOCKS5
/// proxy; direct transport is an explicit opt-in. Every other field is off or
/// empty by default. These are local configuration values, not observed
/// capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkOptions {
    pub transport_mode: TransportPrivacyMode,
    pub socks5_proxy: String,
    pub enable_identify: bool,
    pub enable_ping: bool,
    pub enable_mdns: bool,
    pub enable_kad: bool,
    pub kad_bootstrap_peers: String,
    pub dial_policy: DialPolicy,
    pub relay_mode: RelayMode,
    pub relay_servers: String,
    pub enable_autonat: bool,
    pub enable_dcutr: bool,
}

impl NetworkOptions {
    /// Explicit direct-route settings for callers that deliberately accept
    /// direct IP exposure. This is not the GUI default.
    pub fn direct() -> Self {
        Self {
            transport_mode: TransportPrivacyMode::Direct,
            ..Self::default()
        }
    }
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            transport_mode: TransportPrivacyMode::TorRequired,
            socks5_proxy: String::new(),
            enable_identify: false,
            enable_ping: false,
            enable_mdns: false,
            enable_kad: false,
            kad_bootstrap_peers: String::new(),
            dial_policy: DialPolicy::DirectAllowed,
            relay_mode: RelayMode::Off,
            relay_servers: String::new(),
            enable_autonat: false,
            enable_dcutr: false,
        }
    }
}

impl NetworkOptions {
    /// Convert the text fields to a validated worker configuration. Only
    /// user-supplied direct addresses are accepted; discovery and relay peers
    /// are never defaulted or auto-dialed by the GUI.
    pub fn to_config(&self) -> Result<NetworkConfig, String> {
        let kad_bootstrap_peers: Vec<_> = self
            .kad_bootstrap_peers
            .split(|ch: char| ch.is_whitespace() || ch == ',')
            .filter(|value| !value.is_empty())
            .map(parse_address)
            .collect::<Result<_, _>>()
            .map_err(|error| format!("Invalid Kademlia bootstrap address: {error}"))?;
        let relay_servers: Vec<_> = self
            .relay_servers
            .split(|ch: char| ch.is_whitespace() || ch == ',')
            .filter(|value| !value.is_empty())
            .map(parse_address)
            .collect::<Result<_, _>>()
            .map_err(|error| format!("Invalid relay server address: {error}"))?;

        let socks5_proxy = if self.socks5_proxy.trim().is_empty() {
            None
        } else {
            Some(SocketAddr::from_str(self.socks5_proxy.trim()).map_err(|_| {
                "SOCKS5 proxy must be an IP address and port, not a hostname".to_owned()
            })?)
        };

        if self.transport_mode == TransportPrivacyMode::TorRequired && socks5_proxy.is_none() {
            return Err(
                "SOCKS5/Tor route requires a proxy IP address and port; direct fallback is disabled"
                    .to_owned(),
            );
        }
        if self.transport_mode != TransportPrivacyMode::TorRequired && socks5_proxy.is_some() {
            return Err("SOCKS5 proxy requires SOCKS5/Tor route mode".to_owned());
        }
        if self.transport_mode == TransportPrivacyMode::TorRequired
            && (self.enable_mdns || self.enable_autonat || self.enable_dcutr)
        {
            return Err("SOCKS5/Tor route disables mDNS, AutoNAT and DCUtR".to_owned());
        }

        if self.enable_kad && kad_bootstrap_peers.is_empty() {
            return Err(
                "Kademlia requires at least one user-supplied bootstrap address".to_owned(),
            );
        }
        if !self.enable_kad && !kad_bootstrap_peers.is_empty() {
            return Err("Kademlia bootstrap addresses require Kademlia to be enabled".to_owned());
        }
        if self.relay_mode == RelayMode::Client && relay_servers.is_empty() {
            return Err(
                "Relay-client mode requires at least one user-supplied relay address".to_owned(),
            );
        }
        if self.relay_mode != RelayMode::Client && !relay_servers.is_empty() {
            return Err("Relay server addresses require relay-client mode".to_owned());
        }
        if self.dial_policy == DialPolicy::RelayOnly && self.relay_mode != RelayMode::Client {
            return Err("Relay-only routing requires relay-client mode".to_owned());
        }
        if self.dial_policy == DialPolicy::RelayOnly && self.enable_dcutr {
            return Err("Relay-only routing disables DCUtR hole punching".to_owned());
        }

        Ok(NetworkConfig {
            transport_mode: self.transport_mode,
            socks5_proxy,
            dial_policy: self.dial_policy,
            enable_identify: self.enable_identify,
            enable_ping: self.enable_ping,
            enable_mdns: self.enable_mdns,
            enable_kad: self.enable_kad,
            relay_mode: self.relay_mode,
            enable_autonat: self.enable_autonat,
            enable_dcutr: self.enable_dcutr,
            kad_bootstrap_peers,
            relay_servers,
            ..NetworkConfig::default()
        })
    }
}

/// Public network observations passed from the real Swarm worker. The GUI
/// never invents a connection, a listening address, or an optional capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub connection: String,
    pub listen_addresses: Vec<String>,
    pub connected_peers: usize,
    pub privacy: NetworkPrivacyStatus,
}

/// Short, visible copy for the file affordance. The native build opens an OS
/// picker; feature-only builds say so instead of offering a dead control.
pub fn file_picker_hint() -> &'static str {
    if cfg!(feature = "native") {
        "Choose a file from your device"
    } else {
        "File picker requires the native build"
    }
}

/// One-line default file explanation. Longer safety boundaries stay in the
/// collapsed details panel so the normal send flow is not a setup checklist.
pub fn file_send_summary() -> &'static str {
    "Files are encrypted and stay quarantined until you explicitly approve them."
}

/// Detailed network wording is opt-in so the default screen stays calm. All
/// values remain off/empty unless the user changes them explicitly.
pub fn network_settings_details() -> &'static str {
    "Optional capabilities are off and address lists are empty by default. Discovery candidates are advisory only: never auto-dialed, trusted, or fingerprint-verified. Relay-only routing avoids direct peer connections, but relay operators still see IPs, timing, and sizes and can deny service; file transfer over a relay is disabled. A SOCKS5/Tor route requires a local proxy address and removes direct listeners and DNS lookups from this app; a configured SOCKS5 proxy is policy only and the proxy itself is not established as Tor, and timing correlation remains possible. AutoNAT, mDNS and DCUtR are disabled with SOCKS5/Tor routes. MLS v3 hides sender, conversation, sequence, timestamp, and message kind inside encrypted MLS state, but relays and proxies still observe IP, timing, direction, volume, and coarse size. Wire bytes carry no transferable long-term-key authorship proof; recipients with MLS state can still attribute messages. There is no Tor/I2P/mixnet, anonymity, or complete metadata privacy claim. Settings apply when the network worker starts: lock and unlock the vault after changing them."
}

fn channel_group_label(status: ChannelGroupStatus) -> String {
    match status {
        ChannelGroupStatus::DefaultOnParent => "default text on parent MLS group".to_owned(),
        ChannelGroupStatus::DerivedReady => "derived text group ready".to_owned(),
        ChannelGroupStatus::DerivedSettingUp { awaited } => {
            format!("derived text group setting up ({awaited} acknowledgement(s) outstanding)")
        }
        ChannelGroupStatus::Missing => "derived text group not started".to_owned(),
    }
}

fn channel_group_access(status: ChannelGroupStatus) -> String {
    match status {
        ChannelGroupStatus::DefaultOnParent => {
            "default text uses parent MLS group · all parent members hold its keys · not a complete ACL".to_owned()
        }
        ChannelGroupStatus::DerivedReady => {
            "non-default text and receipts use a ready derived MLS group · parent policy stays on parent group · not a complete ACL".to_owned()
        }
        ChannelGroupStatus::DerivedSettingUp { awaited } => format!(
            "derived MLS group setting up · {awaited} acknowledgement(s) outstanding · non-default text blocked · parent policy stays on parent group"
        ),
        ChannelGroupStatus::Missing => {
            "derived MLS group not started · non-default text blocked · parent policy stays on parent group".to_owned()
        }
    }
}

/// Statuses are observations, not aspirations. Vault state, connection state,
/// and file integrity come from real workers and verified frames; independent
/// malware scanning remains unavailable.
pub fn security_rows(
    state: &VaultState,
    network: Option<&NetworkInfo>,
    group: Option<&ConversationInfo>,
) -> Vec<StatusRow> {
    let (vault, identity, fingerprint, key_protection) = match state {
        VaultState::Missing => (
            "Not created".to_owned(),
            "Not available (no vault)".to_owned(),
            "Available after vault creation".to_owned(),
            "Not active".to_owned(),
        ),
        VaultState::Locked => (
            "Locked".to_owned(),
            "Not available (vault locked)".to_owned(),
            "Available after unlock".to_owned(),
            "Not active".to_owned(),
        ),
        VaultState::Busy(VaultOperation::Creating) => (
            "Creating (Argon2id running)".to_owned(),
            "Not available (vault creating)".to_owned(),
            "Available after creation".to_owned(),
            "Being derived".to_owned(),
        ),
        VaultState::Busy(VaultOperation::Unlocking) => (
            "Unlocking (Argon2id running)".to_owned(),
            "Not available (vault unlocking)".to_owned(),
            "Available after unlock".to_owned(),
            "Being verified".to_owned(),
        ),
        VaultState::Unlocked(info) => (
            format!("Unlocked · {}", truncate(&info.profile_id, 16)),
            truncate(&info.peer_id, 18).to_owned(),
            info.fingerprint.clone(),
            info.kdf_summary.clone(),
        ),
        VaultState::Failed { .. } => (
            "Last operation failed".to_owned(),
            "Not available (vault locked)".to_owned(),
            "Available after unlock".to_owned(),
            "Not active".to_owned(),
        ),
    };

    let message_encryption = match state {
        VaultState::Unlocked(_) => {
            "MLS available (joined groups restored from encrypted vault when present)".to_owned()
        }
        VaultState::Missing | VaultState::Locked | VaultState::Failed { .. } => {
            "Not active (vault locked)".to_owned()
        }
        VaultState::Busy(_) => "Available after unlock".to_owned(),
    };

    let connection = network
        .map(|info| info.connection.clone())
        .unwrap_or_else(|| "Not started".to_owned());
    let listening = match network {
        Some(info) if !info.listen_addresses.is_empty() => info.listen_addresses.join(" · "),
        Some(_) => "None reported".to_owned(),
        None => "Not started".to_owned(),
    };

    let default_privacy = NetworkPrivacyStatus::default();
    let privacy = network
        .map(|info| &info.privacy)
        .unwrap_or(&default_privacy);
    let enabled = |value: bool| if value { "on" } else { "off" };
    let bootstrap_services = if privacy.kad_bootstrap_peers == 0 && privacy.relay_servers == 0 {
        "None configured".to_owned()
    } else {
        format!(
            "{} user-supplied Kademlia bootstrap peer(s) · {} user-supplied relay server(s)",
            privacy.kad_bootstrap_peers, privacy.relay_servers
        )
    };
    let optional_capabilities = format!(
        "identify {} · ping {} · mDNS {} · Kademlia {} · AutoNAT {} · DCUtR {}",
        enabled(privacy.identify_enabled),
        enabled(privacy.ping_enabled),
        enabled(privacy.mdns_enabled),
        enabled(privacy.kad_enabled),
        enabled(privacy.autonat_enabled),
        enabled(privacy.dcutr_enabled)
    );
    let discovery_candidates = format!(
        "{} mDNS candidate(s) · {} Kademlia route(s) · advisory only",
        privacy.discovered_candidates, privacy.kad_routes
    );
    let relay_configuration = format!(
        "{} · {} configured relay server(s)",
        privacy.relay_mode.description(),
        privacy.relay_servers
    );
    let relay_observations = format!(
        "{} reservation event(s) observed since startup · {} circuit event(s) observed since startup · {} relayed connection(s) live at last observation · no trust implied",
        privacy.relay_reservations, privacy.relay_circuits, privacy.relayed_connections
    );

    let (group_control, pending_group_change) = match group {
        Some(info) => {
            let admin = truncate(&info.admin.to_string(), 14).to_owned();
            let pending = info
                .pending_operation
                .map(|operation| format!("{} (awaiting acknowledgements)", operation.description()))
                .unwrap_or_else(|| "none".to_owned());
            (
                format!(
                    "Admin {admin} · {} members in local view",
                    info.members.len()
                ),
                pending,
            )
        }
        None => (
            "No active MLS group".to_owned(),
            "none (no group operation)".to_owned(),
        ),
    };

    let (active_channel, channel_policy, channel_access) = match group {
        Some(info) => {
            let selected = info.active_channel.and_then(|id| {
                info.channels
                    .iter()
                    .find(|channel| channel.channel_id == id)
            });
            let active_channel = match selected {
                Some(channel) => format!(
                    "#{} · revision {} · {}",
                    truncate(&channel.name, 16),
                    channel.revision,
                    channel_group_label(channel.group_status)
                ),
                None => "No channel selected".to_owned(),
            };
            let channel_policy = match selected {
                Some(channel) => format!(
                    "parent MLS group (CHN1) · {} allowed members · policy {}",
                    channel.members.len(),
                    if channel.policy_acknowledged {
                        "acknowledged"
                    } else {
                        "awaiting receipts"
                    }
                ),
                None => "none (no channel selected)".to_owned(),
            };
            let channel_access = match selected {
                Some(channel) => channel_group_access(channel.group_status),
                None => format!(
                    "{} channels in local view · default text uses parent MLS group · parent policy metadata is not a complete ACL",
                    info.channels.len()
                ),
            };
            (active_channel, channel_policy, channel_access)
        }
        None => (
            "No channel selected".to_owned(),
            "none (no active MLS group)".to_owned(),
            "none (no active MLS group)".to_owned(),
        ),
    };

    vec![
        StatusRow {
            label: "Connection",
            value: connection,
        },
        StatusRow {
            label: "Listening",
            value: listening,
        },
        StatusRow {
            label: "Local vault",
            value: vault,
        },
        StatusRow {
            label: "Local identity",
            value: identity,
        },
        StatusRow {
            label: "Fingerprint",
            value: fingerprint,
        },
        StatusRow {
            label: "Key protection",
            value: key_protection,
        },
        StatusRow {
            label: "Message encryption",
            value: message_encryption,
        },
        StatusRow {
            label: "Key agreement",
            value: "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 (0x0051); setup/file signatures use ML-DSA-65 and direct QUIC negotiates X25519MLKEM768; TCP/Noise and TLS PeerId authentication remain classical".to_owned(),
        },
        StatusRow {
            label: "Message metadata",
            value: "MLS v3 keeps sender, conversation, sequence, timestamp, and kind inside encrypted state; relays and proxies still observe IP, timing, volume, and coarse size".to_owned(),
        },
        StatusRow {
            label: "Authorship deniability",
            value: "No transferable long-term-key authorship proof in wire bytes; group members with MLS state can still attribute messages".to_owned(),
        },
        StatusRow {
            label: "Group control",
            value: group_control,
        },
        StatusRow {
            label: "Pending group change",
            value: pending_group_change,
        },
        StatusRow {
            label: "Active channel",
            value: active_channel,
        },
        StatusRow {
            label: "Channel policy",
            value: channel_policy,
        },
        StatusRow {
            label: "Channel access",
            value: channel_access,
        },
        StatusRow {
            label: "File scanner",
            value: "No scanner configured".to_owned(),
        },
        StatusRow {
            label: "File format validation",
            value: "Structural TXT / PNG / GIF only (not malware detection)".to_owned(),
        },
        StatusRow {
            label: "Attachment storage",
            value: "Ciphertext at rest in the encrypted vault".to_owned(),
        },
        StatusRow {
            label: "Quarantine deletion",
            value: "Retain by default; explicit request only where enabled".to_owned(),
        },
        StatusRow {
            label: "Transport mode",
            value: privacy.transport_mode.description().to_owned(),
        },
        StatusRow {
            label: "SOCKS5 proxy",
            value: if privacy.socks5_proxy_configured {
                "Configured (policy only; proxy identity and reachability not established)".to_owned()
            } else {
                "Not configured".to_owned()
            },
        },
        StatusRow {
            label: "Route policy",
            value: privacy.dial_policy.description().to_owned(),
        },
        StatusRow {
            label: "Bootstrap services",
            value: bootstrap_services,
        },
        StatusRow {
            label: "Optional capabilities",
            value: optional_capabilities,
        },
        StatusRow {
            label: "Discovery candidates",
            value: discovery_candidates,
        },
        StatusRow {
            label: "Relay configuration",
            value: relay_configuration,
        },
        StatusRow {
            label: "Relay observations",
            value: relay_observations,
        },
        StatusRow {
            label: "NAT observation",
            value: privacy.nat_description().to_owned(),
        },
        StatusRow {
            label: "Identify observation",
            value: format!(
                "{} identify event(s) observed since startup · transport metadata only",
                privacy.identified_peers
            ),
        },
        StatusRow {
            label: "Anonymity",
            value: "No Tor/I2P/mixnet; a configured SOCKS5 proxy is policy only, may hide IP from a direct peer, but proxy identity and reachability are not established, and peers or relays can observe timing, volume, and coarse size metadata"
                .to_owned(),
        },
    ]
}

fn truncate(value: &str, max_chars: usize) -> &str {
    match value.char_indices().nth(max_chars) {
        Some((byte_index, _)) => &value[..byte_index],
        None => value,
    }
}

pub fn runtime_banner(info: &AppInfo, state: &VaultState, network: Option<&NetworkInfo>) -> String {
    let vault = match state {
        VaultState::Missing => "no local vault",
        VaultState::Locked => "vault locked",
        VaultState::Busy(_) => "vault operation in progress",
        VaultState::Unlocked(_) => "vault unlocked",
        VaultState::Failed { .. } => "vault operation failed",
    };
    let networking = match network {
        Some(info) if info.connected_peers > 0 => "peer-to-peer connected",
        Some(_) => "peer-to-peer listening",
        None => "networking not started",
    };
    format!(
        "Native Rust runtime · v{} · {} · {vault} · {networking}",
        info.version, info.protocol
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_chat::{ChannelInfo, ConversationStatus, GroupOperation};
    use p2p_identity::Identity;

    #[test]
    fn theme_toggles() {
        assert_eq!(next_theme(Theme::Dark), Theme::Light);
        assert_eq!(next_theme(Theme::Light), Theme::Dark);
    }

    fn unlocked_info() -> UnlockedInfo {
        UnlockedInfo {
            peer_id: "12D3KooWExamplePeerIdValue123456789".to_owned(),
            fingerprint:
                "P2PMSGR-ED25519-ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567-89ABCDEF-GHIJKLMN-OPQR"
                    .to_owned(),
            profile_id: "0123456789abcdef0123456789abcdef".to_owned(),
            kdf_summary: "Argon2id · 64 MiB · t=3 · p=1".to_owned(),
        }
    }

    fn network_info(connected_peers: usize) -> NetworkInfo {
        NetworkInfo {
            connection: format!("Connected ({connected_peers})"),
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/4001".to_owned()],
            connected_peers,
            privacy: NetworkPrivacyStatus::default(),
        }
    }

    #[test]
    fn security_rows_report_real_vault_and_network_state() {
        let info = unlocked_info();
        let network = network_info(1);
        let rows = security_rows(&VaultState::Unlocked(info.clone()), Some(&network), None);

        assert_eq!(rows.len(), 30);
        assert!(
            rows.iter()
                .any(|row| row.label == "Fingerprint" && row.value == info.fingerprint)
        );
        assert!(rows.iter().any(|row| row.value.contains("Unlocked")));
        assert!(rows.iter().any(|row| row.label == "Key protection"));
        assert!(rows.iter().any(|row| {
            row.label == "File format validation"
                && row.value.contains("TXT / PNG / GIF")
                && row.value.contains("not malware detection")
        }));
        assert!(rows.iter().any(|row| {
            row.label == "Attachment storage" && row.value.contains("Ciphertext at rest")
        }));
        assert!(rows.iter().any(|row| {
            row.label == "Quarantine deletion"
                && row.value.contains("Retain by default")
                && row.value.contains("explicit request")
        }));
        assert!(
            rows.iter()
                .any(|row| row.label == "Message encryption" && row.value.contains("MLS available"))
        );
        assert!(rows.iter().any(|row| {
            row.label == "Key agreement"
                && row.value.contains("0x0051")
                && row.value.contains("ML-DSA-65")
                && row.value.contains("X25519MLKEM768")
                && row.value.contains("classical")
        }));
        assert!(rows.iter().any(|row| {
            row.label == "Message metadata" && row.value.contains("MLS v3 keeps sender")
        }));
        assert!(rows.iter().any(|row| {
            row.label == "Authorship deniability"
                && row.value.contains("group members with MLS state")
        }));
        assert!(
            rows.iter()
                .any(|row| row.label == "Connection" && row.value == network.connection)
        );
        assert!(
            rows.iter()
                .any(|row| row.label == "Listening" && row.value.contains("tcp/4001"))
        );
        for row in rows.iter().filter(|row| {
            matches!(
                row.label,
                "Message encryption"
                    | "Key agreement"
                    | "Message metadata"
                    | "Authorship deniability"
                    | "Group control"
                    | "Pending group change"
                    | "Active channel"
                    | "Channel policy"
                    | "Channel access"
                    | "File scanner"
                    | "File format validation"
                    | "Attachment storage"
                    | "Quarantine deletion"
                    | "Bootstrap services"
                    | "Optional capabilities"
                    | "Discovery candidates"
                    | "Relay configuration"
                    | "Relay observations"
                    | "NAT observation"
                    | "Identify observation"
                    | "Anonymity"
            )
        }) {
            let value = row.value.to_lowercase();
            assert!(!value.contains("connected"));
            assert!(!value.contains("verified"));
            assert!(!value.contains("clean"));
        }
    }

    #[test]
    fn group_rows_report_local_admin_members_and_pending_operation() {
        let peer = Identity::generate().expect("peer identity").peer_id();
        let group = ConversationInfo {
            conversation_id: [4u8; 16],
            peer,
            admin: peer,
            members: vec![peer],
            epoch: 6,
            status: ConversationStatus::Joined,
            pending_operation: Some(GroupOperation::Add),
            channels: vec![ChannelInfo {
                channel_id: [9u8; 16],
                name: "general".to_owned(),
                creator: peer,
                members: vec![peer],
                revision: 2,
                policy_acknowledged: false,
                group_status: ChannelGroupStatus::DefaultOnParent,
            }],
            active_channel: Some([9u8; 16]),
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, Some(&group));
        assert_eq!(rows.len(), 30);
        let control = rows
            .iter()
            .find(|row| row.label == "Group control")
            .expect("group control row");
        assert!(control.value.contains("Admin"));
        assert!(control.value.contains("1 members in local view"));
        let pending = rows
            .iter()
            .find(|row| row.label == "Pending group change")
            .expect("pending group row");
        assert!(pending.value.contains("member added"));
        assert!(pending.value.contains("awaiting acknowledgements"));
        let channel = rows
            .iter()
            .find(|row| row.label == "Active channel")
            .expect("active channel row");
        assert!(channel.value.contains("general"));
        assert!(channel.value.contains("revision 2"));
        assert!(channel.value.contains("default text on parent MLS group"));
        let policy = rows
            .iter()
            .find(|row| row.label == "Channel policy")
            .expect("channel policy row");
        assert!(policy.value.contains("parent MLS group (CHN1)"));
        assert!(policy.value.contains("policy awaiting receipts"));
        let access = rows
            .iter()
            .find(|row| row.label == "Channel access")
            .expect("channel access row");
        assert!(access.value.contains("all parent members hold its keys"));
        assert!(access.value.contains("not a complete ACL"));
    }

    #[test]
    fn default_channel_status_reports_parent_group_without_acl_claim() {
        let peer = Identity::generate().expect("peer identity").peer_id();
        let group = ConversationInfo {
            conversation_id: [10u8; 16],
            peer,
            admin: peer,
            members: vec![peer],
            epoch: 1,
            status: ConversationStatus::Joined,
            pending_operation: None,
            channels: vec![ChannelInfo {
                channel_id: [11u8; 16],
                name: "general".to_owned(),
                creator: peer,
                members: vec![peer],
                revision: 1,
                policy_acknowledged: true,
                group_status: ChannelGroupStatus::DefaultOnParent,
            }],
            active_channel: Some([11u8; 16]),
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, Some(&group));
        let active = rows
            .iter()
            .find(|row| row.label == "Active channel")
            .expect("active channel row");
        assert!(active.value.contains("default text on parent MLS group"));
        let policy = rows
            .iter()
            .find(|row| row.label == "Channel policy")
            .expect("channel policy row");
        assert!(policy.value.contains("parent MLS group (CHN1)"));
        assert!(policy.value.contains("policy acknowledged"));
        let access = rows
            .iter()
            .find(|row| row.label == "Channel access")
            .expect("channel access row");
        assert!(access.value.contains("all parent members hold its keys"));
        assert!(access.value.contains("not a complete ACL"));
    }

    #[test]
    fn derived_channel_reports_ready_group_and_parent_policy_boundary() {
        let peer = Identity::generate().expect("peer identity").peer_id();
        let group = ConversationInfo {
            conversation_id: [12u8; 16],
            peer,
            admin: peer,
            members: vec![peer],
            epoch: 2,
            status: ConversationStatus::Joined,
            pending_operation: None,
            channels: vec![ChannelInfo {
                channel_id: [13u8; 16],
                name: "ops".to_owned(),
                creator: peer,
                members: vec![peer],
                revision: 1,
                policy_acknowledged: true,
                group_status: ChannelGroupStatus::DerivedReady,
            }],
            active_channel: Some([13u8; 16]),
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, Some(&group));
        let active = rows
            .iter()
            .find(|row| row.label == "Active channel")
            .expect("active channel row");
        assert!(active.value.contains("derived text group ready"));
        let policy = rows
            .iter()
            .find(|row| row.label == "Channel policy")
            .expect("channel policy row");
        assert!(policy.value.contains("parent MLS group (CHN1)"));
        assert!(policy.value.contains("1 allowed members"));
        let access = rows
            .iter()
            .find(|row| row.label == "Channel access")
            .expect("channel access row");
        assert!(
            access
                .value
                .contains("non-default text and receipts use a ready derived MLS group")
        );
        assert!(access.value.contains("parent policy stays on parent group"));
        assert!(access.value.contains("not a complete ACL"));
    }

    #[test]
    fn derived_channel_setup_status_does_not_claim_readiness() {
        let peer = Identity::generate().expect("peer identity").peer_id();
        let group = ConversationInfo {
            conversation_id: [14u8; 16],
            peer,
            admin: peer,
            members: vec![peer],
            epoch: 3,
            status: ConversationStatus::Joined,
            pending_operation: None,
            channels: vec![ChannelInfo {
                channel_id: [15u8; 16],
                name: "ops".to_owned(),
                creator: peer,
                members: vec![peer],
                revision: 1,
                policy_acknowledged: false,
                group_status: ChannelGroupStatus::DerivedSettingUp { awaited: 2 },
            }],
            active_channel: Some([15u8; 16]),
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, Some(&group));
        let active = rows
            .iter()
            .find(|row| row.label == "Active channel")
            .expect("active channel row");
        assert!(
            active
                .value
                .contains("setting up (2 acknowledgement(s) outstanding)")
        );
        assert!(!active.value.contains("ready"));
        let policy = rows
            .iter()
            .find(|row| row.label == "Channel policy")
            .expect("channel policy row");
        assert!(policy.value.contains("policy awaiting receipts"));
        let access = rows
            .iter()
            .find(|row| row.label == "Channel access")
            .expect("channel access row");
        assert!(access.value.contains("2 acknowledgement(s) outstanding"));
        assert!(access.value.contains("non-default text blocked"));
        assert!(!access.value.contains("text and receipts use a ready"));
    }

    #[test]
    fn absent_network_never_claims_a_connection() {
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, None);
        let connection = rows
            .iter()
            .find(|row| row.label == "Connection")
            .expect("connection row");
        assert_eq!(connection.value, "Not started");
        let listening = rows
            .iter()
            .find(|row| row.label == "Listening")
            .expect("listening row");
        assert_eq!(listening.value, "Not started");
    }

    #[test]
    fn locked_and_missing_states_expose_no_identity() {
        for state in [VaultState::Missing, VaultState::Locked] {
            let rows = security_rows(&state, None, None);
            let identity = rows
                .iter()
                .find(|row| row.label == "Local identity")
                .expect("identity row");
            assert!(identity.value.contains("Not available"));
            let fingerprint = rows
                .iter()
                .find(|row| row.label == "Fingerprint")
                .expect("fingerprint row");
            assert!(fingerprint.value.contains("Available after"));
        }
    }

    #[test]
    fn failed_state_keeps_the_identity_hidden() {
        let state = VaultState::Failed {
            operation: VaultOperation::Unlocking,
            message: "incorrect password or damaged vault".to_owned(),
        };
        let rows = security_rows(&state, None, None);
        let identity = rows
            .iter()
            .find(|row| row.label == "Local identity")
            .expect("identity row");
        assert!(identity.value.contains("Not available"));
        let encryption = rows
            .iter()
            .find(|row| row.label == "Message encryption")
            .expect("encryption row");
        assert_eq!(encryption.value, "Not active (vault locked)");
        assert!(
            runtime_banner(&p2p_core::app_info(), &state, None).contains("vault operation failed")
        );
    }

    #[test]
    fn truncate_handles_short_and_unicode_strings() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("a📱b", 2), "a📱");
    }

    #[test]
    fn banner_uses_real_build_info_and_observed_states() {
        let info = p2p_core::app_info();
        let banner = runtime_banner(&info, &VaultState::Missing, None);
        assert!(banner.contains(&info.version));
        assert!(banner.contains(&info.protocol));
        assert!(banner.contains("no local vault"));
        assert!(banner.contains("networking not started"));

        let unlocked = runtime_banner(
            &info,
            &VaultState::Unlocked(unlocked_info()),
            Some(&network_info(2)),
        );
        assert!(unlocked.contains("vault unlocked"));
        assert!(unlocked.contains("peer-to-peer connected"));
        assert!(!unlocked.contains("not persisted"));
    }

    fn direct_address() -> String {
        let peer = Identity::generate().expect("peer identity").peer_id();
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
    }

    #[test]
    fn network_options_default_fails_closed_until_a_proxy_is_configured() {
        let error = NetworkOptions::default()
            .to_config()
            .expect_err("default must not fall back to a direct route");
        assert!(error.contains("direct fallback is disabled"));
    }

    #[test]
    fn network_options_direct_opt_in_is_explicit() {
        let config = NetworkOptions::direct()
            .to_config()
            .expect("explicit direct config");
        assert!(!config.enable_identify);
        assert!(!config.enable_ping);
        assert!(!config.enable_mdns);
        assert!(!config.enable_kad);
        assert!(!config.enable_autonat);
        assert!(!config.enable_dcutr);
        assert!(config.kad_bootstrap_peers.is_empty());
        assert!(config.relay_servers.is_empty());
        assert_eq!(config.relay_mode, RelayMode::Off);
        assert_eq!(config.transport_mode, TransportPrivacyMode::Direct);
        assert!(config.socks5_proxy.is_none());
        assert_eq!(config.dial_policy, DialPolicy::DirectAllowed);
    }

    #[test]
    fn network_options_validate_user_supplied_addresses() {
        let address = direct_address();
        let kad = NetworkOptions {
            enable_kad: true,
            kad_bootstrap_peers: format!("{address}, {address}"),
            ..NetworkOptions::direct()
        };
        assert_eq!(
            kad.to_config()
                .expect("valid bootstrap addresses")
                .kad_bootstrap_peers
                .len(),
            2
        );

        let no_peer = NetworkOptions {
            enable_kad: true,
            kad_bootstrap_peers: "/ip4/127.0.0.1/tcp/4001".to_owned(),
            ..NetworkOptions::direct()
        };
        assert!(no_peer.to_config().is_err());

        let circuit = NetworkOptions {
            relay_mode: RelayMode::Client,
            relay_servers: format!("{address}/p2p-circuit"),
            ..NetworkOptions::direct()
        };
        assert!(circuit.to_config().is_err());
    }

    #[test]
    fn network_options_socks5_route_requires_an_ip_literal_proxy() {
        let valid = NetworkOptions {
            transport_mode: TransportPrivacyMode::TorRequired,
            socks5_proxy: "127.0.0.1:9050".to_owned(),
            ..NetworkOptions::direct()
        };
        let config = valid.to_config().expect("valid proxy route");
        assert_eq!(config.transport_mode, TransportPrivacyMode::TorRequired);
        assert_eq!(
            config.socks5_proxy,
            Some("127.0.0.1:9050".parse().expect("proxy socket addr"))
        );

        assert!(
            NetworkOptions {
                transport_mode: TransportPrivacyMode::TorRequired,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                transport_mode: TransportPrivacyMode::TorRequired,
                socks5_proxy: "localhost:9050".to_owned(),
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                transport_mode: TransportPrivacyMode::TorRequired,
                socks5_proxy: "127.0.0.1:9050".to_owned(),
                enable_mdns: true,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                socks5_proxy: "127.0.0.1:9050".to_owned(),
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
    }

    #[test]
    fn network_options_relay_only_rejects_direct_and_conflicting_settings() {
        let address = direct_address();
        let valid = NetworkOptions {
            dial_policy: DialPolicy::RelayOnly,
            relay_mode: RelayMode::Client,
            relay_servers: address.clone(),
            ..NetworkOptions::direct()
        };
        let config = valid.to_config().expect("valid relay-only config");
        assert_eq!(config.dial_policy, DialPolicy::RelayOnly);
        assert_eq!(config.relay_servers.len(), 1);

        assert!(
            NetworkOptions {
                dial_policy: DialPolicy::RelayOnly,
                relay_servers: address,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                dial_policy: DialPolicy::RelayOnly,
                relay_mode: RelayMode::Client,
                relay_servers: direct_address(),
                enable_dcutr: true,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
    }

    #[test]
    fn network_options_require_addresses_for_kad_and_relay_client() {
        assert!(
            NetworkOptions {
                enable_kad: true,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                relay_mode: RelayMode::Client,
                ..NetworkOptions::direct()
            }
            .to_config()
            .is_err()
        );
        let address = direct_address();
        let relay = NetworkOptions {
            relay_mode: RelayMode::Client,
            relay_servers: address,
            ..NetworkOptions::direct()
        };
        assert!(relay.to_config().is_ok());

        let unused = NetworkOptions {
            kad_bootstrap_peers: direct_address(),
            ..NetworkOptions::direct()
        };
        assert!(unused.to_config().is_err());
    }

    #[test]
    fn privacy_rows_distinguish_configuration_from_observation() {
        let mut network = network_info(0);
        network.privacy = NetworkPrivacyStatus {
            identify_enabled: true,
            mdns_enabled: true,
            kad_enabled: true,
            kad_bootstrap_peers: 1,
            relay_mode: RelayMode::Client,
            relay_servers: 1,
            discovered_candidates: 2,
            kad_routes: 3,
            relay_reservations: 1,
            relay_circuits: 1,
            identified_peers: 4,
            relayed_connections: 5,
            ..NetworkPrivacyStatus::default()
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), Some(&network), None);
        assert_eq!(rows.len(), 30);
        let value = |label: &'static str| {
            rows.iter()
                .find(|row| row.label == label)
                .expect("status row")
                .value
                .clone()
        };
        assert!(value("Transport mode").contains("Direct TCP + Noise"));
        assert!(value("Transport mode").contains("QUIC hybrid KEX"));
        assert!(value("Transport mode").contains("not anonymous"));
        assert!(value("Transport mode").contains("PeerId auth classical"));
        assert_eq!(value("SOCKS5 proxy"), "Not configured");
        assert!(value("Key agreement").contains("0x0051"));
        assert!(value("Key agreement").contains("ML-DSA-65"));
        assert!(value("Key agreement").contains("X25519MLKEM768"));
        assert!(value("Key agreement").contains("PeerId authentication remain classical"));
        assert!(value("Message metadata").contains("relays and proxies still observe IP"));
        assert!(value("Authorship deniability").contains("No transferable"));
        assert!(value("Route policy").contains("Direct allowed"));
        assert!(value("Route policy").contains("not anonymous"));
        assert!(value("Bootstrap services").contains("1 user-supplied"));
        assert!(value("Optional capabilities").contains("identify on"));
        assert!(value("Optional capabilities").contains("ping off"));
        assert!(value("Discovery candidates").contains("2 mDNS candidate(s)"));
        assert!(value("Discovery candidates").contains("advisory only"));
        assert!(value("Relay configuration").contains("reservation not implied"));
        assert!(
            value("Relay observations").contains("1 reservation event(s) observed since startup")
        );
        assert!(value("Relay observations").contains("1 circuit event(s) observed since startup"));
        assert!(value("Relay observations").contains("5 relayed connection(s) live"));
        assert!(
            value("Identify observation").contains("4 identify event(s) observed since startup")
        );
        assert!(value("NAT observation").contains("no AutoNAT observation"));
        assert!(value("Anonymity").contains("No Tor/I2P/mixnet"));
    }

    #[test]
    fn file_picker_copy_does_not_ask_for_a_manual_path() {
        let hint = file_picker_hint();
        assert!(!hint.contains("path"));
        assert!(hint.contains("Choose a file") || hint.contains("native build"));
        assert!(file_send_summary().contains("quarantined"));
    }

    #[test]
    fn network_details_keep_the_bounded_non_claims() {
        let details = network_settings_details();
        assert!(details.contains("off and address lists are empty by default"));
        assert!(details.contains("advisory only"));
        assert!(details.contains("relay"));
        assert!(details.contains("no Tor/I2P/mixnet"));
        assert!(details.contains("MLS v3 hides sender"));
        assert!(
            details.contains("Wire bytes carry no transferable long-term-key authorship proof")
        );
        assert!(details.contains("configured SOCKS5 proxy is policy only"));
    }
}
