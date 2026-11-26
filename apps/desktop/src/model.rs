//! UI state and pure helpers. This module has no GUI-toolkit dependency so it
//! can be unit-tested on any host, including machines without display libraries.

use p2p_chat::{ConversationInfo, parse_address};
use p2p_core::AppInfo;
use p2p_network::{NetworkConfig, NetworkPrivacyStatus, RelayMode};

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

/// User-editable optional network settings. Every field is off or empty by
/// default. These are local configuration values, not observed capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkOptions {
    pub enable_identify: bool,
    pub enable_ping: bool,
    pub enable_mdns: bool,
    pub enable_kad: bool,
    pub kad_bootstrap_peers: String,
    pub relay_mode: RelayMode,
    pub relay_servers: String,
    pub enable_autonat: bool,
    pub enable_dcutr: bool,
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            enable_identify: false,
            enable_ping: false,
            enable_mdns: false,
            enable_kad: false,
            kad_bootstrap_peers: String::new(),
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

        Ok(NetworkConfig {
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
                    "#{} · revision {}",
                    truncate(&channel.name, 16),
                    channel.revision
                ),
                None => "No channel selected".to_owned(),
            };
            let channel_policy = match selected {
                Some(channel) if channel.acknowledged => format!(
                    "{} allowed members · policy acknowledged",
                    channel.members.len()
                ),
                Some(channel) => format!(
                    "{} allowed members · policy awaiting receipts",
                    channel.members.len()
                ),
                None => "none (no channel selected)".to_owned(),
            };
            (
                active_channel,
                channel_policy,
                format!(
                    "{} channels in local view · application policy only",
                    info.channels.len()
                ),
            )
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
            value: "No Tor/I2P/mixnet; peers and relays can observe IP, timing, and size metadata"
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

        assert_eq!(rows.len(), 24);
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
                acknowledged: false,
            }],
            active_channel: Some([9u8; 16]),
        };
        let rows = security_rows(&VaultState::Unlocked(unlocked_info()), None, Some(&group));
        assert_eq!(rows.len(), 24);
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
        let policy = rows
            .iter()
            .find(|row| row.label == "Channel policy")
            .expect("channel policy row");
        assert!(policy.value.contains("policy awaiting receipts"));
        let access = rows
            .iter()
            .find(|row| row.label == "Channel access")
            .expect("channel access row");
        assert!(access.value.contains("1 channels in local view"));
        assert!(access.value.contains("application policy only"));
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
    fn network_options_default_to_all_off() {
        let config = NetworkOptions::default()
            .to_config()
            .expect("default config");
        assert!(!config.enable_identify);
        assert!(!config.enable_ping);
        assert!(!config.enable_mdns);
        assert!(!config.enable_kad);
        assert!(!config.enable_autonat);
        assert!(!config.enable_dcutr);
        assert!(config.kad_bootstrap_peers.is_empty());
        assert!(config.relay_servers.is_empty());
        assert_eq!(config.relay_mode, RelayMode::Off);
    }

    #[test]
    fn network_options_validate_user_supplied_addresses() {
        let address = direct_address();
        let kad = NetworkOptions {
            enable_kad: true,
            kad_bootstrap_peers: format!("{address}, {address}"),
            ..NetworkOptions::default()
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
            ..NetworkOptions::default()
        };
        assert!(no_peer.to_config().is_err());

        let circuit = NetworkOptions {
            relay_mode: RelayMode::Client,
            relay_servers: format!("{address}/p2p-circuit"),
            ..NetworkOptions::default()
        };
        assert!(circuit.to_config().is_err());
    }

    #[test]
    fn network_options_require_addresses_for_kad_and_relay_client() {
        assert!(
            NetworkOptions {
                enable_kad: true,
                ..NetworkOptions::default()
            }
            .to_config()
            .is_err()
        );
        assert!(
            NetworkOptions {
                relay_mode: RelayMode::Client,
                ..NetworkOptions::default()
            }
            .to_config()
            .is_err()
        );
        let address = direct_address();
        let relay = NetworkOptions {
            relay_mode: RelayMode::Client,
            relay_servers: address,
            ..NetworkOptions::default()
        };
        assert!(relay.to_config().is_ok());

        let unused = NetworkOptions {
            kad_bootstrap_peers: direct_address(),
            ..NetworkOptions::default()
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
        assert_eq!(rows.len(), 24);
        let value = |label: &'static str| {
            rows.iter()
                .find(|row| row.label == label)
                .expect("status row")
                .value
                .clone()
        };
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
}
