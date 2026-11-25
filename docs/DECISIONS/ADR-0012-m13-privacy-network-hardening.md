# ADR-0012: Milestone 13 optional discovery, relay, and metadata hardening

- Status: Accepted
- Date: 2026-11-25
- Milestone: M13
- Related: ADR-0001, ADR-0006, ADR-0007, ADR-0011

## Context

The working zero-infrastructure path must remain unchanged: two installations with only each other's direct multiaddrs can connect, authenticate via Noise, and run MLS-protected conversations without any bootstrap, DHT, relay, account, signaling, or discovery service.

Users also asked for honest, optional support for discovery, peer-operated relays, NAT-related observations, and protocol-metadata handling. These capabilities expose additional IP, timing, size, and protocol information. They must not be silently enabled, must not turn observations into trust, and must not degrade the direct-connect path.

## Decision

1. **Defaults remain empty and off.** `NetworkConfig` and the GUI `NetworkOptions` default to `identify = false`, `ping = false`, `mDNS = false`, Kademlia off with no bootstrap peers, `RelayMode::Off` with no relay servers, AutoNAT off, DCUtR off, and a bounded relayed-connection cap of four. No developer-operated address is compiled in.
2. **Optional capabilities are explicit and startup-only.** mDNS, Kademlia, relay client/server, identify, ping, AutoNAT, and DCUtR are wrapped in initialization-time `Toggle`s or equivalent configurations. Changing them requires locking and unlocking the vault, which restarts the network worker. Only addresses the user supplies are contacted at startup.
3. **Discovery is advisory only.** mDNS and Kademlia events update bounded counters in `NetworkPrivacyStatus`. Discovered peers are candidates, never auto-dialed, saved as contacts, marked verified, or treated as authenticated humans. Kademlia requires user-supplied bootstrap addresses; `/p2p-circuit` and addresses without `/p2p/<peer-id>` are rejected.
4. **Relays are explicitly configured and bounded.** Relay-client mode requires user-supplied direct relay addresses; relay-server mode is bounded by configured circuit/reservation rates and a maximum circuit count. Relayed connections are separately capped and counted from real `is_relayed()` connection observations. A relayed connection does not imply a reservation, trust, contact identity, or delivery.
5. **File transfer over a relay is refused.** The signed M7 file offer carries the fresh content key inside the offer frame. A relay would see that framed key bytes, so `Network::send_file` emits an honest `FileEvent::Failed` with reason `file transfer over a relay is disabled by policy` when a peer has any observed relayed connection. A separate end-to-end key exchange is required before this restriction may be lifted.
6. **Identify and control frames are opaque transport observations.** When explicitly enabled, identify hides listen addresses, pushes no address updates, and bounds protocol/agent strings before they reach events or diagnostics. The new `/p2p-messenger/control/1` protocol uses the same bounded opaque codec; the controller drains control frames but derives no capability, contact, verification, or delivery semantics from them.
7. **Status separates configuration from observation.** `NetworkPrivacyStatus` distinguishes local flags and configured-address counts from counters and strings changed only by real libp2p events. NAT text is best-effort (`Unknown`, `Private`, or `Public` observed by AutoNAT) and never claims universal reachability. The GUI renders these fields as transport metadata only.
8. **The pure Rust GUI remains authoritative.** M13 adds opt-in checkboxes, relay mode selection, and user-supplied bootstrap/relay address fields to the egui shell. No Tauri, React, TypeScript, npm, webview, or browser dependency was introduced. No network work runs on the UI thread.

## Consequences

- The direct-connect acceptance path still passes with no configuration and no external infrastructure.
- Optional discovery can reveal queries and candidate addresses to user-chosen peers; relay operators can observe IPs, timing, and sizes and can deny service. The UI and documentation say so explicitly.
- AutoNAT and DCUtR are best-effort observations and hole-punch attempts, not universal NAT traversal.
- Enabling identify reveals a bounded protocol/agent description even though listen addresses are hidden; it remains off by default.
- Control frames cannot be used to claim presence, capabilities, receipts, or safety until a separate application protocol is designed and tested.
- File transfers remain direct-only. This preserves the M7 content-key design without pretending a relay cannot read the offer.
- Optional settings are not live-mutable; the lock/unlock cycle restarts the worker and makes that limitation visible.

## Non-claims

- No strong anonymity, Tor/I2P/mixnet support, metadata confidentiality, or unlinkability.
- No automatic dialing of discovered peers and no trust or fingerprint verification from discovery, identify, relay, NAT, or control observations.
- No guaranteed NAT traversal or relay reachability.
- No cryptographic channel ACL, admin delegation, encrypted MLS persistence, real scanner, or verified Windows/macOS artifact is added by this ADR.
- No mandatory centralized infrastructure of any kind.

## Verification

M13 verification is recorded in `PROJECT_STATUS.md` and `tests/README.md`. It covers default-off configuration, direct-address validation including `/p2p-circuit` rejection, bounded codec/control round trips, redacted event `Debug`, privacy snapshot defaults, GUI rows that distinguish configuration from observation, the serialized workspace test suite, clippy, feature checks, native build, and local Linux release packaging.
