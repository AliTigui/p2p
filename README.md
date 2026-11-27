# P2P Messenger

A decentralized, end-to-end encrypted desktop messenger. **No mandatory centralized server**: users generate their own identities, exchange addresses/fingerprints directly, and communicate over libp2p. Relay and discovery peers are optional and user-operated.

> **Status: Milestones 1–13 complete, plus post-M13 durable control-log/anchor work (not a new milestone); Milestone 13 metadata/privacy hardening and the durability increment are implemented and verified on this Linux host and in green GitHub CI. Optional discovery, relay, NAT, identify, ping, and control capabilities are all off/empty by default; zero-infrastructure direct connect is unchanged.** Direct P2P connect works with only the other peer's multiaddr: TCP + Noise + Yamux, vault-derived Ed25519 identity, real connection status, and zero bootstrap/DHT/relay infrastructure. Peers can complete a signed KeyPackage/Welcome MLS setup, exchange OpenMLS-encrypted text, and advance delivery only on explicit verified receipts. An admin can add, remove, and refresh keys in a multi-member MLS group; group changes use signed, bounded frames in the existing setup protocol and stay pending until required members acknowledge. Milestone 10 adds bounded `CHN1` channel frames inside the MLS application plaintext: every conversation starts with `general`, the admin can create/rename/set members of channels, allowed members can post text, and restricted sends go only to allowed members. Channel membership is local application policy, not cryptographic access control, because all MLS group members hold the group keys. Text composed while a peer is disconnected stays in a ciphertext queue that is encrypted in the vault when a session is attached and is retried only after a new observed connection. Saved user addresses get bounded exponential redial with honest retry state; duplicate dials, extra connections, and excess per-peer requests are rejected. A joined conversation can send files up to 64 MiB as signed, XChaCha20-Poly1305-encrypted chunks with manifest hash verification and ciphertext-only quarantine. Milestone 8 adds narrow TXT/PNG/GIF validation, a conservative scanner/release policy, explicit per-file approval/cancellation, an encrypted attachment store, a native-only OS save flow, and explicit deletion policies. The application configures **no** scanner, no allowed extensions, and `Retain` quarantine deletion by default: integrity verification is never presented as "clean" or "safe", release is denied, and no release or quarantine-deletion action is shown. Admin role delegation, general format/MIME parsing, a configured real scanner, and backups are not implemented yet. Milestone 12 adds cross-platform safe export names, an unraisable 64 MiB release cap, safer native plaintext save, Unix symlink refusal for vault/quarantine paths, redacted transport-event `Debug`, and bounded contact/envelope inputs. Windows ACL hardening, secure erasure, and dependency advisory tooling remain unimplemented; the repository-wide diagnostic review, path/error redaction regressions, and CI diagnostic guard are complete. A post-M13 schema v4 durable setup/group-control digest log with an AEAD-protected, profile-bound anchor gives partial rollback detection only: it cannot detect a restore of the whole vault including the anchor, is not replay-proof, and does not restore MLS state. See [`PROJECT_STATUS.md`](PROJECT_STATUS.md).

## Technology

Pure Rust. No React, TypeScript, Node.js, npm, browser, or webview.

- GUI: `egui` + `eframe`
- Networking: `libp2p` direct connect (TCP + Noise + Yamux; `=0.57.1`), with opt-in mDNS/Kademlia discovery, peer-operated relays, AutoNAT/DCUtR and identify observations; all optional capabilities off by default
- Messaging: canonical signed envelopes, replay cache, MLS-encrypted receipts, honest delivery state, ciphertext-only vault persistence (schema v5) with a durable setup/group-control digest log and partial rollback detection, plus ADR-0014 encrypted opaque MLS-value storage, anchor watermarks, a staged vault-backed OpenMLS `StorageProvider` adapter, and Phase 4 controller restoration of joined groups, pending operations, receipts, and queued ciphertext
- Application: `p2p-chat` controller for signed MLS setup and group control, compose/receive, verified receipts, a ciphertext-only offline send queue with reconnect retry, bounded redial with honest `RedialState`, encrypted file transfers, and `start_with_control_log`, which attaches a cloned vault `Session` with matching identity to record authenticated frame digests and restore encrypted state. With that session, ADR-0014 Phase 4 restores explicitly `Joined` MLS groups, channel policy, bounded pending operations, receipt expectations, and queued ciphertext; decrypted messages remain memory-only. Controllers started without a vault session keep the original memory-only path.
- Wire: bounded `/p2p-messenger/message/1`, `/p2p-messenger/mls-setup/1`, `/p2p-messenger/file/1`, and M13's opaque `/p2p-messenger/control/1` request-response protocols over the Noise-authenticated connection, with duplicate-dial rejection, connection admission limits, bounded relayed connections, and aggregate plus per-protocol request/byte budgets
- Group crypto: `openmls` 0.10.0-rc.1 with X25519/AES-128-GCM/SHA-256/Ed25519; signed multi-member Add/Remove/Update, admin policy, pending commit state, and runtime group state that restores from the encrypted vault when a session is attached. The RC line is used because it carries the patched RustCrypto big-integer stack; this is not a production-stability claim.
- Files: fresh per-transfer XChaCha20-Poly1305 key, 256 KiB chunks, signed SHA-256 manifest, restricted ciphertext-only quarantine, bounded in-memory scanner input, narrow TXT/PNG/GIF structural validation, policy-gated in-memory release, encrypted attachment storage, and explicit deletion policies
- Storage: bundled SQLite + Argon2id/XChaCha20-Poly1305 vault with schema v5 encrypted attachments, `control_log`/`control_state` plus a profile-bound-AAD `<vault>/control.anchor` (v2 adds authoritative per-group MLS watermarks), ADR-0014 encrypted opaque MLS-state rows with blind indexes and per-group chains, a staged transactionally flushed OpenMLS `StorageProvider` adapter, and an authenticated version-2 application record for restore; native-only OS save uses the optional `rfd` dialog
- Hardening: safe release/suggested-save names, hard release byte cap, Unix symlink refusal for vault/quarantine paths, symlink-safe attachment deletion, redacted transport-event diagnostics, and bounded untrusted contact/export inputs

## Quick start

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Compile GUI widget code without display libraries:
cargo check -p p2p-desktop --features gui

# Open the real native window:
cargo run -p p2p-desktop --features native
```

The `native` feature builds a real OS window on Linux/Windows/macOS. Widget code is separately checkable with `--features gui`, so core tests never need display libraries.

## Release artifacts

The build workflow produces locked, release-mode artifacts for Linux x86_64 (`.tar.gz`, `.deb`), Windows x86_64 (`.zip`, `.msi`), and macOS x86_64/arm64 (`.tar.gz`, `.dmg`). On 2026-11-25 all four targets built green in GitHub CI and all eight downloaded per-artifact SHA-256 sidecars verified. Tagged `v*` releases include a single `SHA256SUMS` manifest; verify it with `sha256sum -c SHA256SUMS` before installing. Exact build, inspection, and signing commands are in [docs/BUILDING.md](docs/BUILDING.md). Packages are unsigned by default and macOS DMGs are not notarized by default; GitHub Releases are only a download convenience, not application infrastructure. There is no auto-updater or phone-home service.

On first launch the app asks you to create a local vault (profile name + password). Later launches ask for the password to unlock it. The identity is generated inside the vault, encrypted at rest, and only its public Peer ID and fingerprint are shown once unlocked. There is no account, server, or password recovery.

After unlock, the network worker starts automatically and listens on an ephemeral local TCP port. To connect directly, paste a peer address that ends in `/p2p/<peer-id>`, for example `/ip4/192.0.2.10/tcp/4001/p2p/12D3Koo...`. The address must be supplied by you; the app has no default bootstrap peers. A connected PeerId means the Noise handshake authenticated that key, not that the person is your intended contact — verify fingerprints out of band.

Optional network capabilities are off and their address lists are empty by default. In the unlocked network panel you can enable identify, ping, mDNS, Kademlia with user-supplied bootstrap addresses, relay client/server mode with user-supplied relay addresses, AutoNAT, and DCUtR; settings apply when the worker starts, so lock and unlock the vault after changing them. Advanced settings also offer relay-only dialing and a SOCKS5 proxy route, both reported as route policies rather than verified anonymity. Discovery candidates are advisory only and are never auto-dialed, trusted, or treated as verified contacts. With pinned `libp2p 0.57.1`, relays forward Noise-protected opaque bytes: operators can observe PeerIds, IPs, timing, and sizes and can deny service, but cannot read application plaintext or file content keys. File transfer over an observed relay path is nevertheless disabled as a conservative metadata/policy choice pending a dedicated relay-safe file-key/transport design. Relay reservation/circuit and identify counters show events observed since startup, not live state. AutoNAT/DCUtR are best-effort, not universal NAT traversal. MLS plaintext is padded to fixed buckets before encryption, which only coarsens lengths. There is no verified Tor/I2P/mixnet, anonymity, proxy identity, or metadata-privacy claim.

For a 1:1 encrypted chat, connect first, then paste the peer's Peer ID into the MLS section and choose **Start encrypted chat**. The peer receives a signed KeyPackage request and replies with a signed KeyPackage; the inviter sends a signed Welcome; the invited peer joins and returns a signed acknowledgement. The UI shows the real setup status and epoch. Text messages are MLS-encrypted; local status remains "Sent to peer (delivery unconfirmed)" until a verified encrypted receipt arrives. Setup KeyPackages/Welcomes and decrypted text are session-only. With a vault session, a joined conversation's MLS state, policy, pending operations, receipt expectations, and queued ciphertext restore from authenticated encrypted records with fail-closed validation; the durable control log records only frame digests for partial rollback detection and is not itself a restore path.

The conversation creator is the group admin. Once a group is joined, the admin can add a directly connected peer, remove another member, or refresh its own MLS key. Each change is a signed MLS commit merged locally and sent to the required existing members; the group shows a pending operation until the Welcome and all required acknowledgements are verified. Messages and further changes are blocked while pending, and a disconnected required member can leave the operation pending until it reconnects. A removed member stays on the old epoch and cannot read later group messages. Group text is sent once as MLS ciphertext to every current member and is shown as delivered only after every expected receipt arrives. The app shows admin, members in its local view, and pending state; these are not inferred from transport events.

If the peer disconnects, newly composed text is signed and encrypted immediately but shown as **Queued (offline)**. It is held as ciphertext and retried only after a new authenticated connection to that peer is observed; a queued message is never shown as delivered without its verified receipt. The queue is encrypted in the vault when a session is attached and can survive restart; without a session it remains memory-only. Decrypted text is never written to the vault.

Saved addresses trigger a bounded exponential redial after an observed disconnect or failed dial. The GUI shows the honest retry state separately from the observed connection state; **Disconnect all** suppresses redial until you enter a fresh address. No peer is discovered or contacted without your explicit address.

For a joined conversation, enter a local file path and choose **Send encrypted file**. The offer carries a fresh random content key inside the signed frame over the existing Noise connection; the receiver quarantines ciphertext only. Both sides mark a transfer `Integrity verified; not scanned` only after signed chunk acknowledgements and a verified SHA-256 manifest. The Rust controller can validate the claimed TXT/PNG/GIF structure in memory, scan verified plaintext through an application-supplied `FileScanner`, then release it only if the format is valid, the scanner reports `CleanNoThreatDetected`, the extension/size policy allows it, and the user explicitly approves that file. Approval releases a zeroizing in-memory buffer that the desktop app copies into the encrypted attachment store; the release path writes no plaintext. In native builds, **Save via OS dialog** is the only plaintext disk write and requires you to choose the destination. Stored attachments and quarantine ciphertext are deleted only by separate explicit actions; quarantine deletion defaults to `Retain`. Active transfers have an inactivity deadline and can be aborted locally; abort stops new frames, drops pending response bookkeeping, zeroizes the in-memory key, and removes incomplete quarantine ciphertext. Cancelling a release decision applies only after integrity verification, is terminal for that release, and retains verified ciphertext for separate explicit deletion. The desktop app configures no scanner and no allowed extensions, so its UI shows "Scanning unavailable" and no approve/release/cancel action appears by default. Structural validation is not malware detection, and no file is presented as clean or safe without a real independent scanner result.

## Repository layout

```
crates/core                  shared types, protocol version, errors
crates/crypto                Argon2id, AEAD wrapping, HKDF subkeys, blind indexes
crates/identity              Ed25519 identity, fingerprints, contact URIs, encrypted export
crates/groups                OpenMLS lifecycle, encrypted payloads/receipts, sender binding, Add/Remove/Update commits
crates/files                 signed file frames, chunk AEAD, manifest verification, ciphertext-only quarantine, scan/release gate, explicit quarantine deletion
crates/security              independent scanner interface, exact result categories, conservative release policy
crates/chat                  signed MLS setup/group-control frames, conversation controller with optional durable control-log attachment via a cloned vault Session, admin policy and pending-operation state, memory-only chat view, offline queue, bounded redial, file transfer state, scan/release/deletion API
crates/messaging             signed envelopes, replay cache, receipt codec, delivery state
crates/network               libp2p direct connect, four bounded wire protocols, opt-in discovery/relay/NAT/identify behaviours, real Swarm events, connection/rate limits, honest privacy status
crates/storage               encrypted SQLite vault, schema v5 encrypted attachments, transactional control_log/control_state and mls_groups/mls_state migrations, AEAD v2 control anchor with authoritative MLS watermarks and partial rollback detection, encrypted opaque MLS-state foundation, settings
apps/desktop/src/model.rs    GUI state and pure helpers (tests)
apps/desktop/src/app.rs      egui widget descriptions
apps/desktop/src/lib.rs      feature-gated native runner
packaging/                   Linux/Windows/macOS package scripts and notice
docs/                        architecture, security, networking, crypto, storage, protocol, building
docs/DECISIONS/              architecture decision records
tests/                       cross-crate test plan (implemented tests live beside crates)
```

## Design documents

- [Architecture](docs/ARCHITECTURE.md)
- [Security / threat model](docs/SECURITY.md)
- [Networking](docs/NETWORKING.md)
- [Cryptography](docs/CRYPTOGRAPHY.md)
- [Storage](docs/STORAGE.md)
- [Wire protocol](docs/PROTOCOL.md)
- [Dependency validation](docs/DEPENDENCIES.md)
- [Software bill of materials](docs/SBOM.md)
- [Building and packaging](docs/BUILDING.md)
- [Decision records](docs/DECISIONS/)

## Non-goals for the initial release

- No developer-operated bootstrap, relay, identity, or messaging service, and no auto-updater or telemetry in release packages.
- No signed/notarized binaries or bit-for-bit reproducible builds by default; verify published checksums or build from source.
- No Windows ACL hardening or filesystem secure-erasure guarantee: non-Unix permission helpers are no-ops, and deletion does not erase SSD/CoW blocks.
- No claim of universal NAT traversal or metadata anonymity. Optional relays expose PeerIds, IPs, timing, and sizes to their operators, although Noise prevents them from reading application plaintext or file content keys; discovery candidates are advisory only and are never auto-dialed or trusted; control frames carry no capability, presence, receipt, or delivery meaning.
- No multi-device shared identity (identities are device-specific in v1).
- No password recovery without an encrypted backup and its passphrase.
- No cryptographic channel access control: channels are MLS application partitions with local policy; no separate per-channel MLS keys. No admin role delegation or encrypted MLS state restoration in v1; MLS groups, channels, and pending operations are session-only.
- No detection of a restore of the whole vault including `control.anchor`: the post-M13 digest log detects a DB older than its anchor and anchor tampering, but has no external anchor to compare against and is not replay-proof. The anchor is not a backup and does not restore MLS or channel state.
- No "clean", "safe", or "scanned" file claim from integrity checking or narrow structural validation alone: the desktop app configures no independent scanner, and the API only accepts an exact scanner result through `SecurityConfig::scan`.
