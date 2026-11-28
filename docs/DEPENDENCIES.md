# Dependency Validation Record

The baseline was checked on **2026-11-25** using `cargo info`, `cargo search`, `cargo` resolution output, and published `Cargo.toml` feature tables in this workspace. Toolchain for that baseline: Rust 1.97.1, Cargo 1.97.1. Later Q3/Q4 dependency additions are recorded separately below and are local/uncommitted; no current package count, lockfile hash, or external verification result is asserted here. There is no Node.js/npm dependency in the application.

## Rust crates

| Crate | Stable version chosen | MSRV | Decision |
|---|---|---|---|
| `egui` | 0.35.0 | 1.92 | Pure-Rust immediate-mode GUI description; no webview or JS runtime. Selected with eframe 0.35 to keep the libp2p 0.57 graph resolvable. |
| `eframe` | 0.35.0 | 1.92 | Native OS window integration for egui. The `clipboard` feature was removed in 0.35; clipboard handling is provided by egui-winit. |
| `rfd` | 0.18.0 | 1.92 | MIT, published docs.rs documentation dated 07 November 2026, and active `PolyMeilex/rfd` repository. Checked with `cargo info` (MIT, MSRV 1.92, default features `xdg-portal` + `wayland`). Added as an **optional native-only** dependency for the OS save dialog; `gui`/default builds do not compile it. `FileDialog::new().set_file_name(name).save_file()` returns `Option<PathBuf>`; a cancelled dialog writes nothing. |
| `libp2p` | `=0.57.1` (pinned) | 1.88 | Patched active line; its `libp2p-mdns 0.49.0` uses `hickory-proto 0.26.4`, clearing the 0.25 advisories. Explicit features: `ed25519`, `macros`, `tcp`, `noise`, `yamux`, `quic`, `tokio`, plus M13's `autonat`, `dcutr`, `identify`, `kad`, `mdns`, `ping`, and `relay`; default features off. `macros` only enables the behaviour derive. Optional behaviours are off at runtime by default. |
| `libp2p-tls` (transitive via `quic`) | 0.7.0 (lockfile) | — | Pinned in the lockfile through libp2p's QUIC stack; configures rustls with `prefer-post-quantum` and negotiates X25519MLKEM768. TLS/libp2p PeerId authentication remains classical. |
| `ml-dsa` | `=0.1.2` (pinned) | — | `alloc` feature only. Library ML-DSA-65 for independent PQ identity seeds, setup v5 and file v3 signatures, mandatory admission, and opt-in transport pin verification; 1952-byte public keys and 3309-byte signatures. No custom primitive. |
| `ml-kem` | `=0.3.4` (pinned) | — | `getrandom` and `zeroize` features for the opt-in pinned ML-KEM-768 transport exchange; library KEM only, composed with ML-DSA-65 signatures, HKDF-SHA256, and existing XChaCha20-Poly1305 framing. No custom primitive. |
| `tokio` | 1.54.1 | 1.85 | Runtime for the network worker; features `rt-multi-thread`, `sync`, `time`, `macros`. The worker currently uses `new_current_thread()`. |
| `openmls` | `=0.10.0-rc.1` (pinned) | 1.94 | MIT, docs.rs, active `openmls/openmls`; RFC 9420 release-candidate line selected because it carries the patched RustCrypto stack. Not a production-stability claim; the PQ suite does not make classical PeerId/TLS authentication quantum-resistant. |
| `openmls_rust_crypto` | `=0.7.0-rc.1` (pinned) | 1.94 | MIT, docs.rs, active repository; RustCrypto-backed provider matching OpenMLS 0.10 RC and crypto-bigint 0.7.11. Its pinned draft feature enables `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (`0x0051`); `0x004F` is the previous hybrid-Ed25519 suite and historical, and `0x004D` X-Wing is declared but unsupported by this provider. |
| `openmls_traits` | `=0.7.0-rc.1` (pinned) | 1.94 | MIT, docs.rs, active repository; used for the ML-DSA-65 `Signer` and crypto access with the pinned draft feature enabling the `0x0051` suite. |
| `openmls_memory_storage` | 0.7.0-rc.1 (transitive) | 1.94 | Re-exported by `openmls_rust_crypto`. In-memory storage only; group state is lost on restart and never written to disk in plaintext. |
| `openmls_sqlite_storage` | 0.3.0 | 1.91 | Validated but **not enabled**: it would store MLS secrets unencrypted in SQLite. Revisit only with an encrypted storage design. |
| `rusqlite` | 0.43.0 | 1.89 | `default-features = false`, `bundled`; checked `Cargo.toml` to confirm bundled SQLite without `sqlcipher`. Avoids host lib drift. |
| `libp2p-identity` | 0.3.1 | 1.88 | Direct dependency for Ed25519 transport identities and PeerIds; classical role keys/proof remain parallel in v2 bundles. Features: `ed25519`, `rand`, `peerid`. libp2p 0.57.1 resolves the same 0.3.1 line, so no cross-version Keypair bridge is needed. |
| `libp2p-request-response` | `=0.30.0` (pinned) | 1.88 | MIT-licensed libp2p workspace crate with docs.rs documentation and the active `rust-libp2p` repository. Exact version paired with libp2p 0.57.1; 0.29.0 belonged to the prior 0.56.0 line. The `Codec` implementation now uses the RPITIT trait API. Only the generic byte codec and `Full` protocol support are used; JSON/CBOR codecs are not enabled. |
| `async-trait` | 0.1.92 (removed) | 1.71 | Historical M5 dependency for the `Codec` implementation. The direct dependency was removed after `libp2p-request-response 0.30.0` moved `Codec` to RPITIT; no workspace source uses it. |
| `libp2p-swarm-derive` | 0.36.0 | 1.88 | MIT-licensed proc-macro crate from the active `rust-libp2p` repository. Pulled in only by the libp2p `macros` feature to derive the combined `NetworkBehaviour` on the libp2p 0.57.1 line. |
| `argon2` | 0.6.0 | 1.85 | Argon2id from RustCrypto ecosystem. |
| `aead` | 0.6.1 | 1.85 | `Payload` AAD type and `Aead` trait; `alloc` only. |
| `chacha20poly1305` | 0.11.0 | 1.85 | XChaCha20-Poly1305 support (`alloc`, no default features). |
| `getrandom` | 0.3.4 | — | OS CSPRNG for export salt and nonce. |
| `hkdf` / `sha2` | 0.13.0 / 0.11.2 | 1.85 / 1.88 | HKDF-SHA256 subkeys. |
| `hmac` | 0.13.0 | 1.85 | HMAC-SHA256 blind indexes; re-exports the digest `KeyInit`/`Mac` traits. Q3 adds `hmac` + `sha2` in `p2p-messaging` for v3 route-tag/MAC work and `p2p-crypto` in `p2p-groups` for exporter keys. |
| `dirs` | 7.0.0 | not declared | OS local-data directory for the vault; MIT/Apache-2.0. |
| `tempfile` | 3.27.0 | 1.63 | Dev-only isolated vault directories in storage, messaging, and chat offline-queue tests. |
| `zeroize` | 1.9.2 | 1.85 | Secret hygiene. |
| `serde` | current stable | — | Serialization for config/persistence. |
| `thiserror` | 2.0.21 | 1.77 | Typed errors. |
| `qrcode` | 0.15.0 | 1.85 | Rust-side QR SVG rendering. Features `std`, `svg` only; no `image` backend. |
| `data-encoding` | 2.11.1 | 1.48 | Base32 for fingerprints. |
| `base64` | 0.23.1 | 1.71 | URL-safe no-pad public keys in contact URIs. |
| `percent-encoding` | 2.3.2 | 1.51 | Optional display names in contact URIs. |

Milestone 3 additions (`rusqlite` bundled, `hkdf`, `hmac`, `dirs`, `tempfile`) were validated with `cargo info` and by reading each crate's published `Cargo.toml` for version, license, MSRV, and feature definitions before being added.

## Messaging dependency decision (Milestone 5)

The messaging core added the internal `p2p-messaging` workspace crate with **no new external dependency**. It uses already-validated `getrandom` 0.3 for random message IDs, `thiserror` 2 for typed errors, and `libp2p-identity` 0.3.1 for PeerId parsing and public-key binding, together with the internal `p2p-identity` and `p2p-storage` crates. `tempfile` remains dev-only for isolated vault tests.

The M5 wire layer initially added `libp2p-request-response 0.29.0`, `async-trait 0.1.92`, and the libp2p `macros` feature (`libp2p-swarm-derive 0.35.1`), each checked with `cargo info` for version, license, MSRV, documentation, and repository before enablement. Phase 0 remediation moved to `libp2p-request-response 0.30.0`, `libp2p 0.57.1`, and `libp2p-swarm-derive 0.36.0`; the 0.30 `Codec` trait uses RPITIT, so the direct `async-trait` dependency was removed. The wire codec remains our own bounded byte framing: no serde, JSON, or CBOR codec feature is enabled. The request timeout is 10 seconds, concurrent streams are capped at 8, and both request and response frames are capped at 1 MiB.

### MLS dependency decision (Milestone 5 crypto integration)

`openmls 0.10.0-rc.1`, `openmls_rust_crypto 0.7.0-rc.1`, and `openmls_traits 0.7.0-rc.1` were checked with `cargo info` for version, license (MIT), MSRV (1.94), docs.rs documentation, and repository before being pinned. The RC line was selected during Phase 0 remediation because it carries crypto-bigint 0.7.11 and clears RUSTSEC-2026-0387; it is not a production-stability claim. No separate `openmls_basic_credential` crate is used: `BasicCredential` comes from the `openmls` prelude. `tls-codec` is used only through OpenMLS's re-export for serializing KeyPackages and MLS messages; it is not a separate workspace dependency.

`openmls_rust_crypto 0.7.0-rc.1` brings `openmls_memory_storage 0.7.0-rc.1`. This was chosen deliberately for the current milestone: MLS group secrets stay in process memory and are never written to disk in plaintext. The consequence is that group state does not survive restart. `openmls_sqlite_storage 0.3.0` was validated but not enabled because its SQLite storage would violate the "sensitive local data encrypted at rest" requirement without an additional encryption layer.

The workspace `rust-version` remains 1.95, retained from the earlier egui/eframe 0.37 baseline and not lowered during the dependency refresh. The current OpenMLS RC stack declares MSRV 1.94 and egui/eframe 0.35 declares 1.92, both below the workspace floor. The file protocol was added in Milestone 7; M13 later added `/p2p-messenger/control/1` using the same already-validated bounded codec.

Storage schema v2 reuses the existing bundled `rusqlite` driver and existing `p2p-crypto` XChaCha20-Poly1305/HMAC subkeys. Message envelopes are ciphertext at rest, and lookup keys are blind indexes. No database driver, AEAD provider, or KDF changed in M5.

The M6 offline queue adds **no new external dependency** to `p2p-chat`: it uses `VecDeque` from `std`, reuses the historical pre-v3 signed envelope bytes produced by `p2p-groups`/`p2p-messaging`, and adds only dev-dependencies already validated above (`p2p-storage` as an internal workspace crate and `tempfile` for raw vault-file scans). No serde, JSON, disk queue, or persistence layer was introduced. M6 redial and resource limits also add **no new external dependency**: they use standard `HashMap`, `HashSet`, `BTreeSet`, `VecDeque`, `Duration`, and `Instant` types plus `ConnectionId`/`ConnectedPoint` from the workspace's pinned libp2p line. No new crate, Cargo feature, or protocol dependency was introduced; that line was moved from 0.56.0 to 0.57.1 during Phase 0 remediation without changing this layer's dependency shape.

### File dependency decision (Milestone 7)

Milestone 7 added the internal `p2p-files` workspace crate and a third `libp2p-request-response` behaviour, `/p2p-messenger/file/1`; the pinned request-response version is now `=0.30.0`. It introduced **no new external runtime dependency** at the time: the AEAD (`chacha20poly1305 0.11.0`), SHA-256 (`sha2 0.11.2`), randomness (`getrandom 0.3.4`), zeroizing buffers (`zeroize 1.9.2`), classical signatures (`libp2p-identity 0.3.1`), local data path (`dirs 7.0.0`), and typed errors (`thiserror 2.0.21`) were already validated above. The current PQ file v3 frames additionally use the separately validated pinned `ml-dsa =0.1.2`; legacy v2 classical frames remain adversarial-test only. No malware scanner, anti-virus SDK, archive format, database driver, serde codec, or file-picker crate was added. `tempfile` remains dev-only for quarantine tests.

The file frame uses the same bounded 1 MiB request/response codec as the other protocols; chunk plaintext is capped at 256 KiB and total plaintext at 64 MiB. The per-transfer content key is generated with the OS CSPRNG and never persisted. No independent scanner dependency exists, so a default/unscanned transfer deliberately remains `Unavailable`.

### Security dependency decision (Milestone 8)

Milestone 8 adds the internal `p2p-security` workspace crate and **no new external runtime dependency**. The scanner interface is application-supplied; no antivirus SDK, malware database, archive parser, MIME sniffer, external process launcher, or network scanner service is bundled or configured. Structural validation of TXT, PNG, and GIF is implemented with `std` only (`str::from_utf8`, bounded byte slicing, and a local CRC-32 table); no image codec, media parser, content-type sniffer, or magic-number database was added. Explicit approval/cancellation state uses existing `std` collections and the already-validated `thiserror` typed errors. The only added dependency edge is `zeroize` in `p2p-security`, already validated above for secret hygiene, plus internal `p2p-security` edges in `p2p-files` and `p2p-chat`.

A real scanner still must be validated before any external scanner integration is added: check published documentation, maintenance activity, MSRV, license, sandbox/process boundaries, update mechanism, false-positive reporting, and whether it ever writes or retains scanned bytes. General media parsing and MIME sniffing also require dependency review before adoption; the current validators are deliberately narrow. Until then, `NoScanner` reports `Unavailable`, the release allowlist is empty, and no clean/safe claim is permitted. Releases and approval remain in zeroizing memory/state.

### Attachment store and OS save decision (Milestone 8 completion)

The encrypted attachment store adds **no new runtime dependency**: `p2p-storage` reuses the already-validated `p2p-crypto` AEAD/wrap primitives, `rusqlite` bundled SQLite, `getrandom` random IDs/keys, `zeroize` secret hygiene, and the already-validated `sha2` digest for the at-rest integrity recheck. `p2p-files` and `p2p-chat` add only internal dependency edges and standard-library filesystem deletion policy.

The native OS save flow uses `rfd 0.18.0`, validated above and enabled only by the `native` Cargo feature. The `gui` and default feature sets do not compile a dialog crate. The save call is synchronous and modal, which is acceptable for an explicit user-initiated save action. No GTK/Qt/web/npm backend is defaulted by this application beyond the feature tables already used by `eframe`; on Linux `rfd` uses XDG portal/Wayland support via its declared default features.

No external scanner dependency was added. No general format/MIME parser was added. Structural validation remains TXT/PNG/GIF only and is explicitly not malware detection.

### Group management and channel dependency decision (Milestones 9–10)

Historical Milestones 9 and 10 added **no new external dependency and no fourth wire protocol**. They reused the now-pinned OpenMLS `=0.10.0-rc.1`, `openmls_rust_crypto =0.7.0-rc.1`, and `openmls_traits =0.7.0-rc.1` for Remove/Update commits and commit processing, and extended the then-current signed `/p2p-messenger/mls-setup/1` codec with bounded group-control codes. Milestone 10 reuses the reserved `MessageKind::Channel` envelope code and a bounded internal `CHN1` application codec; it adds no new MLS group, envelope version, setup code, or transport protocol. Strict payload parsing, pending-operation and channel state, local admin/channel policy, and group-wide receipt state use existing `std` collections plus the already-validated `thiserror`, `libp2p-identity`, and internal workspace crates. No policy engine, serialization framework, central service SDK, or encrypted MLS persistence layer was introduced. Any future admin delegation, per-channel MLS keys, or MLS storage backend requires the normal documentation, maintenance, MSRV, license, and security review first.

### Release packaging decision (Milestone 11)

Milestone 11 adds **no new Cargo dependency and no new Cargo feature**. Source builds continue to use the committed `Cargo.lock` with `--locked`. Packaging relies only on platform-native build tools outside the Rust dependency graph: `dpkg-deb` on Linux, WiX Toolset 3.14+ (`candle.exe`/`light.exe`) on Windows, and `hdiutil`/`codesign` on macOS. These tools are used by CI/package scripts only; the application does not link, invoke, or depend on them at runtime. No npm, Node.js, browser, webview, auto-updater, telemetry SDK, or centralized service client was added. Optional signing is operator-controlled through environment-provided platform credentials and is not configured in this repository.

### Local hardening dependency decision (Milestone 12)

Milestone 12 adds **no new Cargo dependency, feature, runtime service, or wire protocol**. Safe-name policy, hard release byte caps, redacted transport-event `Debug`, untrusted input caps, and symlink checks use `std`, existing typed errors, and already-validated workspace crates only. Native plaintext saving continues to use the already-validated optional `rfd` dialog with a local helper for permissions, sync, symlink refusal, and static errors. Windows ACL enforcement would require a platform-specific ACL crate or direct Win32 bindings and was deliberately not introduced; non-Unix restrictive-permission helpers remain no-ops. Filesystem secure erasure is not claimed.

### Metadata/privacy hardening dependency decision (Milestone 13)

Milestone 13 adds **no new top-level Cargo dependency and no new cryptographic primitive**. It enables additional features on the now-pinned `libp2p =0.57.1` (`autonat`, `dcutr`, `identify`, `kad`, `mdns`, `ping`, `relay`) and regenerates `Cargo.lock` under `--locked` verification. The extra resolved `libp2p-*` subcrates come from the same pinned libp2p release, including `libp2p-mdns 0.49.0` with `hickory-proto 0.26.4`; no alternate swarm stack, discovery SDK, relay service client, Tor/I2P library, or web/npm dependency was introduced.

The fourth protocol, `/p2p-messenger/control/1`, reuses the pinned `libp2p-request-response =0.30.0` and the project's bounded byte codec. It has four concurrent streams, a 10-second timeout, and the same 1 MiB empty/oversized-frame rejection as the other three protocols. The controller treats its bytes as opaque and derives no application semantics from them.

The compile-time libp2p features are available to the binary, but the corresponding mDNS, Kademlia, relay, AutoNAT, DCUtR, identify, and ping behaviours are instantiated only when the user explicitly enables them in `NetworkConfig`; defaults are off/empty. Identify is configured to hide listen addresses and bound peer-provided strings. Kademlia and relay-client addresses must be user-supplied direct `/p2p/<peer-id>` addresses; `/p2p-circuit` bootstrap/relay input is rejected. No signing, notarization, updater, telemetry, centralized discovery, or mandatory relay dependency was added.

### Post-v3 wire and PQ-suite dependency decision (Q3/Q4)

Q3/Q4 are complete locally/uncommitted and add `hmac` + `sha2` to `p2p-messaging`, `p2p-crypto` to `p2p-groups`, pinned `ml-dsa =0.1.2` (`alloc`) for PQ identity/setup/file signatures, and PQ transitive crates in the lockfiles through the pinned OpenMLS draft feature on `openmls_rust_crypto`/`openmls_traits` plus libp2p's `quic` feature (lockfile `libp2p-tls 0.7.0`/rustls `prefer-post-quantum`, X25519MLKEM768). That OpenMLS feature enables `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (`0x0051`) with ML-DSA-65 leaf signatures and certified ML-DSA-65 `Mls` role keys; `0x004F` was the previous hybrid-Ed25519 suite and is historical, and `0x004D` is declared but unsupported by the pinned provider. Signed PQ setup v5 uses `/p2p-messenger/mls-setup/2` with a self-contained PqIdentityProof, a 3309-byte ML-DSA-65 signature, `ciphersuite_id` at bytes 6..8 and transaction ID at bytes 8..24; only `0x0051` is accepted, and v1–v3 plus legacy v4 setup frames and unknown suites are rejected. File frames are PQ v3 on `/p2p-messenger/file/1`; legacy setup v4 and file v2 are adversarial-test only. TLS/libp2p PeerId authentication and TCP Noise remain classical, so full post-quantum protection/quantum resistance is not claimed and no custom primitive is made. Production application envelopes are P2P3 `EnvelopeV3`; legacy v2 signed-envelope tests stay only as compatibility/adversarial evidence. Historical post-PQ connection-admission results and current post-transport results are separated in `SECURITY_TESTS.md` and `PROJECT_STATUS.md`.

The opt-in pinned PQ transport adds direct `ml-kem =0.3.4` (`getrandom`, `zeroize`) plus `hkdf`, `sha2`, `zeroize`, and the internal `p2p-crypto` XChaCha20-Poly1305 framing to `p2p-network`; `Cargo.toml` and both lockfiles were refreshed offline. It reuses the existing pinned `ml-dsa =0.1.2` for exact PeerId-to-key transport pins and transcript signatures, and pins `IdentityRole::Application`. No libp2p fork, vendored Noise/TLS implementation, certificate hook, or new application-defined primitive is introduced. QUIC and relay transports are not constructed in pinned mode, while configured SOCKS5 Noise streams remain supported. Current post-transport local gate results are separated from historical workspace/GUI/fuzz results in `SECURITY_TESTS.md`.

## Network dependency decision (Milestone 4)

`libp2p 0.57.1` is now pinned. It uses `libp2p-swarm 0.48.0`, which pins `wasm-bindgen-futures = "=0.4.58"` and therefore `js-sys 0.3.85`. The earlier conflict with `eframe 0.37.0` (`js-sys ^0.3.103`) was resolved by moving the native GUI to egui/eframe 0.35, whose `js-sys ^0.3.77` requirement admits the libp2p-selected version. The upgrade is a documented Phase 0 advisory remediation: `libp2p-mdns 0.49.0` uses `hickory-proto 0.26.4`, clearing the 0.25 advisories.

The direct transport is libp2p `OrTransport` of TCP + Noise + Yamux and QUIC (libp2p-tls 0.7.0/rustls `prefer-post-quantum`, X25519MLKEM768 KEX) under `PerIpPendingTransport`, over Tokio with Ed25519 PeerIds; TLS/libp2p PeerId authentication and TCP Noise remain classical. QUIC direct listeners are disabled under `TransportPrivacyMode::TorRequired` and `DialPolicy::RelayOnly`; `TorRequired` uses SOCKS5 + Noise with no direct fallback. `plaintext`, `pnet`, and `floodsub` are excluded, as are DNS and UPnP features; the facade `request-response` feature is not enabled. M13 enables the pinned libp2p's `identify`, `ping`, `mdns`, `kad`, `autonat`, `dcutr`, and `relay` features, but their behaviours remain off/empty by default and are never mandatory. The separate pinned `libp2p-request-response 0.30.0` dependency provides `/p2p-messenger/message/1`, `/p2p-messenger/file/1`, M13's `/p2p-messenger/control/1`, and the historical `/p2p-messenger/mls-setup/1`; production setup is signed PQ v5 over `/p2p-messenger/mls-setup/2` and rejects v1–v3, legacy v4, and suites other than `0x0051`.

The network layer does not add developer-operated bootstrap addresses, DHT defaults, or relays. Its default listen address is `/ip4/0.0.0.0/tcp/0`, and dialing requires a user-supplied address ending in `/p2p/<peer-id>`. M13 preserves those defaults; user-supplied bootstrap/relay addresses are validated as direct peers, and `/p2p-circuit` input is rejected.

### Supply-chain tooling decision (Phase 0)

Phase 0 adds no new external runtime Cargo dependency to the application. The later P1a security slice adds an internal `p2p-groups -> sha2` dependency edge for domain-separated channel identifier derivation; `sha2` was already workspace-pinned and used elsewhere. `deny.toml` is a policy file; `scripts/check_diagnostics.py` and `scripts/generate_sbom.py` use only the Python standard library. Fuzz harnesses live in a separate `fuzz/` workspace with its own `Cargo.lock` and `libfuzzer-sys` tool dependency, so they do not alter the native application graph. The SBOM generator reads `cargo metadata --locked` and emits SPDX 2.3 JSON; see `docs/SBOM.md` for scope and determinism details.

## Feature gates

- `cargo test --workspace` / `cargo check --workspace`: no GUI dependencies compiled; the default workspace build includes `p2p-network`, `p2p-messaging`, `p2p-groups`, `p2p-chat`, and libp2p.
- `--features gui`: compiles `egui` widget code only; works on any host, no display libraries.
- `--features native`: adds `eframe` and opens an OS window. This was **build-verified locally** with `cargo build -p p2p-desktop --features native`.

## Previous stack, removed

Tauri 2, React, TypeScript, Vite, Tailwind, npm, and browser/webview dependencies were removed per the user's decision to use a pure Rust GUI. ADR-0006 supersedes ADR-0005. No JavaScript runtime, browser engine, or package manager is required to build or run the application.
