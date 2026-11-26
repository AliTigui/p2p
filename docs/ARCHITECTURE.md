# System Architecture — Decentralized P2P Encrypted Messenger

Status: **v0.1 design baseline, Milestones 1–13 implemented and tested on this Linux host**, plus a post-M13 schema-v4 durable control-log/anchor increment, ADR-0014 Phases 1–3 schema-v5 encrypted storage/anchor/provider work, and the Phase 4 core restore slice (none is a new numbered milestone; final local run 230 tests, 0 failures on 2026-11-26; pushed CI/release baseline 207 tests on 2026-11-25). This document describes the target architecture and marks which parts are implemented yet. M13 optional discovery, relay, NAT, identify, and control capabilities are off/empty by default; nothing here should be read as "implemented and tested" unless `PROJECT_STATUS.md` says so. No production-readiness claim is made.

## 1. Non-negotiable constraints

1. **No mandatory centralized server.** No developer-operated bootstrap node, signaling server, identity server, account database, message relay, or cloud storage is required for any core function.
2. **Two installations must be able to communicate with nothing but each other's addresses.** Manual address/QR exchange is a first-class, fully functional mode.
3. **Users own their identities and data.** Identity keys are generated locally, encrypted at rest, and exportable. No hardware identifiers are used.
4. **All user content is end-to-end encrypted.** Relay/discovery peers may carry ciphertext and metadata only.
5. **Established protocols and primitives only.** MLS (RFC 9420) via OpenMLS for conversations; libp2p Noise for transport; Argon2id + XChaCha20-Poly1305 for local key protection. No bespoke cryptographic protocol.
6. **Fail closed and report honestly.** Unimplemented, unavailable, or failed operations must be shown as such. No fake "connected", "delivered", "verified", or "scanned clean" states.

Consequences of these constraints are recorded in `docs/DECISIONS/`.

## 2. System context

```
┌─────────────────────────────── User A computer ───────────────────────────────┐
│  Native Rust GUI (egui/eframe) ──> workers (network + vault) in same process  │
│                                      │                                        │
│                     ┌────────────────┼────────────────┐                        │
│                     v                v                v                        │
│       core/identity   core/messaging   files/quarantine   storage (SQLite)   │
│                     │                │                │                │      │
│                     └──────> crypto/key_management <───┴────────────────┘      │
│                                      │                                        │
│                               network (libp2p Swarm)                          │
│         TCP + Noise + Yamux; M13 discovery/relay/NAT capabilities opt-in        │
└──────────────────────────────────┬─────────────────────────────────────────────┘
                                   │ encrypted streams
        ┌──────────────────────────┼──────────────────────────┐
        v                          v                          v
  User B computer          LAN peers (mDNS)        User-operated relay/DHT peer
  (same stack)             (optional M13)          (optional M13; ciphertext/metadata only)
  Zero-infrastructure direct mode remains the default; optional peers are never mandatory or auto-trusted.
```

There is no "server" component in this repository. Components that happen to provide relay or DHT functions are ordinary user installations with an opt-in role.

## 3. Workspace and crate boundaries

Dependency direction is strictly top-down: `apps/*` → `crates/core/*` → specialized crates → `p2p-core`. Lower layers never import upper layers.

| Path | Responsibility | State after Milestone 10 |
|---|---|---|
| `crates/core` | Shared, stable types: `AppInfo`, protocol version, error taxonomy | Implemented |
| `crates/crypto` | Key derivation, key hierarchy, AEAD wrappers, domain separation | Implemented and tested (M3) |
| `crates/identity` | Ed25519 identity, PeerId, fingerprints, QR payloads, encrypted export | Implemented and tested (M2) |
| `crates/network` | libp2p direct Swarm, connection state, explicit dial/disconnect, four bounded wire protocols, connection and request limits, optional discovery/relay/NAT/identify behaviours | Direct TCP + Noise + Yamux, `/p2p-messenger/message/1`, `/p2p-messenger/mls-setup/1`, `/p2p-messenger/file/1`, duplicate-dial rejection, connection caps, and aggregate plus per-protocol request/byte budgets implemented and tested (M4–M7, SA-019); M13 adds opt-in mDNS/Kademlia, relay client/server, AutoNAT/DCUtR, identify, bounded relay caps, an opaque `/p2p-messenger/control/1` protocol, and `NetworkPrivacyStatus` (locally tested, off by default) |
| `crates/messaging` | Canonical signed envelopes, replay/sequence checks, receipt codec, delivery state, ciphertext-only persistence | Local core and wire exchange implemented and tested (M5); payload decryption belongs to `p2p-groups` |
| `crates/groups` | OpenMLS group lifecycle, envelope payload encryption/decryption, sender binding | Initial setup, KeyPackage/Welcome join, encrypted text/receipts, and tamper/mismatch rejection (M5); multi-member Add/Remove/Update commits, sender/operation checks, and epoch exclusion implemented and tested (M9); unchanged in M10 because channels are application bodies inside one group |
| `crates/files` | Signed file frames, per-chunk AEAD, SHA-256 manifest, ciphertext-only quarantine, scan/release gate, explicit quarantine deletion | Fresh transfer key, bounded chunks, integrity verification, redacted diagnostics, restricted quarantine (M7), validated-format/policy/approval-gated in-memory release, and `Retain`/`Explicit` deletion policy implemented/tested (M8) |
| `crates/chat` | Signed MLS setup/group-control frames, bounded channel codec, application controller, memory-only conversation view, admin/pending/channel state, offline queue, bounded redial, file-transfer state, scan/release/deletion API, privacy snapshot, optional durable control-digest guard | KeyPackage/Welcome/WelcomeAck exchange, controller compose/receive/receipt flow (M5), in-memory ciphertext queue with reconnect retry, bounded redial (M6), file transfer (M7), scan/release/deletion API (M8), admin-only Add/Remove/Update with signed group frames, commit/Welcome acknowledgements, group-wide receipts, and honest pending state (M9), bounded `CHN1` channels inside one MLS group with local membership policy (M10), and M13 control/privacy queue draining with no trust promotion implemented/tested; post-M13 `MessengerController::start_with_control_log` attaches a cloned vault `Session`, rejects identity mismatch at startup, and preserves idempotent/terminal decisions across restart without restoring MLS state |
| `crates/storage` | Encrypted SQLite repository, attachments store, migrations, durable control log and anchor, encrypted MLS-state foundation | Profile vault, settings, message envelopes, migrations, and schema v3 encrypted attachments implemented and tested (M3/M5/M8); post-M13 schema v4 adds `control_log`/`control_state` in transactional migrations plus the AEAD `control.anchor`/`control.anchor.tmp` high-water mark with unlock-time chain, blind-index, and anchor verification and partial-rollback detection; ADR-0014 Phases 1–2 add schema-v5 `mls_groups`/`mls_state` for encrypted opaque provider values with blind indexes, per-group chains, bounds, unlock verification, and a v2 anchor with authoritative MLS watermarks and database-only rollback detection; Phase 3 adds `StagedMlsProvider`, a vault-backed `openmls_traits::StorageProvider` with staged reads, discard, one-transaction atomic flush, same-transaction tombstones, and a tested `MlsGroup::load` round trip; Phase 4 core slice adds a vault-backed `MlsProvider`, controller restore of joined groups with encrypted `p2p.app.conversation/v1` policy, and honest GUI failure states; contacts remain planned; M7 quarantine is separate filesystem ciphertext |
| `crates/security` | Independent scanner interface, exact result categories, narrow format validation, release policy | Scanner trait, `NoScanner`/`Unavailable` default, dependency-free TXT/PNG/GIF structural validation, `ScanOutcome` construction boundary with private validated format, conservative extension allowlist, and tests implemented (M8); no real scanner dependency or configured scanner in the desktop app |
| `apps/desktop` | Native Rust GUI (egui/eframe), worker ownership | Vault create/unlock/lock and `MessengerController` startup implemented; the GUI clones the unlocked vault `Session` with `Session::try_clone` and starts the controller with `start_with_control_log`; network owns its own Tokio current-thread runtime; window gated behind `native`; `rfd` save dialog is native-only; pure Rust GUI authority (ADR-0006) unchanged — no browser engine, webview, JavaScript, or npm |
| `apps/desktop/src/model.rs` | Framework-independent UI state and pure helpers | Implemented with real vault-state, observed network-state, honest message-encryption row, 14 milestone checklist rows including the M13 row, M13 `NetworkOptions` validation, and 24 security/status rows including admin/members/pending group state |
| `apps/desktop/src/app.rs` | egui widget descriptions | Implemented; worker-thread vault flow, direct connect, MLS setup, admin Add/Remove/Refresh-key controls, group member/admin/pending view, encrypted send/receive view, encrypted file path send button, honest transfer/scan/approval/quarantine state list, encrypted attachment list, native OS save, attachment deletion, conditional quarantine deletion, and M13 opt-in network settings applied only at `start_chat()` (lock/unlock restarts the worker), where it clones the vault session for the control-log startup path; identity mismatch fails startup. The app has no scanner, allowed extensions, explicit deletion policy, or enabled optional network feature by default |

Rationale for a small number of real crates instead of one crate per future folder: empty crates add compile and maintenance cost without testable behaviour. Directories for future crates are documented in `PROJECT_STATUS.md` and created as implementation begins.

## 4. Runtime model

- **GUI event loop**: egui/eframe describes panels and widgets. It never performs crypto or blocking I/O; only the current view model is rendered.
- **Typed app facade**: Rust functions called directly from the GUI validate inputs and return typed errors. No network operation is awaited from the GUI thread; long operations run on dedicated workers and deliver events to the view model.
- **Tokio runtime**: the Milestone 4 network worker owns a Tokio current-thread runtime on its own `std::thread`; it owns one libp2p `Swarm` per local identity per process. A future shared application runtime may add dedicated message and file-transfer workers; today `p2p-chat` drives both workflows through the network worker.
- **Blocking pool**: Argon2id derivation, filesystem I/O, and SQLite calls use a dedicated `std::thread` per vault operation today, so the UI never blocks. File reads and writes are short bounded operations driven from `poll`; they will move to a shared Tokio blocking pool as the runtime model expands.
- **Local database**: single writer connection, WAL journal, all sensitive values stored as AEAD ciphertext written by the storage layer. Schema v4 keeps an encrypted, chained digest log in `control_log`/`control_state` and an AEAD-protected high-water mark in the vault directory's `control.anchor` (atomically replaced via `control.anchor.tmp`); unlock verifies records, chain, blind indexes, and anchor, detecting partial (database-only) rollback. Schema v5 adds ADR-0014 Phase 1 `mls_groups`/`mls_state` opaque-value rows under versioned `Purpose::Db` AAD with `Purpose::BlindIndex` indexes and per-group SHA-256 chains; Phase 2 extends the anchor to v2 with authoritative per-group watermarks, so unlock verifies the exact watermark map and detects database-only rollback of the MLS tables. Transfer ciphertext lives in a restricted quarantine directory; the content key is memory-only. M8 scanner input, released plaintext, and OS-save decryption stay in zeroizing memory buffers. Released files are copied into the encrypted attachment store; the only plaintext disk write is the user-initiated native OS save to a chosen path.

Channels between UI and workers are typed `mpsc` queues for vault results, connection state, message events, setup events, file events, control events, and M13 discovery/relay/NAT/identify observations. The network worker reports `SentToPeer`, `RequestReceived`, `ResponseReceived`, and `Failed` for all four bounded protocols and advisory privacy events; it never declares delivery, group join, file integrity, trust, or a fingerprint-verified contact. State transitions are owned by `p2p-chat`/`p2p-messaging`/`p2p-groups`/`p2p-files`; the UI is a projection and never the source of truth. M13 observations update only a cached `NetworkPrivacyStatus`; no application capability follows from them.

## 5. Key hierarchy (implemented in Milestone 3)

```
OS CSPRNG
   ├── libp2p Ed25519 identity keypair ──> PeerId (public, shareable)
   │                                   └──> credential signing key for MLS
   └── master key (32 bytes, random)  ──> Argon2id KEK wraps it in an envelope
                                          └── HKDF-SHA256 domain-separated subkeys
                                                ├── storage/db
                                                ├── storage/attachments
                                                ├── storage/identity
                                                ├── storage/search-index
                                                ├── storage/blind-index
                                                └── storage/backup
```

The password derives only the key-encryption key (KEK). Changing the password re-wraps the master key; no application data is re-encrypted. Losing both password and recovery material means permanent data loss — there is no escrow. Argon2id parameters are bounded before any derivation, and the KDF id, salt, and parameters are bound into the wrapped-key AAD so they cannot be downgraded unnoticed. A dedicated `storage/blind-index` subkey powers HMAC lookups. Schema-v4 control records and the vault anchor are AEAD-encrypted under `Purpose::Db` with profile-bound AAD; their blind indexes use `Purpose::BlindIndex` and never the AEAD key. ADR-0014 Phases 1–3 MLS-state rows and the v2 anchor use the same division of keys with record-version/profile/group/entity/epoch-bound AAD and a separate anchor-version AAD label; a dedicated `Purpose::MlsState` is deferred because it would require a stored-salt-slot migration.

## 6. MLS setup and message lifecycle (Milestones 5, 6, and 9)

Implemented and tested through the Rust controller and GUI:

```
connected peer supplies a Peer ID (address and fingerprint verified out of band)
  → inviter creates an in-memory MlsConversation and signed KeyPackageRequest
  → /p2p-messenger/mls-setup/1 over Noise (SentToPeer is not Joined)
  → responder verifies signature/PeerId, generates MlsKeyPackage, signs KeyPackageResponse
  → inviter verifies response, calls add_member, signs Welcome
  → responder joins with OpenMLS, signs WelcomeAck (accepted or rejected)
  → inviter records Joined only after verifying the accepted WelcomeAck

plaintext application bytes
  → OpenMLS encrypt into the conversation's current member group
  → place TLS-serialized MLS ciphertext in Envelope.payload
  → sign canonical envelope (conversation, MLS epoch, type, IDs, sequence)
  → broadcast once to every current member over /p2p-messenger/message/1
  → if a recipient is connected: hand to the protocol (SentToPeer, not delivered)
  → if disconnected: hold one ciphertext copy for that recipient in the in-memory queue (Queued), retry only after a new Connected event
  → each recipient verifies signature, conversation, epoch, and replay cache
  → each recipient OpenMLS-decrypts and checks group ID, epoch, credential, and leaf key
  → each recipient composes an MLS-encrypted delivery/read receipt response
  → sender decrypts/verifies all expected receipts, then state: SentToPeer → Delivered/Read
  → persist envelope as XChaCha20-Poly1305 ciphertext in the vault
```

The controller renders decrypted messages and delivery descriptions in the native GUI. For groups it broadcasts one signed ciphertext envelope to all current members, keeps one queue entry per disconnected recipient, and promotes a local message to `Delivered` only after all expected receipts. The offline queue holds only signed ciphertext, is retried from the observed-connection path, and is lost on restart or lock. Bounded redial uses only saved user-supplied addresses and reports scheduler intent separately from observed connection state; duplicate dials, excess connections, and excess per-peer requests are rejected. M9 admin-only Add/Remove/Update commits and acknowledgement state are implemented. M10 channels are logical partitions using the existing `MessageKind::Channel` envelope and a bounded `CHN1` MLS application body; channel selection filters the local decrypted view. Not implemented yet: read-receipt UI, controller/GUI group-state restoration using the provider, role delegation, and cryptographic per-channel access control. ADR-0014 Phases 1–3 add encrypted provider values, anchor watermarks, and a staged OpenMLS `StorageProvider` adapter, but nothing calls it from the controller; it does not participate in this message lifecycle.

The legacy `Conversation::load` path can reverify opaque envelope records but parses receipt bodies from raw payload bytes; it is not a restore path for MLS receipts. Runtime `MlsConversation` group state, pending KeyPackages, channel metadata, and decrypted text remain memory-only and are lost on restart. ADR-0014 Phases 1–3 can store opaque provider values as authenticated ciphertext with anchor watermarks and expose a staged `StorageProvider` that a test uses for `MlsGroup::load`, but nothing calls it from the controller yet and no application restore path exists. The schema-v4 control digest log records only SHA-256 digests of already authenticated signed setup/group-control frames and a repeatability flag; **the digests do not restore MLS state** (group/ratchet state, pending key packages, channels, or plaintext). Relays would only ever see outer libp2p ciphertext and routing metadata. OpenMLS provides group authentication and epoch separation in the implemented setup; M9 Update/Remove commits advance epochs and exclude removed members, while durable MLS state restoration remains a target. Timestamps are sender-supplied and displayed as such, never trusted for ordering. `SentToPeer` is not `Delivered`; the GUI shows the exact `DeliveryState::description()` instead of inventing a status.

### Durable control decisions (post-M13, not a new milestone)

- `MessengerController::start_with_control_log` accepts a cloned vault `Session` from `Session::try_clone`; the GUI uses this path. The controller identity must match the session identity, or startup fails with `ControlLogIdentityMismatch`. Controllers started without a session keep only the bounded in-memory setup/group digest cache.
- Schema v4 transactional migrations add `control_log (sequence, record_bi, ciphertext, chain_hash)` and `control_state (id, sequence, chain)`. Records contain only public PeerId bytes, a SHA-256 digest of an already authenticated signed frame, and a repeatable flag. XChaCha20-Poly1305 under `Purpose::Db` with profile-bound AAD protects the records and the vault-directory `control.anchor` high-water mark; the latter is atomically replaced through `control.anchor.tmp`. HMAC indexes under `Purpose::BlindIndex` support lookup, and SHA-256 chaining links records.
- `KeyPackageRequest` and `GroupJoinRequest` are idempotent/repeatable; Welcomes, responses, commits, and all acknowledgements are non-repeatable. The log is bounded at 4,096 records and fails closed when full. `Vault::unlock` verifies records, chain continuity, blind indexes, and anchor before returning a session.
- A database-only rollback (with a current anchor) and an altered or missing anchor are detected as rollback. Restoring the entire vault including the anchor is not locally detectable; there is no external anchor, and this mechanism is not a backup. This is partial rollback detection, not a general replay-proof protocol.
- No wire-format change is involved. The local control log is unrelated to the M13 `/p2p-messenger/control/1` opaque control protocol, which carries no application semantics. `docs/DECISIONS/ADR-0013-durable-control-log-and-anchor.md` records the durable-control-log/anchor decision.

### Encrypted MLS state, anchor, and provider (ADR-0014 Phases 1–3, not a new milestone)

- Schema v5 adds `mls_groups`/`mls_state`: opaque provider values are XChaCha20-Poly1305 ciphertext under versioned `Purpose::Db` AAD, with HMAC blind indexes under `Purpose::BlindIndex`, per-group SHA-256 chains, and bounded CRUD (`1 MiB/value`, `4096` rows, `64` groups).
- Phase 2 extends `<vault>/control.anchor` to a version-2 AEAD record under a new versioned AAD label, keeping the control-log sequence/chain and adding a bounded, authoritative `group_blind_index -> (epoch, state_chain)` map. A v1 anchor is migrated on unlock after both databases verify.
- `Vault::unlock` verifies every MLS row, epoch binding, blind index, group chain, and the exact anchor watermark map before returning a session. A database-only rollback before an MLS write or deletion, an authenticated-but-mismatched anchor, or a missing required group fails with `RollbackDetected`. MLS writes install the anchor before committing so an interrupted write fails closed; control-log appends remain database-first with bounded anchor catch-up. Restoring the whole vault including the anchor remains undetectable.
- Phase 3 adds `StagedMlsProvider`, a vault-backed `openmls_traits::StorageProvider<CURRENT_VERSION>` adapter. It stages writes in memory for one MLS operation, exposes staged values to reads, discards on error or cancellation, and flushes the whole set as one SQLite transaction with anchor advancement and same-transaction tombstones. A real `MlsGroup::new_with_group_id` / `MlsGroup::load` round trip after reopening the vault is covered by `crates/storage/tests/mls_provider.rs`. Group-scoped methods reject reserved or non-16-byte group ids before staging; global provider entries use a reserved sentinel group id and draft virtual-client/extension methods remain unimplemented.
- Phase 4 core slice uses this provider from the controller with an attached vault session: explicitly `Joined` MLS groups and encrypted channel policy are restored, and failures become a real GUI `Failed` state. Pending-operation/receipt/offline-queue and decrypted-message restore, and crash recovery for an anchor-first write, remain out of scope.

## 7. Groups and channels (M9 group management and M10 channels implemented)

- Implemented now: one MLS group per conversation, with a 2-member group for 1:1; KeyPackage generation and binding, Add + Welcome join, encrypted text/receipts, epoch tracking, and rejection of tampered ciphertext or sender/credential mismatch. The signed wire setup exchange drives these calls through `p2p-chat` without out-of-band API handoff. There is no separate 1:1 encryption path to audit.
- M9 group control: codes `5`–`10` of the signed `MLS1` protocol carry group join requests, KeyPackage responses, Welcomes, commits, and acknowledgements. The creator is the initial admin; admin-only Add/Remove/self-Update operations merge the commit locally, broadcast it to required existing members, and remain pending until the Welcome and required CommitAck frames are verified. A joining member receives the new epoch through the Welcome and is excluded from that Add commit's acknowledgement set. Removed members stay on the excluded epoch and cannot read future group messages.
- M9 delivery: one signed MLS envelope per message goes to all current members. A ciphertext copy is held per disconnected recipient; `Delivered` requires receipts from every expected member. Messages and new group operations are blocked while an operation is pending, and pending commits are retried on reconnect.
- M10 channels: bounded `CHN1` frames are MLS application bodies inside the existing signed `MessageKind::Channel` envelope. `channel_id` is part of the authenticated application content; no envelope version, setup code, MLS group, or transport protocol was added. Every conversation starts with `[0; 16]`/`general`. The admin creates, renames, and sets members of channels; allowed members post text, which is sent only to allowed recipients. Channel membership is local application policy, not cryptographic access control, because all MLS group members hold group keys.
- Channel metadata revisions are locally verified and receipt-gated for acknowledgement; invalid or unauthorized frames get no receipt. Custom channels are not replayed to later joiners, who receive the default channel. Target, not implemented: admin role delegation/changes, per-channel MLS keys, and encrypted channel/group-state restoration.

## 8. File sharing, quarantine, policy-gated release, and encrypted storage (M7–M8 implemented)

Implemented and tested through `p2p-files`, `p2p-network`, `p2p-chat`, and the native GUI:

```
joined MLS conversation with authenticated Noise peer
  → sender validates base name, non-empty size ≤ 64 MiB, and ≤ 256 chunks
  → SHA-256 per chunk and over the full plaintext; signed manifest commitment
  → fresh 32-byte content key carried only in the signed offer over Noise
  → sequential 256 KiB XChaCha20-Poly1305 chunks with bound AAD and signed acks
  → receiver writes ciphertext to a 0700 quarantine directory (0600 files on Unix)
  → receiver decrypts in zeroizing memory, checks every chunk hash and full hash
  → signed ManifestAck; both sides report IntegrityVerified, not scanned
  → optional scan_file: validate claimed TXT/PNG/GIF structure, then re-assemble plaintext only in zeroizing memory and call app-supplied FileScanner
  → exact ScanResult category and validated FileFormat stored on the transfer; no scanner means Unavailable; mismatch means UnsupportedFormat
  → approval becomes Pending only after clean scan + validated format + name/size/count/extension policy
  → inactivity deadline or abort_file terminates only an active transfer
  → explicit per-file approval, then release_file; cancel_file is terminal for release
  → ReleasedFile is returned in zeroizing memory; the release path writes no plaintext
  → desktop app copies ReleasedFile into the schema v3 encrypted attachment store
  → native OS save decrypts into a zeroizing buffer and writes plaintext only to a user-chosen path
  → stored-attachment deletion and quarantine deletion are separate explicit actions; quarantine defaults to Retain
```

Integrity verification proves byte agreement with the signed manifest only. Structural validation checks a deliberately small set of formats and is not malware detection or a general media parser. `ScanStatus` is `NotApplicable` before verification and `Unavailable` afterward until `SecurityConfig::scan` actually invokes an independent scanner; no integrity check creates a clean status. A format mismatch short-circuits to `UnsupportedFormat` before the scanner sees bytes. A transfer starts only for a joined MLS conversation, and only one transfer is active per peer. `ScanOutcome` keeps both status and validated format private, so only `SecurityConfig::scan` can create a result that permits release. The default release policy allows no extensions, so release is denied even if a test scanner returns a clean category. An active transfer has a 5-minute default inactivity deadline (configurable up to 1 hour, reset by authenticated progress); timeout or `abort_file` marks it failed, drops pending response bookkeeping, zeroizes the in-memory key, and removes incomplete quarantine ciphertext. `cancel_file` is separate and applies only to an integrity-verified transfer whose verified ciphertext it retains. The pinned request-response API cannot withdraw a worker request already in flight, so abort ignores late responses rather than cancelling worker state.

The encrypted attachment store keeps a blind index, a wrapped random per-file key, and encrypted name/size/digest/format metadata in SQLite; the blob contains only XChaCha20-Poly1305 ciphertext. Reads recheck SHA-256 into a zeroizing buffer. The native-only OS save dialog is the only plaintext disk write and requires a user-chosen path; a cancelled dialog writes nothing. `QuarantineDeletionPolicy::Retain` is the default; under `Explicit`, deletion requires a verified transfer that was released or cancelled. Neither stored-attachment deletion nor quarantine deletion grants a clean status, aborts an active transfer, or guarantees secure erasure on SSD/CoW storage. Filesystem ACL hardening on non-Unix platforms remains a target.

Still absent: general format/MIME parsing, auto-execution policy, transport-level cancellation of an in-flight worker request, backup/restore, and a configured real scanner. No "clean" result may be invented before an independent scanner exists.

## 9. Offline behaviour

- Offline users: `Queued (offline)` is implemented for a joined MLS session. `send_text` composes and signs once, stores only ciphertext in memory, and the controller retries that exact envelope only after a real `Connected` event for the peer. `SentToPeer` remains unconfirmed and `Delivered` still requires a verified receipt. The queue is not persisted and does not survive restart or lock. Bounded redial may produce a new observed `Connected` event, but its state is honest scheduler intent and is never shown as a live connection or delivery claim.
- DHT/relay peers are optional and user-operated. If a recipient is offline and no voluntary store-and-forward peer exists, delivery waits; the application does not silently route through developer infrastructure.
- Implemented connection state is derived from actual Swarm events: `Unknown`, `Starting`, `Listening(addresses)`, `Connecting(peer)`, `Connected(peers)`, `Disconnected(peer)`, and `Failed(peer, reason)`. `Offline`, `Discovering`, `Reconnecting`, and `Degraded (relayed)` are future states and are not shown as if observed today. `RedialState` is separate scheduler intent, not an observed connection state.

## 10. Platform strategy

- One native Rust GUI across Linux, Windows, and macOS using egui/eframe with the glow renderer. No webview, browser engine, Node.js, or npm is shipped or required.
- The `native` Cargo feature adds the OS window; the `gui` feature only describes widgets and compiles without display libraries, enabling CI/core verification anywhere.
- SQLite is bundled (`libsqlite3-sys` `bundled`) to avoid system version drift.
- Secrets use OS secure storage where available (planned: keychain/credential manager for the envelope key wrapper); otherwise the Argon2id-encrypted envelope in a 0700 app-data directory.
- Received files live outside the application executable directory.
- Installers: AppImage/DEB/RPM, MSI/EXE, DMG. Signing and notarization are release-engineering tasks tracked in Milestones 11–12.

## 11. Metadata and privacy hardening (M13, implemented)

- The zero-infrastructure direct path is unchanged: no bootstrap, DHT, relay, account, signaling, identify, or discovery service is needed. Defaults are off/empty for identify, ping, mDNS, Kademlia, relay client/server, AutoNAT, DCUtR, bootstrap addresses, and relay addresses.
- Optional behaviours are startup-only `Toggle`s/configuration in the network worker. The GUI exposes opt-in fields and applies them when `start_chat()` creates the worker; changing them requires lock/unlock. No network operation runs on the UI thread.
- mDNS and Kademlia emit advisory candidates/route counts only. Kademlia needs user-supplied direct bootstrap peers. No candidate is auto-dialed, saved as a contact, trusted, or treated as fingerprint-verified.
- Relay client/server modes require user-supplied direct relay addresses; relay-server circuits and relayed connections are separately bounded. With pinned libp2p 0.56, relays forward Noise-protected opaque bytes: they see PeerIds, IP, timing, and size metadata and can deny service, but they never receive application plaintext, private keys, message keys, or file keys. File transfer is refused on observed relayed paths as a conservative metadata/policy choice pending a dedicated relay-safe file-key/transport design, not because the relay can read the signed offer.
- AutoNAT/DCUtR are best-effort status/hole-punch attempts; ping is liveness only; identify hides listen addresses and bounds protocol/agent strings. None proves a contact's identity or a universal network path.
- The fourth bounded protocol, `/p2p-messenger/control/1`, reuses the opaque 1 MiB frame codec. The controller drains control/discovery/relay/NAT/identify queues to update `NetworkPrivacyStatus`, but promotes nothing to a contact, trust, capability, presence, receipt, or delivery state.
- `NetworkPrivacyStatus` separates configured flags/counts from counters/strings changed only by real libp2p events. GUI rows state limitations and do not claim anonymity, unlinkability, Tor/I2P support, universal NAT traversal, or file transfer over relays.
- ADR-0012 records the accepted decisions and non-claims. Two-machine LAN/NAT/relay verification remains an external test.

## 12. Verification approach

Each milestone must produce runnable, tested software. Tests are layered: Rust unit/integration tests, GUI model tests, `cargo check --features gui` for widget code without display libraries, the passing two-instance direct-connect integration test, message persistence/replay tests that scan raw vault files for plaintext, MLS tests for encrypted text/receipts/tampering/sender binding, a passing two-instance wire test that verifies MLS envelope and receipt exchange over Noise, offline-queue/plaintext-scan tests, bounded-redial and disconnect-suppression tests, duplicate-dial/connection-cap/request-budget acceptance tests, file frame/tamper/malformed/oversize tests, a signed file wire test over Noise, a two-controller multi-chunk transfer test that checks both integrity statuses, `Unavailable` scanning, and absence of plaintext in quarantine, plus scanner-policy and TXT/PNG/GIF validation unit tests, a two-controller validation/approval/cancel/release test using a test-only scanner, encrypted attachment-store tests (blind indexes, wrapped keys, encrypted metadata, digest rechecks, cross-vault isolation, password change, and explicit deletion), explicit quarantine-deletion tests, and native compile/link checks for the OS save dialog. Visual OS dialog testing requires a display host. M9 adds strict group-frame tests, three-member MLS Remove/Update/epoch-exclusion tests, and three-controller Add/Remove/Update/broadcast-receipt acceptance tests. M10 adds bounded `CHN1` codec tests, fixed `Channel` wire-code coverage, and three-controller default-channel, admin-policy, membership-enforcement, and restricted-delivery acceptance tests. M13 adds all-off default checks, direct-only address validation including `/p2p-circuit` rejection, optional configuration preconditions, bounded control-codec round trips, redacted control-event `Debug`, privacy-status/NAT-description tests, GUI address-validation and status-row tests, and a serialized workspace run. ADR-0014 Phase 1 adds encrypted opaque MLS-state round-trip, blind-index, chain-verification, tamper, deletion, password-change, lower-epoch-replacement, bound, and raw-plaintext-scan tests; Phase 2 adds v1-to-v2 anchor migration, an authenticated-but-mismatched MLS watermark, database-only rollback before a write or deletion, a shared control-log/MLS anchor, and an explicit whole-vault-including-anchor restore that remains undetectable. Phase 3 adds staged-read, discard, atomic-flush, tombstone, group-id-rejection, and real `MlsGroup::load` round-trip tests in `crates/storage/tests/mls_provider.rs`; the targeted storage run passed 33 tests with 0 failures. Phase 4 adds controller tests for joined conversation/channel policy restore, missing metadata, membership mismatch, a persisted pending operation, and an unknown active channel, plus a GUI test for a real failed startup state; the locked workspace run passed 230 tests with 0 failures and the `gui`-feature desktop run passed 14 tests with 0 failures. Pending/receipt/offline-queue, decrypted-message restore, and crash-recovery behavior are not tested or claimed. Two-machine discovery/NAT/relay tests, general parser/fuzz work, and later security tests are future work. The post-M13 increment adds chain/anchor tests: storage tests verify contiguous sequences, recomputed SHA-256 chain hashes and HMAC blind indexes, idempotent request repeats versus rejected non-repeatable replay after reopen, database-only rollback with a retained anchor, and tampered/missing anchor detection, with no plaintext in the vault or anchor files; controller tests verify that a replayed terminal frame is ignored before entering the in-memory cache and that a repeatable request retry still succeeds after reopen. The final local serialized workspace run after the ADR-0014 Phase 4 core slice passed 230 tests with 0 failures on 2026-11-26 (chat 51, storage 33); the pushed CI/release baseline remains 207 tests with 0 failures on 2026-11-25. The Phase 4 gate rerun also passed fmt, `git diff --check`, 54-file diagnostic guard, locked workspace check/clippy, GUI/native check and clippy, the native build, both advisory/policy checks, deterministic SBOM regeneration, and six 1000-input fuzz smoke runs. See `PROJECT_STATUS.md` for actual commands and results.
