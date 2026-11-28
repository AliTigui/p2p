# Threat Model

> **Current worktree note (2026-11-28):** Older Q3/P2P3 statements below are historical. The uncommitted work based on `HEAD 34968e4` makes `TorRequired` the fail-closed default (SOCKS5 proxy required; direct transport is explicit `direct()` opt-in), moves production application frames to v4 (`P2P4`) with fresh random per-frame route tags and MAC-based group selection, and raises new vault/identity-export Argon2id defaults to 96 MiB/t=4/p=1 with weak-vault rewrap on unlock and restricted SQLite sidecar permissions. No verified Tor/proxy identity, anonymity, traffic-analysis defense, unlinkability, or protection from a fully compromised endpoint is claimed.

This model states attacker capabilities separately from properties the code currently demonstrates. "Expected defense" is not a claim unless the corresponding test is listed and passing.

## 1. Protected assets

| Asset | Protection boundary | Current status |
|---|---|---|
| Vault master key / password | Argon2id-wrapped random key; zeroizing buffers; no plaintext persistence | Implemented and tested |
| Device identity private key | Classical libp2p transport key plus v2 bundle with independent ML-DSA-65 role seeds and `PqIdentityProof`; encrypted vault export only; redacted `Debug` | Implemented; transport `PeerId`/TLS authentication remains classical |
| Message plaintext | MLS application encryption; memory-only display; no plaintext logs | Implemented and tested |
| MLS ratchet/group state | OpenMLS in-memory provider plus vault-backed encrypted opaque state | Joined groups and ready derived groups restore from authenticated encrypted records; setup KeyPackages/Welcomes and decrypted text do not; the control digest log does not restore MLS state |
| Control-frame digest continuity | Schema v4 chained log + AEAD vault anchor | Implemented for partial local detection; DB-only rollback and anchor tamper detected, full vault including anchor not detectable locally |
| File plaintext | Fresh AEAD key; zeroizing buffers; quarantine ciphertext only | Implemented for tested flows |
| Contact verification state | Out-of-band fingerprint comparison; explicit user action | Implemented; no automatic trust promotion |
| Honest status | UI rows derived from observed transport/application events | Implemented; monotonic counters are labelled as observations |

## 2. Trust boundaries

1. **Local user and process.** Trusted with decrypted data in memory, but not with silent protocol-state changes: setup/group transitions require signed frames and explicit state checks.
2. **Transport-authenticated peer.** Authenticated classically at the libp2p layer (TCP/SOCKS5 Noise or TLS `PeerId`), with direct QUIC optionally negotiating `X25519MLKEM768` hybrid KEX. When the opt-in pinned PQ transport mode is enabled, the classically authenticated PeerId must also match a locally supplied ML-DSA-65 `Application` key and complete a signed ML-KEM-768/HKDF/AEAD upgrade; the PeerId itself remains classical and relay/QUIC paths are rejected in that mode. May be malicious, replay frames, send malformed input, or attempt protocol desynchronization. Application authors are separately bound with ML-DSA-65 in setup/file proofs and MLS credentials.
3. **MLS group member.** Authenticated for group membership. In the current channel design, every group member possesses the MLS keys for all logical channels.
4. **Optional relay operator.** Can observe circuit metadata and ciphertext sizes/timing, delay, drop, or deny service. Cannot decrypt Noise or MLS payloads.
5. **Optional discovery/NAT/identify sources.** Advisory only. Peer-scoped results are released only after PQ admission (64-entry cap); mDNS, local listener/startup, AutoNAT, and ping remain direct/advisory. Never promoted to contacts, trust, delivery, or verification.
6. **Local filesystem attacker.** Can read the vault/quarantine directory. May be able to write or restore snapshots if the OS account is compromised.
7. **Software supply-chain actor.** May attempt to publish modified dependencies, artifacts, or downgrade versions.

## 3. Attacker profiles

### Attacker A — Network observer

- **Capabilities:** Observe source/destination IP, packet sizes, timing, connection duration, and frequency.
- **Assumptions:** No access to endpoint memory or Noise keys.
- **Scenarios:** Link a stable PeerId to activity; infer conversation timing and message-size classes.
- **Expected defenses:** TCP/SOCKS5 Noise hides payloads; direct QUIC uses pinned libp2p-tls 0.7.0 with rustls `prefer-post-quantum` and `X25519MLKEM768` hybrid KEX, while TLS/libp2p `PeerId` authentication and TCP/SOCKS5 Noise remain classical; opt-in pinned PQ transport adds a layered PQ-authenticated AEAD upgrade over Noise but never makes the PeerId post-quantum; the current v4 outer frame has no stable plaintext headers or stable tags; direct mode is explicit opt-in and remains labelled non-anonymous. Q1 relay-only routing avoids the destination peer's direct IP view under explicit configuration, Q2 pads MLS plaintext to fixed buckets, Q3/Q4 move sender/message metadata into the MLS-protected inner frame with bounded wire-level deniability, and Q5's SOCKS5+Noise route is now the fail-closed default requiring a user-supplied proxy with no direct listener or QUIC fallback.
- **Tests:** Direct-connect wire tests; address validation tests; relay-only circuit/routing tests; MLS padding boundary and hostile-input tests; SOCKS5 fake-proxy domain-forwarding tests; v4 MAC-based route selection, random-tag, and inner-frame tests; GUI anonymity/configured-route status rows, plus pinned-transport mutual-pin, downgrade, wrong-pin, and invalid-config tests. Historical post-PQ connection-admission and post-transport results are separated from the current metadata/privacy gates in `SECURITY_TESTS.md` section 12 and `PROJECT_STATUS.md`.
- **Residual risk:** Substantial metadata exposure remains. Q2 padding is coarse and hides neither timing, direction, volume, nor outer-frame sizes; Q1 relays and Q5 proxies observe IP, timing, direction, volume, and coarse length. Current v4 route tags are fresh random values selected by group-keyed MAC verification; they remove link-by-tag but are not secrets, authorship proofs, or a traffic-analysis defense, and zero/ambiguous MAC routes fail closed. Recipients/current group members with MLS state can still attribute messages. No verified anonymity, mixnet, onion, I2P, proxy identity, Tor, full deniability, traffic-analysis defense, or metadata-confidentiality claim exists.

### Attacker B — Malicious network peer

- **Capabilities:** Send malformed, oversized, replayed, or out-of-order frames; disconnect; advertise addresses; exhaust request budgets.
- **Assumptions:** Holds a valid Noise key and can establish a connection.
- **Scenarios:** Frame parser abuse, replayed setup frames, cross-conversation substitution, connection/request flooding.
- **Expected defenses:** Bounded decoders with strict magic/version/length checks; current v4 group-keyed MAC-based route selection before decryption and a message replay cache plus sequence high-water mark in the MLS-protected inner frame; signed setup v5 over `/p2p-messenger/mls-setup/2` with `ciphersuite_id` at bytes 6..8 required to be `0x0051`, transaction ID at bytes 8..24, a self-contained PQ identity proof and a 3309-byte ML-DSA-65 `Application` signature, plus a bounded digest replay cache; production `decode_setup` and `verify_channel_scope` require PQ, while legacy v4 frames decode/verify only for adversarial tests; v1–v3/unknown suites rejected; file frames v3 with a 3309-byte ML-DSA-65 `File` signature are required by the production controller (legacy v2 adversarial-only); direct addresses must end `/p2p/<peer-id>` and reject `/p2p-circuit`; aggregate and per-protocol request caps; PeerId binding.
- **Tests:** Envelope tamper/replay/sequence and mutation tests (legacy v2/v3 retained as compatibility/adversarial evidence); v4 MAC-based route selection, random-tag, and inner-frame tests; setup v5 PQ transaction/tamper/replay-cache and `0x0051` suite tests; legacy v4 and file v2 adversarial decode/verify tests; bounded codec tests; aggregate and cross-protocol resilience tests. Historical post-PQ and post-transport test names/results are separated from current gates in `SECURITY_TESTS.md` section 12.
- **Residual risk:** The 512-entry setup/group-control cache is bounded and memory-only, but the schema v4 chained, blind-indexed digest log plus vault anchor rejects exact authenticated terminal replays after restart and keeps request retries idempotent; it fails closed at 4096 entries or malformed records and does not replace transaction binding or MLS state guards. Restoring the whole vault including the anchor is not locally detectable. Per-protocol reservations are bounded by the configured aggregate request/byte ceiling and are not a distributed-flood or OS-resource guarantee. Explicit pending-socket caps (16 inbound and 16 outbound by default) and a per-source-IP pre-auth cap (four direct TCP upgrades by default) bound concurrent handshakes, but distributed floods and OS-level resource exhaustion require external capacity testing.

### Attacker C — Malicious group member

- **Capabilities:** Send group-control frames, replay commits, attempt unauthorized channel access, exploit epoch confusion.
- **Assumptions:** Is an authenticated MLS group member.
- **Scenarios:** Forge admin role, replay old commit, decrypt a restricted-channel ciphertext obtained out of band.
- **Expected defenses:** Creator-admin authorization, signed commit operation/target binding, epoch checks, MLS sender credential checks, removed-member epoch exclusion.
- **Tests:** MLS Add/Remove/Update tests, stale-epoch rejection, group receipt tests, honest restricted-channel delivery tests.
- **Residual risk:** Channel confidentiality is not cryptographic for parent/default traffic. P6 local device-signed role-delegation primitives exist, but no directory, GUI trust anchor, or admin-role change is wired. Setup/group-control frames now have a bounded memory cache plus a durable chained digest log with anchor verification on unlock, but it is partial local continuity, not a replay-proof log or MLS state restoration.

### Attacker D — Compromised device / local disk extractor

- **Capabilities:** Read vault and quarantine files; possibly restore snapshots; inspect process memory if fully compromised.
- **Assumptions:** Knows or can guess the password only within Argon2id limits; may not have live memory access.
- **Scenarios:** Offline password guessing, plaintext grep of DB/WAL/SHM, key extraction, snapshot rollback, symlink redirection.
- **Expected defenses:** Argon2id with 96 MiB/t=4/p=1 defaults for new vaults and identity exports plus weak-vault rewrap on successful unlock and password-change upgrade; AEAD ciphertext; blind indexes; zeroizing buffers; redacted `Debug`; Unix symlink refusal; `secure_delete`; restricted SQLite `.db`/`-wal`/`-shm` permissions and bounded temp handling; schema v4 chained control log with `<vault>/control.anchor` verified on unlock.
- **Tests:** Vault wrong-password/change/plaintext scans; identity envelope tests; Unix symlink tests; redacted-debug tests; durable replay/idempotence after reopen, older-DB-with-current-anchor rollback detection, and anchor bit-flip detection.
- **Residual risk:** No Windows ACL hardening, no secure erasure guarantee, no external anchor (a full vault restored with its anchor is not locally detectable), no decrypted-message restore, and full device compromise exposes decrypted memory. Encrypted opaque MLS state restores only authenticated joined/ready group state.

### Attacker E — Malicious relay / storage operator

- **Capabilities:** Observe circuit metadata and ciphertext sizes/timing; drop, delay, replay transport bytes; deny service.
- **Assumptions:** Does not possess endpoint Noise or MLS keys.
- **Scenarios:** Inspect file offer to recover content key; tamper with relayed ciphertext; replay stored ciphertext.
- **Expected defenses:** Noise terminates at endpoints; relay copies opaque bytes; MLS and file AEAD reject tampering; file transfer over observed relayed paths is disabled by conservative policy.
- **Tests:** Source-level libp2p verification; direct wire tests; targeted and final-workspace inbound relay-policy tests.
- **Residual risk:** No live three-node relay interception test has been run on this host. No decentralized mailbox/storage protocol exists.

### Attacker F — Malicious software update / supply chain

- **Capabilities:** Publish modified dependency versions, artifacts, or old vulnerable releases.
- **Assumptions:** Can influence registry or release channel but cannot sign with the developer key if signing is configured.
- **Scenarios:** Dependency confusion, yanked/crate compromise, modified installer, downgrade.
- **Expected defenses:** `Cargo.lock`, locked builds, checksums, source-first packaging, and SHA-pinned external workflow actions.
- **Tests:** Locked CI builds and release checksum verification.
- **Residual risk:** A security workflow and `deny.toml` are configured; local advisory/license/ban/source checks now pass for both lockfiles after upgrading libp2p and the OpenMLS provider line. `cargo audit` still reports unmaintained warnings, and the OpenMLS fix is on a release-candidate line. Deterministic SBOMs exist but provide only locked source-graph inventory. Signed artifacts, provenance, and reproducible builds remain absent; pinned actions are not independently audited, signature-verified, or proven trustworthy. Checksums prove release-channel consistency, not developer identity.

## 4. Attack-to-mitigation matrix

| Attack | Primary mitigation | Verified locally | Residual risk |
|---|---|---|---|
| Wrong PeerId impersonation | Classical libp2p `PeerId` binding plus signed setup v5 ML-DSA-65 `Application` proof over the v2 PQ identity bundle and v4 MLS-protected inner-frame sender binding; opt-in pinned transport additionally requires an exact ML-DSA-65 `Application` key and a signed ML-KEM-768 exchange; no third-party long-term signature on the v4 message wire | Yes for classical and opt-in pinned cases | TLS/libp2p `PeerId` authentication remains classical even in pinned mode; human identity still requires out-of-band fingerprint; group members with MLS state can attribute |
| Envelope replay | v4 MAC-based route checks over fresh random tags, then message-ID cache + sequence high-water mark + epoch checks in the MLS-protected inner frame | Yes | Replay state is in-memory; legacy v2/v3 codecs are adversarial evidence only |
| Setup replay/overwrite | Signed v5 PQ frames over `/p2p-messenger/mls-setup/2` with `ciphersuite_id` `0x0051`, self-contained PQ proof, strict `(conversation, transaction, peer)` state guards, bounded 512-entry digest cache, and schema v4 chained blind-indexed log anchored by `<vault>/control.anchor`; legacy v4 is adversarial-only | Yes for tested cases | Memory cache is bounded; durable log caps at 4096 and fails closed; full vault including anchor rollback is not locally detectable |
| Unauthorized group change | Admin check + signed commit operation/target binding | Yes | No directory/GUI delegated roles; P6 local primitives only |
| Unauthorized channel policy | Admin check + signed parent `CHN1` policy + revision checks | Yes | Policy metadata remains visible to all parent members |
| Restricted-channel plaintext disclosure | P1d derived `MlsChannelGroup` for non-default text/receipts, signed parent/channel binding, readiness receipts, P1e authenticated restore, and P1f distinct GUI status | Yes for non-default controller text, including restart of ready groups | Default channel and policy stay on the parent group; setup material does not survive restart and no complete ACL is claimed |
| Relay content-key disclosure | Noise terminates at endpoints | Source verified | No live three-node capture test |
| File tampering | Fresh AEAD key, AAD, manifest hash, full hash | Yes | Scanner availability is a separate policy gate |
| Stalled file transfer | Inactivity deadline, separate abort, local key zeroization, pending-request cleanup, incomplete quarantine cleanup | Yes for loopback timeout/abort tests | Worker request already queued in libp2p cannot be withdrawn; late responses are ignored |
| Malicious file execution | No auto-execute; narrow validation; explicit release | Yes | No general format/MIME parser or real scanner configured |
| Vault plaintext grep | AEAD at rest + blind indexes + WAL/SHM scans | Yes | Full-vault snapshot rollback including the anchor is undetectable locally; DB-only rollback is detected |
| DB-only rollback / anchor tamper | Schema v4 chain plus `control.anchor` verified on unlock | Yes | Full-vault-plus-anchor restore has no local detection and no external anchor |
| Symlink redirection | Unix final-path checks; quarantine ancestor-component and parent-traversal rejection | Partially | Vault parent-path symlinks and Windows reparse points remain gaps |
| Pre-authentication socket flooding | Explicit libp2p pending-inbound/outbound caps plus `PerIpPendingTransport` cap over direct TCP+Noise+Yamux and QUIC before authentication; authenticated aggregate and per-protocol limits after transport authentication | Yes for stalled-socket and per-IP adversarial tests | No distributed flood benchmark or OS FD-tuning claim; relay upgrades are outside the raw-socket rule; QUIC TLS `PeerId` authentication remains classical |
| Same-peer cross-protocol starvation | Aggregate per-peer ceiling plus derived per-protocol request/byte reservations; denied requests are not charged | Yes for local loopback | Reservations are bounded by aggregate config; no distributed flood benchmark |
| Metadata tracing | Q1 relay-only route, Q2 coarse MLS padding, Q3/Q4 inner metadata and bounded wire deniability, current v4 random tags with MAC-based selection | Yes for local configuration/wire checks | Direct peers/relays/proxies still see IP, timing, direction, volume, and coarse length; v4 removes link-by-tag but not traffic-analysis exposure; no anonymity claim |
| Malicious update | Lockfile + locked builds + checksums + local advisory gate | Partially | No signed artifacts, CI gate run, or provenance claim |

## 5. Assumptions that do not hold

- A successful signature does not prove the real-world identity of a contact.
- MLS group membership does not prove authorization for a restricted logical channel in the current design.
- AEAD integrity does not prove a file is free of malware.
- Transport encryption does not provide anonymity.
- A v4 route tag is a fresh random value, not a secret, authorship proof, or traffic-analysis defense; receivers select groups by group-keyed MAC verification, and zero/ambiguous MAC matches fail closed. Historical v3 epoch-stable tags are rejected in production.
- A direct connection or a discovery candidate does not prove network reachability or user trust.
- File deletion does not provide cryptographic erasure on SSD/CoW filesystems.
- A direct QUIC `X25519MLKEM768` KEX does not make TLS/libp2p `PeerId` authentication post-quantum; TCP/SOCKS5 Noise remains classical. The opt-in pinned transport layer adds a PQ-authenticated upgrade over Noise with locally supplied pins, but does not make the PeerId post-quantum and rejects relay/QUIC paths. PQ coverage therefore includes MLS KEM/signatures, setup/file signatures, direct QUIC hybrid KEX, and the opt-in layered transport only; no global full post-quantum protection is claimed.
- `TorRequired` is now the fail-closed default requiring a user-supplied SOCKS5 proxy, but it is policy and status reporting only, not verified Tor, anonymity, or unlinkability; direct QUIC is absent from that default and disabled in `RelayOnly`, and direct transport is explicit `direct()` opt-in.
