# Security Audit Register

This is a source-backed Phase 0 reassessment record, not an external audit. Findings were verified against source and tests before remediation. Classification values are:

- **Confirmed** — the source fact is established.
- **Partially confirmed** — the code fact is established; exploitability or security impact is conditional.
- **Not reproduced** — a suspected issue was checked and not found.
- **Incorrect previous assessment** — an earlier assumption is contradicted by source.
- **Requires further investigation** — evidence is incomplete on this host.

Remediation status is recorded separately so that a planned fix is never mistaken for a completed one.

## 1. Finding register

### SA-001 — Restricted channels are not cryptographically isolated

- **Classification:** Confirmed (boundary); Partially confirmed (impact requires ciphertext access).
- **Files:** `crates/chat/src/channel.rs:1-8`, `crates/chat/src/controller.rs:108-110`, `crates/chat/src/controller.rs:240-318`, `crates/chat/src/controller.rs:2660-2684`, `crates/chat/src/controller.rs:2774-2781`, `crates/chat/tests/controller.rs:1411-1491`.
- **Weakness:** Channels are logical partitions inside one MLS group. `channel_id` is inside authenticated MLS plaintext, but all group members hold the same MLS group secrets.
- **Attack scenario:** An excluded group member obtains a captured channel ciphertext and decrypts it with its MLS group keys; honest receivers merely suppress display.
- **Impact:** Restricted-channel plaintext disclosure. No cryptographic ACL boundary.
- **Reproducibility:** Static property proven; dynamic exploit requires feeding captured ciphertext to an excluded member.
- **Severity:** Medium.
- **Correction:** One independent MLS group per channel with separate group ID, epoch, key schedule, membership, replay state, and membership-change commits.
- **Verification test:** Inject an allowed-member ciphertext into an excluded member and assert MLS decryption fails, not merely that no message is displayed.
- **Status:** Open. Honest limitation documented.

### SA-002 — Single Ed25519 identity reused across roles; `Identity` is `Clone`

- **Classification:** Confirmed (reuse and `Clone`); Partially confirmed (cross-protocol harm).
- **Files:** `crates/identity/src/lib.rs:65-71`, `crates/identity/src/lib.rs:140-155`, `crates/groups/src/lib.rs:98-126`, `crates/messaging/src/envelope.rs:134-139`, `crates/chat/src/setup.rs:289-303`, `crates/files/src/frame.rs:342-359`.
- **Weakness:** The same device key signs Noise transport identity, MLS credentials and commits, outer envelopes, setup frames, and file offers. `Identity` is cloned, duplicating private-key material.
- **Attack scenario:** Memory disclosure from any cloned owner exposes the single key. Cross-protocol signature confusion is theoretically possible but not demonstrated because signed encodings include domain magic/context.
- **Impact:** Increased compromise blast radius; no independent role containment.
- **Severity:** Medium.
- **Correction:** Independent root/device/transport/MLS/application keys with authenticated certificates and revocation/rotation; replace `Clone` with `Arc`; verify underlying zeroization support.
- **Verification test:** Assert distinct role keys, rejection of wrong-role signatures, invalid/expired/revoked certificate rejection, forged rotation rejection, and no secret in `Debug`.
- **Status:** Open. Existing redacted `Debug` and domain-separated signed encodings are positive controls.

### SA-003 — Setup frames lack transaction IDs and strict transaction binding

- **Classification:** Confirmed (original weakness; now remediated with residual limits recorded in SA-020).
- **Files:** `crates/chat/src/setup.rs:45-94`, `crates/chat/src/setup.rs:372-381`, `crates/chat/src/controller.rs:1880-1920`, `crates/chat/src/controller.rs:2019-2025`, `crates/chat/src/controller.rs:2104-2177`, `crates/storage/src/control_log.rs`, `crates/storage/src/lib.rs` (schema v4), `crates/storage/tests/vault.rs`, `apps/desktop/src/app.rs`.
- **Weakness:** Frames originally carried conversation ID only, so another peer could displace a pending KeyPackage and a stale ack could complete a later setup. v2 transaction binding closes those cases; exact authenticated frame replay still needed a durable boundary.
- **Attack scenario:** A malicious connected peer sends a signed request for a pending conversation, displacing the legitimate inviter's KeyPackage; a stale ack completes a later setup prematurely; an exact authenticated frame is replayed after restart.
- **Impact:** Setup denial of service and mis-binding risk; no plaintext disclosure shown.
- **Severity:** Medium.
- **Correction:** Signed transaction ID on every setup frame, state and ack binding by `(conversation_id, transaction_id, peer)`, a bounded in-memory exact-frame cache, and a durable chained digest log with a vault anchor.
- **Verification test:** Duplicate request with a different transaction cannot overwrite; stale ack rejected; tampered transaction ID fails signature; cross-transaction substitution rejected; exact terminal-frame replay after restart ignored; idempotent request retry after restart preserved; durable chain, blind indexes, and anchor verified on unlock.
- **Status:** Implemented and verified in the final 207-test workspace run. `MLS1` v2 adds signed 16-byte transaction IDs; pending state, acks, retries, and Welcomes are bound to `(conversation_id, transaction_id, peer)`, and v1 is rejected. A bounded 512-entry in-memory cache stores only `(PeerId, SHA-256 digest)` pairs. Schema v4 adds `control_log` (`sequence`, `record_bi`, `ciphertext`, `chain_hash`) and `control_state` (`id`, `sequence`, `chain`) with transactional migrations. `crates/storage/src/control_log.rs` records already authenticated signed frames as bounded XChaCha20-Poly1305 records (`Purpose::Db`) containing public PeerId bytes (at most 64), a SHA-256 frame digest, and a repeatable flag, with HMAC blind indexes (`Purpose::BlindIndex`) and a chained SHA-256 hash; the log is capped at 4096 entries and fails closed when full or malformed. `KeyPackageRequest` and `GroupJoinRequest` are repeatable; KeyPackage responses, Welcomes, `GroupWelcome`, `GroupCommit`, and all acks are non-repeatable. `MessengerController::start_with_control_log` accepts a cloned vault `Session` (the GUI passes `session.try_clone()`), and a vault/controller identity mismatch fails startup. `<vault>/control.anchor` holds AEAD-protected high-water-mark state (`sequence`, `chain`) with `<vault>/control.anchor.tmp` for atomic replace; `Vault::unlock` calls `verify_control_log`, which verifies every record, chain continuity, blind indexes, and the anchor. Storage has 15 tests including durable idempotence/replay, DB-only rollback detection, and anchor tamper; chat has two controller restart regressions. This is not OpenMLS persistence: digests are not a backup and do not restore group state, ratchets, channels, or decrypted messages.

### SA-004 — Replay state is memory-only; legacy load loses delivery fidelity

- **Classification:** Partially confirmed.
- **Files:** `crates/messaging/src/conversation.rs:70-97`, `crates/messaging/src/conversation.rs:140-159`, `crates/messaging/src/conversation.rs:281-325`, `crates/messaging/src/conversation.rs:403-421`, `crates/chat/src/lib.rs:9-11`.
- **Weakness:** The core replay cache and high-water marks are memory-only. `Conversation::load` restores delivery state as `Composed` and derives sequence from ciphertext. `p2p-chat` does not use that load path.
- **Attack scenario:** A caller that persists/reloads a legacy conversation can re-accept a captured signed envelope.
- **Impact:** Replay/UI spoofing in the standalone `p2p-messaging` API; not shown in `MessengerController`.
- **Severity:** Medium (conditional).
- **Correction:** Persist authenticated replay state bound to conversation/MLS epoch; reject ambiguous legacy delivery states.
- **Verification test:** Reload and reinject an old envelope; assert replay rejection and accurate delivery state.
- **Status:** Open; documented as a library limitation.

### SA-005 — MLS group state is memory-only

- **Classification:** Confirmed (state model); Partially confirmed (security impact).
- **Files:** `crates/groups/src/lib.rs:1-6`, `crates/groups/src/lib.rs:170-176`, `crates/chat/src/lib.rs:9-11`, `crates/messaging/src/conversation.rs:284-287`.
- **Weakness:** OpenMLS state, key packages, pending commits, ratchet state, and replay state are not persisted.
- **Attack scenario:** Not an active attack; restart causes loss of decryption continuity and forces fresh setup.
- **Impact:** Availability/continuity loss, not plaintext leakage.
- **Severity:** Low–Medium.
- **Correction:** Use a supported OpenMLS storage provider with purpose-specific encrypted keys, transactional state, schema versioning, and epoch/replay binding.
- **Verification test:** Restart after add/remove/message and assert no inconsistent group/epoch/ratchet combination is restored.
- **Status:** Open; explicitly documented. The new control-log digest log does **not** restore OpenMLS ratchet/group state, pending key packages, channels, or decrypted messages.

### SA-006 — Partial authenticated rollback protection for the encrypted vault

- **Classification:** Partially confirmed (residual absence by inspection).
- **Files:** `crates/storage/src/lib.rs` (schema v4), `crates/storage/src/control_log.rs`, `crates/storage/src/lib.rs:227-247`, `crates/storage/tests/vault.rs:616-665`.
- **Weakness:** AEAD tags remain valid when a complete older snapshot is restored. Schema v4's chained control log and `<vault>/control.anchor` now detect a database-only rollback or a tampered/missing anchor, but no state anchor exists outside the replaceable vault directory.
- **Attack scenario:** Attacker with filesystem write access restores an older `profile.db`, WAL, and SHM while leaving the current anchor in place, or tampers with the anchor; both are detected. Restoring the entire vault directory including the anchor is not detected locally.
- **Impact:** Partial rollback of message/attachment/control state; no plaintext exposure or tag forgery.
- **Severity:** Low–Medium.
- **Correction:** Keep the authenticated monotonic chain and add an integrity anchor outside replaceable files where feasible; reject stale state.
- **Verification test:** Restore an older database while keeping the current anchor and assert unlock fails; flip the anchor and assert unlock fails. A full-vault-plus-anchor restore has no local negative test and is recorded as a residual limitation (SA-020).
- **Status:** Partially addressed. The schema v4 chain plus `<vault>/control.anchor` detects database-only rollback and anchor tamper in the final 207-test workspace run. Full-vault-including-anchor rollback remains open; no external anchor is claimed.

### SA-007 — Filesystem path hardening is Unix-only and final-path-only

- **Classification:** Confirmed (platform gap); Partially confirmed (local exploitability).
- **Files:** `crates/files/src/transfer.rs:859-913`, `crates/files/src/transfer.rs:945-958`, `crates/storage/src/lib.rs:610-635`.
- **Weakness:** `reject_symlink` is a no-op on non-Unix platforms and checks only the final quarantine path, not parent components. Windows reparse-point behavior was not verified.
- **Attack scenario:** A local attacker pre-places a symlink/junction in a parent directory and redirects ciphertext writes.
- **Impact:** Quarantine redirection or denial of service; no key/plaintext disclosure shown.
- **Severity:** Low–Medium.
- **Correction:** Verify every path component under a trusted root; use `O_NOFOLLOW`/openat-style admission; add Windows reparse-point checks.
- **Verification test:** Pre-place symlink/junction at base and intermediate path; assert fail-closed.
- **Status:** Partially addressed for file quarantine: generic ancestor-component and parent-traversal rejection is implemented in `crates/files/src/transfer.rs` with two new Unix tests; targeted and final 207-test workspace runs pass. Vault parent-path hardening and Windows reparse points remain open.

### SA-008 — File transfer cancellation is release-only; no transfer expiration

- **Classification:** Confirmed.
- **Files:** `crates/files/src/transfer.rs`, `crates/chat/src/controller.rs`, `crates/chat/src/lib.rs`, `apps/desktop/src/app.rs`.
- **Weakness:** `cancel_file` terminated release decisions but not the transfer; no TTL/deadline existed.
- **Attack scenario:** A peer stalls a transfer indefinitely.
- **Impact:** Resource use and misleading UX; no plaintext exposure.
- **Severity:** Low.
- **Correction:** Add transfer deadlines and distinguish cancel-release from abort-transfer.
- **Verification test:** Stall past TTL and assert abort and bounded state.
- **Status:** Implemented and verified. Active transfers now use a configurable inactivity deadline (default 5 minutes, maximum 1 hour) that is reset only by authenticated progress. `abort_file` stops new frames, drops pending response bookkeeping, zeroizes in-memory keys, and removes incomplete quarantine ciphertext; `cancel_file` is limited to completed integrity-verified transfers. Regression tests cover timeout, late-frame rejection, partial-quarantine cleanup, and starting a replacement transfer. The pinned libp2p request-response API cannot withdraw an already queued worker request, so a local abort ignores late responses rather than cancelling that worker state; the residual limitation is documented in `SECURITY_LIMITATIONS.md`. Final 207-test workspace run passes.

### SA-009 — Incorrect relay file-key visibility rationale

- **Classification:** Incorrect previous assessment.
- **Files:** `crates/network/src/lib.rs:1930-1933`, `docs/NETWORKING.md:36`, `docs/CRYPTOGRAPHY.md:87`, `docs/SECURITY.md:55-56`, `docs/DECISIONS/ADR-0012-m13-privacy-network-hardening.md:20`.
- **Weakness:** Earlier text claimed a relay would see the fresh file content key in the signed Offer.
- **Source evidence:** `libp2p-0.57.1/src/builder/phase/relay.rs:82-85` applies the same security upgrade to the relay transport; `libp2p-relay-0.22.0/src/copy_future.rs:22-25` and `:88-106` forward opaque substream bytes without interpreting the application protocol; `libp2p-noise-0.47.0/src/io/framed.rs:111-128` encrypts/decrypts only at endpoints.
- **Impact:** No cryptographic breach; a false rationale could drive unsafe future design decisions.
- **Correction:** State that relays see ciphertext, PeerIds, IPs, timing, and sizes only. Keep the conservative file-over-relay policy but describe it accurately.
- **Verification test:** Three-node loopback relay harness with sentinel bytes; assert relay does not observe decoded Offer/key and Noise tampering fails.
- **Status:** Rationale corrected in code and docs; targeted and final 207-test workspace runs pass. The external three-node relay capture harness remains pending.

### SA-010 — File-over-relay policy enforced only on outbound sends

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:1934-1943`, `crates/network/src/lib.rs:2383-2402`, `crates/chat/src/controller.rs:2260-2264`.
- **Weakness:** `Network::send_file` rejects relayed peers, but inbound file requests are emitted without checking relay status.
- **Attack scenario:** A relayed peer offers a file to a receiver with a joined conversation.
- **Impact:** Documented policy is not symmetric. Noise still protects the content key.
- **Severity:** Medium (policy honesty).
- **Correction:** Reject inbound file requests from observed relayed peers before creating response state.
- **Verification test:** Inject inbound file event for a relayed peer; assert no `RequestReceived` and a policy failure event.
- **Status:** Symmetric rejection implemented through the shared `file_request_policy_response_id` production helper; targeted and final workspace tests assert no `RequestReceived` and one `Failed` event. A direct `handle_file_event` test is not feasible because libp2p's `ResponseChannel` constructor is private.

### SA-011 — Public dial API bypasses direct-address validation

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:789-795`, `crates/network/src/lib.rs:883-897`, `crates/network/src/lib.rs:1223-1238`, `crates/chat/src/controller.rs:2915-2924`.
- **Weakness:** GUI/config paths validate direct addresses, but `Network::dial` only extracts a PeerId and can queue `/p2p-circuit`.
- **Attack scenario:** A non-GUI caller constructs a circuit address and dials it.
- **Impact:** Documented direct-only validation is bypassed for API callers.
- **Severity:** Low.
- **Correction:** Call `validate_direct_peer_address` in `Network::dial`.
- **Verification test:** Assert circuit addresses are rejected before pending insertion/command queueing.
- **Status:** Implemented and verified in `Network::dial` by targeted and final workspace tests.

### SA-012 — Rate-limiter peer entries are never removed

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:203-235`.
- **Weakness:** Empty `VecDeque` entries remain after the sliding window expires.
- **Attack scenario:** Many distinct peers each send one small request.
- **Impact:** Slow unbounded memory growth over process lifetime.
- **Severity:** Low.
- **Correction:** Remove empty entries after `retain` and bound tracked peers.
- **Verification test:** Insert many peers, advance time, assert stale entries removed.
- **Status:** Implemented and verified with synthetic timestamps in targeted and final workspace tests.

### SA-013 — Fabricated AutoNAT confidence value

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:1777-1793`, `crates/network/src/privacy.rs:114-119`.
- **Weakness:** `NatEvent::StatusChanged` emits `confidence: 0`; libp2p 0.56's AutoNAT `StatusChanged` event exposes no confidence value.
- **Impact:** Misleading diagnostic field; no trust or connection claim is promoted.
- **Severity:** Informational.
- **Correction:** Remove the field rather than guess a value.
- **Verification test:** Compile/test with no fabricated confidence field.
- **Status:** Field removed and verified in targeted and final workspace tests; no guessed value substituted.

### SA-014 — Cumulative counters can be mistaken for live state

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:1099-1106`, `crates/network/src/lib.rs:1136-1139`, `apps/desktop/src/model.rs:390-392`, `apps/desktop/src/model.rs:547-552`.
- **Weakness:** Reservation, circuit, and identify counters only increase; they are displayed alongside a genuine current relayed-connection count.
- **Impact:** Misleading cached status. No trust, contact, or delivery claim results.
- **Severity:** Low.
- **Correction:** Label counters as observed-since-startup or rename fields explicitly.
- **Verification test:** GUI/status test asserts cumulative wording.
- **Status:** Addressed without renaming fields: doc comments and GUI labels say "observed since startup", while `relayed_connections` is labelled as the latest live transport observation. Targeted and final workspace GUI/network tests pass.

### SA-015 — Supply-chain controls are incomplete

- **Classification:** Confirmed.
- **Files:** `.github/workflows/ci.yml`, `.github/workflows/build.yml`, `.github/workflows/security.yml`, `deny.toml`, `fuzz/Cargo.toml`, `docs/DEPENDENCIES.md`.
- **Weakness:** No green `cargo audit`/`cargo deny` advisory result or CI run, no signed artifacts or provenance, no long coverage-guided fuzz campaign, and (previously) mutable GitHub Actions refs in workflows. Local tooling and non-advisory policy checks now run, but known advisories remain.
- **Impact:** Dependency advisories and artifact identity are not automatically enforced.
- **Severity:** Medium for release assurance.
- **Correction:** Pin external GitHub Actions to commit SHAs, add dependency advisory/license/source gates, align the deny config and CI invocation with the installed cargo-deny version, fuzz smoke tests, deterministic SBOM generation and release inclusion, and document signing/key rotation.
- **Verification test:** CI runs locked audit/deny, fuzz smoke, and byte-identical SBOM regeneration on every PR; locally, workflow YAML is parsed, all `uses:` refs are inspected for 40-character SHAs, and all cargo-deny checks plus cargo-audit pass for both lockfiles. A green GitHub CI run remains unclaimed.
- **Status:** Partially addressed by `.github/workflows/security.yml`, `deny.toml`, a deterministic `P2P1` mutation/truncation smoke test, six real libFuzzer targets in `fuzz/`, `scripts/generate_sbom.py`, and SHA-pinned workflow actions. All 25 external action usages in `ci.yml`, `build.yml`, and `security.yml` are pinned to 40-character commit SHAs resolved from GitHub API refs on 2026-11-25; comments retain the source tag or branch, and the `dtolnay/rust-toolchain` pins freeze the `stable`/`nightly` branch heads. Locally generated root and fuzz SPDX documents now contain 479 packages each, regenerate byte-for-byte, and leak no absolute paths. Stable `cargo check`/`cargo clippy`, all 207 workspace tests, and six local plain-libFuzzer 1000-input smoke passes completed without crashes, but the fuzz runs were not coverage-instrumented. Locally installed `cargo-audit 0.23.0` and `cargo-deny 0.22.1` now pass all checks for both lockfiles after moving to libp2p 0.57.1, request-response 0.30.0, OpenMLS 0.10.0-rc.1 with its patched RustCrypto stack, egui/eframe 0.35 to resolve the `js-sys` conflict, and removal of the unused direct `async-trait` dependency after the RPITIT codec migration. `cargo audit` still reports five non-failing unmaintained warnings. No green GitHub CI run is claimed. A nightly coverage-guided campaign, signed artifacts, and build provenance remain absent; pinning does not prove the pinned action code is reviewed, signed, or trustworthy.

### SA-016 — Device-security guarantees remain platform-limited

- **Classification:** Confirmed.
- **Files:** `README.md:93-97`, `docs/STORAGE.md:19,58-59`, `PROJECT_STATUS.md:171-172`.
- **Weakness:** Windows ACL hardening, secure erasure, and real scanner configuration remain absent.
- **Impact:** Local protections are bounded and platform-dependent.
- **Severity:** Medium.
- **Correction:** Implement platform-specific ACLs where verifiable; keep cryptographic-erasure framing; configure a real scanner.
- **Verification test:** Platform-specific ACL tests and scanner integration tests.
- **Status:** Partially addressed: the repository-wide print/log/`Debug` review is complete, path/error regressions pass, and `scripts/check_diagnostics.py` enforces the redaction rules in CI; Windows ACL, erasure, and configured-scanner claims stay open.

### SA-017 — No anonymity architecture exists

- **Classification:** Confirmed.
- **Files:** `Cargo.toml:38-54`, `docs/SECURITY.md:60`, `README.md:44,95`.
- **Weakness:** No Tor/SOCKS/onion/I2P/mixnet support, no `PrivacyMode::TorRequired`, no fail-closed routing, no DNS/IPv6 leak test.
- **Impact:** Direct peers and relays observe metadata; global correlation remains possible.
- **Severity:** High relative to the requested anonymity objective; honest non-claim for current product scope.
- **Correction:** Requires a dedicated anonymity design and external network testing; do not expose an incomplete Tor mode.
- **Verification test:** Packet-capture leak tests on two machines with a controlled Tor/onion setup.
- **Status:** External blocker; documented limitation.

### SA-018 — Pre-authentication socket admission was not explicitly bounded per IP

- **Classification:** Confirmed and remediated at the transport layer.
- **Files:** `crates/network/src/lib.rs` (`TransportLimits`, `PerIpPendingTransport`, `NetworkConfig` fields, `ConnectionLimitBehaviour`, `incoming_error_reason`, `Network::poll_event`), `crates/network/src/pending_admission.rs`, and `crates/network/tests/resilience.rs`.
- **Weakness:** Application connection caps applied only after authenticated `ConnectionEstablished`; libp2p's pending-socket defaults were left implicit, and per-IP policy existed only after authentication.
- **Impact:** A single source IP could occupy the global pending-socket budget with stalled handshakes before Noise authentication, causing FD/task/memory pressure.
- **Severity:** Medium. Local stalled-socket tests demonstrate both global and per-IP admission denial before a Noise handshake; distributed flood capacity was not measured.
- **Correction:** Explicitly configure `with_max_pending_incoming`/`with_max_pending_outgoing` (default 16 each), map established global/per-peer limits into the same libp2p behaviour, and wrap the upgraded TCP transport so at most `max_connections_per_ip` raw sockets from one source IP can be in pre-auth upgrade at once. Pre-auth slots are released when the upgrade completes, fails, or is dropped. Reject zero or oversized limits during config validation and keep peerless advisory failures from overwriting cached live connections.
- **Verification test:** `pending_incoming_limit_blocks_a_stalled_socket_before_noise` holds one raw TCP socket open, asserts a legitimate dial cannot complete, observes a bounded “connection limit exceeded” failure reason, then dials successfully after the stalled socket is dropped. `pending_incoming_per_ip_limit_drops_extra_socket_before_noise` holds two sockets from one IP, proves a third is closed before Noise, and proves the slot is reusable after one is released. Bounded-state unit tests, `peerless_failure_event_does_not_erase_live_connections`, and limit-config tests also pass.
- **Status:** Implemented and verified in the final serialized workspace run. Per-IP admission is now enforced before authentication for direct TCP sockets; relay upgrades are outside this raw-socket rule. No distributed flood benchmark or OS-level FD-tuning claim is made.

### SA-019 — Shared request budget permits same-peer cross-protocol starvation

- **Classification:** Confirmed and remediated with a bounded reservation.
- **Files:** `crates/network/src/lib.rs` (`RequestProtocol`, `RateLimiter`, protocol-specific admission in the swarm loop) and `crates/network/tests/resilience.rs`.
- **Weakness:** Messages, setup, files, and control shared one sliding per-peer budget, so one saturated protocol could consume all of a peer's request capacity.
- **Impact:** A peer could starve its own message or setup traffic; the aggregate ceiling was also the only byte reservation.
- **Severity:** Low.
- **Correction:** Retain the aggregate per-peer request/byte ceiling and add derived per-protocol request/byte buckets for message, setup, file, and control. Denied requests are not charged to either bucket, so a per-protocol rejection cannot consume another protocol's aggregate capacity. When a custom aggregate byte ceiling is below four full frames, the byte reservation falls back to that ceiling; the aggregate limit remains authoritative.
- **Verification test:** `rate_limiter_reserves_protocol_shares_inside_the_aggregate_ceiling`, `rate_limiter_denied_request_does_not_charge_the_aggregate_budget`, and `saturated_control_traffic_does_not_block_messages` pass, along with the existing one-request aggregate ceiling test.
- **Status:** Implemented and verified in the final 207-test workspace run. Per-protocol reservations are bounded by the aggregate configuration; this is DoS isolation for one authenticated peer, not a distributed-flood capacity guarantee.

### SA-020 — Full-vault rollback including the control anchor remains locally undetectable

- **Classification:** Confirmed by source inspection; no positive test is claimed.
- **Files:** `crates/storage/src/control_log.rs:1-9`, `crates/storage/src/control_log.rs:365-424`, `crates/storage/tests/vault.rs:616-665`.
- **Weakness:** `control.anchor` lives in the same vault directory as the database it protects. An attacker who restores a complete older vault snapshot, including the matching anchor, presents a self-consistent `(sequence, chain)` pair; `verify_control_log` has no external reference against which to detect that rollback.
- **Attack scenario:** A filesystem attacker with write access replaces the entire vault directory with an older copy of `profile.db*`, `control.anchor`, and related files.
- **Impact:** Rollback of vault and control-log state; no plaintext exposure or tag forgery. The system is not replay-proof and is not externally anchored.
- **Severity:** Low–Medium (requires filesystem write access and an older snapshot).
- **Correction:** An optional, future, user-controlled external anchor outside the replaceable vault directory (for example, a user-managed path or separate service) would be required. None is implemented.
- **Verification test:** Not present. The existing tests cover database-only rollback and anchor tampering, not a full-vault-plus-anchor restore; do not represent local silence on such a restore as evidence of rollback resistance.
- **Status:** Accepted residual limitation, evidenced by source inspection. An external anchor design is a future option, not a current claim.

## 2. Positive controls — not reproduced as flaws

### PC-001 — Custom cryptography and secret logging

- **Classification:** Not reproduced.
- **Evidence:** `crates/crypto/src/lib.rs:1-9` states no primitive is implemented locally; `crates/crypto/src/aead.rs:20-43` uses fresh nonces; `crates/crypto/src/kdf.rs:30-47,82-107` bounds Argon2id; `crates/crypto/src/subkeys.rs:64-93` uses HKDF separation. Redacted/omitting `Debug` implementations exist across identity, envelope, channel, setup, file, transfer, and network event types.
- **Status:** Preserve with regression tests and the `scripts/check_diagnostics.py` CI guard.

### PC-002 — Scanner and release fail-closed behavior

- **Classification:** Not reproduced as a flaw.
- **Evidence:** `crates/security/src/lib.rs:60-86` allows release only on `CleanNoThreatDetected`; `crates/security/src/lib.rs:213-221` maps no scanner to `Unavailable`; `crates/security/src/lib.rs:320-367` denies by default; `crates/files/src/transfer.rs:655-674` gates release.
- **Status:** Preserve; structural validation is not malware detection.

### PC-003 — Advisory-only optional network events

- **Classification:** Not reproduced as a flaw.
- **Evidence:** `crates/chat/src/controller.rs:618-628` drains control/discovery/relay/NAT/identify queues without promoting them to contacts, trust, delivery, verification, or capabilities.
- **Status:** Preserve with hostile-event regression tests.

### PC-004 — Diagnostic path and untrusted-text exposure

- **Classification:** Partially confirmed (metadata/log-injection hygiene, not secret compromise).
- **Evidence:** Derived `Debug` on `Vault` and `FileConfig` printed local directory paths, and `ContactPayload::parse` reflected an unknown query key into its error text. Both now use static or redacted diagnostics; the repository-wide print/log/`Debug` inventory found no password, private-key, plaintext, or opaque-frame output. `scripts/check_diagnostics.py` rejects unmarked raw output macros, derived `Debug` on protected types, and named fields that indicate secret material.
- **Status:** Corrected in the final 207-test workspace run, with regressions for both path redaction and non-reflected unknown fields and a passing CI diagnostic guard.

## 3. Remediation priority

1. Done: setup transaction binding, a bounded memory-only `(PeerId, SHA-256 digest)` replay cache, and schema v4 durable chained, blind-indexed digest continuity with an AEAD vault anchor (SA-003). Rollback detection remains partial (SA-006), full-vault-including-anchor rollback is an accepted residual limitation (SA-020), and MLS persistence remains open (SA-005).
2. Done: symmetric relay policy, accurate relay rationale, direct dial validation, rate-limiter cleanup, honest status fields, explicit global and per-IP pre-authentication socket caps, per-protocol request isolation, repository-wide diagnostic redaction review, and automated CI diagnostic guard (SA-009–SA-014, SA-018, SA-019, PC-004).
3. Partial: supply-chain workflow/config, SHA-pinned external actions, deterministic smoke test, six libFuzzer targets, a CI fuzz-smoke job, deterministic locked SBOM generation/release inclusion, and locally passing audit/deny gates added (SA-015); unmaintained-crate warnings, OpenMLS RC dependence, green CI, a coverage-guided campaign, signed artifacts, and provenance remain.
4. Done: transfer inactivity deadlines, separate abort from release cancellation, and partial-quarantine cleanup (SA-008).
5. Design separate MLS groups per channel (SA-001).
6. Design role-separated identity certificates (SA-002).
7. Open: implement encrypted MLS persistence with a rollback-aware schema (SA-005). The control digest log is not MLS state or a backup; SA-006 is only partially addressed and SA-020 remains an accepted residual limitation.
8. Treat Tor/anonymity as a separate architecture milestone with external testing (SA-017).

No finding is marked complete in this register until its verification test is present and passing in the recorded full test run.
