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
- **Original weakness:** Channels were logical partitions inside one MLS group. `channel_id` was inside authenticated MLS plaintext, but all group members held the same MLS group secrets. P1d changes non-default text routing, P1e preserves ready derived groups, and P1f reports the boundary; parent policy metadata and the default channel remain on the parent group.
- **Attack scenario:** An excluded group member obtains a captured channel ciphertext and decrypts it with its MLS group keys; honest receivers merely suppress display.
- **Impact:** Restricted-channel plaintext disclosure. No cryptographic ACL boundary.
- **Reproducibility:** Static property proven; dynamic exploit requires feeding captured ciphertext to an excluded member.
- **Severity:** Medium.
- **Correction:** One independent MLS group per non-default channel with separate group ID, epoch, key schedule, membership, replay state, and membership-change commits. Parent `CHN1` policy and default traffic intentionally stay on the parent MLS group.
- **Verification test:** Inject an allowed-member ciphertext into an excluded member and assert MLS decryption fails, not merely that no message is displayed. The P1d controller tests also check that an allowed member's receipt is bound to the derived group, that the derived group rejects policy frames, and that non-default channel text placed in the parent group is rejected without a receipt.
- **Primitive and controller status:** `crates/groups/src/lib.rs` provides `channel_group_id(conversation_id, channel_id)` using domain `p2p.mls-channel-group/v1`. This is identifier derivation, not key derivation. `crates/groups/tests/channel_isolation.rs` proves domain separation, exclusion from captured ciphertext, and continued exclusion after a channel-group key update; the targeted run passed 3 tests. P1b adds `ChannelGroupBinding`, `ChannelKeyPackage`, `ChannelWelcome`, and `MlsChannelGroup` so KeyPackages, Welcomes, group creation, Add/Update/Remove, join, and message handling require an explicit parent/channel binding. `crates/groups/tests/channel_group_lifecycle.rs` passed 6 adversarial lifecycle tests covering wrong-parent/wrong-channel rejection, wrong-sender commit rejection, and parent ciphertext rejection. P1c adds signed channel setup frames with `ChannelScope` and `SetupEnvelope::verify_channel_scope()` plus a controller validation gate binding parent conversation, channel, transaction, and peer. P1d drives the bound KeyPackage/Welcome/Commit flow from `create_channel` and membership changes, routes non-default text and receipts through the derived group, and gates channel sends on welcome/commit convergence; the memory-only controller path passed 3 new adversarial tests and the full P1d gate.
- **Verification test (continued):** P1e restart tests prove authenticated channel-group restore without plaintext, bound receipt routing after restart, rejection of parent-group receipts on derived channels, fail-closed tamper/incomplete-setup/conflicting-label handling, and deletion on policy/member/local-conversation changes. P1f GUI tests prove that parent `CHN1` policy receipts, default parent-group text, derived readiness, and pending setup are reported separately without a complete-ACL claim.
- **Status:** Closed for the validated non-default controller text boundary. P1a–P1f pass locally: derived groups are bound, isolated, persist when ready, restore fail-closed, and are reported honestly in the GUI. Channel policy frames and default-channel traffic remain on the parent MLS group; setup material and decrypted text do not survive restart; no full application cryptographic ACL is claimed.

### SA-002 — Single Ed25519 identity reused across roles; `Identity` is `Clone`

- **Classification:** Confirmed (reuse and `Clone`); Partially confirmed (cross-protocol harm).
- **Files:** `crates/identity/src/lib.rs:65-71`, `crates/identity/src/lib.rs:140-155`, `crates/groups/src/lib.rs:98-126`, `crates/messaging/src/envelope.rs:134-139`, `crates/chat/src/setup.rs:289-303`, `crates/files/src/frame.rs:342-359`.
- **Weakness:** The same device key signs Noise transport identity, MLS credentials and commits, outer envelopes, setup frames, and file offers. `Identity` is cloned, duplicating private-key material.
- **Attack scenario:** Memory disclosure from any cloned owner exposes the single key. Cross-protocol signature confusion is theoretically possible but not demonstrated because signed encodings include domain magic/context.
- **Impact:** Increased compromise blast radius; no independent role containment.
- **Severity:** Medium.
- **Correction:** Independent root/device/transport/MLS/application keys with authenticated certificates and revocation/rotation; replace `Clone` with `Arc`; verify underlying zeroization support.
- **Verification test:** Assert distinct role keys, rejection of wrong-role signatures, invalid/expired/revoked certificate rejection, forged rotation rejection, and no secret in `Debug`.
- **Status:** Remediated at the primitive and wire layers by P2, with a residual boundary. `p2p-identity` now generates independent `Root`, `Device`, `Transport`, `Mls`, `Application`, and `File` Ed25519 keys; the root certifies the device and the device certifies the transport/MLS/application/file keys. Signed fixed-size certificates carry expiry and revocation bits; wire proofs carry only public certificates and signed rotation records. `Envelope` v2 and `SetupEnvelope` v3 sign with `Application`, `FileEnvelope` v2 with `File`, and MLS credentials use the independent `Mls` key. Adversarial tests reject wrong-role signatures, transport-signature reuse, tampered/substituted proofs, expired and revoked certificates, and forged/stale rotations; no private key appears in `Debug`. New vaults persist the complete encrypted bundle; legacy transport-only import binds fresh role keys. `Identity` is still `Clone` rather than `Arc`, and contact-root trust anchors are not wired into `ContactPayload` or the GUI, so no stronger real-world identity claim is made. This closes role-key reuse, not a complete application ACL.

### SA-003 — Setup frames lack transaction IDs and strict transaction binding

- **Classification:** Confirmed (original weakness; now remediated with residual limits recorded in SA-020).
- **Files:** `crates/chat/src/setup.rs:45-94`, `crates/chat/src/setup.rs:372-381`, `crates/chat/src/controller.rs:1880-1920`, `crates/chat/src/controller.rs:2019-2025`, `crates/chat/src/controller.rs:2104-2177`, `crates/storage/src/control_log.rs`, `crates/storage/src/lib.rs` (schema v4), `crates/storage/tests/vault.rs`, `apps/desktop/src/app.rs`.
- **Weakness:** Frames originally carried conversation ID only, so another peer could displace a pending KeyPackage and a stale ack could complete a later setup. v2 transaction binding closes those cases; exact authenticated frame replay still needed a durable boundary.
- **Attack scenario:** A malicious connected peer sends a signed request for a pending conversation, displacing the legitimate inviter's KeyPackage; a stale ack completes a later setup prematurely; an exact authenticated frame is replayed after restart.
- **Impact:** Setup denial of service and mis-binding risk; no plaintext disclosure shown.
- **Severity:** Medium.
- **Correction:** Signed transaction ID on every setup frame, state and ack binding by `(conversation_id, transaction_id, peer)`, a bounded in-memory exact-frame cache, and a durable chained digest log with a vault anchor.
- **Verification test:** Duplicate request with a different transaction cannot overwrite; stale ack rejected; tampered transaction ID fails signature; cross-transaction substitution rejected; exact terminal-frame replay after restart ignored; idempotent request retry after restart preserved; durable chain, blind indexes, and anchor verified on unlock.
- **Status:** Implemented in the 207-test workspace run and re-verified in the final 257-test workspace run. `MLS1` v2 adds signed 16-byte transaction IDs; pending state, acks, retries, and Welcomes are bound to `(conversation_id, transaction_id, peer)`, and v1 is rejected. A bounded 512-entry in-memory cache stores only `(PeerId, SHA-256 digest)` pairs. Schema v4 adds `control_log` (`sequence`, `record_bi`, `ciphertext`, `chain_hash`) and `control_state` (`id`, `sequence`, `chain`) with transactional migrations. `crates/storage/src/control_log.rs` records already authenticated signed frames as bounded XChaCha20-Poly1305 records (`Purpose::Db`) containing public PeerId bytes (at most 64), a SHA-256 frame digest, and a repeatable flag, with HMAC blind indexes (`Purpose::BlindIndex`) and a chained SHA-256 hash; the log is capped at 4096 entries and fails closed when full or malformed. `KeyPackageRequest` and `GroupJoinRequest` are repeatable; KeyPackage responses, Welcomes, `GroupWelcome`, `GroupCommit`, and all acks are non-repeatable. `MessengerController::start_with_control_log` accepts a cloned vault `Session` (the GUI passes `session.try_clone()`), and a vault/controller identity mismatch fails startup. `<vault>/control.anchor` holds AEAD-protected high-water-mark state (`sequence`, `chain`) with `<vault>/control.anchor.tmp` for atomic replace; `Vault::unlock` calls `verify_control_log`, which verifies every record, chain continuity, blind indexes, and the anchor. Storage has 15 tests including durable idempotence/replay, DB-only rollback detection, and anchor tamper; chat has two controller restart regressions. Phase 4 hardening also stores encrypted per-request outcomes so byte-identical group-commit and group-Welcome retries after restart receive the original ack without a second MLS transition; this is not a general replay cache for arbitrary frames. This is not OpenMLS persistence: digests are not a backup and do not restore group state, ratchets, channels, or decrypted messages. P3 adds channel-aware durable outcome keys (parent and channel acks are not interchangeable), version-2 acks with channel IDs and legacy version-1 read compatibility, durable outcomes for channel `Welcome`/`Commit`, and a fail-closed `ControlLogFull` result when the 4096-entry log is exhausted. This remains partial continuity, not a replay-proof guarantee.

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

### SA-005 — MLS group state was memory-only

- **Classification:** Confirmed (original state model; now partially remediated); Partially confirmed (security impact).
- **Files:** `crates/groups/src/lib.rs`, `crates/chat/src/controller.rs`, `crates/chat/src/lib.rs`, `crates/messaging/src/conversation.rs`, `crates/storage/src/mls_provider.rs`, `docs/DECISIONS/ADR-0014-encrypted-mls-state-persistence.md`.
- **Weakness:** OpenMLS state, key packages, pending commits, ratchet state, and replay state were originally memory-only.
- **Attack scenario:** Not an active attack; restart originally caused loss of decryption continuity and forced fresh setup.
- **Impact:** Availability/continuity loss, not plaintext leakage.
- **Severity:** Low–Medium.
- **Correction:** Use a supported OpenMLS storage provider with purpose-specific encrypted keys, transactional state, schema versioning, and epoch/replay binding.
- **Verification test:** Restart after add/remove/message and assert no inconsistent group/epoch/ratchet combination is restored.
- **Status:** Partially remediated by ADR-0014 Phase 4, its hardening pass, and P1e. With an attached vault session, joined group/ratchet state, ready derived channel groups, channel policy, bounded pending operations, receipt expectations, and queued ciphertext restore from authenticated encrypted records and fail startup closed on inconsistent state. Rejection of wrong-vault/controller and KeyPackage identities, per-class provider tamper/bounds/cross-profile coverage, interrupted anchor-first recovery, controlled-restart group flows, removed-peer receipt/queue pruning, encrypted durable outcomes for byte-identical group-commit/Welcome retries, and channel record tamper/incomplete-setup rejection are verified. Pending setup KeyPackage/Welcome material, decrypted messages, general replay-proof control frames, full-vault-plus-anchor rollback detection, and crash recovery for an anchor-first write remain open. The control-log digest log alone does **not** restore OpenMLS state. P4 adds a dedicated `Purpose::MlsState` HKDF key for new vaults with an explicit profile key-version migration (SA-021); legacy rows stay on the DB key rather than being bulk re-encrypted, and anchor writes authenticate MLS watermarks under the selected key. Pending setup material and decrypted messages still do not survive restart.

### SA-006 — Partial authenticated rollback protection for the encrypted vault

- **Classification:** Partially confirmed (residual absence by inspection).
- **Files:** `crates/storage/src/lib.rs` (schema v4), `crates/storage/src/control_log.rs`, `crates/storage/src/lib.rs:227-247`, `crates/storage/tests/vault.rs:616-665`.
- **Weakness:** AEAD tags remain valid when a complete older snapshot is restored. Schema v4's chained control log and `<vault>/control.anchor` now detect a database-only rollback or a tampered/missing anchor, but no state anchor exists outside the replaceable vault directory.
- **Attack scenario:** Attacker with filesystem write access restores an older `profile.db`, WAL, and SHM while leaving the current anchor in place, or tampers with the anchor; both are detected. Restoring the entire vault directory including the anchor is not detected locally.
- **Impact:** Partial rollback of message/attachment/control state; no plaintext exposure or tag forgery.
- **Severity:** Low–Medium.
- **Correction:** Keep the authenticated monotonic chain and add an integrity anchor outside replaceable files where feasible; reject stale state.
- **Verification test:** Restore an older database while keeping the current anchor and assert unlock fails; flip the anchor and assert unlock fails. A full-vault-plus-anchor restore has no local negative test and is recorded as a residual limitation (SA-020).
- **Status:** Partially addressed. The schema v4 chain plus `<vault>/control.anchor`, extended to authoritative MLS watermarks, detects database-only rollback and anchor tamper in the 207-test workspace run and is re-verified with bytewise/provider-class tamper coverage in the P14-era 339-test run and the final post-Q 358-test gate. Full-vault-including-anchor rollback remains open; no external anchor is claimed.

### SA-007 — Filesystem path hardening is Unix-only and final-path-only

- **Classification:** Confirmed (platform gap); Partially confirmed (local exploitability).
- **Files:** `crates/files/src/transfer.rs:859-913`, `crates/files/src/transfer.rs:945-958`, `crates/storage/src/lib.rs:610-635`.
- **Weakness:** `reject_symlink` is a no-op on non-Unix platforms and checks only the final quarantine path, not parent components. Windows reparse-point behavior was not verified.
- **Attack scenario:** A local attacker pre-places a symlink/junction in a parent directory and redirects ciphertext writes.
- **Impact:** Quarantine redirection or denial of service; no key/plaintext disclosure shown.
- **Severity:** Low–Medium.
- **Correction:** Verify every path component under a trusted root; use `O_NOFOLLOW`/openat-style admission; add Windows reparse-point checks.
- **Verification test:** Pre-place symlink/junction at base and intermediate path; assert fail-closed.
- **Status:** Partially addressed for file quarantine: generic ancestor-component and parent-traversal rejection is implemented in `crates/files/src/transfer.rs` with two new Unix tests; targeted runs, the 2026-11-25 207-test workspace run, and the final 257-test workspace run pass. Vault parent-path hardening and Windows reparse points remain open.

### SA-008 — File transfer cancellation is release-only; no transfer expiration

- **Classification:** Confirmed.
- **Files:** `crates/files/src/transfer.rs`, `crates/chat/src/controller.rs`, `crates/chat/src/lib.rs`, `apps/desktop/src/app.rs`.
- **Weakness:** `cancel_file` terminated release decisions but not the transfer; no TTL/deadline existed.
- **Attack scenario:** A peer stalls a transfer indefinitely.
- **Impact:** Resource use and misleading UX; no plaintext exposure.
- **Severity:** Low.
- **Correction:** Add transfer deadlines and distinguish cancel-release from abort-transfer.
- **Verification test:** Stall past TTL and assert abort and bounded state.
- **Status:** Implemented and verified. Active transfers now use a configurable inactivity deadline (default 5 minutes, maximum 1 hour) that is reset only by authenticated progress. `abort_file` stops new frames, drops pending response bookkeeping, zeroizes in-memory keys, and removes incomplete quarantine ciphertext; `cancel_file` is limited to completed integrity-verified transfers. Regression tests cover timeout, late-frame rejection, partial-quarantine cleanup, and starting a replacement transfer. The pinned libp2p request-response API cannot withdraw an already queued worker request, so a local abort ignores late responses rather than cancelling that worker state; the residual limitation is documented in `SECURITY_LIMITATIONS.md`. The P14-era 339-test run and final post-Q 358-test gate pass.

### SA-009 — Incorrect relay file-key visibility rationale

- **Classification:** Incorrect previous assessment.
- **Files:** `crates/network/src/lib.rs:1930-1933`, `docs/NETWORKING.md:36`, `docs/CRYPTOGRAPHY.md:87`, `docs/SECURITY.md:55-56`, `docs/DECISIONS/ADR-0012-m13-privacy-network-hardening.md:20`.
- **Weakness:** Earlier text claimed a relay would see the fresh file content key in the signed Offer.
- **Source evidence:** `libp2p-0.57.1/src/builder/phase/relay.rs:82-85` applies the same security upgrade to the relay transport; `libp2p-relay-0.22.0/src/copy_future.rs:22-25` and `:88-106` forward opaque substream bytes without interpreting the application protocol; `libp2p-noise-0.47.0/src/io/framed.rs:111-128` encrypts/decrypts only at endpoints.
- **Impact:** No cryptographic breach; a false rationale could drive unsafe future design decisions.
- **Correction:** State that relays see ciphertext, PeerIds, IPs, timing, and sizes only. Keep the conservative file-over-relay policy but describe it accurately.
- **Verification test:** Three-node loopback relay harness with sentinel bytes; assert relay does not observe decoded Offer/key and Noise tampering fails.
- **Status:** Rationale corrected in code and docs; targeted runs, the 2026-11-25 207-test workspace run, and the final 257-test workspace run pass. The external three-node relay capture harness remains pending.

### SA-010 — File-over-relay policy enforced only on outbound sends

- **Classification:** Confirmed.
- **Files:** `crates/network/src/lib.rs:1934-1943`, `crates/network/src/lib.rs:2383-2402`, `crates/chat/src/controller.rs:2260-2264`.
- **Weakness:** `Network::send_file` rejects relayed peers, but inbound file requests are emitted without checking relay status.
- **Attack scenario:** A relayed peer offers a file to a receiver with a joined conversation.
- **Impact:** Documented policy is not symmetric. Noise still protects the content key.
- **Severity:** Medium (policy honesty).
- **Correction:** Reject inbound file requests from observed relayed peers before creating response state.
- **Verification test:** Inject inbound file event for a relayed peer; assert no `RequestReceived` and a policy failure event.
- **Status:** Symmetric rejection is implemented through the shared `file_request_policy_response_id` production helper and `outbound_file_request_allowed`. Inbound tests assert no `RequestReceived` and one `Failed` event; P7 adds `outbound_file_requests_use_the_same_relay_policy_as_inbound`. A direct `handle_file_event` test is not feasible because libp2p's `ResponseChannel` constructor is private. File-over-relay remains disabled by policy; relays still forward only Noise/Yamux-protected bytes.

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
- **Weakness:** `NatEvent::StatusChanged` emits `confidence: 0`; the pinned libp2p 0.57.1 AutoNAT `StatusChanged` event exposes no confidence value.
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
- **Weakness:** No signed artifacts or provenance, no long coverage-guided fuzz campaign, and (previously) mutable GitHub Actions refs in workflows. Local tooling and non-advisory policy checks now run, the 2026-11-25 `cargo audit`/`cargo deny` CI gate and other workflows are green, but known unmaintained advisories remain as non-failing warnings.
- **Impact:** Dependency advisories and artifact identity are not automatically enforced.
- **Severity:** Medium for release assurance.
- **Correction:** Pin external GitHub Actions to commit SHAs, add dependency advisory/license/source gates, align the deny config and CI invocation with the installed cargo-deny version, fuzz smoke tests, deterministic SBOM generation and release inclusion, and document signing/key rotation.
- **Verification test:** CI runs locked audit/deny, fuzz smoke, and byte-identical SBOM regeneration on every PR; locally, workflow YAML is parsed, all `uses:` refs are inspected for 40-character SHAs, and all cargo-deny checks plus cargo-audit pass for both lockfiles. Security gates run `45690333396` passed all four jobs on 2026-11-25.
- **Status:** Partially addressed by `.github/workflows/security.yml`, `deny.toml`, a deterministic `P2P1` mutation/truncation smoke test, six real libFuzzer targets in `fuzz/`, `scripts/generate_sbom.py`, and SHA-pinned workflow actions. All 25 external action usages in `ci.yml`, `build.yml`, and `security.yml` are pinned to 40-character commit SHAs resolved from GitHub API refs on 2026-11-25; comments retain the source tag or branch, and the `dtolnay/rust-toolchain` pins freeze the `stable`/`nightly` branch heads. Earlier locally generated root and fuzz SPDX documents contained 479 packages each; after the Q SOCKS5 dependency and lock refresh, the final documents contain 480 packages each, regenerate byte-for-byte, and leak no absolute paths. Stable `cargo check`/`cargo clippy`, all workspace tests in the recorded runs (207 at the time; 339 in the P14 closeout; 358 in the final post-Q gate), and six local plain-libFuzzer 1000-input smoke passes completed without crashes, but the fuzz runs were not coverage-instrumented. Locally installed `cargo-audit 0.23.0` and `cargo-deny 0.22.1` now pass all checks for both lockfiles after moving to libp2p 0.57.1, request-response 0.30.0, OpenMLS 0.10.0-rc.1 with its patched RustCrypto stack, egui/eframe 0.35 to resolve the `js-sys` conflict, and removal of the unused direct `async-trait` dependency after the RPITIT codec migration. `cargo audit` still reports five non-failing unmaintained warnings. CI `45690333393` and Security gates `45690333396` both passed on 2026-11-25. A nightly coverage-guided campaign, signed artifacts, and build provenance remain absent; pinning does not prove the pinned action code is reviewed, signed, or trustworthy.

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
- **Files:** `crates/network/src/privacy.rs` (`TransportPrivacyMode`), `crates/network/src/lib.rs` (`validate_config`, `NetworkPrivacyStatus`), `apps/desktop/src/model.rs`.
- **Weakness:** No verified anonymity design exists. P5 initially provided only a fail-closed configuration boundary; the Q follow-up added a relay-only destination route, a SOCKS5-only outbound route, and coarse MLS plaintext padding, but none establishes Tor identity, hides timing/volume/outer frames, or resists global correlation.
- **Impact:** Direct peers and relays observe PeerIds, IP addresses, timing, and frame sizes; a SOCKS5 proxy operator observes destination and traffic metadata; global correlation remains possible.
- **Severity:** High relative to the requested anonymity objective; honest non-claim for current product scope.
- **Correction:** A dedicated anonymity design with code, integration, and external network testing is still required. Unsafe route combinations fail closed rather than falling back to direct connections.
- **Verification test:** `tor_required_fails_closed_without_direct_fallback` asserts that a missing proxy rejects `TorRequired` before worker start and that the default status remains explicit `Direct`. `socks5_route_requires_a_proxy_and_disables_direct_discovery` checks fail-closed validation; the fake-proxy test proves `example.onion` is handed to the proxy as a domain; Q1 tests reject direct relay-only dials and prove a real local relay circuit; Q2 padding tests reject malformed records. Real proxy/Tor verification, DNS/IPv6/relay packet capture, and two-machine tests remain external and are not claimed.
- **Status:** The absence of an anonymity architecture remains an accepted limitation. P5's boundary is implemented and Q5 adds a SOCKS5-only route with no direct listener/fallback; Q1 adds relay-only routing and Q2 adds coarse bucket padding. No verified Tor/I2P/mixnet, proxy identity, strong anonymity, metadata confidentiality, or unlinkability claim is made.

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
- **Status:** Implemented and verified in the 2026-11-25 207-test workspace run, re-verified in the P14-era 339-test run, and re-verified in the final post-Q 358-test gate. Per-protocol reservations are bounded by the aggregate configuration; this is DoS isolation for one authenticated peer, not a distributed-flood capacity guarantee. P13 adds a hostile-peer matrix proving that an oversized request on any protocol cannot bypass the aggregate byte ceiling.

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

### SA-021 — Dedicated MLS-state key purpose was deferred

- **Classification:** Partially confirmed (defense-in-depth gap, not an exploitable finding).
- **Files:** `crates/crypto/src/subkeys.rs`, `crates/storage/src/lib.rs` (schema v6), `crates/storage/src/mls_state.rs`, `crates/storage/src/control_log.rs`.
- **Weakness:** ADR-0014 Phase 1 encrypted MLS provider rows under the general `Purpose::Db` key. AEAD AAD already separated MLS records, but MLS state had no independent HKDF purpose.
- **Impact:** Larger blast radius if the DB subkey were exposed; no plaintext leakage or tag forgery shown.
- **Correction:** Add `Purpose::MlsState` with its own salt slot for new vaults, record an explicit `mls_key_version` in the profile, and keep legacy rows readable without a risky bulk re-encryption of chained and anchored records.
- **Verification test:** New-vault MLS ciphertext decrypts with the dedicated key and fails with the DB key; a legacy six-salt profile records version 0 and writes under the DB key; an unknown version fails unlock.
- **Status:** Implemented in P4. New vaults use a seven-salt profile with `mls_key_version = 1`; legacy profiles retain `mls_key_version = 0` and a stable derived replacement salt. Anchor writes authenticate MLS watermarks under the selected MLS key. This is key separation, not an external rollback anchor or recovery of pending setup material.

### SA-022 — Signed envelopes expose authorship evidence and clear metadata

- **Classification:** Confirmed by source and test; accepted as a bounded P10 non-claim.
- **Files:** `crates/messaging/src/envelope.rs`, `crates/identity/src/envelope.rs`, `crates/crypto/src/subkeys.rs`.
- **Weakness:** The outer `P2P1` signature binds conversation ID, epoch, sender PeerId, sequence, sender-supplied time, message kind, and ciphertext. Any recipient can verify authorship from the wire bytes before MLS decryption, and those metadata fields are visible to peers and relays.
- **Impact:** Signed frames are transferable evidence of authorship; traffic metadata is not confidential and cannot be claimed unlinkable.
- **Severity:** Informational for the current threat model; High relative to an unstated deniability objective.
- **Correction:** No deniability or metadata-confidentiality mechanism is implemented. The residual property is explicitly documented rather than described as privacy protection.
- **Verification test:** `signed_envelope_exposes_transferable_authorship_and_clear_metadata` parses a signed envelope as a third party, verifies the signature, and asserts that the metadata remains readable before decryption.
- **Status:** Recorded residual limitation. P10 is a bounded non-claim only; no deniability, padding, traffic-analysis resistance, metadata confidentiality, or unlinkability claim is made.

### SA-023 — Offline queue capacity was unbounded

- **Classification:** Confirmed and remediated with an explicit capacity error.
- **Files:** `crates/chat/src/lib.rs` (`MAX_OFFLINE_QUEUE`, `ChatError::OfflineQueueFull`), `crates/chat/src/controller.rs`, `crates/storage/src/lib.rs` (restored-queue validation).
- **Weakness:** A peer that stayed offline could accumulate an arbitrary number of signed ciphertext entries in memory, and a restored record could reintroduce an oversized queue.
- **Impact:** Local memory pressure; no plaintext exposure or remote amplification into mandatory infrastructure.
- **Severity:** Low–Medium.
- **Correction:** Cap the in-memory/offline queue at 16 entries, return `ChatError::OfflineQueueFull` before composing new ciphertext when the would-be offline recipients exceed the cap, and fail vault restore on an oversized queue record.
- **Verification test:** `offline_queue_rejects_a_full_queue_before_composing_ciphertext` fills the queue and asserts the explicit error without creating a new envelope; storage bounds cover restored records.
- **Status:** Implemented in P8. Queue entries remain ciphertext-only; no mailbox service or mandatory infrastructure exists.

### SA-024 — OpenMLS evaluation is classical-only

- **Classification:** Confirmed absence of post-quantum support; not an exploitable flaw.
- **Files:** `crates/groups/src/lib.rs` (`post_quantum_evaluation`), `crates/groups/Cargo.toml`, `Cargo.lock`.
- **Weakness:** The pinned OpenMLS `0.10.0-rc.1` build exposes only classical ciphersuites in this configuration; no hybrid KEM or signature construction exists.
- **Impact:** No quantum-resistance property can be claimed. No custom or weakened construction was introduced.
- **Severity:** Informational for current local scope; High relative to a future quantum-resistance objective.
- **Correction:** Keep the pinned dependency and record the exact ciphersuite evidence. Any future hybrid support requires a separate dependency/design review.
- **Verification test:** `pinned_openmls_advertises_only_classical_ciphersuites` asserts the pinned version and rejects any non-classical suite visible in this build.
- **Status:** Bounded P9 evaluation only. No post-quantum, hybrid, custom-construction, or production-stability claim is made.

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
- **Status:** Corrected in the original 207-test workspace run and re-verified in later local gates, with regressions for both path redaction and non-reflected unknown fields; the historical CI diagnostic guard result is not evidence for this uncommitted workstream.

## 3. Remediation priority

1. Done: setup transaction binding, a bounded memory-only `(PeerId, SHA-256 digest)` replay cache, and schema v4 durable chained, blind-indexed digest continuity with an AEAD vault anchor (SA-003). Rollback detection remains partial (SA-006), full-vault-including-anchor rollback is an accepted residual limitation (SA-020), and encrypted MLS persistence is partially implemented with hardening bounds (SA-005).
2. Done: symmetric relay policy, accurate relay rationale, direct dial validation, rate-limiter cleanup, honest status fields, explicit global and per-IP pre-authentication socket caps, per-protocol request isolation, repository-wide diagnostic redaction review, and automated CI diagnostic guard (SA-009–SA-014, SA-018, SA-019, PC-004).
3. Partial: supply-chain workflow/config, SHA-pinned external actions, deterministic smoke test, six libFuzzer targets, a CI fuzz-smoke job, deterministic locked SBOM generation/release inclusion, locally passing audit/deny gates, and green 2026-11-25 CI added (SA-015); unmaintained-crate warnings, OpenMLS RC dependence, a coverage-guided campaign, signed artifacts, and provenance remain.
4. Done: transfer inactivity deadlines, separate abort from release cancellation, and partial-quarantine cleanup (SA-008).
5. Remediated with residual boundary: separate MLS groups per non-default channel (SA-001). P1a–P1f pass locally at the primitive, controller, persistence, and GUI-status layers; parent policy/default traffic and a complete application ACL remain outside the claim.
6. Done at the primitive/wire layers (P2): independent root/device/transport/MLS/application/file keys with signed certificates, expiry, local revocation, rotation, and role-specific wire signatures (SA-002). Contact-root trust anchors are not wired into the GUI, so no stronger human-identity claim is made.
7. Partially implemented: encrypted MLS persistence with a rollback-aware schema and bounded restore/hardening tests (SA-005), plus a dedicated MLS-state key for new vaults (SA-021). Pending setup KeyPackage/Welcome material, decrypted messages, general replay-proof control frames, and anchor-first crash recovery remain open. The control digest log is not MLS state or a backup; SA-006 is only partially addressed and SA-020 remains an accepted residual limitation.
8. P5 added a fail-closed configuration boundary: `TorRequired` without a proxy is rejected before worker start (SA-017). The Q follow-up implements a SOCKS5-only route, relay-only routing, and coarse MLS padding, but a real anonymity architecture still requires external network testing; no verified Tor/proxy identity, I2P/mixnet, metadata-confidentiality, or unlinkability claim is made.
9. Done (P6/P7/P8): local device-signed role-delegation primitives, symmetric file-over-relay refusal with native OS file picking, and a bounded ciphertext-only offline queue (SA-002 extension, SA-008–SA-011, SA-023). Delegations are not wired into a directory or GUI trust anchor; relayed file transfer remains disabled.
10. Bounded non-claims recorded (P9/P10): classical-only OpenMLS evaluation and transferable signed-envelope authorship with visible metadata (SA-024, SA-022). No post-quantum, deniability, metadata-confidentiality, or unlinkability claim is made.
11. Done with local evidence only (P11–P14): portable encrypted identity bundles, local supply-chain gates and deterministic SBOMs, hostile-peer matrix tests, and final workspace/GUI gate counts. No multi-device convergence, signed release identity, reproducible build, long fuzz campaign, CI, release, commit, push, PR, review, merge, or production-readiness claim is made.

No finding is marked complete in this register until its verification test is present and passing in the recorded full test run.
