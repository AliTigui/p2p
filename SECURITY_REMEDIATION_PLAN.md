# Security Remediation Plan

This is a source-backed engineering plan for the security workstream that follows ADR-0014 Phase 4. It is **not** a new numbered product milestone, not an external audit, and not a claim that the planned properties are implemented. The authoritative finding register is `SECURITY_AUDIT.md`; implemented behavior is recorded in `PROJECT_STATUS.md`; explicit non-claims are in `SECURITY_LIMITATIONS.md`.

## 1. Evidence rules

A finding is only called fixed when all of the following hold:

1. The relevant source path and dependency edge are identified.
2. The intended property is implemented in code, not only in documentation.
3. An adversarial test demonstrates that the old bypass no longer works.
4. The full local gate passes with the new test count recorded.
5. A doc row explicitly separates “primitive exists” from “application uses it”.

No external platform check, user/manual check, CI run, or third-party service result is treated as a local completion claim.

## 2. Current architecture map

```text
apps/desktop (egui/eframe)
    |
    v
MessengerController (p2p-chat)
    |-- ConversationState / CHN1 channel policy
    |-- MlsConversation per conversation (p2p-groups -> OpenMLS)
    |-- signed P2P1 envelopes / receipts (p2p-messaging)
    |-- setup and group-control frames (p2p-chat/setup.rs)
    |-- file lifecycle (p2p-files -> p2p-security)
    |-- device identity (p2p-identity)
    |-- transport worker (p2p-network -> libp2p 0.57.1)
    v
Encrypted vault (p2p-storage -> SQLite + XChaCha20-Poly1305)
```

Current security facts relevant to this plan:

- Every conversation, including 1:1, has one parent MLS group. `CHN1` policy frames stay in that group, and the default channel uses it. Non-default channel text and receipts use a bound derived `MlsChannelGroup`; its readiness is separate from parent policy acknowledgement and is not a complete channel ACL.
- Setup and group-control frames use signed v2 `MLS1` frames with transaction IDs. They have a bounded in-memory replay cache and a schema-v4 durable digest log with a vault-local anchor. This is partial continuity, not a replay-proof log.
- Joined MLS groups, ready derived channel groups, application policy, bounded pending operations, receipt expectations, and queued ciphertext restore from authenticated encrypted records when a vault `Session` is attached. Decrypted messages do not restore.
- P2 uses independently generated `Root`, `Device`, `Transport`, `Mls`, `Application`, and `File` keys with signed certificates, expiry, local revocation, and rotation. Role separation is at the primitive and wire layers; contact-root trust anchors are not wired into the GUI.
- Direct connect requires no bootstrap or relay. Optional discovery/relay capabilities are off and empty by default. Relay forwards Noise-protected bytes and is not treated as an application-key reader; P7 applies the same refusal to outbound and inbound file requests on observed relayed paths.
- There is no anonymity route and no real configured scanner or external rollback anchor. `TransportPrivacyMode::TorRequired` is configuration-only and rejected by `validate_config`; `Direct` is explicitly non-anonymous. No production-readiness claim is made.

Dependency change made by this workstream: `p2p-groups` now has an internal Cargo edge to the already workspace-pinned `sha2` crate. No new external dependency, GUI backend, or mandatory infrastructure is introduced; P1c extends the existing signed `MLS1` setup schema with channel-scope frame codes 11–16 while preserving legacy v2 parent/group frames.

## 3. Phase 0 — source-backed finding register

The register is maintained in `SECURITY_AUDIT.md`. Its highest-priority unresolved items are:

| Finding | Classification | Current state |
|---|---|---|
| SA-001 restricted channels are logical only | Confirmed boundary, remediated for non-default text | Non-default controller text is isolated in bound derived MLS groups, survives restart, and is reported separately from parent policy in the GUI; no complete ACL is claimed. |
| SA-002 single reused Ed25519 identity | Confirmed reuse | Remediated at primitive/wire layers by independent role keys and certificates; contact-root GUI trust anchors remain unwired. |
| SA-003 / SA-020 setup replay and rollback | Partially remediated | v2 transaction binding, digest log, and vault anchor exist; full-vault-plus-anchor rollback and general replay-proof status do not. |
| SA-005 / SA-006 MLS state and rollback | Partially remediated | Joined groups and ready channel groups restore; setup KeyPackages/Welcomes, decrypted messages, external anchor, and crash recovery remain. |
| SA-017 anonymity | Confirmed absence | No Tor/I2P/mixnet route or external test. `TorRequired` is rejected before worker start, with no direct fallback. |
| SA-015 supply chain | Partial | SHA pins, audit/deny, fuzz smoke, and SBOM exist; signing, provenance, and long fuzz campaign do not. |

Phase 0 deliverables are the finding register, this plan, the current/limitation docs, and targeted adversarial tests. Phase 0 does not close SA-001.

## 4. P1 — cryptographic channel isolation

### 4.1 Target architecture

The parent conversation remains the MLS group for membership, admin control, and bounded channel metadata. Each non-default channel also gets an independent MLS group:

```text
parent conversation group id P
    |-- admin, member set, channel registry, CHN1 policy
    |
    +-- channel C group id = channel_group_id(P, C)
            |-- independent epoch, key schedule, ratchet, replay state
            |-- its own membership equal to the allowed channel members
            |-- its own Welcome / Add / Remove / Update commits
```

`channel_group_id(conversation_id, channel_id)` is a domain-separated **identifier derivation**, not key derivation. It is implemented in `crates/groups/src/lib.rs` and proven by `crates/groups/tests/channel_isolation.rs`. The primitive proves that an excluded member cannot decrypt channel ciphertext even with the parent group keys, a captured envelope, and a locally created group with the same public group ID. `MlsChannelGroup`, `ChannelGroupBinding`, `ChannelKeyPackage`, and `ChannelWelcome` now carry that binding through the group-layer lifecycle API and are proven by `crates/groups/tests/channel_group_lifecycle.rs`. P1c adds signed channel setup frame variants and a controller validation gate that binds `(parent conversation, channel id, transaction, peer)`. P1d now drives those wrappers from the shipped controller: `CHN1` policy frames and default-channel traffic stay in the parent MLS group, while non-default channel text and its receipts use the derived `MlsChannelGroup` after bound setup converges. P1e adds authenticated encrypted records for ready channel groups and fail-closed restart validation; P1f reports parent `CHN1` policy/default traffic separately from derived-group readiness and explicitly avoids a complete-ACL claim.

### 4.2 Required migration slices

| Slice | Scope | Exit evidence | State |
|---|---|---|---|
| P1a | Derive independent channel group IDs and prove OpenMLS exclusion | 3 passing adversarial tests including wrong-role substitution and post-update exclusion | Complete |
| P1b | Add a channel-group lifecycle API with explicit parent/channel binding and bounded validation | 6 passing lifecycle tests: explicit binding derivation, wrong-parent/wrong-channel KeyPackage and Welcome rejection, Add/Update/Remove commits, wrong-sender commit rejection, and parent ciphertext rejection | Complete; controller/GUI migration delivered in later slices |
| P1c | Extend signed setup frames so every channel operation binds `(parent conversation, channel id, transaction, peer)` | Setup parser tests for unknown/missing/truncated/tampered/cross-channel frames; controller tests for excluded-member rejection | Complete; shipped application routing delivered in P1d |
| P1d | Route channel envelopes and receipts through the channel group; keep default channel on the existing parent group for compatibility | OpenMLS-layer rejection test plus controller tests where an excluded member cannot decrypt injected ciphertext, an allowed member's receipt is bound to the derived group, and non-default text on the parent group is rejected | Complete; persistence and GUI status delivered in P1e/P1f |
| P1e | Persist channel groups under authenticated labels and restore them with parent/channel/epoch/membership binding | Restart tests for queued ciphertext, bound receipts, lifecycle deletion, tampered metadata, incomplete setup, and conflicting labels | Complete locally; 9 new adversarial controller tests pass |
| P1f | Update GUI status only after the controller migration is complete | GUI tests for default parent-group status, derived readiness, derived setup state, and absence of a complete-ACL claim | Complete locally; 3 new GUI model tests pass |

### 4.3 Migration risks

- **Legacy channel records.** Existing vaults have channel metadata but no channel MLS groups. Migration must not silently present old channels as cryptographically isolated.
- **Default channel compatibility.** Keeping the default channel on the parent group avoids breaking existing 1:1 setup, but it must remain labelled as parent-group confidentiality, not a new ACL boundary.
- **Setup ambiguity.** Reusing the existing `conversation_id` field with a derived group ID requires an explicit reverse binding to the parent and channel. Without that binding, a peer could claim an arbitrary derived group. Slice P1c must bind all three values in signed bytes.
- **Receipt and offline routing.** Channel envelopes will carry the derived group ID. `message_conversations`, `pending_receipts`, `outstanding_messages`, and the offline queue must resolve back to the parent conversation and channel before display or delivery state changes.
- **Membership changes.** Channel membership changes must become MLS commits in the channel group. Application-only `SetMembers` must not be accepted as cryptographic removal.
- **Metadata leakage.** Channel creation/rename/member metadata currently reaches all parent members. P1 does not promise metadata confidentiality; the limitation stays until a separate design exists.
- **Storage caps.** The vault permits at most 64 MLS groups and 16 channels per conversation. Per-channel groups consume that budget; restore and anchor maps must fail closed at the cap.
- **Replay state.** Setup replay keys and durable group-ack outcomes must include the channel group context so a parent commit cannot acknowledge a channel commit or vice versa.
- **Crash consistency.** Parent policy and channel group state must be committed in one authenticated transaction where possible. Partial states must fail closed on restart rather than display an unverified ACL.

P1a–P1f have all passed locally. SA-001 is closed only for the validated non-default-text boundary; parent policy/default traffic remains a documented residual boundary, not a complete application ACL.

## 5. P2 — identity separation

Target: distinct root, transport, MLS signing, envelope/setup, and file keys with authenticated binding, expiry, revocation, and rotation. `Identity` should be shared through `Arc` or another non-copying owner model; debug output and zeroization behavior must be verified per role.

Migration risks: peer IDs are currently derived from the transport key; MLS credentials bind the same public key; contact URIs and fingerprints assume one identity. A compatibility layer or explicit account migration is required. Exit evidence: wrong-role signature rejection, expired/revoked certificate rejection, forged-rotation rejection, and no secret in `Debug`.

## 6. P3 — replay and setup hardening

Current controls: signed v2 transaction IDs, strict `(conversation_id, transaction_id, peer)` binding, bounded memory cache, durable chained digest log, vault anchor, and durable exact-retry acks.

Remaining work: bind setup replay keys to channel/group context introduced in P1, define fail-closed behavior for full logs, add an optional external anchor or explicitly retain the no-external-anchor limitation, and prove that database-only rollback, anchor tamper, and cross-context substitution are rejected after restart. General replay-proof status is not claimed.

## 7. P4 — persistence and recovery

Current controls: schema v5 encrypted opaque MLS state, staged provider, per-group chains, anchor watermarks, and controller restore of joined conversations.

Remaining work: dedicated MLS-state HKDF purpose with a migration plan, authenticated restore of pending setup material, crash-consistent anchor-first writes, and a documented recovery boundary for decrypted messages. P1e now covers ready channel-group restore, including restart after channel lifecycle changes, tampered metadata, incomplete setup, and plaintext-absence checks.

## 8. P5 — anonymity

`TransportPrivacyMode::{Direct, TorRequired}` began as explicit configuration only: `Direct` remains the default and is labelled non-anonymous, and a missing proxy now rejects `TorRequired` before worker start. The post-P14 Q5 follow-up implemented `TorRequired` as a SOCKS5-only outbound transport: no direct listener or fallback, hostname proxy addresses rejected, `/dns4`/`/dns6` domains forwarded to the proxy, and mDNS/AutoNAT/DCUtR disallowed with the route. `NetworkPrivacyStatus::transport_mode` and the GUI status report requested configuration, not an observed anonymity property. Q1 relay-only routing and Q2 MLS padding are separate privacy improvements. No verified Tor/proxy identity, onion/I2P/mixnet route, DNS/IPv6 leak proof, timing defense, metadata-confidentiality claim, or unlinkability claim is made. The finding remains an honesty/fail-closed route boundary rather than an anonymity implementation.

## 9. Complete 15-phase sequence

The authoritative workstream is **Phase 0 through Phase 14** (fifteen phases). The earlier draft of this plan listed only seven items after P1–P5 and omitted a deniability/metadata phase from its closing summary (§19 of the original master prompt). That omission is recorded here rather than silently dropped: Phase 10 is now explicit and remains a bounded non-claim phase until separate evidence exists. The short names `P0`–`P14` below are the canonical identifiers used in status, architecture, and test records.

| Phase | Name | Finding(s) | Exit evidence | Claim boundary |
|---|---|---|---|---|
| P0 | Source-backed reassessment and finding register | all | `SECURITY_AUDIT.md`, this plan, architecture/limitation docs, targeted tests | No finding is closed by documentation alone. |
| P1 | Cryptographic channel isolation (P1a–P1f) | SA-001 | Group-layer exclusion, controller routing, persistence, and GUI-status adversarial tests | Parent policy/default traffic stay on the parent MLS group; no complete ACL claim. |
| P2 | Identity separation | SA-002 | Wrong-role/expired/revoked/forged-rotation rejection; no secret in `Debug`; certified role keys | Contact-root trust anchors are not wired into the GUI; no stronger real-world identity claim. |
| P3 | Replay and setup hardening | SA-003, SA-004 | Durable exact-retry acks, channel-bound outcome keys, control-log fail-closed proof | Not replay-proof; full-vault-plus-anchor rollback remains undetected. |
| P4 | Persistence and recovery | SA-005, SA-006, SA-020 | Dedicated MLS HKDF purpose, legacy key-version migration, anchor-first crash tests | Pending setup material and decrypted messages do not survive restart; no external anchor. |
| P5 | Anonymity / fail-closed transport mode | SA-017 | `TorRequired` rejected before worker start; explicit non-anonymous `Direct` default and honest status row | Config-only mode; no Tor/I2P/mixnet route, direct fallback, strong anonymity, unlinkability, or metadata confidentiality claim. |
| P6 | Administration | SA-002 extension | Delegated role conflict tests; rotation/revocation remain local primitives | No directory/enterprise policy engine or complete ACL claim. |
| P7 | Files | SA-008–SA-011, SA-014 | Relay-policy symmetry, bounded frames, key isolation, natural Session-like send UX | File-over-relay stays disabled; no transfer-after-restart claim. |
| P8 | Offline | SA-004 extension | Ciphertext-only queue bounds, explicit reconnect delivery tests | No mailbox service, mandatory infrastructure, or offline identity resolution claim. |
| P9 | Post-quantum | SA-021 | Pinned OpenMLS capability evaluation with version evidence | No custom hybrid construction or quantum-resistance claim without pinned support. |
| P10 | Deniability and metadata resistance | omitted in §19 draft | Explicit residual-register entries and adversarial tests showing what signatures/traffic expose | No deniability, metadata confidentiality, or unlinkability claim. |
| P11 | Multi-device | SA-002 extension | Portable bundle/rotation tests; independent device keys | No shared secret by default; no seamless multi-device convergence claim. |
| P12 | Supply chain | SA-015 | Existing SHA pins, audit/deny, fuzz smoke, SBOM; signed/provenance/reproducible work remains external | No release signing, provenance, reproducible-build, or long-fuzz-campaign claim. |
| P13 | Adversarial and performance | SA-018, SA-019, PC-004 | Hostile-peer matrix, resource accounting, bounded-capacity tests | No unbounded resource or hostile-network claim. |
| P14 | Final verification and limitation consolidation | all | Full local gates with exact counts; docs reconciled | No CI, release, commit, push, PR, review, merge, or production-readiness claim. |

Each phase follows the same evidence rule as Section 1. A phase is reported complete locally only when its exit evidence passes and its claim boundary is honored. Phases whose exit evidence requires external/manual work remain explicitly open rather than being closed by documentation.

## 10. Current workstream state

| Item | Current state |
|---|---|
| Phase 0 register | Source-backed findings collected in `SECURITY_AUDIT.md`. |
| P1a | Implemented and targeted tests pass. |
| P1b | Group-layer lifecycle API implemented; 6 targeted tests pass. The bound API is now driven by the shipped controller for non-default channel text. |
| P1c | Signed channel-scope setup variants and controller validation gate implemented; 4 new targeted tests pass. Every channel setup frame carries the signed scope. |
| P1d | Implemented: policy frames stay on the parent group, non-default text/receipts use the derived group, readiness gates sends, and membership changes recreate or drop channel groups. Three new controller adversarial tests pass. |
| P1e | Implemented: ready channel groups are stored under `p2p.app.channel-group/v1`, partition from parent records, restore with parent/channel/epoch/membership/pending-state checks, and are deleted with policy changes, parent-member removal, and local conversation removal. Nine new adversarial controller tests pass. |
| P1f | Implemented: the GUI exposes separate parent `CHN1` policy-receipt and derived-group readiness states. Default traffic is labelled as parent-group confidentiality; ready non-default traffic is labelled as a derived-group boundary; setup is labelled as blocked pending acknowledgements. Three new GUI model tests pass and no complete-ACL claim is made. |
| P2 | Implemented: independent root/device/transport/MLS/application/file keys; signed certificates, proofs, expiry, revocation, and rotation; wire versions `Envelope` v2, `SetupEnvelope` v3, `FileEnvelope` v2; wrong-role, tampered/substituted proof, expired/revoked, and transport-signature reuse rejection. Complete encrypted identity bundles in new vaults with explicit legacy transport-only import. Contact-root trust anchors remain unwired in the GUI. |
| P3 | Implemented: channel-aware durable outcome keys, v2 group acks with channel IDs and legacy v1 read compatibility, channel welcome/commit durable acks, and fail-closed control log at its 4096-entry cap. Not replay-proof; no external anchor. |
| P4 | Implemented: dedicated `Purpose::MlsState` HKDF key for new vaults with profile `mls_key_version` migration; legacy six-salt profiles stay readable under the DB key; unknown versions fail closed. Anchor writes now authenticate MLS watermarks under the selected MLS key. Pending setup material and decrypted messages still do not survive restart. |
| P5 | Implemented as a fail-closed configuration boundary: `TransportPrivacyMode::TorRequired` is rejected by `validate_config` and `Network::start`; the GUI shows `Direct TCP + Noise (not anonymous)` and never offers the unsupported mode. No anonymity route is claimed. |
| P6 | Implemented `RoleDelegation` and `resolve_delegated_grant` as local device-signed primitives with expiry, wrong-role rejection, caller-supplied keys, counter conflicts, newer-counter supersession, and redacted `Debug`. No directory, enterprise engine, or GUI trust-anchor wiring exists. |
| P7 | File UX now uses the native OS picker beside `Send`; no typed path form remains in the normal flow. Feature-only builds report the missing picker honestly. File-over-relay refusal is symmetric for inbound requests and outbound sends, with relay bytes still Noise/Yamux-protected. Relayed file transfer remains disabled. |
| P8 | The in-memory/offline queue is ciphertext-only and capped at 16 entries. `ChatError::OfflineQueueFull` is returned before composing ciphertext when the would-be offline recipients would exceed the cap; restored records also reject oversized queues. No mailbox service or mandatory infrastructure exists. |
| P9 | A locked OpenMLS `0.10.0-rc.1` capability test verifies the pinned version and accepts only classical ciphersuites in this build. No post-quantum/hybrid support, custom construction, or quantum-resistance claim is made. |
| P10 | A signed-envelope test records that wire bytes give third parties transferable authorship evidence and expose conversation, epoch, sender, sequence, time, and kind before decryption. No deniability, metadata confidentiality, or unlinkability claim is made. |
| P11 | An integration test proves two installations generate independent device keys while a portable encrypted export restores every role key exactly. No shared secret by default and no seamless multi-device convergence claim exists. |
| P12 | Local SHA-pinned workflow refs, `cargo audit`/`cargo deny` for both lockfiles, locked fuzz check/build/clippy, six 1000-input plain-libFuzzer smoke runs, and byte-identical deterministic SBOM regeneration were re-recorded. No signed release identity, provenance, reproducible-build, long fuzz campaign, or external CI/release claim is made. |
| P13 | A hostile-peer matrix test sends an oversized request on every request protocol and asserts denial without reserving aggregate or per-protocol accounting state. This is a bounded local resource test, not a distributed-flood guarantee. |
| P14 | P14-era local gates passed with exact counts: 339 workspace tests, 20 GUI-feature tests, zero doc-tests, check/clippy/build, diagnostics, fuzz smoke, audit/deny, and deterministic SBOM. Those counts are historical; the final post-Q gate is 358 workspace tests and 22 GUI-feature tests. CI, release, commit, push, PR, review, merge, and production readiness remain outside the claim. |
| Q0–Q5 | Post-P14 privacy follow-up, not a numbered milestone: Q0 comparison/non-claim, Q1 relay-only route, Q2 fixed-bucket MLS padding, and Q5 SOCKS5-only route are complete locally; Q3 clear metadata and Q4 ephemeral delegated keys remain design-only. Final gate: 358 workspace tests, 22 GUI-feature tests, 64 diagnosed Rust sources, and 480-package SBOMs. |
| Commit/push/PR/review/merge | Not authorized; changes remain local. |

P1a–P4 are complete locally with the claim boundaries recorded above. SA-001 is closed only for non-default controller text; parent policy/default traffic and a complete application ACL remain explicitly outside that claim. P2 closes the primitive-level role-separation finding but does not authenticate contact-root trust anchors in the GUI. P3 is not replay-proof and P4 has no external anchor.

## 11. Verification record for this workstream

Commands run locally after the P1a through P1f changes:

```bash
cargo +1.100.0 fmt --all -- --check
git diff --check
python3 scripts/check_diagnostics.py
cargo +1.100.0 test -p p2p-chat --lib --locked
cargo +1.100.0 test -p p2p-groups --test channel_isolation --locked
cargo +1.100.0 test -p p2p-groups --test channel_group_lifecycle --locked
cargo +1.100.0 check --locked --workspace --all-targets
cargo +1.100.0 test --locked --workspace -- --test-threads=1
cargo +1.100.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.100.0 test --locked -p p2p-desktop --features gui -- --test-threads=1
cargo +1.100.0 check --locked -p p2p-desktop --features gui
cargo +1.100.0 clippy --locked -p p2p-desktop --features gui --all-targets -- -D warnings
cargo +1.100.0 check --locked -p p2p-desktop --features native
cargo +1.100.0 clippy --locked -p p2p-desktop --features native --all-targets -- -D warnings
cargo +1.100.0 build --locked -p p2p-desktop --features native
```

The P1a–P1f commands passed with 56 diagnosed Rust sources and 285 workspace tests; those counts are retained as historical P1 evidence. After P2–P13, the P14-era 2026-11-27 serialized workspace run passed **339 tests with 0 failures**: chat 86 (66 unit + 20 integration), core 4, crypto 8, desktop 17, files 20, groups 19 (1 unit + 6 lifecycle + 3 isolation + 9 MLS integration), identity 61 (58 unit + 3 integration), messaging 20 (17 unit + 3 integration), network 44 (33 unit + 11 integration), security 11, storage 49 (12 unit + 28 vault + 9 provider integration); workspace doc-tests were 0. The `gui`-feature desktop run passed **20 tests, 0 failures**; `cargo audit`/`cargo deny` passed for both lockfiles; both SPDX documents regenerated byte-for-byte with 479 packages each; and the diagnostic guard checked 62 Rust sources. That result is historical. After Q1/Q2/Q5, the final serialized workspace run passed **358 tests with 0 failures** across 37 suites: chat 86 (66 unit + 20 integration), core 4, crypto 8, desktop 19, files 20, groups 22 (4 unit + 6 lifecycle + 3 isolation + 9 MLS integration), identity 61 (58 unit + 3 integration), messaging 20 (17 unit + 3 integration), network 58 (46 unit + 12 integration), security 11, storage 49 (12 unit + 28 vault + 9 provider integration); workspace doc-tests were 0. The `gui`-feature desktop run passed **22 tests, 0 failures**. `cargo audit` and `cargo deny` passed for both lockfiles (audit reports non-failing unmaintained warnings); locked fuzz check/clippy/release build and six plain-libFuzzer 1000-input smoke runs passed; both SPDX documents regenerated byte-for-byte with 480 packages each. The diagnostic guard checked 64 Rust sources. Two pre-existing manifest warnings (`p2p-core` in `p2p-crypto`, `zeroize` in `p2p-security`) remain advisory and were not changed by this workstream. These are local results only; no CI, release, commit, push, PR, review, merge, or production-readiness claim is made for this workstream.
