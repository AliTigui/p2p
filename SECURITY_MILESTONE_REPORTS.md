# Security Milestone Reports (P0–P14)

This file contains the required per-phase reports for the local security-hardening workstream that follows ADR-0014 Phase 4. Every report is local-only: no CI, release, commit, push, PR, review, merge, user/manual, external, two-machine, visual-GUI, or production-readiness claim is made. Historical CI/release results are kept only as historical records and are not evidence for this uncommitted workstream.

The authoritative plan is `SECURITY_REMEDIATION_PLAN.md`; the finding register is `SECURITY_AUDIT.md`; non-claims are in `SECURITY_LIMITATIONS.md`; exact gate commands and results are in `SECURITY_TESTS.md` and `tests/README.md`.

## Progress table

| Phase | Short name | Local status | Exit evidence | Claim boundary |
|---|---|---|---|---|
| P0 | Source-backed reassessment | Complete locally | Finding register, plan, architecture/limitation docs, preserved adversarial tests | Documentation alone never closes a finding. |
| P1 | Cryptographic channel isolation (P1a–P1f) | Complete locally | Group exclusion, bound lifecycle, signed channel scope, controller routing, authenticated restore, honest GUI status | Parent policy/default traffic remain on the parent MLS group; no complete ACL claim. |
| P2 | Identity separation | Complete locally | Independent role keys, certificates/proofs, expiry/revocation/rotation, role-specific wire signatures and legacy rejection | Contact-root trust anchors are not wired into the GUI. |
| P3 | Replay/setup hardening | Complete locally | Channel-aware durable acks, v1-record compatibility, fail-closed full control log | Not replay-proof; no external anchor; full-vault-plus-anchor rollback remains undetected. |
| P4 | Persistence and recovery | Complete locally | Dedicated MLS HKDF purpose, legacy migration, unknown-version rejection, anchor-first crash tests | Setup material and decrypted messages do not survive restart; no external anchor or crash-recovery guarantee. |
| P5 | Anonymity / fail-closed transport mode | Complete locally as a non-anonymity boundary | `TorRequired` fail-closed config boundary, `Direct` labelled non-anonymous; Q5 later added SOCKS5-only transport with no direct fallback/listener | No verified Tor/proxy identity, DNS/IPv6 leak proof, metadata confidentiality, or unlinkability. |
| P6 | Administration | Complete locally | Device-signed delegation primitives with conflict/expiry/wrong-role rejection and redacted `Debug` | No directory, enterprise policy engine, GUI trust anchor, or complete ACL. |
| P7 | Files | Complete locally | Native picker copy, symmetric relay refusal, bounded signed file frames | File-over-relay stays disabled; no OS-dialog visual check or transfer-after-restart claim. |
| P8 | Offline | Complete locally | Ciphertext queue capped at 16, pre-compose full error, restored-record rejection | No mailbox service, mandatory infrastructure, or offline identity resolution. |
| P9 | Post-quantum | Complete locally as a bounded evaluation | Pinned OpenMLS version/classical-suite test | No post-quantum, hybrid, custom construction, or production-stability claim. |
| P10 | Deniability and metadata resistance | Complete locally as a bounded non-claim | Signed-envelope authorship/metadata test and residual findings | No deniability, metadata confidentiality, traffic-analysis resistance, or unlinkability; Q2 later added coarse bucket padding only. |
| P11 | Multi-device | Complete locally | Independent device keys plus portable encrypted bundle restore | No shared secret by default and no seamless multi-device convergence. |
| P12 | Supply chain | Complete locally | Local audit/deny, fuzz build/smoke, deterministic SBOM regeneration | No signed release identity, provenance, reproducible-build, long fuzz campaign, CI, or release claim. |
| P13 | Adversarial and performance | Complete locally | Hostile-peer matrix and bounded resource-accounting tests | No distributed-flood, OS-exhaustion, or hostile-network capacity guarantee. |
| P14 | Final verification and limitation consolidation | Complete locally | Final workspace/GUI gates, diagnostic guard, docs reconciled | No production readiness; all changes remain uncommitted. |

Final recorded local aggregate after P0–P14 plus the Q privacy follow-up: `cargo +1.100.0 test --workspace --locked -- --test-threads=1` passed **358 tests, 0 failures** across 37 suites (chat 86, core 4, crypto 8, desktop 19, files 20, groups 22, identity 61, messaging 20, network 58, security 11, storage 49; doc-tests 0). `cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1` passed **22 tests, 0 failures**. The diagnostic guard checked **64 Rust sources**. Fuzz, audit/deny, and deterministic SBOM evidence is recorded under P12 and the Q reports below; the earlier P14-era 339/20/62/479 results are historical.

## Privacy follow-up progress table (Q0–Q5, not a numbered milestone)

| Phase | Short name | Local status | Exit evidence | Claim boundary |
|---|---|---|---|---|
| Q0 | Comparison and claim boundary | Complete locally | `PRIVACY_IMPROVEMENT_PLAN.md` source-backed Signal/Session comparison | No Signal/Session parity, anonymity, or production claim. |
| Q1 | Relay-only route policy | Complete locally | `DialPolicy`, circuit validation/dial, observed-path gates, relay-server activation, real local relay circuit test | Relay sees IP/timing/sizes; no two-machine or anonymity claim. |
| Q2 | MLS application padding | Complete locally | Fixed buckets, strict padding validation, boundary and hostile tests | Coarse bucket hiding only; no timing/volume defence or outer-frame hiding. |
| Q3 | Clear envelope metadata reduction | Design only | New wire version and adversarial tests required before implementation | No silent v2 metadata change; no unlinkability claim. |
| Q4 | Ephemeral delegated application keys | Design only | Wire/identity boundary decision required before implementation | P6 local delegation remains unwired; no deniability claim. |
| Q5 | SOCKS5-only route | Complete locally as route policy only | SOCKS5-only transport, fake-proxy domain forwarding, no-listener/no-fallback tests, GUI non-claims | Proxy identity, real Tor behavior, DNS/IPv6/relay leak tests, and anonymity unverified. |

---

### P0 — Source-backed reassessment and finding register

- **MILESTONE:** P0, source-backed reassessment and finding register; not a numbered product milestone.
- **Implemented changes:** Reassessed source across docs/CI, network/files, identity/groups/setup/replay, and storage/persistence. Created an evidence policy requiring source path, implemented code, an adversarial test, a full local gate, and an explicit primitive-versus-application distinction. Classified findings in `SECURITY_AUDIT.md`, including the restricted-channel disclosure, reused identity key, replay/rollback boundaries, persistence gaps, relay rationale correction, pre-auth admission, resource budgets, and supply-chain boundaries.
- **Modified files:** `SECURITY_AUDIT.md`, `SECURITY_REMEDIATION_PLAN.md`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `THREAT_MODEL.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** A documented, source-backed basis for later phases. No finding was marked closed by documentation alone; claims were separated from primitive existence and application wiring.
- **Tests added:** P0 added no new product test in the final snapshot. It preserved and cited existing adversarial checks for relayed-file refusal, `/p2p-circuit` rejection, pre-authentication socket caps, rate-limiter behaviour, envelope mutation/truncation, and diagnostic redaction.
- **Tests executed:** Targeted identity/messaging/files/network/storage suites listed in `SECURITY_TESTS.md`, `python3 scripts/check_diagnostics.py`, and the final serialized workspace and GUI gates.
- **Test results:** Final post-Q workspace **358 passed, 0 failed**; GUI-feature **22 passed, 0 failed**; diagnostic guard **64 Rust sources**. P0 did not introduce an external or manual verification result.
- **Remaining limitations:** Findings remain open until their own phase evidence exists. No documentation-only closure, external audit, two-machine verification, or production-readiness conclusion.
- **Documentation updated:** Finding register, remediation plan, security architecture, limitations, test execution guide, threat model, and project status were reconciled.

### P1 — Cryptographic channel isolation (P1a–P1f)

- **MILESTONE:** P1, cryptographic channel isolation; not a numbered product milestone.
- **Implemented changes:** Added domain-separated `channel_group_id(parent, channel)` as an MLS identifier derivation; a bound `ChannelGroupBinding`/`ChannelKeyPackage`/`ChannelWelcome`/`MlsChannelGroup` lifecycle API; signed `MLS1` channel-scope frame variants binding parent, channel, transaction, operation, and peer; controller validation and routing so non-default text/receipts use the derived group while policy/default traffic stays on the parent; authenticated encrypted persistence and fail-closed restore for ready channel groups; and honest GUI status separating parent policy from derived readiness.
- **Modified files:** `crates/groups/src/lib.rs`, `crates/groups/Cargo.toml`, `Cargo.lock`, `crates/groups/tests/channel_isolation.rs` (new), `crates/groups/tests/channel_group_lifecycle.rs` (new), `crates/chat/src/setup.rs`, `crates/chat/src/controller.rs`, `crates/chat/src/channel.rs`, `crates/chat/src/lib.rs`, `apps/desktop/src/model.rs`, `apps/desktop/src/app.rs`, `docs/DECISIONS/ADR-0009-m10-channels.md`, `docs/PROTOCOL.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, `PROJECT_STATUS.md`.
- **New dependencies:** An internal Cargo edge from `p2p-groups` to the already workspace-pinned `sha2`; no new external crate, GUI backend, wire protocol, or infrastructure.
- **Security properties achieved:** An excluded parent member cannot decrypt captured non-default channel ciphertext even with parent keys or a locally created same-ID group; wrong-parent/wrong-channel KeyPackages/Welcomes, wrong-sender commits, parent ciphertext in a channel group, and misplaced non-default text are rejected; ready groups restore only under authenticated parent/channel/epoch/membership/pending/receipt bindings.
- **Tests added:** `derived_channel_group_id_is_domain_separated`, `excluded_member_cannot_decrypt_independent_channel_ciphertext`, `channel_key_update_does_not_grant_parent_group_access`; `binding_derives_and_exposes_the_explicit_group_context`, `key_package_with_wrong_parent_or_channel_is_rejected_on_add`, `welcome_with_wrong_parent_or_channel_is_rejected_on_join`, `bound_channel_group_applies_authorized_add_update_and_remove_commits`, `commit_with_a_wrong_sender_is_rejected`, `parent_group_ciphertext_is_rejected_by_the_channel_group`; `channel_scope_round_trips_and_is_covered_by_the_signature`, `channel_scope_frames_reject_missing_truncated_unknown_and_substituted_values`, `channel_setup_scope_binds_parent_channel_transaction_and_peer`, `excluded_parent_member_cannot_validate_a_channel_setup_scope`; controller exclusion/receipt/routing tests; nine P1e restore/tamper/deletion tests; and three P1f GUI model tests.
- **Tests executed:** `cargo +1.100.0 test -p p2p-groups --test channel_isolation --locked`; `cargo +1.100.0 test -p p2p-groups --test channel_group_lifecycle --locked`; `cargo +1.100.0 test -p p2p-chat --lib --locked`; `cargo +1.100.0 test -p p2p-chat --test controller --locked`; `cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** Targeted P1a **3/0**, P1b **6/0**, P1c **50/0**, P1d **53/0**, P1e **62/0** chat-library, P1d controller **20/0**, P1 GUI additions passing in the final **22/0** GUI-feature run. Historical P1 workspace counts were 270, 273, 282, and 285; the final aggregate is **358/0**.
- **Remaining limitations:** SA-001 is closed only for validated non-default controller text. Parent `CHN1` policy metadata and default-channel traffic remain in the parent MLS group; there is no complete channel ACL, metadata confidentiality, setup-material persistence, or decrypted-text restore.
- **Documentation updated:** ADR-0009, protocol/security/architecture docs, project status, test records, and the remediation plan were reconciled with the derived-group and honest-status boundaries.

### P2 — Identity separation

- **MILESTONE:** P2, role-separated identity and role-specific wire signatures; not a numbered product milestone.
- **Implemented changes:** Generated independent `Root`, `Device`, `Transport`, `Mls`, `Application`, and `File` keys with signed certificates, validity windows, local revocation, authenticated root rotation, public proofs, and complete encrypted identity bundles in new vaults. Legacy transport-only import remains explicit migration. Changed wire versions in place to `Envelope` v2, `MLS1` setup v3, and `FileEnvelope` v2; legacy frames are rejected. Envelope/setup use the certified `Application` key, file frames use `File`, MLS uses independent `Mls`, and Noise uses certified `Transport`.
- **Modified files:** `crates/identity/src/lib.rs`, `crates/identity/src/roles.rs` (new), `crates/identity/src/certificate.rs` (new), `crates/identity/src/proof.rs` (new), `crates/identity/src/rotation.rs` (new), `crates/identity/src/bundle.rs` (new), `crates/identity/src/envelope.rs`, `crates/identity/src/contact.rs`, `crates/identity/tests/identity_flow.rs`, `crates/messaging/src/envelope.rs`, `crates/files/src/frame.rs`, `crates/chat/src/setup.rs`, `crates/chat/src/controller.rs`, `crates/groups/src/lib.rs`, `crates/network/src/lib.rs`, `crates/network/tests/message_wire.rs`, `crates/crypto/src/subkeys.rs`, `docs/PROTOCOL.md`, `docs/SECURITY.md`, `docs/CRYPTOGRAPHY.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** Wrong-role signatures, expired/not-yet-valid/revoked certificates, forged or stale rotations, forged/substituted proofs, role-key reuse, and transport-signature reuse at envelope/setup/file layers fail closed. `Debug` output is redacted for certificates, proofs, rotations, bundles, envelopes, and frames.
- **Tests added:** `role_codes_are_stable_and_complete`, `signing_domains_are_distinct`, `valid_certificate_round_trips_and_verifies`, `expired_and_not_yet_valid_certificates_are_rejected`, `revoked_certificate_is_rejected`, `forged_signature_and_wrong_issuer_are_rejected`, `malformed_certificates_are_rejected_before_validation`, `proof_rejects_role_key_reuse`, `forged_rotation_is_rejected`, `stale_rotation_and_self_rotation_are_rejected`, `bundle_round_trip_preserves_all_role_keys`, `tampered_bundle_is_rejected`, `wrong_role_and_transport_signatures_are_rejected`, `substituted_and_tampered_proofs_are_rejected`, and version-rejection tests across envelope/setup/file codecs.
- **Tests executed:** `cargo +1.100.0 test -p p2p-identity --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-messaging -p p2p-files --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-chat --lib --locked`; final serialized workspace gate.
- **Test results:** All targeted P2 suites passed; final post-Q workspace **358/0** with identity 61 and messaging 20. No external identity-verification or human-contact claim was tested.
- **Remaining limitations:** Contact-root trust anchors are not wired into `ContactPayload` or the GUI; revocation is local and not distributed; `Identity` remains clonable; role separation is primitive/wire-level, not a complete application channel ACL.
- **Documentation updated:** Protocol, security, cryptography, architecture, audit, limitations, and status records were updated for versions v2/v3/v2 and role-specific signatures.

### P3 — Replay and setup hardening

- **MILESTONE:** P3, durable replay/setup hardening; not a numbered product milestone.
- **Implemented changes:** Made durable group-ack outcomes channel-aware, added v2 group acks carrying channel IDs with legacy v1 read compatibility, bound channel welcomes/commits into durable ack keys, and made the 4096-entry control log fail closed when full instead of dropping replay state.
- **Modified files:** `crates/chat/src/controller.rs`, `crates/chat/src/setup.rs`, `crates/storage/src/control_log.rs`, `crates/storage/src/lib.rs`, `crates/chat/tests/controller.rs`, `docs/PROTOCOL.md`, `docs/STORAGE.md`, `SECURITY_AUDIT.md`, `SECURITY_ARCHITECTURE.md`.
- **New dependencies:** None.
- **Security properties achieved:** Parent and channel acks cannot satisfy each other; exact authenticated terminal frames remain non-repeatable after restart; idempotent request retries remain idempotent after restart; stale channel/group acks are rejected; a full control log fails closed.
- **Tests added:** `durable_channel_acks_are_separate_from_parent_group_acks`, `restored_group_commit_replay_returns_the_original_ack_without_reapplying`, `restored_group_welcome_replay_returns_the_original_ack_without_rejoining`, `stale_group_commit_and_welcome_acks_are_rejected`, `durable_control_log_rejects_exact_authenticated_frame_after_reopen`, `durable_control_log_keeps_request_retries_idempotent_after_reopen`, `full_control_log_fails_closed_instead_of_dropping_replay_state`, `control_log_is_durable_and_idempotent_only_for_requests`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-chat --lib --locked`; `cargo +1.100.0 test -p p2p-chat --test controller --locked`; `cargo +1.100.0 test -p p2p-storage --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** All targeted P3 tests passed; final post-Q workspace **358/0** with chat 86 and storage 49.
- **Remaining limitations:** Not a replay-proof protocol. There is no external anchor; a full vault restore including `control.anchor` remains locally undetectable; setup KeyPackages/Welcomes and MLS state are not restored by the control log itself.
- **Documentation updated:** Protocol/storage wording, audit findings SA-003/SA-004/SA-020, architecture, limitations, and status records were reconciled.

### P4 — Persistence and recovery

- **MILESTONE:** P4, encrypted persistence and bounded recovery; not a numbered product milestone.
- **Implemented changes:** Added a dedicated `Purpose::MlsState` HKDF slot for new vaults with profile `mls_key_version`; legacy six-salt profiles remain readable through a stable derived salt; unknown versions fail closed; anchor writes authenticate MLS watermarks under the selected MLS key. Kept ADR-0014 Phase 4 restore of explicitly joined groups, ready channel groups, bounded pending operations, receipt expectations, and ciphertext queue under authenticated application records.
- **Modified files:** `crates/crypto/src/subkeys.rs`, `crates/storage/src/lib.rs`, `crates/storage/src/mls_state.rs`, `crates/storage/src/control_log.rs`, `crates/groups/src/lib.rs`, `crates/chat/src/controller.rs`, `crates/chat/tests/controller.rs`, `docs/DECISIONS/ADR-0014-encrypted-mls-state-persistence.md`, `docs/STORAGE.md`, `docs/SECURITY.md`, `SECURITY_AUDIT.md`.
- **New dependencies:** None.
- **Security properties achieved:** New-vault MLS state uses a distinct derived subkey; old vaults remain readable without silent re-encryption; corrupt/unknown key versions and interrupted anchor-first writes/deletes fail closed; restored records are validated for identity, group/membership, epoch, sequence, pending state, receipt state, and ciphertext binding.
- **Tests added:** `purposes_produce_distinct_stable_keys`, `new_vault_encrypts_mls_state_with_the_dedicated_purpose`, `legacy_mls_key_version_keeps_legacy_vaults_readable`, `corrupt_mls_key_version_fails_closed`, `interrupted_anchor_first_write_fails_closed_until_the_anchor_is_restored`, `interrupted_anchor_first_delete_fails_closed_until_the_anchor_is_restored`, plus controller restart/tamper tests including `joined_conversation_and_channel_policy_restore_after_restart` and `vault_backed_group_operations_survive_controlled_restarts`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-crypto --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-storage --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-chat --lib --locked`; `cargo +1.100.0 test -p p2p-chat --test controller --locked`; final serialized workspace gate.
- **Test results:** All targeted P4 suites passed; final post-Q workspace **358/0** with crypto 8, storage 49, and chat 86.
- **Remaining limitations:** Pending setup KeyPackages/Welcomes and decrypted messages do not survive restart. No external rollback anchor, complete crash recovery, backup/restore, or full-vault rollback detection is claimed.
- **Documentation updated:** ADR-0014, storage/security/protocol docs, audit SA-005/SA-006/SA-021, architecture, limitations, and status records were reconciled.

### P5 — Anonymity / fail-closed transport mode

- **MILESTONE:** P5, anonymity boundary implemented as a fail-closed configuration gate; not an anonymity implementation.
- **Implemented changes:** Added `TransportPrivacyMode::{Direct, TorRequired}` to `NetworkConfig`, a `NetworkPrivacyStatus::transport_mode` field, `validate_config`/`Network::start` rejection of `TorRequired` before worker start, an honest GUI row, and local non-claim copy. `Direct` remains the default and is labelled non-anonymous.
- **Modified files:** `crates/network/src/privacy.rs`, `crates/network/src/lib.rs`, `apps/desktop/src/model.rs`, `apps/desktop/src/app.rs`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `docs/NETWORKING.md`, `docs/SECURITY.md`, `SECURITY_TESTS.md`.
- **New dependencies:** None.
- **Security properties achieved:** A requested hidden route that is not implemented is rejected before any transport worker starts; there is no direct fallback in required mode; status reports the requested mode rather than fabricating an observed anonymity property; the GUI never offers the unsupported mode.
- **Tests added:** `tor_required_fails_closed_without_direct_fallback`, `transport_mode_default_is_direct_without_an_anonymity_claim`, plus GUI rows/copy checks including `network_details_keep_the_bounded_non_claims`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-network --lib --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** All targeted P5 tests passed; final post-Q workspace **358/0** with network 58 and GUI-feature **22/0**.
- **Remaining limitations:** At P5 there was no route; Q5 later added a configured SOCKS5-only route with no direct fallback, but no real Tor/proxy identity check, DNS/IPv6 leak test, packet capture, onion/I2P/mixnet route, timing defense, metadata confidentiality, or unlinkability is claimed.
- **Documentation updated:** Networking/security docs, audit SA-017, architecture, limitations, test guide, and status records now describe the fail-closed honesty boundary only.

### P6 — Administration

- **MILESTONE:** P6, delegated administration primitives; not a numbered product milestone.
- **Implemented changes:** Added `RoleDelegation` and `resolve_delegated_grant` as local, device-signed primitives carrying a caller-supplied public key, counter, validity window, role, and redacted `Debug`. Conflicting grants at one counter fail closed, newer counters supersede older ones, and expired, wrong-issuer, wrong-device, tampered, or undelegatable grants are rejected.
- **Modified files:** `crates/identity/src/delegation.rs` (new), `crates/identity/src/lib.rs`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `PROJECT_STATUS.md`, `tests/README.md`.
- **New dependencies:** None.
- **Security properties achieved:** Delegation is cryptographically bound to the issuing device and role; conflict and expiry handling are explicit; signature material is redacted from diagnostics. No secret is derived from the delegated public key.
- **Tests added:** `device_signed_delegation_round_trips_and_validates`, `conflicting_delegations_at_one_counter_fail_closed`, `newer_delegation_supersedes_an_older_counter`, `wrong_issuer_wrong_device_or_tampered_grant_is_rejected`, `expired_and_undelegatable_roles_are_rejected`, `delegated_key_is_caller_supplied_and_not_derived`, `delegation_debug_redacts_the_signature`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-identity --lib --locked -- --test-threads=1`; diagnostic guard; final serialized workspace gate.
- **Test results:** All targeted P6 tests passed; diagnostic guard checked **64 Rust sources** after the redacted-`Debug` correction; final post-Q workspace **358/0** with identity 61.
- **Remaining limitations:** No directory, enterprise policy engine, GUI trust anchor, admin role change, or complete cryptographic channel ACL is wired. Revocation remains a local primitive without real-time propagation.
- **Documentation updated:** Architecture and limitations sections now separate the local primitive from unwired application use; status and test records list the P6 suite.

### P7 — Files

- **MILESTONE:** P7, natural file-send UX and symmetric relay policy; not a numbered product milestone.
- **Implemented changes:** Replaced the typed file-path form with a native OS picker beside `Send`; preserved the encrypted send path and honest transfer status list; collapsed long safety prose into opt-in details; feature-only builds return `File picker requires the native build`; added `outbound_file_request_allowed` so outbound sends and inbound requests share the same observed-relay refusal; retained role-specific `FileEnvelope` signatures and bounded file frames.
- **Modified files:** `apps/desktop/src/app.rs`, `apps/desktop/src/model.rs`, `crates/network/src/lib.rs`, `crates/files/src/frame.rs`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/PROTOCOL.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None; `rfd` was already an optional native-only dependency from M8.
- **Security properties achieved:** No manual path form remains in the normal send flow; unsupported builds do not present a dead picker; relayed file requests are refused symmetrically before pending state or responses; relay bytes remain Noise/Yamux-protected and relays are not application-key readers.
- **Tests added:** `outbound_file_requests_use_the_same_relay_policy_as_inbound`, `relayed_inbound_file_request_emits_only_a_failed_event`, `file_picker_copy_does_not_ask_for_a_manual_path`, plus P2 file-frame role tests retained in `crates/files/src/frame.rs`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-network --lib --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-files --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** All targeted P7 tests passed; final post-Q workspace **358/0** with files 20 and network 58; GUI-feature **22/0**.
- **Remaining limitations:** No headless visual inspection or OS-dialog interaction test; file-over-relay remains disabled; no malware scanning, general MIME parsing, malware-free claim, or transfer-after-restart claim.
- **Documentation updated:** Architecture/security/protocol/limitation wording now describes the native picker, honest feature-only fallback, and symmetric relay refusal.

### P8 — Offline

- **MILESTONE:** P8, bounded ciphertext-only offline queue; not a numbered product milestone.
- **Implemented changes:** Added `MAX_OFFLINE_QUEUE` (16) and `ChatError::OfflineQueueFull`; the send path rejects a would-be offline send before composing new ciphertext when the queue is full; vault restore rejects an oversized queue record. Queue entries remain signed ciphertext only.
- **Modified files:** `crates/chat/src/lib.rs`, `crates/chat/src/controller.rs`, `crates/storage/src/lib.rs`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** Local memory growth from offline recipients is bounded by an explicit error rather than silent accumulation; restored queues cannot exceed the same bound; no plaintext is written to the queue or database.
- **Tests added:** `offline_queue_rejects_a_full_queue_before_composing_ciphertext`, with restored-queue bound coverage in the storage/chat suites and existing plaintext-sentinel scans retained.
- **Tests executed:** `cargo +1.100.0 test -p p2p-chat --lib --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-chat --test controller --locked`; `cargo +1.100.0 test -p p2p-storage --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** All targeted P8 tests passed; final post-Q workspace **358/0** with chat 86 and storage 49.
- **Remaining limitations:** No mailbox service, mandatory store-and-forward infrastructure, offline identity resolution, or delivery guarantee. Restored entries remain unconfirmed until a verified receipt arrives.
- **Documentation updated:** Architecture, limitations, tests, and status records now state the cap and fail-closed pre-compose behaviour.

### P9 — Post-quantum

- **MILESTONE:** P9, bounded OpenMLS capability evaluation; not a quantum-resistance claim.
- **Implemented changes:** Added an internal test module in `p2p-groups` that asserts the pinned OpenMLS `0.10.0-rc.1` version and rejects any non-classical ciphersuite visible in this build. The existing pinned provider/traits versions remain unchanged.
- **Modified files:** `crates/groups/src/lib.rs`, `crates/groups/Cargo.toml`, `Cargo.lock`, `SECURITY_AUDIT.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `PROJECT_STATUS.md`.
- **New dependencies:** No new external dependency; `sha2` was already an internal workspace-pinned edge from P1. No hybrid KEM or signature crate was added.
- **Security properties achieved:** The build’s actual ciphersuite capability is recorded by a test instead of inferred from documentation. Classical-only support is explicit.
- **Tests added:** `pinned_openmls_advertises_only_classical_ciphersuites`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-groups --lib --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** Targeted P9 test passed; final post-Q workspace **358/0** with groups 22.
- **Remaining limitations:** No post-quantum or hybrid KEM/signature support, no custom construction, no interoperability test, no quantum-resistance claim, and no production-stability claim for the release candidate.
- **Documentation updated:** Audit SA-024, limitations, tests, and status records now describe the bounded evaluation and its non-claim.

### P10 — Deniability and metadata resistance

- **MILESTONE:** P10, bounded deniability/metadata non-claim; no privacy mechanism is implemented.
- **Implemented changes:** Added a signed-envelope test that parses wire bytes as a third party, verifies the `Application`-role signature, and asserts which metadata is readable before MLS decryption. Added residual finding SA-022 rather than presenting a deniability feature.
- **Modified files:** `crates/messaging/src/envelope.rs`, `SECURITY_AUDIT.md`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** The exact residual is documented: signed frames are transferable authorship evidence, and conversation, epoch, sender, sequence, sender-supplied time, kind, and ciphertext are visible before decryption.
- **Tests added:** `signed_envelope_exposes_transferable_authorship_and_clear_metadata`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-messaging --lib --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** Targeted P10 test passed; final post-Q workspace **358/0** with messaging 20.
- **Remaining limitations:** No deniability, repudiability, traffic-analysis resistance, metadata confidentiality, or unlinkability. Q2 later added coarse MLS plaintext bucket padding, not metadata confidentiality. Relay operators and peers can observe PeerIds, timing, and outer frame sizes.
- **Documentation updated:** Audit SA-022, architecture, limitations, tests, and status records now state the residual explicitly.

### P11 — Multi-device

- **MILESTONE:** P11, portable encrypted identity bundles; not a multi-device account system.
- **Implemented changes:** Completed encrypted identity bundles carrying every role key and certificate/proof state for new vaults; kept legacy transport-only import as an explicit migration path; tested independent device key generation and exact portable restore.
- **Modified files:** `crates/identity/src/bundle.rs` (new), `crates/identity/src/lib.rs`, `crates/identity/src/envelope.rs`, `crates/identity/src/rotation.rs`, `crates/identity/tests/identity_flow.rs`, `crates/storage/src/lib.rs`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** Two installations do not share role keys by accident; an explicit password-encrypted export/import preserves all role keys exactly; tampered bundles fail closed; legacy transport-only migration binds fresh distinct roles.
- **Tests added:** `independent_devices_keep_separate_keys_but_portable_export_preserves_a_bundle`, `bundle_round_trip_preserves_all_role_keys`, `tampered_bundle_is_rejected`, `legacy_transport_bundle_binds_fresh_distinct_roles`, `legacy_rotation_chain_records_are_supported`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-identity --test identity_flow --locked -- --test-threads=1`; `cargo +1.100.0 test -p p2p-identity --lib --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** All targeted P11 tests passed; final post-Q workspace **358/0** with identity 61 (58 unit + 3 integration).
- **Remaining limitations:** No account model, shared secret by default, automatic contact migration, seamless convergence, or distributed device revocation.
- **Documentation updated:** Identity/protocol/security limitation wording, tests, and status records now separate portable restore from multi-device convergence.

### P12 — Supply chain

- **MILESTONE:** P12, local supply-chain verification and deterministic SBOM evidence; not a release-signed build.
- **Implemented changes:** Re-ran the existing SHA-pinned workflow-ref gates, `cargo audit`/`cargo deny` for root and fuzz lockfiles, locked fuzz check/clippy/build, six plain-libFuzzer smoke runs, and deterministic SBOM generation. Refreshed `fuzz/Cargo.lock` by one line for the already-added internal `sha2` edge so locked fuzz metadata is consistent.
- **Modified files:** `fuzz/Cargo.lock`, `SECURITY_TESTS.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_AUDIT.md`, `SECURITY_REMEDIATION_PLAN.md`, `PROJECT_STATUS.md`; generated SPDX outputs were compared outside the repository.
- **New dependencies:** No new package. The one-line lock refresh records the existing `p2p-groups -> sha2` edge.
- **Security properties achieved:** Local advisory/license/ban/source gates are recorded; fuzz targets build under locked configuration; short smoke runs completed without crashes; SPDX documents regenerate byte-for-byte with unique IDs, relative paths, and no dangling relationships.
- **Tests added:** No new product test. P12 adds execution records and the refreshed fuzz lock line.
- **Tests executed:** `cargo audit --file Cargo.lock`; `cargo deny --locked --manifest-path Cargo.toml check`; `cargo audit --file fuzz/Cargo.lock`; `cargo deny --locked --manifest-path fuzz/Cargo.toml check`; `cargo +1.100.0 check --locked --manifest-path fuzz/Cargo.toml`; `cargo +1.100.0 clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`; `cargo +1.100.0 build --locked --manifest-path fuzz/Cargo.toml`; six 1000-input plain-libFuzzer runs; two SBOM generations per graph followed by `cmp`.
- **Test results:** Root audit zero vulnerabilities with five allowed unmaintained warnings; root deny `advisories ok, bans ok, licenses ok, sources ok`; fuzz audit zero vulnerabilities with two allowed unmaintained warnings; locked fuzz check/clippy/build passed; six smoke runs each completed 1000 inputs without crashes; root and fuzz SPDX regenerated byte-for-byte with 479 packages each. Two pre-existing unused-manifest-dependency warnings remain advisory.
- **Remaining limitations:** No action-code audit, signed release identity, build provenance, reproducible-build proof, long coverage-guided fuzz campaign, CI result, or release claim for this workstream.
- **Documentation updated:** Test execution guide, limitations, audit, remediation plan, and status records now record exact local supply-chain evidence and its boundary.

### P13 — Adversarial and performance

- **MILESTONE:** P13, hostile-peer resource bounds; not a distributed-capacity guarantee.
- **Implemented changes:** Added a hostile-peer matrix test that sends an oversized request on every application request protocol and asserts denial without reserving aggregate or per-protocol accounting state. Retained explicit pending-socket caps, per-IP pre-auth admission, authenticated global/per-peer limits, aggregate request/byte ceilings, derived protocol reservations, denied-request non-charging, and expired rate-limiter cleanup.
- **Modified files:** `crates/network/src/lib.rs`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `SECURITY_AUDIT.md`, `PROJECT_STATUS.md`.
- **New dependencies:** None.
- **Security properties achieved:** A denied oversized request on any protocol cannot bypass the aggregate ceiling or steal another protocol’s reservation; per-protocol saturation is isolated from other protocols; denial does not charge the aggregate budget.
- **Tests added:** `hostile_peer_matrix_cannot_bypass_the_aggregate_byte_ceiling`, alongside retained tests `rate_limiter_reserves_protocol_shares_inside_the_aggregate_ceiling`, `rate_limiter_denied_request_does_not_charge_the_aggregate_budget`, `transport_limits_map_config_to_explicit_libp2p_bounds`, and `rate_limiter_removes_peer_entries_after_expiry`.
- **Tests executed:** `cargo +1.100.0 test -p p2p-network --lib --locked -- --test-threads=1`; final serialized workspace gate.
- **Test results:** Targeted P13 test passed; final post-Q workspace **358/0** with network 58.
- **Remaining limitations:** Single-peer/single-host local evidence only. No distributed flood capacity, OS descriptor exhaustion, relay-flood, latency, throughput, or production-load claim.
- **Documentation updated:** Architecture, limitations, audit SA-018/SA-019/PC-004, tests, and status records now state the matrix coverage and its boundary.

### P14 — Final verification and limitation consolidation

- **MILESTONE:** P14, final local verification and documentation consolidation; not a new numbered product milestone.
- **Implemented changes:** Reconciled status, audit, architecture, limitations, test, protocol, security, storage, networking, ADR, and test-history documents with the implemented P0–P13 code; created this per-phase milestone report; recorded final local gate results with explicit non-claims.
- **Modified files:** `PROJECT_STATUS.md`, `SECURITY_REMEDIATION_PLAN.md`, `SECURITY_AUDIT.md`, `SECURITY_ARCHITECTURE.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_TESTS.md`, `SECURITY_MILESTONE_REPORTS.md` (new), `tests/README.md`, `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/SECURITY.md`, `docs/NETWORKING.md`, `docs/CRYPTOGRAPHY.md`, `docs/STORAGE.md`, `docs/DEPENDENCIES.md`, `docs/DECISIONS/ADR-0009-m10-channels.md`, `docs/DECISIONS/ADR-0014-encrypted-mls-state-persistence.md`.
- **New dependencies:** None.
- **Security properties achieved:** No new primitive. P14 establishes a local evidence trail that separates implemented properties, bounded non-claims, and unresolved limitations.
- **Tests added:** No new product test; P14 adds final test records and this report.
- **Tests executed:** `cargo +1.100.0 fmt --all -- --check`; `git diff --check`; `python3 scripts/check_diagnostics.py`; `cargo +1.100.0 check --locked --workspace --all-targets`; `cargo +1.100.0 clippy --locked --workspace --all-targets -- -D warnings`; `cargo +1.100.0 test --workspace --locked -- --test-threads=1`; GUI-feature check/clippy/test; native check/clippy/build; P12 supply-chain/fuzz/SBOM gates.
- **Test results:** Final post-Q workspace **358 tests, 0 failures**, doc-tests 0; GUI-feature **22 tests, 0 failures**; diagnostics **64 Rust sources**; check/clippy/build gates passed; P12 gates passed as recorded above. Two pre-existing advisory manifest warnings remain non-fatal.
- **Remaining limitations:** No CI, release, commit, push, PR, review, merge, platform-installer execution, visual GUI inspection, two-machine LAN/NAT/relay verification, external audit, or production-readiness claim. Parent/default-channel ACL gaps, partial rollback detection, unwired delegations, metadata exposure, classical-only MLS, and platform-specific gaps remain explicitly open.
- **Documentation updated:** All status, plan, finding, architecture, limitation, test, protocol, and ADR records are reconciled to the final code state; this file is the authoritative per-phase milestone record.

---

### Q0–Q5 — Privacy follow-up consolidated milestone report (not a numbered milestone)

- **MILESTONE:** Q0 comparison/non-claim; Q1 relay-only route policy; Q2 MLS application padding; Q3 clear metadata design-only; Q4 ephemeral delegated application keys design-only; Q5 SOCKS5-only route policy. Local and uncommitted; no Milestone 14 and no anonymity milestone is created.
- **Implemented changes:** Q0 recorded a source-backed Signal/Session comparison and claim boundary. Q1 added `DialPolicy::{DirectAllowed, RelayOnly}`, relay-only config validation, direct-dial and direct-listener refusal, `Network::relayed_address`/`dial_relayed`, circuit-address validation against configured relays, circuit listener state after reservation acceptance, observed-path application route checks, explicit `RelayMode::Server` hop status with non-wildcard external addresses, controller/GUI relay-only dialing, and honest settings/status copy. Q2 added tag-`1`, 5-byte-header MLS application padding into 15 fixed buckets from 64 to 786432 bytes with strict receive-side validation and no wire-version change. Q5 added a SOCKS5-only libp2p transport that forwards IP/domain targets to a user-supplied proxy, rejects `/dnsaddr`/UDP/circuit/incomplete targets, refuses direct listeners and direct fallback, disables mDNS/AutoNAT/DCUtR in proxy mode, and reports configured proxy status without identity or reachability claims. Q3 and Q4 were left as explicit design candidates without silent wire or identity changes.
- **Modified files:** `PRIVACY_IMPROVEMENT_PLAN.md`, `crates/network/src/lib.rs`, `crates/network/src/socks5.rs`, `crates/network/src/privacy.rs`, `crates/network/tests/relay_only.rs`, `crates/groups/src/lib.rs`, `crates/chat/src/controller.rs`, `apps/desktop/src/app.rs`, `apps/desktop/src/model.rs`, `Cargo.toml`, `Cargo.lock`, `crates/network/Cargo.toml`, `fuzz/Cargo.lock`, and documentation reconciled in `PROJECT_STATUS.md`, `SECURITY_MILESTONE_REPORTS.md`, `SECURITY_TESTS.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_ARCHITECTURE.md`, `SECURITY_AUDIT.md`, `SECURITY_REMEDIATION_PLAN.md`, `THREAT_MODEL.md`, `README.md`, `tests/README.md`, `docs/ARCHITECTURE.md`, `docs/NETWORKING.md`, `docs/SECURITY.md`, `docs/CRYPTOGRAPHY.md`, `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/DECISIONS/ADR-0007-file-transfer-v1.md`, and `docs/DECISIONS/ADR-0012-m13-privacy-network-hardening.md`.
- **New dependencies:** `tokio-socks = "=0.5.3"` with `default-features = false` and `features = ["tokio", "futures-io"]`; `tokio-util = { version = "0.7", features = ["compat"] }`. Root and fuzz lockfiles were refreshed; no anonymous network, Tor daemon, centralized service, webview, npm, or Tauri dependency was added.
- **Security properties achieved:** Under explicit relay-only policy, destination peers are not given a direct connection path and application traffic requires an observed relay; a user-selected relay still observes IP, PeerId, timing, and size metadata. MLS plaintext lengths are coarsened to fixed buckets before encryption with fail-closed malformed-padding rejection. Under `TorRequired`, dial targets are handed to the configured SOCKS5 proxy without local hostname resolution, no direct listener or fallback transport exists, and configuration conflicts fail before startup. GUI status distinguishes configured routes from observed facts.
- **Tests added:** Relay-only config-conflict, circuit-address structure/destination, direct-dial rejection, queued relayed dial, observed-path gating, and GUI validation tests; a real local relay integration test proving circuit-only listeners, reservations, a relay-observed circuit, and relayed alice/bob connectivity; MLS padding round-trip, bucket boundary, empty/oversized, wrong-tag, zero-length, extended-length, dirty-tail, and wrong-length tests; SOCKS5 IP/domain target, unsupported-target, no-listener, no-direct-dial, and fake-proxy domain-forwarding tests; GUI SOCKS5 validation and non-claim tests.
- **Tests executed:** Targeted network, groups, and desktop GUI suites; final `cargo +1.100.0 fmt --all -- --check`, `git diff --check`, `python3 scripts/check_diagnostics.py`, `cargo +1.100.0 check --locked --workspace --all-targets`, `cargo +1.100.0 clippy --locked --workspace --all-targets -- -D warnings`, `cargo +1.100.0 test --locked --workspace -- --test-threads=1`, GUI check/clippy/test, native check/clippy/build, both-lockfile `cargo audit`/`cargo deny`, locked fuzz check/clippy/release build, six 1000-input plain-libFuzzer smoke runs, and two deterministic SBOM generations per graph with `cmp`. A final documentation-only reconciliation changed no Rust source or lockfile and re-ran `git diff --check` successfully.
- **Test results:** Final workspace **358 passed, 0 failed** across 37 suites with 0 doc-tests; GUI-feature **22 passed, 0 failed**; diagnostics **64 Rust sources**; all check/clippy/build gates passed. Root audit reported zero vulnerabilities with five allowed unmaintained warnings; fuzz audit zero vulnerabilities with two allowed warnings; both `cargo deny` runs ended `advisories ok, bans ok, licenses ok, sources ok`. Root SBOM: 480 packages/1594 relationships, lock SHA-256 `03e4451bab061e6c08950669c66a91ffbc0d368fb27691d10cc654132bf90ba0`; fuzz SBOM: 480 packages/1565 relationships, lock SHA-256 `fc1c7a4e7f644e06686cf6d0cff1437985219062034bc581aba71e5ccf3312fb`; both byte-identical on regeneration. Two pre-existing unused-manifest-dependency warnings remain advisory.
- **Remaining limitations:** No verified Tor, proxy identity/reachability, DNS/IPv6 leak test, packet capture, I2P/mixnet, onion service, strong anonymity, unlinkability, metadata confidentiality, traffic-analysis defence, or two-machine NAT/relay test. Q1 relays see metadata and can deny service; Q2 changes only coarse plaintext length, not timing, direction, volume, or outer frames; Q5 is a route policy only. Q3/Q4 remain unimplemented. No CI, release, commit, push, PR, review, merge, visual GUI inspection, or production-readiness claim is made.
- **Documentation updated:** `PRIVACY_IMPROVEMENT_PLAN.md`, `PROJECT_STATUS.md`, this milestone report, `SECURITY_TESTS.md`, `SECURITY_LIMITATIONS.md`, `SECURITY_ARCHITECTURE.md`, `SECURITY_AUDIT.md`, `SECURITY_REMEDIATION_PLAN.md`, `THREAT_MODEL.md`, `README.md`, `tests/README.md`, `docs/ARCHITECTURE.md`, `docs/NETWORKING.md`, `docs/SECURITY.md`, `docs/CRYPTOGRAPHY.md`, `docs/PROTOCOL.md`, `docs/STORAGE.md`, and the two referenced ADRs record the implemented Q phases, exact local evidence, new dependencies, changed defaults, superseded historical counts, and non-claims.
