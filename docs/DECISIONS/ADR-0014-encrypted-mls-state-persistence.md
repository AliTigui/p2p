# ADR-0014: Encrypted MLS state persistence with rollback-aware snapshots

- Status: **Accepted — phased implementation in progress.** Phases 1 (encrypted storage foundation), 2 (anchor v2 with MLS watermarks), and 3 (vault-backed staged `StorageProvider` adapter) are implemented in `crates/storage`. The Phase 4 core restore slice is implemented: the controller restores explicitly `Joined` MLS groups and encrypted channel policy from the vault, and startup failures become a real GUI `Failed` state. Pending-operation, receipt, and offline-queue restore remain explicit follow-ups.
- Date: 2026-11-26
- Milestone: None. This is a deferred increment following the post-M13 control-log/anchor work, not a new numbered milestone.
- Related: ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0008, ADR-0009, ADR-0011, ADR-0013

## Context

Every conversation is an MLS group (ADR-0002). The original `MlsSession` constructors still use an `OpenMlsRustCrypto` provider with `openmls_memory_storage::MemoryStorage`; Phase 4 adds storage-backed constructors and a vault-backed `MlsProvider` used by the controller when a vault `Session` is attached. Joined group state and channel policy are restored; pending KeyPackages, Welcome material, group operations, receipts, offline queued ciphertext, and decrypted message text are not restored by this slice. ADR-0013 added a durable, AEAD-protected digest log with a local anchor, but that log records only identities and SHA-256 digests of already authenticated setup/group-control frames; it does not restore MLS group or ratchet state.

The pinned OpenMLS stack is not missing a persistence abstraction:

- `openmls_traits-0.7.0-rc.1/src/storage.rs:41` defines `StorageProvider<const VERSION: u16>`, with getters and setters for group config, trees, transcript hashes, group context, confirmation tags, group state, message secrets, resumption PSKs, leaf indices, epoch secrets, KeyPackages, and related entries.
- `openmls-0.10.0-rc.1/src/group/mls_group/mod.rs:550-563` defines `MlsGroup::load`, which reconstructs a group from those provider entries.
- `openmls_rust_crypto-0.7.0-rc.1/src/lib.rs:18-30` shows that the default `OpenMlsRustCrypto` provider combines `RustCrypto` with `MemoryStorage`.
- `openmls_memory_storage-0.7.0-rc.1/src/lib.rs:3-6` describes `MemoryStorage` as "for testing and prototyping only" and stores values in an in-memory `HashMap`.
- `openmls_memory_storage-0.7.0-rc.1/src/persistence.rs:22-50` writes base64-encoded JSON into the process temp directory. It is not encrypted, not authenticated, not profile-bound, and has no rollback defence.

`openmls_sqlite_storage` was previously validated but not enabled: storing MLS secrets directly in SQLite would violate the encrypted-at-rest requirement without an additional encryption layer. The gap is therefore a **vault-backed encrypted `StorageProvider`** with honest, bounded rollback semantics, not a new wire protocol or a mandatory external service.

## Decision

Implementation is phased. Phases 1–3 below are implemented in `crates/storage`; the Phase 4 core restore slice is implemented in `crates/groups`, `crates/chat`, and `apps/desktop`, with pending-operation/receipt/offline-queue restore deferred. This ADR introduces no new milestone, wire format, or mandatory infrastructure; the Phase 4 slice adds bounded controller startup behavior and honest GUI failure states, not a new protocol. Phases 1–3 reuse existing workspace dependencies (`openmls_traits`, `serde`, `serde_json`, plus dev-only `openmls` and `openmls_rust_crypto`) in `p2p-storage` without adding new locked packages.

### Implementation phases

- **Phase 1 — implemented:** schema-v5 encrypted MLS-state foundation: opaque value CRUD, blind indexes, per-group SHA-256 chains, bounds, and unlock-time verification. No OpenMLS provider, `MlsGroup::load`, controller restore, or GUI change.
- **Phase 2 — implemented:** version-2 `control.anchor` with the existing control-log high-water mark plus bounded per-group MLS watermarks, v1 migration, and database-only rollback detection.
- **Phase 3 — implemented:** vault-backed `openmls_traits::StorageProvider` adapter with in-memory staged writes and reads, one-transaction atomic flush, tombstone deletions, anchor advancement, bounded group-id handling, and a real `MlsGroup::load` round-trip test. No controller, GUI, or application-policy restore.
- **Phase 4 core slice — implemented:** restore joined groups through `MlsGroup::load` with a vault-backed provider, reapply encrypted conversation/channel policy, persist policy on mutation, and surface restore failures as a real GUI `Failed` state. Pending-operation, receipt, and offline-queue restore remain follow-ups.

### 1. Keep the boundary local and encrypted — Phase 1 implemented

1. Phase 1 exposes authenticated encryption and bounded CRUD for opaque provider values through the vault `Session`. Phase 3 now adds the OpenMLS `StorageProvider` adapter on top of that API; Phase 1 by itself does not provide provider integration. No MLS secret, KeyPackage private material, group identifier, channel identifier, or OpenMLS entity label is written in plaintext.
2. Phase 1 uses versioned AAD under the existing `Purpose::Db` subkey, not a new `Purpose::MlsState`. Adding a purpose requires a new salt slot in every existing profile and a stored-salt migration; that migration-bearing change is deferred. A dedicated MLS-state subkey may be introduced in a later phase. Password changes still re-wrap only the random master key and do **not** bulk re-encrypt MLS state.
3. Schema v5 adds `mls_groups` and `mls_state`. Each state row contains an HMAC blind index for the owning group, an HMAC blind index for the provider entity, XChaCha20-Poly1305 ciphertext, an epoch, and a SHA-256 chain link. The record version is embedded in the ciphertext and in AAD. AAD binds the profile ID, record version, group blind index, entity blind index, and epoch; the functional label and key are authenticated inside the ciphertext and bound by the blind index, not stored as plaintext columns.
4. Blind indexes use dedicated HMAC domain labels under `Purpose::BlindIndex`. Provider labels and keys are used only inside authenticated plaintext and in memory; they are not plaintext database keys.
5. Phase 1 is bounded: one value is at most 1 MiB, the store holds at most 4,096 encrypted entries and 64 groups, and exceeding a cap fails closed. `MlsStateEntry` values use zeroizing buffers and redacted `Debug`.

### 2. Make each MLS operation atomic — Phase 3 implemented

1. OpenMLS writes many related provider entries for one commit, Welcome processing, or KeyPackage creation. `StagedMlsProvider` stages all writes in memory for one operation and exposes staged values to later reads through `refcell`-backed `BTreeMap` state. `discard()` drops the staged set and per-group epoch overrides without touching the vault.
2. `flush()` applies the staged set as **one SQLite transaction**: it encrypts and validates every entry, inserts or replaces rows, applies staged tombstones, recomputes affected group chains, installs the v2 anchor, and commits. A failure rolls the transaction back and the staging set is retained for an explicit retry or discard. The caller is responsible for invoking `flush()` only after the OpenMLS operation and validation succeed; Phase 3 does not wire that decision into `p2p-groups`.
3. A partially written epoch is never visible: all staged values carry one application-supplied epoch per group (`set_group_epoch`), and no row is committed until the whole operation succeeds. A fresh provider reads only committed rows. Missing required provider entries still fail closed in `MlsGroup::load`; the adapter does not fabricate state.
4. Provider deletions are staged as tombstones and applied in the **same** transaction as the surviving writes, so a consumed KeyPackage delete and a joined group's state can be committed together when the application calls both methods. The Phase 4 core slice restores a completed joined group and its policy, but it does not resume an interrupted join: a persisted `pending_operation` flag fails startup rather than replaying the operation.
5. Phase 1's `store_mls_state` still writes one opaque value at a time. Phase 3's atomic batch flush is the `StagedMlsProvider` path, not a change to that single-value API.
6. Global (non-group) provider entries such as signature keys, KeyPackages, epoch key pairs, and PSKs use a reserved 16-byte sentinel group id. Group-scoped methods reject that sentinel and any group id that is not exactly 16 bytes before staging anything. Draft virtual-client/extension methods, which are off in this build, remain unimplemented and fail closed.

### 3. Extend the existing local anchor, not a second trust root — Phase 2 implemented

1. `<vault>/control.anchor` is now a versioned record. Version 1 retains only the control-log sequence and chain for compatibility. Version 2 keeps those fields and adds a bounded, sorted per-group MLS watermark map: `group_blind_index -> (epoch, state_chain)`. The group set in the anchor is authoritative: a group present in the database but absent from the anchor, or present in the anchor but absent from the database, is a mismatch.
2. The v2 anchor uses a new versioned AAD label under the existing `Purpose::Db` key and the same temp-file, sync, `chmod`, and rename discipline as v1. A v1 anchor is migrated in place during a successful unlock after both the control log and every MLS row verify; migration rewrites only the anchor and does not re-encrypt application data.
3. Anchor state is bounded at the phase-1 cap of 64 groups and fails closed at the cap. There is still no external anchor, no central service, and no telemetry.
4. `Vault::unlock` verifies the control-log chain, every `mls_state` ciphertext and group chain, and the exact v2 watermark map. A database-only rollback, an authenticated-but-mismatched anchor, a tampered row, or a missing required group fails unlock with the static `RollbackDetected` category.
5. MLS writes install the new anchor before committing their SQLite transaction, so a crash leaves the anchor ahead and fails closed rather than allowing an older database to be blessed. Explicit deletion also removes the watermark before the database commit; restoring a database where a deleted group still exists is therefore detected. Control-log appends remain database-first, and a control anchor that lags by that crash window is brought forward only after the MLS tables fully verify; larger gaps fail closed.
6. Restoring the entire vault directory **including the anchor** remains undetectable by local code. This is partial rollback detection, not replay-proof or rollback-proof state. An interrupted MLS write or deletion can require operator recovery because the anchor is deliberately written first.

### 4. Restore through OpenMLS, then reapply local policy — Phase 4 core slice implemented

1. **Implemented.** After vault identity matching and unlock verification, `MessengerController::build` calls `MlsConversation::load_with_storage` for every persisted MLS group when a vault `Session` is attached. The vault-backed `MlsProvider` calls `MlsGroup::load` through the encrypted `StorageProvider`; a missing group yields `GroupError::MlsStateMissing`, which fails startup instead of producing an empty conversation. Controllers started without a vault session keep the original memory-only path.
2. **Implemented.** Channel metadata and revision state (ADR-0009) remain application-level `CHN1` state, not MLS provider entries. A versioned `p2p.app.conversation/v1` snapshot is encrypted through the vault under the group blind index and carries conversation status, admin/member lists, channels, active channel, and a pending-operation flag. The controller rewrites that record after each relevant mutation and loads it only after the MLS group loads successfully. Restore accepts only `Joined` conversations; setup and failed records remain encrypted but are skipped.
3. **Deferred.** Pending group operations, receipt expectations, and offline queued ciphertext are not restored in this slice. A persisted `pending_operation` flag makes startup fail closed with `ChatError::MlsRestore` rather than silently clearing the operation, and no restored state converts `SentToPeer` into `Delivered`.
4. Decrypted message text remains memory-only. Restoring MLS state does not authorize replaying old Welcomes, commits, or acknowledgements; ADR-0013 continues to gate those frames after signature verification.
5. **Implemented.** `MessengerApp::start_chat` returns startup errors to the worker, which sets a real `VaultState::Failed` with a static category when controller/restore startup fails. No joined conversation, verified peer, delivery, read, scan, or safety status is inferred from a partially loaded provider.
6. Phases 1–3 alone did not change the controller or GUI. The Phase 4 core slice adds explicitly bounded restore: decrypted message text stays memory-only, non-`Joined` conversations are skipped, and only the encrypted group and policy state listed above is reconstructed. It does not restore pending operations, receipts, offline queues, or decrypted messages, and it does not replay old Welcomes, commits, or acknowledgements.

### 5. Explicit non-claims

This design does not introduce mandatory infrastructure, an external anchor, a new application protocol, Tor/I2P/mixnet anonymity, metadata confidentiality, universal NAT traversal, cryptographic per-channel keys, role delegation, a real malware scanner, general MIME parsing, or a production-stability claim for the OpenMLS RC line. It does not make a whole-vault-plus-anchor restore detectable, and it does not turn the control digest log into an MLS state backup. Phases 1–2 do not claim OpenMLS restoration or provider integration. Phase 3 claims a usable provider adapter with transactional staged snapshots and a tested `MlsGroup::load` round trip. The Phase 4 core slice claims controller restore of explicitly `Joined` MLS groups and encrypted channel policy with fail-closed validation, but it does **not** claim pending-operation/receipt/offline-queue or decrypted-message restore, recovery from a crash between an anchor-first MLS write and its database commit, full-vault-plus-anchor rollback detection, or coverage of every OpenMLS provider method outside the create/load paths exercised by tests.

## Consequences

- Phase 1 adds bounded encrypted storage for opaque provider values without changing the controller, GUI, wire format, or dependency graph. It is a foundation, not a restore path.
- Phase 2 makes the existing local anchor cover both control decisions and MLS watermarks. It detects database-only rollback and authenticated-but-stale anchors, but it also makes the anchor authoritative for the group set; an interrupted MLS write or deletion can fail unlock until the operator restores the matching database snapshot.
- Phase 3 adds a `StagedMlsProvider` implementing the pinned `StorageProvider<CURRENT_VERSION>` surface using the Phase 1 encrypted CRUD. It stages writes and reads, flushes one SQLite transaction plus anchor update, and applies tombstones in that same transaction. Draft virtual-client/extension methods are deliberately unimplemented because those features are off in this build.
- The Phase 4 core slice binds controller startup to vault-restored MLS and policy state: a missing group, inconsistent membership/channel policy, unknown active channel, or pending operation fails startup so the GUI can present a real failed state. Restore is limited to `Joined` conversations; pending operations, receipts, offline queued ciphertext, and decrypted text remain deliberately unrestored or memory-only.
- The remaining audit surface stays significant: tests cover the provider entry classes exercised by real group creation and `MlsGroup::load`, not every individual getter/setter or every AAD/blind-index field. Unsupported or unrecognized entries must fail closed, and broader per-class tamper and bounds coverage remains open.
- OpenMLS RC storage APIs may evolve. Any upgrade requires re-reading the pinned trait implementations and a locked test pass; no compatibility promise is made.
- Old MLS secrets should be deleted when epochs advance or groups are removed. Retaining obsolete ratchet entries would enlarge the confidential data set without improving rollback detection.
- Password changes remain cheap because Phase 1 MLS values are encrypted under a master-derived subkey rather than a password-derived key.
- A dedicated MLS-state subkey is deferred because existing profiles store one salt per purpose and cannot adopt a new purpose without a migration.

## Alternatives considered

- **Keep memory-only MLS state.** Safe and current, but restart still loses every conversation. Retained as the fallback until all phases are implemented and verified.
- **Enable `openmls_memory_storage/persistence`.** Rejected: the source writes base64 JSON to the temp directory with no vault key, authentication, profile binding, or rollback defence.
- **Use `openmls_sqlite_storage` directly.** Rejected: SQLite storage of MLS secrets would leave sensitive material plaintext at rest without another encryption layer.
- **Serialize only an `MlsGroup` blob.** Rejected: `MlsGroup::load` reconstructs state from many provider entries; a single opaque blob would be fragile across provider versions and would not cover pending KeyPackages or channel state.
- **Add an external anchor or remote state service.** Rejected for the initial design: it would introduce mandatory or user-operated infrastructure contrary to ADR-0001. A future user-controlled external anchor would be a separate decision.
- **Treat a full encrypted vault export as MLS restore.** Rejected: it would restore the anchor with the state and therefore remain unable to detect a whole-vault rollback.
- **Add `Purpose::MlsState` in Phase 1.** Deferred: it would require a stored-salt-slot migration for existing vaults. Versioned AAD under `Purpose::Db` gives domain separation now without changing the profile format.

## Verification

Phases 1–4 core-slice verification performed locally on 2026-11-26:

- `cargo +1.100.0 test --offline -p p2p-storage -- --test-threads=1` passed **33 tests, 0 failures** (4 unit + 29 integration: 23 in `vault.rs` plus 6 in `mls_provider.rs`). Phase 1 coverage includes encrypted opaque-value round trips, blind indexes, group chains, tamper rejection, deletion, password-change readability, lower-epoch replacement, bounds, and raw DB/WAL/SHM sentinel scans. Phase 2 coverage includes v1-to-v2 anchor migration, an authenticated v2 anchor with a wrong MLS epoch, database-only rollback before an MLS write or deletion, a shared control-log/MLS anchor, and an explicit whole-vault-including-anchor restore that remains undetectable. Phase 3 coverage includes staged reads before flush, discard with no persistence, atomic multi-write flush with anchor advancement, staged tombstones in the same transaction, rejection of unsupported/reserved group ids before staging, and a real `MlsGroup::new_with_group_id` / `MlsGroup::load` round trip after reopening the vault. The post-review-fix rerun also covers discard clearing stale epoch overrides and one-window versus multi-window control-anchor lag.
- `python3 scripts/check_diagnostics.py` and `cargo +1.100.0 clippy --offline -p p2p-storage --all-targets -- -D warnings` passed for this increment. The final locked gate rerun passed fmt, `git diff --check`, the diagnostic guard over **54 Rust source files**, `cargo +1.100.0 check --locked --workspace --all-targets`, `cargo +1.100.0 test --locked --workspace -- --test-threads=1` (**230 tests, 0 failures**), workspace Clippy, GUI/native check and Clippy, and the native build; see `PROJECT_STATUS.md` for the full record. Phase 3 added one new source file, `crates/storage/src/mls_provider.rs`, and one new test file, `crates/storage/tests/mls_provider.rs`; both follow the repository's redaction and diagnostic conventions.
- Phase 4 core-slice tests cover joined conversation/channel policy restore after restart, missing metadata, membership mismatch, a persisted pending operation, an unknown active channel, and a GUI controller-startup failure that remains a real `VaultState::Failed`. The `gui`-feature desktop run passed **14 tests, 0 failures**. No crash-recovery behavior is claimed.

Later hardening must add, at minimum:

- pending-operation, receipt, and offline-queue restore with authenticated consistency checks;
- create/add/remove/update and join flows that survive a controlled restart with the same epoch, member set, channel state, and same-transaction KeyPackage deletion;
- tamper tests for every persisted provider entity class, AAD field, blind index, and chain link beyond the current anchor and MLS-table coverage;
- recovery behavior for an interrupted anchor-first MLS write or deletion;
- raw DB/WAL/SHM scans proving no plaintext MLS secret, KeyPackage private material, conversation identifier, channel identifier, or decrypted message appears after provider integration;
- cross-profile and identity-mismatch rejection tests;
- bounded-cap and missing-required-entry tests for every provider entity class; and
- broader tamper/bounds coverage and a long coverage-guided fuzz campaign; the full locked workspace fmt/check/test/Clippy, GUI/native, advisory/policy, SBOM, and bounded fuzz-smoke gates passed locally and are recorded in `PROJECT_STATUS.md`.
