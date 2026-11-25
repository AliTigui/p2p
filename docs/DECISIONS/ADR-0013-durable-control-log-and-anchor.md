# ADR-0013: Durable setup/group-control digest log with a local anchor

- Status: Accepted
- Date: 2026-11-25
- Milestone: Post-M13 control-log durability
- Related: ADR-0003, ADR-0008, ADR-0011, ADR-0012

## Context

Signed `MLS1` setup/group-control frames were guarded only by a bounded 512-entry in-memory replay cache of `(PeerId, SHA-256 digest)` pairs. A restart erased the cache, so an exact authenticated terminal frame could be replayed into a fresh controller. The vault already has master-derived AEAD and HMAC subkeys (ADR-0003), but the pinned OpenMLS provider offers no supported restoration of ratchet/group state; no MLS persistence is claimed by this decision (ADR-0008, ADR-0011).

## Decision

1. **Schema v4 adds `control_log` and `control_state`.** Migrations remain transactional; appending a record and advancing `control_state` happen in one database transaction.
2. **Records are encrypted and chained.** Each record contains the public PeerId bytes, the SHA-256 digest of the signed frame bytes, and a repeatable flag, encrypted under `Purpose::Db` with sequence/chain AAD and a SHA-256 chain link to the previous record. Lookups use HMAC blind indexes derived under `Purpose::BlindIndex`, with separate indexes for repeatable and non-repeatable frames.
3. **The window is finite and fails closed.** The log is bounded at 4096 entries; at capacity, recording returns `ControlLogFull` instead of evicting older records. Integrity and state mismatches also fail closed.
4. **A local anchor holds the high-water mark.** `<vault>/control.anchor` is AEAD-protected under `Purpose::Db` and written via `<vault>/control.anchor.tmp` with sync and rename. `Vault::unlock` verifies the full record chain, its state, and the anchor, rejecting rollback or tamper.

## Semantics

- `KeyPackageRequest` and `GroupJoinRequest` are idempotent/repeatable: an exact retry is accepted so a lost response can be retried. Every other frame, including Welcomes, commits, responses, and acknowledgements, is non-repeatable; an exact repeat is ignored before it clears correlation state or enters the memory cache.
- The controller consults the durable log after signature verification and before any state mutation via `MessengerController::start_with_control_log`. The GUI supplies an independent `Session::try_clone()`; the vault identity must match the controller identity or construction fails with `ControlLogIdentityMismatch`.
- Without an attached vault session the existing memory-only cache remains the replay boundary. The durable log records frame identities only; it does not restore MLS group or ratchet state.

## Consequences

- An older database restored while the current anchor is retained is detected, as is anchor tampering, deletion, or a chain/state mismatch. Exact authenticated non-repeatable frames remain rejected after reopen; request retries remain idempotent.
- Restoring the entire vault directory, including the anchor, is not detectable by local code alone. There is no external anchor and no central service; the anchor is a local high-water mark, not a backup.
- No wire format changes and no mandatory infrastructure are introduced. Existing constructors and the zero-infrastructure direct-connect path are unchanged.
- No OpenMLS restore or encrypted MLS persistence is claimed; MLS state remains memory-only.

## Alternatives considered

- **Keep the memory-only cache.** Rejected: it leaves a restart gap in which exact replays are accepted.
- **Full OpenMLS persistence.** Deferred: no supported serialization exists through the pinned provider and claiming it would overstate what is implemented.
- **External/remote anchor.** Deferred: it would add mandatory infrastructure or a new optional user service, contrary to the zero-infrastructure design.
- **Plaintext monotonic counter.** Rejected: it leaks metadata and is trivially tampered with; the anchor is AEAD-protected and vault-bound.

## Verification

The 2026-11-25 serialized workspace run recorded in `PROJECT_STATUS.md` passed **207 tests with 0 failures**, including the storage tests `control_log_is_durable_and_idempotent_only_for_requests`, `restoring_an_older_database_while_keeping_the_anchor_is_detected`, and `tampered_control_anchor_is_detected` in `crates/storage/tests/vault.rs`, and the controller tests `durable_control_log_rejects_exact_authenticated_frame_after_reopen` and `durable_control_log_keeps_request_retries_idempotent_after_reopen` in `crates/chat/src/controller.rs`.
