# Local Storage Design

Status: **Milestone 3 implemented and tested** for the profile vault (now schema v4); message envelopes were added in Milestone 5, Milestone 7 adds a filesystem-only ciphertext quarantine, Milestone 8 adds the validation/scan/approval/release gate, an encrypted attachment store, and explicit deletion policies, Milestone 9 adds multi-member MLS group management without persistence, and Milestone 10 adds logical channels inside the existing MLS conversations without persistence. A post-M13 increment adds schema v4's encrypted, chained digest log and vault anchor for already authenticated setup/group-control frames; it preserves decisions only and does not persist MLS state. Remaining database tables below are design targets for later milestones.

## Implementation status (Milestones 3, 5, 7, 8, 9, 10, and post-M13 control log)

Implemented crates: `crates/crypto` (Argon2id, XChaCha20-Poly1305, HKDF-SHA256, HMAC blind indexes) and `crates/storage` (`Vault`, `Session`, schema version 4 with transactional migrations).

- `crates/storage/src/lib.rs`: WAL, `secure_delete = ON`, `temp_store = MEMORY`, `foreign_keys = ON`, `busy_timeout = 5000`; bundled SQLite; 0700 directory and 0600 database file on Unix.
- Tables currently created: `profile`, `settings`, `messages`, `attachments`, `control_log`, `control_state`, and `migrations`. Persistent contacts, conversations, groups, channels, and receipts remain design targets; Milestone 10 channel state is memory-only. The control tables are described in section 5.
- `profile` stores only ciphertext for the username and identity, a random KDF salt, versioned KDF parameters, the wrapped master key, per-purpose HKDF salts, and a coarse creation timestamp. The password is never stored, logged, or passed to the UI view model.
- The master key is random 32 bytes from the OS CSPRNG. Argon2id derives the KEK; XChaCha20-Poly1305 wraps the master key with AAD binding profile id, salt, KDF id, and parameters. HKDF derives `storage/db`, `storage/identity`, `storage/attachments`, `storage/search-index`, `storage/backup`, and `storage/blind-index` subkeys.
- `settings` uses an HMAC blind index for the key and AEAD ciphertext for the value.
- `change_password` derives a new salt/KEK and re-wraps only the master key; no application data is re-encrypted.
- GUI flow: first run creates a vault; later runs unlock it. Argon2id and SQLite calls execute on a dedicated worker thread and the typed outcome is polled by the UI. Locking drops the session. Public identity data reaches the GUI only after a successful unlock.
- `crates/storage/tests/vault.rs` scans raw `profile.db`, `profile.db-wal`, and `profile.db-shm` bytes for username, password, setting key/value, and raw private-key sentinels; it also covers wrong password, duplicate/missing vault, password change, damaged wrap, and Unix permission modes.
- Milestone 5 added schema v2: signed message envelopes are stored as XChaCha20-Poly1305 ciphertext with HMAC blind indexes. Raw DB/WAL/SHM scans find no plaintext message sentinel.
- Milestone 9 does not add a `groups`, `members`, or MLS-state table. Milestone 10 does not add a `channels` table. Group membership, channel metadata, pending commits, and decrypted messages remain memory-only, so restart does not restore an MLS session or its channels. OpenMLS SQLite storage is still rejected without another encryption layer. Schema v4's control log is narrower still: it records SHA-256 digests of already authenticated setup/group-control frames, not MLS group, ratchet, pending KeyPackage, or channel state.
- Milestone 7/8 does **not** add `files`/`transfers` tables. `p2p-files` writes only encrypted chunks and a hash-only manifest into a restricted per-transfer directory under the local-data quarantine path. The content key is never written there, and plaintext is assembled only in a zeroizing memory buffer for integrity verification, structural format validation, scanner input, and explicitly approved policy release. Unix permissions are `0700` for the directory and `0600` for files; Windows ACLs are a target. Integration tests scan quarantine bytes to confirm no plaintext sentinel before and after release or cancellation.
- Milestone 8 adds schema v3 `attachments`: a random 16-byte ID produces a profile-bound HMAC blind index that is the primary key and blob filename; `wrapped_key` is a per-file random key wrapped under `storage/attachments`; `encrypted_metadata` holds the name, size, SHA-256 digest, and narrow format label under that per-file key. Blob files are XChaCha20-Poly1305 ciphertext only at `attachments/<blind-index-hex>.ct`, created `0600` inside a `0700` directory. `change_password` rewraps only the vault master key, so attachment blobs are not re-encrypted. Raw DB/WAL/SHM/blob scans verify that no filename, payload, format label, or raw private key appears in plaintext.

## 1. Principles

- Every user stores their own history locally. There is no server-side mailbox.
- All sensitive values are encrypted **before** being handed to SQLite; plaintext never reaches database pages, WAL, or temporary files.
- Schema changes are explicit, versioned migrations. No implicit schema mutation at runtime.

## 2. Data model

Implemented tables: `profile`, `settings`, `messages`, `attachments`, `control_log`, `control_state`, and `migrations`. The `attachments` table is described in section 4 and the control tables in section 5. Target tables for later milestones: `identity_envelope`, `contacts`, `conversations`, `groups`, `channels`, `receipts`, `files`, and `transfers`.

Sensitive columns are BLOBs produced by the crypto layer: `ciphertext`, `nonce`, `aad_version`, `key_id`. Attachment rows contain only an HMAC blind index, a wrapped per-file key, and encrypted metadata. Lookup columns that would leak identifiers (PeerId, message ID, attachment ID, control-frame peer) are HMAC blind indexes using a dedicated subkey. Non-secret operational columns (created_at as a coarse integer, record type, sequence) may be plaintext; residual traffic-analysis leakage is documented.

## 3. SQLite configuration

```
PRAGMA journal_mode = WAL;        -- WAL contains ciphertext only
PRAGMA secure_delete = ON;
PRAGMA temp_store = MEMORY;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

SQLite is bundled via `libsqlite3-sys` `bundled` so behaviour does not depend on the host library. Database file and directory are created with restrictive permissions (`0700` directory, `0600` file on Unix; equivalent ACLs on Windows). WAL/SHM files inherit directory restrictions.

## 4. Attachments and quarantine

Implemented in M7/M8 by `p2p-files`, `p2p-storage`, and the native GUI:

- Incoming chunks are written as ciphertext to `<quarantine>/<transfer-id-hex>/000000.ct`, `000001.ct`, and so on, with a `manifest.bin` containing only hashes and public transfer metadata.
- The directory is created with `0700` permissions and chunk files with `0600` on Unix; the path is outside any executable directory. Names received from peers are base names only and cannot introduce path components.
- The fresh per-transfer content key is never persisted, so filesystem access alone cannot decrypt quarantined chunks.
- M8 scanner input is a bounded in-memory `ScanRequest` (name plus plaintext bytes); the scanner receives no disk path, and this interface persists no plaintext. `SecurityConfig::scan` first validates TXT/PNG/GIF structure from the bytes; a mismatch is `UnsupportedFormat`. With no scanner configured, a supported format records `Unavailable`.
- `release_file` requires a validated format, a clean independent scanner outcome, policy approval, and explicit per-file `Approved` status, then returns a zeroizing `ReleasedFile`. `cancel_file` applies only to an integrity-verified transfer, is terminal for release, and retains verified ciphertext. Active transfers instead use `abort_file`, which removes only incomplete quarantine ciphertext and drops pending request state. Release itself writes no plaintext to disk. The default policy allows no extensions, so release is denied by default.
- The desktop application immediately copies an in-memory `ReleasedFile` into the encrypted attachment store: schema v3 `attachments` stores an HMAC blind index, a per-file key wrapped under `storage/attachments`, and encrypted metadata containing the base name, size, SHA-256 digest, and narrow uppercase format label. The blob at `attachments/<blind-index-hex>.ct` is XChaCha20-Poly1305 ciphertext only, and the key is never persisted in the clear.
- `read_attachment` rejects symlinks and size mismatches, decrypts into a zeroizing buffer, and rechecks the stored SHA-256 before returning bytes. `change_password` rewraps only the vault master key, so attachment blobs are not re-encrypted.
- The native-only OS save dialog is the only plaintext disk write. It decrypts into a zeroizing buffer and writes only after the user chooses a path; a cancelled dialog writes nothing. GUI-only builds show that the OS save action is unavailable.
- Stored-attachment deletion is always explicit. Quarantine deletion defaults to `QuarantineDeletionPolicy::Retain`; under `Explicit` it requires a verified transfer that was released or whose release was cancelled. These are separate actions: neither scanning, approval, release, cancellation, nor stored-attachment deletion deletes quarantine ciphertext implicitly. Filesystem deletion is not secure erasure on SSD/CoW storage.
- Unix permissions are `0700` for directories and `0600` for database/blob files. Windows ACL hardening and secure-erasure guarantees remain targets.

## 5. Durable control-frame digest log and anchor (schema v4, post-M13)

Schema v4 is applied by the same transactional migration path as v1–v3 and adds:

- `control_log (sequence, record_bi, ciphertext, chain_hash)` — one row per already authenticated signed MLS setup/group-control frame.
- `control_state (id, sequence, chain)` — the current high-water mark for that chain.

Each record plaintext contains only the public PeerId bytes, a SHA-256 digest of the **already verified** signed frame, and a repeatable flag. Frame bodies, KeyPackages, Welcomes, commits, MLS secrets, and plaintext are never recorded. Records are XChaCha20-Poly1305 ciphertext under `Purpose::Db`, with AAD binding the profile id, sequence number, and previous chain value. Lookups use HMAC blind indexes (`record_bi`) under `Purpose::BlindIndex`, computed over a domain label, peer bytes, digest, and repeatable flag. Each row's SHA-256 chain hash covers the previous chain, sequence, peer, digest, and flag, so removing or reordering rows breaks verification.

`control.anchor` in the vault directory holds the AEAD-protected high-water mark (sequence and chain) under `Purpose::Db` with profile-bound AAD. It is written through `control.anchor.tmp` (create, sync, restrict permissions, rename) as an atomic replacement. `KeyPackageRequest` and `GroupJoinRequest` are idempotent/repeatable so a lost response can be retried; Welcomes, responses, commits, and all acknowledgements are non-repeatable. The log is bounded at 4,096 records and fails closed when full rather than evicting old decisions.

`Vault::unlock` calls `verify_control_log`: every ciphertext is decrypted and parsed, sequences are contiguous, each blind index and chain hash is recomputed, `control_state` must match the reconstructed chain, and the anchor must agree. A database-only rollback with a newer anchor, an anchor ahead of or inconsistent with the database, or a tampered/missing anchor fails closed as rollback detection. A crash after the database commit but before the anchor rename is reconciled by bringing the anchor forward. Restoring the **entire** vault directory including the anchor is not locally detectable; no external anchor exists, so this is not a backup.

This log preserves only the terminal/idempotent decisions for authenticated setup/group-control frames. It does **not** restore OpenMLS group or ratchet state, pending key packages, channel metadata, or decrypted messages; MLS state remains memory-only. It is local vault state, not a wire-format change, and is unrelated to the M13 `/p2p-messenger/control/1` opaque control protocol. `MessengerController::start_with_control_log` accepts a cloned vault `Session` (`Session::try_clone`); the GUI uses it, and an identity mismatch fails startup. `docs/DECISIONS/ADR-0013-durable-control-log-and-anchor.md` records this decision.

## 6. Backups and recovery

- Backup = versioned encrypted archive containing profile settings, encrypted identity export, encrypted database export, and encrypted attachments. A dedicated passphrase derives the backup KEK with Argon2id; the archive key is independent of the login password.
- Recovery requires the archive plus its passphrase. Losing both means unrecoverable data loss; the UI states this before the user proceeds.
- Importing a backup replaces the local profile only after explicit confirmation and integrity verification.

## 7. Testing requirements

- Unit tests: AEAD round-trip, wrong key/AAD fails, blind index determinism and key separation, versioned migrations.
- Integration tests: reopen the database, verify no plaintext sentinel appears in the database file, WAL, SHM, or attachment blobs, and confirm journal cleanup.
- File tests added in M7: multi-chunk integrity verification, tampered chunk and manifest rejection, duplicate/unexpected chunk rejection, path-like name rejection, redacted `Debug`, and raw quarantine-byte scans that find no plaintext sentinel.
- M8 scanner/release tests: no-scanner/default-denial policy, exact scanner result categories, clean-result-only `ScanOutcome` construction, TXT/PNG/GIF structural validation and mismatch rejection, threat denial, extension allowlist enforcement, release-before-scan/integrity rejection, approval-required and cancellation behavior, and in-memory released bytes with redacted diagnostics.
- M8 attachment/deletion tests: encrypted at-rest round trip, another vault cannot read a blob, password change rewraps only the master key while attachments remain readable, damaged wrap rejection, size/digest recheck, symlink rejection, explicit stored-attachment deletion, default `Retain` denial, explicit quarantine deletion after release or cancellation, transfer directory removal with parent quarantine retained, and raw DB/WAL/SHM/blob scans for plaintext names, payloads, and format labels.
- Two-controller acceptance tests: validation/scan/approval/cancel/release, released bytes stored encrypted under the vault, attachment metadata readable only through the session, explicit quarantine deletion, and no plaintext sentinel in vault files or quarantine.
- GUI model tests: completed M10 milestone/security checklists (including group admin, member, pending-operation, active-channel, channel-policy, and channel-access rows), M8 attachment-storage and quarantine-deletion security rows, and honest default-status wording. M9 group-management and M10 channel tests verify multi-member operations, channel policy, and receipt state without adding persistence or plaintext-at-rest writes. Native compile and link are checked; visual inspection requires a display host.
- Security tests implemented in M12: cross-platform safe release names, an unraisable 64 MiB release cap, redacted transport-event `Debug`, Unix symlink refusal for vault/quarantine directories, attachment deletion ordering before record removal, contact URI/query caps, and identity envelope byte caps. Unix permission checks remain platform-specific; Windows ACL verification and fuzz decoders are still future work.
- Post-M13 control-log/anchor tests in `crates/storage/tests/vault.rs`: a repeatable request is `Idempotent` and a repeated terminal frame is `Replay` across vault reopen, live and reopened `verify_control_log` checks, restoring an older database while keeping the current anchor is rejected, and a tampered `control.anchor` fails unlock. The no-plaintext scan now covers `control.anchor` and `control.anchor.tmp` as well as the database, WAL, SHM, and attachment blobs.
- Controller control-log tests: an exact authenticated non-repeatable frame replay is ignored before entering the in-memory cache after reopen, while a repeatable request retry stays idempotent after reopen with a cloned vault `Session`.
- The final integrated serialized workspace run passed **207 tests with 0 failures on 2026-11-25**.
