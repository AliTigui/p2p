# ADR-0011: Milestone 12 local hardening scope

Date: 2026-11-24

Status: Accepted and implemented on the Linux host used for this workspace.

## Context

The release and application paths already avoid centralized infrastructure, store sensitive local data encrypted, and keep plaintext in bounded memory except for the explicitly user-chosen native OS save. A broader security pass could not honestly claim cross-platform ACL enforcement or secure erasure from this host: the non-Unix filesystem helpers are no-ops, and normal filesystem deletion has no SSD/CoW erasure guarantee. Broad, unverifiable claims would weaken the threat model more than narrowly tested controls improve it.

## Decision

Implement concrete, testable local hardening first:

- Reject release and suggested-save base names that are unsafe on any supported desktop platform, including path separators, control characters, leading whitespace, trailing dot/space, and Windows device names.
- Enforce a hard 64 MiB release byte cap even when a caller supplies a larger policy value.
- Keep the native OS save dialog as the only plaintext disk write, with a sanitized suggested name, refusal of a pre-existing symlink, `0600` creation on Unix, `sync_all`, and static error messages that disclose no chosen path or content.
- Refuse symlinked final paths for vault and quarantine directories on Unix; keep attachment blob reads and explicit deletions symlink-aware, and check the blob path before deleting the database record.
- Replace derived `Debug` on transport events with hand-written redacted output so opaque message, setup, and file request/response bytes are never formatted into logs.
- Bound contact URIs and their query fields before PeerId parsing, percent-decoding, or base64 decoding, and bound exported identity envelopes before header/KDF-parameter work.
- Add regression tests for every control above.

No Cargo dependency, Cargo feature, wire protocol, envelope version, MLS group, or stored data format was added.

## Consequences

The implemented controls are verified by the full locked workspace suite, feature-specific checks, the native build, and the Linux release package inspection recorded in `PROJECT_STATUS.md`.

The following stay explicitly unimplemented and are not claimed:

- Windows ACL hardening; non-Unix restrictive permission helpers remain no-ops.
- Filesystem secure erasure on SSD/CoW storage.
- Repository-wide log review and dependency advisory tooling.
- Real scanner integration, general format/MIME parsing, network-transfer cancellation, encrypted MLS persistence, and backup/restore.

Windows/macOS artifact builds, installer behavior, signing, notarization, and visual GUI inspection still require configured platform runners or desktop hosts.
