# ADR-0007: Encrypted file transfer v1 with honest scan status

- Status: Accepted
- Date: 2026-11-24

## Context
Milestone 7 needed file sharing with no mandatory server, no new runtime dependency, and no false claim that an integrity check is a malware scan. The existing direct connection is authenticated by libp2p Noise and already carries three bounded application protocols. No independent scanner is configured, and relay support is not implemented.

## Decision
Use a separate `/p2p-messenger/file/1` request-response protocol over the existing authenticated Noise connection, not an MLS `MessageKind::File` envelope.

- Every frame has fixed `FILE` magic, version `1`, an Ed25519 signature, a 16-byte transfer ID, and a strict bounded decoder. The signed sender must match the authenticated peer.
- Each transfer generates a fresh random 32-byte content key. It is carried only in the signed `Offer` over Noise and is never persisted. With pinned libp2p 0.56, a relay forwards the Noise-protected bytes and cannot read that key; file transfer over relays remains disabled as a conservative metadata/policy choice until a dedicated relay-safe file-key/transport design exists.
- Plaintext is capped at 64 MiB, split into at most 256 chunks of at most 256 KiB. Each chunk uses XChaCha20-Poly1305 with a fresh nonce and AAD binding domain, transfer ID, index, chunk count, and exact plaintext length.
- SHA-256 hashes per chunk and over the full plaintext are committed by a domain-separated manifest hash included in the signed offer. The signed manifest is verified before a transfer is marked complete.
- Incoming chunks are written to a restricted quarantine directory as ciphertext only; plaintext and the content key never reach disk. Decryption for hash verification happens in bounded zeroizing memory.
- Status is limited to `AwaitingAccept`, `Sending`, `Receiving`, `IntegrityVerified`, and `Failed`. Scanner status is `NotApplicable` before verification and `Unavailable` afterward. No `Clean`, `Safe`, or `Scanned` state exists.

## Consequences
- File transfer works with the same zero-infrastructure direct connection as messaging. No discovery, relay, or developer-operated service is involved.
- No new external dependency was needed: the AEAD, SHA-256, randomness, zeroizing buffers, signatures, local-data path, and typed errors were already validated for earlier milestones.
- Integrity verification proves byte agreement only. Users must not be told a file is safe or clean without an independent scanner result.
- Not implemented in M7: per-file approval, cancellation, attachment storage/release, extension/MIME policy, format validation, media previews, and scanner integration. Those belong to Milestone 8 before any release-from-quarantine path exists.
- M8 update: an application-supplied scanner interface, exact result categories, a `ScanOutcome` construction boundary with private validated format, dependency-free TXT/PNG/GIF structural validation, a conservative extension policy, explicit per-file approval/cancellation, and an in-memory release path are now implemented at the Rust API level. A format mismatch returns `UnsupportedFormat` before scanning; release requires validated format, clean scan, policy, and explicit approval. Cancellation is terminal for release of a verified transfer and retains ciphertext. Active transfers use a separate inactivity deadline and `abort_file`, which stops application progress, drops pending request bookkeeping, zeroizes the key, and deletes incomplete quarantine ciphertext; a worker request already queued in libp2p cannot be withdrawn through the pinned request-response API, so late responses are ignored. The desktop app still configures no scanner or allowed extensions, so no approve/release/cancel action appears by default.
- M8 completion addendum: approved release is copied into an encrypted attachment store, not written as plaintext by the release path. Each attachment has a random ID, a profile-bound HMAC blind index, a random per-file key wrapped under `storage/attachments`, XChaCha20-Poly1305 ciphertext blob storage, and encrypted name/size/digest/format metadata. Reads recheck size and SHA-256 into a zeroizing buffer. The native-only OS save dialog is the only plaintext disk write and requires a user-chosen path; a cancelled dialog writes nothing. Quarantine deletion defaults to `Retain`; under `Explicit`, deletion requires a verified transfer that was released or cancelled. Attachment deletion and quarantine deletion are separate explicit actions, and filesystem deletion is not secure erasure on SSD/CoW storage.
- Still not implemented: general format/MIME parsing, a configured real scanner, backup/restore, and transport-level cancellation of an already queued worker request. Structural validation is not malware detection, and no clean or safe status is claimed without an independent scanner result.
