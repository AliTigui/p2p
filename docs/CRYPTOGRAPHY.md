# Cryptography Design

Status: design baseline with local identity, local key protection, and Noise transport implemented and tested in Milestones 1–4; initial MLS messaging in Milestone 5; network resilience in Milestone 6; encrypted chunked file transfer and ciphertext-only quarantine in Milestone 7; narrow validation, scanner input, policy/approval-gated release, an encrypted attachment store, a native-only OS save flow, and explicit deletion policies in Milestone 8; multi-member Add/Remove/Update group management in Milestone 9; logical channels inside one MLS group in Milestone 10; optional, off-by-default discovery, relay, NAT, identify, and opaque transport-control plumbing in Milestone 13. M13 adds no new cryptographic primitive. MLS state persistence, admin role delegation, cryptographic per-channel keys, general format/MIME parsing, backup/restore, transport-level cancellation of an already queued worker request, a configured independent malware scanner, strong anonymity, metadata confidentiality, universal NAT traversal, and a dedicated relay-safe file-key/transport design for enabling file transfer over relays remain design targets or non-claims.

## 1. Verified library choices (checked 2026-11-25)

| Purpose | Crate / version | Notes |
|---|---|---|
| Identity + transport | `libp2p =0.57.1` (TCP + Noise + Yamux + Tokio; M13 opt-in `identify`, `ping`, `mdns`, `kad`, `relay`, `autonat`, `dcutr`), `libp2p-identity` 0.3.1 Ed25519 | MSRV 1.88 for libp2p 0.57.1; the earlier egui/eframe 0.37 conflict was resolved by moving the GUI to 0.35. Noise authenticates the dialed PeerId. M13's fourth opaque control protocol reuses the existing bounded codec and adds no primitive. See `docs/DEPENDENCIES.md`. |
| Group messaging | `openmls` 0.10.0-rc.1 | RFC 9420 MLS, MSRV 1.94. Selected for the patched RustCrypto stack; not a production-stability claim. |
| MLS crypto provider | `openmls_rust_crypto` 0.7.0-rc.1 | RustCrypto-backed provider matching OpenMLS 0.10 RC and crypto-bigint 0.7.11. |
| MLS traits | `openmls_traits` 0.7.0-rc.1 | Matching RC line used for `Signer` and crypto access. |
| MLS state storage | `openmls_memory_storage` 0.7.0-rc.1 via `openmls_rust_crypto` | In-memory only: group state is not persisted and is lost on restart. `openmls_sqlite_storage` 0.3.0 was validated but not enabled because it would store MLS secrets unencrypted in SQLite. |
| Password KDF | `argon2` 0.6.0 | Argon2id, constant-time implementation from RustCrypto ecosystem. |
| Local AEAD | `chacha20poly1305` 0.11.0 with XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag, `alloc` feature. |
| KDF for subkeys | `hkdf` 0.13.0 + `sha2` 0.11.1 | HKDF-SHA256 with explicit info labels. |
| Secret hygiene | `zeroize` 1.9.2, optionally `secrecy` 0.10.3 | Zeroize key buffers on drop; avoid debug printing secrets. |
| QR | `qrcode` 0.15.0 on the Rust side | SVG only, no image backend or frontend renderer. Payload is versioned text; no secret material in QR. |

We do not implement any primitive ourselves. Dependency versions are re-verified before each milestone that adds them.

## 2. Local identity

- `libp2p::identity::Keypair::generate_ed25519()` using the OS CSPRNG. No MAC, IP, hostname, serial, or user name as input.
- `PeerId::from(keypair.public())` is the public identifier.
- **Fingerprint**: canonical encoding of the Ed25519 public key, SHA-256, lowercase base32 in 8-character groups, prefixed `P2PMSGR-ED25519-`. Example format (not a real key): `P2PMSGR-ED25519-AB3D 9F02 ...`. Verification compares the full fingerprint; the short prefix is only a convenience and is never sufficient.
- **QR payload**: versioned URI `p2pmsgr://contact/v1/<peerid>?pk=<base64url-public-key>` with an optional display name. It contains no private material and no central URL.
- Contact verification is an explicit user action after comparing fingerprints through an independent channel (voice, in person, another trusted channel). Until then the contact is marked `Unverified`.

### Implemented in Milestone 2 (`crates/identity`)

- Fingerprint input is the **raw 32-byte Ed25519 public key**, not protobuf framing. SHA-256 produces 32 bytes; unpadded base32 is 52 characters, rendered as six 8-character groups plus a final 4-character group. Parsing accepts spaces/hyphens but returns the canonical grouped string, and rejects bad prefixes, lengths, non-base32 characters, and uppercase input.
- Contact URI `pk` is base64url-no-pad of the **protobuf-encoded** libp2p public key, so a receiver can reconstruct the exact key and verify it derives the claimed PeerId. A mismatched PeerId is rejected before the contact is accepted.
- Encrypted identity export format: magic `P2PMSGR-IDENTITY-EXP`, version byte, KDF id byte (`1` = Argon2id), little-endian m/t/p costs, 16-byte salt, 24-byte nonce, then XChaCha20-Poly1305 ciphertext with a 16-byte tag. The whole header plus app name and `p2p-messenger/identity-export/v1` is passed as AAD, so parameter or purpose tampering fails authentication. Import bounds m/t/p to 8–512 MiB / 1–10 / 1–8 to avoid hostile-allocation denial of service.

### Device scope

Milestone 2 identities are **device-specific**. An encrypted export can be imported on another device, but that intentionally moves/copies the same private key. True multi-device identities (separate device keys linked to a common long-term identity) are **not** supported in the initial release and must not be advertised as such. Reusing one identity on two devices simultaneously breaks contact assumptions and is documented as unsupported.

## 3. Password and key hierarchy

- On first launch: username, password, local identity. Username is not an account name; it is a local label.
- Salt: 16 random bytes. Argon2id parameters stored alongside the wrapped key: memory 65536 KiB (64 MiB), iterations 3, parallelism 1, output 32 bytes. Parameters are versioned so they can be raised later; existing envelopes retain their original parameters.
- Master key: 32 random bytes, independent of the password.
- Wrapping: XChaCha20-Poly1305 with random 24-byte nonce; AAD binds application name, envelope version, profile UUID, and purpose string `master-key-wrap`.
- Subkeys: HKDF-SHA256(master key, salt = per-purpose random 16-byte salt stored in config, info = `p2p-messenger/v1/<purpose>`). Purposes: `storage/db`, `storage/identity`, `storage/attachments`, `storage/search-index`, `storage/backup`.
- Password change: generate new salt, derive new KEK, re-wrap the same master key. Data keys do not change; no bulk re-encryption.
- Password loss: no recovery without the encrypted backup/recovery key. We will not display language implying otherwise.

Rationale for 64 MiB / t=3 / p=1: meaningful offline guessing cost on commodity hardware while remaining usable on typical desktops; parameters are configurable and recorded in the envelope. This is a baseline, not a claim of resistance to a well-funded attacker.

## 4. Conversation encryption (all conversations)

**Decision: every conversation is an MLS group.** A 1:1 conversation is a 2-member MLS group. This avoids maintaining two encryption implementations.

- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420). Post-quantum ciphersuites are not available in the stable OpenMLS line; this is documented as a residual risk.
- Credential: OpenMLS `BasicCredential` contains the raw libp2p `PeerId` bytes. The MLS leaf signature key is the raw 32-byte Ed25519 public key from the vault identity, so the same key signs the MLS leaf and the outer envelope. KeyPackage acceptance validates the OpenMLS signature, requires the credential to equal the expected PeerId, requires the expected protobuf public key to derive that PeerId, and requires the leaf signature key to equal the raw Ed25519 key.
- MLS gives: forward secrecy, post-compromise security after commits/updates, group authentication, membership change semantics, epoch separation, and built-in replay protections. M9 implements signed Add/Remove/self-Update commits; removed members remain on the excluded epoch and cannot decrypt later group traffic. Durable MLS state restoration remains a target.
- Application messages carry typed content: text, reply, receipt, pin, policy update, file descriptor, channel metadata. Text, receipts, and bounded `CHN1` channel text/policy bodies are exercised by current tests; the other reserved kinds are not implemented.
- Outer envelope (signed by the identity key): protocol version, conversation ID, MLS epoch, message ID (random 128-bit), sender PeerId, sender sequence number, content type, creation timestamp. The recipient verifies the envelope before attempting MLS decryption; MLS verifies group ID, epoch, credential, member set, and leaf signature key.
- Timestamps are untrusted hints. Ordering uses sender sequence number within an epoch, with epoch boundaries from MLS.
- Implemented in `crates/groups`: group creation with the conversation ID as `GroupId`, KeyPackage generation with retained in-memory provider, Add + Welcome join, encrypted compose/receive, encrypted receipts, rejection of re-signed tampered ciphertext or foreign sender/credential mismatch, and M9 `add_member_parts`/`remove_member`/`self_update_commit`/`process_commit` with operation and target binding.
- M9 group policy is application-level: the creator is the admin, and only that identity may start Add/Remove/Update. Commits are signed at the `MLS1` frame layer and checked against the authenticated sender and declared operation before merging. A joiner receives the new epoch through the Welcome, not by applying the Add commit.
- M10 channels are `CHN1` plaintext bodies encrypted by the same MLS application path. The outer signed envelope and MLS sender binding authenticate the writer; `channel_id` is inside the authenticated application body, not a new envelope field. Channel membership is local policy, not a separate key boundary.
- Not implemented: MLS state persistence, admin role delegation, cryptographic per-channel keys, external commits, and automated policy distribution. In-memory state is never written to disk in plaintext but is lost on restart.

## 5. File encryption (Milestones 7 and 8 implemented)

A file transfer is **not** an MLS `MessageKind::File` and the transfer itself is not stored in an attachment table. It uses the separate `/p2p-messenger/file/1` protocol over the same Noise-authenticated connection, with application-level Ed25519 signatures on every frame. After policy-gated release, the desktop application may copy the in-memory plaintext into the encrypted attachment store described below. ADR-0007 records the format and status decisions.

- **Transfer key**: a fresh random 32-byte key is generated for each transfer, held in a `Zeroizing` buffer, carried only inside the signed `Offer`, and never persisted. The content key is protected by Noise on the wire on both direct and relayed paths: with pinned `libp2p 0.56` the relay client transport uses the same Noise upgrade as direct TCP, so a relay forwards opaque bytes and cannot read the offer or the content key. It can still observe PeerIds, IPs, timing, and sizes. File transfer is conservatively disabled on observed relayed paths pending a dedicated relay-safe file-key/transport design; this is a metadata/policy choice, not a claim that the relay sees the key.
- **Chunk AEAD**: `XChaCha20-Poly1305` from the already validated `chacha20poly1305 0.11.0`. Each chunk of at most 256 KiB uses its own random nonce and AAD `p2pmsgr-file-chunk-v1 || transfer_id || index || chunk_count || exact_plaintext_length`. The AAD binds ordering, total count, and length; out-of-order, duplicate, truncated, or tampered chunks fail closed. Files are limited to 64 MiB and 256 chunks.
- **Integrity**: SHA-256 per chunk and over the full plaintext, plus a domain-separated manifest commitment over transfer ID, chunk count, all chunk hashes, and the full hash. The commitment hash is signed in the offer, so the later signed manifest cannot be substituted. Verification decrypts ciphertext chunk by chunk in bounded zeroizing buffers, compares every hash, and checks the full digest. `IntegrityVerified` means byte agreement only.
- **At rest in M7**: the receiver writes only AEAD ciphertext into a `0700` quarantine directory (`0600` chunk files on Unix), plus a hash-only manifest record. No plaintext or content key is written to quarantine. Restricted permissions are enforced on Unix; equivalent ACL work remains a platform target.
- **M8 validation/scan/release boundary**: `SecurityConfig::scan` first performs dependency-free structural checks for TXT (UTF-8 without disallowed control bytes), PNG (signature/chunk/CRC/IHDR/IEND), and GIF (header/block/trailer). A claimed-format mismatch returns `UnsupportedFormat` before scanning. An application-supplied `FileScanner` then receives a bounded in-memory plaintext buffer and returns one exact category. Only `SecurityConfig::scan` can create a `ScanOutcome`; a clean category and validated format cannot be fabricated by integrity checking or by another application caller. Policy release requires that outcome, a validated format, a safe base name, non-empty bounded size/chunk count, an explicit extension allowlist, and explicit per-file `Approved` status. `ReleasedFile` is zeroizing memory; the desktop app copies it into the encrypted store, and the native OS save dialog writes plaintext only to a user-chosen path. The default app config has no scanner and no allowed extensions. `cancel_file` is terminal for release of an integrity-verified transfer and keeps verified ciphertext in quarantine; an active transfer instead has an inactivity deadline and `abort_file`, which zeroizes its fresh content key and removes incomplete ciphertext.
- **Still not implemented**: general format/MIME parsing, media previews, a configured real scanner, backup/restore, and transport-level cancellation of an already queued worker request. Structural validation is not malware detection; a "clean" or "safe" file status must not be shown without a real independent scanner result.

The `storage/attachments` subkey is used by M8. `Session::store_attachment` creates a random 16-byte ID and a random per-file key; the ID is HMAC blind-indexed with the profile ID and used as both the primary key and blob filename. The per-file key is wrapped under `storage/attachments` with profile/blind-index AAD, and the blob is XChaCha20-Poly1305 ciphertext at `attachments/<blind-index-hex>.ct`. Name, size, SHA-256 digest, and narrow uppercase format label are encrypted under that per-file key. Reads reject symlinks, check the bound and stored size, recheck the digest, and return a zeroizing buffer. Deletion is explicit; `change_password` rewraps only the vault master key. Attachments are single bounded ciphertext records up to 64 MiB, so there is no separate attachment chunk-AAD scheme.

## 6. Metadata and privacy hardening (M13, implemented)

M13 introduces no new cipher, KDF, signature scheme, or key hierarchy. It enables optional libp2p behaviours that are off/empty by default and adds a fourth bounded request-response protocol, `/p2p-messenger/control/1`, that reuses the existing 1 MiB opaque frame codec.

- The control protocol is deliberately not signed or MLS-encrypted at the application layer. It has no cryptographic meaning: it cannot authenticate a human, grant a capability, acknowledge a message, or prove presence. The controller drains its events and records no application state from them.
- Identify, when explicitly enabled, hides listen addresses, pushes no address updates, uses a long interval, and bounds protocol/agent strings before they enter events or diagnostics. It reveals a bounded protocol/agent description to connected peers and does not authenticate the person behind the PeerId.
- mDNS/Kademlia discovery and relay/NAT observations are advisory metadata. Kademlia needs user-supplied direct bootstrap addresses; `/p2p-circuit` and peerless addresses are rejected. Discovered candidates are never auto-dialed or promoted to trusted/verified contacts.
- Relay operators see PeerIds, IP addresses, timing, and sizes and can deny service, but the Noise upgrade means they forward opaque bytes and do not receive private keys, message keys, or file keys/application plaintext. Relayed connections are capped/counted from real transport observations. The signed file offer carries the fresh content key inside Noise-protected bytes; file transfer is nonetheless refused on observed relayed paths as a conservative metadata/policy choice until a dedicated relay-safe file-key/transport design exists. Relay reservation/circuit counters describe events observed since startup, not live state.
- AutoNAT and DCUtR are best-effort observations/hole-punch attempts; ping is liveness only. `NetworkPrivacyStatus` separates local configuration from fact-derived counters and strings, so the GUI cannot present a configured option as an observed capability.
- There is no strong anonymity, Tor/I2P/mixnet, metadata confidentiality, unlinkability, universal NAT traversal, or cryptographic channel ACL added by M13.

## 7. Non-goals / residual risks

- No quantum-resistant conversation cipher in the initial stable release.
- No anonymity network integration. Peer IPs are visible to direct peers and to user-chosen relays; optional discovery reveals queries/candidates to user-chosen peers. Tor/I2P/mixnet support, metadata confidentiality, and unlinkability would be separate designs. M13 relay/NAT/identify features do not provide them.
- MLS group state is memory-only in this milestone; a compromised device can read history available to that member, and a restart loses the MLS session. Forward secrecy limits past traffic, not data still stored locally.
- File integrity is not malware safety. M8 adds narrow structural validation, an application-supplied scanner interface, release policy, explicit approval, an encrypted attachment store, and a user-chosen native OS save path, but no scanner is configured in the desktop app and no general file-type parser exists. The attachment store does not make an unscanned file safe; `IntegrityVerified` and structural validation must never be rendered as "clean".
- Application-level admin permissions and channel memberships are policy enforced by clients, not a cryptographic role or key system. The creator-as-admin M9 design and its limits are recorded in ADR-0008; the M10 channel design and its non-ACL limitation are recorded in ADR-0009. All MLS group members hold group keys, so a restricted channel is not a confidentiality boundary against another group member.
