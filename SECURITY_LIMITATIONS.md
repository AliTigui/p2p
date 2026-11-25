# Security and Privacy Limitations

This document is intentionally conservative. It lists what the implementation does **not** provide. Any claim not supported by source, tests, or an external verification record should be treated as absent.

## 1. Identity limitations

- A single device Ed25519 key is reused for transport, MLS signing, outer envelope signing, setup, and file offer signatures. Cryptographic role separation, certificate chains, expiry, revocation, and authenticated rotation are not implemented.
- `Identity` is `Clone`, so private-key material can be copied to multiple in-memory owners. Underlying libp2p key zeroization behavior is not guaranteed by this repository.
- A valid signature or successful Noise handshake proves control of a key, not that the peer is the human contact you expect. Fingerprints must be compared out of band.
- There is no multi-device account model. Portable identity movement exists only through explicit encrypted export/import.

## 2. Channel and group limitations

- Restricted channels are logical partitions inside one MLS group. Every group member has the MLS group keys and could decrypt channel ciphertext it obtains. Channel sender/receiver checks control honest-client display and routing; they are not cryptographic access control.
- There is no independent MLS group per channel, no per-channel ratchet, no per-channel epoch, and no separate channel membership commit.
- The creator is the only administrator. Delegated administrators, role rotation, revocation, conflicting concurrent admin operations, and cryptographic role enforcement are not implemented.
- Setup and group-control frames have signed v2 transaction IDs, strict `(conversation_id, transaction_id, peer)` binding, and a bounded 512-entry in-memory cache of `(PeerId, SHA-256 digest)` pairs. Schema v4 adds a durable chained, blind-indexed digest log with a vault anchor: `Vault::unlock` verifies every authenticated record, chain link, blind index, and `<vault>/control.anchor`. `KeyPackageRequest` and `GroupJoinRequest` repeats stay idempotent; responses, Welcomes, `GroupWelcome`, `GroupCommit`, and all acks are non-repeatable. The log is capped at 4096 entries and fails closed when full or malformed. This is partial detection, not a replay-proof log: a full vault restored together with its anchor is not locally detectable, and state guards still carry the primary defense.
- MLS group state, pending commits, key packages, ratchets, channels, and decrypted messages remain memory-only. Restart loses them. The digest log is not a backup and does not restore OpenMLS state.

## 3. Storage and recovery limitations

- No encrypted backup/restore flow is implemented.
- Schema v4's chained control log and `<vault>/control.anchor` detect a database-only rollback and a tampered or missing anchor after a nonempty log. There is no external anchor: restoring the entire vault directory including the anchor is not locally detectable, and the digest log is not replay-proof.
- Windows ACL hardening is not implemented. Unix uses `0700`/`0600` and final-path symlink refusal for covered paths; quarantine creation also rejects ancestor symlinks and parent traversal. Vault parent-path symlinks and Windows reparse points remain gaps.
- File deletion is not cryptographic erasure on SSD, CoW, or snapshotting filesystems. The only reliable erasure story is destruction of the wrapping key.
- A fully compromised device can read decrypted messages in memory. No process isolation, secure enclave, or memory-locking mechanism is used.
- Repository-wide automated log-secret review is implemented as a static CI guard, but it cannot prove that every runtime path is free of secrets; it only rejects known unsafe macro and `Debug` derive patterns.

## 4. Network and anonymity limitations

- Direct connections expose IP addresses, connection timing, and packet sizes to peers and network observers.
- Concurrent pre-authentication handshakes are bounded (16 pending inbound and 16 pending outbound by default), and direct TCP sockets are limited to four simultaneous pre-auth upgrades per source IP by default using the same `max_connections_per_ip` value as established connections. This is not a distributed flood-capacity benchmark, and there is no OS file-descriptor tuning or guarantee against resource exhaustion from many source IPs. Relay upgrades are outside the raw-socket per-IP rule.
- Inbound application requests have an aggregate per-peer ceiling plus derived per-protocol reservations for message, setup, file, and control traffic. The reservations cannot exceed the configured aggregate ceiling, and a custom ceiling below four full frames falls back to that aggregate byte cap; this is single-peer DoS isolation, not a distributed-capacity guarantee.
- There is no Tor, SOCKS5, onion-service, I2P, mixnet, or other anonymity route. There is no fail-closed `TorRequired` mode and no DNS/IPv6 leak test.
- No padding, message-size normalization, randomized scheduling, heartbeat minimization, or traffic-analysis resistance is implemented.
- Strong anonymity and protection against global traffic correlation are not claimed.
- mDNS, Kademlia, identify, AutoNAT, DCUtR, relay, ping, and control observations are advisory. They do not establish contact trust, fingerprint verification, presence, capability, receipt, delivery, or reachability.
- AutoNAT and DCUtR are best effort and are not universal NAT traversal.
- Relay operators observe PeerIds, IP addresses, circuit metadata, timing, and frame sizes and can deny service. They do not terminate Noise and do not receive application plaintext or file keys. File transfer over observed relayed paths is disabled as a conservative policy, not because the relay can read the offer key.
- Real two-machine LAN, NAT, mDNS, Kademlia, and volunteer-relay verification has not been run on this host.

## 5. Message delivery limitations

- The offline queue is in-memory and lost on restart or vault lock.
- Transport `SentToPeer` is not delivery. Only verified MLS receipts from every expected member advance delivery state.
- Sequence gaps are not proof of malicious suppression: failed or abandoned outgoing messages intentionally create gaps.
- There is no decentralized mailbox or peer-operated store-and-forward protocol.
- No deniability claim is made. Outer Ed25519 signatures create transferable evidence of authorship at the protocol layer.

## 6. File limitations

- Integrity verification means agreement with signed hashes. It does not mean a file is malware-free or safe to execute.
- The desktop application configures no real malware scanner. With no scanner, the status is `Unavailable` and release is denied.
- Structural validation is narrow and dependency-free for TXT, PNG, and GIF only. It is not a general MIME/format parser.
- Files are never auto-executed or auto-opened.
- Active file transfers now have an inactivity deadline and a local abort, and release cancellation is separate. The pinned libp2p request-response API cannot withdraw a request already queued in the transport worker; abort stops application progress and ignores late responses, but worker-side request state lasts until its normal response or connection failure. This is not a transport-level cancellation primitive.
- Malware scanning results from a scanner are only as trustworthy as that scanner.

## 7. Cryptographic agility limitations

- The cipher suite is fixed: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- No post-quantum or hybrid KEM/signature support is implemented. No custom hybrid construction is attempted.
- Protocol versions are explicit and unknown versions are rejected, but there is no negotiated downgrade-protection framework across all future algorithms.

## 8. Software supply-chain limitations

- CI uses locked builds and a security workflow/`deny.toml` are configured. Locally installed `cargo-audit 0.23.0` and `cargo-deny 0.22.1` now pass all advisory, license, ban, and source checks for both `Cargo.lock` and `fuzz/Cargo.lock`. `cargo audit` still reports non-failing unmaintained warnings (`paste`, `proc-macro-error2`, `zbus_names`, `zvariant`, `zvariant_derive`); these are residual maintenance risks, not evidence of compromise. No green GitHub CI run is claimed.
- The advisory fixes required moving to libp2p 0.57.1 (hickory-proto 0.26.4 through libp2p-mdns 0.49.0) and the OpenMLS 0.10.0-rc.1 provider stack (crypto-bigint 0.7.11). The GUI moved to egui/eframe 0.35 to resolve the `js-sys` graph conflict. Because the OpenMLS line is a release candidate, production stability and API longevity are not claimed; the choice is documented and locked, with all 207 workspace tests re-run after the change.
- Release artifacts have SHA-256 checksums, not developer signatures, provenance attestations, or notarization.
- Builds are not bit-for-bit reproducible.
- There is no auto-updater. Users must verify checksums through an authenticated release channel.
- External GitHub Actions are pinned to 40-character commit SHAs resolved from GitHub API refs on 2026-11-25, with source tag/branch comments retained; the `dtolnay/rust-toolchain` pins freeze the `stable`/`nightly` branch heads. This removes implicit mutable-ref movement but is not action-code review, signature verification, build provenance, or a green CI result.
- Deterministic SPDX SBOMs are generated from locked Cargo metadata and included in checksummed release artifacts, but they are source/lockfile inventories, not binary composition analysis, license legal review, build provenance, or vulnerability proof.
- Six `cargo-fuzz` targets exist and short local plain-libFuzzer smoke passes completed, but no long coverage-guided campaign has been run; a deterministic `P2P1` mutation/truncation smoke test remains the only deterministic mutation guard.

## 9. Production-readiness statement

This codebase has substantial tested cryptographic and local-security foundations, but the following prevent a production-ready security claim: no cryptographic channel isolation, no role-separated identities, no encrypted MLS persistence, only partial rollback detection (database-only rollback and anchor tamper are detected; full vault including the anchor is not), no anonymity architecture, no real scanner configured, no signed release identity, and several platform-specific gaps. Treat it as a locally verified prototype with explicit hardening, not as an audited or anonymous messenger.
