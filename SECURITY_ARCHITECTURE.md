# Security Architecture

This document describes the architecture that is actually implemented in this repository. Claims are limited to properties that can be traced to source code and tests. The authoritative implementation status is in `PROJECT_STATUS.md`; the Phase 0 finding register is in `SECURITY_AUDIT.md`; non-claims are collected in `SECURITY_LIMITATIONS.md`.

## 1. Scope and evidence policy

This is a local-first, device-specific messenger. It has no mandatory account server, messaging server, database, signaling service, relay, discovery service, or update service. Zero-bootstrap direct connect is the authoritative path.

Documentation alone is not evidence for a security property. Every property below is tied to one of:

- a library primitive from an established crate (`OpenMLS`, `libp2p-noise`, `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`),
- a bounded decoder/encoder with adversarial tests,
- an authenticated state transition in `p2p-chat`,
- an encrypted-at-rest boundary in `p2p-storage`,
- or an explicit honest-status row in the GUI.

If none of those applies, the property is listed as a limitation, not a feature.

## 2. System components and trust boundaries

```text
Desktop UI (egui/eframe)
    |
    | in-process calls only; no network work on the UI thread
    v
MessengerController (p2p-chat)
    |-- MLS groups        p2p-groups  -> OpenMLS 0.10.0-rc.1
    |-- envelopes/receipt p2p-messaging
    |-- files             p2p-files   -> p2p-security
    |-- identity          p2p-identity
    |-- transport API     p2p-network -> libp2p 0.57.1
    v
Encrypted vault (p2p-storage) -> SQLite + XChaCha20-Poly1305
```

Trust boundaries:

1. **User / local device.** Controls the vault password, explicit contacts, explicit file approval, and optional network settings. A compromised device is outside the confidentiality boundary for decrypted data held in memory.
2. **Noise-authenticated transport peer.** Authenticated by PeerId during the Noise handshake. This proves control of a transport key, not a human identity or an out-of-band-fingerprint-verified contact.
3. **MLS group member.** Authenticated by MLS credentials and leaf signature keys bound to the envelope sender. This proves membership in a group state, not authorization for every logical channel unless the channel design makes that boundary cryptographic.
4. **Relay operator (optional).** Forwards opaque transport bytes. It observes PeerIds, IP addresses, timing, and frame sizes and can deny service. It does not terminate Noise and does not receive application plaintext or file keys.
5. **Discovery / NAT / identify observations (optional).** Advisory transport facts only. They never become contacts, verified peers, capabilities, receipts, or delivery state.
6. **Malware scanner (pluggable).** Receives bounded in-memory bytes and returns one exact category. It never receives a path and never writes plaintext.

## 3. Cryptographic architecture

### 3.1 Local identity

`p2p-identity` generates one device-specific bundle of independently created Ed25519 keys: `Root`, `Device`, `Transport`, `Mls`, `Application`, and `File`. The `PeerId` is derived only from the `Transport` key, which the device certificate certifies. The root certificate signs the device certificate; the device certificate signs the transport, MLS, application, and file certificates. Certificates carry a fixed-size signed binding of role, public key, issuer, device ID, validity window, and revocation bit. Only public certificates and signed rotation records are placed in a wire `IdentityProof`; private keys are never formatted for logs or `Debug`.

Wire signatures are role-specific: `Envelope` v2 and `SetupEnvelope` v3 use the `Application` role, `FileEnvelope` v2 uses the `File` role, and MLS credentials use the independent `Mls` role. Receivers derive the expected verification key from the certified proof bound to the Noise-authenticated `PeerId`, not from a self-asserted field in the frame. Adversarial tests reject wrong-role signatures, transport signatures reused as role signatures, tampered proofs, substituted proofs, expired certificates, revoked certificates, and stale/forged rotations. A root rotation is mutually signed and preserves the other role keys; a non-root role can be locally revoked by re-signing its certificate.

New vaults store the complete encrypted identity bundle. Legacy transport-only bundles are still imported through an explicit migration path and bind fresh independent role keys; they are not silently presented as a full bundle. Wire versions were changed in place (`Envelope` v2, `SetupEnvelope` v3, `FileEnvelope` v2) and legacy frames are rejected rather than negotiated.

**Current limitation:** contact-root trust anchors are not wired into `ContactPayload` or the GUI verification flow. A valid proof and signature still prove only that the Noise-authenticated peer controls the certified keys; fingerprint comparison remains out of band. Revocation is a local primitive, not a distributed revocation service. This is role separation at the primitive and wire layers, not a complete cryptographic application ACL or a stronger real-world identity claim.

P6 adds `RoleDelegation` and `resolve_delegated_grant` as local, device-signed primitives for non-root wire roles. Grants carry a caller-supplied public key, counter, validity window, and redacted `Debug`; conflicting grants at the same counter fail closed, a newer counter supersedes an older one, and expired or wrong-role grants are rejected. No directory, enterprise policy engine, admin role change, or GUI trust-anchor wiring exists, and no complete application ACL is claimed.

### 3.2 Message encryption and authentication

- Every conversation, including 1:1, is an MLS group using `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- Outer `P2P1` envelopes sign all fields except the signature and carry the actual MLS epoch.
- On receive, the controller checks envelope signature, PeerId/public-key binding, conversation ID, epoch, replay state, MLS group ID, MLS credential, leaf signature key, and sender before accepting plaintext.
- Replay protection uses a bounded message-ID cache plus a per-sender sequence high-water mark. Sequence gaps are not treated as proof of suppression; failed or abandoned outgoing sends intentionally create gaps.
- Signed setup and group-control frames use v2 transaction IDs, strict `(conversation_id, transaction_id, peer)` binding, and a bounded 512-entry in-memory cache keyed by peer and SHA-256 digest. Schema v4 adds a durable chained log of digests for already authenticated frames: encrypted XChaCha20-Poly1305 records contain public PeerId bytes (at most 64), a SHA-256 frame digest, and a repeatable flag, with HMAC blind indexes and a chained SHA-256 hash; the log holds at most 4096 entries and fails closed when full or malformed. `KeyPackageRequest` and `GroupJoinRequest` are repeatable; responses, Welcomes, `GroupWelcome`, `GroupCommit`, and all acks are non-repeatable. `Vault::unlock` verifies every record, chain link, blind index, and the AEAD-protected `<vault>/control.anchor` high-water mark; `MessengerController::start_with_control_log` takes a cloned vault `Session` (the GUI passes `session.try_clone()`) and rejects a vault/controller identity mismatch. P3 expands durable exact-retry outcomes to channel `Commit`/`Welcome` frames: outcome keys are domain-separated with channel IDs and v2 context, stored acks carry the channel binding with v1 records still readable, and parent-group and channel acks cannot be interchanged. When the 4096-entry control log is full, recording a new frame returns `StorageError::ControlLogFull` instead of silently dropping replay state. This is partial continuity across restart, not a replay-proof log or an external anchor.
- With an attached vault session, ADR-0014 Phase 4 and P1e restore joined MLS group/ratchet state, ready derived channel groups, channel policy, bounded pending operations, receipt expectations, and queued ciphertext from authenticated encrypted records. Setup KeyPackages/Welcomes and decrypted messages remain memory-only. The digest log itself is not a backup and does not restore MLS state.

### 3.3 Groups and channels

Group membership changes are MLS commits. The creator is the initial administrator; only that authenticated PeerId may start Add/Remove/Update in the current design. Commits stay pending until required acknowledgements are verified. A removed member remains at the excluded epoch and cannot decrypt later group traffic.

Channel policy and the default channel remain in the parent MLS group. The bounded `CHN1` body carries `channel_id`, revision, and create/rename/member policy frames inside parent MLS application plaintext, so all parent members still receive channel metadata. Non-default channel text and its receipts now use an independent `MlsChannelGroup` derived from `(parent conversation, channel)`; the derived group has its own membership, epoch, ratchet, replay state, and Welcome/Commit flow. Honest clients reject non-default text placed in the parent group and reject policy frames placed in a derived group. This is cryptographic exclusion for non-default text after bound setup converges, not a complete channel ACL: default traffic and policy metadata stay on the parent group. Ready derived groups are persisted under an authenticated channel label and restored with fail-closed binding checks. P1f reports parent policy receipts and derived-group readiness as separate observed states, without presenting either as a complete ACL.

`p2p-groups` exposes `channel_group_id(conversation_id, channel_id)`, a domain-separated derivation that selects an independent MLS group ID. Adversarial OpenMLS tests prove that an excluded parent member cannot decrypt channel ciphertext even with a locally created group of the same ID, and that a channel key update does not grant parent-group access. P1b adds `ChannelGroupBinding`, `ChannelKeyPackage`, `ChannelWelcome`, and `MlsChannelGroup`: the group-layer lifecycle requires an explicit parent/channel binding, rejects wrong-parent/wrong-channel KeyPackages and Welcomes, and does not expose the wrapped MLS group mutably. P1c adds signed channel setup frame variants with a `ChannelScope` covering parent conversation, channel ID, transaction, and peer, plus `validate_channel_setup_scope()` in `MessengerController`; adversarial tests reject missing, truncated, substituted, tampered, wrong-scope, and excluded-parent-member frames. P1d drives these primitives from the controller: a parent `CHN1` policy frame is acknowledged first, then the admin sends signed `ChannelKeyPackageRequest`, bound `ChannelWelcome`, and `ChannelCommit` frames; sends wait for `ChannelWelcomeAck` and required `ChannelCommitAck` receipts. Channel membership changes drop and recreate the derived group after receipt convergence; parent-member removal drops every channel group in that conversation. P1e stores ready channel groups as `p2p.app.channel-group/v1` records under the derived group ID, partitions them from parent records by label presence, and fails startup closed on wrong parent/channel binding, wrong revision/epoch/sequence, membership mismatch, pending setup, or inconsistent receipts/queues. Local conversation removal deletes the parent and every persisted derived group. P1f exposes `ChannelGroupStatus` as `DefaultOnParent`, `DerivedReady`, `DerivedSettingUp { awaited }`, or `Missing`, so GUI text labels parent policy/default traffic separately from derived text readiness. `SECURITY_REMEDIATION_PLAN.md` records the P1 closeout.

### 3.4 Local storage

- The vault master key is random and wrapped by Argon2id; changing the password does not bulk re-encrypt data.
- HKDF domain-separated subkeys distinguish database, attachments, identity, search index, backup, blind index, and a dedicated MLS-state purpose. New vaults use a seven-salt profile with `mls_key_version = 1` and protect OpenMLS rows and their anchor watermarks with `Purpose::MlsState`. Legacy six-salt profiles record `mls_key_version = 0`, derive a stable deterministic replacement salt, and keep reading/writing MLS rows under the general DB key; unknown versions fail closed. No bulk re-encryption of chained and anchored records is performed.
- Sensitive fields are XChaCha20-Poly1305 ciphertext before they reach SQLite. Blind indexes are HMACs under a dedicated subkey.
- WAL, SHM, and database files are included in plaintext sentinel scans.
- Schema migrations are versioned and reject unknown states.
- Schema v4's chained control log and `<vault>/control.anchor` (atomically replaced via `control.anchor.tmp`) detect a database-only rollback and a tampered or missing anchor after a nonempty log. There is no external anchor, so restoring the entire vault directory including the anchor is not locally detectable; full-vault rollback protection is not claimed.
- Windows ACL hardening and filesystem secure erasure are not implemented. Deletion is not cryptographic erasure on SSD/CoW storage.

### 3.5 Files

Each transfer uses a fresh random content key and transfer ID. Chunks are XChaCha20-Poly1305 with bounded AAD and size, and integrity is verified from a signed manifest plus per-chunk hashes and full SHA-256 before release is considered.

Incoming ciphertext is written to a `0700` quarantine directory; plaintext and content keys are never persisted there. Release requires byte-for-byte integrity, narrow structural validation, an exact scanner category of `CleanNoThreatDetected`, extension policy, and explicit user approval. No scanner or unsupported format fails closed. Structural validation is not malware detection.

File transfer over an observed relayed path is disabled by conservative policy. This is **not** because the relay can read the fresh content key; the pinned libp2p relay transport is Noise-protected end to end. It is a policy choice pending a dedicated relay-safe file-key/transport design; both outbound sends and inbound requests are now rejected on observed relayed paths.

## 4. Network architecture

### 4.1 Direct mode

Direct mode uses TCP + Noise + Yamux. User-supplied addresses must end in `/p2p/<peer-id>` and must not contain `/p2p-circuit`. The expected PeerId is authenticated by Noise before a connection is reported. Explicit libp2p pending-socket limits bound concurrent inbound and outbound handshakes before Noise, and a transport wrapper admits at most `max_connections_per_ip` concurrent pre-auth sockets per source IP before any Noise bytes are processed; its counter is released when the upgrade completes, fails, or is dropped. Established global/per-peer/per-IP limits and aggregate plus per-protocol request/byte budgets apply after authentication. Peerless inbound failures are advisory events and do not overwrite cached live connections. Direct mode is explicitly non-anonymous: peers observe IP addresses, timing, and packet sizes.

### 4.2 Optional capabilities

mDNS, Kademlia, relay client/server, AutoNAT, DCUtR, identify, ping, and the opaque `/p2p-messenger/control/1` protocol are startup-only, off by default, and configured from local user input. Discovery candidates are advisory and never auto-dialed, trusted, or marked fingerprint-verified. Relay paths are bounded and counted from real `is_relayed()` transport observations.

No message capability, presence, receipt, delivery, or safety semantics are derived from control frames or observations.

### 4.3 Privacy routing

There is no verified Tor, onion-service, I2P, or mixnet anonymity integration. `Direct` remains the default transport mode and is labelled non-anonymous. The Q follow-up implements two explicit route policies and one coarse length defence: `DialPolicy::RelayOnly` refuses direct application dials/listeners and requires an observed relayed path; `TransportPrivacyMode::TorRequired` selects a SOCKS5-only outbound transport with no direct listener/fallback and hands `/dns4`/`/dns6` targets to the proxy as domains; and MLS application plaintext is padded to fixed buckets with strict receive-side validation. The GUI allows these modes only in advanced settings and labels SOCKS5 status as configured, not verified. Proxy identity, real Tor behavior, DNS/IPv6/relay-reservation leak behavior, timing, volume, outer-frame sizes, metadata confidentiality, and unlinkability remain unverified; Q3 clear-metadata changes and Q4 ephemeral delegated application keys remain design-only.

## 5. Message lifecycle

1. Compose plaintext in the active channel.
2. Check local membership and pending-operation state.
3. Encrypt the bounded `CHN1` body with the MLS group key and wrap it in a signed envelope.
4. Send one ciphertext copy to each authenticated connected recipient; queue ciphertext only for offline recipients.
5. Transport `SentToPeer` means only that the request was accepted by the local network worker.
6. Receiver verifies envelope and MLS state before accepting plaintext.
7. `Delivered`/`Read` state changes only on verified MLS receipts from every expected member.

The offline queue stores ciphertext, never plaintext. It is capped at `MAX_OFFLINE_QUEUE` (16) entries; `ChatError::OfflineQueueFull` is returned before a new envelope is composed when the would-be offline recipients would exceed the cap, and vault restore fails on an oversized record. It is encrypted in the vault and restored after restart when a session is attached; without a session it is in-memory and is lost on restart or lock. No mailbox service or mandatory store-and-forward infrastructure exists.

The outer `P2P1` signature binds conversation, epoch, sender, sequence, sender-supplied time, kind, and ciphertext. A third party holding the wire bytes can verify authorship and read those fields before MLS decryption (P10); this is transferable evidence, not deniability, metadata confidentiality, or unlinkability. P9 records that the pinned OpenMLS build exposes only classical ciphersuites; no post-quantum or hybrid construction is claimed.

## 6. Metadata inventory

| Data | Generated | Stored | Observable by | Lifetime | Deletion |
|---|---|---|---|---|---|
| Vault password | User input | Never; only Argon2id-derived wrapping material in memory | Local device only | Session | Vault lock |
| Identity private keys | Local generation | Complete encrypted bundle in the vault; explicit encrypted export | Local device | Until explicit rotation/revocation | Cryptographic erasure via vault destruction/rekey |
| PeerId / public key | Local identity | Contact records where explicitly saved | Transport peers, relays | Until contact deletion | Explicit contact deletion |
| IP address | OS/network stack | Only transient connection state | Direct peers, relays, network observers | Connection lifetime | Connection close |
| Message ciphertext | Compose | Encrypted vault envelope storage when persisted; in-memory queue otherwise | Intended MLS members; relay sees opaque transport bytes | Until explicit deletion or process exit | Explicit deletion / restart |
| Message plaintext | Decrypt | Memory only for display | Local user | Until cleared/lock/restart | Lock/restart |
| MLS group state | OpenMLS | Encrypted vault rows and anchor watermarks when a session is attached; memory only otherwise | Local device | Until explicit deletion or vault destruction | Explicit deletion / vault destruction |
| Authenticated control-frame digest | Verified signed frame | Encrypted schema v4 record plus AEAD `control.anchor` in vault | Local device | Up to 4096 records | Vault destruction; not an MLS backup or external anchor |
| File content key | Fresh per transfer | Never persisted | Intended peer only over Noise | Active transfer, bounded by inactivity deadline | Completion, timeout, or abort |
| Quarantine ciphertext | Receive | `0700`/`0600` on Unix | Local device | Verified transfer until explicit deletion; incomplete transfer until timeout/abort | Explicit deletion or incomplete-transfer abort (not secure erasure) |
| Discovery candidate | Optional behaviour | Cached advisory count only | Local user | Runtime | Restart/expiry event |
| Identify agent string | Optional behaviour | Bounded cached observation | Connected peers | Runtime | Restart |

## 7. Explicit non-goals

See `SECURITY_LIMITATIONS.md`. Nothing in this document should be read as a claim of strong anonymity, global traffic-correlation resistance, a complete cryptographic channel ACL for all channel policy/default traffic, Windows ACL hardening, secure file erasure, replay-proof control frames, full-vault rollback resistance (including an external anchor), or production-ready audit status. Non-default channel text is cryptographically isolated and ready channel groups survive restart with authenticated fail-closed records; the control digest log is a partial local continuity control only.
