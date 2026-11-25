# Wire and Application Protocol (v1)

Status: **Milestones 5–10 and 13 implemented and tested** for two- and three-member MLS group lifecycles. Canonical envelope encoding, signature verification, replay checks, MLS ciphertext, encrypted receipts, receipt-driven delivery transitions, ciphertext-only persistence, the signed MLS setup and group-control exchange, the application controller, the GUI send/receive path, four bounded request-response protocols over the Noise-authenticated connection (the fourth is M13's opaque control protocol), the in-memory offline send queue with reconnect-triggered retry, bounded redial/backoff, duplicate-dial rejection, connection admission limits including a relayed-connection cap, per-peer request/byte budgets, admin-only Add/Remove/Update with pending acknowledgement state, group-wide delivery receipts, bounded `CHN1` channels inside one MLS group, encrypted chunked file transfer with ciphertext-only quarantine, narrow TXT/PNG/GIF structural validation, an in-memory scanner/policy/approval release gate, an encrypted attachment store, a native-only OS save flow, explicit deletion policies, and opt-in user-configured discovery/relay/NAT/identify plumbing are implemented and tested locally. MLS state persistence, read-receipt UI, role delegation, cryptographic per-channel keys, general format/MIME parsing, a configured real scanner, strong anonymity, universal NAT traversal, and end-to-end file keys over relays are **not implemented or claimed**; the desktop app configures no malware scanner and no optional network feature by default, so file status never claims a scan result.

## 1. Transport negotiation

Four protocols are negotiated with libp2p multistream-select over the existing authenticated Noise + Yamux connection using `libp2p-request-response 0.29.0`:

- `/p2p-messenger/message/1` — signed MLS ciphertext envelopes and encrypted receipts.
- `/p2p-messenger/mls-setup/1` — signed KeyPackage, Welcome, WelcomeAck, and group-control frames (commit/Welcome/acknowledgement).
- `/p2p-messenger/file/1` — signed, encrypted file offer/chunk/manifest frames (section 10).
- `/p2p-messenger/control/1` — M13's bounded opaque control frames; transport observations only (section 11).

Peers register all four protocols as `Full` (inbound and outbound). Unknown protocol names are rejected; protocol version `1` is fixed, and a future version must be added explicitly rather than selected by "highest wins". Message streams are capped at 8 concurrent requests; setup, file, and control streams at 4 each. A 10-second timeout covers connection and request operations. Established connections are additionally capped globally, per authenticated PeerId, and per observed IP, with a separate cap for relayed connections; inbound application requests are capped per peer with a shared sliding request-count and byte budget before the application decoder sees them. Control frames carry no presence, capability, receipt, delivery, trust, or safety meaning.

The request and response of every protocol use a bounded frame: `u32 big-endian length || opaque bytes`. Empty frames and frames larger than 1 MiB are rejected before the body is read. The transport does not verify signatures, decrypt MLS data, or decide delivery/setup/transfer state; the application must decode and verify before calling any state transition.

### Implemented transport API

- `Network::send_message(peer, bytes)` queues an opaque request only to an already-connected, Noise-authenticated peer and returns a local `MessageRequestId`.
- `Network::respond_to_message(id, bytes)` sends the application's verified receipt response.
- `MessageEvent::SentToPeer` means the request was handed to the libp2p behaviour. It never means delivered.
- `MessageEvent::RequestReceived` carries the raw request and a `MessageResponseId`; the application must verify and decrypt the envelope before responding.
- `MessageEvent::ResponseReceived` carries raw response bytes; the application must verify and decrypt the receipt before changing delivery state.
- `MessageEvent::Failed` reports static, non-secret failure categories only.
- `Network::send_setup(peer, bytes)` queues an opaque setup request to an already-connected peer and returns a local `SetupRequestId`; it does not mean the peer joined.
- `Network::respond_to_setup(id, bytes)` sends the application's verified setup response.
- `SetupEvent::SentToPeer` means the frame was handed to libp2p; `SetupEvent::RequestReceived` and `SetupEvent::ResponseReceived` carry raw frames that must be verified before MLS state changes; `SetupEvent::Failed` reports static non-secret reasons.
- `Network::send_file(peer, bytes)` queues an opaque signed file frame to an already-connected peer and returns a local `FileRequestId`; it never means the file was received or verified.
- `Network::respond_to_file(id, bytes)` sends the application's verified file response.
- `FileEvent::SentToPeer` means the frame was handed to libp2p; `RequestReceived` and `ResponseReceived` carry raw signed frames; `Failed` reports static non-secret reasons. No file event claims transfer completion or a scan result. `send_file` refuses peers with an observed relayed connection because the signed offer carries the fresh content key.
- `Network::send_control(peer, bytes)` queues an opaque control request to an already-connected peer and returns a local `ControlRequestId`; it derives no application capability.
- `Network::respond_to_control(id, bytes)` sends the application's opaque response.
- `ControlEvent::SentToPeer`, `RequestReceived`, `ResponseReceived`, and `Failed` report only transport observations. The controller drains them; it never turns a control frame into presence, capability, receipt, delivery, trust, or safety state.
- M13 additionally exposes `poll_discovery_event`, `poll_relay_event`, `poll_nat_event`, `poll_identify_event`, and `privacy_status()`. These update a bounded `NetworkPrivacyStatus` only; discovery candidates are advisory and never auto-dialed or promoted to contacts.

### MLS setup and group-control frame (v1, implemented)

Setup frames use fixed magic `MLS1`, a `u16` version (`1`), a `u8` message code, the 16-byte conversation ID, length-prefixed sender public key, sender PeerId bytes, body, and a 64-byte Ed25519 signature. All multi-byte length fields are little-endian. The signature covers every preceding field and is made by the vault identity. A frame is accepted only when the signer public key derives the declared PeerId **and** the declared PeerId equals the Noise-authenticated transport peer.

| Code | Message | Body |
|---|---|---|
| `1` | `KeyPackageRequest` | empty |
| `2` | `KeyPackageResponse` | encoded MLS KeyPackage |
| `3` | `Welcome` | encoded MLS Welcome |
| `4` | `WelcomeAck` | one byte: `1` accepted, `0` rejected |
| `5` | `GroupJoinRequest` | empty |
| `6` | `GroupKeyPackageResponse` | encoded MLS KeyPackage |
| `7` | `GroupWelcome` | encoded MLS Welcome |
| `8` | `GroupCommit` | operation code, optional target flag/bytes, encoded MLS commit |
| `9` | `GroupCommitAck` | operation code plus one byte: `1` accepted, `0` rejected |
| `10` | `GroupWelcomeAck` | one byte: `1` accepted, `0` rejected |

Group operations are `Add = 1`, `Remove = 2`, and `Update = 3`. Unknown codes, an unknown operation, an invalid target flag, a truncated target PeerId, an empty commit, trailing bytes, and invalid acknowledgement lengths are rejected before state changes. KeyPackages, Welcomes, and commits are opaque to the transport. `p2p-chat` verifies the signed frame against the authenticated peer before passing bytes to `p2p-groups`; `MlsConversation::add_member`, `join`, and `process_commit` still enforce MLS credential, PeerId, public-key, operation, sender, and epoch binding. `Debug` output reports body length only and never prints KeyPackage, Welcome, or commit bytes.

The controller flow is:

1. The inviter creates an in-memory MLS group, records `KeyPackageRequested`, and sends a signed `KeyPackageRequest` to an already-connected peer.
2. The responder generates a `MlsKeyPackage`, retains its in-memory provider in a pending map keyed by conversation ID, and returns a signed `KeyPackageResponse`.
3. The inviter verifies the frame and peer, calls `add_member`, records `WelcomeSent`, and sends a signed `Welcome`.
4. The responder finds the pending `MlsKeyPackage`, joins with OpenMLS, records `Joined`, and returns a signed accepted `WelcomeAck`. A failed join returns a rejected acknowledgement instead of creating fake group state.
5. Only after verifying the accepted `WelcomeAck` does the inviter record `Joined`. Setup status is never inferred from a request being handed to libp2p.

#### Group-control flow (M9)

1. The admin calls `add_member` for a directly connected peer, sending a signed `GroupJoinRequest`. The responder generates a fresh `MlsKeyPackage` and returns `GroupKeyPackageResponse`; this is allowed for a conversation the responder does not yet have, but not for an existing local conversation ID.
2. The admin verifies the response, calls `add_member_parts`, adds the peer to its local member set, records `pending_operation = Add`, sends the new member a `GroupWelcome`, and sends the same signed commit to every other existing member. The joiner is excluded from that commit's acknowledgement set because it receives the new epoch through the Welcome.
3. The joiner verifies the signed Welcome against the connected admin and learns the admin from that frame, joins with OpenMLS, and returns `GroupWelcomeAck`. It must not apply the Add commit that created its epoch.
4. Each existing member verifies the signed `GroupCommit`, checks the declared operation/target/sender with MLS, merges the commit, and returns `GroupCommitAck`.
5. The admin clears `pending_operation` only after the Welcome and all required CommitAck frames are accepted. Until then, messages and new group operations are rejected. Pending requests are retried on reconnect; no timeout or partial success is reported.
6. `remove_member` and `update_member_key` follow the same commit/ack flow without a Welcome. A removed member is excluded from the local member set and remains on the old epoch; remaining members advance to the new epoch and reject stale-epoch ciphertext. Self-removal is denied.

There is no dedicated setup/group-control replay cache in this milestone. Request correlation, pending-KeyPackage and pending-operation ownership, membership checks, and terminal-state guards reject late or unexpected frames; a duplicate KeyPackageRequest can still overwrite pending state. A restart invalidates both the MLS session and all pending setup/group state.

## 2. Envelope (v1, implemented)

```
struct Envelope {
  version: u16,                    // 1
  protocol: [u8; 4],               // "P2P1"
  conversation_id: [u8; 16],       // random, stable; also the MLS GroupId
  epoch: u64,                      // current OpenMLS group epoch
  message_id: [u8; 16],            // random, unique per sender
  sender_public_key: Vec<u8>,      // protobuf PublicKey, bound into signature
  sender: PeerId,                  // public; must match sender_public_key
  sender_sequence: u64,            // monotonic per conversation per sender
  created_at: i64,                 // sender hint, untrusted, display-only
  kind: MessageKind,               // Text | Reply | Receipt | Pin | Unpin | Policy | File | Channel
  payload: Vec<u8>,                // MLS ciphertext produced by p2p-groups
  signature: [u8; 64],             // Ed25519 over canonical bytes excluding signature
}
```

The protobuf public key is included because a PeerId is a multihash and cannot independently verify an Ed25519 signature. It is covered by the signature and checked against the declared PeerId before verification. A valid signature proves control of that key, not that the person is the intended contact; fingerprints are compared out of band.

Encoding is canonical little-endian length-prefixed binary. Limits: total envelope ≤ 1 MiB, payload ≤ 1 MiB − 1024 bytes, sender public key ≤ 256 bytes, PeerId bytes ≤ 128 bytes. Unknown versions, wrong magic, bad kind codes, truncated fields, trailing bytes, and oversized fields are rejected without panics.

`crates/messaging` does not interpret the payload as plaintext. `MlsConversation::compose` creates the MLS application message first and places only its TLS-serialized ciphertext in `Envelope.payload`. `MlsConversation::receive` verifies the outer envelope, decrypts with OpenMLS, checks that the MLS credential/member signature key match the envelope sender, and only then records receive/receipt state.

## 3. MLS group setup, management, and message encryption (implemented)

Every conversation, including 1:1, is an MLS group using ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and OpenMLS 0.9.2.

1. The creator calls `MlsConversation::new`; the MLS `GroupId` is the 16-byte conversation ID.
2. A joining peer calls `MlsConversation::key_package`. The returned `MlsKeyPackage` owns the in-memory OpenMLS provider holding the private key material required to decrypt the Welcome; encoded bytes alone are not enough.
3. The creator calls `add_member(key_package.bytes(), expected_peer, expected_public_key)`. The KeyPackage is decoded and validated, its BasicCredential must contain the expected PeerId bytes, and its leaf signature key must equal the raw Ed25519 key derived from the expected protobuf public key. The public key must derive the expected PeerId.
4. `add_member` commits the Add and returns a Welcome. The joining peer calls `MlsConversation::join` with the original `MlsKeyPackage` and that Welcome.
5. `compose` creates an MLS application message and signs an envelope carrying its ciphertext. `receipt` uses the same path for an encrypted `Receipt` body.
6. `receive` verifies the outer signature, conversation binding, and epoch before OpenMLS decryption. It checks the processed MLS group ID, epoch, BasicCredential peer bytes, member set, and member signature key against the envelope sender. Decrypted plaintext is held in a `Zeroizing` buffer and is never persisted.

The wire setup exchange in section 1 drives these same API calls through `MessengerController`. The controller retains the pending `MlsKeyPackage` until `join`, keeps all conversations and decrypted text in memory, and renders only observed status. It composes text only for a conversation whose verified status is `Joined`.

MLS group state is memory-only in this milestone. It is never written to disk in plaintext, but it is not restored after restart. KeyPackages, Welcomes, commits, channel metadata, and pending acknowledgements must therefore be exchanged in the same running session as the operation, and a restart invalidates the local MLS session. Member removal, update commits, admin-only policy, and logical channels are implemented as described in sections 1, 4, and 7; role delegation, cryptographic per-channel keys, and group-state persistence are not implemented.

## 4. Application message kinds

Kinds have fixed codes and are never renumbered:

- `Text` — body; text application bytes are carried as MLS application messages.
- `Reply` — body plus referenced authenticated message ID.
- `Receipt` — `Delivered` or `Read` for a referenced message ID; the body codec is canonical, and `MlsConversation::receipt` encrypts it as MLS application data.
- `Pin` / `Unpin` — policy message; not implemented.
- `Policy` — group/channel admin changes; not implemented.
- `File` — reserved descriptor kind; not implemented. Milestone 7 file transfer uses the separate `/p2p-messenger/file/1` protocol below, not an MLS `MessageKind::File` envelope.
- `Channel` — fixed code `8`; bounded `CHN1` text and channel policy bodies inside one MLS group (M10, implemented).

Text-style application bytes, the receipt body codec, and `CHN1` channel text/policy bodies are exercised by the current API/tests. Other kinds have reserved codes but no application codec or policy implementation.

### Channel application frames (M10, implemented)

`MessageKind::Channel` uses the same signed v1 envelope and MLS application path as text. M10 added no envelope v2, setup code, transport protocol, or per-channel MLS group; M13's fourth transport protocol is an unrelated opaque control channel and is not used for channel text. After OpenMLS decryption and sender binding, `p2p-chat` strictly decodes a `CHN1` plaintext body:

| Field | Meaning |
|---|---|
| magic | fixed `CHN1`; unknown magic is rejected |
| kind | `1` Text, `2` Create, `3` Rename, `4` SetMembers; unknown kinds are rejected |
| revision | `1` for create; metadata changes require current revision plus one |
| channel_id | 16-byte channel identifier inside authenticated application content |
| body | length-prefixed text, or name/member set for policy frames |

Limits are 4,096 bytes per frame, 2,048 bytes of text, 64 bytes for a name, 64 members, and 16 channels per group. Peer IDs, names, member counts, lengths, and trailing bytes are strictly validated. The default channel ID is `[0; 16]` with name `general`; it exists in every joined conversation, and its membership follows the MLS group. The admin alone may create/rename/set members; explicit member lists must already be MLS group members, while an empty create list means all current members. Any local peer and named recipient who are both MLS and channel members may post text, which is sent only to allowed channel recipients. Channel metadata is broadcast to all group members, remains receipt-gated for local `acknowledged` status, and is not replayed to later joiners. Receipts remain legacy raw MLS receipt bodies; `channel_id` is not added to them. Channel membership is local application policy, not cryptographic access control, because every group member holds the MLS group keys.

## 5. Receipt semantics (implemented state machine)

- `Composed` — accepted by the local runtime and signed; nothing sent yet.
- `Queued` — accepted by the in-memory offline queue when the peer is observed as disconnected. The queue stores the signed MLS ciphertext envelope only; plaintext display text is memory-only and never persisted by `p2p-chat`.
- `SentToPeer` — handed to an encrypted transport stream; **not** proof of delivery.
- `Delivered` — explicit MLS-encrypted `ReceiptStatus::Delivered` received for the exact message ID.
- `Read` — explicit MLS-encrypted `ReceiptStatus::Read` received for the exact message ID.
- `Failed` — rejected, expired, or failed in queue.

The UI must never collapse `SentToPeer` into `Delivered`. Receipts for unknown message IDs are rejected. A `Delivered` receipt cannot downgrade `Read`, and terminal states are not overwritten by later transitions.

### Offline queue retry (implemented)

For a multi-member conversation, `p2p-chat` composes and signs the envelope once and sends that same envelope to every current member. When a recipient is observed as disconnected, the message is marked `Queued` and only its ciphertext bytes are stored in one per-recipient in-memory queue entry; other connected recipients receive the frame immediately. Repeated polls while disconnected do not retry. `poll` retries a recipient's queue only after consuming an observed `ConnectionState::Connected` event that includes that recipient and only while the cached network state still shows it connected. A retry reuses the original envelope and message ID, moves that recipient's pending receipt from `Queued` to `SentToPeer`, and requires a separate verified MLS receipt from every expected recipient before the local message becomes `Delivered`. The queue is not persisted and is lost on restart or lock.

### Automatic redial (implemented)

`connect` saves only a user-supplied address; nothing is discovered or defaulted. An observed `ConnectionState::Disconnected` or an attributed `ConnectionState::Failed` schedules a retry after a base delay that doubles up to a configured maximum. The initial user dial does not count; automatic attempts stop at `max_redial_attempts`. A user `disconnect_all` suppresses redial until a fresh explicit address is supplied. `RedialState` reports `NoSavedAddress`, `Idle`, `Suppressed`, `Scheduled { attempt, delay, remaining }`, `Dialing { attempt }`, or `Exhausted { attempts }`. These are scheduler intents, not connection claims, and they never change message delivery state. Automatic redial can cause a new `Connected` event, and only that observed event can trigger queued-message retry.

## 6. Replay and ordering (implemented)

- A bounded cache rejects duplicate `(conversation_id, sender, message_id)` triples.
- A strict per-sender high-water mark rejects repeated or regressed `sender_sequence`.
- Envelopes for a different conversation, a different epoch, or a failed signature are rejected before replay state is touched.
- `created_at` is display-only and never used for ordering.
- Incoming envelopes are sorted by `(epoch, sender_sequence, message_id)` after verification.
- OpenMLS validates the group epoch and MLS authentication on the encrypted body. The outer envelope epoch is compared with both the local conversation epoch and the decrypted MLS epoch.

## 7. Group membership changes (implemented in M9)

Implemented now:

- Initial Add via KeyPackage + Welcome, epoch advance in creator and joining peer, and binding of PeerId and Ed25519 public key into the MLS credential/leaf signature key.
- Admin-only Add of a connected member to an existing group through signed `GroupJoinRequest`/`GroupKeyPackageResponse`/`GroupWelcome`/`GroupCommit` frames. The joiner receives the new epoch from the Welcome and does not apply that Add commit.
- Admin-only Remove with an MLS Remove commit. The admin and remaining members advance epochs; the removed member stays on the excluded epoch and cannot read future group messages or send readable stale-epoch messages.
- Admin-only `Update` of the admin's own MLS leaf key. Every other member must acknowledge the commit before the operation completes.
- Signed commit verification against the authenticated sender and the declared operation/target before MLS state changes; strict codecs reject malformed operation and target encodings.
- Pending-operation state blocks messages and further group changes until the Welcome and all required CommitAck frames are verified. Pending commits are retried when required members reconnect; no partial completion is reported.
- Group text broadcast with one ciphertext envelope copy sent to each current member and `Delivered` only after all expected member receipts arrive.

Implemented in M10: logical channels are application frames in one MLS group as described above; they create no MLS commit or epoch. Target, not implemented: external commits, admin role delegation/changes, cryptographic per-channel keys, MLS state persistence, and automated channel/group policy distribution. Future changes must continue to distribute new epoch secrets only to current members and reject stale epochs.

## 8. Error handling (implemented locally)

Typed `MessageError` variants include: `UnsupportedVersion`, `BadProtocol`, `TooLarge`, `Truncated`, `TrailingBytes`, `BadKind`, `BadSignature`, `BadPeerId`, `NotEd25519`, `Replay`, `SequenceRegression`, `UnknownMessage`, `WrongConversation`, `EpochMismatch`, `SequenceExhausted`, `InvalidReceipt`, `InvalidStateTransition`, `MissingConversationId`, `WrongLocalIdentity`, `ReplayCacheFull`, `Randomness`, `Identity`, and `Storage`.

`GroupError` reports static MLS categories such as group setup failure, oversized group messages, sender credential mismatch, and epoch mismatch. `ChatError` reports static application categories such as unexpected sender, not admin, not a group member, group operation pending/rejected, invalid group target, pending KeyPackage missing, conversation not ready, invalid peer ID, invalid channel frame, channel not found/already exists/limit reached, not a channel member, and channel revision conflict. No key material, plaintext, KeyPackage/Welcome/commit bytes, or OpenMLS debug output is retained in errors. Wire failures use `NetworkError`, `MessageEvent::Failed`, or `SetupEvent::Failed` with static, non-secret reason categories. No error text is parsed for control flow.

## 9. Persistence (implemented with an MLS caveat)

Message envelopes are stored in schema v2 of the encrypted vault as XChaCha20-Poly1305 ciphertext under the `storage/db` subkey. Conversation and message IDs are represented only by HMAC blind indexes. Raw `profile.db`, `profile.db-wal`, and `profile.db-shm` files are tested to contain no plaintext message sentinel.

The legacy `Conversation::load` path parses receipt bodies from raw envelope payloads and is valid only for opaque pre-MLS receipts. `MlsConversation` currently has no load path because MLS group state and receipt plaintext are not restored after restart. Persisting and restoring MLS state safely is future work; storing OpenMLS secrets in plaintext SQLite is explicitly rejected.

## 10. File transfer protocol (v1, implemented)

`/p2p-messenger/file/1` carries fixed `FILE` magic, a `u16` version (`1`), a `u8` code, a 16-byte random transfer ID, length-prefixed sender public key and PeerId, a bounded body, and a 64-byte Ed25519 signature over every preceding field. Decode rejects wrong magic/version, unknown codes, bad lengths, trailing bytes, and oversized frames before any state change. `FileEnvelope::verify` requires the signer's public key to derive the signed PeerId and that PeerId to equal the Noise-authenticated peer.

| Code | Message | Body |
|---|---|---|
| `1` | `Offer` | name, size, chunk count, chunk size, manifest commitment hash, fresh 32-byte content key |
| `2` | `Accept` | one byte: `1` accepted, `0` rejected |
| `3` | `Chunk` | zero-based index and one XChaCha20-Poly1305 ciphertext |
| `4` | `ChunkAck` | index and one acceptance byte |
| `5` | `Manifest` | every per-chunk SHA-256 hash and the full SHA-256 plaintext hash |
| `6` | `ManifestAck` | one acceptance byte |
| `7` | `Reject` | empty body |

Bounds: file name ≤ 255 UTF-8 bytes with no path separators or control characters; plaintext ≤ 64 MiB; chunk plaintext ≤ 256 KiB; at most 256 chunks; signed frame ≤ 1 MiB. The sender computes SHA-256 for every chunk and for the full plaintext, then derives a manifest commitment from domain prefix, transfer ID, chunk count, all chunk hashes, and the full hash. That commitment hash is signed in the offer, so a manifest cannot be substituted after chunks are accepted. Each chunk AEAD uses a fresh random nonce and AAD binding domain prefix, transfer ID, index, chunk count, and exact plaintext length; out-of-order, duplicate, truncated, or tampered chunks fail closed.

The content key is fresh per transfer, carried only inside the signed offer over the existing Noise-authenticated direct connection, and never written to disk. M13 relay support is opt-in, but file transfer is refused when a peer has an observed relayed connection: a relay would see the framed offer bytes, so an end-to-end key exchange would be required first. `p2p-chat` starts a transfer only for a joined MLS conversation and only one active transfer per peer. The controller advances sequentially: offer → accept → each encrypted chunk and acknowledgement → signed manifest → manifest acknowledgement. Only a verified manifest acknowledgement marks the sender `IntegrityVerified`; the receiver marks that status only after decrypting every quarantined chunk in memory and checking all per-chunk and full SHA-256 hashes. Transport events alone never complete a transfer.

Incoming ciphertext is written to a restricted (`0700`) quarantine directory named by transfer ID; chunk files are `0600` on Unix. Decryption occurs only in bounded, zeroizing memory buffers for AEAD and hash verification; plaintext and the content key are never written to quarantine. The signed manifest record written to quarantine contains only hashes and public transfer metadata. `Debug` implementations redact content keys, signatures, and file paths.

Status is deliberately narrow: `AwaitingAccept`, `Sending { acked }`, `Receiving { received }`, `IntegrityVerified`, or `Failed(reason)`. `IntegrityVerified` means the bytes matched the signed manifest, **not** that the file is safe. `ScanStatus` is `NotApplicable` before verification and `Unavailable` afterward until an application-supplied `FileScanner` is invoked. The exact categories are `CleanNoThreatDetected`, `ThreatDetected`, `Unavailable`, `Failed`, and `UnsupportedFormat`; only `SecurityConfig::scan` can create the outcome that permits release, and it first validates the claimed TXT/PNG/GIF structure from the bytes. A mismatch returns `UnsupportedFormat` without invoking the scanner. `ScanOutcome` privately carries the validated `FileFormat`; release policy requires it in addition to a clean scan, safe name, bounded size/chunk count, and explicit extension allowlist. `ReleaseApproval` starts `NotReady`, becomes `Pending` only when all release requirements except the user decision are met, then becomes `Approved` or terminal `Cancelled`. `release_file` returns plaintext only in a zeroizing buffer after a clean scanner result, validated format, policy evaluation, and explicit approval; it is not a wire-protocol step and writes no plaintext to disk. Cancellation is terminal for release, retains ciphertext, and does not cancel the network transfer. No `Safe` status exists.

Release, storage, and deletion are application-local and are not wire-protocol steps. `ReleasedFile` is zeroizing memory; the desktop application copies it into the encrypted vault attachment store rather than writing plaintext. The native-only OS save dialog decrypts an attachment into a zeroizing buffer and writes plaintext only to a path the user chooses; a cancelled dialog writes nothing. Quarantine deletion defaults to `Retain`; under `Explicit` it requires a verified transfer that was released or cancelled and deletes only that transfer's ciphertext directory. Stored-attachment deletion is a separate explicit action. Neither action cancels the network transfer, grants a clean status, or guarantees secure erasure on SSD/CoW storage.

## 11. Optional control and privacy observations (M13, implemented)

`/p2p-messenger/control/1` uses the same bounded frame format as the other three request-response protocols: `u32 big-endian length || opaque bytes`, rejecting empty and oversized (>1 MiB) frames before body allocation. It is registered as `Full` with four concurrent streams and a 10-second timeout. The frame is deliberately not a signed application envelope, not an MLS application body, and not stored in the vault. `ControlEvent` debug output reports lengths and static failure reasons only.

The controller drains `ControlEvent`, `DiscoveryEvent`, `RelayEvent`, `NatEvent`, and `IdentifyEvent` queues. It updates only the cached `NetworkPrivacyStatus`, which separates configured flags/address counts from counters and strings changed by real libp2p events. No observation is promoted to a saved contact, fingerprint verification, capability, presence, receipt, delivery, or safety claim.

Optional network behaviours are off/empty by default and applied only when the network worker starts:

- mDNS and Kademlia report advisory candidates/routes. Kademlia requires user-supplied direct bootstrap addresses; no candidate is auto-dialed or trusted.
- Relay client/server modes require user-supplied direct relay addresses. User addresses must end in `/p2p/<peer-id>` and must not contain `/p2p-circuit`. Relay reservations, circuits, and relayed connections are counted from real events and bounded; file transfer is refused on relayed paths.
- AutoNAT reports `Unknown`, `Private`, or a best-effort observed `Public` status; DCUtR reports hole-punch outcomes. Neither guarantees NAT traversal.
- Identify hides listen addresses, pushes no address updates, and bounds protocol/agent strings before they reach events or diagnostics; it remains off by default. Ping is low-frequency liveness only.

There is no cryptographic channel ACL, anonymity protocol, Tor/I2P/mixnet, universal NAT traversal, or end-to-end file-key exchange over relays in this protocol version. Two-machine LAN/NAT/relay verification remains external work.
