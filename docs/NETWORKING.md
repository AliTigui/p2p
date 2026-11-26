# Networking Design

Status: **Milestones 4–10 and 13 complete**: zero-infrastructure direct connect, MLS payload encryption, signed MLS setup/group control, the `p2p-chat` controller, the GUI send/receive path, the in-memory offline queue with reconnect retry, bounded redial/backoff, duplicate-dial rejection, connection admission limits, aggregate per-peer and per-protocol request/byte budgets, admin-only multi-member group management, group-wide delivery receipts, logical `CHN1` channels, the separate encrypted file protocol with ciphertext-only quarantine and an approval gate, plus optional M13 discovery, relay, NAT, identify, and control plumbing. A post-M13 local schema-v4 control-frame digest log with a vault anchor preserves only already authenticated setup/group-control decisions across restart; it changes no transport or wire format and restores no MLS state. M13 capabilities are **off/empty by default** and are not required for any core function. Two-machine LAN/NAT/relay verification, strong anonymity, universal NAT traversal, MLS persistence, a real scanner, general MIME parsing, backup/restore, and transport-level cancellation of an already queued worker request remain targets. See `PROJECT_STATUS.md` for actual commands and results.

## 1. Goal and constraint

The application must work with **zero infrastructure owned or operated by the project**. User installations are equal peers. Discovery and relay are optional capabilities provided by users' own installations, never mandatory services. No developer-operated bootstrap addresses, relays, or discovery peers are compiled into the binary.

The networking foundation is `libp2p =0.57.1`. Base transport features are `ed25519`, `macros`, `tcp`, `noise`, `yamux`, and `tokio`. M13 explicitly adds `autonat`, `dcutr`, `identify`, `kad`, `mdns`, `ping`, and `relay` features; their behaviours are created only when the local user enables them. Four explicit protocols use `libp2p-request-response =0.30.0`, the version paired with libp2p 0.57. The 0.57 line was unlocked by moving the native GUI to egui/eframe 0.35, which removed the `js-sys` graph conflict with `libp2p-swarm 0.48.0`; the full rationale is in `docs/DEPENDENCIES.md`. `plaintext`, `pnet`, `floodsub`, QUIC, DNS, UPnP, and a facade `request-response` feature remain excluded.

## 2. Connection modes

### Mode A — Direct connection (implemented, default)
- The user enters a multiaddr such as `/ip4/203.0.113.10/tcp/4001/p2p/12D3Koo...`; the `/p2p/<peer-id>` suffix is required and `/p2p-circuit` is rejected for user-supplied direct addresses.
- `Network::parse_address` validates the address and extracts the expected PeerId before dialing. The first dial comes only from an explicit user action in the GUI or API; bounded automatic redial reuses that saved address after an observed disconnect or attributed dial failure. A user disconnect suppresses further redial until a fresh explicit dial.
- libp2p Noise authenticates that the remote controls the private key for the expected PeerId. The local key is imported from the encrypted vault via the stable protobuf Keypair encoding, so the network PeerId matches the vault identity.
- The default listen address is `/ip4/0.0.0.0/tcp/0`; loopback with an ephemeral port is used in tests.
- No bootstrap, DHT, relay, account service, developer server, identify, or ping is involved by default. This is the acceptance test for "no centralized server", and it passes with two isolated instances on loopback.
- Identify is off by default. When explicitly enabled, it hides listen addresses and bounds protocol/agent strings, but a connected PeerId still does not prove the person is the intended contact. Fingerprints are verified out of band.

### Mode B — Local network discovery (optional, implemented; two-machine test pending)
- `enable_mdns` creates a bounded libp2p mDNS behaviour. Discovered peer/address pairs become advisory candidates reported through `DiscoveryEvent`/`NetworkPrivacyStatus`.
- mDNS is never defaulted. Discovered peers are not auto-dialed, saved as contacts, trusted, or treated as fingerprint-verified. Users still supply the address and verify the fingerprint out of band.
- mDNS is usually limited to a local broadcast domain and may be disabled by OS or network policy. Local reachability is not guaranteed.

### Mode C — Distributed discovery (optional, implemented; two-machine test pending)
- `enable_kad` creates a Kademlia behaviour with an in-memory store, caching disabled, and no periodic publication/bootstrap refresh. It requires at least one **user-supplied** direct bootstrap address ending in `/p2p/<peer-id>`; no default server exists.
- Kademlia events update advisory route/candidate counters. They never auto-dial a discovered peer or promote it to a contact or verified identity.
- No rendezvous service is configured. A user-operated rendezvous alternative would need separate design and dependency review.

### Mode D — Peer-operated relays (optional, implemented; two-machine test pending)
- `RelayMode::Client` requires user-supplied direct relay addresses. The worker listens on circuit addresses built from those user inputs; reservations and circuits are reported from real libp2p relay events.
- `RelayMode::Server` creates a bounded relay service with configured circuit, per-peer, byte, reservation, and circuit-source limits.
- Relayed connections are separately capped (`max_relayed_connections`, default 4) and counted from observed `is_relayed()` connections. A relayed connection does not imply trust, a reservation, a verified contact, or message delivery.
- With pinned `libp2p 0.56`, the relay client transport is upgraded with the same Noise security upgrade as direct TCP. A relay forwards opaque Noise bytes between endpoints: it can observe PeerIds, IPs, timing, and sizes and can deny service, but it cannot read application plaintext, message keys, or the file content key.
- **File transfer over a relay is disabled.** This is a conservative metadata/policy choice, not a claim that a relay sees the framed offer or file key. `Network::send_file` and inbound file requests emit `FileEvent::Failed` with `file transfer over a relay is disabled by policy` when a peer has an observed relayed connection. A dedicated relay-safe file-key/transport design is required before this restriction is changed.
- `relay_reservations` and `relay_circuits` count events observed since worker startup, not currently held reservations or circuits. `relayed_connections` is the latest live count reported by a transport event. `identified_peers` counts identify events observed since startup, not currently connected peers. The GUI labels these facts explicitly.

### Mode E — NAT status, identify, and control observations (optional, implemented)
- `enable_autonat` runs best-effort AutoNAT status probing; `enable_dcutr` attempts hole punching when a relayed path exists. `NatEvent` reports static status categories and hole-punch outcomes. Neither feature guarantees symmetric-NAT/CGNAT traversal.
- `enable_identify` enables libp2p identify with hidden listen addresses, no pushed address updates, an hourly interval, and bounded protocol/agent strings. Peer-provided addresses are not retained in `IdentifyEvent`.
- `enable_ping` enables low-frequency (60 s) liveness pings; ping events are not application health or delivery claims.
- `/p2p-messenger/control/1` carries bounded opaque control frames. The controller drains them but derives no capability, presence, receipt, delivery, trust, or safety state. It is a transport observation only.

## 3. Protocol stack

Implemented:

```
MLS application ciphertext inside signed Envelope.payload
    ↑ p2p-chat decodes bounded CHN1 channel bodies after p2p-groups decrypts and verifies membership/epoch
/p2p-messenger/message/1 (bounded request-response, opaque transport bytes)
    ↑ multistream-select negotiation, Full inbound/outbound, 8 streams
signed MLS1 v2 setup/group frames with a signed 16-byte transaction ID: KeyPackageRequest/Response, Welcome, WelcomeAck, GroupJoinRequest/Response, GroupWelcome, GroupCommit/Ack, GroupWelcomeAck
    ↑ p2p-chat verifies signature, authenticated peer, and transaction binding before MLS state changes
/p2p-messenger/mls-setup/1 (bounded request-response, opaque transport bytes)
    ↑ multistream-select negotiation, Full inbound/outbound, 4 streams
signed `FILE` frames: Offer/Accept/Chunk/ChunkAck/Manifest/ManifestAck/Reject
    ↑ p2p-files verifies signature and authenticated peer, encrypts chunks, checks hashes
/p2p-messenger/file/1 (bounded request-response, opaque transport bytes)
    ↑ multistream-select negotiation, Full inbound/outbound, 4 streams
/p2p-messenger/control/1 (bounded request-response, opaque transport bytes; M13)
    ↑ controller drains frames; no application semantics are inferred
Noise (authenticated encryption, peer identity binding)
Yamux multiplexing
TCP, plus optional user-configured relay transport
libp2p Swarm (10s connection and request timeout)
    ↑ real Swarm events: listening, dialing, connected, disconnected, relayed, discovery, NAT, identify, failures
ConnectionState, MessageEvent, SetupEvent, FileEvent, ControlEvent, and advisory privacy events projected to the controller/GUI
```

Only these four application protocols exist. They are separate protocols with separately bounded events; setup, file, and control frames are never treated as chat messages. Unknown protocol names are rejected by multistream-select, unknown envelope/setup/file versions are rejected by application decoders, and no silent downgrade is permitted. Concurrent pending sockets are capped before Noise authentication (16 inbound and 16 outbound by default), and direct TCP sockets are capped per source IP by `max_connections_per_ip` (four by default) before any Noise bytes are processed; zero/oversized limits are rejected at configuration time. Established connections are capped globally, per authenticated PeerId, and per observed IP; relayed connections have an additional cap. Peerless inbound failures are reported as advisory events without replacing cached live connection state. Duplicate pending dials are rejected; inbound application requests are limited by an aggregate sliding per-peer request-count and byte budget with derived per-protocol reservations for message, setup, file, and control traffic before they reach the application decoder. A denied request is not charged to either window, so one saturated protocol cannot consume another protocol's reserved capacity. File transfers are additionally bounded to 64 MiB, 256 KiB chunks, and 256 chunks. Scanner-driven release is an application-layer gate, not a wire-protocol step: it requires structurally validated TXT/PNG/GIF content, a real scanner result, name/size/count/extension policy, and explicit per-file approval before returning plaintext to memory. The post-M13 local control-log/anchor increment is vault-only: it changes no wire format, adds no protocol, and is unrelated to the opaque `/p2p-messenger/control/1` protocol.

## 4. Security controls

### Implemented
- **Transport peer authentication**: the dialed address must contain the expected PeerId; Noise authenticates the remote against that PeerId. User-supplied bootstrap/relay addresses must also be direct `/p2p/<peer-id>` addresses and never contain `/p2p-circuit`.
- **Application message authentication**: envelope signatures bind the embedded Ed25519 public key to the declared PeerId; the recipient verifies before replay state or delivery state changes.
- **End-to-end payload confidentiality**: `p2p-groups` produces MLS ciphertext for `Envelope.payload`, including receipt bodies. Receipt verification also checks the MLS credential, member signature key, group ID, and epoch against the signed envelope sender.
- **Signed setup binding**: `MLS1` v2 frames are Ed25519-signed and bind the transport PeerId, public key, random transaction ID, conversation ID, message code, and body. `p2p-chat` verifies the frame against the Noise-authenticated peer and rejects version 1 before OpenMLS sees a KeyPackage or Welcome; pending state and acknowledgements are keyed by transaction ID.
- **Signed group control and channel policy**: bounded group frames carry Add/Remove/Update with pending acknowledgement state; `CHN1` bodies stay inside MLS application plaintext and are locally gated by admin/member policy. Neither is a cryptographic role or channel-ACL system.
- **Honest connection and message state**: `ConnectionState` comes only from real Swarm events. `SentToPeer` never means delivered; `Joined` requires verified setup completion; `IntegrityVerified` requires a verified signed manifest. `ControlEvent` and privacy observations never claim application state.
- **No mandatory infrastructure**: all bootstrap lists, relay lists, discovery flags, identify/ping, AutoNAT, and DCUtR default to off/empty; no developer-operated service exists.
- **Bounded application frames**: request and response frames are capped at 1 MiB, with empty/oversized lengths rejected before body allocation. Eight concurrent message streams and four setup/file/control streams are allowed, with a 10-second timeout.
- **Bounded optional network surface**: mDNS/Kademlia candidates are advisory; cumulative relay reservation/circuit events observed since startup and the latest live relayed-connection count come from real events, and relayed connections are separately capped; AutoNAT/DCUtR results are best-effort; identify strings are bounded and listen addresses hidden; the controller drains privacy/control queues without promoting their contents.
- **File transfer isolation**: a transfer starts only with a joined MLS conversation and only one transfer is active per peer. Fresh content keys, bound AEAD AAD, manifest commitments, ciphertext-only quarantine, redacted diagnostics, and a hard refusal on relayed paths keep file verification separate from message delivery.
- **Verified replay boundary**: bounded message-ID cache and strict per-sender sequence high-water marks are applied before application state changes.
- **File policy and storage boundary**: the scanner/policy/approval gate, encrypted attachment store, native-only user-initiated OS save, and explicit deletion policies are implemented at the application layer.

### Designed or partially implemented
- **Identify cross-check**: identify can be enabled and its strings bounded, but the application does not cross-check protocol lists or treat identify as contact verification.
- **Two-machine discovery/NAT/relay verification**: local tests validate configuration, validation, bounded events, and status plumbing; LAN/NAT/relay connectivity between separate machines remains an external test.
- **Strong anonymity and universal NAT traversal**: not implemented. Optional relays and AutoNAT/DCUtR do not hide metadata or guarantee connectivity.
- **File policy limits**: general format/MIME parsing, a configured real scanner, backup/restore, and transport-level cancellation of an already queued worker request are not implemented.
- **MLS features beyond M13**: admin role delegation/changes, external commits, and cryptographic per-channel keys are not implemented. ADR-0014 Phase 4 later added encrypted restoration of joined group state, channel policy, bounded pending operations, receipts, and queued ciphertext when a vault session is attached; setup KeyPackages/Welcomes and decrypted text remain memory-only.

## 5. Honest limitations

- Symmetric NAT, CGNAT, strict firewalls, or networks that block inbound connections can still prevent direct connectivity. AutoNAT, DCUtR, and relays are best-effort options, not a guarantee.
- Without a reachable peer and a manually supplied address, two offline-isolated machines cannot communicate. The UI says the network is listening or disconnected based on observed events; it does not invent a connection.
- mDNS is limited to its local broadcast domain and may be disabled by OS/network policy. Kademlia requires user-supplied bootstrap peers; no default overlay exists.
- A connected PeerId, discovery candidate, identify result, relay reservation, or NAT observation is not proof that the person is the intended contact. Fingerprint verification remains explicit and out of band.
- Discovery candidates are never auto-dialed. The user still supplies the peer address and peer ID; no message or file is sent until the user initiates it.
- Relay operators can observe PeerIds, IPs, timing, and sizes and can deny service, but the Noise upgrade means they forward opaque bytes rather than application plaintext. Relayed paths are capped and reported, but they are not trusted paths.
- File transfer is refused on observed relayed connections as a conservative metadata/policy choice until a dedicated relay-safe file-key/transport design exists; the relay is not assumed to see the file key. Integrity verification alone never means a file is clean or safe.
- Offline queueing is ciphertext-only. Text composed while the peer is disconnected stays `Queued`; the controller retries it only after consuming a real `Connected` event for that peer. With a vault session the queue is encrypted and restored after restart; without one it is per-session and lost on lock. Retry never creates `Delivered` without a verified receipt.
- Without a vault session, MLS group state and decrypted text are memory-only and restart loses the local MLS session. With a session, Phase 4 restores joined groups, channel policy, bounded pending operations, receipt expectations, and queued ciphertext from authenticated encrypted records; setup KeyPackages/Welcomes and decrypted text remain unavailable after restart. Opaque envelope records and authenticated control-frame digests alone do not restore MLS state and are not a backup.
- Setup and group-control frames have signed transaction IDs, a bounded 512-entry in-memory digest replay cache for exact authenticated replays, and bounded group-commit byte caches. With a cloned vault `Session` attached via `MessengerController::start_with_control_log`, schema v4 additionally records SHA-256 digests of already authenticated frames in a bounded (4,096-record, fail-closed) encrypted chain with a separate AEAD-protected anchor. `KeyPackageRequest` and `GroupJoinRequest` repeats remain idempotent; Welcomes, responses, commits, and all acks are non-repeatable and stay rejected after restart. A duplicate with a different transaction ID cannot overwrite pending state. Request correlation, signed transaction IDs, ownership, membership checks, and terminal-state guards reject late, stale, and unexpected frames. Unlock verifies records, chain, blind indexes, and anchor, detecting database-only rollback and anchor tampering; restoring the entire vault including the anchor is not locally detectable because no external anchor exists. Neither cache is a general replay-proof protocol, and no transport behaviour changes.
- A required member that is offline can leave a group operation pending until it reconnects; the app reports pending state rather than success, and there is no timeout, rollback, or silent partial completion.
- Group `Delivered` requires receipts from every expected member. One disconnected recipient keeps the message at `Queued`/unconfirmed; a vault-backed queue can survive restart, but no restored entry is treated as delivered without a verified receipt.

## 6. Test plan

1. **Implemented and passing**: two instances on one machine with distinct identities and explicit loopback multiaddrs connect with zero bootstrap/DHT/relay, mutually observe the expected PeerIds, and observe disconnect.
2. **Implemented and passing**: an MLS-encrypted signed envelope is sent over `/p2p-messenger/message/1`, verified and decrypted by the recipient, and an explicit MLS-encrypted receipt advances the sender from `SentToPeer` to `Delivered`. A tampered envelope is rejected and leaves the sender at `SentToPeer`.
3. **Implemented and passing**: two controllers on explicit loopback connections complete the signed, transaction-bound KeyPackage/Welcome/WelcomeAck exchange (setup frame v2) over `/p2p-messenger/mls-setup/1`, reach the same epoch, exchange encrypted text, and reject setup without a connected peer.
4. **Implemented and passing**: text composed while disconnected stays `Queued` through repeated polls, is retried only after an observed reconnect, reaches `SentToPeer` before the recipient is polled, and becomes `Delivered` only after a verified receipt. A raw vault/WAL/SHM scan finds no queued plaintext sentinel.
5. **Implemented and passing**: bounded redial against an unreachable user-supplied address reaches its retry limit without a connected claim; user disconnect suppresses redial until a fresh explicit dial.
6. **Implemented and passing**: a duplicate dial is rejected until the first settles, an extra peer is blocked by a one-connection cap, a second request from one peer is rejected by the aggregate request budget, and control traffic that saturates its own bucket cannot block a later message request.
7. **Implemented and passing**: three controllers on explicit loopback connections complete an admin Add through signed group frames, clear pending state after Welcome/Commit acknowledgements, broadcast text to all current members, and show `Delivered` only after both receipts. Admin Remove advances the epoch and excludes the removed member; self-Update is acknowledged by every member; non-admin operations are denied.
8. **Implemented and passing**: signed file frames cross `/p2p-messenger/file/1` over Noise; two controllers transfer a multi-chunk file, both sides reach `IntegrityVerified`, scanning stays `Unavailable`, and quarantine bytes contain no plaintext sentinel.
9. **Implemented and passing (M13 local checks)**: default config is all off/empty; user addresses and public `dial` calls require `/p2p/<peer-id>` and reject `/p2p-circuit` before queueing; Kademlia and relay-client preconditions are validated; the control codec round-trips an opaque bounded frame; control-event `Debug` is redacted; privacy status defaults are honest; inbound file requests from observed relayed peers get a `Failed` event without a pending response; expired rate-limit entries are removed; NAT status changes carry no fabricated confidence; GUI fields reject invalid addresses; and status rows distinguish configuration from cumulative observations.
10. **External two-machine test pending**: two machines on the same LAN using manual addresses and optional mDNS.
11. **External two-machine test pending**: two machines behind separate NATs using a volunteer relay on a third user-controlled machine and optional AutoNAT/DCUtR.
12. **External test pending**: Kademlia lookup with a user-configured bootstrap peer; verify empty default bootstrap and no auto-dialing of candidates.
13. **Partially covered**: negative tests for wrong PeerId, replayed message, oversized/malformed/empty frames, and circuit bootstrap addresses are local tests. Relay ciphertext modification and real two-machine NAT behavior remain external work.
14. **Implemented and passing (SA-018 local checks)**: a stalled raw inbound socket consumes the single permitted pending slot, a legitimate dial cannot complete during the flood, the listener reports a bounded “connection limit exceeded” reason, and a later dial succeeds after the socket is dropped. A separate per-IP test holds two unauthenticated sockets from one address, proves a third is closed before Noise, and proves the slot is reusable after one socket is released. Configuration rejects zero or oversized limits, and advisory peerless failures do not erase cached live connections. Distributed flood capacity and OS-level descriptor tuning remain external design/testing work.
15. **Implemented and passing (post-M13 local checks)**: control-log records verify after reopen, repeatable requests stay idempotent while terminal frame replays are rejected, a database-only rollback and a tampered `control.anchor` fail unlock, and the final integrated serialized run passed **207 tests with 0 failures on 2026-11-25**. These are local vault/controller checks; no new wire test is implied.
