# Privacy Improvement Plan (Q0–Q5)

This is a **local engineering plan**, not an external audit, not a privacy guarantee, and not a claim that the app is equivalent to Signal or Session. It follows the P0–P14 closeout. Q0–Q5 below are historical plan phases recorded against an earlier tree. The current worktree is based on `HEAD 34968e4` and adds three local, uncommitted changes: a fail-closed SOCKS5-only default (`TransportPrivacyMode::TorRequired`) with explicit `direct()` opt-in, a production v4 application wire with fresh random per-frame route tags and MAC-based group selection, and at-rest hardening (96 MiB/t=4/p=1 Argon2id, weak-vault rewrap on unlock, and restricted SQLite sidecar permissions). No CI, release, commit, push, PR, review, merge, user/manual, or external verification claim is made.

## 1. What “fixed” can honestly mean

There is no local-only change that makes this app anonymous or hides an IP from every observer.

- A direct peer necessarily sees the source IP at the TCP/Noise layer.
- A relay hides the source IP from the destination peer, but the relay sees source IP, destination PeerId, timing, and sizes.
- Signal’s sealed sender hides the sender from Signal’s server, not the sender’s IP from that server, and Signal still relies on a centrally operated delivery service.
- Session’s onion routing hides IPs from destination service nodes, but relies on a decentralised service-node network and has published attack research against its consensus and group protocol.

Therefore the honest target is:

1. **IP exposure to destination peers** is removed when the user explicitly configures a relay-only route; the user-selected relay still sees IP/timing/size metadata.
2. **Coarse message-size correlation** is reduced by padding application plaintexts to fixed buckets.
3. **Clear metadata and stable-key linkability** are reduced in later protocol work, with explicit wire versions and adversarial tests.
4. Every UI status distinguishes configuration from observation and never claims anonymity, unlinkability, metadata confidentiality, or production readiness.

Calling any partial result “anonymous”, “untraceable”, or “Session-equivalent” is out of scope.

## 2. Source-backed comparison

### Signal

Official Signal documentation describes sealed sender as follows:

- The service still needs the destination to deliver a message.
- A short-lived sender certificate and a 96-bit delivery token replace the usual authenticated upload.
- The sender identity and message ciphertext are encrypted to the recipient using an ephemeral X25519 key and the recipient identity key.
- Signal explicitly says timing and IP-address traffic correlation remain areas of ongoing development.

Source: <https://signal.org/blog/sealed-sender/>.

Relevant takeaways:

- Centralised delivery infrastructure is assumed.
- Sealed sender reduces sender identity metadata visible to the service, not IP visibility or traffic-correlation resistance.
- Our app has no service operator, so a literal sealed-sender copy is not applicable; the analogous local problem is metadata visible to the directly connected peer or user-selected relay.

### Session

Session’s official architecture documentation describes:

- A decentralised network of service nodes with per-user/per-group swarms.
- Three-hop onion routing: entry node knows the source IP, exit node knows the destination, no single node is supposed to know both.
- Persistent guard nodes, subnet-diverse paths, and multiple paths.
- Random alphanumeric Session IDs derived from a mnemonic seed rather than phone numbers.
- Blinded IDs for communities, encrypted local attachments, and config messages synchronised through swarms.

Sources:

- <https://github.com/session-foundation/session-desktop/blob/dev/ARCHITECTURE.md>
- <https://docs.getsession.org/>
- <https://getsession.org/faq>

Important limitation: a 2026 IACR ePrint reports seven vulnerabilities in Session/Oxen, including consensus flaws that could undermine the anonymity layer and serious issues in Version 1 group chat. Source: <https://eprint.iacr.org/2026/773>.

This app must not claim Session parity. Matching Session’s IP protection would require an onion-routing network and service nodes, which is mandatory infrastructure by another name and is not authorised here.

## 3. Current implementation boundary

Source review of `crates/network/src/lib.rs`, `crates/network/src/privacy.rs`, `crates/messaging/src/envelope.rs`, `crates/chat/src/setup.rs`, `crates/files/src/frame.rs`, `crates/groups/src/lib.rs`, and `apps/desktop/src/{app.rs,model.rs}` found:

- Default transport is now `TorRequired`: a user-supplied SOCKS5 proxy is mandatory, no direct listener or fallback is created, and startup fails closed without a valid proxy. Direct TCP/QUIC transport is only an explicit opt-in through `NetworkConfig::direct()` / `NetworkOptions::direct()`. A configured route is not a verified Tor route and is not anonymity.
- Optional relay mode is off/empty by default; relay addresses must be direct `/p2p/<peer-id>` addresses and `/p2p-circuit` is rejected in configuration.
- `TransportPrivacyMode::TorRequired` selects a configured SOCKS5-only outbound route; without a valid proxy address it fails closed before a dial is created. It is not a verified Tor route.
- Legacy v2 and v3 application envelopes expose stable metadata before MLS payload decryption. They remain only as compatibility/adversarial test artifacts; production v4 paths reject them.
- Stable identifiers include PeerId, transport key, Application/File/Mls role keys, conversation ID, transaction ID, transfer ID, channel ID, and sequence. Q4 does not change these identities.
- Q1 adds a `DialPolicy::RelayOnly` route that rejects direct application dials and requires an observed relayed path.
- Q2 pads MLS application plaintext to fixed buckets before encryption and rejects malformed padding after decryption.
- Q5 adds a SOCKS5-only outbound transport with no direct listener or direct fallback; the proxy's identity and reachability are not verified.
- There is no onion routing, I2P, mixnet, blinding, ephemeral per-conversation transport identity, DNS/IPv6 leak proof, or traffic-analysis defence.

## 4. Bounded phases

### Q0 — Comparison and claim boundary

Status: complete with this document.

No code or dependency change. This document anchors all later phases and forbids false anonymity/Session-parity claims.

### Q1 — Relay-only route policy

Status: **historically complete locally**.

Goal: make destination peers unable to learn the local public IP when the user explicitly configures relay-only routing.

Implementation boundary:

- `NetworkConfig::dial_policy` defaults to `DialPolicy::DirectAllowed`. `RelayOnly` requires `RelayMode::Client`, a user-supplied direct relay address, and DCUtR disabled; conflicting configuration fails closed.
- Public `Network::dial` rejects direct application addresses under `RelayOnly`. `Network::dial_relayed` builds and queues only a circuit address ending in the destination `/p2p/<peer-id>` and validated against the configured relay peer.
- Relay-only clients do not create a direct TCP listener. Circuit listener state is emitted only after `ReservationReqAccepted`, and `listen_addresses()` then contains observed circuit addresses.
- Explicit `RelayMode::Server` enables the relay HOP status; concrete non-wildcard `NewListenAddr` values are added as external addresses, while wildcard listens are not advertised.
- Non-relayed inbound connections from non-relay peers are closed, and application traffic is permitted only when the peer has an observed relayed connection.
- `MessengerController::connect_relayed`, advanced GUI settings, and honest status rows expose the mode; file transfer remains disabled on relayed paths.

Tests added: validation conflicts, circuit-address structure/destination checks, direct-dial rejection, queued relayed dials, route-policy gating, GUI relay-only validation, and a real local relay integration test proving circuit-only listeners, a relay reservation/circuit, and alice-to-bob relayed connectivity.

Non-claims: the relay sees IP, timing and sizes; relay operators can deny service; no two-machine relay verification, file-over-relay, onion routing, or anonymity is claimed.

### Q2 — Application message padding

Status: **historically complete locally**.

Goal: reduce coarse plaintext-size correlation for messages and receipts.

Implementation boundary:

- `p2p-groups` pads every MLS application plaintext, including receipts, to fixed buckets before encryption: `[64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 786432]`.
- The padded record uses tag `1` and a 5-byte little-endian original-length header. Receive strips only an exact bucket length, valid tag, nonzero in-range length, and an all-zero tail; malformed padding returns `InvalidPadding`.
- Existing bounded codecs and envelope/setup/file wire versions are unchanged. Oversized plaintexts fail before encryption.

Tests added: bucket selection, exact-fit and one-byte-over boundary behaviour, valid round trip, empty/oversized input rejection, wrong tag, zero length, extended claimed length, dirty tail, and wrong-length padding.

Non-claims: no timing defence, no volume/correlation defence, and no protection against a relay or peer observing outer frame sizes or the selected bucket. Q2 padding is retained inside the current v4 MLS-protected body; v4 additionally randomizes the outer nonce and route tag.

### Q3 — Clear envelope metadata reduction

Goal: reduce stable metadata visible before MLS decryption.

Historically implemented as a new wire version (`P2P3`, version 3) with no silent v2 change; v4 superseded it in production:

- The outer header carries only a per-epoch route tag, a fresh random nonce, an encrypted body length, the wrapped MLS ciphertext, and an HMAC-SHA256 tag keyed by an MLS exporter secret.
- Sender PeerId certified proof, long-term role key, conversation ID, epoch, message ID, sequence, timestamp, and kind move into an MLS-protected inner frame that is recovered only after group-authenticated decryption.
- The MLS ciphertext itself is wrapped with XChaCha20-Poly1305 under a purpose-separated MLS exporter key, so the MLS header, group ID, and epoch are not exposed in clear wire bytes. This is library-backed composition, not a custom primitive.
- Route tags are SHA-256 over a domain separator, group ID, and epoch. They are local routing hints, not secrets, not proofs, and not unlinkability.
- Production parsing rejects v1/v2 wire frames and legacy setup frames; the legacy v2 codec and its transferable-authorship test remain only as a compatibility artifact.

Historical non-claims for Q3: transport PeerId, IP, timing, direction, volume, outer bucket length, and route-tag linkability within one epoch remained observable. Version 3 was not unlinkability, not anonymity, and not a full metadata confidentiality claim.

Status: **historical**. The current production application wire is v4 (`P2P4`): every frame carries a fresh random route tag and nonce, and a receiver selects a candidate group by verifying the group-keyed exporter MAC instead of matching an epoch-stable tag. Outside observers cannot link v4 frames by tag; timing, size, direction, volume, and the transport peer remain observable. v3 is retained only for legacy/adversarial evidence and is rejected by the production receive path.

### Q4 — Bounded authorship deniability

Goal: stop wire bytes from acting as third-party-verifiable long-term-key authorship proof.

Implemented first in the v3 wire path and retained in the production v4 wire:

- The v2 identity proof and long-term application signature are no longer present on the wire. MLS group-authenticated decryption establishes the sender only for a recipient that holds current group state.
- The exported route tag and outer MAC do not identify a sender to an outside observer; the outer MAC is group-keyed, not sender-keyed.
- Recipients and current group members with MLS state can still attribute messages. A past member, an outside observer, or a party without the epoch's MLS state cannot turn a captured frame into transferable authorship proof.

Non-claims: root/device/transport keys remain stable; relay/peer correlation remains possible; this is bounded deniability, not full deniability and not anonymity. Ephemeral delegated application keys (`RoleDelegation` grants) were not introduced.

Status: **historically complete locally** as bounded wire-level deniability and retained in v4; GUI wording and tests state the group-member attribution boundary explicitly.

### Q5 — Optional local SOCKS5/Tor route

Status: **historically complete locally**; the current tree keeps the SOCKS5 route but changes the route to a fail-closed default. This is a configured route, not a verified Tor or anonymity route.

Goal: allow a user who already runs a local SOCKS5 proxy to route outbound dials through it.

Implemented boundary:

- `TransportPrivacyMode::TorRequired` now selects a SOCKS5-only libp2p transport built from `tokio-socks = "0.5.3"` and `tokio-util`'s `compat` feature. It authenticates Noise and multiplexes Yamux over the proxy.
- `socks5_proxy` must be an IP literal and port; hostnames are rejected so the proxy address itself requires no local DNS. `/dns4` and `/dns6` destination names are passed to the proxy as domain CONNECT targets; `/dnsaddr`, UDP, circuit, and incomplete targets fail before a dial future is created.
- Proxy mode disables mDNS, AutoNAT, and DCUtR through fail-closed validation. A proxy address without `TorRequired`, or `TorRequired` without a proxy, is rejected.
- The SOCKS5 transport's `listen_on` always fails with “SOCKS5-only route has no direct listener”. The worker skips the direct listener in proxy mode, and no direct TCP fallback transport is built.
- A fake-proxy test observes the SOCKS5 greeting and CONNECT request and proves that `example.onion` reaches the proxy as a domain rather than being resolved locally.
- GUI copy says the route is configured, proxy identity and reachability are not verified, and no Tor/anonymity claim is made.

Tests added: IP and domain target conversion, unsupported-target failure, no direct listener, rejected direct dial futures, and the fake-proxy domain-forwarding proof.

Remaining verification gap: there is no real Tor service, proxy identity check, external packet capture, or DNS/IPv6/relay-reservation leak test. “TorRequired” names a route policy only.

## 5. Evidence rules

Every implemented phase must report:

- `MILESTONE`
- `Implemented changes`
- `Modified files`
- `New dependencies`
- `Security properties achieved`
- `Tests added`
- `Tests executed`
- `Test results`
- `Remaining limitations`
- `Documentation updated`

A phase is not called complete until targeted adversarial tests and the full local workspace/GUI gates pass. Historical CI/release results are not evidence for this workstream. The historical pre-v3 post-Q gate passed **358 workspace tests / 0 failures** (37 suites, doc-tests 0), **22 GUI-feature tests / 0 failures**, 64 diagnosed Rust sources, both-lockfile audit/deny, locked fuzz build/clippy, six 1000-input smoke runs, and byte-identical 480-package SBOM regeneration; that count is retained only as pre-v3 evidence. The historical Q3/Q4 post-v3 gate passed **369 workspace tests / 0 failures** (26 suites, 0 doc-tests), **22 GUI-feature tests / 0 failures**, 65 diagnosed Rust sources, both-lockfile audit/deny, locked fuzz check/clippy/build, seven 1000-input smoke runs, and byte-identical 489-package SBOM regeneration. That work was subsequently superseded in production by the local PQ upgrade (MLS `0x0051`, setup v5, file v3, v2 identity bundles, direct QUIC hybrid KEX); current results and the classical PeerId authentication boundary are recorded in `SECURITY_TESTS.md`, `PROJECT_STATUS.md`, `POST_QUANTUM_STATUS.md`, and the final local report.

## 6. Current authoritative limitations

The following remain true unless a specific phase changes them with source and tests:

- No verified anonymity, Tor/I2P/mixnet, onion service, proxy identity, or unlinkability. Q5 configures a SOCKS5 route; it does not prove the proxy is Tor.
- No complete metadata confidentiality or traffic-analysis resistance. Q2 coarse padding reduces coarse size correlation, and the v4 production wire removes stable route tags from outside observers, but timing, direction, volume, and outer frame buckets remain observable.
- No mandatory centralized infrastructure.
- No secure multi-device convergence, full ACL, or production readiness.
- Relay operators and direct peers observe metadata that is not hidden by MLS content encryption. Q1 changes the destination peer's view under explicit relay-only routing, not the relay's view.
- v4 supersedes Q3's stable route tag with a fresh random tag per frame and MAC-based route selection. Q4's bounded wire-level authorship deniability remains; group members with MLS state can still attribute messages. Ephemeral delegated application keys remain unimplemented.
- At-rest hardening raises new vault and identity-export KDF parameters to 96 MiB/t=4/p=1, upgrades weak vault parameters on successful unlock or password change, and restricts SQLite WAL/SHM sidecar permissions. This does not protect a fully compromised endpoint that can read decrypted memory.
