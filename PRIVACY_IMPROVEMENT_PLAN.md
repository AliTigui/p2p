# Privacy Improvement Plan (Q0–Q5)

This is a **local engineering plan**, not an external audit, not a privacy guarantee, and not a claim that the app is equivalent to Signal or Session. It follows the P0–P14 closeout. Status: **Q0, Q1, Q2, and Q5 are complete locally and uncommitted; Q3 and Q4 remain design-only**. All work remains local unless the user explicitly changes that requirement. No CI, release, commit, push, PR, review, merge, user/manual, or external verification claim is made.

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

- Default transport is direct TCP + Noise + Yamux and explicitly non-anonymous.
- Optional relay mode is off/empty by default; relay addresses must be direct `/p2p/<peer-id>` addresses and `/p2p-circuit` is rejected in configuration.
- `TransportPrivacyMode::TorRequired` fails closed before any worker starts.
- Application envelopes expose protocol, conversation, epoch, message ID, sender PeerId, certified role key, identity proof, sequence, sender time, kind, and ciphertext before MLS payload decryption. Q3 does not change this wire format.
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

Status: **complete locally and uncommitted**.

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

Status: **complete locally and uncommitted**.

Goal: reduce coarse plaintext-size correlation for messages and receipts.

Implementation boundary:

- `p2p-groups` pads every MLS application plaintext, including receipts, to fixed buckets before encryption: `[64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 786432]`.
- The padded record uses tag `1` and a 5-byte little-endian original-length header. Receive strips only an exact bucket length, valid tag, nonzero in-range length, and an all-zero tail; malformed padding returns `InvalidPadding`.
- Existing bounded codecs and envelope/setup/file wire versions are unchanged. Oversized plaintexts fail before encryption.

Tests added: bucket selection, exact-fit and one-byte-over boundary behaviour, valid round trip, empty/oversized input rejection, wrong tag, zero length, extended claimed length, dirty tail, and wrong-length padding.

Non-claims: no timing defence, no volume/correlation defence, no randomization, and no protection against a relay or peer observing outer frame sizes or the selected bucket. Q2 does not change clear envelope metadata.

### Q3 — Clear envelope metadata reduction

Goal: reduce stable metadata visible before MLS decryption.

Candidates, each requiring a new wire version rather than silently changing v2:

- Replace or blind the clear conversation ID with a per-conversation route tag.
- Coarsen or remove the untrusted sender timestamp.
- Move the identity proof and long-term role key inside the encrypted inner body, verifying only after decryption.

Non-claims: transport PeerId, IP, timing, and frame size remain observable; this is not unlinkability.

Status: design only; do not implement without explicit versioning and fresh adversarial tests.

### Q4 — Ephemeral delegated application keys

Goal: reduce reuse of one long-term Application key across conversations and time.

Candidates:

- Use the existing local `RoleDelegation` primitive to issue short-lived application-signing grants.
- Bind grants to conversation context and expiry.
- Fail closed on conflict, wrong role, or expired delegation.

Non-claims: root/device/transport keys remain stable; relay/peer correlation remains possible; this is not deniability.

Status: design only; requires identity/wire changes and GUI wording updates.

### Q5 — Optional local SOCKS5/Tor route

Status: **complete locally and uncommitted**; this is a configured route, not a verified Tor or anonymity route.

Goal: allow a user who already runs a local SOCKS5 proxy to route outbound dials through it.

Implemented boundary:

- `TransportPrivacyMode::TorRequired` now selects a SOCKS5-only libp2p transport built from `tokio-socks = =0.5.3` and `tokio-util`'s `compat` feature. It authenticates Noise and multiplexes Yamux over the proxy.
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

A phase is not called complete until targeted adversarial tests and the full local workspace/GUI gates pass. Historical CI/release results are not evidence for this workstream. The final post-Q local gate passed **358 workspace tests / 0 failures** (37 suites, doc-tests 0), **22 GUI-feature tests / 0 failures**, 64 diagnosed Rust sources, both-lockfile audit/deny, locked fuzz build/clippy, six 1000-input smoke runs, and byte-identical 480-package SBOM regeneration. Exact commands and results are in `SECURITY_TESTS.md`.

## 6. Current authoritative limitations

The following remain true unless a specific phase changes them with source and tests:

- No verified anonymity, Tor/I2P/mixnet, onion service, proxy identity, or unlinkability. Q5 configures a SOCKS5 route; it does not prove the proxy is Tor.
- No metadata confidentiality or traffic-analysis resistance. Q2 coarse padding does not hide timing, direction, volume, or outer frame buckets.
- No mandatory centralized infrastructure.
- No secure multi-device convergence, full ACL, or production readiness.
- Relay operators and direct peers observe metadata that is not hidden by MLS content encryption. Q1 changes the destination peer's view under explicit relay-only routing, not the relay's view.
- Q3 (clear envelope metadata reduction) and Q4 (ephemeral delegated application keys) remain unimplemented design candidates with no silent wire or identity change.
