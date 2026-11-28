# Post-Quantum Status (local, uncommitted)

This document records the exact post-quantum boundary for the current source
tree. It is not a release note, audit result, CI result, external verification,
two-machine result, visual-GUI result, or production-readiness claim.

## Boundary

Post-quantum protections are present in MLS, application setup/file
authentication, direct QUIC key agreement, and a mandatory ML-DSA-65 connection
admission gate. This is **not** full post-quantum protection: libp2p TLS/Noise
PeerId authentication remains classical, and the classical transport PeerId is
the identity that authorizes a connection. The admission proof is bound to that
PeerId; it authenticates PQ-key possession on a classically authenticated
connection but does not make the transport PeerId authentication
quantum-resistant.

| Layer | Implemented in this tree | Production gate | Residual / non-claim |
|---|---|---|---|
| Direct transport key agreement | Direct mode adds libp2p QUIC using pinned `libp2p-tls 0.7.0` with rustls `prefer-post-quantum`; `X25519MLKEM768` hybrid KEX. TCP+Noise+Yamux remains available. | Direct peer addresses must end in `/p2p/<peer-id>` and reject `/p2p-circuit`; QUIC is not used in `TorRequired` or `DialPolicy::RelayOnly`. | TLS/libp2p PeerId authentication is classical. TCP/Noise, SOCKS5, and relay paths do not get QUIC hybrid KEX. No anonymous route is established. |
| Connection admission | Every accepted libp2p connection runs `/p2p-messenger/pq-auth/1`: both endpoints present the existing self-contained ML-DSA-65 proof and sign a domain-separated challenge containing both PeerIds and a fresh 32-byte nonce with the certified `Application` role key. Application request/response events are withheld until the peer's proof is verified. | Peers without the protocol, malformed frames, wrong PeerId binding, tampered proof/signature, wrong nonce echo, expiry, or application traffic before admission fail closed; one connection per peer is required. | This is a pre-application gate, not quantum-resistant Noise/TLS PeerId authentication. The PQ proof is self-signed, so a quantum attacker who forges the classical PeerId could mint a new proof bound to it. Optional protocol bytes (identify, ping, relay reservation/circuit bootstrap) may still be exchanged before admission; peer-scoped observations are buffered until that peer completes admission (64-entry cap), and no full transport replacement is claimed. |
| Local identity | Bundle v2 stores independent ML-DSA-65 `Root`, `Device`, `Mls`, `Application`, and `File` seeds plus a `PqIdentityProof` binding those keys to the classical transport PeerId and a validity window. Ed25519 role keys/proof remain parallel for transport and legacy compatibility. | Signed frames carry and verify the PQ proof. Importing a legacy v1 bundle without a v2 export generates fresh PQ keys/proof. | The displayed fingerprint and transport PeerId remain Ed25519-derived. No out-of-band human fingerprint verification is wired. |
| MLS | `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (`0x0051`) with ML-DSA-65 leaf signatures and certified ML-DSA-65 `Mls` credential keys. | Setup requires `0x0051`; legacy `0x004F` is historical and not accepted. | No claim about group-member attribution, complete metadata confidentiality, unlinkability, or anonymity. |
| MLS setup | `/p2p-messenger/mls-setup/2` wire version 5 carries a self-contained ~26 KiB PQ proof and a 3309-byte ML-DSA-65 `Application` signature. | `SetupEnvelope::require_pq()` and `verify_channel_scope()` run before KeyPackage/Welcome/commit bytes reach MLS. Version 4 decodes/verifies only in adversarial tests. | Legacy v1–v3 frames are rejected; a decodable v4 frame must never enter a production receive path. |
| File protocol | `/p2p-messenger/file/1` wire version 3 carries the same PQ proof and a 3309-byte ML-DSA-65 `File` signature. | `FileEnvelope::require_pq()` runs in both controller receive paths. Version 2 decodes/verifies only in adversarial tests. | File-over-relay remains disabled. Chunk content still uses per-transfer XChaCha20-Poly1305. |
| Transport privacy | `TorRequired` uses a configured SOCKS5 proxy with no direct fallback. | Missing proxy configuration fails closed. | The proxy is not verified as Tor; DNS/IPv6 leaks, reachability, timing correlation, and anonymity remain unverified. |

## Primitive policy

No custom cryptographic primitive is introduced. ML-DSA-65 comes from the
pinned `ml-dsa = =0.1.2` crate with its `alloc` feature enabled; the PQ proof
container only adds domain separation and size/version validation. QUIC KEX
comes from the pinned libp2p/rustls stack. The previous hybrid-Ed25519 MLS suite
`0x004F` is retained only as historical documentation.

## Non-claims

- No full post-quantum or quantum-resistance claim.
- No post-quantum transport PeerId authentication.
- No verified Tor, I2P, mixnet, proxy identity, or anonymity claim.
- No complete metadata confidentiality, unlinkability, or full deniability claim.
- No CI, release, signed artifact, external verification, two-machine test,
  visual-GUI inspection, or production-readiness claim.
- No claim that M13 optional discovery/relay/NAT capabilities are enabled; they
  remain off/empty by default.

## Explicitly not applied / not claimed (local, uncommitted)

- No literal PQ replacement of libp2p TLS/Noise PeerId authentication. Pinned libp2p 0.57.1, libp2p-tls 0.7.0, libp2p-quic 0.14.0, and rcgen 0.13.2 provide no supported ML-DSA certificate hook; that would require a vendored/forked transport.
- No full post-quantum protection or quantum resistance. The PQ admission proof is self-signed and bound to the classical PeerId; a quantum attacker able to forge that PeerId could mint a fresh proof bound to it.
- No PQ KEX on SOCKS5 or relay paths. X25519MLKEM768 is only for direct QUIC.
- No pre-admission wire-level restriction on optional libp2p behaviours. identify, ping, and relay reservation/circuit bootstrap bytes may still be exchanged before PQ admission; peer-scoped application-visible observations are buffered until that peer completes admission (64-entry cap) and are dropped if the connection closes first. Local listener/startup failures, mDNS candidates, and AutoNAT status remain direct/advisory without full peer-admission context.
- No verified Tor/anonymity. SOCKS5 is configured policy only; proxy identity, reachability, DNS/IPv6 leaks, timing correlation, and anonymity remain unverified.
- No two-machine/LAN/NAT/relay verification, external verification, signed artifacts, installer execution, notarization, or visual GUI inspection.
- No production-readiness claim, reproducibility claim, full metadata confidentiality, unlinkability, full deniability, or complete rollback resistance claim.
- No long coverage-guided fuzz campaign; seven local plain-libFuzzer smoke runs of 10,000 inputs each completed with exit 0 and no artifacts, but they are not coverage-instrumented.

Current local gate results are recorded in `SECURITY_TESTS.md`; all results are
local-only for the exact uncommitted source state.
