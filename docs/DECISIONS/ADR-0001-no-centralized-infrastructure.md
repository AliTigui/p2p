# ADR-0001: No mandatory centralized infrastructure

- Status: Accepted
- Date: 2026-11-23

## Context
The project's fundamental requirement is independence from any company, service provider, or infrastructure owner. Messaging, authentication, account management, discovery, and relay must not require developer-operated servers.

## Decision
No binary default bootstrap node, rendezvous server, identity service, or relay is compiled into the application. Manual multiaddr/QR exchange must work with only two installations. mDNS, Kademlia, AutoNAT, DCUtR, and relay are optional capabilities configured by users. Relay providers are ordinary user installations.

## Consequences
- Public discovery and NAT traversal can fail without reachable peers. The UI must report this explicitly; we do not hide the limitation.
- First contact requires an out-of-band address/fingerprint exchange.
- No global user directory or account recovery exists.
- This decision cannot be silently changed. Any conflicting feature requires a new ADR that preserves a fully functional serverless mode.
