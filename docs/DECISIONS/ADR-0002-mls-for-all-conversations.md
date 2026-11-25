# ADR-0002: MLS for every conversation, including 1:1

- Status: Accepted
- Date: 2026-11-23

## Context
The brief requires established cryptographic protocols, forward secrecy, post-compromise security, and group messaging via OpenMLS (RFC 9420). Maintaining a separate 1:1 protocol doubles audit surface and risks inconsistent security properties.

## Decision
All conversations are MLS groups. A private chat is a 2-member MLS group. OpenMLS 0.9.2 with `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` is the single conversation encryption path. Channels are logical partitions inside a group's MLS application messages with locally verified policy, because MLS has no native sub-group construct.

## Consequences
- One protocol to review and test; membership changes and key rotation behave consistently.
- 1:1 conversations carry MLS group state overhead.
- Channel permission enforcement is application policy, not cryptographic enforcement by MLS. Policy messages must be signed and checked against the current member set.
- Credentials bind the libp2p Ed25519 identity to MLS via a signed structure so peer identity remains verifiable.
