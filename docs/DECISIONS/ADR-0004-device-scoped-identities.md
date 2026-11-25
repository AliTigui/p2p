# ADR-0004: Device-specific identities in the initial release

- Status: Accepted
- Date: 2026-11-23

## Context
Users need portable identities, but a single private key copied across devices weakens contact verification and creates ambiguous delivery/state semantics. Multi-device MLS requires additional device linking infrastructure or protocol work.

## Decision
Milestone 2 generates one libp2p Ed25519 identity per installation and stores it encrypted locally. Export/import as an encrypted backup is supported, but the documented initial-release model is device-specific: importing an identity migrates it, and simultaneous use on multiple devices is unsupported and warned against. True linked multi-device identity is deferred.

## Consequences
- Contact verification is unambiguous per device in v1.
- Users who want separate devices maintain separate contacts or perform explicit verification for each device.
- The UI and documentation must state the device-specific model clearly.
