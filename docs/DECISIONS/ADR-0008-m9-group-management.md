# ADR-0008: Signed MLS group management with local admin policy

- Status: Accepted
- Date: 2026-11-24

## Context
Milestone 9 needed more than the initial two-member MLS setup: a member can be added to an existing group, removed from future epochs, and have its leaf key refreshed without a server. The application already had a Noise-authenticated connection and a bounded signed `/p2p-messenger/mls-setup/1` protocol. Adding a separate control protocol or inventing a new cryptographic membership scheme would increase the audit surface and risk inconsistent authorization.

## Decision
Extend the existing versioned `MLS1` setup protocol with bounded, signed group-control frames; do not add a fourth wire protocol.

- Codes `5`–`10` carry `GroupJoinRequest`, `GroupKeyPackageResponse`, `GroupWelcome`, `GroupCommit`, `GroupCommitAck`, and `GroupWelcomeAck`. Payload parsers are strict, bounded, and reject unknown codes, bad target flags, truncated peer IDs, empty commits, trailing bytes, and malformed acknowledgements.
- The conversation creator is the initial administrator. Only that PeerId may start Add, Remove, or self-Update operations. There is no role delegation in M9.
- The administrator merges an epoch-changing commit locally immediately, broadcasts the same signed commit to every required existing member, and records a pending operation until the Welcome and all required CommitAck frames are verified. A joining member receives the new epoch through its Welcome and is excluded from that Add commit's acknowledgement set.
- Messages and further group operations are blocked while an operation is pending. Pending commits are retried to required members when a connection is observed again; no timeout silently marks an operation complete.
- A removed member stays on the excluded epoch. New MLS ciphertext is not readable by that member, and stale-epoch ciphertext sent by it is rejected by remaining members.
- One signed MLS envelope per text message is broadcast to all current members. The offline queue keeps one ciphertext copy per disconnected recipient. Local status becomes `Delivered` only after verified receipts from every expected recipient.
- Debug output reports body lengths and never prints KeyPackage, Welcome, or commit bytes.

## Consequences
- Multi-member group management works with the same zero-infrastructure direct connection as 1:1 messaging. No discovery, relay, or central policy service exists.
- No new external dependency is introduced. The change is confined to existing MLS, identity, network, controller, and GUI code.
- Admin policy is enforced locally by each client from signed, authenticated frames. It is not a cryptographic role system; compromise of the admin identity still permits authorized operations by that identity.
- A disconnected required member can leave an operation pending until it reconnects. The UI shows that pending state and does not report success, delivery, or completion early.
- Setup and group-control frames keep a bounded 512-entry in-memory digest replay cache for exact authenticated replays. Conversation state, pending-operation ownership, request correlation, and terminal-state guards reject unexpected frames. A post-M13 schema-v4 encrypted, SHA-256-chained digest log with a vault anchor now preserves terminal/idempotent decisions across restart: `KeyPackageRequest` and `GroupJoinRequest` repeats stay idempotent, while repeated Welcomes, responses, commits, and acknowledgements are rejected. The log is bounded at 4096 records and fails closed, detects database-only rollback and anchor tampering on unlock, but cannot detect restoration of the whole vault including the anchor. This is still not a general replay-proof protocol.
- MLS state, pending operations, and decrypted text remain memory-only. Restart loses the session; the v4 log records only digests of already authenticated frames, so no encrypted MLS state layer is introduced and group/ratchet/pending-key-package/channel state is not restored.
- Channels were subsequently added as MLS application partitions in ADR-0009. Admin role changes/delegation, external commits, encrypted MLS state restoration, and automated policy distribution remain future work.
