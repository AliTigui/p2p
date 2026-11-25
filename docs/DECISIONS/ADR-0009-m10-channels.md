# ADR-0009: Channels as logical partitions inside one MLS group

- Status: Accepted
- Date: 2026-11-24

## Context
Milestone 10 needed separate conversational spaces without creating separate MLS groups, new KeyPackages/Welcomes, or another transport protocol. OpenMLS has one group key schedule per group and no native sub-group construct. The v1 envelope already reserved `MessageKind::Channel` with code `8`, but it had no application codec or controller policy. Creating new MLS groups per channel would multiply group state, epoch management, Welcomes, and delivery bookkeeping, and would not fit the requirement that channels remain logical partitions of one authenticated conversation.

## Decision
Reuse the existing signed v1 envelope and MLS application path. Do not add an envelope v2, setup codes, a fourth wire protocol, new MLS groups, or new external dependencies.

- The `CHN1` codec in `crates/chat/src/channel.rs` is a strict, bounded plaintext application body. It carries the 16-byte `channel_id`, a revision, and one of four kinds: `Text`, `Create`, `Rename`, or `SetMembers`.
- `channel_id` is inside the MLS application plaintext. The outer envelope signature and the MLS credential/signature-key binding authenticate the writer; the transport continues to see only opaque signed MLS ciphertext.
- Every joined conversation starts with the fixed default channel ID `[0; 16]`, named `general`, whose allowed set is the current MLS membership. Newly joined members receive the default channel. Custom channel metadata created earlier is not replayed to them.
- The group creator remains the only administrator. Only that authenticated PeerId may create, rename, or change members of a channel. Any local peer and named recipient who are both MLS members and allowed channel members may post text.
- An empty member list at creation means all current MLS group members. Explicit member lists are validated against current MLS membership; duplicates, empty lists, and more than 64 members are rejected. A group holds at most 16 channels. Names are at most 64 UTF-8 bytes, text at most 2,048 bytes, and the framed application body at most 4,096 bytes.
- Metadata frames require the next sequential revision (`1` for create, current revision plus one for rename/member changes) and are broadcast as one signed MLS envelope to all group members. Text is sent only to allowed channel members. Receipts remain the existing legacy raw MLS receipt bodies; no channel ID is added to receipts.
- Channel metadata remains represented by local `ChannelInfo` state and receipt-gated `acknowledged` status. Invalid, unknown, or unauthorized frames produce no delivery receipt and only a static error category in `last_error`.
- Offline queue behavior, one ciphertext copy per disconnected recipient, and `Delivered` only after all expected receipts are unchanged. `send_text` remains the compatibility entry point and sends in the default channel.

## Consequences
- Channels are implemented with the same zero-infrastructure direct connection as text and group management. No new dependency, protocol handshake, or MLS group state is introduced.
- Channel membership is **local application policy, not cryptographic access control**. All members of an MLS group hold its group keys, so any member could decrypt a channel ciphertext it obtains. Restricted channels omit disallowed recipients from ordinary sends, but they do not provide a separate confidentiality boundary. A future cryptographic boundary would require a different key-distribution design.
- Admin authority remains application-level and local. A compromised admin identity can issue authorized channel policy frames. There is no role delegation or automated policy distribution.
- Metadata changes are not epoch-changing MLS commits and do not create pending group operations. Their acknowledged status is based on receipts for the last locally composed policy frame; custom channels are not reconstructed for later joiners.
- Replay resistance continues to rely on the v1 envelope replay cache, strict decoding, membership checks, revision ordering, and state guards. There is no dedicated channel replay cache.
- Channel state, decrypted text, and pending receipts remain memory-only and are lost on restart or lock. Diagnostics redact channel names and text; no plaintext channel body is written to disk by the controller.
