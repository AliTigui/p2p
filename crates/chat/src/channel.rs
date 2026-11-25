//! Bounded, versioned application bodies for MLS group channels.
//!
//! These bytes are encrypted by OpenMLS before they enter a signed v1 envelope.
//! `channel_id` is carried here, inside authenticated application content, so
//! a channel is a logical partition of one MLS group rather than a new group or
//! a new transport protocol. The outer envelope signature and MLS sender
//! binding authenticate who wrote the frame; this codec only bounds and parses
//! the plaintext body.

use std::collections::BTreeSet;
use std::fmt;

use libp2p_identity::PeerId;

use crate::ChatError;

/// Fixed magic. Unknown magic is rejected; it is never negotiated.
pub const CHANNEL_MAGIC: [u8; 4] = *b"CHN1";
/// Legacy/default channel. It is present in every joined conversation.
pub const DEFAULT_CHANNEL_ID: [u8; 16] = [0; 16];

pub const MAX_CHANNEL_NAME_BYTES: usize = 64;
pub const MAX_CHANNEL_TEXT_BYTES: usize = 2048;
pub const MAX_CHANNEL_MEMBERS: usize = 64;
pub const MAX_CHANNEL_ID_PEER_BYTES: usize = 128;
pub const MAX_CHANNELS_PER_GROUP: usize = 16;

const HEADER_BYTES: usize = 4 + 1 + 4 + 16 + 4;
/// Hard cap on the framed application body before MLS encryption.
pub const MAX_CHANNEL_FRAME_BYTES: usize = 4096;
const MAX_CHANNEL_BODY_BYTES: usize = MAX_CHANNEL_FRAME_BYTES - HEADER_BYTES;

const KIND_TEXT: u8 = 1;
const KIND_CREATE: u8 = 2;
const KIND_RENAME: u8 = 3;
const KIND_SET_MEMBERS: u8 = 4;

/// What a channel frame asks the group to do. Metadata is application policy
/// enforced by every client; it does not create an MLS commit or new epoch.
#[derive(Clone, PartialEq, Eq)]
pub enum ChannelFrameKind {
    /// Encrypted text addressed to one channel.
    Text { text: String },
    /// Create a channel with an explicit allowed-member set.
    Create { name: String, members: Vec<PeerId> },
    /// Rename an existing channel.
    Rename { name: String },
    /// Replace an existing channel's allowed-member set.
    SetMembers { members: Vec<PeerId> },
}

impl fmt::Debug for ChannelFrameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text { text } => f
                .debug_struct("Text")
                .field("text_len", &text.len())
                .field("text", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Create { name, members } => f
                .debug_struct("Create")
                .field("name_len", &name.len())
                .field("name", &"<redacted>")
                .field("members", &members.len())
                .finish_non_exhaustive(),
            Self::Rename { name } => f
                .debug_struct("Rename")
                .field("name_len", &name.len())
                .field("name", &"<redacted>")
                .finish_non_exhaustive(),
            Self::SetMembers { members } => f
                .debug_struct("SetMembers")
                .field("members", &members.len())
                .finish_non_exhaustive(),
        }
    }
}

/// A versioned channel application body. All fields are inside MLS ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelFrame {
    pub channel_id: [u8; 16],
    pub revision: u32,
    pub kind: ChannelFrameKind,
}

impl fmt::Debug for ChannelFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelFrame")
            .field("channel_id", &hex(&self.channel_id))
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ChannelFrame {
    pub fn text(channel_id: [u8; 16], revision: u32, text: &str) -> Result<Self, ChatError> {
        validate_text(text)?;
        Ok(Self {
            channel_id,
            revision,
            kind: ChannelFrameKind::Text {
                text: text.to_owned(),
            },
        })
    }

    pub fn create(channel_id: [u8; 16], name: &str, members: &[PeerId]) -> Result<Self, ChatError> {
        let name = validate_name(name)?;
        let members = validate_members(members)?;
        Ok(Self {
            channel_id,
            revision: 1,
            kind: ChannelFrameKind::Create { name, members },
        })
    }

    pub fn rename(channel_id: [u8; 16], revision: u32, name: &str) -> Result<Self, ChatError> {
        let name = validate_name(name)?;
        Ok(Self {
            channel_id,
            revision,
            kind: ChannelFrameKind::Rename { name },
        })
    }

    pub fn set_members(
        channel_id: [u8; 16],
        revision: u32,
        members: &[PeerId],
    ) -> Result<Self, ChatError> {
        let members = validate_members(members)?;
        Ok(Self {
            channel_id,
            revision,
            kind: ChannelFrameKind::SetMembers { members },
        })
    }

    /// Canonical bounded encoding. No serde or external codec is needed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ChatError> {
        let mut body = Vec::with_capacity(128);
        match &self.kind {
            ChannelFrameKind::Text { text } => {
                body.extend_from_slice(text.as_bytes());
            }
            ChannelFrameKind::Create { name, members } => {
                put_name(&mut body, name)?;
                put_members(&mut body, members)?;
            }
            ChannelFrameKind::Rename { name } => put_name(&mut body, name)?,
            ChannelFrameKind::SetMembers { members } => put_members(&mut body, members)?,
        }
        if body.len() > MAX_CHANNEL_BODY_BYTES {
            return Err(ChatError::InvalidChannelFrame("channel body is too large"));
        }

        let mut out = Vec::with_capacity(HEADER_BYTES + body.len());
        out.extend_from_slice(&CHANNEL_MAGIC);
        out.push(self.kind.code());
        out.extend_from_slice(&self.revision.to_le_bytes());
        out.extend_from_slice(&self.channel_id);
        out.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| ChatError::InvalidChannelFrame("channel body length overflow"))?
                .to_le_bytes(),
        );
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strict bounded decoding. Trailing bytes, unknown kinds, invalid UTF-8,
    /// duplicate peers, empty member sets, and oversized fields fail closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChatError> {
        if bytes.len() > MAX_CHANNEL_FRAME_BYTES {
            return Err(ChatError::InvalidChannelFrame("channel frame is too large"));
        }
        let mut reader = Reader::new(bytes);
        if reader.fixed::<4>()? != CHANNEL_MAGIC {
            return Err(ChatError::InvalidChannelFrame(
                "unknown channel frame magic",
            ));
        }
        let kind = ChannelFrameKind::from_code(reader.u8()?)?;
        let revision = reader.u32()?;
        let channel_id = reader.fixed::<16>()?;
        let body_len = reader.u32()? as usize;
        if body_len > MAX_CHANNEL_BODY_BYTES {
            return Err(ChatError::InvalidChannelFrame("channel body is too large"));
        }
        let body = reader.take(body_len)?;
        reader.finish()?;

        let kind = match kind {
            ChannelFrameKindCode::Text => {
                let text = std::str::from_utf8(body)
                    .map_err(|_| ChatError::InvalidChannelFrame("channel text is not UTF-8"))?;
                validate_text(text)?;
                ChannelFrameKind::Text {
                    text: text.to_owned(),
                }
            }
            ChannelFrameKindCode::Create => {
                let mut body_reader = Reader::new(body);
                let name = body_reader.name()?;
                let members = body_reader.members()?;
                body_reader.finish()?;
                ChannelFrameKind::Create { name, members }
            }
            ChannelFrameKindCode::Rename => {
                let mut body_reader = Reader::new(body);
                let name = body_reader.name()?;
                body_reader.finish()?;
                ChannelFrameKind::Rename { name }
            }
            ChannelFrameKindCode::SetMembers => {
                let mut body_reader = Reader::new(body);
                let members = body_reader.members()?;
                body_reader.finish()?;
                ChannelFrameKind::SetMembers { members }
            }
        };
        Ok(Self {
            channel_id,
            revision,
            kind,
        })
    }
}

impl ChannelFrameKind {
    fn code(&self) -> u8 {
        match self {
            Self::Text { .. } => KIND_TEXT,
            Self::Create { .. } => KIND_CREATE,
            Self::Rename { .. } => KIND_RENAME,
            Self::SetMembers { .. } => KIND_SET_MEMBERS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelFrameKindCode {
    Text,
    Create,
    Rename,
    SetMembers,
}

impl ChannelFrameKind {
    fn from_code(code: u8) -> Result<ChannelFrameKindCode, ChatError> {
        match code {
            KIND_TEXT => Ok(ChannelFrameKindCode::Text),
            KIND_CREATE => Ok(ChannelFrameKindCode::Create),
            KIND_RENAME => Ok(ChannelFrameKindCode::Rename),
            KIND_SET_MEMBERS => Ok(ChannelFrameKindCode::SetMembers),
            _ => Err(ChatError::InvalidChannelFrame("unknown channel frame kind")),
        }
    }
}

fn validate_text(text: &str) -> Result<(), ChatError> {
    if text.trim().is_empty() {
        return Err(ChatError::EmptyMessage);
    }
    if text.len() > MAX_CHANNEL_TEXT_BYTES {
        return Err(ChatError::InvalidChannelFrame("channel text is too large"));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<String, ChatError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_CHANNEL_NAME_BYTES {
        return Err(ChatError::InvalidChannelFrame("invalid channel name"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(ChatError::InvalidChannelFrame("invalid channel name"));
    }
    Ok(trimmed.to_owned())
}

fn validate_members(members: &[PeerId]) -> Result<Vec<PeerId>, ChatError> {
    if members.is_empty() || members.len() > MAX_CHANNEL_MEMBERS {
        return Err(ChatError::InvalidChannelFrame(
            "invalid channel member count",
        ));
    }
    let unique: BTreeSet<PeerId> = members.iter().copied().collect();
    if unique.len() != members.len() {
        return Err(ChatError::InvalidChannelFrame("duplicate channel member"));
    }
    Ok(unique.into_iter().collect())
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<(), ChatError> {
    let bytes = name.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(ChatError::InvalidChannelFrame(
            "channel name length overflow",
        ));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_members(out: &mut Vec<u8>, members: &[PeerId]) -> Result<(), ChatError> {
    if members.len() > u16::MAX as usize {
        return Err(ChatError::InvalidChannelFrame(
            "channel member count overflow",
        ));
    }
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    for member in members {
        let bytes = member.to_bytes();
        if bytes.len() > MAX_CHANNEL_ID_PEER_BYTES {
            return Err(ChatError::InvalidChannelFrame(
                "channel peer id is too large",
            ));
        }
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ChatError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(ChatError::InvalidChannelFrame("length overflow"))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ChatError::InvalidChannelFrame("truncated channel frame"))?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ChatError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ChatError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ChatError::InvalidChannelFrame("truncated channel frame"))?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ChatError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ChatError::InvalidChannelFrame("truncated channel frame"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ChatError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChatError::InvalidChannelFrame("truncated channel frame"))
    }

    fn name(&mut self) -> Result<String, ChatError> {
        let len = self.u16()? as usize;
        if len == 0 || len > MAX_CHANNEL_NAME_BYTES {
            return Err(ChatError::InvalidChannelFrame("invalid channel name"));
        }
        let bytes = self.take(len)?;
        let name = std::str::from_utf8(bytes)
            .map_err(|_| ChatError::InvalidChannelFrame("channel name is not UTF-8"))?;
        validate_name(name)
    }

    fn members(&mut self) -> Result<Vec<PeerId>, ChatError> {
        let count = self.u16()? as usize;
        if count == 0 || count > MAX_CHANNEL_MEMBERS {
            return Err(ChatError::InvalidChannelFrame(
                "invalid channel member count",
            ));
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.u16()? as usize;
            if len == 0 || len > MAX_CHANNEL_ID_PEER_BYTES {
                return Err(ChatError::InvalidChannelFrame("invalid channel peer id"));
            }
            let peer = PeerId::from_bytes(self.take(len)?)
                .map_err(|_| ChatError::InvalidChannelFrame("invalid channel peer id"))?;
            members.push(peer);
        }
        validate_members(&members)
    }

    fn finish(self) -> Result<(), ChatError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ChatError::InvalidChannelFrame(
                "trailing bytes in channel frame",
            ))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        p2p_identity::Identity::generate()
            .expect("identity")
            .peer_id()
    }

    #[test]
    fn text_frame_round_trips_and_keeps_channel_id() {
        let frame = ChannelFrame::text([7; 16], 3, "hello channel").expect("frame");
        let bytes = frame.to_bytes().expect("encode");
        let decoded = ChannelFrame::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.channel_id, [7; 16]);
        assert_eq!(decoded.revision, 3);
    }

    #[test]
    fn policy_frames_round_trip_with_bounded_members() {
        let members = vec![peer(), peer()];
        let create = ChannelFrame::create([9; 16], " general ", &members).expect("create");
        let bytes = create.to_bytes().expect("encode");
        assert_eq!(ChannelFrame::from_bytes(&bytes).expect("decode"), create);

        let rename = ChannelFrame::rename([9; 16], 2, "renamed").expect("rename");
        let bytes = rename.to_bytes().expect("encode");
        assert_eq!(ChannelFrame::from_bytes(&bytes).expect("decode"), rename);

        let set = ChannelFrame::set_members([9; 16], 3, &members).expect("set members");
        let bytes = set.to_bytes().expect("encode");
        assert_eq!(ChannelFrame::from_bytes(&bytes).expect("decode"), set);
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let frame = ChannelFrame::text([1; 16], 1, "ok").expect("frame");
        let bytes = frame.to_bytes().expect("encode");

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xff;
        assert!(ChannelFrame::from_bytes(&bad_magic).is_err());

        let mut bad_kind = bytes.clone();
        bad_kind[4] = 99;
        assert!(ChannelFrame::from_bytes(&bad_kind).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ChannelFrame::from_bytes(&trailing).is_err());

        let truncated = &bytes[..bytes.len() - 1];
        assert!(ChannelFrame::from_bytes(truncated).is_err());

        let oversized = vec![0u8; MAX_CHANNEL_FRAME_BYTES + 1];
        assert!(ChannelFrame::from_bytes(&oversized).is_err());
    }

    #[test]
    fn invalid_names_members_and_text_are_rejected() {
        assert!(ChannelFrame::text([0; 16], 1, "   ").is_err());
        assert!(ChannelFrame::create([0; 16], "", &[peer()]).is_err());
        assert!(ChannelFrame::create([0; 16], "name", &[]).is_err());
        let duplicate = peer();
        assert!(ChannelFrame::create([0; 16], "name", &[duplicate, duplicate]).is_err());
        assert!(ChannelFrame::text([0; 16], 1, &"x".repeat(MAX_CHANNEL_TEXT_BYTES + 1)).is_err());
    }

    #[test]
    fn debug_output_redacts_channel_text_and_name() {
        let frame = ChannelFrame::create([3; 16], "secret-channel", &[peer()]).expect("frame");
        let rendered = format!("{frame:?}");
        assert!(!rendered.contains("secret-channel"));
        assert!(rendered.contains("<redacted>"));

        let text = ChannelFrame::text([3; 16], 1, "secret-message").expect("frame");
        let rendered = format!("{text:?}");
        assert!(!rendered.contains("secret-message"));
        assert!(rendered.contains("<redacted>"));
    }
}
