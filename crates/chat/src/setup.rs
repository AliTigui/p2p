//! Signed, versioned frames for the MLS setup protocol.
//!
//! KeyPackage and Welcome frames are transport-protected by Noise and signed by
//! the vault Ed25519 identity. The signature binds the sender PeerId, public
//! key, conversation ID, and frame body so an application cannot accept a setup
//! message from a different authenticated peer. Setup frames are not chat
//! messages and never carry delivery status.

use std::fmt;

use libp2p_identity::PeerId;
use p2p_groups::GroupOperation;
use p2p_identity::{Identity, verify_signature_with_public_bytes};

use crate::ChatError;

/// Fixed frame magic. Unknown magic is rejected, never negotiated.
pub const SETUP_MAGIC: [u8; 4] = *b"MLS1";
/// Setup frame version implemented by this build.
pub const SETUP_VERSION: u16 = 1;

/// Maximum bytes accepted in one setup frame. This matches the transport cap.
pub const MAX_SETUP_FRAME_BYTES: usize = p2p_network::MAX_MESSAGE_BYTES;
/// Maximum bytes in the signed setup body, leaving room for metadata.
pub const MAX_SETUP_PAYLOAD_BYTES: usize = MAX_SETUP_FRAME_BYTES - 4096;

const MAX_PUBLIC_KEY_BYTES: usize = 256;
const MAX_PEER_ID_BYTES: usize = 128;
const SIGNATURE_LEN: usize = 64;

const KEY_PACKAGE_REQUEST: u8 = 1;
const KEY_PACKAGE_RESPONSE: u8 = 2;
const WELCOME: u8 = 3;
const WELCOME_ACK: u8 = 4;
const GROUP_JOIN_REQUEST: u8 = 5;
const GROUP_KEY_PACKAGE_RESPONSE: u8 = 6;
const GROUP_WELCOME: u8 = 7;
const GROUP_COMMIT: u8 = 8;
const GROUP_COMMIT_ACK: u8 = 9;
const GROUP_WELCOME_ACK: u8 = 10;

/// One step of the signed MLS setup and group-management exchange. Payloads are
/// opaque here; `p2p-groups` validates KeyPackages, Welcomes, and commits before
/// any group state changes.
#[derive(Clone, PartialEq, Eq)]
pub enum SetupMessage {
    /// Ask the peer to generate a KeyPackage for a new conversation.
    KeyPackageRequest { conversation_id: [u8; 16] },
    /// Return the generated KeyPackage for that conversation.
    KeyPackageResponse {
        conversation_id: [u8; 16],
        key_package: Vec<u8>,
    },
    /// Add the peer from its KeyPackage and deliver the Welcome.
    Welcome {
        conversation_id: [u8; 16],
        welcome: Vec<u8>,
    },
    /// Acknowledge that the Welcome was accepted and the group was joined.
    WelcomeAck {
        conversation_id: [u8; 16],
        accepted: bool,
    },
    /// Ask an already connected peer to join an existing group.
    GroupJoinRequest { conversation_id: [u8; 16] },
    /// Return a fresh KeyPackage for a group join request.
    GroupKeyPackageResponse {
        conversation_id: [u8; 16],
        key_package: Vec<u8>,
    },
    /// Deliver a Welcome to a newly added group member.
    GroupWelcome {
        conversation_id: [u8; 16],
        welcome: Vec<u8>,
    },
    /// Apply one authorized epoch-changing MLS commit.
    GroupCommit {
        conversation_id: [u8; 16],
        operation: GroupOperation,
        target: Option<PeerId>,
        commit: Vec<u8>,
    },
    /// Acknowledge that a group commit was applied or report rejection.
    GroupCommitAck {
        conversation_id: [u8; 16],
        operation: GroupOperation,
        accepted: bool,
    },
    /// Acknowledge that a group Welcome was accepted and joined.
    GroupWelcomeAck {
        conversation_id: [u8; 16],
        accepted: bool,
    },
}

impl SetupMessage {
    fn code(&self) -> u8 {
        match self {
            Self::KeyPackageRequest { .. } => KEY_PACKAGE_REQUEST,
            Self::KeyPackageResponse { .. } => KEY_PACKAGE_RESPONSE,
            Self::Welcome { .. } => WELCOME,
            Self::WelcomeAck { .. } => WELCOME_ACK,
            Self::GroupJoinRequest { .. } => GROUP_JOIN_REQUEST,
            Self::GroupKeyPackageResponse { .. } => GROUP_KEY_PACKAGE_RESPONSE,
            Self::GroupWelcome { .. } => GROUP_WELCOME,
            Self::GroupCommit { .. } => GROUP_COMMIT,
            Self::GroupCommitAck { .. } => GROUP_COMMIT_ACK,
            Self::GroupWelcomeAck { .. } => GROUP_WELCOME_ACK,
        }
    }

    fn conversation_id(&self) -> &[u8; 16] {
        match self {
            Self::KeyPackageRequest { conversation_id }
            | Self::KeyPackageResponse {
                conversation_id, ..
            }
            | Self::Welcome {
                conversation_id, ..
            }
            | Self::WelcomeAck {
                conversation_id, ..
            }
            | Self::GroupJoinRequest { conversation_id }
            | Self::GroupKeyPackageResponse {
                conversation_id, ..
            }
            | Self::GroupWelcome {
                conversation_id, ..
            }
            | Self::GroupCommit {
                conversation_id, ..
            }
            | Self::GroupCommitAck {
                conversation_id, ..
            }
            | Self::GroupWelcomeAck {
                conversation_id, ..
            } => conversation_id,
        }
    }

    fn payload(&self) -> Result<Vec<u8>, ChatError> {
        match self {
            Self::KeyPackageRequest { .. } | Self::GroupJoinRequest { .. } => Ok(Vec::new()),
            Self::KeyPackageResponse { key_package, .. }
            | Self::GroupKeyPackageResponse { key_package, .. } => Ok(key_package.clone()),
            Self::Welcome { welcome, .. } | Self::GroupWelcome { welcome, .. } => {
                Ok(welcome.clone())
            }
            Self::WelcomeAck { accepted, .. } | Self::GroupWelcomeAck { accepted, .. } => {
                Ok(vec![u8::from(*accepted)])
            }
            Self::GroupCommit {
                operation,
                target,
                commit,
                ..
            } => group_commit_payload(*operation, target.as_ref(), commit),
            Self::GroupCommitAck {
                operation,
                accepted,
                ..
            } => Ok(vec![operation.code(), u8::from(*accepted)]),
        }
    }

    fn from_parts(
        code: u8,
        conversation_id: [u8; 16],
        payload: Vec<u8>,
    ) -> Result<Self, ChatError> {
        match code {
            KEY_PACKAGE_REQUEST => {
                expect_empty(&payload)?;
                Ok(Self::KeyPackageRequest { conversation_id })
            }
            KEY_PACKAGE_RESPONSE => {
                expect_payload(&payload)?;
                Ok(Self::KeyPackageResponse {
                    conversation_id,
                    key_package: payload,
                })
            }
            WELCOME => {
                expect_payload(&payload)?;
                Ok(Self::Welcome {
                    conversation_id,
                    welcome: payload,
                })
            }
            WELCOME_ACK => {
                let accepted = parse_ack(&payload, "invalid welcome acknowledgement")?;
                Ok(Self::WelcomeAck {
                    conversation_id,
                    accepted,
                })
            }
            GROUP_JOIN_REQUEST => {
                expect_empty(&payload)?;
                Ok(Self::GroupJoinRequest { conversation_id })
            }
            GROUP_KEY_PACKAGE_RESPONSE => {
                expect_payload(&payload)?;
                Ok(Self::GroupKeyPackageResponse {
                    conversation_id,
                    key_package: payload,
                })
            }
            GROUP_WELCOME => {
                expect_payload(&payload)?;
                Ok(Self::GroupWelcome {
                    conversation_id,
                    welcome: payload,
                })
            }
            GROUP_COMMIT => {
                let (operation, target, commit) = parse_group_commit_payload(&payload)?;
                Ok(Self::GroupCommit {
                    conversation_id,
                    operation,
                    target,
                    commit,
                })
            }
            GROUP_COMMIT_ACK => {
                if payload.len() != 2 || payload[1] > 1 {
                    return Err(ChatError::InvalidSetup(
                        "invalid group commit acknowledgement",
                    ));
                }
                let operation = GroupOperation::from_code(payload[0])
                    .ok_or(ChatError::InvalidSetup("unknown group operation"))?;
                Ok(Self::GroupCommitAck {
                    conversation_id,
                    operation,
                    accepted: payload[1] == 1,
                })
            }
            GROUP_WELCOME_ACK => {
                let accepted = parse_ack(&payload, "invalid group welcome acknowledgement")?;
                Ok(Self::GroupWelcomeAck {
                    conversation_id,
                    accepted,
                })
            }
            _ => Err(ChatError::InvalidSetup("unknown setup message type")),
        }
    }
}

impl fmt::Debug for SetupMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::KeyPackageRequest { .. } => "key-package-request",
            Self::KeyPackageResponse { .. } => "key-package-response",
            Self::Welcome { .. } => "welcome",
            Self::WelcomeAck { .. } => "welcome-ack",
            Self::GroupJoinRequest { .. } => "group-join-request",
            Self::GroupKeyPackageResponse { .. } => "group-key-package-response",
            Self::GroupWelcome { .. } => "group-welcome",
            Self::GroupCommit { .. } => "group-commit",
            Self::GroupCommitAck { .. } => "group-commit-ack",
            Self::GroupWelcomeAck { .. } => "group-welcome-ack",
        };
        f.debug_struct("SetupMessage")
            .field("kind", &kind)
            .field("conversation_id", &hex(self.conversation_id()))
            .field(
                "payload_len",
                &self.payload().map(|payload| payload.len()).unwrap_or(0),
            )
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A signed setup frame. Parsing does not verify the signature; callers must
/// call [`Self::verify`] with the PeerId authenticated by Noise before using
/// any field for group state.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupEnvelope {
    pub sender: PeerId,
    pub sender_public_key: Vec<u8>,
    pub message: SetupMessage,
    signature: [u8; SIGNATURE_LEN],
}

impl SetupEnvelope {
    /// Sign a new setup frame with the local vault identity.
    pub fn new(identity: &Identity, message: SetupMessage) -> Result<Self, ChatError> {
        let mut envelope = Self {
            sender: identity.peer_id(),
            sender_public_key: identity.public_key_bytes(),
            message,
            signature: [0; SIGNATURE_LEN],
        };
        envelope.check_sizes()?;
        let signature = identity.sign(&envelope.signing_bytes()?)?;
        envelope.signature = signature.as_slice().try_into().map_err(|_| {
            ChatError::InvalidSetup("identity produced an unexpected signature length")
        })?;
        Ok(envelope)
    }

    /// Decode a setup frame. This does not verify the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChatError> {
        if bytes.len() > MAX_SETUP_FRAME_BYTES {
            return Err(ChatError::InvalidSetup("frame is too large"));
        }
        let mut reader = Reader::new(bytes);
        if reader.fixed::<4>()? != SETUP_MAGIC {
            return Err(ChatError::InvalidSetup("wrong frame magic"));
        }
        let version = reader.u16()?;
        if version != SETUP_VERSION {
            return Err(ChatError::InvalidSetup("unsupported frame version"));
        }
        let code = reader.u8()?;
        let conversation_id = reader.fixed::<16>()?;
        let sender_public_key = reader.var(MAX_PUBLIC_KEY_BYTES)?;
        let sender_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let payload = reader.var(MAX_SETUP_PAYLOAD_BYTES)?;
        let signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;

        let sender = PeerId::from_bytes(&sender_bytes)
            .map_err(|_| ChatError::InvalidSetup("invalid sender PeerId"))?;
        let message = SetupMessage::from_parts(code, conversation_id, payload)?;
        let envelope = Self {
            sender,
            sender_public_key,
            message,
            signature,
        };
        envelope.check_sizes()?;
        Ok(envelope)
    }

    /// Encode the full signed setup frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ChatError> {
        self.check_sizes()?;
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > MAX_SETUP_FRAME_BYTES {
            return Err(ChatError::InvalidSetup("frame is too large"));
        }
        Ok(bytes)
    }

    /// Verify protocol fields, signature, and binding to the authenticated
    /// transport peer. This must happen before any KeyPackage or Welcome bytes
    /// are passed to OpenMLS.
    pub fn verify(&self, expected_peer: &PeerId) -> Result<(), ChatError> {
        if &self.sender != expected_peer {
            return Err(ChatError::UnexpectedSender);
        }
        self.check_sizes()?;
        let valid = verify_signature_with_public_bytes(
            &self.signing_bytes()?,
            &self.signature,
            &self.sender_public_key,
            &self.sender,
        )?;
        if valid {
            Ok(())
        } else {
            Err(ChatError::InvalidSetup("signature is invalid"))
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, ChatError> {
        let mut bytes = Vec::with_capacity(self.message.payload()?.len() + 128);
        bytes.extend_from_slice(&SETUP_MAGIC);
        bytes.extend_from_slice(&SETUP_VERSION.to_le_bytes());
        bytes.push(self.message.code());
        bytes.extend_from_slice(self.message.conversation_id());
        put_bytes(&mut bytes, &self.sender_public_key)?;
        put_bytes(&mut bytes, &self.sender.to_bytes())?;
        put_bytes(&mut bytes, &self.message.payload()?)?;
        Ok(bytes)
    }

    fn check_sizes(&self) -> Result<(), ChatError> {
        if SETUP_MAGIC != *b"MLS1" {
            return Err(ChatError::InvalidSetup("wrong frame magic"));
        }
        if self.sender_public_key.is_empty() || self.sender_public_key.len() > MAX_PUBLIC_KEY_BYTES
        {
            return Err(ChatError::InvalidSetup("invalid sender public key length"));
        }
        let peer_bytes = self.sender.to_bytes();
        if peer_bytes.is_empty() || peer_bytes.len() > MAX_PEER_ID_BYTES {
            return Err(ChatError::InvalidSetup("invalid sender PeerId length"));
        }
        if self.message.payload()?.len() > MAX_SETUP_PAYLOAD_BYTES {
            return Err(ChatError::InvalidSetup("setup payload is too large"));
        }
        Ok(())
    }
}

impl fmt::Debug for SetupEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupEnvelope")
            .field("version", &SETUP_VERSION)
            .field("sender", &self.sender.to_string())
            .field("public_key_len", &self.sender_public_key.len())
            .field("message", &self.message)
            .field("signature", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn expect_empty(payload: &[u8]) -> Result<(), ChatError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(ChatError::InvalidSetup("unexpected setup payload"))
    }
}

fn expect_payload(payload: &[u8]) -> Result<(), ChatError> {
    if payload.is_empty() {
        Err(ChatError::InvalidSetup("missing setup payload"))
    } else {
        Ok(())
    }
}

fn parse_ack(payload: &[u8], reason: &'static str) -> Result<bool, ChatError> {
    if payload.len() != 1 || payload[0] > 1 {
        Err(ChatError::InvalidSetup(reason))
    } else {
        Ok(payload[0] == 1)
    }
}

fn group_commit_payload(
    operation: GroupOperation,
    target: Option<&PeerId>,
    commit: &[u8],
) -> Result<Vec<u8>, ChatError> {
    if commit.is_empty() {
        return Err(ChatError::InvalidSetup("missing MLS commit"));
    }
    let mut payload = Vec::with_capacity(commit.len() + 64);
    payload.push(operation.code());
    match target {
        Some(peer) => {
            payload.push(1);
            put_bytes(&mut payload, &peer.to_bytes())?;
        }
        None => payload.push(0),
    }
    payload.extend_from_slice(commit);
    Ok(payload)
}

fn parse_group_commit_payload(
    payload: &[u8],
) -> Result<(GroupOperation, Option<PeerId>, Vec<u8>), ChatError> {
    let mut reader = Reader::new(payload);
    let operation = GroupOperation::from_code(reader.u8()?)
        .ok_or(ChatError::InvalidSetup("unknown group operation"))?;
    let target_present = reader.u8()?;
    if target_present > 1 {
        return Err(ChatError::InvalidSetup("invalid group commit target flag"));
    }
    let target = if target_present == 1 {
        let bytes = reader.var(MAX_PEER_ID_BYTES)?;
        Some(
            PeerId::from_bytes(&bytes)
                .map_err(|_| ChatError::InvalidSetup("invalid group commit target"))?,
        )
    } else {
        None
    };
    let commit = reader.rest(MAX_SETUP_PAYLOAD_BYTES)?;
    if commit.is_empty() {
        return Err(ChatError::InvalidSetup("missing MLS commit"));
    }
    reader.finish()?;
    Ok((operation, target, commit.to_vec()))
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ChatError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| ChatError::InvalidSetup("length field overflow"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
            .ok_or(ChatError::InvalidSetup("length overflow"))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ChatError::InvalidSetup("truncated frame"))?;
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
            .map_err(|_| ChatError::InvalidSetup("truncated frame"))?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ChatError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ChatError::InvalidSetup("truncated frame"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ChatError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChatError::InvalidSetup("truncated frame"))
    }

    fn var(&mut self, max: usize) -> Result<Vec<u8>, ChatError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(ChatError::InvalidSetup("field is too large"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn rest(&mut self, max: usize) -> Result<&'a [u8], ChatError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if remaining > max {
            return Err(ChatError::InvalidSetup("field is too large"));
        }
        self.take(remaining)
    }

    fn finish(self) -> Result<(), ChatError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ChatError::InvalidSetup("trailing bytes in frame"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> SetupMessage {
        SetupMessage::KeyPackageResponse {
            conversation_id: [7u8; 16],
            key_package: b"opaque key package bytes".to_vec(),
        }
    }

    #[test]
    fn signed_setup_frame_round_trips_and_binds_the_sender() {
        let identity = Identity::generate().expect("identity");
        let envelope = SetupEnvelope::new(&identity, message()).expect("signed frame");
        let bytes = envelope.to_bytes().expect("encoded frame");
        let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded frame");
        assert_eq!(decoded, envelope);
        decoded
            .verify(&identity.peer_id())
            .expect("valid signature");
    }

    #[test]
    fn welcome_acknowledgement_round_trips_both_statuses() {
        let identity = Identity::generate().expect("identity");
        for accepted in [true, false] {
            let envelope = SetupEnvelope::new(
                &identity,
                SetupMessage::WelcomeAck {
                    conversation_id: [9u8; 16],
                    accepted,
                },
            )
            .expect("signed ack");
            let bytes = envelope.to_bytes().expect("encoded ack");
            let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded ack");
            decoded.verify(&identity.peer_id()).expect("valid ack");
            assert_eq!(decoded, envelope);
        }
    }

    #[test]
    fn tampered_and_wrong_peer_frames_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let mut bytes = SetupEnvelope::new(&identity, message())
            .expect("signed frame")
            .to_bytes()
            .expect("encoded frame");
        *bytes.last_mut().expect("signature byte") ^= 1;

        let tampered = SetupEnvelope::from_bytes(&bytes).expect("parsed tampered frame");
        assert!(tampered.verify(&identity.peer_id()).is_err());

        let valid = SetupEnvelope::new(&identity, message()).expect("signed frame");
        assert!(matches!(
            valid.verify(&other.peer_id()),
            Err(ChatError::UnexpectedSender)
        ));
    }

    #[test]
    fn malformed_and_oversized_frames_are_rejected() {
        assert!(SetupEnvelope::from_bytes(&[]).is_err());
        assert!(SetupEnvelope::from_bytes(b"not a setup frame").is_err());

        let identity = Identity::generate().expect("identity");
        let oversized = SetupMessage::KeyPackageResponse {
            conversation_id: [1u8; 16],
            key_package: vec![0u8; MAX_SETUP_PAYLOAD_BYTES + 1],
        };
        assert!(SetupEnvelope::new(&identity, oversized).is_err());
    }

    #[test]
    fn debug_output_omits_key_package_and_welcome_bytes() {
        let identity = Identity::generate().expect("identity");
        let secret = b"SECRET_WELCOME_BYTES".to_vec();
        let envelope = SetupEnvelope::new(
            &identity,
            SetupMessage::Welcome {
                conversation_id: [3u8; 16],
                welcome: secret,
            },
        )
        .expect("signed frame");
        let debug = format!("{envelope:?}");
        assert!(!debug.contains("SECRET_WELCOME_BYTES"));
        assert!(debug.contains("payload_len"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn group_control_frames_round_trip_and_bind_the_sender() {
        let identity = Identity::generate().expect("identity");
        let target = Identity::generate().expect("target").peer_id();
        let conversation_id = [11u8; 16];
        let cases = [
            SetupMessage::GroupJoinRequest { conversation_id },
            SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                key_package: b"group key package".to_vec(),
            },
            SetupMessage::GroupWelcome {
                conversation_id,
                welcome: b"group welcome".to_vec(),
            },
            SetupMessage::GroupCommit {
                conversation_id,
                operation: GroupOperation::Add,
                target: Some(target),
                commit: b"group commit".to_vec(),
            },
            SetupMessage::GroupCommit {
                conversation_id,
                operation: GroupOperation::Update,
                target: None,
                commit: b"update commit".to_vec(),
            },
            SetupMessage::GroupCommitAck {
                conversation_id,
                operation: GroupOperation::Remove,
                accepted: true,
            },
            SetupMessage::GroupCommitAck {
                conversation_id,
                operation: GroupOperation::Update,
                accepted: false,
            },
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                accepted: true,
            },
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                accepted: false,
            },
        ];

        for case in cases {
            let envelope = SetupEnvelope::new(&identity, case.clone()).expect("signed frame");
            let bytes = envelope.to_bytes().expect("encoded frame");
            let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded frame");
            decoded
                .verify(&identity.peer_id())
                .expect("valid signed control frame");
            assert_eq!(decoded, envelope);
        }
    }

    #[test]
    fn group_commit_payloads_are_strictly_decoded() {
        let conversation_id = [12u8; 16];

        let mut unknown_operation = vec![GroupOperation::Add.code() + 9, 0];
        unknown_operation.extend_from_slice(b"commit");
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT, conversation_id, unknown_operation).is_err()
        );

        let mut bad_target_flag = vec![GroupOperation::Remove.code(), 2];
        bad_target_flag.extend_from_slice(b"commit");
        assert!(SetupMessage::from_parts(GROUP_COMMIT, conversation_id, bad_target_flag).is_err());

        let mut truncated_target = vec![GroupOperation::Remove.code(), 1, 8, 0, 0, 0];
        truncated_target.extend_from_slice(&[7u8; 4]);
        assert!(SetupMessage::from_parts(GROUP_COMMIT, conversation_id, truncated_target).is_err());

        let missing_commit = vec![GroupOperation::Update.code(), 0];
        assert!(SetupMessage::from_parts(GROUP_COMMIT, conversation_id, missing_commit).is_err());

        assert!(SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, vec![1]).is_err());
        assert!(SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, vec![1, 2]).is_err());
        assert!(SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, vec![99, 1]).is_err());
        assert!(SetupMessage::from_parts(GROUP_WELCOME_ACK, conversation_id, vec![1, 1]).is_err());
        assert!(SetupMessage::from_parts(GROUP_JOIN_REQUEST, conversation_id, vec![0]).is_err());
    }

    #[test]
    fn oversized_and_tampered_group_frames_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let oversized = SetupMessage::GroupCommit {
            conversation_id: [13u8; 16],
            operation: GroupOperation::Add,
            target: None,
            commit: vec![0u8; MAX_SETUP_PAYLOAD_BYTES + 1],
        };
        assert!(SetupEnvelope::new(&identity, oversized).is_err());

        let mut bytes = SetupEnvelope::new(
            &identity,
            SetupMessage::GroupWelcome {
                conversation_id: [13u8; 16],
                welcome: b"signed welcome".to_vec(),
            },
        )
        .expect("signed frame")
        .to_bytes()
        .expect("encoded frame");
        *bytes.last_mut().expect("signature byte") ^= 1;
        let tampered = SetupEnvelope::from_bytes(&bytes).expect("parsed frame");
        assert!(tampered.verify(&identity.peer_id()).is_err());
    }

    #[test]
    fn group_control_debug_redacts_welcome_and_commit_bytes() {
        let identity = Identity::generate().expect("identity");
        let secret = b"SECRET_GROUP_WELCOME_BYTES";
        let commit_secret = b"SECRET_MLS_COMMIT_BYTES";
        let welcome = SetupEnvelope::new(
            &identity,
            SetupMessage::GroupWelcome {
                conversation_id: [14u8; 16],
                welcome: secret.to_vec(),
            },
        )
        .expect("signed welcome");
        let commit = SetupEnvelope::new(
            &identity,
            SetupMessage::GroupCommit {
                conversation_id: [14u8; 16],
                operation: GroupOperation::Add,
                target: None,
                commit: commit_secret.to_vec(),
            },
        )
        .expect("signed commit");

        let debug = format!("{welcome:?}\n{commit:?}");
        assert!(!debug.contains("SECRET_GROUP_WELCOME_BYTES"));
        assert!(!debug.contains("SECRET_MLS_COMMIT_BYTES"));
        assert!(debug.contains("group-welcome"));
        assert!(debug.contains("group-commit"));
        assert!(debug.contains("<redacted>"));
    }
}
