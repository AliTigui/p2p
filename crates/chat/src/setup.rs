//! Signed, versioned frames for the MLS setup protocol.
//!
//! KeyPackage and Welcome frames are transport-protected by Noise and signed by
//! the vault Ed25519 identity. The signature binds the sender PeerId, public
//! key, transaction ID, conversation ID, and frame body so an application cannot
//! accept a setup message from a different authenticated peer or a different
//! operation. Setup frames are not chat messages and never carry delivery
//! status.

use std::fmt;

use libp2p_identity::PeerId;
use p2p_groups::GroupOperation;
use p2p_identity::{Identity, verify_signature_with_public_bytes};

use crate::ChatError;

/// Fixed frame magic. Unknown magic is rejected, never negotiated.
pub const SETUP_MAGIC: [u8; 4] = *b"MLS1";
/// Setup frame version implemented by this build. Version 1 frames carried no
/// transaction ID and are rejected rather than ambiguously accepted.
pub const SETUP_VERSION: u16 = 2;
/// Length of the random, signed transaction ID carried by every setup frame.
pub const TRANSACTION_ID_LEN: usize = 16;
/// A fresh random identifier shared by every frame of one setup operation.
pub type TransactionId = [u8; TRANSACTION_ID_LEN];

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
    KeyPackageRequest {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
    },
    /// Return the generated KeyPackage for that conversation.
    KeyPackageResponse {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        key_package: Vec<u8>,
    },
    /// Add the peer from its KeyPackage and deliver the Welcome.
    Welcome {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        welcome: Vec<u8>,
    },
    /// Acknowledge that the Welcome was accepted and the group was joined.
    WelcomeAck {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        accepted: bool,
    },
    /// Ask an already connected peer to join an existing group.
    GroupJoinRequest {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
    },
    /// Return a fresh KeyPackage for a group join request.
    GroupKeyPackageResponse {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        key_package: Vec<u8>,
    },
    /// Deliver a Welcome to a newly added group member.
    GroupWelcome {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        welcome: Vec<u8>,
    },
    /// Apply one authorized epoch-changing MLS commit.
    GroupCommit {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        operation: GroupOperation,
        target: Option<PeerId>,
        commit: Vec<u8>,
    },
    /// Acknowledge that a group commit was applied or report rejection.
    GroupCommitAck {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
        operation: GroupOperation,
        accepted: bool,
    },
    /// Acknowledge that a group Welcome was accepted and joined.
    GroupWelcomeAck {
        conversation_id: [u8; 16],
        transaction_id: TransactionId,
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

    /// The conversation this setup frame belongs to.
    pub fn conversation_id(&self) -> &[u8; 16] {
        match self {
            Self::KeyPackageRequest {
                conversation_id, ..
            }
            | Self::KeyPackageResponse {
                conversation_id, ..
            }
            | Self::Welcome {
                conversation_id, ..
            }
            | Self::WelcomeAck {
                conversation_id, ..
            }
            | Self::GroupJoinRequest {
                conversation_id, ..
            }
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

    /// The signed transaction ID shared by every frame of one setup operation.
    pub fn transaction_id(&self) -> &TransactionId {
        match self {
            Self::KeyPackageRequest { transaction_id, .. }
            | Self::KeyPackageResponse { transaction_id, .. }
            | Self::Welcome { transaction_id, .. }
            | Self::WelcomeAck { transaction_id, .. }
            | Self::GroupJoinRequest { transaction_id, .. }
            | Self::GroupKeyPackageResponse { transaction_id, .. }
            | Self::GroupWelcome { transaction_id, .. }
            | Self::GroupCommit { transaction_id, .. }
            | Self::GroupCommitAck { transaction_id, .. }
            | Self::GroupWelcomeAck { transaction_id, .. } => transaction_id,
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
        transaction_id: TransactionId,
        payload: Vec<u8>,
    ) -> Result<Self, ChatError> {
        match code {
            KEY_PACKAGE_REQUEST => {
                expect_empty(&payload)?;
                Ok(Self::KeyPackageRequest {
                    conversation_id,
                    transaction_id,
                })
            }
            KEY_PACKAGE_RESPONSE => {
                expect_payload(&payload)?;
                Ok(Self::KeyPackageResponse {
                    conversation_id,
                    transaction_id,
                    key_package: payload,
                })
            }
            WELCOME => {
                expect_payload(&payload)?;
                Ok(Self::Welcome {
                    conversation_id,
                    transaction_id,
                    welcome: payload,
                })
            }
            WELCOME_ACK => {
                let accepted = parse_ack(&payload, "invalid welcome acknowledgement")?;
                Ok(Self::WelcomeAck {
                    conversation_id,
                    transaction_id,
                    accepted,
                })
            }
            GROUP_JOIN_REQUEST => {
                expect_empty(&payload)?;
                Ok(Self::GroupJoinRequest {
                    conversation_id,
                    transaction_id,
                })
            }
            GROUP_KEY_PACKAGE_RESPONSE => {
                expect_payload(&payload)?;
                Ok(Self::GroupKeyPackageResponse {
                    conversation_id,
                    transaction_id,
                    key_package: payload,
                })
            }
            GROUP_WELCOME => {
                expect_payload(&payload)?;
                Ok(Self::GroupWelcome {
                    conversation_id,
                    transaction_id,
                    welcome: payload,
                })
            }
            GROUP_COMMIT => {
                let (operation, target, commit) = parse_group_commit_payload(&payload)?;
                Ok(Self::GroupCommit {
                    conversation_id,
                    transaction_id,
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
                    transaction_id,
                    operation,
                    accepted: payload[1] == 1,
                })
            }
            GROUP_WELCOME_ACK => {
                let accepted = parse_ack(&payload, "invalid group welcome acknowledgement")?;
                Ok(Self::GroupWelcomeAck {
                    conversation_id,
                    transaction_id,
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
            .field("transaction_id", &hex(self.transaction_id()))
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
        if version == 1 {
            return Err(ChatError::InvalidSetup(
                "unsupported setup frame version 1; transaction IDs are required",
            ));
        }
        if version != SETUP_VERSION {
            return Err(ChatError::InvalidSetup("unsupported setup frame version"));
        }
        let transaction_id = reader.fixed::<TRANSACTION_ID_LEN>()?;
        let code = reader.u8()?;
        let conversation_id = reader.fixed::<16>()?;
        let sender_public_key = reader.var(MAX_PUBLIC_KEY_BYTES)?;
        let sender_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let payload = reader.var(MAX_SETUP_PAYLOAD_BYTES)?;
        let signature = reader.fixed::<SIGNATURE_LEN>()?;
        reader.finish()?;

        let sender = PeerId::from_bytes(&sender_bytes)
            .map_err(|_| ChatError::InvalidSetup("invalid sender PeerId"))?;
        let message = SetupMessage::from_parts(code, conversation_id, transaction_id, payload)?;
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
        bytes.extend_from_slice(self.message.transaction_id());
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
    use p2p_messaging::random_id;

    fn txid() -> TransactionId {
        random_id().expect("random transaction id")
    }

    fn message() -> SetupMessage {
        SetupMessage::KeyPackageResponse {
            conversation_id: [7u8; 16],
            transaction_id: txid(),
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
                    transaction_id: txid(),
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
            transaction_id: txid(),
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
                transaction_id: txid(),
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
            SetupMessage::GroupJoinRequest {
                conversation_id,
                transaction_id: txid(),
            },
            SetupMessage::GroupKeyPackageResponse {
                conversation_id,
                transaction_id: txid(),
                key_package: b"group key package".to_vec(),
            },
            SetupMessage::GroupWelcome {
                conversation_id,
                transaction_id: txid(),
                welcome: b"group welcome".to_vec(),
            },
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id: txid(),
                operation: GroupOperation::Add,
                target: Some(target),
                commit: b"group commit".to_vec(),
            },
            SetupMessage::GroupCommit {
                conversation_id,
                transaction_id: txid(),
                operation: GroupOperation::Update,
                target: None,
                commit: b"update commit".to_vec(),
            },
            SetupMessage::GroupCommitAck {
                conversation_id,
                transaction_id: txid(),
                operation: GroupOperation::Remove,
                accepted: true,
            },
            SetupMessage::GroupCommitAck {
                conversation_id,
                transaction_id: txid(),
                operation: GroupOperation::Update,
                accepted: false,
            },
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                transaction_id: txid(),
                accepted: true,
            },
            SetupMessage::GroupWelcomeAck {
                conversation_id,
                transaction_id: txid(),
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
            SetupMessage::from_parts(GROUP_COMMIT, conversation_id, txid(), unknown_operation)
                .is_err()
        );

        let mut bad_target_flag = vec![GroupOperation::Remove.code(), 2];
        bad_target_flag.extend_from_slice(b"commit");
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT, conversation_id, txid(), bad_target_flag)
                .is_err()
        );

        let mut truncated_target = vec![GroupOperation::Remove.code(), 1, 8, 0, 0, 0];
        truncated_target.extend_from_slice(&[7u8; 4]);
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT, conversation_id, txid(), truncated_target)
                .is_err()
        );

        let missing_commit = vec![GroupOperation::Update.code(), 0];
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT, conversation_id, txid(), missing_commit)
                .is_err()
        );

        assert!(
            SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, txid(), vec![1]).is_err()
        );
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, txid(), vec![1, 2])
                .is_err()
        );
        assert!(
            SetupMessage::from_parts(GROUP_COMMIT_ACK, conversation_id, txid(), vec![99, 1])
                .is_err()
        );
        assert!(
            SetupMessage::from_parts(GROUP_WELCOME_ACK, conversation_id, txid(), vec![1, 1])
                .is_err()
        );
        assert!(
            SetupMessage::from_parts(GROUP_JOIN_REQUEST, conversation_id, txid(), vec![0]).is_err()
        );
    }

    #[test]
    fn oversized_and_tampered_group_frames_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let oversized = SetupMessage::GroupCommit {
            conversation_id: [13u8; 16],
            transaction_id: txid(),
            operation: GroupOperation::Add,
            target: None,
            commit: vec![0u8; MAX_SETUP_PAYLOAD_BYTES + 1],
        };
        assert!(SetupEnvelope::new(&identity, oversized).is_err());

        let mut bytes = SetupEnvelope::new(
            &identity,
            SetupMessage::GroupWelcome {
                conversation_id: [13u8; 16],
                transaction_id: txid(),
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
                transaction_id: txid(),
                welcome: secret.to_vec(),
            },
        )
        .expect("signed welcome");
        let commit = SetupEnvelope::new(
            &identity,
            SetupMessage::GroupCommit {
                conversation_id: [14u8; 16],
                transaction_id: txid(),
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

    #[test]
    fn every_role_and_transaction_carries_a_distinct_signed_id() {
        let inviter = Identity::generate().expect("inviter identity");
        let responder = Identity::generate().expect("responder identity");
        let target = Identity::generate().expect("target identity").peer_id();
        let conversation_id = [21u8; 16];
        let ids: Vec<TransactionId> = (0..10).map(|n| [n + 1; TRANSACTION_ID_LEN]).collect();
        let cases = [
            (
                &inviter,
                SetupMessage::KeyPackageRequest {
                    conversation_id,
                    transaction_id: ids[0],
                },
            ),
            (
                &responder,
                SetupMessage::KeyPackageResponse {
                    conversation_id,
                    transaction_id: ids[1],
                    key_package: b"key package".to_vec(),
                },
            ),
            (
                &inviter,
                SetupMessage::Welcome {
                    conversation_id,
                    transaction_id: ids[2],
                    welcome: b"welcome".to_vec(),
                },
            ),
            (
                &responder,
                SetupMessage::WelcomeAck {
                    conversation_id,
                    transaction_id: ids[3],
                    accepted: true,
                },
            ),
            (
                &inviter,
                SetupMessage::GroupJoinRequest {
                    conversation_id,
                    transaction_id: ids[4],
                },
            ),
            (
                &responder,
                SetupMessage::GroupKeyPackageResponse {
                    conversation_id,
                    transaction_id: ids[5],
                    key_package: b"group key package".to_vec(),
                },
            ),
            (
                &inviter,
                SetupMessage::GroupWelcome {
                    conversation_id,
                    transaction_id: ids[6],
                    welcome: b"group welcome".to_vec(),
                },
            ),
            (
                &inviter,
                SetupMessage::GroupCommit {
                    conversation_id,
                    transaction_id: ids[7],
                    operation: GroupOperation::Add,
                    target: Some(target),
                    commit: b"commit".to_vec(),
                },
            ),
            (
                &responder,
                SetupMessage::GroupCommitAck {
                    conversation_id,
                    transaction_id: ids[8],
                    operation: GroupOperation::Add,
                    accepted: true,
                },
            ),
            (
                &responder,
                SetupMessage::GroupWelcomeAck {
                    conversation_id,
                    transaction_id: ids[9],
                    accepted: true,
                },
            ),
        ];

        let mut seen = std::collections::BTreeSet::new();
        for (signer, message) in cases {
            assert!(seen.insert(*message.transaction_id()));
            let envelope = SetupEnvelope::new(signer, message.clone()).expect("signed frame");
            let bytes = envelope.to_bytes().expect("encoded frame");
            let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded frame");
            assert_eq!(decoded.message.transaction_id(), message.transaction_id());
            decoded.verify(&signer.peer_id()).expect("valid signature");
        }
        assert_eq!(seen.len(), ids.len());
    }

    #[test]
    fn transaction_id_round_trips_and_is_covered_by_the_signature() {
        let identity = Identity::generate().expect("identity");
        let transaction_id = [0xa5u8; TRANSACTION_ID_LEN];
        let envelope = SetupEnvelope::new(
            &identity,
            SetupMessage::WelcomeAck {
                conversation_id: [22u8; 16],
                transaction_id,
                accepted: true,
            },
        )
        .expect("signed ack");
        let mut bytes = envelope.to_bytes().expect("encoded ack");

        // magic || version || transaction id: the ID is in the signed header.
        assert_eq!(&bytes[..4], &SETUP_MAGIC);
        assert_eq!(&bytes[4..6], &SETUP_VERSION.to_le_bytes());
        assert_eq!(&bytes[6..6 + TRANSACTION_ID_LEN], &transaction_id);

        let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded ack");
        assert_eq!(decoded.message.transaction_id(), &transaction_id);
        decoded.verify(&identity.peer_id()).expect("valid ack");

        bytes[6] ^= 1;
        let tampered = SetupEnvelope::from_bytes(&bytes).expect("decoded tampered ack");
        assert_ne!(tampered.message.transaction_id(), &transaction_id);
        assert!(matches!(
            tampered.verify(&identity.peer_id()),
            Err(ChatError::InvalidSetup("signature is invalid"))
        ));
    }

    #[test]
    fn version_one_and_unknown_version_frames_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let bytes = SetupEnvelope::new(
            &identity,
            SetupMessage::KeyPackageRequest {
                conversation_id: [23u8; 16],
                transaction_id: txid(),
            },
        )
        .expect("signed frame")
        .to_bytes()
        .expect("encoded frame");

        let mut v1 = bytes.clone();
        v1[4..6].copy_from_slice(&1u16.to_le_bytes());
        let v1_error = SetupEnvelope::from_bytes(&v1).expect_err("v1 is rejected");
        assert!(v1_error.to_string().contains("unsupported"));
        assert!(v1_error.to_string().contains("version 1"));

        let mut future = bytes;
        future[4..6].copy_from_slice(&(SETUP_VERSION + 1).to_le_bytes());
        assert!(SetupEnvelope::from_bytes(&future).is_err());
    }

    #[test]
    fn truncated_and_trailing_transaction_header_bytes_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let bytes = SetupEnvelope::new(
            &identity,
            SetupMessage::KeyPackageRequest {
                conversation_id: [24u8; 16],
                transaction_id: txid(),
            },
        )
        .expect("signed frame")
        .to_bytes()
        .expect("encoded frame");

        for len in 6..6 + TRANSACTION_ID_LEN {
            assert!(SetupEnvelope::from_bytes(&bytes[..len]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(SetupEnvelope::from_bytes(&trailing).is_err());
    }
}
