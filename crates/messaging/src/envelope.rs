//! Canonical, signed message envelopes.
//!
//! The payload is opaque to this crate. It must be ciphertext produced by the
//! `p2p-groups` MLS layer before the application sends it; this crate provides
//! the envelope, verification, replay boundary, and local state machine only. The
//! sender's protobuf public key is included because a PeerId is a multihash and
//! cannot independently verify an Ed25519 signature. It is bound to the signed
//! bytes and checked against the declared PeerId before verification.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use libp2p_identity::PeerId;
use p2p_identity::{
    Identity, IdentityError, IdentityRole, MAX_IDENTITY_PROOF_BYTES, certified_role_public_key,
    unix_time_seconds, verify_application_signature,
};

use crate::MessageError;

/// Wire version implemented by this build.
pub const ENVELOPE_VERSION: u16 = 2;
/// Fixed protocol magic. Unknown magic is rejected, never negotiated.
pub const PROTOCOL_MAGIC: &[u8; 4] = b"P2P1";
/// Maximum total size of an encoded envelope.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Maximum opaque payload size, leaving room for bounded metadata fields.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024 - 1024;

/// Version 3 removes transferable clear-message authorship and stable
/// identifiers from the outer wire. The outer layer carries only a local
/// routing tag, a random nonce, the MLS ciphertext, and a group-keyed MAC.
pub const ENVELOPE_V3_VERSION: u16 = 3;
pub const V3_MAGIC: &[u8; 4] = b"P2P3";
pub const V3_ROUTE_TAG_LEN: usize = 32;
pub const V3_NONCE_LEN: usize = 16;
pub const V3_MAC_LEN: usize = 32;

/// Version 4 replaces the stable per-epoch route tag with a fresh random tag
/// on every frame. The tag remains a local selector only: receivers identify a
/// candidate group by verifying the group-keyed MAC, not by matching a stable
/// clear value. Outside observers cannot link two frames by tag.
pub const ENVELOPE_V4_VERSION: u16 = 4;
pub const V4_MAGIC: &[u8; 4] = b"P2P4";
pub const V4_ROUTE_TAG_LEN: usize = 32;
pub const V4_NONCE_LEN: usize = 16;
pub const V4_MAC_LEN: usize = 32;
const V4_HEADER_LEN: usize = 4 + 2 + V4_ROUTE_TAG_LEN + V4_NONCE_LEN + 4;

/// Version 1 of the MLS-protected inner frame. It is never present on the wire
/// in plaintext; only MLS group members can decrypt it.
pub const V3_INNER_MAGIC: &[u8; 4] = b"P2I1";
pub const V3_INNER_VERSION: u8 = 1;

const MAX_PUBLIC_KEY_BYTES: usize = 256;
const MAX_PEER_ID_BYTES: usize = 128;
const SIGNATURE_LEN: usize = 64;

const KIND_TEXT: u8 = 1;
const KIND_REPLY: u8 = 2;
const KIND_RECEIPT: u8 = 3;
const KIND_PIN: u8 = 4;
const KIND_UNPIN: u8 = 5;
const KIND_POLICY: u8 = 6;
const KIND_FILE: u8 = 7;
const KIND_CHANNEL: u8 = 8;

/// Application message category. Codes are fixed and never renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Text,
    Reply,
    Receipt,
    Pin,
    Unpin,
    Policy,
    File,
    Channel,
}

impl MessageKind {
    pub fn code(self) -> u8 {
        match self {
            Self::Text => KIND_TEXT,
            Self::Reply => KIND_REPLY,
            Self::Receipt => KIND_RECEIPT,
            Self::Pin => KIND_PIN,
            Self::Unpin => KIND_UNPIN,
            Self::Policy => KIND_POLICY,
            Self::File => KIND_FILE,
            Self::Channel => KIND_CHANNEL,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            KIND_TEXT => Some(Self::Text),
            KIND_REPLY => Some(Self::Reply),
            KIND_RECEIPT => Some(Self::Receipt),
            KIND_PIN => Some(Self::Pin),
            KIND_UNPIN => Some(Self::Unpin),
            KIND_POLICY => Some(Self::Policy),
            KIND_FILE => Some(Self::File),
            KIND_CHANNEL => Some(Self::Channel),
            _ => None,
        }
    }
}

/// Non-secret inputs to a new envelope. Callers choose IDs and timestamps so
/// tests are deterministic; the local conversation supplies the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeParams {
    pub conversation_id: [u8; 16],
    pub epoch: u64,
    pub message_id: [u8; 16],
    pub sender_sequence: u64,
    pub created_at: i64,
    pub kind: MessageKind,
}

/// A signed wire envelope. `payload` is opaque ciphertext from a higher layer.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub protocol: [u8; 4],
    pub conversation_id: [u8; 16],
    pub epoch: u64,
    pub message_id: [u8; 16],
    pub sender_public_key: Vec<u8>,
    pub sender: PeerId,
    pub sender_sequence: u64,
    pub created_at: i64,
    pub kind: MessageKind,
    pub identity_proof: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
}

impl Envelope {
    /// Create and sign an envelope with the local identity.
    pub fn new(
        identity: &Identity,
        params: EnvelopeParams,
        payload: Vec<u8>,
    ) -> Result<Self, MessageError> {
        if params.sender_sequence == 0 {
            return Err(MessageError::InvalidStateTransition);
        }
        let mut envelope = Self {
            version: ENVELOPE_VERSION,
            protocol: *PROTOCOL_MAGIC,
            conversation_id: params.conversation_id,
            epoch: params.epoch,
            message_id: params.message_id,
            sender_public_key: identity
                .role_public_bytes(IdentityRole::Application)?
                .to_vec(),
            sender: identity.peer_id(),
            sender_sequence: params.sender_sequence,
            created_at: params.created_at,
            kind: params.kind,
            identity_proof: identity.proof().to_bytes(),
            payload,
            signature: [0; SIGNATURE_LEN],
        };
        let signing_bytes = envelope.signing_bytes()?;
        let signature = identity.sign_with_role(IdentityRole::Application, &signing_bytes)?;
        envelope.signature = signature
            .as_slice()
            .try_into()
            .map_err(|_| MessageError::BadSignature)?;
        Ok(envelope)
    }

    /// Parse a canonical envelope. This does not verify the signature or replay
    /// state; callers must do both before trusting any field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let protocol: [u8; 4] = reader.fixed().map_err(|_| MessageError::BadProtocol)?;
        if &protocol != PROTOCOL_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        let version = reader.u16()?;
        if version != ENVELOPE_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let conversation_id = reader.fixed()?;
        let epoch = reader.u64()?;
        let message_id = reader.fixed()?;
        let sender_public_key = reader.var(MAX_PUBLIC_KEY_BYTES)?;
        let sender_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let sender = PeerId::from_bytes(&sender_bytes).map_err(|_| MessageError::BadPeerId)?;
        let sender_sequence = reader.u64()?;
        let created_at = reader.i64()?;
        let kind_code = reader.u8()?;
        let kind = MessageKind::from_code(kind_code).ok_or(MessageError::BadKind(kind_code))?;
        let identity_proof = reader.var(MAX_IDENTITY_PROOF_BYTES)?;
        let payload = reader.var(MAX_PAYLOAD_BYTES)?;
        let signature = reader.fixed()?;
        reader.finish()?;

        let envelope = Self {
            version,
            protocol,
            conversation_id,
            epoch,
            message_id,
            sender_public_key,
            sender,
            sender_sequence,
            created_at,
            kind,
            identity_proof,
            payload,
            signature,
        };
        envelope.check_sizes()?;
        Ok(envelope)
    }

    /// Encode the full signed envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Bytes covered by the Ed25519 signature. The signature itself is excluded.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, MessageError> {
        self.check_sizes()?;
        let mut bytes = Vec::with_capacity(self.payload.len() + 128);
        bytes.extend_from_slice(&self.protocol);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.conversation_id);
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.message_id);
        put_bytes(&mut bytes, &self.sender_public_key)?;
        put_bytes(&mut bytes, &self.sender.to_bytes())?;
        bytes.extend_from_slice(&self.sender_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.push(self.kind.code());
        put_bytes(&mut bytes, &self.identity_proof)?;
        put_bytes(&mut bytes, &self.payload)?;
        Ok(bytes)
    }

    /// Extract a certified role key from the proof carried by this envelope.
    /// This is used by the MLS layer to bind the inner signature key to the
    /// same Noise-authenticated peer as the outer application signature.
    pub fn sender_role_public_key(&self, role: IdentityRole) -> Result<[u8; 32], MessageError> {
        certified_role_public_key(
            &self.identity_proof,
            role,
            &self.sender,
            unix_time_seconds(),
        )
        .map_err(map_identity_error)
    }

    /// Verify protocol version and signature, binding the embedded public key
    /// to the declared PeerId. Replay and conversation checks are separate.
    pub fn verify(&self) -> Result<(), MessageError> {
        if self.version != ENVELOPE_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if &self.protocol != PROTOCOL_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        self.check_sizes()?;
        let signing_bytes = self.signing_bytes()?;
        let certified_key = verify_application_signature(
            &self.identity_proof,
            IdentityRole::Application,
            &self.sender,
            &signing_bytes,
            &self.signature,
            unix_time_seconds(),
        )
        .map_err(map_identity_error)?;
        if self.sender_public_key != certified_key {
            return Err(MessageError::BadPeerId);
        }
        Ok(())
    }

    fn check_sizes(&self) -> Result<(), MessageError> {
        if &self.protocol != PROTOCOL_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        if self.version != ENVELOPE_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::TooLarge {
                len: self.payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }
        if self.sender_public_key.len() != 32 {
            return Err(MessageError::BadPeerId);
        }
        if self.identity_proof.is_empty() || self.identity_proof.len() > MAX_IDENTITY_PROOF_BYTES {
            return Err(MessageError::Identity(IdentityError::InvalidIdentityProof(
                "identity proof length is invalid".to_owned(),
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &self.version)
            .field("conversation_id", &hex(&self.conversation_id))
            .field("message_id", &hex(&self.message_id))
            .field("epoch", &self.epoch)
            .field("sender", &self.sender.to_string())
            .field("sender_sequence", &self.sender_sequence)
            .field("kind", &self.kind)
            .field("identity_proof_len", &self.identity_proof.len())
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// A version-3 wire envelope. No stable sender key, identity proof, message
/// ID, conversation ID, sequence, timestamp, or kind appears in the clear.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeV3 {
    pub version: u16,
    pub protocol: [u8; 4],
    /// Per-epoch tag used only for local route selection. It is derived from a
    /// group ID and epoch, is not secret, and does not provide unlinkability.
    pub route_tag: [u8; V3_ROUTE_TAG_LEN],
    /// Fresh random bytes that make repeated outer frames differ.
    pub nonce: [u8; V3_NONCE_LEN],
    /// MLS ciphertext carrying [`V3InnerFrame`].
    pub body: Vec<u8>,
    /// HMAC-SHA256 under an MLS exporter-derived group key.
    pub mac: [u8; V3_MAC_LEN],
}

impl EnvelopeV3 {
    /// Build and authenticate a v3 envelope. `mac_key` comes from the current
    /// MLS epoch; this crate never invents or exports key material itself.
    pub fn new(
        route_tag: [u8; V3_ROUTE_TAG_LEN],
        body: Vec<u8>,
        mac_key: &[u8; V3_MAC_LEN],
    ) -> Result<Self, MessageError> {
        if body.is_empty() || body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut nonce = [0u8; V3_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| MessageError::Randomness)?;
        let mut envelope = Self {
            version: ENVELOPE_V3_VERSION,
            protocol: *V3_MAGIC,
            route_tag,
            nonce,
            body,
            mac: [0; V3_MAC_LEN],
        };
        let authenticated = envelope.authenticated_bytes()?;
        envelope.mac = derive_v3_mac(mac_key, &authenticated)?;
        Ok(envelope)
    }

    /// Parse a canonical v3 envelope. This does **not** verify the MAC or the
    /// MLS ciphertext; callers must do both before trusting the group route.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let protocol: [u8; 4] = reader.fixed().map_err(|_| MessageError::BadProtocol)?;
        if &protocol != V3_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        let version = reader.u16()?;
        if version != ENVELOPE_V3_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let route_tag = reader.fixed()?;
        let nonce = reader.fixed()?;
        let body_len = reader.u32()? as usize;
        if body_len == 0 || body_len > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let body = reader.take(body_len)?.to_vec();
        let mac = reader.fixed()?;
        reader.finish()?;
        Ok(Self {
            version,
            protocol,
            route_tag,
            nonce,
            body,
            mac,
        })
    }

    /// Versioned outer header used as AEAD associated data for the wrapped MLS
    /// ciphertext. It contains only the route tag, nonce, and body length.
    pub fn header_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if &self.protocol != V3_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        if self.version != ENVELOPE_V3_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.body.is_empty() || self.body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut bytes = Vec::with_capacity(V3_HEADER_LEN);
        bytes.extend_from_slice(&self.protocol);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.route_tag);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        Ok(bytes)
    }

    /// All bytes covered by the MAC. The tag itself is deliberately excluded.
    pub fn authenticated_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if &self.protocol != V3_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        if self.version != ENVELOPE_V3_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.body.is_empty() || self.body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut bytes = Vec::with_capacity(self.body.len() + V3_HEADER_LEN);
        bytes.extend_from_slice(&self.protocol);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.route_tag);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }

    /// Encode the full authenticated envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut bytes = self.authenticated_bytes()?;
        bytes.extend_from_slice(&self.mac);
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Constant-time verification of the group-keyed outer MAC.
    pub fn verify_mac(&self, mac_key: &[u8; V3_MAC_LEN]) -> Result<(), MessageError> {
        let authenticated = self.authenticated_bytes()?;
        let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| MessageError::BadMac)?;
        mac.update(&authenticated);
        mac.verify_slice(&self.mac)
            .map_err(|_| MessageError::BadMac)
    }
}

impl fmt::Debug for EnvelopeV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeV3")
            .field("version", &self.version)
            .field("route_tag", &hex(&self.route_tag))
            .field("body_len", &self.body.len())
            .field("body", &"<mls ciphertext>")
            .finish_non_exhaustive()
    }
}

/// A version-4 wire envelope. The per-frame random route tag is unlinkable to
/// an outside observer; it is authenticated but carries no stable group or
/// epoch identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeV4 {
    pub version: u16,
    pub protocol: [u8; 4],
    /// Fresh random selector for this frame only. Not a secret or a proof.
    pub route_tag: [u8; V4_ROUTE_TAG_LEN],
    /// Fresh random bytes that make repeated outer frames differ.
    pub nonce: [u8; V4_NONCE_LEN],
    /// MLS ciphertext carrying [`V3InnerFrame`].
    pub body: Vec<u8>,
    /// HMAC-SHA256 under an MLS exporter-derived group key.
    pub mac: [u8; V4_MAC_LEN],
}

impl EnvelopeV4 {
    /// Build an authenticated v4 envelope with a fresh random route tag and
    /// nonce. Callers cannot supply a stable tag, which is what makes the
    /// outer selector unlinkable between frames.
    pub fn new(body: Vec<u8>, mac_key: &[u8; V4_MAC_LEN]) -> Result<Self, MessageError> {
        let mut envelope = Self::with_random_header()?;
        envelope.set_body_and_sign(body, mac_key)?;
        Ok(envelope)
    }

    /// Allocate a fresh random outer header before the protected body exists.
    /// This lets a caller bind the random route tag into AEAD associated data;
    /// no caller-supplied tag is accepted anywhere in the v4 API.
    pub fn with_random_header() -> Result<Self, MessageError> {
        let mut route_tag = [0u8; V4_ROUTE_TAG_LEN];
        let mut nonce = [0u8; V4_NONCE_LEN];
        getrandom::fill(&mut route_tag).map_err(|_| MessageError::Randomness)?;
        getrandom::fill(&mut nonce).map_err(|_| MessageError::Randomness)?;
        Ok(Self {
            version: ENVELOPE_V4_VERSION,
            protocol: *V4_MAGIC,
            route_tag,
            nonce,
            body: Vec::new(),
            mac: [0; V4_MAC_LEN],
        })
    }

    /// Install the already protected body and recompute the group MAC over the
    /// whole frame, including the random route tag.
    pub fn set_body_and_sign(
        &mut self,
        body: Vec<u8>,
        mac_key: &[u8; V4_MAC_LEN],
    ) -> Result<(), MessageError> {
        if body.is_empty() || body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        self.body = body;
        let authenticated = self.authenticated_bytes()?;
        self.mac = derive_v3_mac(mac_key, &authenticated)?;
        Ok(())
    }

    /// Parse a canonical v4 envelope. This does **not** verify the MAC or the
    /// MLS ciphertext; callers must do both before trusting the group route.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let protocol: [u8; 4] = reader.fixed().map_err(|_| MessageError::BadProtocol)?;
        if &protocol != V4_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        let version = reader.u16()?;
        if version != ENVELOPE_V4_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let route_tag = reader.fixed()?;
        let nonce = reader.fixed()?;
        let body_len = reader.u32()? as usize;
        if body_len == 0 || body_len > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let body = reader.take(body_len)?.to_vec();
        let mac = reader.fixed()?;
        reader.finish()?;
        Ok(Self {
            version,
            protocol,
            route_tag,
            nonce,
            body,
            mac,
        })
    }

    /// Versioned outer header used as AEAD associated data for the wrapped MLS
    /// ciphertext. It contains only the random route tag, nonce, and body
    /// length.
    pub fn header_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if &self.protocol != V4_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        if self.version != ENVELOPE_V4_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.body.is_empty() || self.body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut bytes = Vec::with_capacity(V4_HEADER_LEN);
        bytes.extend_from_slice(&self.protocol);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.route_tag);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        Ok(bytes)
    }

    /// All bytes covered by the MAC: versioned header, random tag, nonce,
    /// body length, and body. The tag cannot be swapped without invalidating
    /// the MAC, but it remains unlinkable because it is random per frame.
    pub fn authenticated_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if &self.protocol != V4_MAGIC {
            return Err(MessageError::BadProtocol);
        }
        if self.version != ENVELOPE_V4_VERSION {
            return Err(MessageError::UnsupportedVersion(self.version));
        }
        if self.body.is_empty() || self.body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut bytes = Vec::with_capacity(self.body.len() + V4_HEADER_LEN);
        bytes.extend_from_slice(&self.protocol);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.route_tag);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }

    /// Encode the full authenticated envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let mut bytes = self.authenticated_bytes()?;
        bytes.extend_from_slice(&self.mac);
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(MessageError::TooLarge {
                len: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Constant-time verification of the group-keyed outer MAC.
    pub fn verify_mac(&self, mac_key: &[u8; V4_MAC_LEN]) -> Result<(), MessageError> {
        let authenticated = self.authenticated_bytes()?;
        let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| MessageError::BadMac)?;
        mac.update(&authenticated);
        mac.verify_slice(&self.mac)
            .map_err(|_| MessageError::BadMac)
    }
}

impl fmt::Debug for EnvelopeV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeV4")
            .field("version", &self.version)
            .field("route_tag", &"<random selector>")
            .field("body_len", &self.body.len())
            .field("body", &"<mls ciphertext>")
            .finish_non_exhaustive()
    }
}

/// Metadata recovered only after successful MLS decryption. The body is the
/// application frame; it is zeroized by the caller's decrypted buffer.
#[derive(Clone, PartialEq, Eq)]
pub struct V3InnerFrame {
    pub conversation_id: [u8; 16],
    pub message_id: [u8; 16],
    pub sender: PeerId,
    pub sender_sequence: u64,
    pub created_at: i64,
    pub kind: MessageKind,
    pub body: Vec<u8>,
}

impl V3InnerFrame {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if self.body.is_empty() || self.body.len() > MAX_PAYLOAD_BYTES {
            return Err(MessageError::BadV3Inner);
        }
        let mut bytes = Vec::with_capacity(self.body.len() + 96);
        bytes.extend_from_slice(V3_INNER_MAGIC);
        bytes.push(V3_INNER_VERSION);
        bytes.extend_from_slice(&self.conversation_id);
        bytes.extend_from_slice(&self.message_id);
        put_bytes(&mut bytes, &self.sender.to_bytes())?;
        bytes.extend_from_slice(&self.sender_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.push(self.kind.code());
        put_bytes(&mut bytes, &self.body)?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut reader = Reader::new(bytes);
        let magic: [u8; 4] = reader.fixed().map_err(|_| MessageError::BadV3Inner)?;
        if &magic != V3_INNER_MAGIC {
            return Err(MessageError::BadV3Inner);
        }
        let version = reader.u8()?;
        if version != V3_INNER_VERSION {
            return Err(MessageError::BadV3Inner);
        }
        let conversation_id = reader.fixed()?;
        let message_id = reader.fixed()?;
        let sender_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let sender = PeerId::from_bytes(&sender_bytes).map_err(|_| MessageError::BadPeerId)?;
        let sender_sequence = reader.u64()?;
        let created_at = reader.i64()?;
        let kind_code = reader.u8()?;
        let kind = MessageKind::from_code(kind_code).ok_or(MessageError::BadKind(kind_code))?;
        let body = reader.var(MAX_PAYLOAD_BYTES)?;
        if body.is_empty() {
            return Err(MessageError::BadV3Inner);
        }
        reader.finish()?;
        Ok(Self {
            conversation_id,
            message_id,
            sender,
            sender_sequence,
            created_at,
            kind,
            body,
        })
    }
}

impl fmt::Debug for V3InnerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V3InnerFrame")
            .field("conversation_id", &hex(&self.conversation_id))
            .field("message_id", &hex(&self.message_id))
            .field("sender", &self.sender.to_string())
            .field("sender_sequence", &self.sender_sequence)
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish_non_exhaustive()
    }
}

const V3_HEADER_LEN: usize = 4 + 2 + V3_ROUTE_TAG_LEN + V3_NONCE_LEN + 4;

type HmacSha256 = Hmac<sha2::Sha256>;

fn derive_v3_mac(
    key: &[u8; V3_MAC_LEN],
    authenticated: &[u8],
) -> Result<[u8; V3_MAC_LEN], MessageError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| MessageError::BadMac)?;
    mac.update(authenticated);
    let bytes = mac.finalize().into_bytes();
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| MessageError::BadMac)
}

/// Generate a random 16-byte identifier.
pub fn random_id() -> Result<[u8; 16], MessageError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| MessageError::Randomness)?;
    Ok(id)
}

/// Sender-supplied timestamp hint. Display only; never used for ordering.
pub fn now_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

fn map_identity_error(error: IdentityError) -> MessageError {
    match error {
        IdentityError::InvalidSignature => MessageError::BadSignature,
        IdentityError::PeerIdMismatch => MessageError::BadPeerId,
        IdentityError::NotEd25519 => MessageError::NotEd25519,
        other => MessageError::Identity(other),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MessageError> {
    let len = u32::try_from(bytes.len()).map_err(|_| MessageError::Truncated)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
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

    fn take(&mut self, len: usize) -> Result<&'a [u8], MessageError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(MessageError::Truncated)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(MessageError::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, MessageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MessageError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| MessageError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, MessageError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| MessageError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, MessageError> {
        Ok(i64::from_le_bytes(self.u64()?.to_le_bytes()))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], MessageError> {
        self.take(N)?
            .try_into()
            .map_err(|_| MessageError::Truncated)
    }

    fn var(&mut self, max: usize) -> Result<Vec<u8>, MessageError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(MessageError::TooLarge { len, max });
        }
        Ok(self.take(len)?.to_vec())
    }

    fn u32(&mut self) -> Result<u32, MessageError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| MessageError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn finish(self) -> Result<(), MessageError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MessageError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_identity::{CERTIFICATE_BYTES, IDENTITY_PROOF_HEADER_BYTES};

    fn params() -> EnvelopeParams {
        EnvelopeParams {
            conversation_id: [7u8; 16],
            epoch: 0,
            message_id: [9u8; 16],
            sender_sequence: 1,
            created_at: 1_700_000_000,
            kind: MessageKind::Text,
        }
    }

    #[test]
    fn envelope_round_trip_preserves_fields_and_verifies() {
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let bytes = envelope.to_bytes().expect("encoded envelope");
        let decoded = Envelope::from_bytes(&bytes).expect("decoded envelope");
        assert_eq!(decoded, envelope);
        decoded.verify().expect("valid signature");
    }

    #[test]
    fn signed_envelope_exposes_transferable_authorship_and_clear_metadata() {
        let identity = Identity::generate().expect("identity");
        let expected = params();
        let envelope = Envelope::new(&identity, expected, b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let bytes = envelope.to_bytes().expect("encoded envelope");
        let decoded = Envelope::from_bytes(&bytes).expect("decoded envelope");

        // Any party holding only the wire bytes can verify the signature. This
        // is positive evidence of authorship; no deniability is claimed.
        decoded.verify().expect("third-party verification");

        // Conversation ID, epoch, time, sender, kind, and sequence are parsed
        // before any decryption, so they are not confidential on the wire.
        assert_eq!(decoded.conversation_id, expected.conversation_id);
        assert_eq!(decoded.epoch, expected.epoch);
        assert_eq!(decoded.sender_sequence, expected.sender_sequence);
        assert_eq!(decoded.created_at, expected.created_at);
        assert_eq!(decoded.kind, expected.kind);
        assert_eq!(decoded.sender, identity.peer_id());
        assert!(
            bytes
                .windows(expected.conversation_id.len())
                .any(|window| window == expected.conversation_id),
            "conversation ID is present in the clear"
        );
    }

    #[test]
    fn tampering_with_payload_or_key_is_rejected() {
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let mut changed = envelope.clone();
        changed.payload.push(0);
        assert!(changed.verify().is_err());

        let other = Identity::generate().expect("other identity");
        let mut mismatched = envelope;
        mismatched.sender_public_key = other
            .role_public_bytes(IdentityRole::Application)
            .expect("application role key")
            .to_vec();
        assert!(mismatched.verify().is_err());
    }

    fn tampered_proof(identity: &Identity) -> Vec<u8> {
        let mut bytes = identity.proof().to_bytes();
        // The application certificate is fourth in canonical role order. This
        // byte is inside its signed public key, so parsing still succeeds but
        // certificate and frame verification must fail.
        let index = IDENTITY_PROOF_HEADER_BYTES + CERTIFICATE_BYTES * 4 + 34;
        bytes[index] ^= 0x01;
        bytes
    }

    #[test]
    fn wrong_role_and_transport_signatures_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let mut envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let signed_bytes = envelope.signing_bytes().expect("signed bytes");

        let file_signature = identity
            .sign_with_role(IdentityRole::File, &signed_bytes)
            .expect("file role signature");
        envelope.signature = file_signature.as_slice().try_into().expect("signature");
        assert!(matches!(envelope.verify(), Err(MessageError::BadSignature)));

        let transport_signature = identity.sign(&signed_bytes).expect("transport signature");
        envelope.signature = transport_signature
            .as_slice()
            .try_into()
            .expect("signature");
        assert!(matches!(envelope.verify(), Err(MessageError::BadSignature)));
    }

    #[test]
    fn substituted_and_tampered_proofs_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");

        let mut substituted = envelope.clone();
        substituted.identity_proof = other.proof().to_bytes();
        assert!(matches!(substituted.verify(), Err(MessageError::BadPeerId)));

        let mut tampered = envelope.clone();
        tampered.identity_proof = tampered_proof(&identity);
        assert!(tampered.verify().is_err());
        assert!(
            tampered
                .sender_role_public_key(IdentityRole::Application)
                .is_err()
        );

        let certified = envelope
            .sender_role_public_key(IdentityRole::Application)
            .expect("certified application key");
        assert_eq!(
            certified,
            identity
                .role_public_bytes(IdentityRole::Application)
                .expect("local application key")
        );
        assert_ne!(
            certified,
            identity.ed25519_public_bytes().expect("transport key")
        );
    }

    #[test]
    fn malformed_encodings_are_rejected_without_panics() {
        assert!(matches!(
            Envelope::from_bytes(&[]),
            Err(MessageError::BadProtocol)
        ));
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, params(), vec![]).expect("envelope");
        let mut bytes = envelope.to_bytes().expect("bytes");
        bytes.push(0);
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(MessageError::TrailingBytes)
        ));
        bytes.truncate(bytes.len() - 1);
        let next_version = ENVELOPE_VERSION + 1;
        bytes[4..6].copy_from_slice(&next_version.to_le_bytes());
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(MessageError::UnsupportedVersion(version)) if version == next_version
        ));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let identity = Identity::generate().expect("identity");
        let result = Envelope::new(&identity, params(), vec![0u8; MAX_PAYLOAD_BYTES + 1]);
        assert!(matches!(result, Err(MessageError::TooLarge { .. })));
    }

    #[test]
    fn debug_output_omits_payload_and_signature() {
        let identity = Identity::generate().expect("identity");
        let envelope =
            Envelope::new(&identity, params(), b"SECRET_PAYLOAD".to_vec()).expect("envelope");
        let debug = format!("{envelope:?}");
        assert!(!debug.contains("SECRET_PAYLOAD"));
        assert!(debug.contains("payload_len"));
    }

    #[test]
    fn channel_kind_has_a_fixed_wire_code_and_round_trips() {
        assert_eq!(MessageKind::Channel.code(), 8);
        assert_eq!(MessageKind::from_code(8), Some(MessageKind::Channel));

        let mut channel_params = params();
        channel_params.kind = MessageKind::Channel;
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, channel_params, b"opaque CHN1 body".to_vec())
            .expect("signed channel envelope");
        let bytes = envelope.to_bytes().expect("encoded envelope");
        let decoded = Envelope::from_bytes(&bytes).expect("decoded envelope");
        assert_eq!(decoded.kind, MessageKind::Channel);
        assert_eq!(decoded, envelope);
        decoded.verify().expect("valid channel signature");
    }

    #[test]
    fn deterministic_bit_flips_never_produce_a_verified_envelope() {
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let bytes = envelope.to_bytes().expect("encoded envelope");

        for index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x01;
            if let Ok(decoded) = Envelope::from_bytes(&mutated) {
                assert!(
                    decoded.verify().is_err(),
                    "bit {index} produced a verified envelope"
                );
            }
        }
    }

    #[test]
    fn every_truncated_encoding_is_rejected_without_panics() {
        let identity = Identity::generate().expect("identity");
        let envelope = Envelope::new(&identity, params(), b"opaque ciphertext".to_vec())
            .expect("signed envelope");
        let bytes = envelope.to_bytes().expect("encoded envelope");

        for len in 0..bytes.len() {
            assert!(
                Envelope::from_bytes(&bytes[..len]).is_err(),
                "prefix of length {len} was accepted"
            );
        }
    }

    fn v3_inner() -> V3InnerFrame {
        V3InnerFrame {
            conversation_id: [0x11; 16],
            message_id: [0x22; 16],
            sender: Identity::generate().expect("sender").peer_id(),
            sender_sequence: 7,
            created_at: 1_700_000_001,
            kind: MessageKind::Text,
            body: b"MLS-protected application frame".to_vec(),
        }
    }

    #[test]
    fn v3_wire_has_no_stable_sender_or_message_metadata() {
        let identity = Identity::generate().expect("identity");
        let route = [0x77; V3_ROUTE_TAG_LEN];
        let key = [0x33; V3_MAC_LEN];
        let envelope = EnvelopeV3::new(route, vec![0xaa; 128], &key).expect("v3 envelope");
        let bytes = envelope.to_bytes().expect("encoded v3");

        assert_eq!(&bytes[..4], V3_MAGIC);
        assert_eq!(&bytes[4..6], &ENVELOPE_V3_VERSION.to_le_bytes());
        assert!(
            !bytes
                .windows(16)
                .any(|w| w == identity.peer_id().to_bytes())
        );
        assert!(!bytes.windows(16).any(|w| w == [0x22; 16]));
        assert!(!bytes.windows(16).any(|w| w == [0x11; 16]));
        assert!(format!("{envelope:?}").contains("<mls ciphertext>"));
        assert!(!format!("{envelope:?}").contains("aa"));

        let decoded = EnvelopeV3::from_bytes(&bytes).expect("decoded v3");
        decoded.verify_mac(&key).expect("valid group MAC");
        assert_eq!(decoded.route_tag, route);
        assert_eq!(decoded.body, vec![0xaa; 128]);
    }

    #[test]
    fn v3_mac_rejects_body_nonce_route_tag_and_version_tampering() {
        let key = [0x44; V3_MAC_LEN];
        let envelope = EnvelopeV3::new([0x55; 32], vec![0x66; 96], &key).expect("v3 envelope");
        let bytes = envelope.to_bytes().expect("encoded v3");

        assert!(matches!(
            EnvelopeV3::from_bytes(&[0u8; 8]),
            Err(MessageError::BadProtocol)
        ));

        for index in [4, 6, 22, 38, 42, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            if let Ok(decoded) = EnvelopeV3::from_bytes(&changed) {
                assert!(
                    decoded.verify_mac(&key).is_err(),
                    "byte {index} produced an authenticated frame"
                );
            }
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            EnvelopeV3::from_bytes(&trailing),
            Err(MessageError::TrailingBytes)
        ));

        let mut future = bytes.clone();
        future[4..6].copy_from_slice(&(ENVELOPE_V3_VERSION + 1).to_le_bytes());
        assert!(matches!(
            EnvelopeV3::from_bytes(&future),
            Err(MessageError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn v3_inner_frame_round_trips_and_rejects_tampering() {
        let frame = v3_inner();
        let bytes = frame.to_bytes().expect("encoded inner frame");
        assert_eq!(V3InnerFrame::from_bytes(&bytes).expect("decoded"), frame);
        assert!(format!("{frame:?}").contains("<redacted>"));
        assert!(!format!("{frame:?}").contains("MLS-protected"));

        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            assert!(
                V3InnerFrame::from_bytes(&changed).is_err()
                    || V3InnerFrame::from_bytes(&changed).expect("decoded") != frame,
                "bit {index} left the inner frame unchanged"
            );
        }
        let mut empty_body = frame.clone();
        empty_body.body.clear();
        assert!(empty_body.to_bytes().is_err());
    }

    #[test]
    fn every_v3_prefix_is_rejected_without_panics() {
        let envelope = EnvelopeV3::new([0x88; 32], vec![0x99; 64], &[0x01; 32]).expect("v3");
        let bytes = envelope.to_bytes().expect("encoded v3");
        for len in 0..bytes.len() {
            assert!(
                EnvelopeV3::from_bytes(&bytes[..len]).is_err(),
                "v3 prefix of length {len} was accepted"
            );
        }
    }

    #[test]
    fn v4_route_tag_is_random_and_outer_frame_hides_stable_metadata() {
        let identity = Identity::generate().expect("identity");
        let key = [0x55; V4_MAC_LEN];
        let first = EnvelopeV4::new(vec![0xaa; 128], &key).expect("first v4");
        let second = EnvelopeV4::new(vec![0xaa; 128], &key).expect("second v4");
        assert_ne!(first.route_tag, second.route_tag);
        assert_ne!(first.nonce, second.nonce);

        let bytes = first.to_bytes().expect("encoded v4");
        assert_eq!(&bytes[..4], V4_MAGIC);
        assert_eq!(&bytes[4..6], &ENVELOPE_V4_VERSION.to_le_bytes());
        assert!(
            !bytes
                .windows(16)
                .any(|w| w == identity.peer_id().to_bytes())
        );
        assert!(!bytes.windows(16).any(|w| w == [0x11; 16]));
        assert!(!bytes.windows(16).any(|w| w == [0x22; 16]));
        assert!(format!("{first:?}").contains("<random selector>"));
        assert!(!format!("{first:?}").contains("aa"));

        let decoded = EnvelopeV4::from_bytes(&bytes).expect("decoded v4");
        decoded.verify_mac(&key).expect("valid group MAC");
        assert_eq!(decoded.route_tag, first.route_tag);
        assert_eq!(decoded.body, vec![0xaa; 128]);

        // The two-step API exists so the random tag can be bound into AEAD AAD
        // before the protected body is installed; it still rejects a caller-
        // supplied tag because no setter is exposed.
        let mut prepared = EnvelopeV4::with_random_header().expect("fresh header");
        prepared
            .set_body_and_sign(vec![0xaa; 128], &key)
            .expect("signed body");
        prepared.verify_mac(&key).expect("valid prepared MAC");
        assert_ne!(prepared.route_tag, first.route_tag);
    }

    #[test]
    fn v4_mac_rejects_tampering_and_legacy_wire_is_rejected() {
        let key = [0x66; V4_MAC_LEN];
        let envelope = EnvelopeV4::new(vec![0x77; 96], &key).expect("v4 envelope");
        let bytes = envelope.to_bytes().expect("encoded v4");

        for index in [4, 6, 22, 38, 42, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 0x01;
            if let Ok(decoded) = EnvelopeV4::from_bytes(&changed) {
                assert!(
                    decoded.verify_mac(&key).is_err(),
                    "byte {index} produced an authenticated frame"
                );
            }
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            EnvelopeV4::from_bytes(&trailing),
            Err(MessageError::TrailingBytes)
        ));

        let legacy = EnvelopeV3::new([0x11; 32], vec![0x22; 64], &[0x33; 32]).expect("v3");
        assert!(EnvelopeV4::from_bytes(&legacy.to_bytes().expect("v3 bytes")).is_err());

        for len in 0..bytes.len() {
            assert!(
                EnvelopeV4::from_bytes(&bytes[..len]).is_err(),
                "v4 prefix of length {len} was accepted"
            );
        }
    }
}
