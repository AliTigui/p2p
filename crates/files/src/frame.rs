//! Bounded, signed application frames for the file-transfer protocol.
//!
//! Frames travel inside `/p2p-messenger/file/1` over a libp2p-authenticated
//! connection. Version 3 carries a self-contained ML-DSA-65 proof and an
//! ML-DSA-65 `File` signature binding transfer ID, sender PeerId, public key,
//! message code, and payload. Version 2 is a decodable legacy Ed25519 codec for
//! adversarial tests; the chat controller rejects it. Payload bytes are opaque
//! here; chunk ciphertext is authenticated separately with bound AAD.

use std::fmt;

use libp2p_identity::PeerId;
use p2p_crypto::{NONCE_LEN, TAG_LEN};
use p2p_identity::{
    Identity, IdentityRole, MAX_IDENTITY_PROOF_BYTES, MAX_PQ_IDENTITY_PROOF_BYTES,
    PQ_PUBLIC_KEY_BYTES, PQ_SIGNATURE_BYTES, unix_time_seconds, verify_application_signature,
    verify_pq_application_signature,
};
use zeroize::Zeroizing;

use crate::FileError;

/// File protocol negotiated with libp2p multistream-select. It is separate
/// from message and MLS setup protocols and uses the same authenticated Noise
/// connection.
pub const FILE_PROTOCOL: &str = "/p2p-messenger/file/1";

/// Fixed frame magic. Unknown magic is rejected, never negotiated.
pub const FILE_MAGIC: [u8; 4] = *b"FILE";
/// Post-quantum file frame version implemented by this build.
pub const FILE_VERSION: u16 = 3;
/// Last classical-signature file codec. It decodes for compatibility tests
/// only and is rejected by every production receive path.
pub const LEGACY_FILE_VERSION: u16 = 2;

/// Maximum bytes accepted in one file request or response frame. This matches
/// the transport codec cap and prevents unbounded length-prefix allocation.
pub const MAX_FILE_FRAME_BYTES: usize = 1024 * 1024;
/// Room reserved for frame metadata, leaving a bounded payload.
pub const MAX_FILE_PAYLOAD_BYTES: usize = MAX_FILE_FRAME_BYTES - 4096;
/// Maximum UTF-8 bytes in a transferred file name. Names never carry paths.
pub const MAX_FILE_NAME_BYTES: usize = 255;
/// Maximum plaintext bytes in one encrypted chunk.
pub const MAX_CHUNK_PLAINTEXT_BYTES: usize = 256 * 1024;
/// Maximum total plaintext bytes in one transfer.
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum chunk count implied by the fixed size and chunk bounds.
pub const MAX_CHUNKS: u32 = 256;

const MAX_PUBLIC_KEY_BYTES: usize = PQ_PUBLIC_KEY_BYTES;
const MAX_PEER_ID_BYTES: usize = 128;
const LEGACY_SIGNATURE_LEN: usize = 64;
const MAX_CHUNK_CIPHERTEXT_BYTES: usize = MAX_CHUNK_PLAINTEXT_BYTES + NONCE_LEN + TAG_LEN;

const OFFER: u8 = 1;
const ACCEPT: u8 = 2;
const CHUNK: u8 = 3;
const CHUNK_ACK: u8 = 4;
const MANIFEST: u8 = 5;
const MANIFEST_ACK: u8 = 6;
const REJECT: u8 = 7;

/// One step of the file-transfer exchange. Sensitive fields are kept in
/// zeroizing buffers where practical and are redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub enum FileMessage {
    /// Announce a transfer, including the fresh content key. This is protected
    /// by Noise on the wire and never written to quarantine storage.
    Offer {
        transfer_id: [u8; 16],
        name: String,
        size: u64,
        chunk_count: u32,
        chunk_size: u32,
        manifest_hash: [u8; 32],
        content_key: Zeroizing<[u8; 32]>,
    },
    /// Accept or reject an offer. A `true` value is not a transfer claim.
    Accept {
        transfer_id: [u8; 16],
        accepted: bool,
    },
    /// One encrypted chunk with an explicit zero-based index.
    Chunk {
        transfer_id: [u8; 16],
        index: u32,
        ciphertext: Vec<u8>,
    },
    /// Acknowledge that a chunk was accepted into ciphertext quarantine.
    ChunkAck {
        transfer_id: [u8; 16],
        index: u32,
        accepted: bool,
    },
    /// Final commitment to every chunk hash and the full plaintext digest.
    Manifest {
        transfer_id: [u8; 16],
        chunk_hashes: Vec<[u8; 32]>,
        plaintext_hash: [u8; 32],
    },
    /// Acknowledge that the manifest hash was verified locally.
    ManifestAck {
        transfer_id: [u8; 16],
        accepted: bool,
    },
    /// Reject an unexpected or invalid transfer step.
    Reject { transfer_id: [u8; 16] },
}

impl FileMessage {
    fn code(&self) -> u8 {
        match self {
            Self::Offer { .. } => OFFER,
            Self::Accept { .. } => ACCEPT,
            Self::Chunk { .. } => CHUNK,
            Self::ChunkAck { .. } => CHUNK_ACK,
            Self::Manifest { .. } => MANIFEST,
            Self::ManifestAck { .. } => MANIFEST_ACK,
            Self::Reject { .. } => REJECT,
        }
    }

    fn transfer_id(&self) -> &[u8; 16] {
        match self {
            Self::Offer { transfer_id, .. }
            | Self::Accept { transfer_id, .. }
            | Self::Chunk { transfer_id, .. }
            | Self::ChunkAck { transfer_id, .. }
            | Self::Manifest { transfer_id, .. }
            | Self::ManifestAck { transfer_id, .. }
            | Self::Reject { transfer_id } => transfer_id,
        }
    }

    fn payload(&self) -> Result<Vec<u8>, FileError> {
        let mut out = Vec::new();
        match self {
            Self::Offer {
                name,
                size,
                chunk_count,
                chunk_size,
                manifest_hash,
                content_key,
                ..
            } => {
                put_bytes(&mut out, name.as_bytes())?;
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&chunk_count.to_le_bytes());
                out.extend_from_slice(&chunk_size.to_le_bytes());
                out.extend_from_slice(manifest_hash);
                out.extend_from_slice(content_key.as_ref());
            }
            Self::Accept { accepted, .. } | Self::ManifestAck { accepted, .. } => {
                out.push(u8::from(*accepted));
            }
            Self::Reject { .. } => {}
            Self::Chunk {
                index, ciphertext, ..
            } => {
                out.extend_from_slice(&index.to_le_bytes());
                put_bytes(&mut out, ciphertext)?;
            }
            Self::ChunkAck {
                index, accepted, ..
            } => {
                out.extend_from_slice(&index.to_le_bytes());
                out.push(u8::from(*accepted));
            }
            Self::Manifest {
                chunk_hashes,
                plaintext_hash,
                ..
            } => {
                let count =
                    u32::try_from(chunk_hashes.len()).map_err(|_| FileError::InvalidField)?;
                out.extend_from_slice(&count.to_le_bytes());
                for hash in chunk_hashes {
                    out.extend_from_slice(hash);
                }
                out.extend_from_slice(plaintext_hash);
            }
        }
        if out.len() > MAX_FILE_PAYLOAD_BYTES {
            return Err(FileError::FrameTooLarge);
        }
        Ok(out)
    }

    fn from_parts(code: u8, transfer_id: [u8; 16], payload: Vec<u8>) -> Result<Self, FileError> {
        let mut reader = Reader::new(&payload);
        let message = match code {
            OFFER => {
                let name_bytes = reader.var(MAX_FILE_NAME_BYTES)?;
                let name =
                    String::from_utf8(name_bytes.to_vec()).map_err(|_| FileError::InvalidField)?;
                validate_name(&name)?;
                let size = reader.u64()?;
                let chunk_count = reader.u32()?;
                let chunk_size = reader.u32()?;
                let manifest_hash = reader.fixed::<32>()?;
                let key: [u8; 32] = reader.fixed::<32>()?;
                Self::Offer {
                    transfer_id,
                    name,
                    size,
                    chunk_count,
                    chunk_size,
                    manifest_hash,
                    content_key: Zeroizing::new(key),
                }
            }
            ACCEPT => Self::Accept {
                transfer_id,
                accepted: read_bool(&mut reader)?,
            },
            CHUNK => {
                let index = reader.u32()?;
                let ciphertext = reader.var(MAX_CHUNK_CIPHERTEXT_BYTES)?;
                Self::Chunk {
                    transfer_id,
                    index,
                    ciphertext: ciphertext.to_vec(),
                }
            }
            CHUNK_ACK => {
                let index = reader.u32()?;
                Self::ChunkAck {
                    transfer_id,
                    index,
                    accepted: read_bool(&mut reader)?,
                }
            }
            MANIFEST => {
                let count = reader.u32()?;
                if count == 0 || count > MAX_CHUNKS {
                    return Err(FileError::InvalidField);
                }
                let mut chunk_hashes = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    chunk_hashes.push(reader.fixed::<32>()?);
                }
                Self::Manifest {
                    transfer_id,
                    chunk_hashes,
                    plaintext_hash: reader.fixed::<32>()?,
                }
            }
            MANIFEST_ACK => Self::ManifestAck {
                transfer_id,
                accepted: read_bool(&mut reader)?,
            },
            REJECT => Self::Reject { transfer_id },
            _ => return Err(FileError::UnknownMessage),
        };
        reader.finish()?;
        message.check_sizes()?;
        Ok(message)
    }

    fn check_sizes(&self) -> Result<(), FileError> {
        match self {
            Self::Offer {
                name,
                size,
                chunk_count,
                chunk_size,
                ..
            } => {
                validate_name(name)?;
                if *size == 0 || *size > MAX_TRANSFER_BYTES || *chunk_count > MAX_CHUNKS {
                    return Err(FileError::InvalidSize);
                }
                if *chunk_size == 0
                    || *chunk_size as usize > MAX_CHUNK_PLAINTEXT_BYTES
                    || *chunk_count == 0
                {
                    return Err(FileError::InvalidField);
                }
                let expected = size.div_ceil(u64::from(*chunk_size));
                if expected > u64::from(MAX_CHUNKS) || expected != u64::from(*chunk_count) {
                    return Err(FileError::ChunkCountMismatch);
                }
            }
            Self::Chunk {
                index, ciphertext, ..
            } => {
                if *index >= MAX_CHUNKS
                    || ciphertext.is_empty()
                    || ciphertext.len() > MAX_CHUNK_CIPHERTEXT_BYTES
                {
                    return Err(FileError::InvalidField);
                }
            }
            Self::ChunkAck { index, .. } => {
                if *index >= MAX_CHUNKS {
                    return Err(FileError::InvalidField);
                }
            }
            Self::Manifest { chunk_hashes, .. } => {
                if chunk_hashes.is_empty() || chunk_hashes.len() > MAX_CHUNKS as usize {
                    return Err(FileError::InvalidField);
                }
            }
            Self::Accept { .. } | Self::ManifestAck { .. } | Self::Reject { .. } => {}
        }
        if self.payload()?.len() > MAX_FILE_PAYLOAD_BYTES {
            return Err(FileError::FrameTooLarge);
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Offer { .. } => "offer",
            Self::Accept { .. } => "accept",
            Self::Chunk { .. } => "chunk",
            Self::ChunkAck { .. } => "chunk-ack",
            Self::Manifest { .. } => "manifest",
            Self::ManifestAck { .. } => "manifest-ack",
            Self::Reject { .. } => "reject",
        }
    }
}

impl fmt::Debug for FileMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileMessage")
            .field("kind", &self.kind())
            .field("transfer_id", &hex(self.transfer_id()))
            .field(
                "payload_len",
                &self.payload().map_or(0, |bytes| bytes.len()),
            )
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A signed file-protocol frame. Decoding does not verify the signature;
/// callers must call [`Self::verify`] with the authenticated peer and
/// [`Self::require_pq`] in production paths.
#[derive(Clone, PartialEq, Eq)]
pub struct FileEnvelope {
    pub sender: PeerId,
    pub sender_public_key: Vec<u8>,
    pub identity_proof: Vec<u8>,
    pub message: FileMessage,
    version: u16,
    signature: Vec<u8>,
}

impl FileEnvelope {
    /// Sign a new post-quantum file frame with the local vault identity.
    pub fn new(identity: &Identity, message: FileMessage) -> Result<Self, FileError> {
        message.check_sizes()?;
        let mut envelope = Self {
            sender: identity.peer_id(),
            sender_public_key: identity.pq_role_public_bytes(IdentityRole::File)?,
            identity_proof: identity.pq_proof_bytes(),
            message,
            version: FILE_VERSION,
            signature: vec![0u8; PQ_SIGNATURE_BYTES],
        };
        envelope.check_sizes()?;
        envelope.signature =
            identity.pq_sign_with_role(IdentityRole::File, &envelope.signing_bytes()?)?;
        Ok(envelope)
    }

    /// Wire version of this frame.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Fail closed unless this frame is the post-quantum codec. The legacy v2
    /// codec remains decodable and verifiable for adversarial tests only.
    pub fn require_pq(&self) -> Result<(), FileError> {
        if self.version != FILE_VERSION {
            return Err(FileError::UnsupportedVersion);
        }
        Ok(())
    }

    /// Build a valid classical-signature v2 frame for adversarial controller
    /// tests. Production send paths always use [`Self::new`] with v3 frames.
    #[doc(hidden)]
    pub fn legacy_v2_frame_for_tests(
        sender: &Identity,
        message: FileMessage,
    ) -> Result<Self, FileError> {
        message.check_sizes()?;
        let mut frame = Self {
            sender: sender.peer_id(),
            sender_public_key: sender.role_public_bytes(IdentityRole::File)?.to_vec(),
            identity_proof: sender.proof().to_bytes(),
            message,
            version: LEGACY_FILE_VERSION,
            signature: vec![0u8; LEGACY_SIGNATURE_LEN],
        };
        frame.check_sizes()?;
        frame.signature = sender.sign_with_role(IdentityRole::File, &frame.signing_bytes()?)?;
        Ok(frame)
    }

    /// Decode a signed frame. This does not verify the signature or sender.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FileError> {
        if bytes.len() > MAX_FILE_FRAME_BYTES {
            return Err(FileError::FrameTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.fixed::<4>()? != FILE_MAGIC {
            return Err(FileError::BadMagic);
        }
        let version = reader.u16()?;
        if version != FILE_VERSION && version != LEGACY_FILE_VERSION {
            return Err(FileError::UnsupportedVersion);
        }
        let code = reader.u8()?;
        let transfer_id = reader.fixed::<16>()?;
        let sender_public_key = reader.var(MAX_PUBLIC_KEY_BYTES)?;
        let sender_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let identity_proof = reader.var(MAX_PQ_IDENTITY_PROOF_BYTES)?;
        let payload = reader.var(MAX_FILE_PAYLOAD_BYTES)?;
        let signature = reader.take(signature_len_for_version(version))?.to_vec();
        reader.finish()?;

        let sender = PeerId::from_bytes(sender_bytes).map_err(|_| FileError::BadPeerId)?;
        let message = FileMessage::from_parts(code, transfer_id, payload.to_vec())?;
        let envelope = Self {
            sender,
            sender_public_key: sender_public_key.to_vec(),
            identity_proof: identity_proof.to_vec(),
            message,
            version,
            signature,
        };
        envelope.check_sizes()?;
        Ok(envelope)
    }

    /// Encode the full signed frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FileError> {
        self.check_sizes()?;
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > MAX_FILE_FRAME_BYTES {
            return Err(FileError::FrameTooLarge);
        }
        Ok(bytes)
    }

    /// Public transfer identifier carried by every frame.
    pub fn transfer_id(&self) -> &[u8; 16] {
        self.message.transfer_id()
    }

    /// Verify protocol fields, signature, public-key binding, and the expected
    /// Noise-authenticated sender before any frame field is used for state.
    pub fn verify(&self, expected_peer: &PeerId) -> Result<(), FileError> {
        if &self.sender != expected_peer {
            return Err(FileError::UnexpectedSender);
        }
        self.check_sizes()?;
        let signing_bytes = self.signing_bytes()?;
        let certified_key = if self.version == FILE_VERSION {
            verify_pq_application_signature(
                &self.identity_proof,
                IdentityRole::File,
                &self.sender,
                &signing_bytes,
                &self.signature,
                unix_time_seconds(),
            )
        } else {
            verify_application_signature(
                &self.identity_proof,
                IdentityRole::File,
                &self.sender,
                &signing_bytes,
                &self.signature,
                unix_time_seconds(),
            )
            .map(|key| key.to_vec())
        }?;
        if self.sender_public_key != certified_key {
            return Err(FileError::InvalidField);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, FileError> {
        let payload = self.message.payload()?;
        let mut bytes = Vec::with_capacity(payload.len() + 128);
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.push(self.message.code());
        bytes.extend_from_slice(self.message.transfer_id());
        put_bytes(&mut bytes, &self.sender_public_key)?;
        put_bytes(&mut bytes, &self.sender.to_bytes())?;
        put_bytes(&mut bytes, &self.identity_proof)?;
        put_bytes(&mut bytes, &payload)?;
        Ok(bytes)
    }

    fn check_sizes(&self) -> Result<(), FileError> {
        if FILE_MAGIC != *b"FILE" {
            return Err(FileError::BadMagic);
        }
        if self.version != FILE_VERSION && self.version != LEGACY_FILE_VERSION {
            return Err(FileError::UnsupportedVersion);
        }
        let is_pq = self.version == FILE_VERSION;
        let expected_key_len = if is_pq { PQ_PUBLIC_KEY_BYTES } else { 32 };
        if self.sender_public_key.len() != expected_key_len {
            return Err(FileError::InvalidField);
        }
        let proof_max = if is_pq {
            MAX_PQ_IDENTITY_PROOF_BYTES
        } else {
            MAX_IDENTITY_PROOF_BYTES
        };
        if self.identity_proof.is_empty() || self.identity_proof.len() > proof_max {
            return Err(FileError::InvalidField);
        }
        if self.signature.len() != signature_len_for_version(self.version) {
            return Err(FileError::BadSignature);
        }
        let peer_bytes = self.sender.to_bytes();
        if peer_bytes.is_empty() || peer_bytes.len() > MAX_PEER_ID_BYTES {
            return Err(FileError::BadPeerId);
        }
        self.message.check_sizes()?;
        if self
            .signing_bytes()?
            .len()
            .saturating_add(signature_len_for_version(self.version))
            > MAX_FILE_FRAME_BYTES
        {
            return Err(FileError::FrameTooLarge);
        }
        Ok(())
    }
}

fn signature_len_for_version(version: u16) -> usize {
    if version == FILE_VERSION {
        PQ_SIGNATURE_BYTES
    } else {
        LEGACY_SIGNATURE_LEN
    }
}

impl fmt::Debug for FileEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileEnvelope")
            .field("version", &self.version)
            .field("sender", &self.sender.to_string())
            .field("sender_public_key_len", &self.sender_public_key.len())
            .field("identity_proof_len", &self.identity_proof.len())
            .field("kind", &self.message.kind())
            .field("transfer_id", &hex(self.message.transfer_id()))
            .field("signature", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl From<p2p_identity::IdentityError> for FileError {
    fn from(error: p2p_identity::IdentityError) -> Self {
        match error {
            p2p_identity::IdentityError::NotEd25519 => FileError::NotEd25519,
            p2p_identity::IdentityError::PeerIdMismatch => FileError::BadPeerId,
            _ => FileError::BadSignature,
        }
    }
}

fn read_bool(reader: &mut Reader<'_>) -> Result<bool, FileError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FileError::InvalidField),
    }
}

pub(crate) fn validate_name(name: &str) -> Result<(), FileError> {
    if name.is_empty()
        || name.len() > MAX_FILE_NAME_BYTES
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|character| character.is_control() || character == '/' || character == '\\')
    {
        return Err(FileError::InvalidName);
    }
    Ok(())
}

/// Canonical commitment over a manifest. The offer carries its SHA-256 so a
/// final manifest cannot be substituted after chunks have been accepted.
pub(crate) fn manifest_commitment_bytes(
    transfer_id: &[u8; 16],
    chunk_hashes: &[[u8; 32]],
    plaintext_hash: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = b"p2pmsgr-file-manifest-v1".to_vec();
    bytes.extend_from_slice(transfer_id);
    let count = chunk_hashes.len() as u32;
    bytes.extend_from_slice(&count.to_le_bytes());
    for hash in chunk_hashes {
        bytes.extend_from_slice(hash);
    }
    bytes.extend_from_slice(plaintext_hash);
    bytes
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FileError> {
    let length = u32::try_from(bytes.len()).map_err(|_| FileError::FrameTooLarge)?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], FileError> {
        let slice = self.take(N)?;
        let mut value = [0u8; N];
        value.copy_from_slice(slice);
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, FileError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FileError> {
        Ok(u16::from_le_bytes(self.fixed::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, FileError> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, FileError> {
        Ok(u64::from_le_bytes(self.fixed::<8>()?))
    }

    fn var(&mut self, max: usize) -> Result<&'a [u8], FileError> {
        let length = self.u32()? as usize;
        if length > max {
            return Err(FileError::InvalidField);
        }
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], FileError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FileError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FileError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn finish(&self) -> Result<(), FileError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FileError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(sender: &Identity) -> FileEnvelope {
        FileEnvelope::new(
            sender,
            FileMessage::Offer {
                transfer_id: [7; 16],
                name: "report.txt".to_owned(),
                size: 1024,
                chunk_count: 1,
                chunk_size: MAX_CHUNK_PLAINTEXT_BYTES as u32,
                manifest_hash: [3; 32],
                content_key: Zeroizing::new([9; 32]),
            },
        )
        .expect("signed offer")
    }

    #[test]
    fn frame_round_trips_and_verifies_against_authenticated_peer() {
        let sender = Identity::generate().expect("identity");
        let frame = offer(&sender);
        let bytes = frame.to_bytes().expect("encode frame");
        let decoded = FileEnvelope::from_bytes(&bytes).expect("decode frame");
        decoded.verify(&sender.peer_id()).expect("verify frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn tampered_frames_and_wrong_peer_fail_closed() {
        let sender = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let mut bytes = offer(&sender).to_bytes().expect("encode frame");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = FileEnvelope::from_bytes(&bytes).expect("decode tampered frame");
        assert!(matches!(
            tampered.verify(&sender.peer_id()),
            Err(FileError::BadSignature)
        ));

        let original = offer(&sender);
        assert!(matches!(
            original.verify(&other.peer_id()),
            Err(FileError::UnexpectedSender)
        ));
    }

    fn tampered_pq_proof(identity: &Identity) -> Vec<u8> {
        let mut bytes = identity.pq_proof_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        bytes
    }

    fn legacy_v2_frame(sender: &Identity) -> FileEnvelope {
        FileEnvelope::legacy_v2_frame_for_tests(
            sender,
            FileMessage::Accept {
                transfer_id: [7; 16],
                accepted: true,
            },
        )
        .expect("legacy frame")
    }

    #[test]
    fn legacy_v2_frames_decode_and_verify_but_fail_the_production_gate() {
        let sender = Identity::generate().expect("identity");
        let frame = legacy_v2_frame(&sender);
        let encoded = frame.to_bytes().expect("legacy encoded frame");
        let decoded = FileEnvelope::from_bytes(&encoded).expect("legacy decode");
        assert_eq!(decoded.version(), LEGACY_FILE_VERSION);
        decoded.verify(&sender.peer_id()).expect("legacy signature");
        assert!(decoded.require_pq().is_err());
    }

    #[test]
    fn wrong_role_and_classical_signatures_are_rejected() {
        let sender = Identity::generate().expect("identity");
        let mut frame = offer(&sender);
        let signed_bytes = frame.signing_bytes().expect("signed bytes");

        let application_signature = sender
            .pq_sign_with_role(IdentityRole::Application, &signed_bytes)
            .expect("application PQ role signature");
        frame.signature = application_signature;
        assert!(matches!(
            frame.verify(&sender.peer_id()),
            Err(FileError::BadSignature)
        ));

        let transport_signature = sender.sign(&signed_bytes).expect("transport signature");
        frame.signature = transport_signature;
        assert!(matches!(
            frame.verify(&sender.peer_id()),
            Err(FileError::BadSignature)
        ));
    }

    #[test]
    fn substituted_and_tampered_pq_proofs_are_rejected() {
        let sender = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let frame = offer(&sender);

        let mut substituted = frame.clone();
        substituted.identity_proof = other.pq_proof_bytes();
        assert!(substituted.verify(&sender.peer_id()).is_err());

        let mut tampered = frame.clone();
        tampered.identity_proof = tampered_pq_proof(&sender);
        assert!(tampered.verify(&sender.peer_id()).is_err());

        assert_eq!(
            frame.sender_public_key,
            sender
                .pq_role_public_bytes(IdentityRole::File)
                .expect("local PQ file key")
        );
        assert_ne!(
            frame.sender_public_key.as_slice(),
            sender.ed25519_public_bytes().expect("transport key")
        );
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let sender = Identity::generate().expect("identity");
        let frame = offer(&sender);
        let mut bytes = frame.to_bytes().expect("encode frame");
        bytes[0] = b'X';
        assert!(matches!(
            FileEnvelope::from_bytes(&bytes),
            Err(FileError::BadMagic)
        ));
        assert!(matches!(
            FileEnvelope::from_bytes(&[0u8; 4]),
            Err(FileError::BadMagic)
        ));
        assert!(matches!(
            FileEnvelope::from_bytes(&FILE_MAGIC),
            Err(FileError::Truncated)
        ));
        assert!(matches!(
            FileEnvelope::from_bytes(&vec![0u8; MAX_FILE_FRAME_BYTES + 1]),
            Err(FileError::FrameTooLarge)
        ));
        let mut trailing = frame.to_bytes().expect("encode frame");
        trailing.push(0);
        assert!(matches!(
            FileEnvelope::from_bytes(&trailing),
            Err(FileError::TrailingBytes)
        ));
    }

    #[test]
    fn path_like_names_are_rejected() {
        let sender = Identity::generate().expect("identity");
        for name in ["../secret", "dir/file", "C:\\secret", "", ".."] {
            let result = FileEnvelope::new(
                &sender,
                FileMessage::Offer {
                    transfer_id: [1; 16],
                    name: name.to_owned(),
                    size: 1,
                    chunk_count: 1,
                    chunk_size: 64,
                    manifest_hash: [0; 32],
                    content_key: Zeroizing::new([2; 32]),
                },
            );
            assert!(
                matches!(result, Err(FileError::InvalidName)),
                "name: {name}"
            );
        }
    }

    #[test]
    fn debug_output_redacts_key_and_signature() {
        let sender = Identity::generate().expect("identity");
        let frame = offer(&sender);
        let decoded = format!("{frame:?}");
        assert!(decoded.contains("<redacted>"));
        assert!(!decoded.contains("content_key"));
        assert!(!decoded.contains("signature: ["));
    }
}
