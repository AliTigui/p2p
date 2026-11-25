//! Local cryptographic identity for the P2P messenger.
//!
//! Identities are generated locally with Ed25519, exposed through libp2p
//! [`PeerId`]s, and verified by an out-of-band fingerprint. Nothing in this
//! crate contacts a server, reads hardware identifiers, or derives a key from
//! a password. Private keys are never formatted for display or logs.

#![forbid(unsafe_code)]

mod contact;
mod envelope;
mod fingerprint;

pub use contact::{CONTACT_PATH_PREFIX, ContactPayload};
pub use envelope::{
    DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST, EXPORT_PURPOSE, EncryptedIdentity,
    KDF_ARGON2ID_V1,
};
pub use fingerprint::{FINGERPRINT_PREFIX, Fingerprint};

use std::fmt;

use libp2p_identity::{KeyType, Keypair, PeerId, PublicKey};
use thiserror::Error;

/// Errors produced by identity generation and verification.
///
/// Variants deliberately carry only non-secret context. Error strings must
/// never include key material, passwords, or decrypted bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("fingerprint is invalid: {0}")]
    InvalidFingerprint(String),
    #[error("contact payload is invalid: {0}")]
    InvalidContactPayload(String),
    #[error("contact public key does not match its PeerId")]
    PeerIdMismatch,
    #[error("encrypted identity envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("unsupported encrypted identity envelope version {0}")]
    UnsupportedEnvelopeVersion(u8),
    #[error("unsupported key derivation function id {0}")]
    UnsupportedKdf(u8),
    #[error("Argon2id parameters in the envelope are outside safe bounds")]
    UnsafeKdfParams,
    #[error("password cannot be empty")]
    EmptyPassword,
    #[error("password is incorrect or the encrypted envelope is damaged")]
    DecryptionFailed,
    #[error("key is not Ed25519; this build only supports Ed25519 identities")]
    NotEd25519,
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("system randomness source failed")]
    Randomness,
    #[error("QR code could not be generated: {0}")]
    Qr(String),
}

/// A locally generated Ed25519 identity.
///
/// The private key is held in memory only. This type intentionally implements
/// a redacting [`fmt::Debug`] and has no `Serialize` implementation for secret
/// state; persistence is possible only through [`EncryptedIdentity::encrypt`].
#[derive(Clone)]
pub struct Identity {
    keypair: Keypair,
    peer_id: PeerId,
    public_key: PublicKey,
    fingerprint: Fingerprint,
}

impl Identity {
    /// Generate a fresh, cryptographically random Ed25519 identity.
    pub fn generate() -> Result<Self, IdentityError> {
        Self::from_keypair(Keypair::generate_ed25519())
    }

    /// Adopt an existing libp2p keypair. Rejects non-Ed25519 keys so that
    /// fingerprints and exports have one unambiguous meaning.
    pub fn from_keypair(keypair: Keypair) -> Result<Self, IdentityError> {
        let public_key = keypair.public();
        let fingerprint = Fingerprint::from_public_key(&public_key)?;
        let peer_id = public_key.to_peer_id();
        Ok(Self {
            keypair,
            peer_id,
            public_key,
            fingerprint,
        })
    }

    /// Public network identifier derived from the Ed25519 public key.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Public key used by Noise and by contact verification.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Protobuf-encoded public key, safe to store or transmit in the clear.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.encode_protobuf()
    }

    /// Raw 32-byte Ed25519 public key used by MLS credentials and the envelope
    /// signer binding. This identity only accepts Ed25519 keys, so failure here
    /// indicates internal corruption rather than an unsupported key type.
    pub fn ed25519_public_bytes(&self) -> Result<[u8; 32], IdentityError> {
        raw_ed25519_public_bytes_from_protobuf(&self.public_key_bytes())
    }

    /// Raw private keypair bytes for encrypted local persistence.
    ///
    /// This is *not* an export format for users: callers must encrypt the
    /// returned buffer (e.g. with the `storage/identity` subkey) before writing
    /// it anywhere. The buffer zeroizes itself when dropped.
    pub fn export_keypair_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(
            self.keypair
                .to_protobuf_encoding()
                .expect("an Ed25519 keypair always encodes to protobuf"),
        )
    }

    /// Rebuild an identity from bytes written by [`Self::export_keypair_bytes`].
    pub fn import_keypair_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let keypair = Keypair::from_protobuf_encoding(bytes)
            .map_err(|_| IdentityError::InvalidEnvelope("private key decode failed".to_owned()))?;
        Self::from_keypair(keypair)
    }

    /// Stable, out-of-band verification string.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Sign a message with this identity's private key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.keypair
            .sign(message)
            .map_err(|err| IdentityError::Crypto(err.to_string()))
    }

    /// Verify a signature with this identity's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.public_key.verify(message, signature)
    }

    pub(crate) fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

/// Decode a raw 32-byte Ed25519 public key from the protobuf form carried in
/// signed envelopes and MLS credentials.
pub fn raw_ed25519_public_bytes_from_protobuf(
    public_key_bytes: &[u8],
) -> Result<[u8; 32], IdentityError> {
    let public_key = PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|_| IdentityError::InvalidEnvelope("public key decode failed".to_owned()))?;
    let ed25519 = public_key
        .try_into_ed25519()
        .map_err(|_| IdentityError::NotEd25519)?;
    Ok(ed25519.to_bytes())
}

/// Verify a signature from a protobuf-encoded public key and bind it to an
/// expected PeerId.
///
/// This is used by wire layers that carry the sender's public key alongside
/// its PeerId. A PeerId alone is a multihash and cannot independently verify an
/// Ed25519 signature, so both values are checked here before `verify` runs.
pub fn verify_signature_with_public_bytes(
    message: &[u8],
    signature: &[u8],
    public_key_bytes: &[u8],
    expected_peer: &PeerId,
) -> Result<bool, IdentityError> {
    let public_key = PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|_| IdentityError::InvalidEnvelope("public key decode failed".to_owned()))?;
    if public_key.key_type() != KeyType::Ed25519 {
        return Err(IdentityError::NotEd25519);
    }
    if &public_key.to_peer_id() != expected_peer {
        return Err(IdentityError::PeerIdMismatch);
    }
    Ok(public_key.verify(message, signature))
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("peer_id", &self.peer_id.to_string())
            .field("fingerprint", &self.fingerprint.as_str())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identities_are_unique_and_internally_consistent() {
        let first = Identity::generate().expect("identity generation");
        let second = Identity::generate().expect("identity generation");

        assert_ne!(first.peer_id(), second.peer_id());
        assert_eq!(first.peer_id(), first.public_key().to_peer_id());
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_eq!(
            PublicKey::try_decode_protobuf(&first.public_key_bytes()).expect("public key decode"),
            *first.public_key()
        );
    }

    #[test]
    fn raw_public_key_helper_matches_the_identity_key_and_rejects_invalid_input() {
        let identity = Identity::generate().expect("identity");
        let raw = identity.ed25519_public_bytes().expect("raw public key");
        assert_eq!(raw.len(), 32);
        assert_eq!(
            raw_ed25519_public_bytes_from_protobuf(&identity.public_key_bytes()).expect("decoded"),
            raw
        );
        assert!(raw_ed25519_public_bytes_from_protobuf(&[0xff]).is_err());
        assert_ne!(
            raw,
            Identity::generate()
                .expect("other")
                .ed25519_public_bytes()
                .unwrap()
        );
    }

    #[test]
    fn signatures_verify_and_reject_modified_messages() {
        let identity = Identity::generate().expect("identity generation");
        let signature = identity.sign(b"contact request").expect("sign");

        assert!(identity.verify(b"contact request", &signature));
        assert!(!identity.verify(b"contact request!", &signature));
        assert!(!identity.verify(b"contact request", b"bad signature"));

        let other = Identity::generate().expect("identity generation");
        assert!(!other.verify(b"contact request", &signature));
    }

    #[test]
    fn debug_output_never_contains_the_private_key() {
        let identity = Identity::generate().expect("identity generation");
        let debug = format!("{identity:?}");

        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(identity.peer_id().to_string().as_str()));
        assert!(debug.contains(identity.fingerprint().as_str()));

        let private = identity
            .keypair()
            .to_protobuf_encoding()
            .expect("private key encoding");
        // The redacted Debug output must not expose raw private-key bytes as hex.
        let hex: String = private
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");
        assert!(!debug.contains(&hex));
    }
}
