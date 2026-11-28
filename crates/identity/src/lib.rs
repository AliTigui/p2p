//! Local cryptographic identity for the P2P messenger.
//!
//! One account owns independent Ed25519 keys for the account root, device,
//! libp2p transport, MLS signing, application envelopes/setup, and file frames.
//! Root and device keys certify the purpose-specific keys. Nothing in this crate
//! contacts a server, reads hardware identifiers, or derives a key from a
//! password. Private keys are never formatted for display or logs.

#![forbid(unsafe_code)]

mod bundle;
mod certificate;
mod contact;
mod delegation;
mod envelope;
mod fingerprint;
mod pq;
mod proof;
mod roles;
mod rotation;

pub use bundle::{MAX_IDENTITY_BUNDLE_BYTES, RootKey};
pub use certificate::{
    CERTIFICATE_BYTES, CERTIFICATE_VERSION, DEFAULT_CERT_VALIDITY_SECONDS, IdentityCertificate,
};
pub use contact::{CONTACT_PATH_PREFIX, ContactPayload};
pub use delegation::{RoleDelegation, resolve_delegated_grant};
pub use envelope::{
    DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST, EXPORT_PURPOSE, EncryptedIdentity,
    KDF_ARGON2ID_V1,
};
pub use fingerprint::{FINGERPRINT_PREFIX, Fingerprint};
pub use pq::{
    MAX_PQ_IDENTITY_PROOF_BYTES, PQ_PROOF_VERSION, PQ_PROOF_VERSION as PQ_SIGNATURE_VERSION,
    PQ_PUBLIC_KEY_BYTES, PQ_SCHEME_ID, PQ_SEED_BYTES, PQ_SIGNATURE_BYTES,
    verify_pq_role_signature_with_key,
};
pub(crate) use pq::{PqIdentityProof, PqSeeds, random_seed, sign_seed};
pub use proof::{IDENTITY_PROOF_HEADER_BYTES, IdentityProof, MAX_IDENTITY_PROOF_BYTES};
pub use roles::IdentityRole;
pub use rotation::{ROTATION_BYTES, ROTATION_VERSION, RotationRecord};

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p_identity::{KeyType, Keypair, PeerId, PublicKey};
use thiserror::Error;

use bundle::IdentityBundle;

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
    #[error("requested role is not available for this operation")]
    WrongRole,
    #[error("identity certificate is invalid: {0}")]
    InvalidCertificate(String),
    #[error("identity proof is invalid: {0}")]
    InvalidIdentityProof(String),
    #[error("identity certificate has expired")]
    ExpiredCertificate,
    #[error("identity or certificate is revoked")]
    RevokedIdentity,
    #[error("root rotation record is invalid: {0}")]
    InvalidRotation(String),
    #[error("signature does not match the certified role key")]
    InvalidSignature,
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("system randomness source failed")]
    Randomness,
    #[error("QR code could not be generated: {0}")]
    Qr(String),
}

/// Current Unix timestamp in seconds, floored at zero for pre-epoch clocks.
pub fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Short non-secret prefix for diagnostic output only.
pub(crate) fn hex_short(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// A locally generated, role-separated cryptographic identity.
///
/// Private keys are held in memory only. This type intentionally implements a
/// redacting [`fmt::Debug`] and has no `Serialize` implementation for secret
/// state; persistence is possible only through encrypted credentials.
#[derive(Clone)]
pub struct Identity {
    bundle: IdentityBundle,
    peer_id: PeerId,
    public_key: PublicKey,
    fingerprint: Fingerprint,
}

impl Identity {
    /// Generate a fresh account with independent keys for every role.
    pub fn generate() -> Result<Self, IdentityError> {
        Self::from_bundle(IdentityBundle::generate()?)
    }

    /// Adopt an existing libp2p keypair and bind fresh role keys to it. This
    /// preserves the PeerId for legacy vault migration while creating a new
    /// certified account for role-separated operations.
    pub fn from_keypair(keypair: Keypair) -> Result<Self, IdentityError> {
        Self::from_bundle(IdentityBundle::from_transport(keypair)?)
    }

    fn from_bundle(bundle: IdentityBundle) -> Result<Self, IdentityError> {
        bundle.validate_at(unix_time_seconds())?;
        let public_key = bundle.transport().public();
        let fingerprint = Fingerprint::from_public_key(&public_key)?;
        let peer_id = public_key.to_peer_id();
        Ok(Self {
            bundle,
            peer_id,
            public_key,
            fingerprint,
        })
    }

    /// Public network identifier derived from the transport Ed25519 key.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Transport public key used by libp2p Noise and contact verification.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Protobuf-encoded transport public key, safe to store or transmit.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.encode_protobuf()
    }

    /// Raw 32-byte transport Ed25519 public key.
    pub fn ed25519_public_bytes(&self) -> Result<[u8; 32], IdentityError> {
        raw_ed25519_public_bytes_from_protobuf(&self.public_key_bytes())
    }

    /// Raw 32-byte public key for one purpose-specific role.
    pub fn role_public_bytes(&self, role: IdentityRole) -> Result<[u8; 32], IdentityError> {
        self.bundle.proof().role_public_key(role)
    }

    /// Self-contained ML-DSA-65 proof for this identity. This is the proof
    /// carried by post-quantum setup and file frames.
    pub fn pq_proof_bytes(&self) -> Vec<u8> {
        self.bundle.pq_proof().to_bytes()
    }

    /// Encoded ML-DSA-65 public key for one non-transport role.
    pub fn pq_role_public_bytes(&self, role: IdentityRole) -> Result<Vec<u8>, IdentityError> {
        Ok(self.bundle.pq_proof().role_public_key(role)?.to_vec())
    }

    /// Zeroizing ML-DSA-65 seed for one role. Used by the MLS signer and never
    /// exposed on the wire.
    pub fn pq_role_seed(
        &self,
        role: IdentityRole,
    ) -> Result<zeroize::Zeroizing<[u8; PQ_SEED_BYTES]>, IdentityError> {
        self.bundle.pq_seeds().get(role).cloned()
    }

    /// Sign application data with an ML-DSA-65 role key. The signed bytes bind
    /// the role, message length, message, and exact certified public key.
    pub fn pq_sign_with_role(
        &self,
        role: IdentityRole,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let signed = self.bundle.pq_proof().signing_bytes(role, message)?;
        sign_seed(self.bundle.pq_seeds().get(role)?, &signed)
    }

    /// Signed public certificate for one role.
    pub fn certificate(&self, role: IdentityRole) -> Option<&IdentityCertificate> {
        self.bundle.proof().certificate(role)
    }

    /// Public certificate chain and root-rotation history.
    pub fn proof(&self) -> &IdentityProof {
        self.bundle.proof()
    }

    /// Validate all certificates against the current time.
    pub fn validate_certificates(&self) -> Result<(), IdentityError> {
        self.bundle.validate_at(unix_time_seconds())
    }

    /// Validate all certificates against a caller-supplied time.
    pub fn validate_certificates_at(&self, now: u64) -> Result<(), IdentityError> {
        self.bundle.validate_at(now)
    }

    /// Root key first verified by a contact.
    pub fn initial_root(&self) -> [u8; 32] {
        self.bundle.proof().initial_root()
    }

    /// Verify a signed root transition against a previously trusted root.
    pub fn verify_rotation(
        &self,
        trusted_root: [u8; 32],
        record: &RotationRecord,
        now: u64,
    ) -> Result<(), IdentityError> {
        record.validate(now)?;
        if record.previous_root() != trusted_root {
            return Err(IdentityError::InvalidRotation(
                "rotation does not continue the trusted root".to_owned(),
            ));
        }
        Ok(())
    }

    /// Rotate the account root while preserving the same device, transport, and
    /// role keys. Old contacts can verify the returned record against the root
    /// they previously trusted.
    pub fn rotate_root(
        &mut self,
        next: RootKey,
        now: u64,
    ) -> Result<RotationRecord, IdentityError> {
        let next = next.into_keypair();
        let record = RotationRecord::new(self.bundle.root(), &next, now)?;
        record.validate(now)?;

        let expires = now.saturating_add(DEFAULT_CERT_VALIDITY_SECONDS);
        let next_root_key = next.public().to_bytes();
        let device_key = self.bundle.proof().device().public_key();

        let root_cert = IdentityCertificate::reissued_signed(
            self.bundle.proof().root(),
            next_root_key,
            next_root_key,
            now,
            expires,
            &next,
        )?;
        let device_cert = IdentityCertificate::reissued_signed(
            self.bundle.proof().device(),
            device_key,
            next_root_key,
            now,
            expires,
            &next,
        )?;

        fn reissue(
            template: &IdentityCertificate,
            issuer: [u8; 32],
            issuer_key: &libp2p_identity::ed25519::Keypair,
            now: u64,
            expires: u64,
        ) -> Result<IdentityCertificate, IdentityError> {
            let public = template.public_key();
            IdentityCertificate::reissued_signed(template, public, issuer, now, expires, issuer_key)
        }

        let transport_cert = reissue(
            self.bundle
                .proof()
                .certificate(IdentityRole::Transport)
                .expect("transport cert"),
            device_key,
            self.bundle.device(),
            now,
            expires,
        )?;
        let mls_cert = reissue(
            self.bundle
                .proof()
                .certificate(IdentityRole::Mls)
                .expect("mls cert"),
            device_key,
            self.bundle.device(),
            now,
            expires,
        )?;
        let application_cert = reissue(
            self.bundle
                .proof()
                .certificate(IdentityRole::Application)
                .expect("app cert"),
            device_key,
            self.bundle.device(),
            now,
            expires,
        )?;
        let file_cert = reissue(
            self.bundle
                .proof()
                .certificate(IdentityRole::File)
                .expect("file cert"),
            device_key,
            self.bundle.device(),
            now,
            expires,
        )?;

        let mut rotations = self.bundle.proof().rotations().to_vec();
        rotations.push(record.clone());
        let proof = IdentityProof::new(
            self.bundle.proof().initial_root(),
            root_cert,
            device_cert,
            transport_cert,
            mls_cert,
            application_cert,
            file_cert,
            rotations,
        )?;
        proof.validate_at(now)?;
        self.bundle.set_root(next);
        self.bundle.replace_proof(proof);
        let pq_root = random_seed()?;
        self.bundle
            .replace_pq_seed(IdentityRole::Root, pq_root, now)?;
        Ok(record)
    }

    /// Revoke one non-root role in the locally held proof. Root keys are
    /// rotated instead of revoked. The reissued certificate remains signed by
    /// the correct issuing key, so it can be sent in a public identity proof.
    pub fn revoke_role(&mut self, role: IdentityRole) -> Result<(), IdentityError> {
        let issuer: &libp2p_identity::ed25519::Keypair;
        let mut certificate = match role {
            IdentityRole::Root => return Err(IdentityError::WrongRole),
            IdentityRole::Device => {
                issuer = self.bundle.root();
                self.bundle.proof().device().clone()
            }
            IdentityRole::Transport
            | IdentityRole::Mls
            | IdentityRole::Application
            | IdentityRole::File => {
                issuer = self.bundle.device();
                self.bundle
                    .proof()
                    .certificate(role)
                    .ok_or(IdentityError::WrongRole)?
                    .clone()
            }
        };
        let now = unix_time_seconds();
        self.bundle.proof().validate_at(now)?;
        certificate.set_revoked(true, issuer)?;
        let mut proof = self.bundle.proof().clone();
        proof.replace_certificate(certificate);
        self.bundle.replace_proof(proof);
        let pq_seed = random_seed()?;
        self.bundle.replace_pq_seed(role, pq_seed, now)?;
        Ok(())
    }

    /// Whether a role certificate in the local proof is marked revoked.
    pub fn is_role_revoked(&self, role: IdentityRole) -> bool {
        self.bundle
            .proof()
            .certificate(role)
            .is_some_and(IdentityCertificate::revoked)
    }

    /// Raw transport private keypair bytes for the libp2p swarm only.
    ///
    /// This is *not* a role-separated export format: callers must use it only to
    /// build a libp2p `Keypair`. The buffer zeroizes itself when dropped.
    pub fn export_keypair_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(
            self.bundle
                .transport()
                .to_protobuf_encoding()
                .expect("an Ed25519 keypair always encodes to protobuf"),
        )
    }

    /// Rebuild a legacy transport-only identity. New code must use
    /// [`Self::import_bundle_bytes`] so role keys survive a restart.
    pub fn import_keypair_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let keypair = Keypair::from_protobuf_encoding(bytes)
            .map_err(|_| IdentityError::InvalidEnvelope("private key decode failed".to_owned()))?;
        Self::from_keypair(keypair)
    }

    /// Encode the complete role-separated private bundle. The buffer zeroizes
    /// itself and must only be written through authenticated encryption.
    pub fn export_bundle_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, IdentityError> {
        self.bundle.encode()
    }

    /// Import a complete role-separated bundle, or a legacy transport-only
    /// keypair for explicit migration.
    pub fn import_bundle_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.starts_with(bundle::BUNDLE_MAGIC) {
            let bundle = IdentityBundle::decode(bytes)?;
            return Self::from_bundle(bundle);
        }
        Self::import_keypair_bytes(bytes)
    }

    /// Stable, out-of-band verification string for the transport key.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Legacy transport-key signature. Application wire layers must use
    /// [`Self::sign_with_role`] with their dedicated role.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.bundle
            .transport()
            .sign(message)
            .map_err(|err| IdentityError::Crypto(err.to_string()))
    }

    /// Verify a legacy transport-key signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.public_key.verify(message, signature)
    }

    /// Sign application data with one role's independent private key.
    pub fn sign_with_role(
        &self,
        role: IdentityRole,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let signing_bytes = role_signing_bytes(role, message);
        match role {
            IdentityRole::Transport => self
                .bundle
                .transport()
                .sign(&signing_bytes)
                .map_err(|error| IdentityError::Crypto(error.to_string())),
            IdentityRole::Root
            | IdentityRole::Device
            | IdentityRole::Mls
            | IdentityRole::Application
            | IdentityRole::File => Ok(self.bundle.role_key(role)?.sign(&signing_bytes)),
        }
    }

    /// Sign a protocol payload whose own format supplies domain separation.
    /// OpenMLS signatures must cover the exact MLS bytes, so the role key is
    /// still separated, but this method does not add the application wire prefix.
    pub fn sign_raw_with_role(
        &self,
        role: IdentityRole,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        match role {
            IdentityRole::Transport => self
                .bundle
                .transport()
                .sign(message)
                .map_err(|error| IdentityError::Crypto(error.to_string())),
            IdentityRole::Root
            | IdentityRole::Device
            | IdentityRole::Mls
            | IdentityRole::Application
            | IdentityRole::File => Ok(self.bundle.role_key(role)?.sign(message)),
        }
    }

    /// Verify application data with one role's certified public key.
    pub fn verify_with_role(
        &self,
        role: IdentityRole,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, IdentityError> {
        let signing_bytes = role_signing_bytes(role, message);
        match role {
            IdentityRole::Transport => {
                let public =
                    PublicKey::try_decode_protobuf(&self.public_key_bytes()).map_err(|_| {
                        IdentityError::InvalidEnvelope("public key decode failed".to_owned())
                    })?;
                Ok(public.verify(&signing_bytes, signature))
            }
            IdentityRole::Root
            | IdentityRole::Device
            | IdentityRole::Mls
            | IdentityRole::Application
            | IdentityRole::File => {
                let bytes = self.role_public_bytes(role)?;
                let public =
                    libp2p_identity::ed25519::PublicKey::try_from_bytes(&bytes).map_err(|_| {
                        IdentityError::InvalidCertificate("invalid role key".to_owned())
                    })?;
                Ok(public.verify(&signing_bytes, signature))
            }
        }
    }
}

/// Sign raw MLS payload bytes with an ML-DSA-65 seed. OpenMLS requires the
/// signature to cover exactly its serialized bytes, so no domain prefix is
/// added here; role separation comes from the certified MLS seed.
pub fn pq_sign_for_mls(
    seed: &[u8; PQ_SEED_BYTES],
    payload: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    sign_seed(seed, payload)
}

/// Domain-separated bytes actually signed by a role key.
pub fn role_signing_bytes(role: IdentityRole, message: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(role.signing_domain().len() + message.len());
    bytes.extend_from_slice(role.signing_domain());
    bytes.extend_from_slice(message);
    bytes
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

/// Verify a raw Ed25519 signature from a protobuf-encoded public key and bind
/// it to an expected transport PeerId. Used only by legacy transport-signed
/// wire layers; new layers verify role certificates instead.
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

/// Verify a signature with a raw Ed25519 public key without PeerId binding.
/// Callers must first bind the key to an authenticated role certificate.
pub fn verify_raw_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, IdentityError> {
    let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map_err(|_| IdentityError::InvalidCertificate("invalid role key".to_owned()))?;
    Ok(public.verify(message, signature))
}

/// Derive the transport PeerId from a raw Ed25519 transport certificate key.
pub fn peer_id_from_raw_ed25519(public_key: &[u8; 32]) -> Result<PeerId, IdentityError> {
    let ed25519 = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map_err(|_| IdentityError::InvalidCertificate("invalid transport key".to_owned()))?;
    Ok(PeerId::from(PublicKey::from(ed25519)))
}

/// Extract one certified role key from a self-contained public identity proof.
///
/// The transport certificate must derive exactly the PeerId authenticated by
/// Noise. Expired, revoked, forged, or wrong-role proofs are rejected before a
/// role key is returned.
pub fn certified_role_public_key(
    proof_bytes: &[u8],
    role: IdentityRole,
    expected_peer: &PeerId,
    now: u64,
) -> Result<[u8; 32], IdentityError> {
    let proof = IdentityProof::from_bytes(proof_bytes)?;
    proof.validate_at(now)?;
    let transport = proof.role_public_key(IdentityRole::Transport)?;
    if &peer_id_from_raw_ed25519(&transport)? != expected_peer {
        return Err(IdentityError::PeerIdMismatch);
    }
    proof.role_public_key(role)
}

/// Extract one certified ML-DSA-65 role key from a self-contained PQ proof.
/// The proof's root/device chain and PeerId binding are fully validated first.
pub fn certified_pq_role_public_key(
    proof_bytes: &[u8],
    role: IdentityRole,
    expected_peer: &PeerId,
    now: u64,
) -> Result<Vec<u8>, IdentityError> {
    let proof = PqIdentityProof::from_bytes(proof_bytes)?;
    proof.validate_at(expected_peer, now)?;
    Ok(proof.role_public_key(role)?.to_vec())
}

/// Verify an ML-DSA-65 role signature against a self-contained PQ proof. The
/// returned key is the certified key that verified the signature.
pub fn verify_pq_application_signature(
    proof_bytes: &[u8],
    role: IdentityRole,
    expected_peer: &PeerId,
    message: &[u8],
    signature: &[u8],
    now: u64,
) -> Result<Vec<u8>, IdentityError> {
    let proof = PqIdentityProof::from_bytes(proof_bytes)?;
    proof.validate_at(expected_peer, now)?;
    proof.verify_role_signature(role, message, signature)?;
    Ok(proof.role_public_key(role)?.to_vec())
}

/// Verify a role signature against a self-contained public identity proof.
/// The returned key is the certified key that verified the signature.
pub fn verify_application_signature(
    proof_bytes: &[u8],
    role: IdentityRole,
    expected_peer: &PeerId,
    message: &[u8],
    signature: &[u8],
    now: u64,
) -> Result<[u8; 32], IdentityError> {
    let role_key = certified_role_public_key(proof_bytes, role, expected_peer, now)?;
    if !verify_raw_signature(&role_key, &role_signing_bytes(role, message), signature)? {
        return Err(IdentityError::InvalidSignature);
    }
    Ok(role_key)
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("peer_id", &self.peer_id.to_string())
            .field("fingerprint", &self.fingerprint.as_str())
            .field("proof", self.proof())
            .field("private_keys", &"<redacted>")
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
    fn role_keys_are_independent_and_wrong_role_signatures_fail() {
        let identity = Identity::generate().expect("identity");
        let roles = [
            IdentityRole::Root,
            IdentityRole::Device,
            IdentityRole::Transport,
            IdentityRole::Mls,
            IdentityRole::Application,
            IdentityRole::File,
        ];
        let mut keys = Vec::new();
        for role in roles {
            let key = identity.role_public_bytes(role).expect("role key");
            assert!(!keys.contains(&key), "role {role} reused a key");
            keys.push(key);
        }

        let message = b"role separation";
        let mls = identity
            .sign_with_role(IdentityRole::Mls, message)
            .expect("mls signature");
        assert!(
            identity
                .verify_with_role(IdentityRole::Mls, message, &mls)
                .expect("verify mls")
        );
        assert!(
            !identity
                .verify_with_role(IdentityRole::Application, message, &mls)
                .expect("verify app")
        );
        assert!(
            !identity
                .verify_with_role(IdentityRole::File, message, &mls)
                .expect("verify file")
        );

        let transport = identity.sign(message).expect("transport signature");
        assert!(
            !identity
                .verify_with_role(IdentityRole::Mls, message, &transport)
                .expect("verify mls")
        );
    }

    #[test]
    fn raw_public_key_helper_matches_the_transport_key_and_rejects_invalid_input() {
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
    fn valid_root_rotation_preserves_transport_and_role_keys() {
        let mut identity = Identity::generate().expect("identity");
        let trusted_root = identity.initial_root();
        let old_peer = identity.peer_id();
        let old_mls = identity
            .role_public_bytes(IdentityRole::Mls)
            .expect("mls key");
        let next = RootKey::generate();
        let record = identity
            .rotate_root(next, unix_time_seconds())
            .expect("root rotation");

        assert_eq!(identity.peer_id(), old_peer);
        assert_eq!(
            identity
                .role_public_bytes(IdentityRole::Mls)
                .expect("mls key"),
            old_mls
        );
        identity
            .verify_rotation(trusted_root, &record, unix_time_seconds())
            .expect("rotation continuity");
        identity
            .validate_certificates()
            .expect("certificates after rotation");
    }

    #[test]
    fn forged_and_stale_root_rotations_are_rejected() {
        let mut identity = Identity::generate().expect("identity");
        let trusted_root = identity.initial_root();
        let next = RootKey::generate();
        let record = identity
            .rotate_root(next, unix_time_seconds())
            .expect("root rotation");

        let mut forged_bytes = record.to_bytes();
        forged_bytes[137] ^= 0x01;
        let forged = RotationRecord::from_bytes(&forged_bytes).expect("tampered record");
        assert!(
            identity
                .verify_rotation(trusted_root, &forged, unix_time_seconds())
                .is_err()
        );
        assert!(
            identity
                .verify_rotation([9u8; 32], &record, unix_time_seconds())
                .is_err()
        );

        let mut rewound_bytes = record.to_bytes();
        let future = unix_time_seconds() + 10_000;
        rewound_bytes[65..73].copy_from_slice(&future.to_le_bytes());
        let rewound = RotationRecord::from_bytes(&rewound_bytes).expect("rewound record");
        assert!(
            identity
                .verify_rotation(trusted_root, &rewound, unix_time_seconds())
                .is_err()
        );
    }

    #[test]
    fn bundle_round_trip_preserves_separated_roles() {
        let identity = Identity::generate().expect("identity");
        let encoded = identity.export_bundle_bytes().expect("bundle");
        let restored = Identity::import_bundle_bytes(&encoded).expect("restore");

        assert_eq!(restored.peer_id(), identity.peer_id());
        assert_eq!(restored.fingerprint(), identity.fingerprint());
        for role in IdentityRole::ALL {
            assert_eq!(
                restored.role_public_bytes(role).expect("role key"),
                identity.role_public_bytes(role).expect("role key")
            );
        }
    }

    #[test]
    fn debug_output_never_contains_private_keys() {
        let identity = Identity::generate().expect("identity generation");
        let debug = format!("{identity:?}");

        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(identity.peer_id().to_string().as_str()));
        assert!(debug.contains(identity.fingerprint().as_str()));

        for role in IdentityRole::ALL {
            let bytes = match role {
                IdentityRole::Transport => identity
                    .bundle
                    .transport()
                    .to_protobuf_encoding()
                    .expect("private key encoding"),
                _ => {
                    let key = identity.bundle.role_key(role).expect("role key").to_bytes();
                    key.to_vec()
                }
            };
            let hex: String = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("");
            assert!(!debug.contains(&hex), "debug exposed {role} key bytes");
        }
    }

    #[test]
    fn certified_role_keys_come_from_the_matching_certificate() {
        let identity = Identity::generate().expect("identity");
        let proof = identity.proof().to_bytes();
        let now = unix_time_seconds();

        for role in IdentityRole::WIRE_ROLES {
            let certified = certified_role_public_key(&proof, role, &identity.peer_id(), now)
                .expect("role key");
            assert_eq!(
                certified,
                identity.role_public_bytes(role).expect("local key")
            );
        }
        assert_ne!(
            certified_role_public_key(&proof, IdentityRole::Mls, &identity.peer_id(), now)
                .expect("mls key"),
            identity.ed25519_public_bytes().expect("transport key")
        );
    }

    #[test]
    fn expired_and_revoked_proofs_are_rejected_by_role_verification() {
        let mut identity = Identity::generate().expect("identity");
        let message = b"certified wire payload";
        let signature = identity
            .sign_with_role(IdentityRole::Application, message)
            .expect("application signature");
        let expired_at = identity
            .certificate(IdentityRole::Application)
            .expect("application certificate")
            .expires_at();

        assert!(matches!(
            certified_role_public_key(
                &identity.proof().to_bytes(),
                IdentityRole::Application,
                &identity.peer_id(),
                expired_at,
            ),
            Err(IdentityError::ExpiredCertificate)
        ));
        assert!(
            verify_application_signature(
                &identity.proof().to_bytes(),
                IdentityRole::Application,
                &identity.peer_id(),
                message,
                &signature,
                expired_at,
            )
            .is_err()
        );

        identity
            .revoke_role(IdentityRole::Application)
            .expect("revoke application role");
        assert!(identity.is_role_revoked(IdentityRole::Application));
        assert!(matches!(
            certified_role_public_key(
                &identity.proof().to_bytes(),
                IdentityRole::Application,
                &identity.peer_id(),
                unix_time_seconds(),
            ),
            Err(IdentityError::RevokedIdentity)
        ));
        assert!(identity.revoke_role(IdentityRole::Root).is_err());
    }

    #[test]
    fn substituted_proofs_and_transport_signatures_fail_role_verification() {
        let identity = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let message = b"certified wire payload";
        let signature = identity
            .sign_with_role(IdentityRole::Application, message)
            .expect("application signature");
        let now = unix_time_seconds();

        assert!(
            verify_application_signature(
                &other.proof().to_bytes(),
                IdentityRole::Application,
                &identity.peer_id(),
                message,
                &signature,
                now,
            )
            .is_err()
        );

        let transport_signature = identity.sign(message).expect("transport signature");
        assert!(
            verify_application_signature(
                &identity.proof().to_bytes(),
                IdentityRole::Application,
                &identity.peer_id(),
                message,
                &transport_signature,
                now,
            )
            .is_err()
        );
    }
}
