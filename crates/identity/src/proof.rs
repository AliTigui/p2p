//! Public, wire-ready proof of an identity's role bindings.
//!
//! A proof contains only signed certificates and signed root-rotation records.
//! It is included in application envelopes so a receiver can verify that the
//! signing key used for a frame belongs to the expected role of the authenticated
//! transport peer.

use std::fmt;

use crate::{
    CERTIFICATE_BYTES, IdentityCertificate, IdentityError, IdentityRole, ROTATION_BYTES,
    RotationRecord, hex_short, unix_time_seconds,
};

const PROOF_MAGIC: &[u8] = b"P2PMSGR-IDENTITY-PROOF";
const PROOF_VERSION: u8 = 1;
const ROOT_KEY_LEN: usize = 32;
const MAX_ROTATIONS: usize = 8;
/// Fixed prefix length before the six encoded certificates.
pub const IDENTITY_PROOF_HEADER_BYTES: usize = PROOF_MAGIC.len() + 1 + ROOT_KEY_LEN;
/// Upper bound for one encoded identity proof.
pub const MAX_IDENTITY_PROOF_BYTES: usize = 4096;

/// Public certificates and rotation records for one account/device.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityProof {
    initial_root: [u8; ROOT_KEY_LEN],
    root: IdentityCertificate,
    device: IdentityCertificate,
    transport: IdentityCertificate,
    mls: IdentityCertificate,
    application: IdentityCertificate,
    file: IdentityCertificate,
    rotations: Vec<RotationRecord>,
}

impl IdentityProof {
    /// Assemble a proof from public certificates. Structural validation is
    /// performed by [`Self::validate_at`] and by callers that use the proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        initial_root: [u8; ROOT_KEY_LEN],
        root: IdentityCertificate,
        device: IdentityCertificate,
        transport: IdentityCertificate,
        mls: IdentityCertificate,
        application: IdentityCertificate,
        file: IdentityCertificate,
        rotations: Vec<RotationRecord>,
    ) -> Result<Self, IdentityError> {
        if rotations.len() > MAX_ROTATIONS {
            return Err(IdentityError::InvalidIdentityProof(
                "too many rotation records".to_owned(),
            ));
        }
        Ok(Self {
            initial_root,
            root,
            device,
            transport,
            mls,
            application,
            file,
            rotations,
        })
    }

    /// Root certificate for the current root key.
    pub fn root(&self) -> &IdentityCertificate {
        &self.root
    }

    /// Device certificate signed by the current root key.
    pub fn device(&self) -> &IdentityCertificate {
        &self.device
    }

    /// Certificate for one role.
    pub fn certificate(&self, role: IdentityRole) -> Option<&IdentityCertificate> {
        match role {
            IdentityRole::Root => Some(&self.root),
            IdentityRole::Device => Some(&self.device),
            IdentityRole::Transport => Some(&self.transport),
            IdentityRole::Mls => Some(&self.mls),
            IdentityRole::Application => Some(&self.application),
            IdentityRole::File => Some(&self.file),
        }
    }

    /// Signed rotation records, in chronological order.
    pub fn rotations(&self) -> &[RotationRecord] {
        &self.rotations
    }

    /// Public key certified for one role.
    pub fn role_public_key(&self, role: IdentityRole) -> Result<[u8; 32], IdentityError> {
        self.certificate(role)
            .map(IdentityCertificate::public_key)
            .ok_or(IdentityError::WrongRole)
    }

    /// Replace one certificate with a locally reissued version. Callers must
    /// revalidate the complete chain after updating a certificate.
    pub(crate) fn replace_certificate(&mut self, certificate: IdentityCertificate) {
        match certificate.role() {
            IdentityRole::Root => self.root = certificate,
            IdentityRole::Device => self.device = certificate,
            IdentityRole::Transport => self.transport = certificate,
            IdentityRole::Mls => self.mls = certificate,
            IdentityRole::Application => self.application = certificate,
            IdentityRole::File => self.file = certificate,
        }
    }

    /// Root key verified by the first contact verification.
    pub fn initial_root(&self) -> [u8; ROOT_KEY_LEN] {
        self.initial_root
    }

    /// Validate the complete certificate chain and rotation continuity at `now`.
    pub fn validate_at(&self, now: u64) -> Result<(), IdentityError> {
        let root_key = self.root.public_key();
        let device_key = self.device.public_key();

        self.root.validate_at(now, root_key)?;
        self.device.validate_at(now, root_key)?;

        let mut keys = vec![root_key, device_key];
        for role in IdentityRole::WIRE_ROLES {
            let certificate = self.certificate(role).ok_or_else(|| {
                IdentityError::InvalidIdentityProof("missing role certificate".to_owned())
            })?;
            if certificate.role() != role {
                return Err(IdentityError::InvalidIdentityProof(
                    "role certificate has the wrong role".to_owned(),
                ));
            }
            certificate.validate_at(now, device_key)?;
            keys.push(certificate.public_key());
        }

        for (index, first) in keys.iter().enumerate() {
            if keys.iter().skip(index + 1).any(|other| other == first) {
                return Err(IdentityError::InvalidIdentityProof(
                    "role keys must be independently generated".to_owned(),
                ));
            }
        }

        let device_id = self.device.device_id();
        if self.root.device_id() != device_id
            || self.transport.device_id() != device_id
            || self.mls.device_id() != device_id
            || self.application.device_id() != device_id
            || self.file.device_id() != device_id
        {
            return Err(IdentityError::InvalidIdentityProof(
                "certificates belong to different devices".to_owned(),
            ));
        }
        if self.device.issued_at() < self.root.issued_at() {
            return Err(IdentityError::InvalidIdentityProof(
                "device certificate precedes root certificate".to_owned(),
            ));
        }
        for role in IdentityRole::WIRE_ROLES {
            let certificate = self
                .certificate(role)
                .expect("wire role certificate exists");
            if certificate.issued_at() < self.device.issued_at() {
                return Err(IdentityError::InvalidIdentityProof(
                    "role certificate precedes device certificate".to_owned(),
                ));
            }
        }

        let mut expected_previous = self.initial_root;
        for rotation in &self.rotations {
            rotation.validate(now)?;
            if rotation.previous_root() != expected_previous {
                return Err(IdentityError::InvalidRotation(
                    "root rotation chain is not continuous".to_owned(),
                ));
            }
            expected_previous = rotation.next_root();
        }
        if expected_previous != root_key {
            return Err(IdentityError::InvalidRotation(
                "root rotation chain does not end at the current root".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate with the current system time.
    pub fn validate(&self) -> Result<(), IdentityError> {
        self.validate_at(unix_time_seconds())
    }

    /// Encode the public proof.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PROOF_MAGIC.len()
                + 1
                + ROOT_KEY_LEN
                + 6 * CERTIFICATE_BYTES
                + 1
                + self.rotations.len() * ROTATION_BYTES,
        );
        bytes.extend_from_slice(PROOF_MAGIC);
        bytes.push(PROOF_VERSION);
        bytes.extend_from_slice(&self.initial_root);
        for role in IdentityRole::ALL {
            let certificate = self
                .certificate(role)
                .expect("all roles are present in a complete proof");
            bytes.extend_from_slice(&certificate.to_bytes());
        }
        bytes.push(self.rotations.len() as u8);
        for rotation in &self.rotations {
            bytes.extend_from_slice(&rotation.to_bytes());
        }
        bytes
    }

    /// Parse and structurally validate an encoded proof. Signature, time, and
    /// chain validation remain separate so tests can use a deterministic clock.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_IDENTITY_PROOF_BYTES {
            return Err(IdentityError::InvalidIdentityProof(
                "identity proof is too large".to_owned(),
            ));
        }
        let header_len = PROOF_MAGIC.len() + 1 + ROOT_KEY_LEN + 6 * CERTIFICATE_BYTES;
        if bytes.len() < header_len + 1 {
            return Err(IdentityError::InvalidIdentityProof(
                "identity proof is truncated".to_owned(),
            ));
        }
        if !bytes.starts_with(PROOF_MAGIC) {
            return Err(IdentityError::InvalidIdentityProof(
                "identity proof has the wrong magic".to_owned(),
            ));
        }
        let version = bytes[PROOF_MAGIC.len()];
        if version != PROOF_VERSION {
            return Err(IdentityError::InvalidIdentityProof(
                "unsupported identity proof version".to_owned(),
            ));
        }
        let mut position = PROOF_MAGIC.len() + 1;
        let mut initial_root = [0u8; ROOT_KEY_LEN];
        initial_root.copy_from_slice(&bytes[position..position + ROOT_KEY_LEN]);
        position += ROOT_KEY_LEN;

        let mut certificates = Vec::with_capacity(6);
        for _ in 0..6 {
            let encoded = &bytes[position..position + CERTIFICATE_BYTES];
            certificates.push(IdentityCertificate::from_bytes(encoded)?);
            position += CERTIFICATE_BYTES;
        }
        let rotation_count = bytes[position] as usize;
        position += 1;
        if rotation_count > MAX_ROTATIONS {
            return Err(IdentityError::InvalidIdentityProof(
                "too many rotation records".to_owned(),
            ));
        }
        let expected_len = header_len + 1 + rotation_count * ROTATION_BYTES;
        if bytes.len() != expected_len {
            return Err(IdentityError::InvalidIdentityProof(
                "identity proof has trailing or missing bytes".to_owned(),
            ));
        }
        let mut rotations = Vec::with_capacity(rotation_count);
        for _ in 0..rotation_count {
            rotations.push(RotationRecord::from_bytes(
                &bytes[position..position + ROTATION_BYTES],
            )?);
            position += ROTATION_BYTES;
        }

        Self::new(
            initial_root,
            certificates[0].clone(),
            certificates[1].clone(),
            certificates[2].clone(),
            certificates[3].clone(),
            certificates[4].clone(),
            certificates[5].clone(),
            rotations,
        )
    }
}

impl fmt::Debug for IdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityProof")
            .field("version", &PROOF_VERSION)
            .field("initial_root", &hex_short(&self.initial_root))
            .field("current_root", &hex_short(&self.root.public_key()))
            .field("rotations", &self.rotations.len())
            .field("roles", &IdentityRole::ALL)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, unix_time_seconds};

    #[test]
    fn generated_proof_round_trips_and_validates() {
        let identity = Identity::generate().expect("identity");
        let proof = identity.proof().clone();
        let decoded = IdentityProof::from_bytes(&proof.to_bytes()).expect("decode");
        assert_eq!(decoded, proof);
        decoded
            .validate_at(unix_time_seconds())
            .expect("valid proof");
    }

    #[test]
    fn proof_rejects_role_key_reuse() {
        let mut proof = Identity::generate().expect("identity").proof().clone();
        let mls_key = proof.mls.public_key();
        proof.file = proof.mls.clone();
        let mut bytes = proof.to_bytes();
        // Decoded certificates are consistent but intentionally reuse a key.
        let decoded = IdentityProof::from_bytes(&bytes).expect("decode");
        assert!(decoded.validate_at(unix_time_seconds()).is_err());
        assert_eq!(
            decoded.file.public_key(),
            mls_key,
            "fixture intentionally reuses the key"
        );
        bytes.truncate(2);
        assert!(IdentityProof::from_bytes(&bytes).is_err());
    }
}
