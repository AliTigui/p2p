//! Authenticated account-root rotation records.
//!
//! A rotation is signed by both the previous and the next root key. Contacts
//! that verified an earlier root can follow the signed chain to the current
//! root instead of treating a new key as an unrelated account.

use std::fmt;

use libp2p_identity::ed25519::Keypair;

use crate::IdentityError;

/// Rotation wire format implemented by this build.
pub const ROTATION_VERSION: u8 = 1;
const ROTATION_DOMAIN: &[u8] = b"p2p.identity.rotation/v1";
const ROOT_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const HEADER_LEN: usize = 1 + ROOT_KEY_LEN + ROOT_KEY_LEN + 8;
/// Fixed encoded size of one rotation record.
pub const ROTATION_BYTES: usize = HEADER_LEN + SIGNATURE_LEN * 2;

/// A mutually signed transition from one account root key to the next.
#[derive(Clone, PartialEq, Eq)]
pub struct RotationRecord {
    version: u8,
    previous_root: [u8; ROOT_KEY_LEN],
    next_root: [u8; ROOT_KEY_LEN],
    issued_at: u64,
    previous_signature: [u8; SIGNATURE_LEN],
    next_signature: [u8; SIGNATURE_LEN],
}

impl RotationRecord {
    /// Create a rotation record signed by both root keys.
    pub fn new(previous: &Keypair, next: &Keypair, issued_at: u64) -> Result<Self, IdentityError> {
        if previous.public().to_bytes() == next.public().to_bytes() {
            return Err(IdentityError::InvalidRotation(
                "rotation must change the root key".to_owned(),
            ));
        }
        let mut record = Self {
            version: ROTATION_VERSION,
            previous_root: previous.public().to_bytes(),
            next_root: next.public().to_bytes(),
            issued_at,
            previous_signature: [0; SIGNATURE_LEN],
            next_signature: [0; SIGNATURE_LEN],
        };
        let signing_bytes = record.signing_bytes();
        record.previous_signature = previous.sign(&signing_bytes).try_into().map_err(|_| {
            IdentityError::InvalidRotation("unexpected signature length".to_owned())
        })?;
        record.next_signature = next.sign(&signing_bytes).try_into().map_err(|_| {
            IdentityError::InvalidRotation("unexpected signature length".to_owned())
        })?;
        Ok(record)
    }

    /// Previous root public key.
    pub fn previous_root(&self) -> [u8; ROOT_KEY_LEN] {
        self.previous_root
    }

    /// Next root public key.
    pub fn next_root(&self) -> [u8; ROOT_KEY_LEN] {
        self.next_root
    }

    /// Rotation time in Unix seconds.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Verify both signatures and all structural fields.
    pub fn validate(&self, now: u64) -> Result<(), IdentityError> {
        if self.version != ROTATION_VERSION {
            return Err(IdentityError::InvalidRotation(
                "unsupported rotation version".to_owned(),
            ));
        }
        if now < self.issued_at {
            return Err(IdentityError::InvalidRotation(
                "rotation is not yet valid".to_owned(),
            ));
        }
        if self.previous_root == self.next_root {
            return Err(IdentityError::InvalidRotation(
                "rotation does not change the root key".to_owned(),
            ));
        }
        let signing_bytes = self.signing_bytes();
        if !verify_raw(
            &self.previous_root,
            &signing_bytes,
            &self.previous_signature,
        ) || !verify_raw(&self.next_root, &signing_bytes, &self.next_signature)
        {
            return Err(IdentityError::InvalidRotation(
                "rotation signature is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Fixed-size public encoding.
    pub fn to_bytes(&self) -> [u8; ROTATION_BYTES] {
        let mut bytes = [0u8; ROTATION_BYTES];
        bytes[0] = self.version;
        bytes[1..33].copy_from_slice(&self.previous_root);
        bytes[33..65].copy_from_slice(&self.next_root);
        bytes[65..73].copy_from_slice(&self.issued_at.to_le_bytes());
        bytes[73..137].copy_from_slice(&self.previous_signature);
        bytes[137..201].copy_from_slice(&self.next_signature);
        bytes
    }

    /// Parse a fixed-size rotation record. Parsing does not verify signatures.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != ROTATION_BYTES {
            return Err(IdentityError::InvalidRotation(
                "rotation has the wrong length".to_owned(),
            ));
        }
        let version = bytes[0];
        if version != ROTATION_VERSION {
            return Err(IdentityError::InvalidRotation(
                "unsupported rotation version".to_owned(),
            ));
        }
        let mut previous_root = [0u8; ROOT_KEY_LEN];
        previous_root.copy_from_slice(&bytes[1..33]);
        let mut next_root = [0u8; ROOT_KEY_LEN];
        next_root.copy_from_slice(&bytes[33..65]);
        let issued_at = u64::from_le_bytes(bytes[65..73].try_into().expect("fixed slice"));
        let mut previous_signature = [0u8; SIGNATURE_LEN];
        previous_signature.copy_from_slice(&bytes[73..137]);
        let mut next_signature = [0u8; SIGNATURE_LEN];
        next_signature.copy_from_slice(&bytes[137..201]);
        Ok(Self {
            version,
            previous_root,
            next_root,
            issued_at,
            previous_signature,
            next_signature,
        })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let encoded = self.to_bytes();
        let mut bytes = Vec::with_capacity(ROTATION_DOMAIN.len() + HEADER_LEN);
        bytes.extend_from_slice(ROTATION_DOMAIN);
        bytes.extend_from_slice(&encoded[..HEADER_LEN]);
        bytes
    }
}

fn verify_raw(public_key: &[u8; ROOT_KEY_LEN], message: &[u8], signature: &[u8]) -> bool {
    libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map(|key| key.verify(message, signature))
        .unwrap_or(false)
}

impl fmt::Debug for RotationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotationRecord")
            .field("previous_root", &crate::hex_short(&self.previous_root))
            .field("next_root", &crate::hex_short(&self.next_root))
            .field("issued_at", &self.issued_at)
            .field("signatures", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(_byte: u8) -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn rotation_round_trips_and_validates() {
        let old = key(1);
        let next = key(2);
        let record = RotationRecord::new(&old, &next, 1_000).expect("rotation");
        let decoded = RotationRecord::from_bytes(&record.to_bytes()).expect("decode");
        assert_eq!(decoded, record);
        decoded.validate(1_500).expect("valid rotation");
    }

    #[test]
    fn forged_rotation_is_rejected() {
        let old = key(1);
        let next = key(2);
        let attacker = key(7);
        let mut record = RotationRecord::new(&old, &next, 1_000).expect("rotation");

        record.next_root = attacker.public().to_bytes();
        assert!(record.validate(1_500).is_err());

        let forged = RotationRecord::new(&attacker, &next, 1_000).expect("forged record");
        assert!(forged.validate(1_500).is_ok());
        assert_ne!(forged.previous_root(), old.public().to_bytes());
    }

    #[test]
    fn stale_rotation_and_self_rotation_are_rejected() {
        let old = key(1);
        let next = key(2);
        let record = RotationRecord::new(&old, &next, 2_000).expect("rotation");
        assert!(record.validate(1_999).is_err());
        assert!(RotationRecord::new(&old, &old, 1_000).is_err());
    }

    #[test]
    fn debug_output_omits_signatures() {
        let record = RotationRecord::new(&key(1), &key(2), 1_000).expect("rotation");
        let debug = format!("{record:?}");
        let hex: String = record
            .previous_signature
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex));
    }
}
