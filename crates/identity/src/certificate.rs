//! Signed, purpose-specific identity certificates.
//!
//! Certificate bytes are canonical and fixed size. Every field except the
//! signature is covered by an Ed25519 signature from the issuing role. Certificates
//! carry only public data and are safe to include in a signed wire envelope.

use std::fmt;

use libp2p_identity::ed25519::{Keypair, PublicKey};

use crate::{Fingerprint, IdentityError, IdentityRole, unix_time_seconds};

/// Certificate wire format implemented by this build.
pub const CERTIFICATE_VERSION: u8 = 1;
/// Default validity window for newly issued certificates (30 days).
pub const DEFAULT_CERT_VALIDITY_SECONDS: u64 = 30 * 24 * 60 * 60;

const CERTIFICATE_DOMAIN: &[u8] = b"p2p.identity.certificate/v1";
const SERIAL_LEN: usize = 16;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const DEVICE_ID_LEN: usize = 16;
const HEADER_LEN: usize = 115;
/// Fixed encoded size of one certificate.
pub const CERTIFICATE_BYTES: usize = 115 + SIGNATURE_LEN;

/// A signed binding between an account role and one Ed25519 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityCertificate {
    version: u8,
    serial: [u8; SERIAL_LEN],
    role: IdentityRole,
    device_id: [u8; DEVICE_ID_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
    issued_at: u64,
    expires_at: u64,
    revoked: bool,
    issuer: [u8; PUBLIC_KEY_LEN],
    signature: [u8; SIGNATURE_LEN],
}

impl IdentityCertificate {
    /// Create a certificate and sign it with the issuing role's private key.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        role: IdentityRole,
        device_id: [u8; DEVICE_ID_LEN],
        public_key: [u8; PUBLIC_KEY_LEN],
        issued_at: u64,
        expires_at: u64,
        issuer: [u8; PUBLIC_KEY_LEN],
        issuer_key: &Keypair,
    ) -> Result<Self, IdentityError> {
        if issued_at > expires_at {
            return Err(IdentityError::InvalidCertificate(
                "certificate validity window is empty".to_owned(),
            ));
        }
        let mut serial = [0u8; SERIAL_LEN];
        getrandom::fill(&mut serial).map_err(|_| IdentityError::Randomness)?;
        let mut certificate = Self {
            version: CERTIFICATE_VERSION,
            serial,
            role,
            device_id,
            public_key,
            issued_at,
            expires_at,
            revoked: false,
            issuer,
            signature: [0; SIGNATURE_LEN],
        };
        certificate.signature = certificate.sign_with(issuer_key)?.try_into().map_err(|_| {
            IdentityError::InvalidCertificate("unexpected signature length".to_owned())
        })?;
        Ok(certificate)
    }

    /// Replacement certificate issued from an existing certificate template.
    /// Used for root rotation, where the certified key and issuer change but
    /// the device and validity structure remain linked.
    pub fn reissued_signed(
        template: &Self,
        public_key: [u8; PUBLIC_KEY_LEN],
        issuer: [u8; PUBLIC_KEY_LEN],
        issued_at: u64,
        expires_at: u64,
        issuer_key: &Keypair,
    ) -> Result<Self, IdentityError> {
        if issued_at > expires_at {
            return Err(IdentityError::InvalidCertificate(
                "certificate validity window is empty".to_owned(),
            ));
        }
        let mut certificate = Self {
            version: CERTIFICATE_VERSION,
            serial: template.serial,
            role: template.role,
            device_id: template.device_id,
            public_key,
            issued_at,
            expires_at,
            revoked: false,
            issuer,
            signature: [0; SIGNATURE_LEN],
        };
        certificate.signature = certificate.sign_with(issuer_key)?.try_into().map_err(|_| {
            IdentityError::InvalidCertificate("unexpected signature length".to_owned())
        })?;
        Ok(certificate)
    }

    /// Mark this certificate revoked and re-sign it with the issuing key.
    pub fn set_revoked(
        &mut self,
        revoked: bool,
        issuer_key: &Keypair,
    ) -> Result<(), IdentityError> {
        self.revoked = revoked;
        self.signature = self.sign_with(issuer_key)?.try_into().map_err(|_| {
            IdentityError::InvalidCertificate("unexpected signature length".to_owned())
        })?;
        Ok(())
    }

    /// Role bound by this certificate.
    pub fn role(&self) -> IdentityRole {
        self.role
    }

    /// Certified raw Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// Device identifier carried by the certificate.
    pub fn device_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.device_id
    }

    /// Issuer public key.
    pub fn issuer(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.issuer
    }

    /// Issuance time in Unix seconds.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Expiration time in Unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the certificate is marked revoked.
    pub fn revoked(&self) -> bool {
        self.revoked
    }

    /// Validate version, time window, issuer, and signature at `now`.
    pub fn validate_at(
        &self,
        now: u64,
        expected_issuer: [u8; PUBLIC_KEY_LEN],
    ) -> Result<(), IdentityError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(IdentityError::InvalidCertificate(
                "unsupported certificate version".to_owned(),
            ));
        }
        if now < self.issued_at {
            return Err(IdentityError::InvalidCertificate(
                "certificate is not yet valid".to_owned(),
            ));
        }
        if now >= self.expires_at {
            return Err(IdentityError::ExpiredCertificate);
        }
        if self.revoked {
            return Err(IdentityError::RevokedIdentity);
        }
        if self.issuer != expected_issuer {
            return Err(IdentityError::InvalidCertificate(
                "certificate issuer does not match its chain".to_owned(),
            ));
        }
        let public = PublicKey::try_from_bytes(&self.issuer)
            .map_err(|_| IdentityError::InvalidCertificate("invalid issuer key".to_owned()))?;
        if !public.verify(&self.signing_bytes(), &self.signature) {
            return Err(IdentityError::InvalidCertificate(
                "certificate signature is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate with the current system time.
    pub fn validate(&self, expected_issuer: [u8; PUBLIC_KEY_LEN]) -> Result<(), IdentityError> {
        self.validate_at(unix_time_seconds(), expected_issuer)
    }

    /// Fixed-size public encoding.
    pub fn to_bytes(&self) -> [u8; CERTIFICATE_BYTES] {
        let mut bytes = [0u8; CERTIFICATE_BYTES];
        bytes[0] = self.version;
        bytes[1..1 + SERIAL_LEN].copy_from_slice(&self.serial);
        bytes[17] = self.role.code();
        bytes[18..18 + DEVICE_ID_LEN].copy_from_slice(&self.device_id);
        bytes[34..34 + PUBLIC_KEY_LEN].copy_from_slice(&self.public_key);
        bytes[66..74].copy_from_slice(&self.issued_at.to_le_bytes());
        bytes[74..82].copy_from_slice(&self.expires_at.to_le_bytes());
        bytes[82] = u8::from(self.revoked);
        bytes[83..83 + PUBLIC_KEY_LEN].copy_from_slice(&self.issuer);
        bytes[HEADER_LEN..].copy_from_slice(&self.signature);
        bytes
    }

    /// Parse a fixed-size certificate. Parsing does not validate its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != CERTIFICATE_BYTES {
            return Err(IdentityError::InvalidCertificate(
                "certificate has the wrong length".to_owned(),
            ));
        }
        let version = bytes[0];
        if version != CERTIFICATE_VERSION {
            return Err(IdentityError::InvalidCertificate(
                "unsupported certificate version".to_owned(),
            ));
        }
        let role = IdentityRole::from_code(bytes[17]).ok_or_else(|| {
            IdentityError::InvalidCertificate("unknown certificate role".to_owned())
        })?;
        if bytes[82] > 1 {
            return Err(IdentityError::InvalidCertificate(
                "invalid revocation flag".to_owned(),
            ));
        }
        let mut serial = [0u8; SERIAL_LEN];
        serial.copy_from_slice(&bytes[1..1 + SERIAL_LEN]);
        let mut device_id = [0u8; DEVICE_ID_LEN];
        device_id.copy_from_slice(&bytes[18..18 + DEVICE_ID_LEN]);
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[34..34 + PUBLIC_KEY_LEN]);
        let issued_at = u64::from_le_bytes(bytes[66..74].try_into().expect("fixed slice"));
        let expires_at = u64::from_le_bytes(bytes[74..82].try_into().expect("fixed slice"));
        let mut issuer = [0u8; PUBLIC_KEY_LEN];
        issuer.copy_from_slice(&bytes[83..83 + PUBLIC_KEY_LEN]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[HEADER_LEN..]);
        Ok(Self {
            version,
            serial,
            role,
            device_id,
            public_key,
            issued_at,
            expires_at,
            revoked: bytes[82] == 1,
            issuer,
            signature,
        })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let encoded = self.to_bytes();
        let mut bytes = Vec::with_capacity(CERTIFICATE_DOMAIN.len() + HEADER_LEN);
        bytes.extend_from_slice(CERTIFICATE_DOMAIN);
        bytes.extend_from_slice(&encoded[..HEADER_LEN]);
        bytes
    }

    fn sign_with(&self, issuer_key: &Keypair) -> Result<Vec<u8>, IdentityError> {
        Ok(issuer_key.sign(&self.signing_bytes()))
    }
}

impl fmt::Debug for IdentityCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityCertificate")
            .field("role", &self.role)
            .field("device_id", &crate::hex_short(&self.device_id))
            .field(
                "public_fingerprint",
                &Fingerprint::from_ed25519_bytes(&self.public_key),
            )
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .field("signature", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(_byte: u8) -> Keypair {
        Keypair::generate()
    }

    fn cert(
        issuer: &Keypair,
        subject: &Keypair,
        role: IdentityRole,
        revoked: bool,
    ) -> IdentityCertificate {
        let mut certificate = IdentityCertificate::new_signed(
            role,
            [3u8; 16],
            subject.public().to_bytes(),
            1_000,
            2_000,
            issuer.public().to_bytes(),
            issuer,
        )
        .expect("certificate");
        if revoked {
            certificate
                .set_revoked(true, issuer)
                .expect("revocation signature");
        }
        certificate
    }

    #[test]
    fn valid_certificate_round_trips_and_verifies() {
        let issuer = key(1);
        let subject = key(2);
        let certificate = cert(&issuer, &subject, IdentityRole::File, false);
        let encoded = certificate.to_bytes();
        let decoded = IdentityCertificate::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, certificate);
        decoded
            .validate_at(1_500, issuer.public().to_bytes())
            .expect("valid certificate");
    }

    #[test]
    fn expired_and_not_yet_valid_certificates_are_rejected() {
        let issuer = key(1);
        let subject = key(2);
        let certificate = cert(&issuer, &subject, IdentityRole::Mls, false);
        assert!(matches!(
            certificate.validate_at(2_000, issuer.public().to_bytes()),
            Err(IdentityError::ExpiredCertificate)
        ));
        assert!(
            certificate
                .validate_at(999, issuer.public().to_bytes())
                .is_err()
        );
    }

    #[test]
    fn revoked_certificate_is_rejected() {
        let issuer = key(1);
        let subject = key(2);
        let certificate = cert(&issuer, &subject, IdentityRole::Application, true);
        assert_eq!(
            certificate.validate_at(1_500, issuer.public().to_bytes()),
            Err(IdentityError::RevokedIdentity)
        );
    }

    #[test]
    fn forged_signature_and_wrong_issuer_are_rejected() {
        let issuer = key(1);
        let attacker = key(9);
        let subject = key(2);
        let certificate = cert(&issuer, &subject, IdentityRole::Transport, false);
        assert!(
            certificate
                .validate_at(1_500, attacker.public().to_bytes())
                .is_err()
        );

        let mut tampered = certificate.clone();
        tampered.public_key = attacker.public().to_bytes();
        assert!(
            tampered
                .validate_at(1_500, issuer.public().to_bytes())
                .is_err()
        );
    }

    #[test]
    fn malformed_certificates_are_rejected_before_validation() {
        assert!(IdentityCertificate::from_bytes(&[]).is_err());
        let encoded = cert(&key(1), &key(2), IdentityRole::Root, false).to_bytes();
        let mut wrong_role = encoded;
        wrong_role[17] = 200;
        assert!(IdentityCertificate::from_bytes(&wrong_role).is_err());
        let mut wrong_flag = encoded;
        wrong_flag[82] = 2;
        assert!(IdentityCertificate::from_bytes(&wrong_flag).is_err());
    }

    #[test]
    fn debug_output_does_not_contain_signature_bytes() {
        let certificate = cert(&key(1), &key(2), IdentityRole::Root, false);
        let debug = format!("{certificate:?}");
        let hex: String = certificate
            .signature
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex));
    }
}
