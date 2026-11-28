//! Versioned encrypted export/import of a local identity.
//!
//! The private key is wrapped with XChaCha20-Poly1305. The wrapping key comes
//! from Argon2id(password, random salt) with versioned parameters. All header
//! fields are authenticated as AAD, so downgrading the KDF cost or changing
//! the purpose string makes decryption fail instead of silently weakening it.

use std::fmt;

use aead::{Aead, Payload};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use libp2p_identity::Keypair;
use zeroize::Zeroizing;

use crate::{Identity, IdentityError, bundle::BUNDLE_MAGIC};

const MAGIC: &[u8] = b"P2PMSGR-IDENTITY-EXP";
const VERSION: u8 = 1;

/// Identifier stored in the envelope for the Argon2id KDF.
pub const KDF_ARGON2ID_V1: u8 = 1;
/// Default Argon2id memory cost in KiB (96 MiB).
pub const DEFAULT_M_COST: u32 = 96 * 1024;
/// Default Argon2id iteration count.
pub const DEFAULT_T_COST: u32 = 4;
/// Default Argon2id parallelism.
pub const DEFAULT_P_COST: u32 = 1;

/// Domain-separation string bound into the AEAD associated data.
pub const EXPORT_PURPOSE: &[u8] = b"p2p-messenger/identity-export/v1";
/// Maximum accepted exported identity envelope. Imports stop before header or
/// ciphertext parsing when a supplied file exceeds this bound.
pub const MAX_ENCRYPTED_IDENTITY_BYTES: usize = 128 * 1024;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

const OFFSET_VERSION: usize = MAGIC.len();
const OFFSET_KDF: usize = OFFSET_VERSION + 1;
const OFFSET_M_COST: usize = OFFSET_KDF + 1;
const OFFSET_T_COST: usize = OFFSET_M_COST + 4;
const OFFSET_P_COST: usize = OFFSET_T_COST + 4;
const OFFSET_SALT: usize = OFFSET_P_COST + 4;
const OFFSET_NONCE: usize = OFFSET_SALT + SALT_LEN;
const HEADER_LEN: usize = OFFSET_NONCE + NONCE_LEN;

// Bounds prevent a hostile envelope from requesting multi-gigabyte Argon2id
// allocations. They are upper limits for import, not the defaults we write.
const MIN_IMPORT_M_COST: u32 = 8 * 1024;
const MAX_IMPORT_M_COST: u32 = 512 * 1024;
const MAX_IMPORT_T_COST: u32 = 10;
const MAX_IMPORT_P_COST: u32 = 8;

/// A validated, password-encrypted identity export.
///
/// The bytes contain only public metadata plus authenticated ciphertext. They
/// are safe to back up or transfer, provided the password travels separately.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedIdentity(Vec<u8>);

impl EncryptedIdentity {
    /// Encrypt an identity with a new random salt and nonce.
    pub fn encrypt(identity: &Identity, password: &str) -> Result<Self, IdentityError> {
        if password.is_empty() {
            return Err(IdentityError::EmptyPassword);
        }
        let password = Zeroizing::new(password.to_owned());
        let plaintext = identity.export_bundle_bytes()?;

        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| IdentityError::Randomness)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| IdentityError::Randomness)?;

        let mut bytes = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(KDF_ARGON2ID_V1);
        bytes.extend_from_slice(&DEFAULT_M_COST.to_le_bytes());
        bytes.extend_from_slice(&DEFAULT_T_COST.to_le_bytes());
        bytes.extend_from_slice(&DEFAULT_P_COST.to_le_bytes());
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce);
        debug_assert_eq!(bytes.len(), HEADER_LEN);

        let key = derive_key(
            &password,
            &salt,
            DEFAULT_M_COST,
            DEFAULT_T_COST,
            DEFAULT_P_COST,
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|error| IdentityError::Crypto(error.to_string()))?;
        let associated_data = associated_data_for(&bytes);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|error| IdentityError::Crypto(error.to_string()))?;
        bytes.extend_from_slice(&ciphertext);

        Ok(Self(bytes))
    }

    /// Validate the envelope structure and KDF parameters without performing
    /// the expensive derivation or requiring a password.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, IdentityError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_ENCRYPTED_IDENTITY_BYTES {
            return Err(IdentityError::InvalidEnvelope(
                "envelope is too large".to_owned(),
            ));
        }
        if bytes.len() < HEADER_LEN + TAG_LEN || !bytes.starts_with(MAGIC) {
            return Err(IdentityError::InvalidEnvelope(
                "too short or wrong magic".to_owned(),
            ));
        }
        let version = bytes[OFFSET_VERSION];
        if version != VERSION {
            return Err(IdentityError::UnsupportedEnvelopeVersion(version));
        }
        let kdf = bytes[OFFSET_KDF];
        if kdf != KDF_ARGON2ID_V1 {
            return Err(IdentityError::UnsupportedKdf(kdf));
        }
        check_params(
            read_u32(&bytes, OFFSET_M_COST)?,
            read_u32(&bytes, OFFSET_T_COST)?,
            read_u32(&bytes, OFFSET_P_COST)?,
        )?;
        Ok(Self(bytes))
    }

    /// Envelope bytes for writing to disk or transferring to another device.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decrypt and import the identity. Wrong passwords and any modification
    /// of the header or ciphertext produce a single generic failure.
    pub fn decrypt(&self, password: &str) -> Result<Identity, IdentityError> {
        if password.is_empty() {
            return Err(IdentityError::EmptyPassword);
        }
        let password = Zeroizing::new(password.to_owned());

        let m_cost = read_u32(&self.0, OFFSET_M_COST)?;
        let t_cost = read_u32(&self.0, OFFSET_T_COST)?;
        let p_cost = read_u32(&self.0, OFFSET_P_COST)?;
        check_params(m_cost, t_cost, p_cost)?;

        let salt = &self.0[OFFSET_SALT..OFFSET_SALT + SALT_LEN];
        let nonce = XNonce::try_from(&self.0[OFFSET_NONCE..OFFSET_NONCE + NONCE_LEN])
            .map_err(|_| IdentityError::InvalidEnvelope("invalid nonce".to_owned()))?;
        let key = derive_key(&password, salt, m_cost, t_cost, p_cost)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|error| IdentityError::Crypto(error.to_string()))?;
        let associated_data = associated_data_for(&self.0);

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &self.0[HEADER_LEN..],
                        aad: &associated_data,
                    },
                )
                .map_err(|_| IdentityError::DecryptionFailed)?,
        );
        if plaintext.starts_with(BUNDLE_MAGIC) {
            Identity::import_bundle_bytes(&plaintext)
        } else {
            let keypair = Keypair::from_protobuf_encoding(&plaintext).map_err(|_| {
                IdentityError::InvalidEnvelope("private key decode failed".to_owned())
            })?;
            Identity::from_keypair(keypair)
        }
    }
}

impl fmt::Debug for EncryptedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedIdentity")
            .field("version", &self.0.get(OFFSET_VERSION))
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, IdentityError> {
    let slice: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| IdentityError::InvalidEnvelope("truncated header".to_owned()))?
        .try_into()
        .map_err(|_| IdentityError::InvalidEnvelope("truncated header".to_owned()))?;
    Ok(u32::from_le_bytes(slice))
}

fn check_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), IdentityError> {
    if !(MIN_IMPORT_M_COST..=MAX_IMPORT_M_COST).contains(&m_cost)
        || !(1..=MAX_IMPORT_T_COST).contains(&t_cost)
        || !(1..=MAX_IMPORT_P_COST).contains(&p_cost)
    {
        return Err(IdentityError::UnsafeKdfParams);
    }
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, IdentityError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|error| IdentityError::Crypto(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|error| IdentityError::Crypto(error.to_string()))?;
    Ok(key)
}

fn associated_data_for(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + p2p_core::APP_NAME.len() + EXPORT_PURPOSE.len());
    aad.extend_from_slice(&header[..HEADER_LEN]);
    aad.extend_from_slice(p2p_core::APP_NAME.as_bytes());
    aad.extend_from_slice(EXPORT_PURPOSE);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity::generate().expect("identity generation")
    }

    #[test]
    fn export_import_round_trip_preserves_identity() {
        let original = identity();
        let envelope =
            EncryptedIdentity::encrypt(&original, "correct horse battery staple").expect("encrypt");
        let validated = EncryptedIdentity::from_bytes(envelope.as_bytes()).expect("validate");

        assert_eq!(validated, envelope);
        let restored = validated
            .decrypt("correct horse battery staple")
            .expect("decrypt");
        assert_eq!(restored.peer_id(), original.peer_id());
        assert_eq!(restored.public_key(), original.public_key());
        assert_eq!(restored.fingerprint(), original.fingerprint());
        for role in crate::IdentityRole::ALL {
            assert_eq!(
                restored.role_public_bytes(role).expect("restored role key"),
                original.role_public_bytes(role).expect("original role key")
            );
        }
        assert_eq!(restored.proof(), original.proof());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let envelope = EncryptedIdentity::encrypt(&identity(), "right password").expect("encrypt");
        assert_eq!(
            envelope.decrypt("wrong password").expect_err("must fail"),
            IdentityError::DecryptionFailed
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let envelope = EncryptedIdentity::encrypt(&identity(), "password").expect("encrypt");
        let mut bytes = envelope.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let tampered = EncryptedIdentity::from_bytes(bytes).expect("still structurally valid");
        assert_eq!(
            tampered.decrypt("password").expect_err("must fail"),
            IdentityError::DecryptionFailed
        );
    }

    #[test]
    fn tampered_header_is_rejected_before_derivation() {
        let envelope = EncryptedIdentity::encrypt(&identity(), "password").expect("encrypt");
        let mut bytes = envelope.as_bytes().to_vec();
        bytes[OFFSET_KDF] ^= 0x01;
        assert_eq!(
            EncryptedIdentity::from_bytes(bytes).expect_err("must fail"),
            IdentityError::UnsupportedKdf(0)
        );

        let mut bytes = envelope.as_bytes().to_vec();
        bytes[OFFSET_VERSION] = 99;
        assert_eq!(
            EncryptedIdentity::from_bytes(bytes).expect_err("must fail"),
            IdentityError::UnsupportedEnvelopeVersion(99)
        );

        let mut bytes = envelope.as_bytes().to_vec();
        bytes[..MAGIC.len()].fill(0);
        assert!(matches!(
            EncryptedIdentity::from_bytes(bytes),
            Err(IdentityError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn hostile_argon2_parameters_are_rejected() {
        let envelope = EncryptedIdentity::encrypt(&identity(), "password").expect("encrypt");
        let mut bytes = envelope.as_bytes().to_vec();
        bytes[OFFSET_M_COST..OFFSET_M_COST + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            EncryptedIdentity::from_bytes(bytes).expect_err("must fail"),
            IdentityError::UnsafeKdfParams
        );
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let original = identity();
        let first = EncryptedIdentity::encrypt(&original, "password").expect("encrypt");
        let second = EncryptedIdentity::encrypt(&original, "password").expect("encrypt");

        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn empty_password_and_truncated_bytes_are_rejected() {
        let original = identity();
        assert_eq!(
            EncryptedIdentity::encrypt(&original, "").expect_err("must fail"),
            IdentityError::EmptyPassword
        );
        assert!(EncryptedIdentity::from_bytes(b"short").is_err());
    }

    #[test]
    fn envelope_size_is_capped_before_structure_parsing() {
        let oversized = vec![0u8; MAX_ENCRYPTED_IDENTITY_BYTES + 1];
        let message = match EncryptedIdentity::from_bytes(oversized) {
            Err(IdentityError::InvalidEnvelope(message)) => message,
            other => panic!("expected static invalid-envelope error, got {other:?}"),
        };
        assert!(message.contains("too large"));

        let at_limit = vec![0u8; MAX_ENCRYPTED_IDENTITY_BYTES];
        let message = match EncryptedIdentity::from_bytes(at_limit) {
            Err(IdentityError::InvalidEnvelope(message)) => message,
            other => panic!("expected static invalid-envelope error, got {other:?}"),
        };
        assert!(message.contains("too short or wrong magic"));
    }

    #[test]
    fn debug_output_does_not_dump_ciphertext() {
        let envelope = EncryptedIdentity::encrypt(&identity(), "password").expect("encrypt");
        let debug = format!("{envelope:?}");
        assert!(debug.contains("EncryptedIdentity"));
        assert!(!debug.contains(&format!("{:?}", envelope.as_bytes())));
    }
}
