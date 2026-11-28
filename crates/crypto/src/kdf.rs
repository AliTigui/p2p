//! Argon2id password-to-KEK derivation with versioned, bounded parameters.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::CryptoError;

/// KDF identifier stored in envelopes. Changing it requires a migration.
pub const ARGON2_ID_V1: u8 = 1;
/// Length of all symmetric keys produced by this crate, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the per-profile Argon2id salt, in bytes.
pub const SALT_LEN: usize = 16;

// Import bounds. Without these, a damaged or hostile envelope could request a
// multi-gigabyte allocation before any password is checked.
const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 512 * 1024;
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 8;

/// Argon2id parameters stored alongside an encrypted envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Parameters used for newly created profiles: 96 MiB, t=4, p=1. This is
    /// a bounded local cost increase, not protection from a compromised
    /// endpoint that can read decrypted memory.
    pub const RECOMMENDED: Self = Self {
        memory_kib: 96 * 1024,
        iterations: 4,
        parallelism: 1,
    };

    /// Approximate password-guessing work. Parallelism is not included because
    /// it mostly trades wall-clock time against hardware concurrency.
    pub const fn work_factor(self) -> u64 {
        self.memory_kib as u64 * self.iterations as u64
    }

    /// Whether these parameters make password guessing cheaper than `other`.
    /// Used only to decide whether an unlock should rewrap at startup.
    pub const fn is_weaker_than(self, other: Self) -> bool {
        self.work_factor() < other.work_factor()
    }

    /// Reject parameters that are either invalid for Argon2id or capable of
    /// exhausting the machine during an unlock attempt.
    pub fn validate(self) -> Result<(), CryptoError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(1..=MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(CryptoError::UnsafeParams);
        }
        Ok(())
    }

    /// Stable little-endian representation for authenticated envelope headers.
    pub fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.iterations.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.parallelism.to_le_bytes());
        bytes
    }

    /// Parse a representation produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 12] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let params = Self {
            memory_kib: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            iterations: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            parallelism: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
        };
        params.validate()?;
        Ok(params)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

/// Derive a key-encryption key from a password. The result is suitable only
/// for wrapping a random master key, never for encrypting user data directly.
pub fn derive_kek(
    password: &str,
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSalt);
    }
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| CryptoError::Operation(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|error| CryptoError::Operation(error.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let salt = [7u8; SALT_LEN];
        let a = derive_kek("password", &salt, Argon2Params::RECOMMENDED).expect("derive");
        let b = derive_kek("password", &salt, Argon2Params::RECOMMENDED).expect("derive");
        assert_eq!(&a[..], &b[..]);

        assert_ne!(
            &a[..],
            &derive_kek("other password", &salt, Argon2Params::RECOMMENDED).expect("derive")[..]
        );
        assert_ne!(
            &a[..],
            &derive_kek("password", &[8u8; SALT_LEN], Argon2Params::RECOMMENDED).expect("derive")[..]
        );
    }

    #[test]
    fn work_factor_detects_weaker_stored_parameters() {
        let weak = Argon2Params {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 8,
        };
        assert!(weak.is_weaker_than(Argon2Params::RECOMMENDED));
        assert!(!Argon2Params::RECOMMENDED.is_weaker_than(weak));
        assert_eq!(Argon2Params::RECOMMENDED.work_factor(), 96 * 1024 * 4);
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert_eq!(
            derive_kek("", &[0u8; SALT_LEN], Argon2Params::RECOMMENDED),
            Err(CryptoError::EmptyPassword)
        );
        assert_eq!(
            derive_kek("password", &[0u8; 4], Argon2Params::RECOMMENDED),
            Err(CryptoError::InvalidSalt)
        );
        assert_eq!(
            derive_kek(
                "password",
                &[0u8; SALT_LEN],
                Argon2Params {
                    memory_kib: u32::MAX,
                    ..Argon2Params::RECOMMENDED
                }
            ),
            Err(CryptoError::UnsafeParams)
        );
    }
}
