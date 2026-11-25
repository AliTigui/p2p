//! Thin wrappers around audited cryptographic primitives.
//!
//! This crate implements no primitive itself. It owns the framing and domain
//! separation rules used by local storage:
//!
//! - Argon2id derives a KEK from a password, never a data key.
//! - XChaCha20-Poly1305 wraps a random master key and encrypts values.
//! - HKDF-SHA256 derives independent subkeys for distinct purposes.
//! - HMAC-SHA256 creates blind indexes so lookup keys are not stored plainly.

#![forbid(unsafe_code)]

pub mod aead;
pub mod kdf;
pub mod subkeys;

pub use aead::{NONCE_LEN, TAG_LEN, decrypt_bytes, encrypt_bytes, unwrap_key, wrap_key};
pub use kdf::{ARGON2_ID_V1, Argon2Params, KEY_LEN, SALT_LEN, derive_kek};
pub use subkeys::{Purpose, Subkeys, blind_index, fresh_salt};

use thiserror::Error;

/// Errors from the crypto layer. Messages never include passwords, keys, or
/// plaintext.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("password cannot be empty")]
    EmptyPassword,
    #[error("KDF parameters are outside safe bounds")]
    UnsafeParams,
    #[error("salt has the wrong length")]
    InvalidSalt,
    #[error("ciphertext is too short or malformed")]
    InvalidCiphertext,
    #[error("authentication failed: wrong key, wrong AAD, or modified data")]
    AuthenticationFailed,
    #[error("cryptographic operation failed: {0}")]
    Operation(String),
    #[error("system randomness source failed")]
    Randomness,
}
