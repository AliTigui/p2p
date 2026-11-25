//! XChaCha20-Poly1305 framing with random 24-byte nonces.
//!
//! Framed format: `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
//! Every encryption uses a fresh nonce. The AAD is supplied by the caller and
//! must bind version, purpose, and record identifiers.

use aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{CryptoError, KEY_LEN};

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypt bytes with a fresh random nonce. The nonce is prepended to the
/// returned ciphertext.
pub fn encrypt_bytes(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|error| CryptoError::Operation(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|error| CryptoError::Operation(error.to_string()))?;

    let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    framed.extend_from_slice(&nonce);
    framed.extend_from_slice(&ciphertext);
    Ok(framed)
}

/// Decrypt framed ciphertext. Wrong keys, wrong AAD, and modifications all
/// produce the same `AuthenticationFailed` error.
pub fn decrypt_bytes(
    key: &[u8; KEY_LEN],
    framed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if framed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce =
        XNonce::try_from(&framed[..NONCE_LEN]).map_err(|_| CryptoError::InvalidCiphertext)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|error| CryptoError::Operation(error.to_string()))?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &framed[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Wrap a 32-byte key under a key-encryption key.
pub fn wrap_key(
    key: &[u8; KEY_LEN],
    kek: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_bytes(kek, key, aad)
}

/// Unwrap a 32-byte key, rejecting any value that is not exactly one key.
pub fn unwrap_key(
    framed: &[u8],
    kek: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let plaintext = decrypt_bytes(kek, framed, aad)?;
    let key: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn round_trip_and_fresh_nonces() {
        let key = key(3);
        let first = encrypt_bytes(&key, b"secret message", b"aad").expect("encrypt");
        let second = encrypt_bytes(&key, b"secret message", b"aad").expect("encrypt");

        assert_ne!(first, second);
        assert_eq!(
            &decrypt_bytes(&key, &first, b"aad").expect("decrypt")[..],
            b"secret message"
        );
    }

    #[test]
    fn wrong_key_wrong_aad_and_truncation_fail() {
        let ciphertext = encrypt_bytes(&key(1), b"secret", b"right aad").expect("encrypt");

        assert_eq!(
            decrypt_bytes(&key(2), &ciphertext, b"right aad").expect_err("wrong key"),
            CryptoError::AuthenticationFailed
        );
        assert_eq!(
            decrypt_bytes(&key(1), &ciphertext, b"wrong aad").expect_err("wrong aad"),
            CryptoError::AuthenticationFailed
        );
        assert_eq!(
            decrypt_bytes(&key(1), &ciphertext[..NONCE_LEN], b"right aad").expect_err("truncated"),
            CryptoError::InvalidCiphertext
        );
    }

    #[test]
    fn wrap_key_requires_exactly_one_key() {
        let kek = key(9);
        let wrapped = wrap_key(&key(4), &kek, b"purpose").expect("wrap");
        let unwrapped = unwrap_key(&wrapped, &kek, b"purpose").expect("unwrap");
        assert_eq!(&unwrapped[..], &key(4));

        let too_short = encrypt_bytes(&kek, b"short", b"purpose").expect("encrypt");
        assert_eq!(
            unwrap_key(&too_short, &kek, b"purpose").expect_err("must fail"),
            CryptoError::InvalidCiphertext
        );
    }
}
