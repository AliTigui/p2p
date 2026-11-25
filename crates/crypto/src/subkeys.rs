//! HKDF-SHA256 subkeys and HMAC blind indexes.

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, KEY_LEN, SALT_LEN};

/// Independent purposes derived from the master key. Adding a purpose requires
/// a new salt slot in the profile and a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Db,
    Attachments,
    Identity,
    SearchIndex,
    Backup,
    BlindIndex,
}

impl Purpose {
    pub const ALL: [Self; 6] = [
        Self::Db,
        Self::Attachments,
        Self::Identity,
        Self::SearchIndex,
        Self::Backup,
        Self::BlindIndex,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Db => "storage/db",
            Self::Attachments => "storage/attachments",
            Self::Identity => "storage/identity",
            Self::SearchIndex => "storage/search-index",
            Self::Backup => "storage/backup",
            Self::BlindIndex => "storage/blind-index",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Db => 0,
            Self::Attachments => 1,
            Self::Identity => 2,
            Self::SearchIndex => 3,
            Self::Backup => 4,
            Self::BlindIndex => 5,
        }
    }
}

/// A fresh per-purpose HKDF salt.
pub fn fresh_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Randomness)?;
    Ok(salt)
}

/// Per-installation subkeys derived from one random master key.
#[derive(Clone)]
pub struct Subkeys {
    master: Zeroizing<[u8; KEY_LEN]>,
    salts: [[u8; SALT_LEN]; Purpose::ALL.len()],
}

impl Subkeys {
    pub fn new(
        master: Zeroizing<[u8; KEY_LEN]>,
        salts: [[u8; SALT_LEN]; Purpose::ALL.len()],
    ) -> Self {
        Self { master, salts }
    }

    /// Derive the key for one purpose with HKDF-SHA256. The purpose name is
    /// included in `info`, and each purpose has its own random salt.
    pub fn derive(&self, purpose: Purpose) -> Zeroizing<[u8; KEY_LEN]> {
        let info = format!("p2p-messenger/v1/{}", purpose.as_str());
        let hkdf = Hkdf::<Sha256>::new(Some(&self.salts[purpose.index()]), &self.master[..]);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(info.as_bytes(), &mut key[..])
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }

    /// Deterministic blind index for a lookup value. The value itself is never
    /// stored in the database.
    pub fn blind_index(&self, value: &[u8]) -> [u8; 32] {
        blind_index(&self.derive(Purpose::BlindIndex), value)
    }

    /// Salts are public but returned as a fixed array for storage.
    pub fn salts(&self) -> &[[u8; SALT_LEN]; Purpose::ALL.len()] {
        &self.salts
    }
}

impl fmt::Debug for Subkeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subkeys")
            .field("master", &"<redacted>")
            .field("purposes", &Purpose::ALL.len())
            .finish()
    }
}

/// HMAC-SHA256 blind index under a dedicated subkey.
pub fn blind_index(key: &[u8; KEY_LEN], value: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subkeys() -> Subkeys {
        Subkeys::new(
            Zeroizing::new([5u8; KEY_LEN]),
            [[6u8; SALT_LEN]; Purpose::ALL.len()],
        )
    }

    #[test]
    fn purposes_produce_distinct_stable_keys() {
        let subkeys = subkeys();
        let db = subkeys.derive(Purpose::Db);
        let identity = subkeys.derive(Purpose::Identity);

        assert_ne!(&db[..], &identity[..]);
        assert_eq!(&db[..], &subkeys.derive(Purpose::Db)[..]);
    }

    #[test]
    fn blind_indexes_are_deterministic_and_key_separated() {
        let subkeys = subkeys();
        let first = subkeys.blind_index(b"alice@example.test");
        assert_eq!(first, subkeys.blind_index(b"alice@example.test"));
        assert_ne!(first, subkeys.blind_index(b"bob@example.test"));

        let other = blind_index(&[9u8; KEY_LEN], b"alice@example.test");
        assert_ne!(first, other);
    }

    #[test]
    fn debug_output_is_redacted() {
        let debug = format!("{:?}", subkeys());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("5, 5, 5"));
    }
}
