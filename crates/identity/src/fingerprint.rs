//! Stable Ed25519 fingerprint encoding and strict parsing.
//!
//! Format: `P2PMSGR-ED25519-` + lowercase base32(SHA-256(raw 32-byte Ed25519
//! public key)) split into groups of eight characters. Base32 without padding
//! of a 32-byte digest is 52 characters, so the canonical suffix has seven
//! groups (six groups of eight plus a final group of four).

use data_encoding::BASE32_NOPAD;
use libp2p_identity::PublicKey;
use sha2::{Digest, Sha256};

use crate::IdentityError;

/// Prefix that identifies this fingerprint format.
pub const FINGERPRINT_PREFIX: &str = "P2PMSGR-ED25519-";
const GROUP_LEN: usize = 8;
const ENCODED_LEN: usize = 52;

/// A parsed, canonically formatted fingerprint.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Compute the fingerprint from the raw 32-byte Ed25519 public key.
    pub fn from_ed25519_bytes(public_key: &[u8; 32]) -> Self {
        let digest = Sha256::digest(public_key);
        let encoded = BASE32_NOPAD.encode(&digest).to_ascii_lowercase();
        Self(format!("{FINGERPRINT_PREFIX}{}", group(&encoded)))
    }

    /// Compute the fingerprint from a libp2p public key.
    ///
    /// Non-Ed25519 keys are rejected so one fingerprint format always means
    /// one key algorithm.
    pub fn from_public_key(public_key: &PublicKey) -> Result<Self, IdentityError> {
        let ed25519 = public_key
            .clone()
            .try_into_ed25519()
            .map_err(|_| IdentityError::NotEd25519)?;
        Ok(Self::from_ed25519_bytes(&ed25519.to_bytes()))
    }

    /// Parse and canonicalize a fingerprint typed or pasted by a user.
    ///
    /// Hyphens and whitespace inside the suffix are accepted as separators so
    /// that copy/paste from different renderings works. The returned value is
    /// always in the canonical grouped form.
    pub fn parse(input: &str) -> Result<Self, IdentityError> {
        let raw = input.trim();
        let suffix = raw.strip_prefix(FINGERPRINT_PREFIX).ok_or_else(|| {
            IdentityError::InvalidFingerprint("wrong or missing prefix".to_owned())
        })?;

        let compact: String = suffix
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '-')
            .collect();

        if compact.len() != ENCODED_LEN {
            return Err(IdentityError::InvalidFingerprint(format!(
                "expected {ENCODED_LEN} base32 characters, got {}",
                compact.len()
            )));
        }
        if !compact
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(IdentityError::InvalidFingerprint(
                "suffix must be lowercase base32 (a-z, 2-7)".to_owned(),
            ));
        }

        let decoded = BASE32_NOPAD
            .decode(compact.to_ascii_uppercase().as_bytes())
            .map_err(|_| {
                IdentityError::InvalidFingerprint("suffix is not valid base32".to_owned())
            })?;
        if decoded.len() != 32 {
            return Err(IdentityError::InvalidFingerprint(
                "digest must be 32 bytes".to_owned(),
            ));
        }

        // Re-encode to guarantee a single canonical representation.
        Ok(Self(format!("{FINGERPRINT_PREFIX}{}", group(&compact))))
    }

    /// Full canonical string, suitable for display and comparison.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short first group for UI convenience. Never sufficient for trust
    /// decisions; callers must display and compare the full fingerprint.
    pub fn short(&self) -> &str {
        &self.0[FINGERPRINT_PREFIX.len()..FINGERPRINT_PREFIX.len() + GROUP_LEN]
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Fingerprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn group(encoded: &str) -> String {
    let mut grouped = String::with_capacity(encoded.len() + encoded.len() / GROUP_LEN);
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % GROUP_LEN == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn format_is_stable_and_grouped() {
        let fingerprint = Fingerprint::from_ed25519_bytes(&key(7));
        let suffix = fingerprint
            .as_str()
            .strip_prefix(FINGERPRINT_PREFIX)
            .expect("prefix");

        assert_eq!(suffix.len(), 58); // 52 characters + 6 separators
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&(c as u8)) || c == '-')
        );
        assert_eq!(suffix.split('-').count(), 7);
        assert!(suffix.split('-').take(6).all(|g| g.len() == GROUP_LEN));
        assert_eq!(suffix.split('-').next_back().expect("last group").len(), 4);
        assert_eq!(fingerprint.short().len(), GROUP_LEN);
        assert_eq!(Fingerprint::from_ed25519_bytes(&key(7)), fingerprint);
    }

    #[test]
    fn different_keys_have_different_fingerprints() {
        assert_ne!(
            Fingerprint::from_ed25519_bytes(&key(1)),
            Fingerprint::from_ed25519_bytes(&key(2))
        );
    }

    #[test]
    fn parse_accepts_spaces_and_canonicalizes() {
        let fingerprint = Fingerprint::from_ed25519_bytes(&key(9));
        let suffix = &fingerprint.as_str()[FINGERPRINT_PREFIX.len()..];
        let spaced = format!("{FINGERPRINT_PREFIX}{}", suffix.replace('-', " "));
        assert_eq!(Fingerprint::parse(&spaced).expect("parse"), fingerprint);
        assert_eq!(
            Fingerprint::parse(fingerprint.as_str()).expect("parse"),
            fingerprint
        );
    }

    #[test]
    fn parse_rejects_wrong_prefix_length_and_characters() {
        let fingerprint = Fingerprint::from_ed25519_bytes(&key(3)).to_string();

        assert!(Fingerprint::parse("ED25519-ABCD").is_err());
        assert!(Fingerprint::parse(&format!("P2PMSGR-RSA-{}", &fingerprint[16..])).is_err());
        assert!(Fingerprint::parse(&format!("{fingerprint}0")).is_err());
        let mut invalid = fingerprint.clone();
        let suffix_start = FINGERPRINT_PREFIX.len();
        invalid.replace_range(suffix_start..suffix_start + 1, "1");
        assert!(Fingerprint::parse(&invalid).is_err());
        assert!(Fingerprint::parse("").is_err());
    }

    #[test]
    fn uppercase_is_rejected_because_canonical_form_is_lowercase() {
        let fingerprint = Fingerprint::from_ed25519_bytes(&key(11)).to_string();
        assert!(Fingerprint::parse(&fingerprint.to_ascii_uppercase()).is_err());
    }
}
