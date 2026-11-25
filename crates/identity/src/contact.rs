//! Versioned, public-only contact exchange payloads.
//!
//! URI shape: `p2pmsgr://contact/v1/<peerid>?pk=<base64url-public-key>`
//! with an optional `&name=<percent-encoded-display-name>`. The payload never
//! contains private key material, a central URL, or a discovery service.

use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libp2p_identity::{PeerId, PublicKey};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use qrcode::{QrCode, render::svg};

use crate::{Fingerprint, IdentityError};

/// Prefix of the v1 contact URI.
pub const CONTACT_PATH_PREFIX: &str = "p2pmsgr://contact/v1/";
/// Maximum accepted contact URI length. Parsing stops before PeerId, base64,
/// or percent-decoding work when a pasted URI exceeds this bound.
pub const MAX_CONTACT_URI_BYTES: usize = 2048;
const MAX_NAME_CHARS: usize = 64;
const MAX_PEER_PART_BYTES: usize = 128;
const MAX_QUERY_BYTES: usize = 1536;
const MAX_QUERY_KEY_BYTES: usize = 32;
const MAX_QUERY_VALUE_BYTES: usize = 1024;
const MAX_PUBLIC_KEY_FIELD_BYTES: usize = 128;

/// A contact's public identity, safe to show in a QR code or paste in chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPayload {
    pub peer_id: PeerId,
    pub public_key: PublicKey,
    pub display_name: Option<String>,
}

impl ContactPayload {
    /// Build a payload, checking that the public key actually derives the
    /// supplied PeerId. This prevents a QR code from claiming an identity it
    /// does not hold.
    pub fn new(
        peer_id: PeerId,
        public_key: PublicKey,
        display_name: Option<String>,
    ) -> Result<Self, IdentityError> {
        if peer_id != public_key.to_peer_id() {
            return Err(IdentityError::PeerIdMismatch);
        }
        if let Some(name) = &display_name {
            if name.trim().is_empty() {
                return Err(IdentityError::InvalidContactPayload(
                    "display name cannot be empty".to_owned(),
                ));
            }
            if name.chars().count() > MAX_NAME_CHARS {
                return Err(IdentityError::InvalidContactPayload(format!(
                    "display name cannot exceed {MAX_NAME_CHARS} characters"
                )));
            }
        }
        Ok(Self {
            peer_id,
            public_key,
            display_name,
        })
    }

    /// Encode as a versioned URI.
    pub fn encode(&self) -> String {
        let public_key = URL_SAFE_NO_PAD.encode(self.public_key.encode_protobuf());
        let mut uri = format!("{CONTACT_PATH_PREFIX}{}?pk={public_key}", self.peer_id);
        if let Some(name) = &self.display_name {
            let escaped: String = percent_encode(name.as_bytes(), NON_ALPHANUMERIC).collect();
            uri.push_str("&name=");
            uri.push_str(&escaped);
        }
        uri
    }

    /// Parse a URI produced by [`Self::encode`]. All size checks happen before
    /// PeerId parsing, base64 decoding, or percent-decoding.
    pub fn parse(input: &str) -> Result<Self, IdentityError> {
        let input = input.trim();
        if input.len() > MAX_CONTACT_URI_BYTES {
            return Err(IdentityError::InvalidContactPayload(
                "contact URI is too long".to_owned(),
            ));
        }
        let rest = input.strip_prefix(CONTACT_PATH_PREFIX).ok_or_else(|| {
            IdentityError::InvalidContactPayload("wrong or missing URI prefix".to_owned())
        })?;

        let (peer_part, query) = rest.split_once('?').ok_or_else(|| {
            IdentityError::InvalidContactPayload("missing query string".to_owned())
        })?;
        if peer_part.is_empty() || query.is_empty() {
            return Err(IdentityError::InvalidContactPayload(
                "missing PeerId or public key".to_owned(),
            ));
        }
        if peer_part.len() > MAX_PEER_PART_BYTES {
            return Err(IdentityError::InvalidContactPayload(
                "PeerId is too long".to_owned(),
            ));
        }
        if query.len() > MAX_QUERY_BYTES {
            return Err(IdentityError::InvalidContactPayload(
                "query string is too long".to_owned(),
            ));
        }
        let peer_id = PeerId::from_str(peer_part)
            .map_err(|_| IdentityError::InvalidContactPayload("PeerId is not valid".to_owned()))?;

        let mut encoded_key: Option<&str> = None;
        let mut display_name: Option<String> = None;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').ok_or_else(|| {
                IdentityError::InvalidContactPayload("bad query field".to_owned())
            })?;
            if key.is_empty() || key.len() > MAX_QUERY_KEY_BYTES {
                return Err(IdentityError::InvalidContactPayload(
                    "query field name is invalid".to_owned(),
                ));
            }
            if value.is_empty() {
                return Err(IdentityError::InvalidContactPayload(
                    "query values cannot be empty".to_owned(),
                ));
            }
            if value.len() > MAX_QUERY_VALUE_BYTES {
                return Err(IdentityError::InvalidContactPayload(
                    "query value is too long".to_owned(),
                ));
            }
            match key {
                "pk" => {
                    if value.len() > MAX_PUBLIC_KEY_FIELD_BYTES {
                        return Err(IdentityError::InvalidContactPayload(
                            "public key field is too long".to_owned(),
                        ));
                    }
                    if encoded_key.replace(value).is_some() {
                        return Err(IdentityError::InvalidContactPayload(
                            "duplicate public key".to_owned(),
                        ));
                    }
                }
                "name" => {
                    if display_name.is_some() {
                        return Err(IdentityError::InvalidContactPayload(
                            "duplicate display name".to_owned(),
                        ));
                    }
                    let decoded = percent_decode_str(value)
                        .decode_utf8()
                        .map_err(|_| {
                            IdentityError::InvalidContactPayload(
                                "display name is not valid UTF-8".to_owned(),
                            )
                        })?
                        .into_owned();
                    display_name = Some(decoded);
                }
                other => {
                    return Err(IdentityError::InvalidContactPayload(format!(
                        "unknown query field '{other}'"
                    )));
                }
            }
        }

        let encoded_key = encoded_key
            .ok_or_else(|| IdentityError::InvalidContactPayload("missing public key".to_owned()))?;
        let key_bytes = URL_SAFE_NO_PAD.decode(encoded_key).map_err(|_| {
            IdentityError::InvalidContactPayload("public key is not valid base64url".to_owned())
        })?;
        let public_key = PublicKey::try_decode_protobuf(&key_bytes).map_err(|_| {
            IdentityError::InvalidContactPayload("public key could not be decoded".to_owned())
        })?;

        Self::new(peer_id, public_key, display_name)
    }

    /// Fingerprint of the public key in this payload. Compare it out of band
    /// before marking a contact verified.
    pub fn fingerprint(&self) -> Result<Fingerprint, IdentityError> {
        Fingerprint::from_public_key(&self.public_key)
    }

    /// Render the URI as a standalone QR code in SVG format.
    pub fn to_qr_svg(&self) -> Result<String, IdentityError> {
        let code = QrCode::new(self.encode().as_bytes())
            .map_err(|error| IdentityError::Qr(error.to_string()))?;
        Ok(code.render::<svg::Color>().build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn sample() -> Identity {
        Identity::generate().expect("identity generation")
    }

    fn invalid_message(input: &str) -> String {
        match ContactPayload::parse(input) {
            Err(IdentityError::InvalidContactPayload(message)) => message,
            other => panic!("expected static invalid-payload error, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_without_name() {
        let identity = sample();
        let payload = ContactPayload::new(identity.peer_id(), identity.public_key().clone(), None)
            .expect("contact payload");

        let encoded = payload.encode();
        assert!(encoded.starts_with(CONTACT_PATH_PREFIX));
        assert!(!encoded.contains("name="));
        assert_eq!(ContactPayload::parse(&encoded).expect("parse"), payload);
        assert_eq!(
            payload.fingerprint().expect("fingerprint"),
            *identity.fingerprint()
        );
    }

    #[test]
    fn round_trip_with_unicode_name() {
        let identity = sample();
        let payload = ContactPayload::new(
            identity.peer_id(),
            identity.public_key().clone(),
            Some("Ada's phone 📱".to_owned()),
        )
        .expect("contact payload");

        let encoded = payload.encode();
        assert!(!encoded.contains('📱'));
        assert_eq!(ContactPayload::parse(&encoded).expect("parse"), payload);
    }

    #[test]
    fn rejects_mismatched_peer_id() {
        let identity = sample();
        let other = sample();
        assert_eq!(
            ContactPayload::new(other.peer_id(), identity.public_key().clone(), None),
            Err(IdentityError::PeerIdMismatch)
        );
    }

    #[test]
    fn rejects_tampered_public_key_and_unknown_fields() {
        let identity = sample();
        let encoded = ContactPayload::new(identity.peer_id(), identity.public_key().clone(), None)
            .expect("contact payload")
            .encode();

        let tampered = format!("{encoded}0");
        assert!(ContactPayload::parse(&tampered).is_err());
        assert!(ContactPayload::parse(&format!("{encoded}&relay=/dns4/evil")).is_err());
        assert!(ContactPayload::parse("p2pmsgr://contact/v2/abc?pk=AA").is_err());
    }

    #[test]
    fn qr_svg_is_real_svg_containing_no_private_material() {
        let identity = sample();
        let payload = ContactPayload::new(
            identity.peer_id(),
            identity.public_key().clone(),
            Some("Friend".to_owned()),
        )
        .expect("contact payload");
        let svg = payload.to_qr_svg().expect("qr svg");

        assert!(svg.starts_with("<?xml"));
        assert!(svg.contains("<svg"));
        let private = identity
            .keypair()
            .to_protobuf_encoding()
            .expect("private key encoding");
        let hex: String = private
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");
        assert!(!svg.contains(&hex));
    }

    #[test]
    fn contact_uri_size_is_capped_before_decoding() {
        let oversized = "x".repeat(MAX_CONTACT_URI_BYTES + 1);
        assert!(invalid_message(&oversized).contains("contact URI is too long"));

        let at_limit = "x".repeat(MAX_CONTACT_URI_BYTES);
        assert!(invalid_message(&at_limit).contains("wrong or missing URI prefix"));
    }

    #[test]
    fn contact_query_fields_are_capped_before_decoding() {
        let identity = sample();
        let encoded = ContactPayload::new(identity.peer_id(), identity.public_key().clone(), None)
            .expect("contact payload")
            .encode();

        let oversized_name = format!("{encoded}&name={}", "A".repeat(MAX_QUERY_VALUE_BYTES + 1));
        assert!(invalid_message(&oversized_name).contains("query value is too long"));

        let at_limit_name = format!("{encoded}&name={}", "A".repeat(MAX_QUERY_VALUE_BYTES));
        assert!(invalid_message(&at_limit_name).contains("display name cannot exceed"));

        let long_key = format!("{encoded}&{}=", "K".repeat(MAX_QUERY_KEY_BYTES + 1));
        assert!(invalid_message(&long_key).contains("query field name is invalid"));

        let long_public_key = format!(
            "{encoded}&pk={}",
            "A".repeat(MAX_PUBLIC_KEY_FIELD_BYTES + 1)
        );
        assert!(invalid_message(&long_public_key).contains("public key field is too long"));
    }
}
