//! Device-signed role delegations with explicit conflict handling.
//!
//! This is a local primitive, not a directory service. It lets one device key
//! delegate a wire role to an independently generated public key, and it fails
//! closed when two different grants claim the same counter. No grant is wired
//! into the GUI or into contact verification yet.

use std::fmt;

use crate::{Identity, IdentityError, IdentityRole, role_signing_bytes, verify_raw_signature};

const DELEGATION_MAGIC: &[u8] = b"P2PMSGR-ROLE-DELEGATION-V1";
const DELEGATION_VERSION: u8 = 1;
const DEVICE_ID_LEN: usize = 16;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const COUNTER_BYTES: usize = 8;
const TIME_BYTES: usize = 8;
const FIXED_BYTES: usize = DELEGATION_MAGIC.len()
    + 1
    + 1
    + DEVICE_ID_LEN
    + PUBLIC_KEY_LEN
    + COUNTER_BYTES
    + TIME_BYTES
    + TIME_BYTES
    + SIGNATURE_LEN;

/// A fixed-size, device-signed grant for one non-root wire role.
#[derive(Clone, PartialEq, Eq)]
pub struct RoleDelegation {
    role: IdentityRole,
    public_key: [u8; PUBLIC_KEY_LEN],
    device_id: [u8; DEVICE_ID_LEN],
    counter: u64,
    issued_at: u64,
    expires_at: u64,
    signature: [u8; SIGNATURE_LEN],
}

impl RoleDelegation {
    pub(crate) fn unsigned(
        role: IdentityRole,
        public_key: [u8; PUBLIC_KEY_LEN],
        device_id: [u8; DEVICE_ID_LEN],
        counter: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            role,
            public_key,
            device_id,
            counter,
            issued_at,
            expires_at,
            signature: [0; SIGNATURE_LEN],
        }
    }

    pub(crate) fn with_signature(mut self, signature: [u8; SIGNATURE_LEN]) -> Self {
        self.signature = signature;
        self
    }

    /// Exact bytes covered by the device-key signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_BYTES - SIGNATURE_LEN);
        bytes.extend_from_slice(DELEGATION_MAGIC);
        bytes.push(DELEGATION_VERSION);
        bytes.push(self.role.code());
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes
    }

    pub fn role(&self) -> IdentityRole {
        self.role
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != FIXED_BYTES {
            return Err(IdentityError::InvalidIdentityProof(
                "role delegation has an invalid length".to_owned(),
            ));
        }
        if &bytes[..DELEGATION_MAGIC.len()] != DELEGATION_MAGIC {
            return Err(IdentityError::InvalidIdentityProof(
                "role delegation has an invalid magic".to_owned(),
            ));
        }
        if bytes[DELEGATION_MAGIC.len()] != DELEGATION_VERSION {
            return Err(IdentityError::InvalidIdentityProof(
                "role delegation has an unsupported version".to_owned(),
            ));
        }
        let role = IdentityRole::from_code(bytes[DELEGATION_MAGIC.len() + 1]).ok_or_else(|| {
            IdentityError::InvalidIdentityProof("unknown delegation role".to_owned())
        })?;
        let mut cursor = DELEGATION_MAGIC.len() + 2;
        let mut device_id = [0; DEVICE_ID_LEN];
        device_id.copy_from_slice(&bytes[cursor..cursor + DEVICE_ID_LEN]);
        cursor += DEVICE_ID_LEN;
        let mut public_key = [0; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LEN]);
        cursor += PUBLIC_KEY_LEN;
        let counter = u64::from_le_bytes(
            bytes[cursor..cursor + COUNTER_BYTES]
                .try_into()
                .expect("fixed counter slice"),
        );
        cursor += COUNTER_BYTES;
        let issued_at = u64::from_le_bytes(
            bytes[cursor..cursor + TIME_BYTES]
                .try_into()
                .expect("fixed issue-time slice"),
        );
        cursor += TIME_BYTES;
        let expires_at = u64::from_le_bytes(
            bytes[cursor..cursor + TIME_BYTES]
                .try_into()
                .expect("fixed expiry slice"),
        );
        cursor += TIME_BYTES;
        let mut signature = [0; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LEN]);
        Ok(Self {
            role,
            public_key,
            device_id,
            counter,
            issued_at,
            expires_at,
            signature,
        })
    }

    /// Verify this grant against the device public key it claims to come from.
    pub fn validate_at(
        &self,
        expected_role: IdentityRole,
        expected_device_id: &[u8; DEVICE_ID_LEN],
        expected_device_public: &[u8; PUBLIC_KEY_LEN],
        now: u64,
    ) -> Result<(), IdentityError> {
        if !IdentityRole::WIRE_ROLES.contains(&self.role) || self.role != expected_role {
            return Err(IdentityError::WrongRole);
        }
        if self.counter == 0 {
            return Err(IdentityError::InvalidIdentityProof(
                "delegation counter must start at one".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(IdentityError::InvalidIdentityProof(
                "delegation validity window is empty".to_owned(),
            ));
        }
        if now > self.expires_at {
            return Err(IdentityError::ExpiredCertificate);
        }
        if &self.device_id != expected_device_id {
            return Err(IdentityError::InvalidIdentityProof(
                "delegation device id mismatch".to_owned(),
            ));
        }
        if !verify_raw_signature(
            expected_device_public,
            &role_signing_bytes(IdentityRole::Device, &self.signing_bytes()),
            &self.signature,
        )? {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }
}

impl fmt::Display for RoleDelegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} delegation counter {}",
            self.role.label(),
            self.counter
        )
    }
}

impl fmt::Debug for RoleDelegation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleDelegation")
            .field("role", &self.role)
            .field("device_id", &crate::hex_short(&self.device_id))
            .field(
                "public_fingerprint",
                &crate::Fingerprint::from_ed25519_bytes(&self.public_key),
            )
            .field("counter", &self.counter)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// Pick the highest valid counter for one role, rejecting two different keys
/// that claim the same counter. A duplicated identical grant is harmless.
pub fn resolve_delegated_grant(
    grants: &[RoleDelegation],
    role: IdentityRole,
    device_id: &[u8; DEVICE_ID_LEN],
    device_public: &[u8; PUBLIC_KEY_LEN],
    now: u64,
) -> Result<Option<RoleDelegation>, IdentityError> {
    let mut best: Option<&RoleDelegation> = None;
    for grant in grants {
        grant.validate_at(role, device_id, device_public, now)?;
        match best {
            None => best = Some(grant),
            Some(current) if grant.counter > current.counter => best = Some(grant),
            Some(current)
                if grant.counter == current.counter && grant.public_key != current.public_key =>
            {
                return Err(IdentityError::InvalidIdentityProof(
                    "conflicting role delegations at the same counter".to_owned(),
                ));
            }
            _ => {}
        }
    }
    Ok(best.cloned())
}

impl Identity {
    /// Create a device-signed delegation for one wire role. The delegated key
    /// is supplied by the caller and is never derived from another private key.
    pub fn delegate_role(
        &self,
        role: IdentityRole,
        public_key: [u8; PUBLIC_KEY_LEN],
        counter: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<RoleDelegation, IdentityError> {
        if !IdentityRole::WIRE_ROLES.contains(&role) {
            return Err(IdentityError::WrongRole);
        }
        let certificate = self.certificate(IdentityRole::Device).ok_or_else(|| {
            IdentityError::InvalidCertificate("missing device certificate".to_owned())
        })?;
        let unsigned = RoleDelegation::unsigned(
            role,
            public_key,
            certificate.device_id(),
            counter,
            issued_at,
            expires_at,
        );
        let signature = self
            .sign_with_role(IdentityRole::Device, &unsigned.signing_bytes())?
            .try_into()
            .map_err(|_| IdentityError::InvalidSignature)?;
        Ok(unsigned.with_signature(signature))
    }

    /// Resolve delegated grants against this identity's certified device key.
    pub fn resolve_delegated_grant(
        &self,
        grants: &[RoleDelegation],
        role: IdentityRole,
        now: u64,
    ) -> Result<Option<RoleDelegation>, IdentityError> {
        let certificate = self.certificate(IdentityRole::Device).ok_or_else(|| {
            IdentityError::InvalidCertificate("missing device certificate".to_owned())
        })?;
        resolve_delegated_grant(
            grants,
            role,
            &certificate.device_id(),
            &certificate.public_key(),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::ed25519;

    use super::*;
    use crate::unix_time_seconds;

    fn delegated_key(byte: u8) -> [u8; PUBLIC_KEY_LEN] {
        [byte; PUBLIC_KEY_LEN]
    }

    #[test]
    fn device_signed_delegation_round_trips_and_validates() {
        let identity = Identity::generate().expect("identity");
        let now = unix_time_seconds();
        let grant = identity
            .delegate_role(
                IdentityRole::Application,
                delegated_key(7),
                1,
                now,
                now + 3600,
            )
            .expect("delegation");
        let decoded = RoleDelegation::from_bytes(&grant.to_bytes()).expect("decode");
        assert_eq!(decoded, grant);
        assert_eq!(
            identity
                .resolve_delegated_grant(&[decoded], IdentityRole::Application, now)
                .expect("valid grant")
                .expect("one grant")
                .public_key(),
            &delegated_key(7)
        );
    }

    #[test]
    fn conflicting_delegations_at_one_counter_fail_closed() {
        let identity = Identity::generate().expect("identity");
        let now = unix_time_seconds();
        let first = identity
            .delegate_role(IdentityRole::File, delegated_key(1), 4, now, now + 3600)
            .expect("first delegation");
        let conflicting = identity
            .delegate_role(IdentityRole::File, delegated_key(2), 4, now, now + 3600)
            .expect("conflicting delegation");
        assert!(matches!(
            identity.resolve_delegated_grant(
                &[first, conflicting],
                IdentityRole::File,
                now
            ),
            Err(IdentityError::InvalidIdentityProof(reason))
                if reason.contains("same counter")
        ));
    }

    #[test]
    fn newer_delegation_supersedes_an_older_counter() {
        let identity = Identity::generate().expect("identity");
        let now = unix_time_seconds();
        let older = identity
            .delegate_role(IdentityRole::Mls, delegated_key(3), 1, now, now + 3600)
            .expect("older delegation");
        let newer = identity
            .delegate_role(IdentityRole::Mls, delegated_key(4), 2, now, now + 3600)
            .expect("newer delegation");
        let chosen = identity
            .resolve_delegated_grant(&[older, newer], IdentityRole::Mls, now)
            .expect("valid grants")
            .expect("one grant");
        assert_eq!(chosen.public_key(), &delegated_key(4));
    }

    #[test]
    fn wrong_issuer_wrong_device_or_tampered_grant_is_rejected() {
        let identity = Identity::generate().expect("identity");
        let other = Identity::generate().expect("other identity");
        let now = unix_time_seconds();
        let grant = identity
            .delegate_role(
                IdentityRole::Application,
                delegated_key(5),
                1,
                now,
                now + 3600,
            )
            .expect("delegation");

        assert!(
            other
                .resolve_delegated_grant(
                    std::slice::from_ref(&grant),
                    IdentityRole::Application,
                    now
                )
                .is_err()
        );

        let mut tampered = grant.to_bytes();
        let signature_start = tampered.len() - SIGNATURE_LEN;
        tampered[signature_start] ^= 0x01;
        let tampered = RoleDelegation::from_bytes(&tampered).expect("tampered grant");
        assert!(
            identity
                .resolve_delegated_grant(&[tampered], IdentityRole::Application, now)
                .is_err()
        );

        let mut truncated = grant.to_bytes();
        truncated.pop();
        assert!(RoleDelegation::from_bytes(&truncated).is_err());
    }

    #[test]
    fn expired_and_undelegatable_roles_are_rejected() {
        let identity = Identity::generate().expect("identity");
        let now = unix_time_seconds();
        let grant = identity
            .delegate_role(IdentityRole::File, delegated_key(6), 1, now, now + 60)
            .expect("delegation");
        assert!(matches!(
            identity.resolve_delegated_grant(&[grant], IdentityRole::File, now + 61),
            Err(IdentityError::ExpiredCertificate)
        ));
        assert_eq!(
            identity.delegate_role(IdentityRole::Root, delegated_key(8), 1, now, now + 60),
            Err(IdentityError::WrongRole)
        );
        assert_eq!(
            identity.delegate_role(IdentityRole::Device, delegated_key(9), 1, now, now + 60),
            Err(IdentityError::WrongRole)
        );
    }

    #[test]
    fn delegated_key_is_caller_supplied_and_not_derived() {
        let identity = Identity::generate().expect("identity");
        let generated = ed25519::Keypair::generate().public().to_bytes();
        let now = unix_time_seconds();
        let grant = identity
            .delegate_role(IdentityRole::File, generated, 1, now, now + 3600)
            .expect("delegation");
        assert_ne!(
            grant.public_key(),
            &identity
                .role_public_bytes(IdentityRole::File)
                .expect("file key")
        );
        assert_ne!(
            grant.public_key(),
            &identity
                .role_public_bytes(IdentityRole::Device)
                .expect("device key")
        );
    }

    #[test]
    fn delegation_debug_redacts_the_signature() {
        let identity = Identity::generate().expect("identity");
        let now = unix_time_seconds();
        let grant = identity
            .delegate_role(
                IdentityRole::Application,
                delegated_key(11),
                1,
                now,
                now + 3600,
            )
            .expect("delegation");
        let debug = format!("{grant:?}");
        assert!(debug.contains("signature: \"<redacted>\""));
        assert!(!debug.contains(&crate::hex_short(&grant.to_bytes())));
    }
}
