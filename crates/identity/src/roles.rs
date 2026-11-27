//! Purpose-specific identity roles.
//!
//! A single account owns several independent Ed25519 keypairs. The role is
//! part of every signed certificate and wire envelope, so a signature made by
//! one role cannot be interpreted as a signature from another role.

use std::fmt;

/// Cryptographic roles in the local identity bundle.
///
/// The root key certifies the device key; the device key certifies the
/// transport, MLS, application, and file keys. Each role uses an independently
/// generated key. No role key is derived from another private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityRole {
    Root = 0,
    Device = 1,
    Transport = 2,
    Mls = 3,
    Application = 4,
    File = 5,
}

impl IdentityRole {
    /// All roles in canonical certificate order.
    pub const ALL: [Self; 6] = [
        Self::Root,
        Self::Device,
        Self::Transport,
        Self::Mls,
        Self::Application,
        Self::File,
    ];

    /// Roles whose private keys are used for application wire protocols.
    pub const WIRE_ROLES: [Self; 4] = [Self::Transport, Self::Mls, Self::Application, Self::File];

    /// Fixed wire code. Codes are never renumbered.
    pub fn code(self) -> u8 {
        match self {
            Self::Root => 0,
            Self::Device => 1,
            Self::Transport => 2,
            Self::Mls => 3,
            Self::Application => 4,
            Self::File => 5,
        }
    }

    /// Parse a fixed wire code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Root),
            1 => Some(Self::Device),
            2 => Some(Self::Transport),
            3 => Some(Self::Mls),
            4 => Some(Self::Application),
            5 => Some(Self::File),
            _ => None,
        }
    }

    /// Stable human-readable label for diagnostics. Never includes key data.
    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Device => "device",
            Self::Transport => "transport",
            Self::Mls => "mls",
            Self::Application => "application",
            Self::File => "file",
        }
    }

    /// Domain used when a role key signs application data.
    pub fn signing_domain(self) -> &'static [u8] {
        match self {
            Self::Root => b"p2p.identity.sign.root/v1",
            Self::Device => b"p2p.identity.sign.device/v1",
            Self::Transport => b"p2p.identity.sign.transport/v1",
            Self::Mls => b"p2p.identity.sign.mls/v1",
            Self::Application => b"p2p.identity.sign.application/v1",
            Self::File => b"p2p.identity.sign.file/v1",
        }
    }
}

impl fmt::Display for IdentityRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_codes_are_stable_and_complete() {
        assert_eq!(IdentityRole::ALL.len(), 6);
        for role in IdentityRole::ALL {
            assert_eq!(IdentityRole::from_code(role.code()), Some(role));
        }
        assert_eq!(IdentityRole::from_code(6), None);
    }

    #[test]
    fn signing_domains_are_distinct() {
        for (index, first) in IdentityRole::ALL.iter().enumerate() {
            for second in IdentityRole::ALL.iter().skip(index + 1) {
                assert_ne!(first.signing_domain(), second.signing_domain());
            }
        }
    }
}
