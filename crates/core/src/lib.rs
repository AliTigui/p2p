//! Shared, dependency-light types used across the P2P messenger workspace.
//!
//! This crate deliberately contains no networking or cryptographic code. It is
//! the stable bottom layer that every other crate may depend on.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Display name of the application.
pub const APP_NAME: &str = "P2P Messenger";
/// Current application version, taken from the crate manifest.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Version of the application-level wire protocol implemented by this build.
pub const PROTOCOL_VERSION: &str = "p2p-messenger/1";
const PROTOCOL_PREFIX: &str = "p2p-messenger/";

/// Non-secret information shown in the GUI and reported over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub protocol: String,
}

/// Return the non-secret metadata for this build.
pub fn app_info() -> AppInfo {
    AppInfo {
        name: APP_NAME.to_owned(),
        version: APP_VERSION.to_owned(),
        protocol: PROTOCOL_VERSION.to_owned(),
    }
}

/// Errors shared by crates that need typed protocol handling.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("protocol string must start with '{expected}', got '{actual}'")]
    InvalidProtocolPrefix { expected: String, actual: String },
    #[error("protocol version is not a valid unsigned integer")]
    InvalidProtocolNumber,
    #[error("unsupported protocol version {0}; supported version is 1")]
    UnsupportedProtocolVersion(u32),
}

/// Parse a protocol string of the form `p2p-messenger/<u32>`.
///
/// Unknown versions are rejected instead of being silently accepted, which
/// prevents accidental downgrade in later milestones.
pub fn parse_protocol_version(input: &str) -> Result<u32, CoreError> {
    let number =
        input
            .strip_prefix(PROTOCOL_PREFIX)
            .ok_or_else(|| CoreError::InvalidProtocolPrefix {
                expected: PROTOCOL_PREFIX.to_owned(),
                actual: input.to_owned(),
            })?;

    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CoreError::InvalidProtocolNumber);
    }

    let version: u32 = number
        .parse()
        .map_err(|_| CoreError::InvalidProtocolNumber)?;

    if version != 1 {
        return Err(CoreError::UnsupportedProtocolVersion(version));
    }

    Ok(version)
}

/// Whether `input` is a protocol string this build can speak.
pub fn is_supported_protocol(input: &str) -> bool {
    parse_protocol_version(input).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_is_supported() {
        assert_eq!(parse_protocol_version(PROTOCOL_VERSION), Ok(1));
        assert!(is_supported_protocol(PROTOCOL_VERSION));
    }

    #[test]
    fn app_info_carries_build_metadata() {
        let info = app_info();
        assert_eq!(info.name, APP_NAME);
        assert_eq!(info.version, APP_VERSION);
        assert_eq!(info.protocol, PROTOCOL_VERSION);
    }
}
