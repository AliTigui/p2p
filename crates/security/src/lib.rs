//! Independent file scanning interface and release policy.
//!
//! This crate deliberately contains no scanner implementation. With no
//! independent scanner configured, the result is `Unavailable`, and a
//! quarantine release is denied. Integrity verification is not a malware scan.

#![forbid(unsafe_code)]

mod format;

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

pub use format::{FileFormat, validate_format};

/// Maximum base name accepted for a released file.
pub const MAX_RELEASE_NAME_BYTES: usize = 255;
/// Maximum plaintext accepted for a released file.
pub const MAX_RELEASE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum chunk count accepted for a released file.
pub const MAX_RELEASE_CHUNKS: u32 = 256;

/// Reject names that are unsafe as a user-visible base file name on any
/// supported desktop platform. Trailing dots/spaces and Windows device names
/// are rejected even on Unix so a name cannot become dangerous after export.
pub fn is_safe_file_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > MAX_RELEASE_NAME_BYTES
        || name == "."
        || name == ".."
        || name.starts_with(char::is_whitespace)
        || name.ends_with('.')
        || name.ends_with(' ')
        || name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    if let Some(number) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    {
        return number
            .parse::<u8>()
            .map_or(true, |value| !(1..=9).contains(&value));
    }
    true
}

/// Exact result categories an independent scanner may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResult {
    CleanNoThreatDetected,
    ThreatDetected,
    Unavailable,
    Failed,
    UnsupportedFormat,
}

impl ScanResult {
    /// Honest, user-facing text. It never says a file is safe.
    pub fn description(self) -> &'static str {
        match self {
            Self::CleanNoThreatDetected => "Independent scanner detected no threat",
            Self::ThreatDetected => "Independent scanner detected a threat",
            Self::Unavailable => "Scanning unavailable (no independent scanner configured)",
            Self::Failed => "Independent scanner failed",
            Self::UnsupportedFormat => "File format is unsupported or does not match its name",
        }
    }

    /// Only an explicit no-threat result from an independent scanner permits release.
    pub fn permits_release(self) -> bool {
        matches!(self, Self::CleanNoThreatDetected)
    }
}

/// Observable scan status for one transfer. `Unavailable` is the default for a
/// completed transfer until an independent scanner actually returns a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    NotApplicable,
    Unavailable,
    CleanNoThreatDetected,
    ThreatDetected,
    Failed,
    UnsupportedFormat,
}

impl ScanStatus {
    pub fn description(self) -> &'static str {
        match self {
            Self::NotApplicable => "No independent scanner result",
            other => ScanResult::from(other).description(),
        }
    }

    pub fn result(self) -> Option<ScanResult> {
        match self {
            Self::NotApplicable => None,
            Self::Unavailable => Some(ScanResult::Unavailable),
            Self::CleanNoThreatDetected => Some(ScanResult::CleanNoThreatDetected),
            Self::ThreatDetected => Some(ScanResult::ThreatDetected),
            Self::Failed => Some(ScanResult::Failed),
            Self::UnsupportedFormat => Some(ScanResult::UnsupportedFormat),
        }
    }

    pub fn permits_release(self) -> bool {
        self.result().is_some_and(ScanResult::permits_release)
    }
}

impl From<ScanResult> for ScanStatus {
    fn from(result: ScanResult) -> Self {
        match result {
            ScanResult::CleanNoThreatDetected => Self::CleanNoThreatDetected,
            ScanResult::ThreatDetected => Self::ThreatDetected,
            ScanResult::Unavailable => Self::Unavailable,
            ScanResult::Failed => Self::Failed,
            ScanResult::UnsupportedFormat => Self::UnsupportedFormat,
        }
    }
}

impl From<ScanStatus> for ScanResult {
    fn from(status: ScanStatus) -> Self {
        status
            .result()
            .expect("NotApplicable has no independent scanner result")
    }
}

/// A scanner result that can only be produced by [`SecurityConfig::scan`].
///
/// The private field prevents an application from fabricating a
/// `CleanNoThreatDetected` result without calling a [`FileScanner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOutcome {
    status: ScanStatus,
    format: Option<FileFormat>,
}

impl ScanOutcome {
    fn new(status: ScanStatus, format: Option<FileFormat>) -> Self {
        Self { status, format }
    }

    pub fn status(self) -> ScanStatus {
        self.status
    }

    /// The format that passed structural validation, if any. A clean scanner
    /// result without a validated format is never sufficient for release.
    pub fn format(self) -> Option<FileFormat> {
        self.format
    }

    pub fn result(self) -> Option<ScanResult> {
        self.status.result()
    }

    pub fn permits_release(self) -> bool {
        self.status.permits_release()
    }
}

impl From<ScanOutcome> for ScanStatus {
    fn from(outcome: ScanOutcome) -> Self {
        outcome.status
    }
}

/// Bounded, in-memory input to an independent scanner.
///
/// No bytes are written to disk by this interface. The scanner implementation
/// is responsible for not retaining or persisting the supplied bytes.
#[derive(Clone, Copy)]
pub struct ScanRequest<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

impl fmt::Debug for ScanRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanRequest")
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// An independent scanner supplied by the application.
///
/// Implementations must return one of the exact [`ScanResult`] categories and
/// must not claim safety themselves. No scanner is configured by the core
/// application; a test or future user-configured adapter may implement this.
pub trait FileScanner: Send + Sync {
    fn scan(&self, request: &ScanRequest<'_>) -> ScanResult;
}

/// Default scanner: reports `Unavailable` without inspecting any bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScanner;

impl FileScanner for NoScanner {
    fn scan(&self, _request: &ScanRequest<'_>) -> ScanResult {
        ScanResult::Unavailable
    }
}

/// Static reasons a quarantine release may be denied. No file bytes or paths
/// are included in errors or diagnostics.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRejection {
    #[error("independent scanner did not report no threat detected")]
    ScanNotClean,
    #[error("file name is empty or contains a path component")]
    InvalidName,
    #[error("file is empty or too large")]
    InvalidSize,
    #[error("file has too many chunks")]
    TooManyChunks,
    #[error("file extension is not allowed by release policy")]
    ExtensionNotAllowed,
    #[error("file format was not structurally validated")]
    FormatNotValidated,
}

impl ReleaseRejection {
    pub fn description(self) -> &'static str {
        match self {
            Self::ScanNotClean => "Release denied: no clean independent scanner result",
            Self::InvalidName => "Release denied: invalid file name",
            Self::InvalidSize => "Release denied: invalid file size",
            Self::TooManyChunks => "Release denied: too many chunks",
            Self::ExtensionNotAllowed => "Release denied: file extension not allowed",
            Self::FormatNotValidated => "Release denied: file format was not validated",
        }
    }
}

/// Conservative release policy. An empty `allowed_extensions` list denies all
/// releases; this is intentional until an application explicitly configures it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    pub max_bytes: u64,
    pub allowed_extensions: Vec<String>,
}

impl Default for ReleasePolicy {
    fn default() -> Self {
        Self {
            max_bytes: MAX_RELEASE_BYTES,
            allowed_extensions: Vec::new(),
        }
    }
}

impl ReleasePolicy {
    pub fn new(max_bytes: u64, allowed_extensions: Vec<String>) -> Self {
        Self {
            max_bytes: max_bytes.min(MAX_RELEASE_BYTES),
            allowed_extensions,
        }
    }

    /// Evaluate a release request. A clean scanner result, a safe name and
    /// size, an allowed extension, and a validated content format are all
    /// required. Extension checking alone is never treated as format
    /// validation.
    pub fn evaluate(
        &self,
        name: &str,
        size: u64,
        chunk_count: u32,
        scan: ScanStatus,
        format: Option<FileFormat>,
    ) -> Result<(), ReleaseRejection> {
        if !scan.permits_release() {
            return Err(ReleaseRejection::ScanNotClean);
        }
        if !is_safe_file_name(name) {
            return Err(ReleaseRejection::InvalidName);
        }
        if size == 0 || size > self.max_bytes.min(MAX_RELEASE_BYTES) {
            return Err(ReleaseRejection::InvalidSize);
        }
        if chunk_count == 0 || chunk_count > MAX_RELEASE_CHUNKS {
            return Err(ReleaseRejection::TooManyChunks);
        }
        let extension = name.rsplit_once('.').map(|(_, value)| value);
        if extension.is_none_or(|value| value.is_empty())
            || !self.allowed_extensions.iter().any(|allowed| {
                allowed.eq_ignore_ascii_case(extension.expect("extension is present"))
            })
        {
            return Err(ReleaseRejection::ExtensionNotAllowed);
        }
        if format.is_none() {
            return Err(ReleaseRejection::FormatNotValidated);
        }
        Ok(())
    }
}

/// Scanner and release policy attached to one controller. The default has no
/// scanner and denies every extension, so release is unavailable by default.
#[derive(Clone, Default)]
pub struct SecurityConfig {
    scanner: Option<Arc<dyn FileScanner>>,
    release_policy: ReleasePolicy,
}

impl SecurityConfig {
    pub fn new(scanner: Option<Arc<dyn FileScanner>>, release_policy: ReleasePolicy) -> Self {
        Self {
            scanner,
            release_policy,
        }
    }

    pub fn with_scanner<S: FileScanner + 'static>(mut self, scanner: S) -> Self {
        self.scanner = Some(Arc::new(scanner));
        self
    }

    pub fn with_release_policy(mut self, release_policy: ReleasePolicy) -> Self {
        self.release_policy = release_policy;
        self
    }

    pub fn scanner(&self) -> Option<&dyn FileScanner> {
        self.scanner.as_deref()
    }

    pub fn release_policy(&self) -> &ReleasePolicy {
        &self.release_policy
    }

    /// Structurally validate the claimed format, then invoke the configured
    /// independent scanner, or report `Unavailable` when none is configured.
    /// A format mismatch short-circuits to `UnsupportedFormat` before any
    /// scanner sees the bytes. Only this method can create a [`ScanOutcome`].
    pub fn scan(&self, request: &ScanRequest<'_>) -> ScanOutcome {
        let Some(format) = validate_format(request.name, request.bytes) else {
            return ScanOutcome::new(ScanStatus::UnsupportedFormat, None);
        };
        let result = self
            .scanner
            .as_deref()
            .map(|scanner| scanner.scan(request))
            .unwrap_or(ScanResult::Unavailable);
        ScanOutcome::new(ScanStatus::from(result), Some(format))
    }
}

impl fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field(
                "scanner",
                &if self.scanner.is_some() {
                    "configured"
                } else {
                    "none"
                },
            )
            .field("release_policy", &self.release_policy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scanner_reports_unavailable() {
        let bytes = [1u8, 2, 3];
        let result = NoScanner.scan(&ScanRequest {
            name: "report.bin",
            bytes: &bytes,
        });
        assert_eq!(result, ScanResult::Unavailable);
        assert!(!ScanStatus::from(result).permits_release());
    }

    #[test]
    fn release_policy_requires_clean_result_format_and_allowed_extension() {
        let policy = ReleasePolicy::new(1024, vec!["txt".to_owned()]);
        assert_eq!(
            policy.evaluate(
                "report.txt",
                128,
                1,
                ScanStatus::Unavailable,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::ScanNotClean)
        );
        assert_eq!(
            policy.evaluate(
                "report.txt",
                128,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Ok(())
        );
        assert_eq!(
            policy.evaluate(
                "report.bin",
                128,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::ExtensionNotAllowed)
        );
        assert_eq!(
            policy.evaluate(
                "../report.txt",
                128,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::InvalidName)
        );
        assert_eq!(
            policy.evaluate(
                "report.txt",
                2048,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::InvalidSize)
        );
        assert_eq!(
            policy.evaluate(
                "report.txt",
                128,
                257,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::TooManyChunks)
        );
        assert_eq!(
            policy.evaluate(
                "report.txt",
                128,
                1,
                ScanStatus::CleanNoThreatDetected,
                None
            ),
            Err(ReleaseRejection::FormatNotValidated)
        );
    }

    #[test]
    fn default_config_denies_every_release() {
        let config = SecurityConfig::default();
        assert!(config.scanner().is_none());
        assert!(config.release_policy().allowed_extensions.is_empty());
        assert_eq!(
            config.release_policy().evaluate(
                "report.txt",
                128,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::ExtensionNotAllowed)
        );
    }

    #[test]
    fn scan_status_text_never_claims_safety() {
        for status in [
            ScanStatus::NotApplicable,
            ScanStatus::Unavailable,
            ScanStatus::CleanNoThreatDetected,
            ScanStatus::ThreatDetected,
            ScanStatus::Failed,
            ScanStatus::UnsupportedFormat,
        ] {
            let text = status.description().to_ascii_lowercase();
            assert!(!text.contains("safe"), "{text}");
            assert!(!text.contains("clean"), "{text}");
        }
    }

    struct FixedScanner(ScanResult);

    impl FileScanner for FixedScanner {
        fn scan(&self, _request: &ScanRequest<'_>) -> ScanResult {
            self.0
        }
    }

    #[test]
    fn only_config_scan_creates_an_outcome() {
        let bytes = b"valid text".to_vec();
        let request = ScanRequest {
            name: "report.txt",
            bytes: &bytes,
        };
        let clean =
            SecurityConfig::default().with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected));
        let outcome = clean.scan(&request);
        assert_eq!(outcome.status(), ScanStatus::CleanNoThreatDetected);
        assert_eq!(outcome.result(), Some(ScanResult::CleanNoThreatDetected));
        assert_eq!(outcome.format(), Some(FileFormat::Text));
        assert!(outcome.permits_release());

        let unavailable = SecurityConfig::default().scan(&request);
        assert_eq!(unavailable.status(), ScanStatus::Unavailable);
        assert_eq!(unavailable.format(), Some(FileFormat::Text));
        assert!(!unavailable.permits_release());
    }

    #[test]
    fn format_mismatch_blocks_scanner_and_release() {
        let bytes = b"not a png".to_vec();
        let request = ScanRequest {
            name: "report.png",
            bytes: &bytes,
        };
        let config =
            SecurityConfig::default().with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected));
        let outcome = config.scan(&request);
        assert_eq!(outcome.status(), ScanStatus::UnsupportedFormat);
        assert_eq!(outcome.format(), None);
        assert!(!outcome.permits_release());
        assert_eq!(
            config.release_policy().evaluate(
                "report.png",
                bytes.len() as u64,
                1,
                outcome.status(),
                outcome.format()
            ),
            Err(ReleaseRejection::ScanNotClean)
        );
    }

    #[test]
    fn unsafe_export_names_are_rejected() {
        for name in [
            "CON",
            "con.txt",
            "PRN.log",
            "COM1",
            "lpt9.txt",
            "report.txt.",
            "report.txt ",
            " bad.txt",
            "C:report.txt",
            "",
            ".",
            "..",
        ] {
            assert!(!is_safe_file_name(name), "{name}");
        }
        for name in ["report.txt", "COM0.txt", "notes-2026.txt", "résumé.txt"] {
            assert!(is_safe_file_name(name), "{name}");
        }
    }

    #[test]
    fn release_policy_cannot_exceed_the_hard_byte_cap() {
        let policy = ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]);
        assert_eq!(policy.max_bytes, MAX_RELEASE_BYTES);
        assert_eq!(
            policy.evaluate(
                "report.txt",
                MAX_RELEASE_BYTES + 1,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::InvalidSize)
        );

        let mutated = ReleasePolicy {
            max_bytes: u64::MAX,
            ..policy
        };
        assert_eq!(
            mutated.evaluate(
                "report.txt",
                MAX_RELEASE_BYTES + 1,
                1,
                ScanStatus::CleanNoThreatDetected,
                Some(FileFormat::Text)
            ),
            Err(ReleaseRejection::InvalidSize)
        );
    }
}
