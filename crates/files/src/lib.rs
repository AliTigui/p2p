//! Encrypted chunk transfer for the P2P messenger.
//!
//! This crate owns the application-level file frames, chunk encryption,
//! integrity checking, ciphertext-only quarantine, and policy-gated release.
//! It never invents a scanner result: without an independent scanner supplied
//! by the application, an integrity-verified transfer remains `Unavailable`
//! and cannot be released.
//!
//! File bytes are encrypted with a fresh per-transfer XChaCha20-Poly1305 key.
//! The key is carried only in the signed offer over the already
//! Noise-authenticated connection and is never written to quarantine. Each
//! chunk has a bounded plaintext size and bound AAD; a final signed manifest
//! commits to every chunk hash and to the full SHA-256 digest.

#![forbid(unsafe_code)]

mod frame;
mod transfer;

use std::fmt;
use std::path::PathBuf;

pub use frame::{
    FILE_MAGIC, FILE_PROTOCOL, FILE_VERSION, FileEnvelope, FileMessage, MAX_CHUNK_PLAINTEXT_BYTES,
    MAX_FILE_FRAME_BYTES, MAX_FILE_NAME_BYTES, MAX_TRANSFER_BYTES,
};
pub use p2p_security::{
    FileFormat, MAX_RELEASE_BYTES, MAX_RELEASE_CHUNKS, MAX_RELEASE_NAME_BYTES, ReleasePolicy,
    ReleaseRejection, ScanRequest, ScanResult, ScanStatus,
};
use thiserror::Error;
pub use transfer::{IncomingFile, OutgoingFile, ReleasedFile, VerificationResult};

impl From<p2p_crypto::CryptoError> for FileError {
    fn from(_: p2p_crypto::CryptoError) -> Self {
        // AEAD failures are kept uniform; no primitive error detail is exposed.
        Self::Crypto
    }
}

/// Errors from the file layer. Variants carry only static categories or public
/// lengths; no content key, plaintext, or file bytes are included.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FileError {
    #[error("file name is empty or contains a path component")]
    InvalidName,
    #[error("file is empty or too large")]
    InvalidSize,
    #[error("file has too many chunks")]
    TooManyChunks,
    #[error("file frame is too large")]
    FrameTooLarge,
    #[error("wrong file frame magic")]
    BadMagic,
    #[error("unsupported file frame version")]
    UnsupportedVersion,
    #[error("unknown file message type")]
    UnknownMessage,
    #[error("file frame is truncated")]
    Truncated,
    #[error("file frame has trailing bytes")]
    TrailingBytes,
    #[error("file frame contains an invalid field")]
    InvalidField,
    #[error("wrong file frame signature")]
    BadSignature,
    #[error("signed file sender does not match the authenticated peer")]
    UnexpectedSender,
    #[error("invalid file sender identifier")]
    BadPeerId,
    #[error("file sender key is not Ed25519")]
    NotEd25519,
    #[error("randomness source failed")]
    Randomness,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("file I/O operation failed")]
    Io,
    #[error("quarantine write failed")]
    Quarantine,
    #[error("unexpected chunk index")]
    UnexpectedChunk,
    #[error("chunk was already received")]
    DuplicateChunk,
    #[error("chunk count does not match the offer")]
    ChunkCountMismatch,
    #[error("chunk length does not match the offer")]
    ChunkLengthMismatch,
    #[error("missing chunks in completed transfer")]
    MissingChunk,
    #[error("chunk hash mismatch")]
    HashMismatch,
    #[error("unexpected frame for the current transfer state")]
    UnexpectedFrame,
    #[error("transfer was rejected by the peer")]
    Rejected,
    #[error("transfer integrity has not been verified")]
    IntegrityNotVerified,
    #[error("file has already been released")]
    AlreadyReleased,
    #[error("independent scanner did not report no threat detected")]
    ScanNotClean,
    #[error("explicit user approval is required before release")]
    ApprovalRequired,
    #[error("user cancelled release for this file")]
    ReleaseCancelled,
    #[error("release policy denied this file: {0}")]
    ReleaseDenied(&'static str),
    #[error("quarantine deletion is not permitted by policy")]
    QuarantineDeletionDenied,
    #[error("quarantine ciphertext was already deleted")]
    QuarantineAlreadyDeleted,
    #[error("quarantine deletion failed")]
    QuarantineDeletionFailed,
    #[error("transfer has already completed and cannot be aborted")]
    TransferCompleted,
}

/// Explicit quarantine deletion policy. Integrity verification, format
/// validation, scan results, approval, cancellation, and release never delete
/// ciphertext on their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuarantineDeletionPolicy {
    #[default]
    Retain,
    Explicit,
}

impl QuarantineDeletionPolicy {
    pub fn description(self) -> &'static str {
        match self {
            Self::Retain => "Retain quarantine ciphertext",
            Self::Explicit => "Delete quarantine ciphertext only on explicit request",
        }
    }
}

/// Local file-transfer policy. Only the quarantine directory is user-visible;
/// all other limits are fixed protocol constants.
#[derive(Clone, PartialEq, Eq)]
pub struct FileConfig {
    pub quarantine_dir: PathBuf,
    pub quarantine_deletion: QuarantineDeletionPolicy,
}

impl fmt::Debug for FileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileConfig")
            .field("quarantine_dir", &"<redacted local path>")
            .field("quarantine_deletion", &self.quarantine_deletion)
            .finish_non_exhaustive()
    }
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: dirs::data_local_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("p2p-messenger")
                .join("quarantine"),
            quarantine_deletion: QuarantineDeletionPolicy::Retain,
        }
    }
}

/// Direction of one tracked transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Outgoing,
    Incoming,
}

/// Explicit user decision for a pending in-memory release. No release occurs
/// without `Approved`, and `Cancelled` is terminal for that transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseApproval {
    NotApplicable,
    NotReady,
    Pending,
    Approved,
    Cancelled,
}

impl ReleaseApproval {
    pub fn description(self) -> &'static str {
        match self {
            Self::NotApplicable => "No release decision applies",
            Self::NotReady => "Release not eligible (format or scan requirements unmet)",
            Self::Pending => "Awaiting explicit user approval",
            Self::Approved => "Approved for in-memory release",
            Self::Cancelled => "Cancelled by user (ciphertext retained)",
        }
    }
}

/// Honest transfer progress. This never means scanned or safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Offer was composed or received and acceptance is pending.
    AwaitingAccept,
    /// Peer accepted; ciphertext chunks are being sent.
    Sending { acked: u32 },
    /// Ciphertext chunks are arriving in quarantine.
    Receiving { received: u32 },
    /// Every chunk and the full SHA-256 digest were verified.
    IntegrityVerified,
    /// Peer rejected the offer or a transfer step failed.
    Failed(&'static str),
}

impl TransferStatus {
    pub fn description(self) -> &'static str {
        match self {
            Self::AwaitingAccept => "Waiting for peer acceptance (not transferred)",
            Self::Sending { .. } => "Sending encrypted chunks (not yet completed)",
            Self::Receiving { .. } => "Receiving encrypted chunks into quarantine",
            Self::IntegrityVerified => "Integrity verified; not scanned",
            Self::Failed(reason) => reason,
        }
    }

    pub fn completed(self) -> bool {
        matches!(self, Self::IntegrityVerified)
    }

    /// True while the transfer is still exchanging frames. A failed or
    /// integrity-verified transfer is terminal and cannot be aborted; a
    /// completed transfer may still have a separate release decision.
    pub fn active(self) -> bool {
        !matches!(self, Self::IntegrityVerified | Self::Failed(_))
    }
}

/// Public view model for one active or recently completed file transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferInfo {
    pub transfer_id: [u8; 16],
    pub peer: libp2p_identity::PeerId,
    pub direction: TransferDirection,
    pub name: String,
    pub size: u64,
    pub chunks_done: u32,
    pub chunks_total: u32,
    pub status: TransferStatus,
    pub scan: ScanStatus,
    pub approval: ReleaseApproval,
    pub format: Option<FileFormat>,
    pub released: bool,
    pub quarantine_deleted: bool,
}
