//! Outgoing/incoming transfer state and ciphertext-only quarantine.
//!
//! Incoming ciphertext is written to a restricted directory and decrypted only
//! in memory for hash verification. The content key is never persisted, so
//! quarantine files cannot be turned into plaintext by a later process that
//! only has filesystem access.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use libp2p_identity::PeerId;
use p2p_crypto::{KEY_LEN, decrypt_bytes, encrypt_bytes};
use p2p_security::{FileFormat, ReleasePolicy, ReleaseRejection, ScanOutcome};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::frame::{
    MAX_CHUNK_PLAINTEXT_BYTES, MAX_CHUNKS, MAX_TRANSFER_BYTES, manifest_commitment_bytes,
    validate_name,
};
use crate::{
    FileConfig, FileEnvelope, FileError, FileMessage, QuarantineDeletionPolicy, ReleaseApproval,
    ScanStatus, TransferStatus,
};

/// Result of a successful in-memory integrity check. It carries only lengths;
/// no plaintext bytes are returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationResult {
    pub chunks_verified: u32,
    pub plaintext_len: usize,
}

/// Plaintext accepted by the release policy.
///
/// Release is an in-memory handoff to an encrypted attachment store or an OS
/// save dialog. It deliberately does not write plaintext to disk itself. The
/// buffer is zeroized on drop and redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleasedFile {
    name: String,
    bytes: Zeroizing<Vec<u8>>,
    format: Option<FileFormat>,
    plaintext_hash: [u8; 32],
}

impl ReleasedFile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Structurally validated format, if any. This is not a safety claim.
    pub fn format(&self) -> Option<FileFormat> {
        self.format
    }

    /// Short uppercase format label for encrypted attachment metadata.
    pub fn format_label(&self) -> Option<&'static str> {
        self.format.map(FileFormat::label)
    }

    /// SHA-256 digest of the released plaintext, recomputed during release.
    pub fn plaintext_hash(&self) -> [u8; 32] {
        self.plaintext_hash
    }
}

impl std::fmt::Debug for ReleasedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedFile")
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .field("format", &self.format)
            .field("plaintext_hash", &"<redacted>")
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn fresh_transfer_id() -> Result<[u8; 16], FileError> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| FileError::Randomness)?;
    Ok(id)
}

fn fresh_content_key() -> Result<Zeroizing<[u8; KEY_LEN]>, FileError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|_| FileError::Randomness)?;
    Ok(key)
}

fn key_bytes(key: &Zeroizing<[u8; KEY_LEN]>) -> &[u8; KEY_LEN] {
    key
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let output = Sha256::digest(bytes);
    let mut value = [0u8; 32];
    value.copy_from_slice(&output);
    value
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn chunk_aad(
    transfer_id: &[u8; 16],
    index: u32,
    chunk_count: u32,
    plaintext_len: usize,
) -> Vec<u8> {
    let mut bytes = b"p2pmsgr-file-chunk-v1".to_vec();
    bytes.extend_from_slice(transfer_id);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&chunk_count.to_le_bytes());
    let length = u32::try_from(plaintext_len).expect("chunk length is bounded");
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes
}

/// Sender-side transfer state. The file is read chunk by chunk; no complete
/// plaintext copy is held in memory.
pub struct OutgoingFile {
    path: PathBuf,
    transfer_id: [u8; 16],
    name: String,
    size: u64,
    chunk_count: u32,
    chunk_size: u32,
    content_key: Zeroizing<[u8; KEY_LEN]>,
    chunk_hashes: Vec<[u8; 32]>,
    plaintext_hash: [u8; 32],
    manifest_hash: [u8; 32],
    next_index: u32,
    acked: BTreeSet<u32>,
    manifest_sent: bool,
    status: TransferStatus,
}

impl OutgoingFile {
    /// Prepare a bounded regular file. Only its base name is sent; paths and
    /// directory components are rejected.
    pub fn new(path: &Path) -> Result<Self, FileError> {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(FileError::InvalidName)?;
        validate_name(name)?;
        let metadata = fs::metadata(path).map_err(|_| FileError::Io)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TRANSFER_BYTES {
            return Err(FileError::InvalidSize);
        }
        let chunk_size = MAX_CHUNK_PLAINTEXT_BYTES as u32;
        let chunk_count = metadata.len().div_ceil(u64::from(chunk_size));
        if chunk_count == 0 || chunk_count > u64::from(MAX_CHUNKS) {
            return Err(FileError::TooManyChunks);
        }

        let transfer_id = fresh_transfer_id()?;
        let content_key = fresh_content_key()?;
        let mut file = File::open(path).map_err(|_| FileError::Io)?;
        let mut buffer = vec![0u8; chunk_size as usize];
        let mut full_hash = Sha256::new();
        let mut chunk_hashes = Vec::with_capacity(chunk_count as usize);
        loop {
            let read = file.read(&mut buffer).map_err(|_| FileError::Io)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            full_hash.update(chunk);
            chunk_hashes.push(digest(chunk));
        }
        if chunk_hashes.len() != chunk_count as usize {
            return Err(FileError::Io);
        }
        let mut plaintext_hash = [0u8; 32];
        plaintext_hash.copy_from_slice(&full_hash.finalize());
        let manifest_hash = digest(&manifest_commitment_bytes(
            &transfer_id,
            &chunk_hashes,
            &plaintext_hash,
        ));

        Ok(Self {
            path: path.to_path_buf(),
            transfer_id,
            name: name.to_owned(),
            size: metadata.len(),
            chunk_count: chunk_count as u32,
            chunk_size,
            content_key,
            chunk_hashes,
            plaintext_hash,
            manifest_hash,
            next_index: 0,
            acked: BTreeSet::new(),
            manifest_sent: false,
            status: TransferStatus::AwaitingAccept,
        })
    }

    /// Build the signed offer carrying the fresh content key and manifest
    /// commitment. The key is protected by Noise on the wire and is never
    /// persisted by this crate.
    pub fn offer_frame(
        &self,
        identity: &p2p_identity::Identity,
    ) -> Result<FileEnvelope, FileError> {
        if !self.status.active() {
            return Err(FileError::UnexpectedFrame);
        }
        FileEnvelope::new(
            identity,
            FileMessage::Offer {
                transfer_id: self.transfer_id,
                name: self.name.clone(),
                size: self.size,
                chunk_count: self.chunk_count,
                chunk_size: self.chunk_size,
                manifest_hash: self.manifest_hash,
                content_key: self.content_key.clone(),
            },
        )
    }

    /// Encrypt and sign the next sequential chunk, or `None` when all chunks
    /// have been composed. The plaintext slice is zeroized before returning.
    pub fn next_chunk_frame(
        &mut self,
        identity: &p2p_identity::Identity,
    ) -> Result<Option<FileEnvelope>, FileError> {
        if !self.status.active() {
            return Err(FileError::UnexpectedFrame);
        }
        if self.next_index >= self.chunk_count {
            return Ok(None);
        }
        let index = self.next_index;
        let offset = u64::from(index) * u64::from(self.chunk_size);
        let expected = self.plain_len(index)?;
        let mut plaintext = Zeroizing::new(vec![0u8; expected]);
        let mut file = File::open(&self.path).map_err(|_| FileError::Io)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| FileError::Io)?;
        file.read_exact(&mut plaintext).map_err(|_| FileError::Io)?;
        let aad = chunk_aad(&self.transfer_id, index, self.chunk_count, expected);
        let ciphertext = encrypt_bytes(key_bytes(&self.content_key), &plaintext, &aad)
            .map_err(|_| FileError::Crypto)?;
        self.next_index = self.next_index.saturating_add(1);
        let frame = FileEnvelope::new(
            identity,
            FileMessage::Chunk {
                transfer_id: self.transfer_id,
                index,
                ciphertext,
            },
        )?;
        Ok(Some(frame))
    }

    /// Build the final signed manifest after every chunk was acknowledged.
    pub fn manifest_frame(
        &self,
        identity: &p2p_identity::Identity,
    ) -> Result<FileEnvelope, FileError> {
        if !self.status.active() {
            return Err(FileError::UnexpectedFrame);
        }
        FileEnvelope::new(
            identity,
            FileMessage::Manifest {
                transfer_id: self.transfer_id,
                chunk_hashes: self.chunk_hashes.clone(),
                plaintext_hash: self.plaintext_hash,
            },
        )
    }

    /// Apply the peer's offer acceptance. Progress stays unconfirmed until
    /// individual chunks are acknowledged.
    pub fn mark_accepted(&mut self) {
        if !matches!(self.status, TransferStatus::Failed(_)) {
            self.status = TransferStatus::Sending { acked: 0 };
        }
    }

    /// Record one authenticated chunk acknowledgement. This is transport
    /// progress, not proof of integrity or scanning.
    pub fn mark_acked(&mut self, index: u32, accepted: bool) -> Result<(), FileError> {
        if !self.status.active() {
            return Err(FileError::UnexpectedFrame);
        }
        if index >= self.chunk_count {
            return Err(FileError::UnexpectedChunk);
        }
        if !accepted {
            self.status = TransferStatus::Failed("Chunk rejected by peer");
            return Ok(());
        }
        self.acked.insert(index);
        let acked = self.acked.len() as u32;
        self.status = TransferStatus::Sending { acked };
        Ok(())
    }

    /// Apply the receiver's final manifest acknowledgement.
    pub fn mark_manifest_ack(&mut self, accepted: bool) {
        if !self.status.active() {
            return;
        }
        self.status = if accepted {
            TransferStatus::IntegrityVerified
        } else {
            TransferStatus::Failed("Manifest rejected by peer")
        };
    }

    pub fn mark_failed(&mut self, reason: &'static str) {
        self.status = TransferStatus::Failed(reason);
    }

    /// Abort this transfer locally. The content key is zeroized and no further
    /// chunk or manifest frame will be composed. This does not withdraw a
    /// request already queued in the transport worker; a late response is
    /// ignored by the application controller.
    pub fn abort(&mut self, reason: &'static str) -> Result<(), FileError> {
        if self.status.completed() || matches!(self.status, TransferStatus::Failed(_)) {
            return Err(FileError::TransferCompleted);
        }
        self.content_key = Zeroizing::new([0u8; KEY_LEN]);
        self.status = TransferStatus::Failed(reason);
        Ok(())
    }

    pub fn all_chunks_acked(&self) -> bool {
        self.acked.len() as u32 == self.chunk_count
    }

    /// True while at least one encrypted chunk has not been composed yet.
    pub fn has_more_chunks(&self) -> bool {
        self.next_index < self.chunk_count
    }

    pub fn manifest_sent(&self) -> bool {
        self.manifest_sent
    }

    pub fn mark_manifest_sent(&mut self) {
        self.manifest_sent = true;
    }

    pub fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn status(&self) -> TransferStatus {
        self.status
    }

    pub fn scan_status(&self) -> ScanStatus {
        match self.status {
            TransferStatus::IntegrityVerified => ScanStatus::Unavailable,
            _ => ScanStatus::NotApplicable,
        }
    }

    fn plain_len(&self, index: u32) -> Result<usize, FileError> {
        if index >= self.chunk_count {
            return Err(FileError::UnexpectedChunk);
        }
        let offset = u64::from(index) * u64::from(self.chunk_size);
        let remaining = self.size.saturating_sub(offset);
        Ok(remaining.min(u64::from(self.chunk_size)) as usize)
    }
}

impl std::fmt::Debug for OutgoingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingFile")
            .field("transfer_id", &hex(&self.transfer_id))
            .field("name", &self.name)
            .field("size", &self.size)
            .field("chunk_count", &self.chunk_count)
            .field("acked", &self.acked.len())
            .field("content_key", &"<redacted>")
            .field("path", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Receiver-side transfer state. Ciphertext chunks are stored in a restricted
/// quarantine directory; plaintext exists only inside bounded memory buffers
/// during integrity verification.
pub struct IncomingFile {
    peer: PeerId,
    transfer_id: [u8; 16],
    name: String,
    size: u64,
    chunk_count: u32,
    chunk_size: u32,
    manifest_hash: [u8; 32],
    content_key: Zeroizing<[u8; KEY_LEN]>,
    quarantine_dir: PathBuf,
    deletion_policy: QuarantineDeletionPolicy,
    received: BTreeSet<u32>,
    verified_hashes: Option<(Vec<[u8; 32]>, [u8; 32])>,
    status: TransferStatus,
    scan: ScanStatus,
    approval: ReleaseApproval,
    format: Option<FileFormat>,
    released: bool,
    quarantine_deleted: bool,
    verified: bool,
}

impl IncomingFile {
    /// Create quarantine state from a signature-verified offer. The caller's
    /// authenticated PeerId must match the signed sender.
    pub fn new(
        frame: &FileEnvelope,
        expected_peer: PeerId,
        config: &FileConfig,
    ) -> Result<Self, FileError> {
        frame.verify(&expected_peer)?;
        let FileMessage::Offer {
            transfer_id,
            name,
            size,
            chunk_count,
            chunk_size,
            manifest_hash,
            content_key,
        } = &frame.message
        else {
            return Err(FileError::UnexpectedFrame);
        };
        let quarantine_dir = config.quarantine_dir.join(hex(transfer_id));
        create_restricted_dir(&quarantine_dir)?;
        Ok(Self {
            peer: expected_peer,
            transfer_id: *transfer_id,
            name: name.clone(),
            size: *size,
            chunk_count: *chunk_count,
            chunk_size: *chunk_size,
            manifest_hash: *manifest_hash,
            content_key: content_key.clone(),
            quarantine_dir,
            deletion_policy: config.quarantine_deletion,
            received: BTreeSet::new(),
            verified_hashes: None,
            status: TransferStatus::Receiving { received: 0 },
            scan: ScanStatus::NotApplicable,
            approval: ReleaseApproval::NotReady,
            format: None,
            released: false,
            quarantine_deleted: false,
            verified: false,
        })
    }

    /// Verify one signed chunk, decrypt it only to check the AEAD tag and
    /// length, then persist the ciphertext in quarantine.
    pub fn accept_chunk(&mut self, frame: &FileEnvelope) -> Result<(), FileError> {
        if self.verified || matches!(self.status, TransferStatus::Failed(_)) {
            return Err(FileError::UnexpectedFrame);
        }
        frame.verify(&self.peer)?;
        let FileMessage::Chunk {
            transfer_id,
            index,
            ciphertext,
        } = &frame.message
        else {
            return Err(FileError::UnexpectedFrame);
        };
        if *transfer_id != self.transfer_id {
            return Err(FileError::UnexpectedFrame);
        }
        if *index >= self.chunk_count {
            return Err(FileError::UnexpectedChunk);
        }
        if self.received.contains(index) {
            return Err(FileError::DuplicateChunk);
        }
        let expected = self.plain_len(*index)?;
        let aad = chunk_aad(&self.transfer_id, *index, self.chunk_count, expected);
        let plaintext = Zeroizing::new(
            decrypt_bytes(key_bytes(&self.content_key), ciphertext, &aad)
                .map_err(|_| FileError::Crypto)?,
        );
        if plaintext.len() != expected {
            return Err(FileError::ChunkLengthMismatch);
        }
        write_restricted(&self.chunk_path(*index), ciphertext)?;
        self.received.insert(*index);
        self.status = TransferStatus::Receiving {
            received: self.received.len() as u32,
        };
        Ok(())
    }

    /// Verify the final signed manifest, every per-chunk hash, and the full
    /// SHA-256 digest. Plaintext is assembled only in a zeroizing buffer and
    /// is never written to quarantine. Integrity verification leaves the scan
    /// status `Unavailable`; it never invents a scanner result.
    pub fn verify_manifest(
        &mut self,
        frame: &FileEnvelope,
    ) -> Result<VerificationResult, FileError> {
        if self.verified || matches!(self.status, TransferStatus::Failed(_)) {
            return Err(FileError::UnexpectedFrame);
        }
        frame.verify(&self.peer)?;
        let FileMessage::Manifest {
            transfer_id,
            chunk_hashes,
            plaintext_hash,
        } = &frame.message
        else {
            return Err(FileError::UnexpectedFrame);
        };
        if *transfer_id != self.transfer_id {
            return Err(FileError::UnexpectedFrame);
        }
        if chunk_hashes.len() as u32 != self.chunk_count {
            self.status = TransferStatus::Failed("Chunk count mismatch");
            return Err(FileError::ChunkCountMismatch);
        }
        let manifest_hash = digest(&manifest_commitment_bytes(
            &self.transfer_id,
            chunk_hashes,
            plaintext_hash,
        ));
        if manifest_hash != self.manifest_hash {
            self.status = TransferStatus::Failed("Manifest hash mismatch");
            return Err(FileError::HashMismatch);
        }

        let assembled = match self.assemble_plaintext(chunk_hashes, plaintext_hash) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.status = TransferStatus::Failed(match error {
                    FileError::MissingChunk => "Missing chunks",
                    FileError::Crypto => "Chunk decryption failed",
                    FileError::ChunkLengthMismatch => "Chunk length mismatch",
                    FileError::HashMismatch => "Chunk hash mismatch",
                    FileError::InvalidSize => "Transfer size mismatch",
                    FileError::Quarantine | FileError::Io => "Quarantine read failed",
                    _ => "File verification failed",
                });
                return Err(error);
            }
        };

        let manifest_record =
            manifest_commitment_bytes(&self.transfer_id, chunk_hashes, plaintext_hash);
        write_restricted(&self.quarantine_dir.join("manifest.bin"), &manifest_record)?;
        self.verified_hashes = Some((chunk_hashes.clone(), *plaintext_hash));
        self.verified = true;
        self.status = TransferStatus::IntegrityVerified;
        self.scan = ScanStatus::Unavailable;
        self.approval = ReleaseApproval::NotReady;
        self.format = None;
        Ok(VerificationResult {
            chunks_verified: self.chunk_count,
            plaintext_len: assembled.len(),
        })
    }

    pub fn mark_failed(&mut self, reason: &'static str) {
        self.status = TransferStatus::Failed(reason);
    }

    /// Abort an incomplete incoming transfer. Terminating a transfer is
    /// distinct from cancelling a release decision: this clears the in-memory
    /// key, marks the transfer terminal, and removes the partial ciphertext
    /// quarantine directory because no integrity-verified file exists yet.
    /// A verified transfer cannot be aborted here; use release cancellation.
    pub fn abort(&mut self, reason: &'static str) -> Result<(), FileError> {
        if self.released || self.verified || !self.status.active() {
            return Err(FileError::TransferCompleted);
        }
        self.content_key = Zeroizing::new([0u8; KEY_LEN]);
        self.approval = ReleaseApproval::Cancelled;
        self.status = TransferStatus::Failed(reason);
        remove_quarantine_dir(&self.quarantine_dir)?;
        self.quarantine_deleted = true;
        Ok(())
    }

    /// Reassemble plaintext only in a zeroizing memory buffer for an
    /// independent scanner. No bytes are persisted here, and the bytes are
    /// dropped (and zeroized) as soon as the scanner call returns.
    pub fn plaintext_for_scan(&self) -> Result<Zeroizing<Vec<u8>>, FileError> {
        if self.approval == ReleaseApproval::Cancelled {
            return Err(FileError::ReleaseCancelled);
        }
        if !self.verified || self.released {
            return Err(FileError::IntegrityNotVerified);
        }
        let Some((chunk_hashes, plaintext_hash)) = &self.verified_hashes else {
            return Err(FileError::IntegrityNotVerified);
        };
        self.assemble_plaintext(chunk_hashes, plaintext_hash)
    }

    /// Apply a scanner result from [`p2p_security::SecurityConfig::scan`].
    /// This accepts only a `ScanOutcome`, so a clean status cannot be
    /// fabricated by an application caller.
    pub fn apply_scan(&mut self, outcome: ScanOutcome) -> Result<(), FileError> {
        if !self.verified || self.released {
            return Err(FileError::IntegrityNotVerified);
        }
        if self.approval == ReleaseApproval::Cancelled {
            return Err(FileError::ReleaseCancelled);
        }
        self.scan = ScanStatus::from(outcome);
        self.format = outcome.format();
        if !self.scan.permits_release() {
            self.approval = ReleaseApproval::NotReady;
        }
        Ok(())
    }

    /// Record an explicit per-file approval after a clean independent scan,
    /// validated format, and policy check. Approval alone does not write
    /// plaintext or save a file; [`Self::release`] still requires it.
    pub fn approve(&mut self, policy: &ReleasePolicy) -> Result<(), FileError> {
        self.ensure_release_eligible()?;
        if self.approval == ReleaseApproval::Approved {
            return Ok(());
        }
        self.evaluate_policy(policy)?;
        self.approval = ReleaseApproval::Approved;
        Ok(())
    }

    /// Cancel any pending release decision. Cancellation is terminal for this
    /// transfer; ciphertext stays in quarantine until a separate explicit
    /// deletion request is allowed by policy. It does not abort an active
    /// transfer; use [`Self::abort`] for that.
    pub fn cancel(&mut self) -> Result<(), FileError> {
        if self.released {
            return Err(FileError::AlreadyReleased);
        }
        self.approval = ReleaseApproval::Cancelled;
        Ok(())
    }

    /// Move a not-yet-approved transfer into `Pending` when every release
    /// requirement except the explicit user decision is satisfied. A user
    /// cancellation or approval is never silently overwritten.
    pub fn refresh_approval(&mut self, policy: &ReleasePolicy) {
        if self.released || self.approval == ReleaseApproval::Cancelled {
            return;
        }
        if self.evaluate_policy(policy).is_ok() {
            if self.approval != ReleaseApproval::Approved {
                self.approval = ReleaseApproval::Pending;
            }
        } else {
            self.approval = ReleaseApproval::NotReady;
        }
    }

    /// Release verified plaintext into memory after a clean independent scan,
    /// validated format, policy check, and explicit user approval. This never
    /// writes plaintext to disk or presents the file as safe. Quarantine
    /// ciphertext is retained until a separate explicit deletion request is
    /// allowed by policy.
    pub fn release(&mut self, policy: &ReleasePolicy) -> Result<ReleasedFile, FileError> {
        self.ensure_release_eligible()?;
        self.evaluate_policy(policy)?;
        match self.approval {
            ReleaseApproval::Approved => {}
            ReleaseApproval::Cancelled => return Err(FileError::ReleaseCancelled),
            _ => return Err(FileError::ApprovalRequired),
        }
        let Some((chunk_hashes, plaintext_hash)) = &self.verified_hashes else {
            return Err(FileError::IntegrityNotVerified);
        };
        let bytes = self.assemble_plaintext(chunk_hashes, plaintext_hash)?;
        self.released = true;
        Ok(ReleasedFile {
            name: self.name.clone(),
            bytes,
            format: self.format,
            plaintext_hash: *plaintext_hash,
        })
    }

    /// Delete this transfer's own quarantine directory after an explicit
    /// request. The default policy retains ciphertext; integrity verification,
    /// validation, scanning, approval, cancellation, and release never delete
    /// it implicitly. Deletion is not secure erasure on SSD/CoW storage.
    pub fn delete_quarantine(&mut self) -> Result<(), FileError> {
        if self.deletion_policy != QuarantineDeletionPolicy::Explicit {
            return Err(FileError::QuarantineDeletionDenied);
        }
        if self.quarantine_deleted {
            return Err(FileError::QuarantineAlreadyDeleted);
        }
        if !self.verified || !self.status.completed() {
            return Err(FileError::IntegrityNotVerified);
        }
        if !self.released && self.approval != ReleaseApproval::Cancelled {
            return Err(FileError::QuarantineDeletionDenied);
        }
        remove_quarantine_dir(&self.quarantine_dir)?;
        self.quarantine_deleted = true;
        Ok(())
    }

    pub fn released(&self) -> bool {
        self.released
    }

    pub fn quarantine_deleted(&self) -> bool {
        self.quarantine_deleted
    }

    pub fn approval(&self) -> ReleaseApproval {
        self.approval
    }

    pub fn format(&self) -> Option<FileFormat> {
        self.format
    }

    fn ensure_release_eligible(&self) -> Result<(), FileError> {
        if !self.verified || self.status != TransferStatus::IntegrityVerified {
            return Err(FileError::IntegrityNotVerified);
        }
        if self.released {
            return Err(FileError::AlreadyReleased);
        }
        if self.approval == ReleaseApproval::Cancelled {
            return Err(FileError::ReleaseCancelled);
        }
        Ok(())
    }

    fn evaluate_policy(&self, policy: &ReleasePolicy) -> Result<(), FileError> {
        policy
            .evaluate(
                self.name(),
                self.size,
                self.chunk_count,
                self.scan,
                self.format,
            )
            .map_err(|rejection| match rejection {
                ReleaseRejection::ScanNotClean => FileError::ScanNotClean,
                other => FileError::ReleaseDenied(other.description()),
            })
    }

    pub fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    pub fn peer(&self) -> PeerId {
        self.peer
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn status(&self) -> TransferStatus {
        self.status
    }

    pub fn scan_status(&self) -> ScanStatus {
        self.scan
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    fn plain_len(&self, index: u32) -> Result<usize, FileError> {
        if index >= self.chunk_count {
            return Err(FileError::UnexpectedChunk);
        }
        let offset = u64::from(index) * u64::from(self.chunk_size);
        Ok(self
            .size
            .saturating_sub(offset)
            .min(u64::from(self.chunk_size)) as usize)
    }

    fn chunk_path(&self, index: u32) -> PathBuf {
        self.quarantine_dir.join(format!("{index:06}.ct"))
    }

    /// Rebuild the plaintext from ciphertext quarantine and re-check every
    /// committed hash. The buffer is zeroized on every success and error path.
    fn assemble_plaintext(
        &self,
        chunk_hashes: &[[u8; 32]],
        plaintext_hash: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, FileError> {
        if chunk_hashes.len() as u32 != self.chunk_count {
            return Err(FileError::ChunkCountMismatch);
        }
        if self.received.len() as u32 != self.chunk_count {
            return Err(FileError::MissingChunk);
        }
        let mut assembled = Zeroizing::new(Vec::with_capacity(self.size as usize));
        let mut full_hash = Sha256::new();
        for index in 0..self.chunk_count {
            let ciphertext = fs::read(self.chunk_path(index)).map_err(|_| FileError::Io)?;
            let expected = self.plain_len(index)?;
            let aad = chunk_aad(&self.transfer_id, index, self.chunk_count, expected);
            let plaintext = Zeroizing::new(
                decrypt_bytes(key_bytes(&self.content_key), &ciphertext, &aad)
                    .map_err(|_| FileError::Crypto)?,
            );
            if plaintext.len() != expected {
                return Err(FileError::ChunkLengthMismatch);
            }
            if digest(&plaintext) != chunk_hashes[index as usize] {
                return Err(FileError::HashMismatch);
            }
            full_hash.update(plaintext.as_slice());
            assembled.extend_from_slice(&plaintext);
        }
        if assembled.len() as u64 != self.size {
            return Err(FileError::InvalidSize);
        }
        let mut actual_hash = [0u8; 32];
        actual_hash.copy_from_slice(&full_hash.finalize());
        if actual_hash != *plaintext_hash {
            return Err(FileError::HashMismatch);
        }
        Ok(assembled)
    }
}

impl std::fmt::Debug for IncomingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingFile")
            .field("transfer_id", &hex(&self.transfer_id))
            .field("peer", &self.peer.to_string())
            .field("name", &self.name)
            .field("size", &self.size)
            .field("chunk_count", &self.chunk_count)
            .field("received", &self.received.len())
            .field("scan", &self.scan)
            .field("approval", &self.approval)
            .field("format", &self.format)
            .field("released", &self.released)
            .field("quarantine_deleted", &self.quarantine_deleted)
            .field("content_key", &"<redacted>")
            .field("quarantine_dir", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Refuse an existing symlink at any already-present path component. This is
/// deliberately applied on every platform: `symlink_metadata` does not follow
/// the final component, and on Windows it also rejects ordinary symlinks.
/// Windows junctions/reparse points still require platform-specific handling.
fn reject_symlink(path: &Path) -> Result<(), FileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(FileError::Quarantine),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FileError::Quarantine),
    }
}

/// Walk a path from its root and reject symlinks or parent traversal in every
/// existing component, not just the final quarantine directory.
fn reject_unsafe_path_components(path: &Path) -> Result<(), FileError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => {
                current.push(part);
                reject_symlink(&current)?;
            }
            Component::ParentDir => return Err(FileError::Quarantine),
        }
    }
    Ok(())
}

/// Remove only a transfer's own quarantine directory after rejecting unsafe
/// path components and a symlink at the final component. This is filesystem
/// deletion, not secure erasure on SSD/CoW storage.
fn remove_quarantine_dir(path: &Path) -> Result<(), FileError> {
    reject_unsafe_path_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| FileError::QuarantineDeletionFailed)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FileError::QuarantineDeletionFailed);
    }
    fs::remove_dir_all(path).map_err(|_| FileError::QuarantineDeletionFailed)
}

#[cfg(unix)]
fn create_restricted_dir(path: &Path) -> Result<(), FileError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    reject_unsafe_path_components(path)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(path).map_err(|_| FileError::Quarantine)?;
    reject_unsafe_path_components(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| FileError::Quarantine)
}

#[cfg(not(unix))]
fn create_restricted_dir(path: &Path) -> Result<(), FileError> {
    reject_unsafe_path_components(path)?;
    fs::create_dir_all(path).map_err(|_| FileError::Quarantine)?;
    reject_unsafe_path_components(path)
}

#[cfg(unix)]
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| FileError::Quarantine)?;
    file.write_all(bytes).map_err(|_| FileError::Quarantine)?;
    file.sync_all().map_err(|_| FileError::Quarantine)
}

#[cfg(not(unix))]
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| FileError::Quarantine)?;
    file.write_all(bytes).map_err(|_| FileError::Quarantine)?;
    file.sync_all().map_err(|_| FileError::Quarantine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_CHUNK_PLAINTEXT_BYTES;

    fn config(dir: &Path) -> FileConfig {
        FileConfig {
            quarantine_dir: dir.to_path_buf(),
            quarantine_deletion: QuarantineDeletionPolicy::Retain,
        }
    }

    fn explicit_config(dir: &Path) -> FileConfig {
        FileConfig {
            quarantine_dir: dir.to_path_buf(),
            quarantine_deletion: QuarantineDeletionPolicy::Explicit,
        }
    }

    #[test]
    fn file_config_debug_redacts_the_local_quarantine_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secret_path = dir.path().join("SENTINEL_QUARANTINE_DIRECTORY");
        let debug = format!("{:?}", config(&secret_path));

        assert!(debug.contains("quarantine_deletion"));
        assert!(!debug.contains("SENTINEL_QUARANTINE_DIRECTORY"));
        assert!(!debug.contains(secret_path.to_string_lossy().as_ref()));
    }

    fn read_all(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in fs::read_dir(dir).expect("quarantine entries") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                all.extend(fs::read(path).expect("quarantine file"));
            }
        }
        all
    }

    #[cfg(unix)]
    #[test]
    fn restricted_quarantine_directory_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target directory");
        let link = directory.path().join("quarantine-link");
        symlink(&target, &link).expect("quarantine symlink");

        assert_eq!(create_restricted_dir(&link), Err(FileError::Quarantine));
        assert_eq!(fs::read_dir(&target).expect("target entries").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn restricted_quarantine_directory_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target directory");
        let link = directory.path().join("quarantine-parent-link");
        symlink(&target, &link).expect("parent symlink");

        let path = link.join("child");
        assert_eq!(create_restricted_dir(&path), Err(FileError::Quarantine));
        assert_eq!(fs::read_dir(&target).expect("target entries").count(), 0);
    }

    #[test]
    fn restricted_quarantine_directory_rejects_parent_traversal() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory
            .path()
            .join("quarantine")
            .join("..")
            .join("escaped");
        assert_eq!(create_restricted_dir(&path), Err(FileError::Quarantine));
        assert!(!directory.path().join("escaped").exists());
    }

    #[test]
    fn multichunk_transfer_verifies_integrity_without_writing_plaintext() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("transfer.bin");
        let sentinel = b"quarantine-plaintext-sentinel";
        let mut payload = vec![7u8; MAX_CHUNK_PLAINTEXT_BYTES + 97];
        payload.extend_from_slice(sentinel);
        fs::write(&source, &payload).expect("source file");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        assert_eq!(outgoing.chunk_count(), 2);
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");

        let mut chunks = 0;
        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
            outgoing.mark_acked(chunks, true).expect("ack chunk");
            chunks += 1;
        }
        assert_eq!(chunks, 2);
        assert!(outgoing.all_chunks_acked());

        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        let result = incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");
        assert_eq!(result.chunks_verified, 2);
        assert_eq!(result.plaintext_len, payload.len());
        assert_eq!(incoming.status(), crate::TransferStatus::IntegrityVerified);
        assert_eq!(incoming.scan_status(), ScanStatus::Unavailable);
        let raw = read_all(&quarantine.join(hex(incoming.transfer_id())));
        assert!(
            !raw.windows(sentinel.len()).any(|window| window == sentinel),
            "quarantine must not contain plaintext"
        );
    }

    #[test]
    fn tampered_chunk_is_rejected_before_quarantine_write() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("file.bin");
        fs::write(&source, vec![11u8; 100]).expect("source");
        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");
        let chunk = outgoing.next_chunk_frame(&sender).expect("chunk").unwrap();
        let mut tampered_message = chunk.message.clone();
        if let FileMessage::Chunk { ciphertext, .. } = &mut tampered_message {
            let last = ciphertext.len() - 1;
            ciphertext[last] ^= 0x01;
        }
        let tampered = FileEnvelope::new(&sender, tampered_message).expect("re-signed tampering");
        assert!(matches!(
            incoming.accept_chunk(&tampered),
            Err(FileError::Crypto)
        ));
    }

    #[test]
    fn abort_clears_partial_transfer_state_and_quarantine() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("file.bin");
        fs::write(&source, vec![13u8; 100]).expect("source");
        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine_root = dir.path().join("quarantine");
        let mut incoming = IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine_root))
            .expect("incoming");
        let chunk = outgoing
            .next_chunk_frame(&sender)
            .expect("chunk")
            .expect("one chunk");
        incoming.accept_chunk(&chunk).expect("partial chunk");

        let transfer_dir = quarantine_root.join(hex(incoming.transfer_id()));
        assert!(transfer_dir.exists());
        outgoing
            .abort("Transfer aborted by user")
            .expect("abort outgoing");
        incoming
            .abort("Transfer aborted by user")
            .expect("abort incoming");

        assert_eq!(
            incoming.status(),
            crate::TransferStatus::Failed("Transfer aborted by user")
        );
        assert_eq!(incoming.approval(), ReleaseApproval::Cancelled);
        assert!(incoming.quarantine_deleted());
        assert!(!transfer_dir.exists());
        assert!(incoming.accept_chunk(&chunk).is_err());
        assert!(outgoing.next_chunk_frame(&sender).is_err());
        assert!(incoming.abort("Again").is_err());
    }

    #[test]
    fn duplicate_chunk_and_manifest_hash_mismatch_are_rejected() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("file.bin");
        fs::write(&source, vec![12u8; 100]).expect("source");
        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");
        let chunk = outgoing.next_chunk_frame(&sender).expect("chunk").unwrap();
        incoming.accept_chunk(&chunk).expect("first chunk");
        assert!(matches!(
            incoming.accept_chunk(&chunk),
            Err(FileError::DuplicateChunk)
        ));

        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        let mut tampered_message = manifest.message.clone();
        if let FileMessage::Manifest { plaintext_hash, .. } = &mut tampered_message {
            plaintext_hash[0] ^= 0x01;
        }
        let tampered = FileEnvelope::new(&sender, tampered_message).expect("re-signed tampering");
        assert!(matches!(
            incoming.verify_manifest(&tampered),
            Err(FileError::HashMismatch)
        ));
    }

    struct FixedScanner(p2p_security::ScanResult);

    impl p2p_security::FileScanner for FixedScanner {
        fn scan(&self, _request: &p2p_security::ScanRequest<'_>) -> p2p_security::ScanResult {
            self.0
        }
    }

    #[test]
    fn release_requires_clean_scan_format_policy_and_explicit_approval() {
        use p2p_security::{
            ReleasePolicy, ReleaseRejection, ScanRequest, ScanResult, SecurityConfig,
        };

        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let sentinel = b"release policy payload";
        let payload = sentinel.to_vec();
        let source = dir.path().join("file.txt");
        fs::write(&source, &payload).expect("source");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");

        let early = SecurityConfig::default()
            .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
            .scan(&ScanRequest {
                name: incoming.name(),
                bytes: &payload,
            });
        assert_eq!(
            incoming.apply_scan(early),
            Err(FileError::IntegrityNotVerified)
        );

        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
        }
        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");
        assert_eq!(incoming.scan_status(), ScanStatus::Unavailable);
        assert_eq!(incoming.approval(), ReleaseApproval::NotReady);
        assert_eq!(
            incoming.release(&ReleasePolicy::default()),
            Err(FileError::ScanNotClean)
        );

        let bytes = incoming.plaintext_for_scan().expect("plaintext for scan");
        assert_eq!(bytes.as_slice(), payload.as_slice());

        let threat = SecurityConfig::default()
            .with_scanner(FixedScanner(ScanResult::ThreatDetected))
            .scan(&ScanRequest {
                name: incoming.name(),
                bytes: &bytes,
            });
        incoming.apply_scan(threat).expect("apply threat");
        incoming.refresh_approval(&ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]));
        assert_eq!(incoming.scan_status(), ScanStatus::ThreatDetected);
        assert_eq!(incoming.approval(), ReleaseApproval::NotReady);
        assert_eq!(
            incoming.release(&ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()])),
            Err(FileError::ScanNotClean)
        );

        let clean = SecurityConfig::default()
            .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
            .scan(&ScanRequest {
                name: incoming.name(),
                bytes: &bytes,
            });
        incoming.apply_scan(clean).expect("apply clean");
        assert_eq!(incoming.scan_status(), ScanStatus::CleanNoThreatDetected);
        assert_eq!(incoming.format(), Some(FileFormat::Text));

        let default_policy = ReleasePolicy::default();
        incoming.refresh_approval(&default_policy);
        assert_eq!(incoming.approval(), ReleaseApproval::NotReady);
        assert_eq!(
            incoming.approve(&default_policy),
            Err(FileError::ReleaseDenied(
                ReleaseRejection::ExtensionNotAllowed.description()
            ))
        );

        let policy = ReleasePolicy::new(u64::MAX, vec!["TXT".to_owned()]);
        incoming.refresh_approval(&policy);
        assert_eq!(incoming.approval(), ReleaseApproval::Pending);
        assert_eq!(incoming.release(&policy), Err(FileError::ApprovalRequired));

        incoming.approve(&policy).expect("explicit approval");
        assert_eq!(incoming.approval(), ReleaseApproval::Approved);
        let released = incoming.release(&policy).expect("release");
        assert_eq!(released.name(), "file.txt");
        assert_eq!(released.bytes(), payload.as_slice());
        assert!(!format!("{released:?}").contains("release policy payload"));
        assert!(incoming.released());
        assert_eq!(incoming.release(&policy), Err(FileError::AlreadyReleased));

        let raw = read_all(&quarantine.join(hex(incoming.transfer_id())));
        assert!(
            !raw.windows(sentinel.len()).any(|window| window == sentinel),
            "quarantine must remain ciphertext-only after release"
        );
    }

    #[test]
    fn quarantine_deletion_is_explicit_and_retains_by_default() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("retain.txt");
        fs::write(&source, b"retained ciphertext").expect("source");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");
        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
        }
        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");

        assert_eq!(
            incoming.delete_quarantine(),
            Err(FileError::QuarantineDeletionDenied)
        );
        assert!(incoming.quarantine_dir().is_dir());
        assert!(!incoming.quarantine_deleted());

        incoming.cancel().expect("cancel");
        assert_eq!(
            incoming.delete_quarantine(),
            Err(FileError::QuarantineDeletionDenied)
        );
        assert!(incoming.quarantine_dir().is_dir());
        assert!(!incoming.quarantine_deleted());
    }

    #[test]
    fn explicit_quarantine_deletion_requires_verified_released_or_cancelled_state() {
        use p2p_security::{ReleasePolicy, ScanRequest, ScanResult, SecurityConfig};

        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let sentinel = b"explicit deletion payload";
        let source = dir.path().join("delete.txt");
        fs::write(&source, sentinel).expect("source");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &explicit_config(&quarantine))
                .expect("incoming");
        let transfer_dir = incoming.quarantine_dir().to_path_buf();
        assert_eq!(
            incoming.delete_quarantine(),
            Err(FileError::IntegrityNotVerified)
        );

        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
        }
        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");
        assert_eq!(
            incoming.delete_quarantine(),
            Err(FileError::QuarantineDeletionDenied)
        );

        let policy = ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]);
        let clean = SecurityConfig::default()
            .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
            .scan(&ScanRequest {
                name: incoming.name(),
                bytes: incoming.plaintext_for_scan().expect("plaintext").as_slice(),
            });
        incoming.apply_scan(clean).expect("apply clean");
        incoming.approve(&policy).expect("approve");
        let released = incoming.release(&policy).expect("release");
        assert_eq!(released.bytes(), sentinel);
        assert_eq!(released.format_label(), Some("TXT"));
        assert_eq!(released.plaintext_hash(), digest(sentinel));

        let raw = read_all(&transfer_dir);
        assert!(!raw.windows(sentinel.len()).any(|window| window == sentinel));
        incoming.delete_quarantine().expect("delete quarantine");
        assert!(incoming.quarantine_deleted());
        assert!(!transfer_dir.exists());
        assert!(quarantine.is_dir());
        assert_eq!(
            incoming.delete_quarantine(),
            Err(FileError::QuarantineAlreadyDeleted)
        );
    }

    #[test]
    fn explicit_quarantine_deletion_after_cancellation_removes_transfer_directory() {
        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("cancel.txt");
        fs::write(&source, b"cancelled deletion payload").expect("source");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &explicit_config(&quarantine))
                .expect("incoming");
        let transfer_dir = incoming.quarantine_dir().to_path_buf();
        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
        }
        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");
        incoming.cancel().expect("cancel release");
        incoming.delete_quarantine().expect("delete quarantine");
        assert!(incoming.quarantine_deleted());
        assert!(!transfer_dir.exists());
        assert!(quarantine.is_dir());
    }

    #[test]
    fn cancellation_blocks_pending_release_and_further_scanning() {
        use p2p_security::{ReleasePolicy, ScanRequest, ScanResult, SecurityConfig};

        let sender = p2p_identity::Identity::generate().expect("sender");
        let dir = tempfile::tempdir().expect("temp dir");
        let sentinel = b"cancelled payload";
        let source = dir.path().join("cancelled.txt");
        fs::write(&source, sentinel).expect("source");

        let mut outgoing = OutgoingFile::new(&source).expect("outgoing");
        let offer = outgoing.offer_frame(&sender).expect("offer");
        let quarantine = dir.path().join("quarantine");
        let mut incoming =
            IncomingFile::new(&offer, sender.peer_id(), &config(&quarantine)).expect("incoming");
        while let Some(chunk) = outgoing.next_chunk_frame(&sender).expect("chunk") {
            incoming.accept_chunk(&chunk).expect("accept chunk");
        }
        let manifest = outgoing.manifest_frame(&sender).expect("manifest");
        incoming
            .verify_manifest(&manifest)
            .expect("verify manifest");

        let clean = SecurityConfig::default()
            .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
            .scan(&ScanRequest {
                name: incoming.name(),
                bytes: incoming.plaintext_for_scan().expect("plaintext").as_slice(),
            });
        incoming.apply_scan(clean).expect("apply clean");
        let policy = ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]);
        incoming.refresh_approval(&policy);
        assert_eq!(incoming.approval(), ReleaseApproval::Pending);

        incoming.cancel().expect("cancel release");
        assert_eq!(incoming.approval(), ReleaseApproval::Cancelled);
        assert_eq!(incoming.approve(&policy), Err(FileError::ReleaseCancelled));
        assert_eq!(incoming.release(&policy), Err(FileError::ReleaseCancelled));
        assert_eq!(
            incoming.plaintext_for_scan(),
            Err(FileError::ReleaseCancelled)
        );
        assert!(!incoming.released());

        let raw = read_all(&quarantine.join(hex(incoming.transfer_id())));
        assert!(
            !raw.windows(sentinel.len()).any(|window| window == sentinel),
            "cancelled transfer must remain ciphertext-only"
        );
    }
}
