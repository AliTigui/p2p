//! Durable, authenticated record of signed setup/group-control frames.
//!
//! Only public peer identifiers and SHA-256 frame digests are recorded, and
//! they are stored as HMAC blind indexes plus XChaCha20-Poly1305 ciphertext.
//! Each row is chained to the previous row, and a separate AEAD-protected
//! anchor file records the high-water mark. Restoring an older database while
//! leaving the current anchor in place is detected. Restoring the entire vault
//! directory, including the anchor, remains outside what local code can detect
//! without an external anchor.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use p2p_crypto::{Purpose, decrypt_bytes, encrypt_bytes};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Session, StorageError, fixed, reject_symlink, restrict_file, tagged_aad};

const ANCHOR_FILE: &str = "control.anchor";
const ANCHOR_TEMP: &str = "control.anchor.tmp";
const ANCHOR_AAD: &[u8] = b"p2p-messenger/control-anchor/v1";
const RECORD_AAD: &[u8] = b"p2p-messenger/control-log/v1";
const INDEX_LABEL: &[u8] = b"p2p-messenger/control-frame/v1";
const CHAIN_LABEL: &[u8] = b"p2p-messenger/control-chain/v1";
const ANCHOR_MAGIC: &[u8] = b"P2PANCH1";
const ANCHOR_VERSION: u8 = 1;
const RECORD_VERSION: u8 = 1;
const ZERO_CHAIN: [u8; 32] = [0u8; 32];

/// Maximum authenticated peer identifier length accepted by the control log.
pub const MAX_CONTROL_PEER_BYTES: usize = 64;
/// Finite replay window. The log fails closed instead of dropping old records.
pub const MAX_CONTROL_LOG_ENTRIES: u64 = 4096;

const MAX_ANCHOR_BYTES: usize = 256;
const ANCHOR_PLAINTEXT_BYTES: usize = 8 + 1 + 8 + 32;

/// Result of recording one authenticated control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRecordOutcome {
    /// A new record was appended at this sequence number.
    Appended(u64),
    /// This exact idempotent request was already recorded.
    Idempotent(u64),
    /// This exact non-repeatable frame was already recorded.
    Replay(u64),
}

impl ControlRecordOutcome {
    /// Sequence number of the matching log record.
    pub fn sequence(self) -> u64 {
        match self {
            Self::Appended(sequence) | Self::Idempotent(sequence) | Self::Replay(sequence) => {
                sequence
            }
        }
    }

    /// True when a terminal or acknowledgement frame must not be re-applied.
    pub fn is_replay(self) -> bool {
        matches!(self, Self::Replay(_))
    }
}

/// Authenticated high-water mark of the durable control log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlLogState {
    pub sequence: u64,
    pub chain: [u8; 32],
}

#[derive(Clone)]
struct ControlRecord {
    peer: Vec<u8>,
    digest: [u8; 32],
    repeatable: bool,
}

fn record_aad(profile_id: &[u8; 16], sequence: u64, previous_chain: &[u8; 32]) -> Vec<u8> {
    let mut aad = tagged_aad(RECORD_AAD, profile_id);
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(previous_chain);
    aad
}

fn chain_hash(
    previous_chain: &[u8; 32],
    sequence: u64,
    record: &ControlRecord,
) -> Result<[u8; 32], StorageError> {
    if record.peer.is_empty() || record.peer.len() > MAX_CONTROL_PEER_BYTES {
        return Err(StorageError::InvalidProfile(
            "control frame peer length is outside safe bounds".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_LABEL);
    hasher.update(previous_chain);
    hasher.update(sequence.to_le_bytes());
    hasher.update((record.peer.len() as u16).to_le_bytes());
    hasher.update(&record.peer);
    hasher.update(record.digest);
    hasher.update([u8::from(record.repeatable)]);
    Ok(hasher.finalize().into())
}

fn record_plaintext(record: &ControlRecord) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if record.peer.is_empty() || record.peer.len() > MAX_CONTROL_PEER_BYTES {
        return Err(StorageError::InvalidProfile(
            "control frame peer length is outside safe bounds".to_owned(),
        ));
    }
    let length = 1 + 2 + record.peer.len() + 32 + 1;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    bytes.push(RECORD_VERSION);
    bytes.extend_from_slice(&(record.peer.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&record.peer);
    bytes.extend_from_slice(&record.digest);
    bytes.push(u8::from(record.repeatable));
    Ok(bytes)
}

fn parse_record(bytes: &[u8]) -> Result<ControlRecord, StorageError> {
    let invalid = || StorageError::InvalidProfile("malformed control log record".to_owned());
    if bytes.len() < 1 + 2 + 32 + 1 {
        return Err(invalid());
    }
    if bytes[0] != RECORD_VERSION {
        return Err(invalid());
    }
    let peer_len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
    if peer_len == 0 || peer_len > MAX_CONTROL_PEER_BYTES {
        return Err(invalid());
    }
    let expected = 1 + 2 + peer_len + 32 + 1;
    if bytes.len() != expected {
        return Err(invalid());
    }
    let index = 3;
    let peer = bytes[index..index + peer_len].to_vec();
    let digest: [u8; 32] = fixed(
        &bytes[index + peer_len..index + peer_len + 32],
        "frame digest",
    )?;
    let repeatable = match bytes[expected - 1] {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    Ok(ControlRecord {
        peer,
        digest,
        repeatable,
    })
}

fn anchor_plaintext(state: &ControlLogState) -> [u8; ANCHOR_PLAINTEXT_BYTES] {
    let mut bytes = [0u8; ANCHOR_PLAINTEXT_BYTES];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC);
    bytes[8] = ANCHOR_VERSION;
    bytes[9..17].copy_from_slice(&state.sequence.to_le_bytes());
    bytes[17..].copy_from_slice(&state.chain);
    bytes
}

fn parse_anchor(bytes: &[u8]) -> Result<ControlLogState, StorageError> {
    let invalid = || StorageError::RollbackDetected;
    if bytes.len() != ANCHOR_PLAINTEXT_BYTES || &bytes[..8] != ANCHOR_MAGIC {
        return Err(invalid());
    }
    if bytes[8] != ANCHOR_VERSION {
        return Err(invalid());
    }
    let sequence = u64::from_le_bytes(bytes[9..17].try_into().map_err(|_| invalid())?);
    let chain: [u8; 32] = fixed(&bytes[17..], "control anchor chain")?;
    Ok(ControlLogState { sequence, chain })
}

impl Session {
    fn anchor_path(&self) -> PathBuf {
        self.vault_dir.join(ANCHOR_FILE)
    }

    fn anchor_aad(&self) -> Vec<u8> {
        tagged_aad(ANCHOR_AAD, &self.profile_id)
    }

    fn frame_index(&self, peer: &[u8], digest: &[u8; 32], repeatable: bool) -> Vec<u8> {
        let mut input = Vec::with_capacity(INDEX_LABEL.len() + peer.len() + digest.len() + 1);
        input.extend_from_slice(INDEX_LABEL);
        input.extend_from_slice(peer);
        input.extend_from_slice(digest);
        input.push(u8::from(repeatable));
        self.subkeys.blind_index(&input).to_vec()
    }

    /// Read the current authenticated control-log high-water mark.
    pub fn control_log_state(&self) -> Result<ControlLogState, StorageError> {
        let (sequence, chain): (i64, Vec<u8>) = self.conn.query_row(
            "SELECT sequence, chain FROM control_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let sequence = u64::try_from(sequence)
            .map_err(|_| StorageError::ControlLogIntegrity("negative log sequence".to_owned()))?;
        if sequence > MAX_CONTROL_LOG_ENTRIES {
            return Err(StorageError::ControlLogIntegrity(
                "log sequence exceeds the configured bound".to_owned(),
            ));
        }
        Ok(ControlLogState {
            sequence,
            chain: fixed(&chain, "control state chain")?,
        })
    }

    /// Verify every encrypted record, its chain link, and the separate anchor.
    pub fn verify_control_log(&self) -> Result<ControlLogState, StorageError> {
        let state = self.control_log_state()?;
        let mut expected_sequence = 0u64;
        let mut previous_chain = ZERO_CHAIN;
        let mut statement = self.conn.prepare(
            "SELECT sequence, record_bi, ciphertext, chain_hash FROM control_log ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        for row in rows {
            let (raw_sequence, stored_index, ciphertext, stored_chain) = row?;
            let sequence = u64::try_from(raw_sequence).map_err(|_| {
                StorageError::ControlLogIntegrity("negative record sequence".to_owned())
            })?;
            if sequence != expected_sequence + 1 {
                return Err(StorageError::ControlLogIntegrity(
                    "control log sequence is not contiguous".to_owned(),
                ));
            }
            let plaintext = decrypt_bytes(
                &self.subkeys.derive(Purpose::Db),
                &ciphertext,
                &record_aad(&self.profile_id, sequence, &previous_chain),
            )?;
            let record = parse_record(&plaintext)?;
            if self.frame_index(&record.peer, &record.digest, record.repeatable) != stored_index {
                return Err(StorageError::ControlLogIntegrity(
                    "control record blind index mismatch".to_owned(),
                ));
            }
            let chain = chain_hash(&previous_chain, sequence, &record)?;
            if fixed(&stored_chain, "control record chain")? != chain {
                return Err(StorageError::ControlLogIntegrity(
                    "control record chain mismatch".to_owned(),
                ));
            }
            previous_chain = chain;
            expected_sequence = sequence;
        }
        if expected_sequence != state.sequence || previous_chain != state.chain {
            return Err(StorageError::ControlLogIntegrity(
                "control state does not match the record chain".to_owned(),
            ));
        }
        self.verify_anchor(&state)?;
        Ok(state)
    }

    /// Record one already authenticated signed frame. Terminal frames and
    /// acknowledgements are non-repeatable; KeyPackage and group-join requests
    /// stay idempotent so a lost response can still be retried in one session.
    pub fn record_control_frame(
        &mut self,
        peer: &[u8],
        digest: &[u8; 32],
        repeatable: bool,
    ) -> Result<ControlRecordOutcome, StorageError> {
        if peer.is_empty() || peer.len() > MAX_CONTROL_PEER_BYTES {
            return Err(StorageError::InvalidProfile(
                "control frame peer length is outside safe bounds".to_owned(),
            ));
        }
        let repeatable_index = self.frame_index(peer, digest, true);
        let terminal_index = self.frame_index(peer, digest, false);
        let replay_sequence: Option<i64> = self
            .conn
            .query_row(
                "SELECT sequence FROM control_log WHERE record_bi = ?1",
                params![terminal_index],
                |row| row.get(0),
            )
            .optional()?;
        let idempotent_sequence: Option<i64> = self
            .conn
            .query_row(
                "SELECT sequence FROM control_log WHERE record_bi = ?1",
                params![repeatable_index],
                |row| row.get(0),
            )
            .optional()?;
        let has_replay = replay_sequence.is_some();
        if let Some(raw_sequence) = replay_sequence.or(idempotent_sequence) {
            let sequence = u64::try_from(raw_sequence).map_err(|_| {
                StorageError::ControlLogIntegrity("negative record sequence".to_owned())
            })?;
            return Ok(if has_replay {
                ControlRecordOutcome::Replay(sequence)
            } else {
                ControlRecordOutcome::Idempotent(sequence)
            });
        }

        let state = self.control_log_state()?;
        if state.sequence >= MAX_CONTROL_LOG_ENTRIES {
            return Err(StorageError::ControlLogFull);
        }
        let sequence = state.sequence + 1;
        let index = if repeatable {
            repeatable_index
        } else {
            terminal_index
        };
        let record = ControlRecord {
            peer: peer.to_vec(),
            digest: *digest,
            repeatable,
        };
        let ciphertext = encrypt_bytes(
            &self.subkeys.derive(Purpose::Db),
            &record_plaintext(&record)?,
            &record_aad(&self.profile_id, sequence, &state.chain),
        )?;
        let chain = chain_hash(&state.chain, sequence, &record)?;
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "INSERT INTO control_log (sequence, record_bi, ciphertext, chain_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                i64::try_from(sequence).map_err(|_| StorageError::ControlLogFull)?,
                index,
                ciphertext,
                chain.to_vec(),
            ],
        )?;
        transaction.execute(
            "UPDATE control_state SET sequence = ?1, chain = ?2 WHERE id = 1",
            params![
                i64::try_from(sequence).map_err(|_| StorageError::ControlLogFull)?,
                chain.to_vec(),
            ],
        )?;
        transaction.commit()?;

        let new_state = ControlLogState { sequence, chain };
        self.write_anchor(&new_state)?;
        Ok(ControlRecordOutcome::Appended(sequence))
    }

    fn read_anchor(&self) -> Result<Option<ControlLogState>, StorageError> {
        let path = self.anchor_path();
        reject_symlink(&path)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(StorageError::RollbackDetected);
        }
        let plaintext = decrypt_bytes(
            &self.subkeys.derive(Purpose::Db),
            &bytes,
            &self.anchor_aad(),
        )
        .map_err(|_| StorageError::RollbackDetected)?;
        Ok(Some(
            parse_anchor(&plaintext).map_err(|_| StorageError::RollbackDetected)?,
        ))
    }

    fn write_anchor(&self, state: &ControlLogState) -> Result<(), StorageError> {
        let path = self.anchor_path();
        reject_symlink(&path)?;
        let bytes = encrypt_bytes(
            &self.subkeys.derive(Purpose::Db),
            &anchor_plaintext(state),
            &self.anchor_aad(),
        )?;
        let temporary = self.vault_dir.join(ANCHOR_TEMP);
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        restrict_file(&temporary)?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    fn verify_anchor(&self, state: &ControlLogState) -> Result<(), StorageError> {
        match self.read_anchor()? {
            None if state.sequence == 0 => self.write_anchor(state),
            None => Err(StorageError::RollbackDetected),
            Some(anchor) => {
                if anchor.sequence > state.sequence
                    || (anchor.sequence == state.sequence && anchor.chain != state.chain)
                {
                    return Err(StorageError::RollbackDetected);
                }
                if anchor.sequence < state.sequence {
                    // A crash after the database commit but before the anchor
                    // rename leaves the anchor behind; bring it forward.
                    self.write_anchor(state)?;
                }
                Ok(())
            }
        }
    }

    /// Create the initial zero-sequence anchor for a new vault.
    pub(crate) fn initialize_control_log(&self) -> Result<(), StorageError> {
        let state = self.control_log_state()?;
        if state.sequence != 0 || state.chain != ZERO_CHAIN {
            return Err(StorageError::ControlLogIntegrity(
                "new vault has a non-empty control log".to_owned(),
            ));
        }
        self.write_anchor(&state)
    }
}
