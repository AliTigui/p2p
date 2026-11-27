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
use std::path::{Path, PathBuf};

use p2p_crypto::{NONCE_LEN, Purpose, Subkeys, TAG_LEN, decrypt_bytes, encrypt_bytes};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::mls_state::{MAX_MLS_GROUPS, MlsWatermark, collect_mls_watermarks};
use super::{Session, StorageError, fixed, reject_symlink, restrict_file, tagged_aad};

const ANCHOR_FILE: &str = "control.anchor";
const ANCHOR_TEMP: &str = "control.anchor.tmp";
const ANCHOR_AAD_V1: &[u8] = b"p2p-messenger/control-anchor/v1";
const ANCHOR_AAD_V2: &[u8] = b"p2p-messenger/control-anchor/v2";
const RECORD_AAD: &[u8] = b"p2p-messenger/control-log/v1";
const INDEX_LABEL: &[u8] = b"p2p-messenger/control-frame/v1";
const CHAIN_LABEL: &[u8] = b"p2p-messenger/control-chain/v1";
const ANCHOR_MAGIC_V1: &[u8] = b"P2PANCH1";
const ANCHOR_MAGIC_V2: &[u8] = b"P2PANCH2";
const ANCHOR_VERSION_V1: u8 = 1;
const ANCHOR_VERSION_V2: u8 = 2;
const RECORD_VERSION: u8 = 1;
const ZERO_CHAIN: [u8; 32] = [0u8; 32];

/// Maximum authenticated peer identifier length accepted by the control log.
pub const MAX_CONTROL_PEER_BYTES: usize = 64;
/// Finite replay window. The log fails closed instead of dropping old records.
pub const MAX_CONTROL_LOG_ENTRIES: u64 = 4096;

const ANCHOR_V1_PLAINTEXT_BYTES: usize = 8 + 1 + 8 + 32;
const ANCHOR_V2_HEADER_BYTES: usize = 8 + 1 + 8 + 32 + 2;
const MLS_WATERMARK_BYTES: usize = 32 + 8 + 32;
const ANCHOR_V2_PLAINTEXT_BYTES: usize =
    ANCHOR_V2_HEADER_BYTES + MAX_MLS_GROUPS as usize * MLS_WATERMARK_BYTES;
const MAX_ANCHOR_BYTES: usize = ANCHOR_V2_PLAINTEXT_BYTES + NONCE_LEN + TAG_LEN;

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

/// Versioned contents of the local anchor file. Version 1 covers only the
/// control log; version 2 also carries bounded per-group MLS watermarks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnchorState {
    V1(ControlLogState),
    V2 {
        control: ControlLogState,
        mls: Vec<MlsWatermark>,
    },
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

fn anchor_plaintext_v1(state: &ControlLogState) -> [u8; ANCHOR_V1_PLAINTEXT_BYTES] {
    let mut bytes = [0u8; ANCHOR_V1_PLAINTEXT_BYTES];
    bytes[..8].copy_from_slice(ANCHOR_MAGIC_V1);
    bytes[8] = ANCHOR_VERSION_V1;
    bytes[9..17].copy_from_slice(&state.sequence.to_le_bytes());
    bytes[17..].copy_from_slice(&state.chain);
    bytes
}

fn anchor_plaintext_v2(state: &AnchorState) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let AnchorState::V2 { control, mls } = state else {
        return Err(StorageError::RollbackDetected);
    };
    if u64::try_from(mls.len()).unwrap_or(u64::MAX) > MAX_MLS_GROUPS {
        return Err(StorageError::RollbackDetected);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(ANCHOR_V2_HEADER_BYTES));
    bytes.extend_from_slice(ANCHOR_MAGIC_V2);
    bytes.push(ANCHOR_VERSION_V2);
    bytes.extend_from_slice(&control.sequence.to_le_bytes());
    bytes.extend_from_slice(&control.chain);
    bytes.extend_from_slice(&(mls.len() as u16).to_le_bytes());
    for entry in mls {
        bytes.extend_from_slice(&entry.group_bi);
        bytes.extend_from_slice(&entry.epoch.to_le_bytes());
        bytes.extend_from_slice(&entry.chain);
    }
    Ok(bytes)
}

fn parse_anchor(bytes: &[u8]) -> Result<AnchorState, StorageError> {
    let invalid = || StorageError::RollbackDetected;
    let magic = bytes.get(..8).ok_or_else(invalid)?;
    if magic == ANCHOR_MAGIC_V1 {
        if bytes.len() != ANCHOR_V1_PLAINTEXT_BYTES || bytes[8] != ANCHOR_VERSION_V1 {
            return Err(invalid());
        }
        let sequence = u64::from_le_bytes(bytes[9..17].try_into().map_err(|_| invalid())?);
        let chain: [u8; 32] = fixed(&bytes[17..], "control anchor chain")?;
        return Ok(AnchorState::V1(ControlLogState { sequence, chain }));
    }
    if magic != ANCHOR_MAGIC_V2 {
        return Err(invalid());
    }
    if bytes.len() < ANCHOR_V2_HEADER_BYTES || bytes[8] != ANCHOR_VERSION_V2 {
        return Err(invalid());
    }
    let sequence = u64::from_le_bytes(bytes[9..17].try_into().map_err(|_| invalid())?);
    let chain: [u8; 32] = fixed(&bytes[17..49], "control anchor chain")?;
    let count = usize::from(u16::from_le_bytes(
        bytes[49..51].try_into().map_err(|_| invalid())?,
    ));
    if count > MAX_MLS_GROUPS as usize {
        return Err(invalid());
    }
    let expected_len = ANCHOR_V2_HEADER_BYTES + count * MLS_WATERMARK_BYTES;
    if bytes.len() != expected_len {
        return Err(invalid());
    }
    let mut mls = Vec::with_capacity(count);
    let mut cursor = ANCHOR_V2_HEADER_BYTES;
    let mut previous: Option<[u8; 32]> = None;
    for _ in 0..count {
        let group_bi: [u8; 32] = fixed(&bytes[cursor..cursor + 32], "MLS anchor group index")?;
        cursor += 32;
        if previous.is_some_and(|previous| group_bi <= previous) {
            return Err(invalid());
        }
        previous = Some(group_bi);
        let epoch = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| invalid())?,
        );
        cursor += 8;
        if epoch > i64::MAX as u64 {
            return Err(invalid());
        }
        let anchor_chain: [u8; 32] = fixed(&bytes[cursor..cursor + 32], "MLS anchor chain")?;
        cursor += 32;
        mls.push(MlsWatermark {
            group_bi,
            epoch,
            chain: anchor_chain,
        });
    }
    Ok(AnchorState::V2 {
        control: ControlLogState { sequence, chain },
        mls,
    })
}

/// Accept an exact anchor match or a one-record lag left by the database-first
/// control-log write. Larger gaps fail closed instead of being silently brought
/// forward.
fn check_control_anchor(
    anchor: &ControlLogState,
    expected: &ControlLogState,
) -> Result<(), StorageError> {
    let too_far_behind = match anchor.sequence.checked_add(1) {
        Some(next) => next < expected.sequence,
        None => true,
    };
    if too_far_behind
        || anchor.sequence > expected.sequence
        || (anchor.sequence == expected.sequence && anchor.chain != expected.chain)
    {
        return Err(StorageError::RollbackDetected);
    }
    Ok(())
}

fn control_log_state_from(conn: &Connection) -> Result<ControlLogState, StorageError> {
    let (sequence, chain): (i64, Vec<u8>) = conn.query_row(
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

pub(crate) fn anchor_state_from_conn(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
) -> Result<AnchorState, StorageError> {
    Ok(AnchorState::V2 {
        control: control_log_state_from(conn)?,
        mls: collect_mls_watermarks(conn, key, subkeys, profile_id)?,
    })
}

fn anchor_aad_for(profile_id: &[u8; 16], version: u8) -> Vec<u8> {
    let tag = match version {
        ANCHOR_VERSION_V1 => ANCHOR_AAD_V1,
        ANCHOR_VERSION_V2 => ANCHOR_AAD_V2,
        _ => ANCHOR_AAD_V2,
    };
    tagged_aad(tag, profile_id)
}

fn anchor_path_in(vault_dir: &Path) -> PathBuf {
    vault_dir.join(ANCHOR_FILE)
}

fn write_anchor_state_to(
    vault_dir: &Path,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
    state: &AnchorState,
) -> Result<(), StorageError> {
    let path = anchor_path_in(vault_dir);
    reject_symlink(&path)?;
    let (version, plaintext) = match state {
        AnchorState::V1(control) => (
            ANCHOR_VERSION_V1,
            Zeroizing::new(anchor_plaintext_v1(control).to_vec()),
        ),
        AnchorState::V2 { .. } => (ANCHOR_VERSION_V2, anchor_plaintext_v2(state)?),
    };
    let bytes = encrypt_bytes(
        &subkeys.derive(Purpose::Db),
        &plaintext,
        &anchor_aad_for(profile_id, version),
    )?;
    let temporary = vault_dir.join(ANCHOR_TEMP);
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

/// Write a complete anchor from a connection, including one still inside an
/// open MLS write transaction. Callers pass the derived fields separately so
/// the transaction can keep its mutable borrow of the session connection.
pub(crate) fn write_current_anchor_to(
    vault_dir: &Path,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
    conn: &Connection,
    mls_key: &Zeroizing<[u8; 32]>,
) -> Result<(), StorageError> {
    let state = anchor_state_from_conn(conn, mls_key, subkeys, profile_id)?;
    write_anchor_state_to(vault_dir, subkeys, profile_id, &state)
}

impl Session {
    fn anchor_path(&self) -> PathBuf {
        self.vault_dir.join(ANCHOR_FILE)
    }

    fn anchor_aad(&self, version: u8) -> Vec<u8> {
        anchor_aad_for(&self.profile_id, version)
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
        control_log_state_from(&self.conn)
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
        self.verify_anchor_full()?;
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

        self.write_current_anchor(&self.conn)?;
        Ok(ControlRecordOutcome::Appended(sequence))
    }

    /// Write a complete anchor snapshot derived from a connection.
    pub(crate) fn write_current_anchor(&self, conn: &Connection) -> Result<(), StorageError> {
        write_current_anchor_to(
            &self.vault_dir,
            &self.subkeys,
            &self.profile_id,
            conn,
            &self.mls_key(),
        )
    }

    fn read_anchor(&self) -> Result<Option<AnchorState>, StorageError> {
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
        let key = self.subkeys.derive(Purpose::Db);
        for version in [ANCHOR_VERSION_V2, ANCHOR_VERSION_V1] {
            if let Ok(plaintext) = decrypt_bytes(&key, &bytes, &self.anchor_aad(version)) {
                let state = parse_anchor(&plaintext).map_err(|_| StorageError::RollbackDetected)?;
                return Ok(Some(state));
            }
        }
        Err(StorageError::RollbackDetected)
    }

    fn write_anchor_state(&self, state: &AnchorState) -> Result<(), StorageError> {
        write_anchor_state_to(&self.vault_dir, &self.subkeys, &self.profile_id, state)
    }

    /// Verify the v2 anchor against both the control log and the encrypted MLS
    /// state. A v1 anchor is migrated after both databases verify. A control
    /// log anchor that lags by one crash window is brought forward; larger gaps
    /// fail closed. Any MLS mismatch fails closed instead of being silently
    /// blessed.
    pub(crate) fn verify_anchor_full(&self) -> Result<AnchorState, StorageError> {
        let control = self.control_log_state()?;
        let key = self.mls_key();
        let mls = collect_mls_watermarks(&self.conn, &key, &self.subkeys, &self.profile_id)?;
        match self.read_anchor()? {
            None => {
                if control.sequence == 0 && control.chain == ZERO_CHAIN && mls.is_empty() {
                    let state = AnchorState::V2 { control, mls };
                    self.write_anchor_state(&state)?;
                    Ok(state)
                } else {
                    Err(StorageError::RollbackDetected)
                }
            }
            Some(AnchorState::V1(anchor_control)) => {
                check_control_anchor(&anchor_control, &control)?;
                let state = AnchorState::V2 { control, mls };
                self.write_anchor_state(&state)?;
                Ok(state)
            }
            Some(AnchorState::V2 {
                control: anchor_control,
                mls: anchor_mls,
            }) => {
                check_control_anchor(&anchor_control, &control)?;
                if anchor_mls != mls {
                    return Err(StorageError::RollbackDetected);
                }
                if anchor_control != control {
                    // A crash after the control database commit but before the
                    // anchor rename leaves only the control field behind.
                    let state = AnchorState::V2 { control, mls };
                    self.write_anchor_state(&state)?;
                    Ok(state)
                } else {
                    Ok(AnchorState::V2 {
                        control: anchor_control,
                        mls: anchor_mls,
                    })
                }
            }
        }
    }

    /// Create the initial v2 anchor for a new vault.
    pub(crate) fn initialize_control_log(&self) -> Result<(), StorageError> {
        let state = self.control_log_state()?;
        if state.sequence != 0 || state.chain != ZERO_CHAIN {
            return Err(StorageError::ControlLogIntegrity(
                "new vault has a non-empty control log".to_owned(),
            ));
        }
        self.write_current_anchor(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use p2p_identity::Identity;

    const USERNAME: &str = "anchor-user";
    const PASSWORD: &str = "anchor-password";

    #[test]
    fn v1_anchor_is_migrated_and_control_log_stays_verified() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory.path()).expect("open vault");

        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .record_control_frame(b"12D3KooWANCHORV1", &[6u8; 32], false)
            .expect("record frame");
        let state = session.control_log_state().expect("control state");
        session
            .write_anchor_state(&AnchorState::V1(state))
            .expect("write v1 anchor");
        drop(session);

        let reopened = vault.unlock(PASSWORD).expect("unlock migrates v1 anchor");
        assert_eq!(
            reopened.control_log_state().expect("state").sequence,
            1,
            "control log survives migration"
        );
        reopened.verify_control_log().expect("verify control log");
        reopened.verify_mls_state().expect("verify MLS state");
        assert!(
            matches!(
                reopened.read_anchor().expect("read migrated anchor"),
                Some(AnchorState::V2 { .. })
            ),
            "anchor is now version 2"
        );
    }

    #[test]
    fn full_control_log_fails_closed_instead_of_dropping_replay_state() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory.path()).expect("open vault");
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");

        session
            .conn
            .execute(
                "UPDATE control_state SET sequence = ?1",
                [i64::try_from(MAX_CONTROL_LOG_ENTRIES).expect("sequence fits")],
            )
            .expect("advance control log to its cap");

        assert!(matches!(
            session.record_control_frame(b"12D3KooWFULLLOG", &[5u8; 32], false),
            Err(StorageError::ControlLogFull)
        ));
    }

    #[test]
    fn valid_v2_anchor_with_wrong_mls_epoch_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory.path()).expect("open vault");

        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_mls_state(&[31u8; 16], "tree", b"node", 4, b"ANCHOR_WATERMARK_31")
            .expect("store MLS state");
        let mut anchor = session
            .read_anchor()
            .expect("read anchor")
            .expect("anchor exists");
        let AnchorState::V2 { mls, .. } = &mut anchor else {
            panic!("new vault must use a v2 anchor");
        };
        assert_eq!(mls.len(), 1);
        mls[0].epoch = 5;
        session
            .write_anchor_state(&anchor)
            .expect("write authenticated but mismatched anchor");
        drop(session);

        assert!(matches!(
            vault.unlock(PASSWORD),
            Err(StorageError::RollbackDetected)
        ));
    }

    #[test]
    fn control_anchor_lagging_by_one_crash_window_is_brought_forward() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory.path()).expect("open vault");

        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .record_control_frame(b"12D3KooWANCHORLAG", &[7u8; 32], false)
            .expect("first frame");
        let stale = session
            .read_anchor()
            .expect("read stale anchor")
            .expect("anchor exists");
        session
            .record_control_frame(b"12D3KooWANCHORLAG", &[8u8; 32], false)
            .expect("second frame");
        session
            .write_anchor_state(&stale)
            .expect("write one-record stale anchor");
        drop(session);

        let reopened = vault.unlock(PASSWORD).expect("one-window lag catch-up");
        assert_eq!(
            reopened
                .control_log_state()
                .expect("control state")
                .sequence,
            2
        );
        assert!(matches!(
            reopened.read_anchor().expect("catch-up anchor"),
            Some(AnchorState::V2 { control, .. }) if control.sequence == 2
        ));
    }

    #[test]
    fn control_anchor_lagging_by_more_than_one_window_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate().expect("identity");
        let vault = Vault::open(directory.path()).expect("open vault");

        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .record_control_frame(b"12D3KooWANCHORLAG", &[9u8; 32], false)
            .expect("first frame");
        let stale = session
            .read_anchor()
            .expect("read stale anchor")
            .expect("anchor exists");
        session
            .record_control_frame(b"12D3KooWANCHORLAG", &[10u8; 32], false)
            .expect("second frame");
        session
            .record_control_frame(b"12D3KooWANCHORLAG", &[11u8; 32], false)
            .expect("third frame");
        session
            .write_anchor_state(&stale)
            .expect("write multi-record stale anchor");
        drop(session);

        assert!(matches!(
            vault.unlock(PASSWORD),
            Err(StorageError::RollbackDetected)
        ));
    }
}
