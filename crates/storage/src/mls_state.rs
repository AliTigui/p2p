//! Encrypted, chained local state for future OpenMLS group restoration.
//!
//! This module implements the encrypted persistence foundation for ADR-0014
//! Phases 1–3. It stores opaque OpenMLS provider values as XChaCha20-Poly1305
//! ciphertext with HMAC blind indexes, recomputes per-group chains, and
//! atomically applies staged provider writes. Controller restore is deferred:
//! no controller behavior changes here.

use std::fmt;

use p2p_crypto::{Purpose, Subkeys, decrypt_bytes, encrypt_bytes};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::control_log::write_current_anchor_to;
use super::{
    MLS_KEY_VERSION_DEDICATED, MLS_KEY_VERSION_LEGACY, Session, StorageError, fixed, index_input,
    tagged_aad,
};

const STATE_AAD: &[u8] = b"p2p-messenger/mls-state/v1";
const GROUP_AAD: &[u8] = b"p2p-messenger/mls-group/v1";
const GROUP_INDEX: &[u8] = b"p2p-messenger/mls-group-index/v1";
const ENTITY_INDEX: &[u8] = b"p2p-messenger/mls-entity-index/v1";
const CHAIN_LABEL: &[u8] = b"p2p-messenger/mls-state-chain/v1";

const RECORD_VERSION: u8 = 1;
const ZERO_CHAIN: [u8; 32] = [0u8; 32];
const MAX_LABEL_BYTES: usize = 64;
const MAX_KEY_BYTES: usize = 256;

/// Maximum opaque provider value accepted for one MLS state entity.
pub const MAX_MLS_STATE_BYTES: usize = 1024 * 1024;
/// Finite number of encrypted MLS state rows across all groups.
pub const MAX_MLS_STATE_ENTRIES: u64 = 4096;
/// Finite number of distinct groups tracked by the local MLS state store.
pub const MAX_MLS_GROUPS: u64 = 64;
/// Reserved provider bucket for OpenMLS entries that are not tied to a group,
/// such as pending KeyPackages and PSKs. It is authenticated like any other
/// group row but is not an application conversation.
pub const GLOBAL_PROVIDER_GROUP: [u8; 16] = *b"P2PMLSGLOBALROOT";

/// One provider write staged by the `StorageProvider` adapter. `value = None`
/// is a tombstone: the matching encrypted row is removed by the flush.
pub(crate) struct StagedMlsWrite {
    pub group_id: [u8; 16],
    pub label: String,
    pub key: Vec<u8>,
    pub epoch: u64,
    pub value: Option<Zeroizing<Vec<u8>>>,
}

/// One decrypted provider entry returned for a future `MlsGroup::load` call.
pub struct MlsStateEntry {
    pub label: String,
    pub entity_key: Vec<u8>,
    pub epoch: u64,
    pub value: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MlsStateEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlsStateEntry")
            .field("label_len", &self.label.len())
            .field("entity_key_len", &self.entity_key.len())
            .field("epoch", &self.epoch)
            .field("value", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct StateRecord {
    epoch: u64,
    label: String,
    entity_key: Vec<u8>,
    value: Zeroizing<Vec<u8>>,
}

struct GroupRow {
    group_id: [u8; 16],
    epoch: u64,
    chain: [u8; 32],
}

/// One authenticated per-group high-water mark stored in the version-2 anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MlsWatermark {
    pub group_bi: [u8; 32],
    pub epoch: u64,
    pub chain: [u8; 32],
}

fn group_index(subkeys: &Subkeys, group_id: &[u8; 16]) -> [u8; 32] {
    subkeys.blind_index(&index_input(GROUP_INDEX, group_id, &[]))
}

fn entity_index(subkeys: &Subkeys, group_id: &[u8; 16], label: &str, key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(group_id.len() + 2 + label.len() + 2 + key.len());
    input.extend_from_slice(group_id);
    input.extend_from_slice(&(label.len() as u16).to_le_bytes());
    input.extend_from_slice(label.as_bytes());
    input.extend_from_slice(&(key.len() as u16).to_le_bytes());
    input.extend_from_slice(key);
    subkeys.blind_index(&index_input(ENTITY_INDEX, group_id, &input))
}

fn group_aad(profile_id: &[u8; 16], group_bi: &[u8; 32]) -> Vec<u8> {
    let mut aad = tagged_aad(GROUP_AAD, profile_id);
    aad.extend_from_slice(group_bi);
    aad
}

fn state_aad(
    profile_id: &[u8; 16],
    group_bi: &[u8; 32],
    entity_bi: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut aad = tagged_aad(STATE_AAD, profile_id);
    aad.push(RECORD_VERSION);
    aad.extend_from_slice(group_bi);
    aad.extend_from_slice(entity_bi);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

fn chain_hash(
    previous: &[u8; 32],
    group_bi: &[u8; 32],
    entity_bi: &[u8; 32],
    epoch: u64,
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_LABEL);
    hasher.update(previous);
    hasher.update(group_bi);
    hasher.update(entity_bi);
    hasher.update(epoch.to_le_bytes());
    hasher.update(Sha256::digest(ciphertext));
    hasher.finalize().into()
}

fn record_plaintext(record: &StateRecord) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if record.label.is_empty() || record.label.len() > MAX_LABEL_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "MLS state label length is outside safe bounds".to_owned(),
        ));
    }
    if record.entity_key.len() > MAX_KEY_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "MLS state key length is outside safe bounds".to_owned(),
        ));
    }
    if record.value.is_empty() || record.value.len() > MAX_MLS_STATE_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "MLS state value length is outside safe bounds".to_owned(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        1 + 8 + 2 + record.label.len() + 2 + record.entity_key.len() + record.value.len(),
    ));
    bytes.push(RECORD_VERSION);
    bytes.extend_from_slice(&record.epoch.to_le_bytes());
    bytes.extend_from_slice(&(record.label.len() as u16).to_le_bytes());
    bytes.extend_from_slice(record.label.as_bytes());
    bytes.extend_from_slice(&(record.entity_key.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&record.entity_key);
    bytes.extend_from_slice(&record.value);
    Ok(bytes)
}

fn parse_record(bytes: &[u8], expected_epoch: u64) -> Result<StateRecord, StorageError> {
    let mut cursor = 0usize;
    let version = *bytes
        .get(cursor)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state record is empty".to_owned()))?;
    cursor += 1;
    if version != RECORD_VERSION {
        return Err(StorageError::MlsStateIntegrity(
            "unsupported MLS state record version".to_owned(),
        ));
    }
    let epoch_bytes: [u8; 8] = bytes
        .get(cursor..cursor + 8)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state epoch is truncated".to_owned()))?
        .try_into()
        .map_err(|_| StorageError::MlsStateIntegrity("state epoch is truncated".to_owned()))?;
    cursor += 8;
    let epoch = u64::from_le_bytes(epoch_bytes);
    if epoch != expected_epoch {
        return Err(StorageError::MlsStateIntegrity(
            "state epoch does not match its authenticated index".to_owned(),
        ));
    }

    let label_len_bytes: [u8; 2] = bytes
        .get(cursor..cursor + 2)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state label is truncated".to_owned()))?
        .try_into()
        .map_err(|_| StorageError::MlsStateIntegrity("state label is truncated".to_owned()))?;
    cursor += 2;
    let label_len = usize::from(u16::from_le_bytes(label_len_bytes));
    if label_len == 0 || label_len > MAX_LABEL_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "state label length is outside safe bounds".to_owned(),
        ));
    }
    let label_bytes = bytes
        .get(cursor..cursor + label_len)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state label is truncated".to_owned()))?;
    cursor += label_len;
    let label = String::from_utf8(label_bytes.to_vec()).map_err(|_| {
        StorageError::MlsStateIntegrity("state label is not valid UTF-8".to_owned())
    })?;

    let key_len_bytes: [u8; 2] = bytes
        .get(cursor..cursor + 2)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state key is truncated".to_owned()))?
        .try_into()
        .map_err(|_| StorageError::MlsStateIntegrity("state key is truncated".to_owned()))?;
    cursor += 2;
    let key_len = usize::from(u16::from_le_bytes(key_len_bytes));
    if key_len > MAX_KEY_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "state key length is outside safe bounds".to_owned(),
        ));
    }
    let entity_key = bytes
        .get(cursor..cursor + key_len)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state key is truncated".to_owned()))?
        .to_vec();
    cursor += key_len;

    let value = bytes
        .get(cursor..)
        .ok_or_else(|| StorageError::MlsStateIntegrity("state value is truncated".to_owned()))?;
    if value.is_empty() || value.len() > MAX_MLS_STATE_BYTES {
        return Err(StorageError::MlsStateIntegrity(
            "state value length is outside safe bounds".to_owned(),
        ));
    }
    Ok(StateRecord {
        epoch,
        label,
        entity_key,
        value: Zeroizing::new(value.to_vec()),
    })
}

fn read_group_bi(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    profile_id: &[u8; 16],
    group_bi: &[u8; 32],
) -> Result<Option<GroupRow>, StorageError> {
    let row: Option<(Vec<u8>, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT ciphertext, epoch, chain FROM mls_groups WHERE group_bi = ?1",
            params![group_bi.to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((ciphertext, raw_epoch, chain)) = row else {
        return Ok(None);
    };
    let epoch = u64::try_from(raw_epoch)
        .map_err(|_| StorageError::MlsStateIntegrity("MLS group epoch is negative".to_owned()))?;
    let plaintext = decrypt_bytes(key, &ciphertext, &group_aad(profile_id, group_bi))?;
    let group_id = fixed::<16>(&plaintext, "MLS group id")?;
    Ok(Some(GroupRow {
        group_id,
        epoch,
        chain: fixed(&chain, "MLS group chain")?,
    }))
}

fn ensure_group_row(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
    group_id: &[u8; 16],
) -> Result<[u8; 32], StorageError> {
    let group_bi = group_index(subkeys, group_id);
    if read_group_bi(conn, key, profile_id, &group_bi)?.is_some() {
        return Ok(group_bi);
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM mls_groups", [], |row| row.get(0))?;
    if u64::try_from(count).unwrap_or(u64::MAX) >= MAX_MLS_GROUPS {
        return Err(StorageError::MlsStateFull);
    }
    let ciphertext = encrypt_bytes(key, group_id, &group_aad(profile_id, &group_bi))?;
    conn.execute(
        "INSERT INTO mls_groups (group_bi, ciphertext, epoch, chain)
         VALUES (?1, ?2, 0, ?3)",
        params![group_bi.to_vec(), ciphertext, ZERO_CHAIN.to_vec()],
    )?;
    Ok(group_bi)
}

fn recompute_group_chain(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
    group_id: &[u8; 16],
    group_bi: &[u8; 32],
    update_rows: bool,
) -> Result<(u64, [u8; 32]), StorageError> {
    let mut statement = conn.prepare(
        "SELECT entity_bi, epoch, ciphertext, chain_hash FROM mls_state
         WHERE group_bi = ?1 ORDER BY entity_bi",
    )?;
    let rows = statement.query_map(params![group_bi.to_vec()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;

    let mut previous = ZERO_CHAIN;
    let mut max_epoch = 0u64;
    let mut updates = Vec::new();
    for row in rows {
        let (raw_entity_bi, raw_epoch, ciphertext, stored_chain) = row?;
        let entity_bi = fixed::<32>(&raw_entity_bi, "MLS entity index")?;
        let epoch = u64::try_from(raw_epoch).map_err(|_| {
            StorageError::MlsStateIntegrity("MLS state epoch is negative".to_owned())
        })?;
        let plaintext = decrypt_bytes(
            key,
            &ciphertext,
            &state_aad(profile_id, group_bi, &entity_bi, epoch),
        )?;
        let record = parse_record(&plaintext, epoch)?;
        if entity_index(subkeys, group_id, &record.label, &record.entity_key) != entity_bi {
            return Err(StorageError::MlsStateIntegrity(
                "MLS entity blind index mismatch".to_owned(),
            ));
        }
        let chain = chain_hash(&previous, group_bi, &entity_bi, epoch, &ciphertext);
        if fixed::<32>(&stored_chain, "MLS state chain")? != chain {
            if !update_rows {
                return Err(StorageError::MlsStateIntegrity(
                    "MLS state chain mismatch".to_owned(),
                ));
            }
            updates.push((entity_bi, chain));
        }
        previous = chain;
        max_epoch = max_epoch.max(epoch);
    }
    drop(statement);
    if update_rows {
        let mut update = conn.prepare(
            "UPDATE mls_state SET chain_hash = ?1
             WHERE group_bi = ?2 AND entity_bi = ?3",
        )?;
        for (entity_bi, chain) in updates {
            update.execute(params![
                chain.to_vec(),
                group_bi.to_vec(),
                entity_bi.to_vec()
            ])?;
        }
    }
    Ok((max_epoch, previous))
}

/// Fully verify the encrypted MLS tables and return their authenticated
/// per-group high-water marks in stable blind-index order.
pub(crate) fn collect_mls_watermarks(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    subkeys: &Subkeys,
    profile_id: &[u8; 16],
) -> Result<Vec<MlsWatermark>, StorageError> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM mls_state", [], |row| row.get(0))?;
    if u64::try_from(count).unwrap_or(u64::MAX) > MAX_MLS_STATE_ENTRIES {
        return Err(StorageError::MlsStateFull);
    }
    let mut statement = conn
        .prepare("SELECT group_bi, ciphertext, epoch, chain FROM mls_groups ORDER BY group_bi")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut watermarks = Vec::new();
    for (raw_group_bi, ciphertext, raw_epoch, raw_chain) in rows {
        let group_bi = fixed::<32>(&raw_group_bi, "MLS group index")?;
        let plaintext = decrypt_bytes(key, &ciphertext, &group_aad(profile_id, &group_bi))?;
        let group_id = fixed::<16>(&plaintext, "MLS group id")?;
        if group_index(subkeys, &group_id) != group_bi {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group blind index mismatch".to_owned(),
            ));
        }
        let epoch = u64::try_from(raw_epoch).map_err(|_| {
            StorageError::MlsStateIntegrity("MLS group epoch is negative".to_owned())
        })?;
        let chain = fixed::<32>(&raw_chain, "MLS group chain")?;
        let (computed_epoch, computed_chain) =
            recompute_group_chain(conn, key, subkeys, profile_id, &group_id, &group_bi, false)?;
        if epoch != computed_epoch || chain != computed_chain {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group state does not match its chain".to_owned(),
            ));
        }
        // The reserved global provider bucket is verified and anchored, but it
        // is not an application conversation and must not consume the group
        // budget.
        if u64::try_from(watermarks.len()).unwrap_or(u64::MAX) > MAX_MLS_GROUPS {
            return Err(StorageError::MlsStateFull);
        }
        watermarks.push(MlsWatermark {
            group_bi,
            epoch,
            chain,
        });
    }
    let orphan: Option<i64> = conn
        .query_row(
            "SELECT COUNT(*) FROM mls_state s
             WHERE NOT EXISTS (SELECT 1 FROM mls_groups g WHERE g.group_bi = s.group_bi)",
            [],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if orphan.unwrap_or(0) != 0 {
        return Err(StorageError::MlsStateIntegrity(
            "MLS state has an unknown group".to_owned(),
        ));
    }
    Ok(watermarks)
}

impl Session {
    /// Key protecting this vault's MLS rows. New vaults use a dedicated
    /// purpose; legacy vaults keep the general DB key they were written with.
    pub(crate) fn mls_key(&self) -> Zeroizing<[u8; 32]> {
        match self.mls_key_version {
            MLS_KEY_VERSION_DEDICATED => self.subkeys.derive(Purpose::MlsState),
            MLS_KEY_VERSION_LEGACY => self.subkeys.derive(Purpose::Db),
            _ => unreachable!("read_profile rejects unknown MLS key versions"),
        }
    }

    /// Store one opaque OpenMLS provider value. The caller supplies only
    /// already authenticated provider state; this method stores it as
    /// ciphertext with blind indexes and a group-chained integrity link.
    pub fn store_mls_state(
        &mut self,
        group_id: &[u8; 16],
        label: &str,
        key: &[u8],
        epoch: u64,
        value: &[u8],
    ) -> Result<(), StorageError> {
        let storage_key = self.mls_key();
        let group_bi = self.group_index(group_id);
        let expected_group_bi = group_bi;
        let entity_bi = self.entity_index(group_id, label, key);
        let record = StateRecord {
            epoch,
            label: label.to_owned(),
            entity_key: key.to_vec(),
            value: Zeroizing::new(value.to_vec()),
        };
        let ciphertext = encrypt_bytes(
            &storage_key,
            &record_plaintext(&record)?,
            &state_aad(&self.profile_id, &group_bi, &entity_bi, epoch),
        )?;
        let vault_dir = self.vault_dir.clone();
        let subkeys = self.subkeys.clone();
        let profile_id = self.profile_id;

        let transaction = self.conn.transaction()?;
        let group_bi = ensure_group_row(
            &transaction,
            &storage_key,
            &self.subkeys,
            &self.profile_id,
            group_id,
        )?;
        if group_bi != expected_group_bi {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group index changed during storage".to_owned(),
            ));
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM mls_state", [], |row| row.get(0))?;
        if u64::try_from(count).unwrap_or(u64::MAX) >= MAX_MLS_STATE_ENTRIES {
            return Err(StorageError::MlsStateFull);
        }
        transaction.execute(
            "INSERT INTO mls_state (group_bi, entity_bi, epoch, ciphertext, chain_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_bi, entity_bi) DO UPDATE SET
                 epoch = excluded.epoch,
                 ciphertext = excluded.ciphertext",
            params![
                group_bi.to_vec(),
                entity_bi.to_vec(),
                i64::try_from(epoch).map_err(|_| StorageError::MlsStateFull)?,
                ciphertext,
                ZERO_CHAIN.to_vec(),
            ],
        )?;
        let (chain_epoch, chain) = recompute_group_chain(
            &transaction,
            &storage_key,
            &self.subkeys,
            &self.profile_id,
            group_id,
            &group_bi,
            true,
        )?;
        transaction.execute(
            "UPDATE mls_groups SET epoch = ?1, chain = ?2 WHERE group_bi = ?3",
            params![
                i64::try_from(chain_epoch).map_err(|_| StorageError::MlsStateFull)?,
                chain.to_vec(),
                group_bi.to_vec(),
            ],
        )?;
        // Install the new watermark before committing the database change. A
        // crash after this point leaves the anchor ahead and fails closed, so
        // an older database cannot silently replace the newer MLS state.
        write_current_anchor_to(
            &vault_dir,
            &subkeys,
            &profile_id,
            &transaction,
            &storage_key,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Apply one complete staged MLS operation as a single SQLite transaction.
    /// Every write or tombstone is encrypted/verified first, then all rows and
    /// group chains are updated inside one transaction and the v2 anchor is
    /// installed before the commit. A failure anywhere rolls the whole set
    /// back and leaves neither partial rows nor a partial anchor behind.
    pub(crate) fn apply_staged_writes(
        &mut self,
        writes: &[StagedMlsWrite],
    ) -> Result<(), StorageError> {
        if writes.is_empty() {
            return Ok(());
        }
        let storage_key = self.mls_key();
        let vault_dir = self.vault_dir.clone();
        let subkeys = self.subkeys.clone();
        let profile_id = self.profile_id;

        // Validate and encrypt every value before opening the transaction so a
        // bad entry cannot leave a half-applied operation behind.
        let mut prepared = Vec::with_capacity(writes.len());
        let mut groups = std::collections::BTreeSet::new();
        for write in writes {
            let group_bi = group_index(&subkeys, &write.group_id);
            let entity_bi = entity_index(&subkeys, &write.group_id, &write.label, &write.key);
            let ciphertext = match &write.value {
                Some(value) => {
                    let record = StateRecord {
                        epoch: write.epoch,
                        label: write.label.clone(),
                        entity_key: write.key.clone(),
                        value: value.clone(),
                    };
                    Some(encrypt_bytes(
                        &storage_key,
                        &record_plaintext(&record)?,
                        &state_aad(&profile_id, &group_bi, &entity_bi, write.epoch),
                    )?)
                }
                None => None,
            };
            groups.insert(write.group_id);
            prepared.push((write.group_id, group_bi, entity_bi, write.epoch, ciphertext));
        }

        let transaction = self.conn.transaction()?;
        for (group_id, group_bi, entity_bi, epoch, ciphertext) in &prepared {
            // Only a real write creates a group row. A tombstone for a group
            // that never existed must not leave an empty group behind.
            if let Some(ciphertext) = ciphertext {
                ensure_group_row(&transaction, &storage_key, &subkeys, &profile_id, group_id)?;
                transaction.execute(
                    "INSERT INTO mls_state (group_bi, entity_bi, epoch, ciphertext, chain_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(group_bi, entity_bi) DO UPDATE SET
                         epoch = excluded.epoch,
                         ciphertext = excluded.ciphertext",
                    params![
                        group_bi.to_vec(),
                        entity_bi.to_vec(),
                        i64::try_from(*epoch).map_err(|_| StorageError::MlsStateFull)?,
                        ciphertext.as_slice(),
                        ZERO_CHAIN.to_vec(),
                    ],
                )?;
            }
        }

        // Remove tombstones after all inserts so a key replaced in the same
        // operation is not deleted by an earlier tombstone.
        for (group_bi, entity_bi, ciphertext) in prepared
            .iter()
            .map(|(_, group_bi, entity_bi, _, ciphertext)| (group_bi, entity_bi, ciphertext))
        {
            if ciphertext.is_none() {
                transaction.execute(
                    "DELETE FROM mls_state WHERE group_bi = ?1 AND entity_bi = ?2",
                    params![group_bi.to_vec(), entity_bi.to_vec()],
                )?;
            }
        }

        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM mls_state", [], |row| row.get(0))?;
        if u64::try_from(count).unwrap_or(u64::MAX) > MAX_MLS_STATE_ENTRIES {
            return Err(StorageError::MlsStateFull);
        }

        // Recompute and persist every affected group chain, then advance the
        // anchor from the transaction state before committing.
        for group_id in groups {
            let group_bi = group_index(&subkeys, &group_id);
            let (epoch, chain) = recompute_group_chain(
                &transaction,
                &storage_key,
                &subkeys,
                &profile_id,
                &group_id,
                &group_bi,
                true,
            )?;
            transaction.execute(
                "UPDATE mls_groups SET epoch = ?1, chain = ?2 WHERE group_bi = ?3",
                params![
                    i64::try_from(epoch).map_err(|_| StorageError::MlsStateFull)?,
                    chain.to_vec(),
                    group_bi.to_vec(),
                ],
            )?;
        }
        write_current_anchor_to(
            &vault_dir,
            &subkeys,
            &profile_id,
            &transaction,
            &storage_key,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn group_index(&self, group_id: &[u8; 16]) -> [u8; 32] {
        group_index(&self.subkeys, group_id)
    }

    fn entity_index(&self, group_id: &[u8; 16], label: &str, key: &[u8]) -> [u8; 32] {
        entity_index(&self.subkeys, group_id, label, key)
    }

    /// Load one opaque provider value. `None` means no such authenticated row.
    pub fn load_mls_state(
        &self,
        group_id: &[u8; 16],
        label: &str,
        key: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let storage_key = self.mls_key();
        let group_bi = self.group_index(group_id);
        let entity_bi = self.entity_index(group_id, label, key);
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT epoch, ciphertext FROM mls_state
                 WHERE group_bi = ?1 AND entity_bi = ?2",
                params![group_bi.to_vec(), entity_bi.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((raw_epoch, ciphertext)) = row else {
            return Ok(None);
        };
        let epoch = u64::try_from(raw_epoch).map_err(|_| {
            StorageError::MlsStateIntegrity("MLS state epoch is negative".to_owned())
        })?;
        let plaintext = decrypt_bytes(
            &storage_key,
            &ciphertext,
            &state_aad(&self.profile_id, &group_bi, &entity_bi, epoch),
        )?;
        let record = parse_record(&plaintext, epoch)?;
        if record.label != label || record.entity_key != key {
            return Err(StorageError::MlsStateIntegrity(
                "MLS state label or key does not match its blind index".to_owned(),
            ));
        }
        Ok(Some(record.value))
    }

    /// Load every opaque provider value for one group, ordered by blind index.
    pub fn load_mls_state_group(
        &self,
        group_id: &[u8; 16],
    ) -> Result<Vec<MlsStateEntry>, StorageError> {
        self.verify_anchor_full()?;
        self.verify_mls_state_group(group_id)?;
        let storage_key = self.mls_key();
        let group_bi = self.group_index(group_id);
        let mut statement = self.conn.prepare(
            "SELECT entity_bi, epoch, ciphertext FROM mls_state
             WHERE group_bi = ?1 ORDER BY entity_bi",
        )?;
        let rows = statement.query_map(params![group_bi.to_vec()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (raw_entity_bi, raw_epoch, ciphertext) = row?;
            let entity_bi = fixed::<32>(&raw_entity_bi, "MLS entity index")?;
            let epoch = u64::try_from(raw_epoch).map_err(|_| {
                StorageError::MlsStateIntegrity("MLS state epoch is negative".to_owned())
            })?;
            let plaintext = decrypt_bytes(
                &storage_key,
                &ciphertext,
                &state_aad(&self.profile_id, &group_bi, &entity_bi, epoch),
            )?;
            let record = parse_record(&plaintext, epoch)?;
            if self.entity_index(group_id, &record.label, &record.entity_key) != entity_bi {
                return Err(StorageError::MlsStateIntegrity(
                    "MLS entity blind index mismatch".to_owned(),
                ));
            }
            entries.push(MlsStateEntry {
                label: record.label,
                entity_key: record.entity_key,
                epoch,
                value: record.value,
            });
        }
        Ok(entries)
    }

    /// Group identifiers whose encrypted MLS state is present in this vault.
    pub fn mls_group_ids(&self) -> Result<Vec<[u8; 16]>, StorageError> {
        let storage_key = self.mls_key();
        let mut statement = self
            .conn
            .prepare("SELECT group_bi, ciphertext FROM mls_groups ORDER BY group_bi")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut ids = Vec::new();
        for row in rows {
            let (raw_group_bi, ciphertext) = row?;
            let group_bi = fixed::<32>(&raw_group_bi, "MLS group index")?;
            let plaintext = decrypt_bytes(
                &storage_key,
                &ciphertext,
                &group_aad(&self.profile_id, &group_bi),
            )?;
            let group_id = fixed::<16>(&plaintext, "MLS group id")?;
            if group_id == GLOBAL_PROVIDER_GROUP {
                continue;
            }
            if self.group_index(&group_id) != group_bi {
                return Err(StorageError::MlsStateIntegrity(
                    "MLS group blind index mismatch".to_owned(),
                ));
            }
            ids.push(group_id);
        }
        Ok(ids)
    }

    /// Delete one group's encrypted state. This is explicit local deletion,
    /// not a claim of secure erasure.
    pub fn delete_mls_state_group(&mut self, group_id: &[u8; 16]) -> Result<(), StorageError> {
        let group_bi = self.group_index(group_id).to_vec();
        let storage_key = self.mls_key();
        let vault_dir = self.vault_dir.clone();
        let subkeys = self.subkeys.clone();
        let profile_id = self.profile_id;
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "DELETE FROM mls_state WHERE group_bi = ?1",
            params![group_bi],
        )?;
        transaction.execute(
            "DELETE FROM mls_groups WHERE group_bi = ?1",
            params![group_bi],
        )?;
        // Anchor first: a database restored to a state where this group still
        // exists must not be accepted after an explicit deletion.
        write_current_anchor_to(
            &vault_dir,
            &subkeys,
            &profile_id,
            &transaction,
            &storage_key,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn verify_mls_state_group(&self, group_id: &[u8; 16]) -> Result<(), StorageError> {
        let storage_key = self.mls_key();
        let group_bi = self.group_index(group_id);
        let Some(row) = read_group_bi(&self.conn, &storage_key, &self.profile_id, &group_bi)?
        else {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group state is missing".to_owned(),
            ));
        };
        if row.group_id != *group_id {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group identity mismatch".to_owned(),
            ));
        }
        let (epoch, chain) = recompute_group_chain(
            &self.conn,
            &storage_key,
            &self.subkeys,
            &self.profile_id,
            group_id,
            &group_bi,
            false,
        )?;
        if epoch != row.epoch || chain != row.chain {
            return Err(StorageError::MlsStateIntegrity(
                "MLS group state does not match its chain".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verify every encrypted MLS state row, group chain, and the version-2
    /// anchor watermarks. Called on unlock so damage or database-only rollback
    /// fails closed before any MLS use.
    pub fn verify_mls_state(&self) -> Result<(), StorageError> {
        self.verify_anchor_full()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use p2p_identity::Identity;

    use super::super::{StorageError, Vault};
    use super::*;

    fn vault_session(directory: &std::path::Path) -> Session {
        let vault = Vault::open(directory).expect("open vault");
        let identity = Identity::generate().expect("identity");
        vault
            .create("mls-state-unit", "mls-state-password", &identity)
            .expect("create vault")
    }

    fn staged_write(group_id: [u8; 16], key: Vec<u8>, epoch: u64, value: &[u8]) -> StagedMlsWrite {
        StagedMlsWrite {
            group_id,
            label: "OwnLeafNodeIndex".to_owned(),
            key,
            epoch,
            value: Some(Zeroizing::new(value.to_vec())),
        }
    }

    /// Apply a valid MLS write and install the matching anchor from inside the
    /// still-open transaction, then deliberately roll back without committing.
    /// This is the exact interruption point an anchor-first write exposes.
    fn interrupt_anchor_first_write(session: &mut Session, group_id: [u8; 16]) {
        let storage_key = session.mls_key();
        let subkeys = session.subkeys.clone();
        let profile_id = session.profile_id;
        let vault_dir = session.vault_dir.clone();
        let group_bi = group_index(&subkeys, &group_id);
        let key = b"interrupted".to_vec();
        let entity_bi = entity_index(&subkeys, &group_id, "OwnLeafNodeIndex", &key);
        let record = StateRecord {
            epoch: 1,
            label: "OwnLeafNodeIndex".to_owned(),
            entity_key: key.clone(),
            value: Zeroizing::new(b"interrupted-value".to_vec()),
        };
        let ciphertext = encrypt_bytes(
            &storage_key,
            &record_plaintext(&record).expect("record plaintext"),
            &state_aad(&profile_id, &group_bi, &entity_bi, 1),
        )
        .expect("encrypt interrupted write");

        let transaction = session.conn.transaction().expect("begin interrupted write");
        let group_bi =
            ensure_group_row(&transaction, &storage_key, &subkeys, &profile_id, &group_id)
                .expect("ensure group row");
        transaction
            .execute(
                "INSERT INTO mls_state (group_bi, entity_bi, epoch, ciphertext, chain_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    group_bi.to_vec(),
                    entity_bi.to_vec(),
                    1_i64,
                    ciphertext,
                    ZERO_CHAIN.to_vec(),
                ],
            )
            .expect("insert interrupted row");
        let (epoch, chain) = recompute_group_chain(
            &transaction,
            &storage_key,
            &subkeys,
            &profile_id,
            &group_id,
            &group_bi,
            true,
        )
        .expect("recompute interrupted chain");
        transaction
            .execute(
                "UPDATE mls_groups SET epoch = ?1, chain = ?2 WHERE group_bi = ?3",
                params![epoch as i64, chain.to_vec(), group_bi.to_vec()],
            )
            .expect("update interrupted group");
        super::super::control_log::write_current_anchor_to(
            &vault_dir,
            &subkeys,
            &profile_id,
            &transaction,
            &storage_key,
        )
        .expect("install interrupted anchor");
        drop(transaction);
    }

    /// Apply a valid MLS deletion and install the matching anchor from inside
    /// the still-open transaction, then deliberately roll back without
    /// committing.
    fn interrupt_anchor_first_delete(session: &mut Session, group_id: [u8; 16]) {
        let storage_key = session.mls_key();
        let group_bi = session.group_index(&group_id).to_vec();
        let transaction = session
            .conn
            .transaction()
            .expect("begin interrupted delete");
        transaction
            .execute(
                "DELETE FROM mls_state WHERE group_bi = ?1",
                params![group_bi.clone()],
            )
            .expect("delete interrupted rows");
        transaction
            .execute(
                "DELETE FROM mls_groups WHERE group_bi = ?1",
                params![group_bi],
            )
            .expect("delete interrupted group");
        super::super::control_log::write_current_anchor_to(
            &session.vault_dir,
            &session.subkeys,
            &session.profile_id,
            &transaction,
            &storage_key,
        )
        .expect("install interrupted delete anchor");
        drop(transaction);
    }

    #[test]
    fn staged_writes_enforce_the_global_entry_cap() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut session = vault_session(directory.path());
        let group = [1u8; 16];
        let writes = (0..MAX_MLS_STATE_ENTRIES as u32)
            .map(|index| staged_write(group, index.to_le_bytes().to_vec(), 1, b"entry"))
            .collect::<Vec<_>>();
        session.apply_staged_writes(&writes).expect("fill to cap");

        let overflow = staged_write(
            group,
            (MAX_MLS_STATE_ENTRIES as u32).to_le_bytes().to_vec(),
            1,
            b"overflow",
        );
        assert!(matches!(
            session.apply_staged_writes(&[overflow]),
            Err(StorageError::MlsStateFull)
        ));
    }

    #[test]
    fn staged_writes_enforce_the_group_cap() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut session = vault_session(directory.path());
        let writes = (1..=MAX_MLS_GROUPS as u8)
            .map(|byte| staged_write([byte; 16], b"key".to_vec(), 1, b"entry"))
            .collect::<Vec<_>>();
        session
            .apply_staged_writes(&writes)
            .expect("fill group cap");
        assert_eq!(
            session.mls_group_ids().expect("group ids").len(),
            MAX_MLS_GROUPS as usize
        );

        let overflow = staged_write(
            [(MAX_MLS_GROUPS + 1) as u8; 16],
            b"key".to_vec(),
            1,
            b"overflow",
        );
        assert!(matches!(
            session.apply_staged_writes(&[overflow]),
            Err(StorageError::MlsStateFull)
        ));
        assert_eq!(
            session
                .mls_group_ids()
                .expect("group ids after rollback")
                .len(),
            MAX_MLS_GROUPS as usize
        );
    }

    #[test]
    fn interrupted_anchor_first_write_fails_closed_until_the_anchor_is_restored() {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let identity = Identity::generate().expect("identity");
        let _initial = vault
            .create("mls-state-unit", "mls-state-password", &identity)
            .expect("create vault");
        let anchor_path = directory.path().join("control.anchor");
        let baseline = fs::read(&anchor_path).expect("baseline anchor");
        drop(_initial);

        let mut session = vault.unlock("mls-state-password").expect("unlock");
        interrupt_anchor_first_write(&mut session, [31u8; 16]);
        assert_ne!(
            fs::read(&anchor_path).expect("advanced anchor"),
            baseline,
            "the anchor must be installed before the database commit"
        );
        drop(session);
        assert!(matches!(
            vault.unlock("mls-state-password"),
            Err(StorageError::RollbackDetected)
        ));

        fs::write(&anchor_path, &baseline).expect("restore interrupted anchor");
        let recovered = vault
            .unlock("mls-state-password")
            .expect("recover from baseline");
        assert!(
            recovered
                .mls_group_ids()
                .expect("no committed group")
                .is_empty(),
            "the interrupted write must not survive its rolled-back transaction"
        );
    }

    #[test]
    fn interrupted_anchor_first_delete_fails_closed_until_the_anchor_is_restored() {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let identity = Identity::generate().expect("identity");
        let group = [32u8; 16];
        {
            let mut session = vault
                .create("mls-state-unit", "mls-state-password", &identity)
                .expect("create vault");
            session
                .store_mls_state(&group, "tree", b"node", 1, b"delete-me")
                .expect("store state");
        }
        let anchor_path = directory.path().join("control.anchor");
        let baseline = fs::read(&anchor_path).expect("baseline anchor");

        let mut session = vault.unlock("mls-state-password").expect("unlock");
        interrupt_anchor_first_delete(&mut session, group);
        assert_ne!(
            fs::read(&anchor_path).expect("advanced anchor"),
            baseline,
            "the delete anchor must be installed before the database commit"
        );
        drop(session);
        assert!(matches!(
            vault.unlock("mls-state-password"),
            Err(StorageError::RollbackDetected)
        ));

        fs::write(&anchor_path, &baseline).expect("restore interrupted anchor");
        let recovered = vault
            .unlock("mls-state-password")
            .expect("recover from baseline");
        assert_eq!(
            recovered.mls_group_ids().expect("committed group"),
            vec![group],
            "the interrupted deletion must not survive its rolled-back transaction"
        );
    }

    #[test]
    fn new_vault_encrypts_mls_state_with_the_dedicated_purpose() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut session = vault_session(directory.path());
        let group = [41u8; 16];
        let label = "OwnLeafNodeIndex";
        let key = b"dedicated".to_vec();
        session
            .store_mls_state(&group, label, &key, 1, b"secret-mls-state")
            .expect("store MLS state");

        let group_bi = session.group_index(&group);
        let entity_bi = session.entity_index(&group, label, &key);
        let ciphertext: Vec<u8> = session
            .conn
            .query_row(
                "SELECT ciphertext FROM mls_state WHERE group_bi = ?1 AND entity_bi = ?2",
                params![group_bi.to_vec(), entity_bi.to_vec()],
                |row| row.get(0),
            )
            .expect("stored ciphertext");
        let aad = state_aad(&session.profile_id, &group_bi, &entity_bi, 1);
        let dedicated = session.subkeys.derive(Purpose::MlsState);
        let legacy = session.subkeys.derive(Purpose::Db);

        assert!(
            decrypt_bytes(&dedicated, &ciphertext, &aad).is_ok(),
            "the dedicated MLS key must decrypt the row"
        );
        assert!(
            decrypt_bytes(&legacy, &ciphertext, &aad).is_err(),
            "the general DB key must not decrypt an MLS row"
        );
    }

    #[test]
    fn legacy_mls_key_version_keeps_legacy_vaults_readable() {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let identity = Identity::generate().expect("identity");
        {
            let session = vault
                .create("mls-state-unit", "mls-state-password", &identity)
                .expect("create vault");
            assert_eq!(session.mls_key_version, MLS_KEY_VERSION_DEDICATED);
            let salts = super::super::flatten_salts(session.subkeys.salts());
            let legacy_len = (Purpose::ALL.len() - 1) * super::super::SALT_LEN;
            session
                .conn
                .execute(
                    "UPDATE profile SET subkey_salts = ?1, mls_key_version = ?2 WHERE id = 1",
                    params![salts[..legacy_len].to_vec(), MLS_KEY_VERSION_LEGACY],
                )
                .expect("convert the profile to the legacy layout");
        }

        let mut session = vault
            .unlock("mls-state-password")
            .expect("unlock legacy-layout vault");
        assert_eq!(session.mls_key_version, MLS_KEY_VERSION_LEGACY);
        let group = [42u8; 16];
        session
            .store_mls_state(&group, "tree", b"node", 1, b"legacy-value")
            .expect("store under the legacy key");

        let group_bi = session.group_index(&group);
        let entity_bi = session.entity_index(&group, "tree", b"node");
        let ciphertext: Vec<u8> = session
            .conn
            .query_row(
                "SELECT ciphertext FROM mls_state WHERE group_bi = ?1 AND entity_bi = ?2",
                params![group_bi.to_vec(), entity_bi.to_vec()],
                |row| row.get(0),
            )
            .expect("stored ciphertext");
        let aad = state_aad(&session.profile_id, &group_bi, &entity_bi, 1);
        assert!(
            decrypt_bytes(&session.subkeys.derive(Purpose::Db), &ciphertext, &aad).is_ok(),
            "legacy rows must stay readable with the DB key"
        );
        assert!(
            decrypt_bytes(
                &session.subkeys.derive(Purpose::MlsState),
                &ciphertext,
                &aad
            )
            .is_err(),
            "legacy rows must not silently switch keys"
        );
    }

    #[test]
    fn corrupt_mls_key_version_fails_closed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let identity = Identity::generate().expect("identity");
        {
            let session = vault
                .create("mls-state-unit", "mls-state-password", &identity)
                .expect("create vault");
            session
                .conn
                .execute("UPDATE profile SET mls_key_version = 9 WHERE id = 1", [])
                .expect("corrupt MLS key version");
        }
        assert!(matches!(
            vault.unlock("mls-state-password"),
            Err(StorageError::InvalidProfile(_))
        ));
    }
}
