//! Encrypted attachment blobs stored beside the vault database.
//!
//! The database contains only blind indexes, wrapped per-file keys, and
//! encrypted metadata. Blob files contain only XChaCha20-Poly1305 ciphertext.
//! A password change rewraps only the vault master key, never these blobs.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use p2p_crypto::{KEY_LEN, Purpose, decrypt_bytes, encrypt_bytes, unwrap_key, wrap_key};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Session, StorageError, fixed, index_input, now_seconds, random_bytes, tagged_aad};

pub(super) const ATTACHMENT_DIR: &str = "attachments";

/// Upper bound for one decrypted attachment. This matches the file-transfer
/// plaintext bound without importing the file crate into the storage layer.
pub const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

const ATTACHMENT_META_VERSION: u8 = 1;
const MAX_ATTACHMENT_NAME_BYTES: usize = 255;
const MAX_ATTACHMENT_FORMAT_BYTES: usize = 16;
const ATTACHMENT_ID_INDEX: &[u8] = b"p2p-messenger/attachment-id/v1";
const ATTACHMENT_DATA_AAD: &[u8] = b"p2p-messenger/attachment-data/v1";
const ATTACHMENT_META_AAD: &[u8] = b"p2p-messenger/attachment-metadata/v1";
const ATTACHMENT_KEY_AAD: &[u8] = b"p2p-messenger/attachment-key-wrap/v1";

/// Non-secret view model for one encrypted attachment. The name and format
/// label are decrypted only into memory for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// Blind index of the random attachment ID. It is also the blob filename.
    pub id: [u8; 32],
    pub name: String,
    pub size: u64,
    pub format: Option<String>,
    pub inserted_at: i64,
}

struct AttachmentMeta {
    name: String,
    size: u64,
    plaintext_hash: [u8; 32],
    format: Option<String>,
}

impl Session {
    /// Store one verified file as an encrypted attachment. The name, digest,
    /// and format label are encrypted inside the metadata blob; no plaintext
    /// filename or content key is written to SQLite or the blob directory.
    /// The returned 32-byte blind index identifies the stored attachment.
    pub fn store_attachment(
        &self,
        name: &str,
        bytes: &[u8],
        plaintext_hash: [u8; 32],
        format: Option<&str>,
    ) -> Result<[u8; 32], StorageError> {
        validate_name(name)?;
        validate_format(format)?;
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(StorageError::InvalidAttachmentSize);
        }

        let id = random_bytes::<16>()?;
        let blind =
            self.subkeys
                .blind_index(&index_input(ATTACHMENT_ID_INDEX, &self.profile_id, &id));
        let data_aad = attachment_aad(ATTACHMENT_DATA_AAD, &self.profile_id, &blind);
        let meta_aad = attachment_aad(ATTACHMENT_META_AAD, &self.profile_id, &blind);
        let key_aad = attachment_aad(ATTACHMENT_KEY_AAD, &self.profile_id, &blind);

        let file_key = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let wrapped_key = wrap_key(
            &file_key,
            &self.subkeys.derive(Purpose::Attachments),
            &key_aad,
        )?;
        let ciphertext = encrypt_bytes(&file_key, bytes, &data_aad)?;
        if ciphertext.len() > MAX_ATTACHMENT_BYTES + 64 {
            return Err(StorageError::InvalidAttachmentSize);
        }

        let meta = AttachmentMeta {
            name: name.to_owned(),
            size: u64::try_from(bytes.len()).map_err(|_| StorageError::InvalidAttachmentSize)?,
            plaintext_hash,
            format: format.map(str::to_owned),
        };
        let encrypted_meta = encrypt_bytes(&file_key, &encode_meta(&meta), &meta_aad)?;

        let blob_path = self.attachment_blob_path(&blind);
        write_new_restricted(&blob_path, &ciphertext)?;
        if let Err(error) = self.conn.execute(
            "INSERT INTO attachments (attachment_bi, wrapped_key, encrypted_metadata, inserted_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![blind.to_vec(), wrapped_key, encrypted_meta, now_seconds()?,],
        ) {
            let _ = fs::remove_file(&blob_path);
            return Err(error.into());
        }
        Ok(blind)
    }

    /// List encrypted attachments with only non-secret metadata exposed.
    pub fn attachment_infos(&self) -> Result<Vec<AttachmentInfo>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT attachment_bi, wrapped_key, encrypted_metadata, inserted_at
             FROM attachments ORDER BY inserted_at, rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        let mut infos = Vec::new();
        for row in rows {
            let (blind_bytes, wrapped_key, encrypted_meta, inserted_at) = row?;
            let blind = fixed::<32>(&blind_bytes, "attachment id")?;
            let file_key = self.unwrap_attachment_key(&wrapped_key, &blind)?;
            let meta_aad = attachment_aad(ATTACHMENT_META_AAD, &self.profile_id, &blind);
            let meta_bytes = decrypt_bytes(&file_key, &encrypted_meta, &meta_aad)?;
            let meta = decode_meta(&meta_bytes)?;
            infos.push(AttachmentInfo {
                id: blind,
                name: meta.name,
                size: meta.size,
                format: meta.format,
                inserted_at,
            });
        }
        Ok(infos)
    }

    /// Decrypt one attachment into a zeroizing in-memory buffer. The stored
    /// digest is rechecked, so a swapped or damaged blob fails closed.
    pub fn read_attachment(&self, id: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let (wrapped_key, encrypted_meta) = self
            .conn
            .query_row(
                "SELECT wrapped_key, encrypted_metadata FROM attachments WHERE attachment_bi = ?1",
                params![id.to_vec()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StorageError::from)?
            .ok_or(StorageError::AttachmentNotFound)?;

        let file_key = self.unwrap_attachment_key(&wrapped_key, id)?;
        let meta_aad = attachment_aad(ATTACHMENT_META_AAD, &self.profile_id, id);
        let meta_bytes = decrypt_bytes(&file_key, &encrypted_meta, &meta_aad)?;
        let meta = decode_meta(&meta_bytes)?;

        let blob_path = self.attachment_blob_path(id);
        let blob_meta = fs::symlink_metadata(&blob_path)?;
        if blob_meta.file_type().is_symlink() || !blob_meta.is_file() {
            return Err(StorageError::InvalidAttachment(
                "attachment blob is not a regular file".to_owned(),
            ));
        }
        if blob_meta.len() > u64::try_from(MAX_ATTACHMENT_BYTES + 64).unwrap_or(u64::MAX) {
            return Err(StorageError::InvalidAttachmentSize);
        }
        let ciphertext = fs::read(&blob_path)?;
        let data_aad = attachment_aad(ATTACHMENT_DATA_AAD, &self.profile_id, id);
        let plaintext = decrypt_bytes(&file_key, &ciphertext, &data_aad)?;
        if plaintext.len() as u64 != meta.size {
            return Err(StorageError::InvalidAttachment(
                "attachment size does not match metadata".to_owned(),
            ));
        }
        if Sha256::digest(plaintext.as_slice()) != meta.plaintext_hash {
            return Err(StorageError::InvalidAttachment(
                "attachment digest does not match metadata".to_owned(),
            ));
        }
        Ok(plaintext)
    }

    /// Explicitly delete one encrypted attachment and its ciphertext blob.
    /// This is never implied by scan, approval, integrity verification, or
    /// release state. Filesystem deletion is not secure erasure on SSD/CoW
    /// storage.
    pub fn delete_attachment(&self, id: &[u8; 32]) -> Result<(), StorageError> {
        let blob_path = self.attachment_blob_path(id);
        // Check the blob before deleting the record so an unsafe path fails
        // closed without orphaning a live database entry. Filesystem deletion
        // is not secure erasure on SSD/CoW storage.
        match fs::symlink_metadata(&blob_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StorageError::InvalidAttachment(
                    "attachment blob is a symlink".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let deleted = self.conn.execute(
            "DELETE FROM attachments WHERE attachment_bi = ?1",
            params![id.to_vec()],
        )?;
        if deleted == 0 {
            return Err(StorageError::AttachmentNotFound);
        }
        match fs::remove_file(&blob_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn unwrap_attachment_key(
        &self,
        wrapped_key: &[u8],
        blind: &[u8; 32],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, StorageError> {
        let key_aad = attachment_aad(ATTACHMENT_KEY_AAD, &self.profile_id, blind);
        Ok(unwrap_key(
            wrapped_key,
            &self.subkeys.derive(Purpose::Attachments),
            &key_aad,
        )?)
    }

    fn attachment_blob_path(&self, blind: &[u8; 32]) -> PathBuf {
        self.attachment_dir.join(format!("{}.ct", hex(blind)))
    }
}

fn attachment_aad(tag: &[u8], profile_id: &[u8; 16], blind: &[u8; 32]) -> Vec<u8> {
    let mut aad = tagged_aad(tag, profile_id);
    aad.extend_from_slice(blind);
    aad
}

fn validate_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > MAX_ATTACHMENT_NAME_BYTES
        || name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
    {
        return Err(StorageError::InvalidAttachment(
            "invalid attachment name".to_owned(),
        ));
    }
    Ok(())
}

fn validate_format(format: Option<&str>) -> Result<(), StorageError> {
    if let Some(label) = format
        && (label.is_empty()
            || label.len() > MAX_ATTACHMENT_FORMAT_BYTES
            || !label
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err(StorageError::InvalidAttachment(
            "invalid attachment format label".to_owned(),
        ));
    }
    Ok(())
}

fn encode_meta(meta: &AttachmentMeta) -> Vec<u8> {
    let name_len = u16::try_from(meta.name.len()).expect("validated name length");
    let mut bytes = Vec::with_capacity(1 + 2 + meta.name.len() + 8 + 32 + 1 + 2);
    bytes.push(ATTACHMENT_META_VERSION);
    bytes.extend_from_slice(&name_len.to_le_bytes());
    bytes.extend_from_slice(meta.name.as_bytes());
    bytes.extend_from_slice(&meta.size.to_le_bytes());
    bytes.extend_from_slice(&meta.plaintext_hash);
    match &meta.format {
        None => bytes.push(0),
        Some(label) => {
            let format_len = u16::try_from(label.len()).expect("validated format length");
            bytes.push(1);
            bytes.extend_from_slice(&format_len.to_le_bytes());
            bytes.extend_from_slice(label.as_bytes());
        }
    }
    bytes
}

fn decode_meta(bytes: &[u8]) -> Result<AttachmentMeta, StorageError> {
    let mut position = 0;
    let version = *take(bytes, &mut position, 1)?
        .first()
        .ok_or_else(|| StorageError::InvalidAttachment("empty metadata".to_owned()))?;
    if version != ATTACHMENT_META_VERSION {
        return Err(StorageError::InvalidAttachment(
            "unsupported attachment metadata version".to_owned(),
        ));
    }
    let name_len = u16::from_le_bytes(fixed::<2>(
        take(bytes, &mut position, 2)?,
        "attachment name length",
    )?) as usize;
    if name_len == 0 || name_len > MAX_ATTACHMENT_NAME_BYTES {
        return Err(StorageError::InvalidAttachment(
            "invalid attachment name length".to_owned(),
        ));
    }
    let name = String::from_utf8(take(bytes, &mut position, name_len)?.to_vec())
        .map_err(|_| StorageError::InvalidAttachment("attachment name is not UTF-8".to_owned()))?;
    validate_name(&name)?;
    let size = u64::from_le_bytes(fixed::<8>(
        take(bytes, &mut position, 8)?,
        "attachment size",
    )?);
    let plaintext_hash = fixed::<32>(take(bytes, &mut position, 32)?, "attachment plaintext hash")?;
    let format_tag = *take(bytes, &mut position, 1)?
        .first()
        .ok_or_else(|| StorageError::InvalidAttachment("missing format tag".to_owned()))?;
    let format = match format_tag {
        0 => None,
        1 => {
            let format_len = u16::from_le_bytes(fixed::<2>(
                take(bytes, &mut position, 2)?,
                "attachment format length",
            )?) as usize;
            if format_len == 0 || format_len > MAX_ATTACHMENT_FORMAT_BYTES {
                return Err(StorageError::InvalidAttachment(
                    "invalid attachment format length".to_owned(),
                ));
            }
            let label = String::from_utf8(take(bytes, &mut position, format_len)?.to_vec())
                .map_err(|_| {
                    StorageError::InvalidAttachment("format label is not UTF-8".to_owned())
                })?;
            validate_format(Some(&label))?;
            Some(label)
        }
        _ => {
            return Err(StorageError::InvalidAttachment(
                "invalid attachment format tag".to_owned(),
            ));
        }
    };
    if position != bytes.len() {
        return Err(StorageError::InvalidAttachment(
            "trailing attachment metadata".to_owned(),
        ));
    }
    if size == 0 || size as usize > MAX_ATTACHMENT_BYTES {
        return Err(StorageError::InvalidAttachmentSize);
    }
    Ok(AttachmentMeta {
        name,
        size,
        plaintext_hash,
        format,
    })
}

fn take<'a>(bytes: &'a [u8], position: &mut usize, len: usize) -> Result<&'a [u8], StorageError> {
    let end = position
        .checked_add(len)
        .ok_or_else(|| StorageError::InvalidAttachment("metadata length overflow".to_owned()))?;
    if end > bytes.len() {
        return Err(StorageError::InvalidAttachment(
            "truncated attachment metadata".to_owned(),
        ));
    }
    let slice = &bytes[*position..end];
    *position = end;
    Ok(slice)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn write_new_restricted(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
