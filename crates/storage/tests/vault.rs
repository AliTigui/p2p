//! Integration tests for the encrypted vault, including raw-file scans.

use std::fs;
use std::path::{Path, PathBuf};

use p2p_identity::Identity;
use p2p_storage::{ControlRecordOutcome, StorageError, Vault};
use sha2::{Digest, Sha256};

const USERNAME: &str = "SENTINEL_USER_42";
const PASSWORD: &str = "SENTINEL_PASSWORD_99";
const SETTING_KEY: &str = "SENTINEL_KEY_42";
const SETTING_VALUE: &str = "SENTINEL_VALUE_42";
const MESSAGE_PAYLOAD: &str = "SENTINEL_MESSAGE_PAYLOAD_77";
const ATTACHMENT_NAME: &str = "SENTINEL_ATTACHMENT_42.txt";
const ATTACHMENT_PAYLOAD: &[u8] = b"SENTINEL_ATTACHMENT_PAYLOAD_77";
const ATTACHMENT_FORMAT: &str = "TXT";
const MLS_STATE_SENTINEL: &str = "SENTINEL_MLS_STATE_PAYLOAD_88";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn every_file(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(every_file(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn attachment_hash() -> [u8; 32] {
    let digest = Sha256::digest(ATTACHMENT_PAYLOAD);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn assert_no_plaintext(directory: &std::path::Path, private_key: &[u8]) {
    let mut files = vec![
        directory.join("profile.db"),
        directory.join("profile.db-wal"),
        directory.join("profile.db-shm"),
        directory.join("control.anchor"),
        directory.join("control.anchor.tmp"),
    ];
    files.extend(every_file(&directory.join("attachments")));
    for path in files {
        let name = path.display().to_string();
        let bytes = fs::read(&path).unwrap_or_default();
        for sentinel in [
            USERNAME,
            PASSWORD,
            SETTING_KEY,
            SETTING_VALUE,
            MESSAGE_PAYLOAD,
            ATTACHMENT_NAME,
            ATTACHMENT_FORMAT,
            MLS_STATE_SENTINEL,
        ] {
            assert!(
                !contains(&bytes, sentinel.as_bytes()),
                "{name} contains plaintext sentinel {sentinel}"
            );
        }
        assert!(
            !contains(&bytes, ATTACHMENT_PAYLOAD),
            "{name} contains plaintext attachment bytes"
        );
        assert!(
            !contains(&bytes, private_key),
            "{name} contains the raw private key"
        );
    }
}

#[test]
fn vault_debug_redacts_the_local_directory_path() {
    let directory = tempfile::tempdir().expect("temp dir");
    let secret_path = directory.path().join("SENTINEL_VAULT_DIRECTORY");
    let vault = Vault::open(secret_path.clone()).expect("open vault");
    let debug = format!("{vault:?}");

    assert!(debug.contains("Vault"));
    assert!(!debug.contains("SENTINEL_VAULT_DIRECTORY"));
    assert!(!debug.contains(secret_path.to_string_lossy().as_ref()));
}

#[test]
fn vault_round_trip_preserves_identity_and_settings_without_plaintext() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    assert!(!vault.exists());

    let identity = Identity::generate().expect("identity");
    let peer_id = identity.peer_id();
    let fingerprint = identity.fingerprint().to_string();
    let private_key = identity.export_keypair_bytes();

    {
        let session = vault
            .create(USERNAME, PASSWORD, &identity)
            .expect("create vault");
        assert_eq!(session.identity().peer_id(), peer_id);
        assert_eq!(session.identity().fingerprint().as_str(), fingerprint);
        assert_eq!(session.get_setting("missing").expect("read missing"), None);
        assert_eq!(session.kdf_params(), p2p_crypto::Argon2Params::RECOMMENDED);

        session
            .set_setting(SETTING_KEY, SETTING_VALUE)
            .expect("set setting");
        session
            .set_setting("theme", "dark")
            .expect("set second setting");
        assert_eq!(
            session
                .get_setting(SETTING_KEY)
                .expect("read setting")
                .as_deref(),
            Some(SETTING_VALUE)
        );
        assert_eq!(
            session
                .get_setting("theme")
                .expect("read setting")
                .as_deref(),
            Some("dark")
        );
    }

    assert_no_plaintext(directory.path(), &private_key);

    let reopened = vault.unlock(PASSWORD).expect("unlock");
    assert_eq!(reopened.identity().peer_id(), peer_id);
    assert_eq!(reopened.identity().fingerprint().as_str(), fingerprint);
    assert_eq!(
        reopened
            .get_setting(SETTING_KEY)
            .expect("read setting")
            .as_deref(),
        Some(SETTING_VALUE)
    );
    assert!(!reopened.profile_id_hex().is_empty());
}

#[test]
fn messages_are_stored_only_as_ciphertext_and_scope_to_conversation() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let private_key = identity.export_keypair_bytes();
    let conversation = [1u8; 16];
    let other_conversation = [2u8; 16];
    let message = [3u8; 16];

    {
        let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_message(&conversation, &message, MESSAGE_PAYLOAD.as_bytes())
            .expect("store message");
        session
            .store_message(&conversation, &message, MESSAGE_PAYLOAD.as_bytes())
            .expect("duplicate store is idempotent");
        assert!(session.store_message(&conversation, &message, &[]).is_err());
        assert_eq!(
            session
                .messages_for_conversation(&conversation)
                .expect("read messages"),
            vec![MESSAGE_PAYLOAD.as_bytes().to_vec()]
        );
        assert!(
            session
                .messages_for_conversation(&other_conversation)
                .expect("read other conversation")
                .is_empty()
        );
    }

    assert_no_plaintext(directory.path(), &private_key);

    let unlocked = vault.unlock(PASSWORD).expect("unlock");
    assert_eq!(
        unlocked
            .messages_for_conversation(&conversation)
            .expect("read messages after unlock"),
        vec![MESSAGE_PAYLOAD.as_bytes().to_vec()]
    );
}

#[test]
fn wrong_password_and_duplicate_or_missing_vault_fail() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");

    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::VaultNotFound)
    ));

    let identity = Identity::generate().expect("identity");
    let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    drop(session);

    assert!(matches!(
        vault.unlock("wrong password"),
        Err(StorageError::AuthenticationFailed)
    ));
    assert!(matches!(
        vault.create(USERNAME, PASSWORD, &identity),
        Err(StorageError::VaultExists)
    ));
    assert!(matches!(
        vault.create(USERNAME, "", &identity),
        Err(StorageError::VaultExists)
    ));

    let other = tempfile::tempdir().expect("temp dir");
    let other_vault = Vault::open(other.path()).expect("open other vault");
    assert!(matches!(
        other_vault.create("", PASSWORD, &identity),
        Err(StorageError::EmptyUsername)
    ));
    assert!(matches!(
        other_vault.create(USERNAME, "", &identity),
        Err(StorageError::EmptyPassword)
    ));
}

#[test]
fn password_change_rewraps_only_the_master_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let private_key = identity.export_keypair_bytes();

    {
        let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .set_setting(SETTING_KEY, SETTING_VALUE)
            .expect("set setting");
    }

    let mut session = vault.unlock(PASSWORD).expect("unlock");
    assert!(matches!(
        session.change_password("wrong", "NEW_PASSWORD_42"),
        Err(StorageError::AuthenticationFailed)
    ));
    assert!(matches!(
        session.change_password(PASSWORD, ""),
        Err(StorageError::EmptyPassword)
    ));
    session
        .change_password(PASSWORD, "NEW_PASSWORD_42")
        .expect("change password");
    drop(session);

    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::AuthenticationFailed)
    ));
    let unlocked = vault
        .unlock("NEW_PASSWORD_42")
        .expect("unlock with new password");
    assert_eq!(unlocked.identity().peer_id(), identity.peer_id());
    assert_eq!(
        unlocked
            .get_setting(SETTING_KEY)
            .expect("read setting")
            .as_deref(),
        Some(SETTING_VALUE)
    );
    drop(unlocked);

    assert_no_plaintext(directory.path(), &private_key);
}

#[test]
fn damaged_master_wrap_is_rejected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    drop(session);

    let conn = rusqlite::Connection::open(vault.database_path()).expect("open raw db");
    conn.execute(
        "UPDATE profile SET wrapped_master = ?1 WHERE id = 1",
        rusqlite::params![vec![0u8; 64]],
    )
    .expect("tamper");
    drop(conn);

    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::AuthenticationFailed)
    ));
}

#[test]
fn attachments_are_encrypted_at_rest_and_deleted_only_explicitly() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let private_key = identity.export_keypair_bytes();
    let id;

    {
        let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        id = session
            .store_attachment(
                ATTACHMENT_NAME,
                ATTACHMENT_PAYLOAD,
                attachment_hash(),
                Some(ATTACHMENT_FORMAT),
            )
            .expect("store attachment");
        let infos = session.attachment_infos().expect("list attachments");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].id, id);
        assert_eq!(infos[0].name, ATTACHMENT_NAME);
        assert_eq!(infos[0].size, ATTACHMENT_PAYLOAD.len() as u64);
        assert_eq!(infos[0].format.as_deref(), Some(ATTACHMENT_FORMAT));
        assert_eq!(
            session
                .read_attachment(&id)
                .expect("read attachment")
                .as_slice(),
            ATTACHMENT_PAYLOAD
        );
        assert!(matches!(
            session.store_attachment("../escape", ATTACHMENT_PAYLOAD, attachment_hash(), None),
            Err(StorageError::InvalidAttachment(_))
        ));
        assert!(matches!(
            session.store_attachment(ATTACHMENT_NAME, &[], attachment_hash(), None),
            Err(StorageError::InvalidAttachmentSize)
        ));
        assert!(matches!(
            session.read_attachment(&[0u8; 32]),
            Err(StorageError::AttachmentNotFound)
        ));
    }

    assert_no_plaintext(directory.path(), &private_key);
    assert_eq!(every_file(&directory.path().join("attachments")).len(), 1);

    let reopened = vault.unlock(PASSWORD).expect("unlock");
    assert_eq!(
        reopened
            .read_attachment(&id)
            .expect("read after unlock")
            .as_slice(),
        ATTACHMENT_PAYLOAD
    );
    reopened.delete_attachment(&id).expect("delete attachment");
    assert!(matches!(
        reopened.read_attachment(&id),
        Err(StorageError::AttachmentNotFound)
    ));
    assert!(reopened.attachment_infos().expect("empty list").is_empty());
    assert!(every_file(&directory.path().join("attachments")).is_empty());
    assert_no_plaintext(directory.path(), &private_key);
}

#[test]
fn password_change_keeps_attachments_readable() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let private_key = identity.export_keypair_bytes();

    let id = {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        let id = session
            .store_attachment(
                ATTACHMENT_NAME,
                ATTACHMENT_PAYLOAD,
                attachment_hash(),
                Some(ATTACHMENT_FORMAT),
            )
            .expect("store attachment");
        session
            .change_password(PASSWORD, "NEW_PASSWORD_42")
            .expect("change password");
        id
    };

    let unlocked = vault.unlock("NEW_PASSWORD_42").expect("unlock");
    assert_eq!(
        unlocked
            .read_attachment(&id)
            .expect("read after password change")
            .as_slice(),
        ATTACHMENT_PAYLOAD
    );
    assert_no_plaintext(directory.path(), &private_key);
}

#[test]
fn another_vault_cannot_read_an_attachment() {
    let first_dir = tempfile::tempdir().expect("first temp dir");
    let first_vault = Vault::open(first_dir.path()).expect("first vault");
    let identity = Identity::generate().expect("identity");
    let id = first_vault
        .create(USERNAME, PASSWORD, &identity)
        .expect("create")
        .store_attachment(
            ATTACHMENT_NAME,
            ATTACHMENT_PAYLOAD,
            attachment_hash(),
            Some(ATTACHMENT_FORMAT),
        )
        .expect("store attachment");

    let second_dir = tempfile::tempdir().expect("second temp dir");
    let second_vault = Vault::open(second_dir.path()).expect("second vault");
    let other_identity = Identity::generate().expect("other identity");
    let second_session = second_vault
        .create(USERNAME, PASSWORD, &other_identity)
        .expect("create second vault");
    assert!(matches!(
        second_session.read_attachment(&id),
        Err(StorageError::AttachmentNotFound)
    ));
}

#[cfg(unix)]
#[test]
fn unix_permissions_are_restrictive() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    session
        .store_attachment(
            ATTACHMENT_NAME,
            ATTACHMENT_PAYLOAD,
            attachment_hash(),
            Some(ATTACHMENT_FORMAT),
        )
        .expect("store attachment");

    let dir_mode = fs::metadata(directory.path())
        .expect("dir metadata")
        .permissions()
        .mode()
        & 0o777;
    let file_mode = fs::metadata(vault.database_path())
        .expect("file metadata")
        .permissions()
        .mode()
        & 0o777;
    let attachment_dir = directory.path().join("attachments");
    let attachment_dir_mode = fs::metadata(&attachment_dir)
        .expect("attachment dir metadata")
        .permissions()
        .mode()
        & 0o777;
    let blob_path = every_file(&attachment_dir).pop().expect("attachment blob");
    let blob_mode = fs::metadata(blob_path)
        .expect("blob metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    assert_eq!(attachment_dir_mode, 0o700);
    assert_eq!(blob_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn vault_open_refuses_a_symlinked_directory() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temp dir");
    let target = directory.path().join("target");
    fs::create_dir(&target).expect("target directory");
    let link = directory.path().join("vault-link");
    symlink(&target, &link).expect("vault symlink");

    assert!(matches!(Vault::open(&link), Err(StorageError::UnsafePath)));
    assert!(!target.join("profile.db").exists());
}

#[cfg(unix)]
#[test]
fn attachment_deletion_refuses_a_symlink_before_removing_the_record() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    let id = session
        .store_attachment(
            ATTACHMENT_NAME,
            ATTACHMENT_PAYLOAD,
            attachment_hash(),
            Some(ATTACHMENT_FORMAT),
        )
        .expect("store attachment");
    let blob = vault
        .directory()
        .join("attachments")
        .join(format!("{}.ct", hex(&id)));
    fs::remove_file(&blob).expect("remove blob");
    symlink(directory.path().join("elsewhere"), &blob).expect("blob symlink");

    assert!(matches!(
        session.delete_attachment(&id),
        Err(StorageError::InvalidAttachment(_))
    ));
    assert_eq!(session.attachment_infos().expect("infos").len(), 1);
    assert!(
        fs::symlink_metadata(&blob)
            .expect("blob metadata")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn control_log_is_durable_and_idempotent_only_for_requests() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let peer = b"12D3KooWCONTROLPEER".to_vec();
    let first = [1u8; 32];
    let terminal = [2u8; 32];
    let other_peer = b"12D3KooWOTHERPEER".to_vec();

    let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    assert_eq!(
        session
            .record_control_frame(&peer, &first, true)
            .expect("record first request"),
        ControlRecordOutcome::Appended(1)
    );
    assert_eq!(
        session
            .record_control_frame(&peer, &first, true)
            .expect("record repeated request"),
        ControlRecordOutcome::Idempotent(1)
    );
    assert_eq!(
        session
            .record_control_frame(&peer, &terminal, false)
            .expect("record terminal frame"),
        ControlRecordOutcome::Appended(2)
    );
    assert_eq!(
        session
            .record_control_frame(&peer, &terminal, false)
            .expect("record replayed terminal frame"),
        ControlRecordOutcome::Replay(2)
    );
    assert_eq!(
        session
            .record_control_frame(&other_peer, &terminal, false)
            .expect("record peer-specific frame"),
        ControlRecordOutcome::Appended(3)
    );
    session.verify_control_log().expect("verify live log");
    assert_eq!(session.control_log_state().expect("state").sequence, 3);
    drop(session);

    let mut reopened = vault.unlock(PASSWORD).expect("unlock");
    reopened.verify_control_log().expect("verify reopened log");
    assert_eq!(
        reopened
            .record_control_frame(&peer, &terminal, false)
            .expect("record replay after reopen"),
        ControlRecordOutcome::Replay(2)
    );
    assert_no_plaintext(directory.path(), &identity.export_keypair_bytes());
}

fn database_snapshot(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fs::read_dir(directory)
        .expect("read vault directory")
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !name.starts_with("profile.db") || !path.is_file() {
                return None;
            }
            Some((path.to_path_buf(), fs::read(&path).expect("read db file")))
        })
        .collect()
}

fn restore_database_snapshot(snapshot: &[(PathBuf, Vec<u8>)]) {
    for (path, bytes) in snapshot {
        fs::write(path, bytes).expect("restore db file");
    }
}

#[test]
fn restoring_an_older_database_while_keeping_the_anchor_is_detected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let peer = b"12D3KooWCONTROLPEER".to_vec();

    let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    session
        .record_control_frame(&peer, &[7u8; 32], false)
        .expect("first frame");
    drop(session);
    let snapshot = database_snapshot(directory.path());

    let mut session = vault.unlock(PASSWORD).expect("unlock");
    session
        .record_control_frame(&peer, &[8u8; 32], false)
        .expect("second frame");
    drop(session);

    restore_database_snapshot(&snapshot);
    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn tampered_control_anchor_is_detected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");

    let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    session
        .record_control_frame(b"12D3KooWCONTROLPEER", &[9u8; 32], false)
        .expect("frame");
    drop(session);

    let anchor = directory.path().join("control.anchor");
    let mut bytes = fs::read(&anchor).expect("read anchor");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&anchor, bytes).expect("write tampered anchor");

    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn mls_state_round_trips_as_ciphertext_and_explicit_delete_removes_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(directory.path()).expect("open vault");
    let identity = Identity::generate().expect("identity");
    let private_key = identity.export_keypair_bytes();
    let group = [7u8; 16];

    {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_mls_state(
                &group,
                "tree",
                b"group-node",
                3,
                MLS_STATE_SENTINEL.as_bytes(),
            )
            .expect("store tree");
        session
            .store_mls_state(&group, "secrets", b"epoch-3", 3, b"MLS_SECRET_42")
            .expect("store secrets");
        assert_eq!(
            session
                .load_mls_state(&group, "tree", b"group-node")
                .expect("load tree")
                .as_deref()
                .map(|value| value.as_slice()),
            Some(MLS_STATE_SENTINEL.as_bytes())
        );
        assert_eq!(session.mls_group_ids().expect("group ids"), vec![group]);
        assert_eq!(
            session
                .load_mls_state_group(&group)
                .expect("load group")
                .len(),
            2
        );

        let replaced = [8u8; 16];
        session
            .store_mls_state(&replaced, "tree", b"node", 5, b"MLS_EPOCH_5")
            .expect("store newer epoch");
        session
            .store_mls_state(&replaced, "tree", b"node", 2, b"MLS_EPOCH_2")
            .expect("replace with older epoch");
    }

    assert_no_plaintext(directory.path(), &private_key);

    {
        let session = vault.unlock(PASSWORD).expect("unlock");
        session.verify_mls_state().expect("verified on unlock");
        assert_eq!(
            session
                .load_mls_state(&group, "secrets", b"epoch-3")
                .expect("load secrets")
                .as_deref()
                .map(|value| value.as_slice()),
            Some(b"MLS_SECRET_42".as_slice())
        );
        assert!(
            session
                .load_mls_state(&group, "missing", b"none")
                .expect("missing entry")
                .is_none()
        );
        assert_eq!(
            session
                .load_mls_state(&[8u8; 16], "tree", b"node")
                .expect("load replaced state")
                .as_deref()
                .map(|value| value.as_slice()),
            Some(b"MLS_EPOCH_2".as_slice())
        );
    }

    {
        let mut session = vault.unlock(PASSWORD).expect("unlock again");
        session
            .delete_mls_state_group(&group)
            .expect("delete group");
        session
            .delete_mls_state_group(&[8u8; 16])
            .expect("delete replaced group");
        session.verify_mls_state().expect("empty state verifies");
        assert!(session.mls_group_ids().expect("no groups").is_empty());
    }

    let reopened = vault.unlock(PASSWORD).expect("unlock after delete");
    assert!(reopened.mls_group_ids().expect("no groups").is_empty());
}

#[test]
fn tampered_mls_state_is_rejected_on_unlock() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");

    let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
    session
        .store_mls_state(
            &[11u8; 16],
            "tree",
            b"node",
            1,
            MLS_STATE_SENTINEL.as_bytes(),
        )
        .expect("store");
    drop(session);

    let conn = rusqlite::Connection::open(vault.database_path()).expect("open database");
    conn.execute(
        "UPDATE mls_state SET ciphertext = ?1",
        rusqlite::params![vec![0u8; 40]],
    )
    .expect("tamper ciphertext");
    drop(conn);

    assert!(vault.unlock(PASSWORD).is_err());
}

#[test]
fn password_change_keeps_encrypted_mls_state_readable() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let group = [13u8; 16];

    {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_mls_state(&group, "policy", b"channel", 2, b"MLS_POLICY_77")
            .expect("store");
        session
            .change_password(PASSWORD, "NEW_SENTINEL_PASSWORD_12")
            .expect("change password");
    }

    let reopened = vault
        .unlock("NEW_SENTINEL_PASSWORD_12")
        .expect("unlock with new password");
    assert_eq!(
        reopened
            .load_mls_state(&group, "policy", b"channel")
            .expect("load")
            .as_deref()
            .map(|value| value.as_slice()),
        Some(b"MLS_POLICY_77".as_slice())
    );
}

#[test]
fn mls_state_rejects_oversized_and_empty_values() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");

    assert!(
        session
            .store_mls_state(&[15u8; 16], "tree", b"node", 1, &[])
            .is_err()
    );
    assert!(
        session
            .store_mls_state(
                &[15u8; 16],
                "tree",
                b"node",
                1,
                &vec![7u8; p2p_storage::MAX_MLS_STATE_BYTES + 1],
            )
            .is_err()
    );
    assert!(
        session
            .store_mls_state(&[15u8; 16], &"x".repeat(65), b"node", 1, b"value",)
            .is_err()
    );
}

#[test]
fn restoring_database_before_mls_write_is_detected_by_anchor() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");

    {
        let session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        drop(session);
    }
    let empty_snapshot = database_snapshot(directory.path());

    {
        let mut session = vault.unlock(PASSWORD).expect("unlock");
        session
            .store_mls_state(&[21u8; 16], "tree", b"node", 1, b"MLS_ANCHOR_WRITE_21")
            .expect("store MLS state");
    }

    restore_database_snapshot(&empty_snapshot);
    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn restoring_database_before_mls_deletion_is_detected_by_anchor() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let group = [22u8; 16];

    {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_mls_state(&group, "tree", b"node", 1, b"MLS_ANCHOR_DELETE_22")
            .expect("store MLS state");
    }
    let populated_snapshot = database_snapshot(directory.path());

    {
        let mut session = vault.unlock(PASSWORD).expect("unlock");
        session
            .delete_mls_state_group(&group)
            .expect("delete MLS group");
    }

    restore_database_snapshot(&populated_snapshot);
    assert!(matches!(
        vault.unlock(PASSWORD),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn control_log_and_mls_state_share_one_anchor() {
    let directory = tempfile::tempdir().expect("temp dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let group = [24u8; 16];

    {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        assert_eq!(
            session
                .record_control_frame(b"12D3KooWMLSANCHOR", &[4u8; 32], false)
                .expect("record control frame"),
            ControlRecordOutcome::Appended(1)
        );
        session
            .store_mls_state(&group, "tree", b"node", 3, b"MLS_ANCHOR_SHARED_24")
            .expect("store MLS state");
    }

    let reopened = vault.unlock(PASSWORD).expect("unlock");
    assert_eq!(
        reopened
            .control_log_state()
            .expect("control state")
            .sequence,
        1
    );
    assert_eq!(
        reopened
            .load_mls_state(&group, "tree", b"node")
            .expect("load MLS state")
            .as_deref()
            .map(|value| value.as_slice()),
        Some(b"MLS_ANCHOR_SHARED_24".as_slice())
    );
    reopened.verify_control_log().expect("verify control log");
    reopened.verify_mls_state().expect("verify MLS state");
    assert_no_plaintext(directory.path(), &identity.export_keypair_bytes());
}

#[test]
fn restoring_whole_vault_including_anchor_is_not_detected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let backup = tempfile::tempdir().expect("backup dir");
    let identity = Identity::generate().expect("identity");
    let vault = Vault::open(directory.path()).expect("open vault");
    let group = [25u8; 16];

    {
        let mut session = vault.create(USERNAME, PASSWORD, &identity).expect("create");
        session
            .store_mls_state(&group, "tree", b"node", 1, b"MLS_ANCHOR_WHOLE_VAULT_25")
            .expect("store MLS state");
    }

    for entry in fs::read_dir(directory.path())
        .expect("read vault dir")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, backup.path().join(entry.file_name())).expect("back up file");
        }
    }

    {
        let mut session = vault.unlock(PASSWORD).expect("unlock");
        session
            .delete_mls_state_group(&group)
            .expect("delete MLS group");
    }

    for entry in fs::read_dir(directory.path())
        .expect("read vault dir")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            fs::remove_file(path).expect("remove current file");
        }
    }
    for entry in fs::read_dir(backup.path())
        .expect("read backup dir")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, directory.path().join(entry.file_name())).expect("restore file");
        }
    }

    let reopened = vault
        .unlock(PASSWORD)
        .expect("whole-vault-plus-anchor restore is not locally detectable");
    assert_eq!(
        reopened
            .load_mls_state(&group, "tree", b"node")
            .expect("load restored MLS state")
            .as_deref()
            .map(|value| value.as_slice()),
        Some(b"MLS_ANCHOR_WHOLE_VAULT_25".as_slice())
    );
}
