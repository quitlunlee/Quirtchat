//! Encrypted local state and bounded, capability-authorized ciphertext mailboxes.
//!
//! The application must supply the authenticated transport peer as `owner` for
//! mailbox allocation, reads, and deletion. A caller-supplied identity is not an
//! authentication substitute. Relay quotas account for serialized data plus a
//! per-record allowance; they are not a limit on the whole SQLite file.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::model::{AppState, Envelope, MAX_FRAME_BYTES};

pub const RELAY_TOTAL_BYTES: usize = 256 * 1024 * 1024;
pub const RELAY_MAILBOX_BYTES: usize = 32 * 1024 * 1024;
pub const LOCAL_MEDIA_BYTES: usize = 256 * 1024 * 1024;
pub const RELAY_MAX_MAILBOXES: usize = 1024;
/// Four concurrent pages fit the shared 256 KiB/s budget and ten-second timeout.
pub const RELAY_PAGE_BYTES: usize = 384 * 1024;
const RECORD_OVERHEAD: usize = 256;
const SCHEMA_VERSION: i64 = 2;

struct RelayLimits {
    total_bytes: usize,
    mailbox_bytes: usize,
    mailboxes: usize,
    local_media_bytes: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            total_bytes: RELAY_TOTAL_BYTES,
            mailbox_bytes: RELAY_MAILBOX_BYTES,
            mailboxes: RELAY_MAX_MAILBOXES,
            local_media_bytes: LOCAL_MEDIA_BYTES,
        }
    }
}

/// One encrypted profile. Field order closes SQLite before releasing the lock.
pub struct Store {
    connection: Connection,
    _key: Zeroizing<[u8; 32]>,
    limits: RelayLimits,
    _lock: File,
}

impl Store {
    /// Creates a new database. Existing database or salt files are never replaced.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        validate_password(password)?;
        let lock = lock_profile(path)?;
        let salt_path = sidecar(path, ".salt");
        ensure!(
            !path.exists() && !salt_path.exists(),
            "profile already exists"
        );
        let mut cleanup = CreatedFiles::default();

        let database_file = private_new_file(path).context("cannot create profile database")?;
        cleanup.paths.push(path.to_path_buf());
        drop(database_file);
        let mut salt_file = private_new_file(&salt_path).context("cannot create profile salt")?;
        cleanup.paths.push(salt_path);
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt_file.write_all(&salt)?;
        salt_file.sync_all()?;
        drop(salt_file);

        let key = derive_key(password, &salt)?;
        let connection = keyed_connection(path, &key)?;
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE app_state (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 body BLOB NOT NULL
             );
             CREATE TABLE relay_mailboxes (
                 id TEXT PRIMARY KEY,
                 owner TEXT NOT NULL UNIQUE,
                 write_hash BLOB NOT NULL CHECK(length(write_hash) = 32),
                 read_hash BLOB NOT NULL CHECK(length(read_hash) = 32),
                 write_token TEXT NOT NULL CHECK(length(write_token) = 64),
                 read_token TEXT NOT NULL CHECK(length(read_token) = 64)
             );
             CREATE INDEX relay_owner ON relay_mailboxes(owner);
             CREATE TABLE relay_envelopes (
                 mailbox_id TEXT NOT NULL REFERENCES relay_mailboxes(id),
                 message_id TEXT NOT NULL,
                 expires_at INTEGER NOT NULL,
                 body BLOB NOT NULL,
                 accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes > 0),
                 PRIMARY KEY(mailbox_id, message_id)
             );
             CREATE INDEX relay_expiry ON relay_envelopes(expires_at);
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
        media_store::migrate(&connection)?;
        cleanup.committed = true;
        Ok(Self {
            connection,
            _key: key,
            limits: RelayLimits::default(),
            _lock: lock,
        })
    }

    /// Opens an existing encrypted profile and verifies its key before returning.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        validate_password(password)?;
        ensure!(
            path.is_file(),
            "profile does not exist; initialize it first"
        );
        let lock = lock_profile(path)?;
        // Read a bounded amount: a damaged or replaced salt cannot exhaust memory.
        let mut salt = [0u8; 16];
        let mut salt_file =
            File::open(sidecar(path, ".salt")).context("profile salt is missing")?;
        salt_file
            .read_exact(&mut salt)
            .context("invalid profile salt")?;
        ensure!(salt_file.read(&mut [0u8; 1])? == 0, "invalid profile salt");
        let key = derive_key(password, &salt)?;
        let connection = keyed_connection(path, &key)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(
            (1..=SCHEMA_VERSION).contains(&version),
            "unsupported profile database version"
        );
        if version == 1 {
            media_store::migrate(&connection)?;
        }
        Ok(Self {
            connection,
            _key: key,
            limits: RelayLimits::default(),
            _lock: lock,
        })
    }

    /// Reads state and clears expired chat content before returning it to the UI.
    pub fn load_state(&self) -> Result<Option<AppState>> {
        let transaction = self.transaction()?;
        let Some(mut state) = read_state(&transaction)? else {
            return Ok(None);
        };
        let before = expiring_item_count(&state);
        state.purge_expired(crate::model::now());
        if before != expiring_item_count(&state) {
            write_state(&transaction, &state)?;
        }
        transaction.commit()?;
        Ok(Some(state))
    }

    /// One transaction commits MLS state and its exact outgoing bytes together.
    pub fn save_state(&self, state: &AppState) -> Result<()> {
        let transaction = self.transaction()?;
        write_state(&transaction, state)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn allocate(&self, owner: &str) -> Result<(String, String, String)> {
        ensure!(
            !owner.is_empty() && owner.len() <= 128,
            "invalid mailbox owner"
        );
        let transaction = self.transaction()?;
        // The authenticated transport owner can repeat a lost allocation request.
        // These recovery capabilities are protected by the same SQLCipher database;
        // request authorization still compares their fixed-size hashes below.
        let existing = transaction
            .query_row(
                "SELECT id, write_token, read_token FROM relay_mailboxes WHERE owner = ?1",
                [owner],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return Ok(existing);
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM relay_mailboxes", [], |r| r.get(0))?;
        ensure!(
            count < self.limits.mailboxes as i64,
            "relay mailbox limit reached"
        );
        let mailbox_id = random_token(16);
        let write_token = random_token(32);
        let read_token = random_token(32);
        let write_hash = token_hash(&write_token)?;
        let read_hash = token_hash(&read_token)?;
        transaction.execute(
            "INSERT INTO relay_mailboxes(id, owner, write_hash, read_hash, write_token, read_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                mailbox_id,
                owner,
                &write_hash[..],
                &read_hash[..],
                write_token,
                read_token
            ],
        )?;
        transaction.commit()?;
        Ok((mailbox_id, write_token, read_token))
    }

    pub fn store(
        &self,
        mailbox_id: &str,
        write_token: &str,
        envelope: &Envelope,
        now: i64,
    ) -> Result<()> {
        envelope.validate(now)?;
        ensure!(
            !envelope.id.is_empty() && !envelope.conversation.is_empty(),
            "empty envelope identifier"
        );
        let body = serde_json::to_vec(envelope)?;
        let size = body
            .len()
            .checked_add(RECORD_OVERHEAD)
            .context("envelope too large")?;
        let transaction = self.transaction()?;
        authorize(&transaction, mailbox_id, write_token, None)?;
        transaction.execute("DELETE FROM relay_envelopes WHERE expires_at <= ?1", [now])?;
        media_store::purge_relay(&transaction, now)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT body FROM relay_envelopes WHERE mailbox_id = ?1 AND message_id = ?2",
                params![mailbox_id, envelope.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                existing == body,
                "message ID already exists with different content"
            );
            transaction.commit()?;
            return Ok(());
        }
        let (used, total) = media_store::relay_usage(&transaction, mailbox_id)?;
        ensure!(
            used.saturating_add(size as i64) <= self.limits.mailbox_bytes as i64,
            "mailbox capacity reached"
        );
        ensure!(
            total.saturating_add(size as i64) <= self.limits.total_bytes as i64,
            "relay capacity reached"
        );
        transaction.execute(
            "INSERT INTO relay_envelopes(mailbox_id, message_id, expires_at, body, accounted_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                mailbox_id,
                envelope.id,
                envelope.expires_at,
                body,
                size as i64
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Returns the oldest page. The recipient acknowledges/deletes it to advance.
    /// Reserve envelope response framing so the final response fits MAX_FRAME_BYTES.
    pub fn fetch(
        &self,
        mailbox_id: &str,
        read_token: &str,
        owner: &str,
        now: i64,
    ) -> Result<Vec<Envelope>> {
        let transaction = self.transaction()?;
        authorize(&transaction, mailbox_id, read_token, Some(owner))?;
        transaction.execute("DELETE FROM relay_envelopes WHERE expires_at <= ?1", [now])?;
        let mut envelopes = Vec::new();
        let mut bytes = 64usize;
        {
            let mut statement = transaction.prepare(
                "SELECT body FROM relay_envelopes WHERE mailbox_id = ?1 ORDER BY expires_at, message_id",
            )?;
            let mut rows = statement.query([mailbox_id])?;
            while let Some(row) = rows.next()? {
                let body: Vec<u8> = row.get(0)?;
                ensure!(
                    bytes + body.len() < MAX_FRAME_BYTES,
                    "stored envelope exceeds frame limit"
                );
                // A single maximum-size envelope may serialize to slightly over
                // 512 KiB. Always allow that first record so pagination progresses.
                if !envelopes.is_empty() && bytes + body.len() + 1 > RELAY_PAGE_BYTES {
                    break;
                }
                let envelope: Envelope = serde_json::from_slice(&body)?;
                envelope.validate(now)?;
                bytes += body.len() + 1;
                envelopes.push(envelope);
            }
        }
        transaction.commit()?;
        Ok(envelopes)
    }

    pub fn delete(
        &self,
        mailbox_id: &str,
        read_token: &str,
        owner: &str,
        ids: &[String],
    ) -> Result<()> {
        ensure!(
            ids.len() <= 4096 && ids.iter().all(|id| id.len() <= 64),
            "invalid deletion batch"
        );
        let transaction = self.transaction()?;
        authorize(&transaction, mailbox_id, read_token, Some(owner))?;
        {
            let mut statement = transaction
                .prepare("DELETE FROM relay_envelopes WHERE mailbox_id = ?1 AND message_id = ?2")?;
            for id in ids {
                statement.execute(params![mailbox_id, id])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Clears expired relay data and local chat/outbox records atomically.
    /// Membership and MLS control records are intentionally retained.
    pub fn purge(&self, now: i64) -> Result<usize> {
        let transaction = self.transaction()?;
        let mut removed =
            transaction.execute("DELETE FROM relay_envelopes WHERE expires_at <= ?1", [now])?;
        removed += media_store::purge_relay(&transaction, now)?;
        removed += media_store::purge_local(&transaction, now)?;
        if let Some(mut state) = read_state(&transaction)? {
            let before = expiring_item_count(&state);
            state.purge_expired(now);
            let local_removed = before - expiring_item_count(&state);
            if local_removed > 0 {
                write_state(&transaction, &state)?;
            }
            removed += local_removed;
        }
        transaction.commit()?;
        Ok(removed)
    }

    fn transaction(&self) -> Result<Transaction<'_>> {
        Ok(Transaction::new_unchecked(
            &self.connection,
            TransactionBehavior::Immediate,
        )?)
    }
}

#[path = "media_store.rs"]
mod media_store;

fn expiring_item_count(state: &AppState) -> usize {
    state.messages.len()
        + state.outbox.len()
        + state.deferred.len()
        + state.message_signatures.len()
        + state.media_uploads.len()
        + state.media_downloads.len()
}

fn read_state(connection: &Connection) -> Result<Option<AppState>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row("SELECT body FROM app_state WHERE singleton = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    bytes
        .map(|bytes| {
            let bytes = Zeroizing::new(bytes);
            serde_json::from_slice(&bytes).context("invalid stored application state")
        })
        .transpose()
}

fn write_state(connection: &Connection, state: &AppState) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(state)?);
    connection.execute(
        "INSERT INTO app_state(singleton, body) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET body = excluded.body",
        params![&bytes[..]],
    )?;
    Ok(())
}

fn keyed_connection(path: &Path, key: &[u8; 32]) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    let mut key_hex = Zeroizing::new([0u8; 64]);
    hex::encode_to_slice(key, &mut key_hex[..])?;
    let pragma = Zeroizing::new(format!(
        "PRAGMA key = \"x'{}'\";",
        std::str::from_utf8(&key_hex[..])?
    ));
    connection
        .execute_batch(&pragma)
        .map_err(|_| anyhow::anyhow!("cannot initialize profile encryption"))?;
    // An ordinary SQLite build silently ignores key PRAGMAs, so fail closed.
    let cipher_version: String = connection
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .context("SQLCipher support is required")?;
    ensure!(!cipher_version.is_empty(), "SQLCipher support is required");
    connection
        .execute_batch("PRAGMA cipher_memory_security = ON; PRAGMA cipher_log_level = NONE;")?;
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| {
            anyhow::anyhow!("cannot unlock profile: incorrect password or damaged database")
        })?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(connection)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    // Fixed format-v1 parameters: Argon2id, 19 MiB, two passes, one lane.
    let parameters = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid password derivation parameters"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|_| anyhow::anyhow!("password derivation failed"))?;
    Ok(key)
}

fn validate_password(password: &str) -> Result<()> {
    ensure!(
        !password.is_empty() && password.len() <= 16 * 1024,
        "password must be nonempty and at most 16 KiB"
    );
    Ok(())
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut result = path.as_os_str().to_os_string();
    result.push(suffix);
    PathBuf::from(result)
}

fn private_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn lock_profile(path: &Path) -> Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(sidecar(path, ".lock"))?;
    FileExt::try_lock_exclusive(&file).context("profile is already open in another instance")?;
    Ok(file)
}

fn random_token(length: usize) -> String {
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes[..])
}

fn token_hash(token: &str) -> Result<[u8; 32]> {
    ensure!(token.len() == 64, "mailbox authorization failed");
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(token, &mut bytes[..])
        .map_err(|_| anyhow::anyhow!("mailbox authorization failed"))?;
    Ok(Sha256::digest(&bytes[..]).into())
}

fn authorize(
    connection: &Connection,
    mailbox_id: &str,
    token: &str,
    owner: Option<&str>,
) -> Result<()> {
    ensure!(mailbox_id.len() == 32, "mailbox authorization failed");
    let supplied = token_hash(token)?;
    let expected: Option<(String, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT owner, write_hash, read_hash FROM relay_mailboxes WHERE id = ?1",
            [mailbox_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((expected_owner, write_hash, read_hash)) = expected else {
        bail!("mailbox authorization failed")
    };
    let expected_hash = if let Some(owner) = owner {
        ensure!(owner == expected_owner, "mailbox authorization failed");
        read_hash
    } else {
        write_hash
    };
    ensure!(
        expected_hash.len() == 32,
        "invalid stored mailbox authorization"
    );
    ensure!(
        bool::from(expected_hash.as_slice().ct_eq(&supplied)),
        "mailbox authorization failed"
    );
    Ok(())
}

#[derive(Default)]
struct CreatedFiles {
    paths: Vec<PathBuf>,
    committed: bool,
}

impl Drop for CreatedFiles {
    fn drop(&mut self) {
        if !self.committed {
            for path in self.paths.iter().rev() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChatMessage, ControlRecord, MESSAGE_TTL, Outgoing, Response};
    use tempfile::TempDir;

    fn profile() -> (TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::create(
            &directory.path().join("profile.db"),
            "correct horse battery",
        )
        .unwrap();
        (directory, store)
    }

    fn envelope(id: &str, now: i64) -> Envelope {
        Envelope {
            id: id.into(),
            conversation: "group".into(),
            created_at: now,
            expires_at: now + MESSAGE_TTL,
            ciphertext: vec![42; 32],
        }
    }

    #[test]
    fn encrypted_roundtrip_wrong_password_and_existing_profile_are_safe() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        assert!(store.load_state().unwrap().is_none());
        let state = AppState {
            name: "a secret sentinel not to appear on disk".into(),
            crypto: vec![1, 2, 3],
            ..AppState::default()
        };
        store.save_state(&state).unwrap();
        drop(store);
        let before = fs::read(&path).unwrap();
        assert!(!before.starts_with(b"SQLite format 3"));
        assert!(
            !before
                .windows(state.name.len())
                .any(|part| part == state.name.as_bytes())
        );
        assert!(Store::open(&path, "incorrect").is_err());
        assert_eq!(before, fs::read(&path).unwrap());
        assert!(Store::create(&path, "different").is_err());
        assert_eq!(before, fs::read(&path).unwrap());
        let reopened = Store::open(&path, "correct horse battery").unwrap();
        let loaded = reopened.load_state().unwrap().unwrap();
        assert_eq!(loaded.name, state.name);
        assert_eq!(loaded.crypto, state.crypto);
    }

    #[test]
    fn single_instance_lock_releases_on_drop() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        assert!(Store::open(&path, "correct horse battery").is_err());
        drop(store);
        assert!(Store::open(&path, "correct horse battery").is_ok());
    }

    #[test]
    fn reopening_discards_expired_chat_before_returning_state() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        let now = crate::model::now();
        let expired = envelope("expired", now - MESSAGE_TTL - 1);
        let live = envelope("live", now);
        let mut state = AppState {
            crypto: vec![7, 8, 9],
            ..AppState::default()
        };
        state.outbox.push(Outgoing {
            recipient: "bob".into(),
            envelope: expired,
            stored_at: vec![],
        });
        state.outbox.push(Outgoing {
            recipient: "bob".into(),
            envelope: live.clone(),
            stored_at: vec!["replica".into()],
        });
        store.save_state(&state).unwrap();
        drop(store);
        let store = Store::open(&path, "correct horse battery").unwrap();
        let loaded = store.load_state().unwrap().unwrap();
        assert_eq!(loaded.crypto, state.crypto);
        assert_eq!(loaded.outbox.len(), 1);
        assert_eq!(
            serde_json::to_vec(&loaded.outbox[0].envelope).unwrap(),
            serde_json::to_vec(&live).unwrap()
        );
        assert_eq!(loaded.outbox[0].stored_at, vec!["replica"]);
        // The cleanup is persisted, rather than only hidden in the returned value.
        assert_eq!(
            read_state(&store.connection).unwrap().unwrap().outbox.len(),
            1
        );
    }

    #[test]
    fn deferred_only_and_orphan_signature_cleanup_is_persisted() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let mut state = AppState::default();
        state
            .deferred
            .push(envelope("expired", now - MESSAGE_TTL - 1));
        state
            .message_signatures
            .insert("group/deleted-message".into(), vec![7; 64]);
        store.save_state(&state).unwrap();
        let loaded = store.load_state().unwrap().unwrap();
        assert!(loaded.deferred.is_empty() && loaded.message_signatures.is_empty());
        let persisted = read_state(&store.connection).unwrap().unwrap();
        assert!(persisted.deferred.is_empty() && persisted.message_signatures.is_empty());

        let mut state = AppState::default();
        state.deferred.push(envelope("pending-epoch", now));
        store.save_state(&state).unwrap();
        assert_eq!(store.purge(now + MESSAGE_TTL).unwrap(), 1);
        assert!(
            read_state(&store.connection)
                .unwrap()
                .unwrap()
                .deferred
                .is_empty()
        );
    }

    #[test]
    fn failed_save_preserves_the_previous_crypto_and_outbox_snapshot() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let mut state = AppState {
            crypto: vec![1, 2, 3],
            ..AppState::default()
        };
        state.outbox.push(Outgoing {
            recipient: "bob".into(),
            envelope: envelope("committed", now),
            stored_at: vec![],
        });
        store.save_state(&state).unwrap();
        let expected = serde_json::to_vec(&state).unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_state_save BEFORE UPDATE ON app_state
             BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;",
            )
            .unwrap();
        state.crypto = vec![4, 5, 6];
        state.outbox.clear();
        assert!(store.save_state(&state).is_err());
        assert_eq!(
            serde_json::to_vec(&read_state(&store.connection).unwrap().unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn interrupted_transaction_recovers_the_last_committed_snapshot() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        let now = crate::model::now();
        let mut state = AppState {
            crypto: vec![1, 2, 3],
            ..AppState::default()
        };
        state.outbox.push(Outgoing {
            recipient: "bob".into(),
            envelope: envelope("committed", now),
            stored_at: vec![],
        });
        store.save_state(&state).unwrap();
        let expected = serde_json::to_vec(&state).unwrap();
        drop(store);

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::tests::crash_transaction_helper",
                "--ignored",
            ])
            .env("CLICHAT_TEST_CRASH_PROFILE", &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "crash helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            sidecar(&path, ".interrupted").is_file(),
            "helper did not reach the interrupted write"
        );
        assert!(
            sidecar(&path, "-journal").is_file(),
            "interrupted write did not leave a rollback journal"
        );
        let reopened = Store::open(&path, "correct horse battery").unwrap();
        assert_eq!(
            serde_json::to_vec(&reopened.load_state().unwrap().unwrap()).unwrap(),
            expected
        );
        assert!(!sidecar(&path, "-journal").exists());
    }

    #[test]
    #[ignore = "runs only as the abrupt-exit child of interrupted_transaction_recovers_the_last_committed_snapshot"]
    fn crash_transaction_helper() {
        let Some(path) = std::env::var_os("CLICHAT_TEST_CRASH_PROFILE") else {
            return;
        };
        let path = PathBuf::from(path);
        let store = Store::open(&path, "correct horse battery").unwrap();
        let mut state = store.load_state().unwrap().unwrap();
        // Exceed SQLite's page cache so this is a real journal-recovery exercise,
        // not simply an uncommitted change that never left process memory.
        state.crypto = vec![165; 4 * 1024 * 1024];
        state.outbox.clear();
        let transaction = store.transaction().unwrap();
        write_state(&transaction, &state).unwrap();
        fs::write(
            sidecar(&path, ".interrupted"),
            b"uncommitted write completed",
        )
        .unwrap();
        // Skip every Rust destructor, including SQLite rollback and lock cleanup.
        std::process::exit(0);
    }

    #[test]
    fn invalid_salt_and_corrupted_database_fail_without_reinitializing() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        store
            .save_state(&AppState {
                name: "preserve existing profile".into(),
                ..AppState::default()
            })
            .unwrap();
        drop(store);
        let before = fs::read(&path).unwrap();
        let salt_path = sidecar(&path, ".salt");
        let salt = fs::read(&salt_path).unwrap();
        fs::write(&salt_path, [1, 2, 3]).unwrap();
        assert!(Store::open(&path, "correct horse battery").is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::write(&salt_path, salt).unwrap();
        let mut corrupted = before;
        corrupted[128] ^= 0x80;
        fs::write(&path, &corrupted).unwrap();
        assert!(Store::open(&path, "correct horse battery").is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupted);
    }

    #[test]
    fn read_and_write_tokens_are_separate_and_owner_is_authenticated() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let (mailbox, write, read) = store.allocate("alice").unwrap();
        let message = envelope("first", now);
        assert!(store.store(&mailbox, &read, &message, now).is_err());
        store.store(&mailbox, &write, &message, now).unwrap();
        assert!(store.fetch(&mailbox, &write, "alice", now).is_err());
        assert!(store.fetch(&mailbox, &read, "mallory", now).is_err());
        assert!(
            store
                .delete(&mailbox, &read, "mallory", &["first".into()])
                .is_err()
        );
        assert_eq!(store.fetch(&mailbox, &read, "alice", now).unwrap().len(), 1);
        store
            .delete(&mailbox, &read, "alice", &["first".into()])
            .unwrap();
        assert!(
            store
                .fetch(&mailbox, &read, "alice", now)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn allocation_retries_recover_the_same_capabilities_without_consuming_slots() {
        let (directory, mut store) = profile();
        let path = directory.path().join("profile.db");
        store.limits.mailboxes = 1;
        let original = store.allocate("alice").unwrap();
        for _ in 0..8 {
            assert_eq!(store.allocate("alice").unwrap(), original);
        }
        assert!(store.allocate("bob").is_err());
        drop(store);
        let reopened = Store::open(&path, "correct horse battery").unwrap();
        assert_eq!(reopened.allocate("alice").unwrap(), original);
    }

    #[test]
    fn ttl_boundary_cleans_local_history_outbox_and_relay_but_not_controls() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let message = envelope("first", now);
        let (mailbox, write, read) = store.allocate("alice").unwrap();
        store.store(&mailbox, &write, &message, now).unwrap();
        let mut state = AppState::default();
        state.messages.push(ChatMessage {
            id: "first".into(),
            conversation: "group".into(),
            sender: "alice".into(),
            created_at: now,
            expires_at: now + MESSAGE_TTL,
            text: "temporary".into(),
            attachment: None,
        });
        state.outbox.push(Outgoing {
            recipient: "bob".into(),
            envelope: message.clone(),
            stored_at: vec![],
        });
        state.controls.push(ControlRecord {
            conversation: "group".into(),
            epoch: 1,
            commit: vec![1],
            proposals: vec![],
        });
        store.save_state(&state).unwrap();
        assert_eq!(
            store
                .fetch(&mailbox, &read, "alice", message.expires_at - 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.purge(message.expires_at).unwrap(), 3);
        assert!(
            store
                .fetch(&mailbox, &read, "alice", message.expires_at)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .store(&mailbox, &write, &message, message.expires_at)
                .is_err()
        );
        let loaded = store.load_state().unwrap().unwrap();
        assert!(loaded.messages.is_empty() && loaded.outbox.is_empty());
        assert_eq!(loaded.controls.len(), 1);
    }

    #[test]
    fn duplicate_retry_is_idempotent_and_collision_cannot_change_ttl() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let (mailbox, write, read) = store.allocate("alice").unwrap();
        let message = envelope("first", now);
        store.store(&mailbox, &write, &message, now).unwrap();
        store.store(&mailbox, &write, &message, now + 1).unwrap();
        let mut collision = message.clone();
        collision.created_at += 1;
        collision.expires_at += 1;
        assert!(store.store(&mailbox, &write, &collision, now + 1).is_err());
        collision = message.clone();
        collision.ciphertext[0] ^= 1;
        assert!(store.store(&mailbox, &write, &collision, now + 1).is_err());
        assert_eq!(
            store
                .fetch(&mailbox, &read, "alice", now + 1)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn quota_failure_preserves_accepted_data_and_expiry_reclaims_capacity() {
        let (_directory, mut store) = profile();
        let now = crate::model::now();
        let first = envelope("first", now);
        let size = serde_json::to_vec(&first).unwrap().len() + RECORD_OVERHEAD;
        store.limits.mailbox_bytes = size;
        store.limits.total_bytes = size * 2;
        store.limits.mailboxes = 2;
        let (box1, write1, read1) = store.allocate("alice").unwrap();
        let (box2, write2, _read2) = store.allocate("bob").unwrap();
        assert!(store.allocate("carol").is_err());
        store.store(&box1, &write1, &first, now).unwrap();
        store.store(&box2, &write2, &first, now).unwrap();
        assert!(
            store
                .store(&box1, &write1, &envelope("other", now), now)
                .is_err()
        );
        assert_eq!(store.fetch(&box1, &read1, "alice", now).unwrap().len(), 1);
        store.limits.mailbox_bytes = size * 2;
        assert!(
            store
                .store(&box1, &write1, &envelope("other", now), now)
                .is_err()
        );
        store
            .store(
                &box1,
                &write1,
                &envelope("later", now + MESSAGE_TTL),
                now + MESSAGE_TTL,
            )
            .unwrap();
        assert_eq!(
            store
                .fetch(&box1, &read1, "alice", now + MESSAGE_TTL)
                .unwrap()[0]
                .id,
            "later"
        );
    }

    #[test]
    fn fetch_pages_fit_the_transport_frame_and_advance_on_ack() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let (mailbox, write, read) = store.allocate("alice").unwrap();
        for index in 0..8 {
            let mut message = envelope(&format!("{index:02}"), now);
            message.ciphertext = vec![255; 128 * 1024];
            store.store(&mailbox, &write, &message, now).unwrap();
        }
        let page = store.fetch(&mailbox, &read, "alice", now).unwrap();
        assert_eq!(page.len(), 1);
        assert!(
            serde_json::to_vec(&Response::Envelopes(page.clone()))
                .unwrap()
                .len()
                <= MAX_FRAME_BYTES
        );
        let ids: Vec<String> = page.iter().map(|message| message.id.clone()).collect();
        store.delete(&mailbox, &read, "alice", &ids).unwrap();
        let next = store.fetch(&mailbox, &read, "alice", now).unwrap();
        assert!(!next.is_empty());
        assert!(next.iter().all(|message| !ids.contains(&message.id)));

        let (small_box, small_write, small_read) = store.allocate("bob").unwrap();
        for index in 0..8 {
            let mut message = envelope(&format!("{index:02}"), now);
            message.ciphertext = vec![255; 16 * 1024];
            store
                .store(&small_box, &small_write, &message, now)
                .unwrap();
        }
        let page = store.fetch(&small_box, &small_read, "bob", now).unwrap();
        assert!(page.len() > 1 && page.len() < 8);
        assert!(
            serde_json::to_vec(&Response::Envelopes(page))
                .unwrap()
                .len()
                <= RELAY_PAGE_BYTES
        );
    }
}
