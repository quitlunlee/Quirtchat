//! Ciphertext-only attachment storage. The containing profile remains SQLCipher encrypted.

use super::{Connection, OptionalExtension, RECORD_OVERHEAD, Store, authorize, token_hash};
use crate::media::{CHUNK_SIZE, MAX_MEDIA_BYTES, MediaChunk};
use anyhow::{Context, Result, ensure};
use rusqlite::{Transaction, TransactionBehavior, params};
use subtle::ConstantTimeEq;

const MAX_CHUNKS: usize = MAX_MEDIA_BYTES.div_ceil(CHUNK_SIZE);

/// Upgrading an existing profile changes only its schema, in one recoverable transaction.
pub(super) fn migrate(connection: &Connection) -> Result<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE local_media (
             media_id TEXT NOT NULL CHECK(length(media_id) = 64),
             chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0 AND chunk_index < 320),
             created_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL,
             ciphertext BLOB NOT NULL,
             read_hash BLOB NOT NULL CHECK(length(read_hash) = 32),
             accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes > 0),
             PRIMARY KEY(media_id, chunk_index)
         );
         CREATE INDEX local_media_expiry ON local_media(expires_at);
         CREATE TABLE relay_media (
             media_id TEXT NOT NULL CHECK(length(media_id) = 64),
             chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0 AND chunk_index < 320),
             mailbox_id TEXT NOT NULL REFERENCES relay_mailboxes(id),
             created_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL,
             ciphertext BLOB NOT NULL,
             read_hash BLOB NOT NULL CHECK(length(read_hash) = 32),
             accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes > 0),
             PRIMARY KEY(media_id, chunk_index)
         );
         CREATE INDEX relay_media_expiry ON relay_media(expires_at);
         CREATE INDEX relay_media_mailbox ON relay_media(mailbox_id);
         PRAGMA user_version = 2;",
    )?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn purge_relay(connection: &Connection, now: i64) -> Result<usize> {
    Ok(connection.execute("DELETE FROM relay_media WHERE expires_at <= ?1", [now])?)
}

pub(super) fn purge_local(connection: &Connection, now: i64) -> Result<usize> {
    Ok(connection.execute("DELETE FROM local_media WHERE expires_at <= ?1", [now])?)
}

/// Both write paths use the same accounting, so text and media cannot bypass each other's limits.
pub(super) fn relay_usage(connection: &Connection, mailbox: &str) -> Result<(i64, i64)> {
    Ok(connection.query_row(
        "SELECT
          (SELECT coalesce(sum(accounted_bytes), 0) FROM relay_envelopes WHERE mailbox_id = ?1)
          + (SELECT coalesce(sum(accounted_bytes), 0) FROM relay_media WHERE mailbox_id = ?1),
          (SELECT coalesce(sum(accounted_bytes), 0) FROM relay_envelopes)
          + (SELECT coalesce(sum(accounted_bytes), 0) FROM relay_media)",
        [mailbox],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

impl Store {
    /// Stages a whole outgoing attachment, or an incoming subset, atomically.
    pub fn store_local_media(
        &self,
        chunks: &[MediaChunk],
        read_token: &str,
        now: i64,
    ) -> Result<()> {
        ensure!(
            !chunks.is_empty() && chunks.len() <= MAX_CHUNKS,
            "invalid media chunk batch"
        );
        let read_hash = token_hash(read_token)?;
        let first = &chunks[0];
        for chunk in chunks {
            validate_chunk(chunk, now)?;
            ensure!(
                chunk.media_id == first.media_id,
                "media batch contains multiple files"
            );
            ensure!(
                chunk.created_at == first.created_at && chunk.expires_at == first.expires_at,
                "media chunk timestamps differ"
            );
        }
        let transaction = self.transaction()?;
        purge_local(&transaction, now)?;
        verify_file(&transaction, first, &read_hash, None)?;
        let mut used: i64 = transaction.query_row(
            "SELECT coalesce(sum(accounted_bytes), 0) FROM local_media",
            [],
            |r| r.get(0),
        )?;
        for chunk in chunks {
            if verify_duplicate(&transaction, chunk, &read_hash, false)? {
                continue;
            }
            let size = accounted_bytes(chunk)?;
            used = used
                .checked_add(size)
                .context("media cache size overflow")?;
            ensure!(
                used <= self.limits.local_media_bytes as i64,
                "local media cache capacity reached"
            );
            transaction.execute(
                "INSERT INTO local_media(media_id, chunk_index, created_at, expires_at, ciphertext, read_hash, accounted_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![chunk.media_id, chunk.index, chunk.created_at, chunk.expires_at,
                    chunk.ciphertext, &read_hash[..], size],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_local_media(
        &self,
        media_id: &str,
        index: u32,
        read_token: &str,
        now: i64,
    ) -> Result<Option<MediaChunk>> {
        read_chunk(&self.connection, media_id, index, read_token, now, false)
    }

    /// Local progress is available only to this profile; network reads always need the capability.
    pub fn media_progress(&self, media_id: &str, now: i64) -> Result<usize> {
        validate_id(media_id)?;
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM local_media WHERE media_id = ?1 AND expires_at > ?2",
            params![media_id, now],
            |r| r.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn delete_local_media(&self, media_id: &str) -> Result<()> {
        validate_id(media_id)?;
        self.connection
            .execute("DELETE FROM local_media WHERE media_id = ?1", [media_id])?;
        Ok(())
    }

    pub fn store_relay_media(
        &self,
        mailbox_id: &str,
        write_token: &str,
        read_token: &str,
        chunk: &MediaChunk,
        now: i64,
    ) -> Result<()> {
        validate_chunk(chunk, now)?;
        let read_hash = token_hash(read_token)?;
        let transaction = self.transaction()?;
        authorize(&transaction, mailbox_id, write_token, None)?;
        transaction.execute("DELETE FROM relay_envelopes WHERE expires_at <= ?1", [now])?;
        purge_relay(&transaction, now)?;
        verify_file(&transaction, chunk, &read_hash, Some(mailbox_id))?;
        if verify_duplicate(&transaction, chunk, &read_hash, true)? {
            transaction.commit()?;
            return Ok(());
        }
        let size = accounted_bytes(chunk)?;
        let (used, total) = relay_usage(&transaction, mailbox_id)?;
        ensure!(
            used.saturating_add(size) <= self.limits.mailbox_bytes as i64,
            "mailbox capacity reached"
        );
        ensure!(
            total.saturating_add(size) <= self.limits.total_bytes as i64,
            "relay capacity reached"
        );
        transaction.execute(
            "INSERT INTO relay_media(media_id, chunk_index, mailbox_id, created_at, expires_at, ciphertext, read_hash, accounted_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![chunk.media_id, chunk.index, mailbox_id, chunk.created_at, chunk.expires_at,
                chunk.ciphertext, &read_hash[..], size],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_relay_media(
        &self,
        media_id: &str,
        index: u32,
        read_token: &str,
        now: i64,
    ) -> Result<Option<MediaChunk>> {
        read_chunk(&self.connection, media_id, index, read_token, now, true)
    }
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid media identifier"
    );
    Ok(())
}

fn validate_chunk(chunk: &MediaChunk, now: i64) -> Result<()> {
    chunk.validate(now)?;
    validate_id(&chunk.media_id)?;
    ensure!(
        (chunk.index as usize) < MAX_CHUNKS,
        "media chunk index out of bounds"
    );
    ensure!(
        chunk.ciphertext.len() >= 16 && chunk.ciphertext.len() <= CHUNK_SIZE + 16,
        "invalid media ciphertext size"
    );
    Ok(())
}

fn accounted_bytes(chunk: &MediaChunk) -> Result<i64> {
    Ok(i64::try_from(
        chunk
            .ciphertext
            .len()
            .checked_add(RECORD_OVERHEAD)
            .context("media chunk too large")?,
    )?)
}

fn same_cap(expected: &[u8], supplied: &[u8; 32]) -> Result<()> {
    ensure!(
        expected.len() == 32 && bool::from(expected.ct_eq(supplied)),
        "media authorization failed"
    );
    Ok(())
}

/// A file's first accepted chunk pins its absolute TTL, capability, and relay mailbox.
fn verify_file(
    connection: &Connection,
    chunk: &MediaChunk,
    read_hash: &[u8; 32],
    mailbox: Option<&str>,
) -> Result<()> {
    let sql = if mailbox.is_some() {
        "SELECT created_at, expires_at, read_hash, mailbox_id FROM relay_media WHERE media_id = ?1 LIMIT 1"
    } else {
        "SELECT created_at, expires_at, read_hash, NULL FROM local_media WHERE media_id = ?1 LIMIT 1"
    };
    let record: Option<(i64, i64, Vec<u8>, Option<String>)> = connection
        .query_row(sql, [&chunk.media_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    if let Some((created_at, expires_at, expected_hash, stored_mailbox)) = record {
        same_cap(&expected_hash, read_hash)?;
        ensure!(
            created_at == chunk.created_at && expires_at == chunk.expires_at,
            "media timestamps cannot change"
        );
        ensure!(
            stored_mailbox.as_deref() == mailbox,
            "media belongs to another mailbox"
        );
    }
    Ok(())
}

fn verify_duplicate(
    connection: &Connection,
    chunk: &MediaChunk,
    read_hash: &[u8; 32],
    relay: bool,
) -> Result<bool> {
    let sql = if relay {
        "SELECT created_at, expires_at, ciphertext, read_hash FROM relay_media WHERE media_id = ?1 AND chunk_index = ?2"
    } else {
        "SELECT created_at, expires_at, ciphertext, read_hash FROM local_media WHERE media_id = ?1 AND chunk_index = ?2"
    };
    let record = connection
        .query_row(sql, params![chunk.media_id, chunk.index], read_row)
        .optional()?;
    if let Some((created_at, expires_at, ciphertext, expected_hash)) = record {
        same_cap(&expected_hash, read_hash)?;
        ensure!(
            created_at == chunk.created_at
                && expires_at == chunk.expires_at
                && ciphertext == chunk.ciphertext,
            "media chunk already exists with different content"
        );
        return Ok(true);
    }
    Ok(false)
}

type ChunkRow = (i64, i64, Vec<u8>, Vec<u8>);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChunkRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn read_chunk(
    connection: &Connection,
    media_id: &str,
    index: u32,
    read_token: &str,
    now: i64,
    relay: bool,
) -> Result<Option<MediaChunk>> {
    validate_id(media_id)?;
    ensure!(
        (index as usize) < MAX_CHUNKS,
        "media chunk index out of bounds"
    );
    let supplied_hash = token_hash(read_token)?;
    let sql = if relay {
        "SELECT created_at, expires_at, ciphertext, read_hash FROM relay_media
         WHERE media_id = ?1 AND chunk_index = ?2 AND expires_at > ?3"
    } else {
        "SELECT created_at, expires_at, ciphertext, read_hash FROM local_media
         WHERE media_id = ?1 AND chunk_index = ?2 AND expires_at > ?3"
    };
    let record = connection
        .query_row(sql, params![media_id, index, now], read_row)
        .optional()?;
    let Some((created_at, expires_at, ciphertext, expected_hash)) = record else {
        return Ok(None);
    };
    same_cap(&expected_hash, &supplied_hash)?;
    let chunk = MediaChunk {
        media_id: media_id.to_owned(),
        index,
        created_at,
        expires_at,
        ciphertext,
    };
    validate_chunk(&chunk, now)?;
    Ok(Some(chunk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AppState, Envelope, MESSAGE_TTL};
    use tempfile::TempDir;

    fn profile() -> (TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Store::create(&directory.path().join("profile.db"), "media test password").unwrap();
        (directory, store)
    }

    fn chunk(index: u32, now: i64) -> MediaChunk {
        MediaChunk {
            media_id: "ab".repeat(32),
            index,
            created_at: now,
            expires_at: now + MESSAGE_TTL,
            ciphertext: vec![42; CHUNK_SIZE + 16],
        }
    }

    fn envelope(now: i64) -> Envelope {
        Envelope {
            id: "text-message".into(),
            conversation: "group".into(),
            created_at: now,
            expires_at: now + MESSAGE_TTL,
            ciphertext: vec![3; 32],
        }
    }

    fn assert_original(actual: Option<MediaChunk>, expected: &MediaChunk) {
        let actual = actual.unwrap();
        assert_eq!(actual.media_id, expected.media_id);
        assert_eq!(actual.index, expected.index);
        assert_eq!(actual.created_at, expected.created_at);
        assert_eq!(actual.expires_at, expected.expires_at);
        assert_eq!(actual.ciphertext, expected.ciphertext);
    }

    #[test]
    fn media_capabilities_are_separate_and_survive_encrypted_reopening() {
        let (directory, store) = profile();
        let now = crate::model::now();
        let first = chunk(0, now);
        let capability = "12".repeat(32);
        let wrong_capability = "34".repeat(32);
        let (mailbox, write, read) = store.allocate("alice").unwrap();
        assert!(
            store
                .store_relay_media(&mailbox, &read, &capability, &first, now)
                .is_err()
        );
        assert!(
            store
                .store_local_media(std::slice::from_ref(&first), "malformed", now)
                .is_err()
        );
        store
            .store_local_media(std::slice::from_ref(&first), &capability, now)
            .unwrap();
        store
            .store_relay_media(&mailbox, &write, &capability, &first, now)
            .unwrap();
        assert!(
            store
                .get_local_media(&first.media_id, 0, &wrong_capability, now)
                .is_err()
        );
        assert!(
            store
                .get_relay_media(&first.media_id, 0, &read, now)
                .is_err()
        );
        assert!(
            store
                .get_relay_media(&first.media_id, 0, &write, now)
                .is_err()
        );
        let path = directory.path().join("profile.db");
        drop(store);
        assert!(Store::open(&path, "wrong password").is_err());
        let store = Store::open(&path, "media test password").unwrap();
        assert_original(
            store
                .get_local_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
        assert_original(
            store
                .get_relay_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
        assert_eq!(store.media_progress(&first.media_id, now).unwrap(), 1);
        store.delete_local_media(&first.media_id).unwrap();
        assert_eq!(store.media_progress(&first.media_id, now).unwrap(), 0);
        assert_original(
            store
                .get_relay_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
    }

    #[test]
    fn retries_cannot_change_bytes_capability_mailbox_or_file_timestamps() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let first = chunk(0, now);
        let capability = "12".repeat(32);
        let other_capability = "34".repeat(32);
        let (box1, write1, _) = store.allocate("alice").unwrap();
        let (box2, write2, _) = store.allocate("bob").unwrap();
        store
            .store_local_media(std::slice::from_ref(&first), &capability, now)
            .unwrap();
        store
            .store_relay_media(&box1, &write1, &capability, &first, now)
            .unwrap();
        store
            .store_local_media(std::slice::from_ref(&first), &capability, now + 1)
            .unwrap();
        store
            .store_relay_media(&box1, &write1, &capability, &first, now + 1)
            .unwrap();
        assert_eq!(store.media_progress(&first.media_id, now).unwrap(), 1);
        assert!(
            store
                .store_relay_media(&box2, &write2, &capability, &first, now)
                .is_err()
        );
        assert!(
            store
                .store_relay_media(&box1, &write1, &other_capability, &first, now)
                .is_err()
        );
        assert!(
            store
                .store_local_media(std::slice::from_ref(&first), &other_capability, now)
                .is_err()
        );
        let mut changed = chunk(0, now);
        changed.ciphertext[0] ^= 1;
        assert!(
            store
                .store_relay_media(&box1, &write1, &capability, &changed, now)
                .is_err()
        );
        assert!(
            store
                .store_local_media(&[changed], &capability, now)
                .is_err()
        );
        let next = chunk(1, now + 1);
        assert!(
            store
                .store_relay_media(&box1, &write1, &capability, &next, now + 1)
                .is_err()
        );
        assert!(
            store
                .store_local_media(&[next], &capability, now + 1)
                .is_err()
        );
        let next = chunk(1, now);
        assert!(
            store
                .store_relay_media(&box2, &write2, &capability, &next, now)
                .is_err()
        );
        store
            .store_relay_media(&box1, &write1, &capability, &next, now)
            .unwrap();
        assert_original(
            store
                .get_relay_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
        assert_original(
            store
                .get_local_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
    }

    #[test]
    fn media_ttl_is_absolute_and_purge_reclaims_both_caches_at_the_boundary() {
        let (_directory, store) = profile();
        let now = crate::model::now();
        let first = chunk(0, now);
        let capability = "12".repeat(32);
        let (mailbox, write, _) = store.allocate("alice").unwrap();
        store
            .store_local_media(std::slice::from_ref(&first), &capability, now)
            .unwrap();
        store
            .store_relay_media(&mailbox, &write, &capability, &first, now)
            .unwrap();
        assert_original(
            store
                .get_relay_media(&first.media_id, 0, &capability, first.expires_at - 1)
                .unwrap(),
            &first,
        );
        assert!(
            store
                .get_relay_media(&first.media_id, 0, &capability, first.expires_at)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_local_media(&first.media_id, 0, &capability, first.expires_at)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .media_progress(&first.media_id, first.expires_at)
                .unwrap(),
            0
        );
        assert!(
            store
                .store_relay_media(&mailbox, &write, &capability, &first, first.expires_at)
                .is_err()
        );
        assert!(
            store
                .store_local_media(std::slice::from_ref(&first), &capability, first.expires_at)
                .is_err()
        );
        let mut long_lived = chunk(1, now);
        long_lived.expires_at += 1;
        assert!(
            store
                .store_local_media(&[long_lived], &capability, now)
                .is_err()
        );
        let invalid_index = chunk(MAX_CHUNKS as u32, now);
        assert!(
            store
                .store_relay_media(&mailbox, &write, &capability, &invalid_index, now)
                .is_err()
        );
        assert_eq!(store.purge(first.expires_at).unwrap(), 2);
        assert_eq!(relay_usage(&store.connection, &mailbox).unwrap(), (0, 0));
        let local_count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM local_media", [], |r| r.get(0))
            .unwrap();
        assert_eq!(local_count, 0);
    }

    #[test]
    fn local_staging_rolls_back_every_chunk_on_quota_or_database_failure() {
        let (_directory, mut store) = profile();
        let now = crate::model::now();
        let capability = "12".repeat(32);
        let first = chunk(0, now);
        let size = accounted_bytes(&first).unwrap() as usize;
        store.limits.local_media_bytes = size;
        store.limits.total_bytes = 1; // Relay capacity is independent of the local cache.
        assert!(
            store
                .store_local_media(&[chunk(0, now), chunk(1, now)], &capability, now)
                .is_err()
        );
        assert_eq!(store.media_progress(&first.media_id, now).unwrap(), 0);
        store
            .store_local_media(std::slice::from_ref(&first), &capability, now)
            .unwrap();
        assert!(
            store
                .store_local_media(&[chunk(1, now)], &capability, now)
                .is_err()
        );
        assert_original(
            store
                .get_local_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
        store.limits.local_media_bytes = size * 3;
        store.connection.execute_batch(
            "CREATE TRIGGER fail_media_insert BEFORE INSERT ON local_media WHEN NEW.chunk_index = 2
             BEGIN SELECT RAISE(ABORT, 'injected media write failure'); END;"
        ).unwrap();
        assert!(
            store
                .store_local_media(&[chunk(1, now), chunk(2, now)], &capability, now)
                .is_err()
        );
        assert_eq!(store.media_progress(&first.media_id, now).unwrap(), 1);
        assert!(
            store
                .get_local_media(&first.media_id, 1, &capability, now)
                .unwrap()
                .is_none()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_media_insert;")
            .unwrap();
        store.limits.local_media_bytes = size;
        let later = chunk(0, first.expires_at);
        store
            .store_local_media(&[later], &capability, first.expires_at)
            .unwrap();
        assert_eq!(
            store
                .media_progress(&first.media_id, first.expires_at)
                .unwrap(),
            1
        );
    }

    #[test]
    fn relay_text_and_media_share_mailbox_and_global_quotas_in_both_write_directions() {
        let (_directory, mut store) = profile();
        let now = crate::model::now();
        let capability = "12".repeat(32);
        let first = chunk(0, now);
        let text = envelope(now);
        let media_size = accounted_bytes(&first).unwrap() as usize;
        let text_size = serde_json::to_vec(&text).unwrap().len() + RECORD_OVERHEAD;
        let combined = media_size + text_size;
        store.limits.mailbox_bytes = combined;
        store.limits.total_bytes = combined + media_size;
        let (box1, write1, read1) = store.allocate("alice").unwrap();
        let (box2, write2, _) = store.allocate("bob").unwrap();
        store.store(&box1, &write1, &text, now).unwrap();
        store
            .store_relay_media(&box1, &write1, &capability, &first, now)
            .unwrap();
        assert!(
            store
                .store_relay_media(&box1, &write1, &capability, &chunk(1, now), now)
                .is_err()
        );
        let mut other_text = envelope(now);
        other_text.id = "other-message".into();
        assert!(store.store(&box1, &write1, &other_text, now).is_err());
        let mut other_file = chunk(0, now);
        other_file.media_id = "cd".repeat(32);
        store
            .store_relay_media(&box2, &write2, &capability, &other_file, now)
            .unwrap();
        assert!(store.store(&box2, &write2, &text, now).is_err());
        other_file.index = 1;
        assert!(
            store
                .store_relay_media(&box2, &write2, &capability, &other_file, now)
                .is_err()
        );
        assert_eq!(store.fetch(&box1, &read1, "alice", now).unwrap().len(), 1);
        assert_original(
            store
                .get_relay_media(&first.media_id, 0, &capability, now)
                .unwrap(),
            &first,
        );
        assert_eq!(
            relay_usage(&store.connection, &box1).unwrap(),
            (combined as i64, (combined + media_size) as i64)
        );
        // A new text write reclaims expired media as well as expired text.
        let later = envelope(first.expires_at);
        store
            .store(&box1, &write1, &later, first.expires_at)
            .unwrap();
        assert_eq!(
            relay_usage(&store.connection, &box1).unwrap(),
            (text_size as i64, text_size as i64)
        );
        // The media write path also frees expired text before enforcing capacity.
        let newest = chunk(0, later.expires_at);
        store
            .store_relay_media(&box1, &write1, &capability, &newest, later.expires_at)
            .unwrap();
        assert_eq!(
            relay_usage(&store.connection, &box1).unwrap(),
            (media_size as i64, media_size as i64)
        );
    }

    #[test]
    fn schema_one_migration_preserves_encrypted_state_mailboxes_and_messages() {
        let (directory, store) = profile();
        let path = directory.path().join("profile.db");
        let now = crate::model::now();
        let allocation = store.allocate("alice").unwrap();
        let text = envelope(now);
        store
            .store(&allocation.0, &allocation.1, &text, now)
            .unwrap();
        let state = AppState {
            name: "existing encrypted account".into(),
            crypto: vec![4, 5, 6],
            ..AppState::default()
        };
        store.save_state(&state).unwrap();
        let mut old_state = serde_json::to_value(&state).unwrap();
        old_state.as_object_mut().unwrap().remove("media_uploads");
        old_state.as_object_mut().unwrap().remove("media_downloads");
        store
            .connection
            .execute(
                "UPDATE app_state SET body = ?1 WHERE singleton = 1",
                params![serde_json::to_vec(&old_state).unwrap()],
            )
            .unwrap();
        // This is the exact version-one schema, with real encrypted application data.
        store
            .connection
            .execute_batch(
                "DROP TABLE local_media; DROP TABLE relay_media; PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(store);
        let before = std::fs::read(&path).unwrap();
        assert!(Store::open(&path, "wrong password").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let store = Store::open(&path, "media test password").unwrap();
        let version: i64 = store
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let loaded = store.load_state().unwrap().unwrap();
        assert_eq!(loaded.name, state.name);
        assert_eq!(loaded.crypto, state.crypto);
        assert_eq!(store.allocate("alice").unwrap(), allocation);
        assert_eq!(
            store
                .fetch(&allocation.0, &allocation.2, "alice", now)
                .unwrap()[0]
                .id,
            text.id
        );
        store
            .store_local_media(&[chunk(0, now)], &"12".repeat(32), now)
            .unwrap();
        drop(store);
        let store = Store::open(&path, "media test password").unwrap();
        assert_eq!(store.media_progress(&"ab".repeat(32), now).unwrap(), 1);
    }

    #[test]
    fn expired_media_jobs_alone_trigger_persistent_state_cleanup() {
        use crate::model::{Mailbox, MediaDownload, MediaUpload};

        let (_directory, store) = profile();
        let now = crate::model::now();
        let mut state = AppState::default();
        state.media_uploads.push(MediaUpload {
            media_id: "ab".repeat(32),
            mailbox: Mailbox {
                node_ticket: "test".into(),
                mailbox_id: "mailbox".into(),
                write_token: "12".repeat(32),
            },
            read_token: "34".repeat(32),
            next_chunk: 0,
            chunks: 1,
            expires_at: now,
        });
        state.media_downloads.push(MediaDownload {
            message_id: "message".into(),
            conversation: "group".into(),
            media_id: "cd".repeat(32),
            next_chunk: 0,
            source_cursor: 0,
            expires_at: now,
        });
        store.save_state(&state).unwrap();
        let loaded = store.load_state().unwrap().unwrap();
        assert!(loaded.media_uploads.is_empty() && loaded.media_downloads.is_empty());
        let persisted = super::super::read_state(&store.connection)
            .unwrap()
            .unwrap();
        assert!(persisted.media_uploads.is_empty() && persisted.media_downloads.is_empty());
        store.save_state(&state).unwrap();
        assert_eq!(store.purge(now).unwrap(), 2);
        let persisted = super::super::read_state(&store.connection)
            .unwrap()
            .unwrap();
        assert!(persisted.media_uploads.is_empty() && persisted.media_downloads.is_empty());
    }
}
