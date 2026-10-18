//! Additional tables in a dedicated SQLCipher Store, never in an App profile.

use super::*;
use crate::server_protocol::{
    SERVER_PAGE_BYTES, SERVER_PAGE_RECORDS, SequencedEnvelope, SignedGroupConfig,
    SignedGroupControl, SignedInboxRecord, SignedMailboxBinding,
};

pub(crate) const SERVER_MAX_GROUPS: usize = 128;
pub(crate) const SERVER_MAX_PERSONAL_MAILBOXES: usize = 512;
const MAX_GROUP_IDENTITIES: usize = 512;
const MAX_INBOX_RECORDS: usize = 4096;

impl Store {
    pub(crate) fn server_initialize(&self, body: &[u8]) -> Result<()> {
        ensure!(
            read_state(&self.connection)?.is_none(),
            "a client profile cannot become a server"
        );
        let transaction = self.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE server_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body BLOB NOT NULL);
             CREATE TABLE server_groups (
                 id TEXT PRIMARY KEY, body BLOB NOT NULL,
                 mailbox_id TEXT NOT NULL UNIQUE REFERENCES relay_mailboxes(id),
                 write_token TEXT NOT NULL, read_token TEXT NOT NULL
             );
             CREATE TABLE server_group_members (
                 group_id TEXT NOT NULL REFERENCES server_groups(id), identity TEXT NOT NULL,
                 endpoint TEXT NOT NULL, removed_epoch INTEGER, PRIMARY KEY(group_id, identity)
             );
             CREATE INDEX server_member_endpoint ON server_group_members(endpoint);
             CREATE TABLE server_personal_mailboxes (
                 identity TEXT PRIMARY KEY, endpoint TEXT NOT NULL UNIQUE, body BLOB NOT NULL,
                 mailbox_id TEXT NOT NULL UNIQUE REFERENCES relay_mailboxes(id)
             );
             CREATE TABLE server_group_messages (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 group_id TEXT NOT NULL REFERENCES server_groups(id),
                 mailbox_id TEXT NOT NULL, message_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                 UNIQUE(group_id, message_id),
                 FOREIGN KEY(mailbox_id, message_id) REFERENCES relay_envelopes(mailbox_id, message_id) ON DELETE CASCADE
             );
             CREATE INDEX server_group_sequence ON server_group_messages(group_id, sequence);
             CREATE TABLE server_controls (
                 group_id TEXT NOT NULL REFERENCES server_groups(id), epoch INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL, body BLOB NOT NULL, accounted_bytes INTEGER NOT NULL,
                 PRIMARY KEY(group_id, epoch)
             );
             CREATE INDEX server_control_expiry ON server_controls(expires_at);
             CREATE TABLE server_inbox (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
                 group_id TEXT NOT NULL REFERENCES server_groups(id), recipient TEXT NOT NULL,
                 expires_at INTEGER NOT NULL, digest BLOB NOT NULL, body BLOB,
                 accounted_bytes INTEGER NOT NULL, delivered INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX server_inbox_expiry ON server_inbox(expires_at);
             CREATE INDEX server_inbox_recipient ON server_inbox(group_id, recipient, delivered);",
        )?;
        transaction.execute(
            "INSERT INTO server_state(singleton,body) VALUES(1,?1)",
            [body],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_load(&self) -> Result<Vec<u8>> {
        ensure!(
            read_state(&self.connection)?.is_none(),
            "a client profile is not a server"
        );
        self.connection
            .query_row(
                "SELECT body FROM server_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .context("server is not initialized")
    }

    pub(crate) fn server_group(&self, group: &str) -> Result<Option<SignedGroupConfig>> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT body FROM server_groups WHERE id=?1",
                [group],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).context("invalid stored group config"))
            .transpose()
    }

    pub(crate) fn server_save_group(
        &self,
        config: &SignedGroupConfig,
        mailbox: &(String, String, String),
    ) -> Result<()> {
        let transaction = self.transaction()?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM server_groups WHERE id=?1)",
            [&config.config.group_id],
            |row| row.get(0),
        )?;
        let count: usize = transaction
            .query_row("SELECT count(*) FROM server_groups", [], |row| {
                row.get::<_, i64>(0)
            })?
            .try_into()?;
        ensure!(
            exists || count < SERVER_MAX_GROUPS,
            "server group limit reached"
        );
        let old_members: usize = transaction
            .query_row(
                "SELECT count(*) FROM server_group_members WHERE group_id=?1",
                [&config.config.group_id],
                |row| row.get::<_, i64>(0),
            )?
            .try_into()?;
        let mut added = 0;
        for member in &config.config.members {
            let known: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM server_group_members WHERE group_id=?1 AND identity=?2)",
                params![config.config.group_id, member.identity], |row| row.get(0))?;
            added += usize::from(!known);
        }
        ensure!(
            old_members + added <= MAX_GROUP_IDENTITIES,
            "server group membership history limit reached"
        );
        transaction.execute(
            "INSERT INTO server_groups(id,body,mailbox_id,write_token,read_token) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET body=excluded.body",
            params![config.config.group_id, serde_json::to_vec(config)?, mailbox.0, mailbox.1, mailbox.2],
        )?;
        for (identity, epoch) in &config.config.removal_epochs {
            transaction.execute(
                "UPDATE server_group_members SET removed_epoch=CASE
                WHEN removed_epoch IS NULL THEN ?3 ELSE min(removed_epoch,?3) END
                WHERE group_id=?1 AND identity=?2",
                params![config.config.group_id, identity, i64::try_from(*epoch)?],
            )?;
        }
        for member in &config.config.members {
            transaction.execute("INSERT INTO server_group_members(group_id,identity,endpoint) VALUES(?1,?2,?3)
                ON CONFLICT(group_id,identity) DO UPDATE SET endpoint=excluded.endpoint,removed_epoch=NULL",
                params![config.config.group_id, member.identity, member.endpoint])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_group_mailbox(&self, group: &str) -> Result<(String, String, String)> {
        self.connection
            .query_row(
                "SELECT mailbox_id,write_token,read_token FROM server_groups WHERE id=?1",
                [group],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context("unknown hosted group")
    }

    pub(crate) fn server_known_member(&self, group: &str, identity: &str) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM server_group_members WHERE group_id=?1 AND identity=?2)",
            params![group, identity],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn server_removed_epoch(&self, group: &str, identity: &str) -> Result<Option<u64>> {
        let value: Option<i64> = self.connection.query_row(
            "SELECT removed_epoch FROM server_group_members WHERE group_id=?1 AND identity=?2",
            params![group, identity],
            |row| row.get(0),
        )?;
        value
            .map(|value| u64::try_from(value).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn server_former_member_epoch(&self, group: &str, endpoint: &str) -> Result<u64> {
        let epoch: Option<i64> = self.connection.query_row(
            "SELECT max(removed_epoch) FROM server_group_members WHERE group_id=?1 AND endpoint=?2",
            params![group, endpoint],
            |row| row.get(0),
        )?;
        Ok(epoch
            .context("endpoint has no previous membership in this group")?
            .try_into()?)
    }

    pub(crate) fn server_binding(&self, identity: &str) -> Result<Option<SignedMailboxBinding>> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT body FROM server_personal_mailboxes WHERE identity=?1",
                [identity],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).context("invalid stored mailbox binding"))
            .transpose()
    }

    pub(crate) fn server_check_binding_endpoint(
        &self,
        binding: &SignedMailboxBinding,
    ) -> Result<()> {
        let identity: Option<String> = self
            .connection
            .query_row(
                "SELECT identity FROM server_personal_mailboxes WHERE endpoint=?1",
                [&binding.binding.endpoint],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            identity.is_none_or(|identity| identity == binding.binding.identity),
            "endpoint is already bound to a different mailbox identity"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn server_mailbox_count(&self) -> Result<usize> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM relay_mailboxes", [], |row| {
                row.get::<_, i64>(0)
            })?
            .try_into()?)
    }

    pub(crate) fn server_save_binding(
        &self,
        binding: &SignedMailboxBinding,
        mailbox: &str,
    ) -> Result<()> {
        let transaction = self.transaction()?;
        let count: usize = transaction
            .query_row(
                "SELECT count(*) FROM server_personal_mailboxes",
                [],
                |row| row.get::<_, i64>(0),
            )?
            .try_into()?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM server_personal_mailboxes WHERE identity=?1)",
            [&binding.binding.identity],
            |row| row.get(0),
        )?;
        ensure!(
            exists || count < SERVER_MAX_PERSONAL_MAILBOXES,
            "personal mailbox limit reached"
        );
        transaction.execute("INSERT INTO server_personal_mailboxes(identity,endpoint,body,mailbox_id) VALUES(?1,?2,?3,?4)
            ON CONFLICT(identity) DO UPDATE SET endpoint=excluded.endpoint,body=excluded.body",
            params![binding.binding.identity,binding.binding.endpoint,serde_json::to_vec(binding)?,mailbox])?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_personal_owner(
        &self,
        mailbox: &str,
        peer: Option<&str>,
    ) -> Result<String> {
        let (identity, endpoint): (String, String) = self
            .connection
            .query_row(
                "SELECT identity,endpoint FROM server_personal_mailboxes WHERE mailbox_id=?1",
                [mailbox],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("unknown personal mailbox")?;
        ensure!(
            peer.is_none_or(|peer| peer == endpoint),
            "mailbox endpoint is not authorized"
        );
        Ok(format!("personal:{identity}"))
    }

    pub(crate) fn server_check_envelope_capacity(
        &self,
        mailbox: &str,
        envelope: &Envelope,
    ) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_envelopes WHERE mailbox_id=?1 AND message_id=?2)",
            params![mailbox, envelope.id],
            |row| row.get(0),
        )?;
        if !exists {
            check_capacity(
                &self.connection,
                mailbox,
                serde_json::to_vec(envelope)?.len() + RECORD_OVERHEAD,
                self.limits.mailbox_bytes,
                self.limits.total_bytes,
            )?;
        }
        Ok(())
    }

    pub(crate) fn server_check_media_capacity(
        &self,
        mailbox: &str,
        chunk: &crate::media::MediaChunk,
    ) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_media WHERE media_id=?1 AND chunk_index=?2)",
            params![chunk.media_id, chunk.index],
            |row| row.get(0),
        )?;
        if !exists {
            check_capacity(
                &self.connection,
                mailbox,
                chunk.ciphertext.len() + RECORD_OVERHEAD,
                self.limits.mailbox_bytes,
                self.limits.total_bytes,
            )?;
        }
        Ok(())
    }

    pub(crate) fn server_index_message(
        &self,
        group: &str,
        mailbox: &str,
        message: &str,
        epoch: u64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO server_group_messages(group_id,mailbox_id,message_id,epoch) VALUES(?1,?2,?3,?4)
            ON CONFLICT(group_id,message_id) DO NOTHING",
            params![group, mailbox, message,i64::try_from(epoch)?],
        )?;
        Ok(())
    }

    pub(crate) fn server_fetch_group(
        &self,
        group: &str,
        after: u64,
        joined_epoch: u64,
        time: i64,
    ) -> Result<(Vec<SequencedEnvelope>, u64)> {
        let after_sql = i64::try_from(after).context("invalid group cursor")?;
        let mut statement = self.connection.prepare("SELECT log.sequence,envelope.body FROM server_group_messages log
            JOIN relay_envelopes envelope ON envelope.mailbox_id=log.mailbox_id AND envelope.message_id=log.message_id
            WHERE log.group_id=?1 AND log.sequence>?2 AND envelope.expires_at>?3 AND log.epoch>=?5 ORDER BY log.sequence LIMIT ?4")?;
        let mut rows = statement.query(params![
            group,
            after_sql,
            time,
            SERVER_PAGE_RECORDS as i64,
            i64::try_from(joined_epoch)?
        ])?;
        let mut page = Vec::new();
        let mut used = 128usize;
        let mut next = after;
        while let Some(row) = rows.next()? {
            let sequence: u64 = row.get::<_, i64>(0)?.try_into()?;
            let body: Vec<u8> = row.get(1)?;
            let record = SequencedEnvelope {
                sequence,
                envelope: serde_json::from_slice(&body)?,
            };
            let size = serde_json::to_vec(&record)?.len() + 1;
            ensure!(
                used + size < MAX_FRAME_BYTES,
                "stored group message exceeds frame limit"
            );
            if !page.is_empty() && used + size > SERVER_PAGE_BYTES {
                break;
            }
            record.envelope.validate(time)?;
            used += size;
            next = sequence;
            page.push(record);
        }
        Ok((page, next))
    }

    pub(crate) fn server_media_group(&self, media_id: &str) -> Result<Option<String>> {
        Ok(self.connection.query_row("SELECT groups.id FROM relay_media media JOIN server_groups groups ON media.mailbox_id=groups.mailbox_id
            WHERE media.media_id=?1 LIMIT 1", [media_id], |row| row.get(0)).optional()?)
    }

    pub(crate) fn server_put_control(&self, control: &SignedGroupControl) -> Result<()> {
        let body = serde_json::to_vec(control)?;
        let epoch = i64::try_from(control.record.epoch).context("group epoch is too large")?;
        let transaction = self.transaction()?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT body FROM server_controls WHERE group_id=?1 AND epoch=?2",
                params![control.record.conversation, epoch],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(existing == body, "conflicting hosted control epoch");
            return Ok(());
        }
        let mailbox = self.server_group_mailbox(&control.record.conversation)?.0;
        let size = body.len() + RECORD_OVERHEAD;
        check_capacity(
            &transaction,
            &mailbox,
            size,
            self.limits.mailbox_bytes,
            self.limits.total_bytes,
        )?;
        transaction.execute("INSERT INTO server_controls(group_id,epoch,expires_at,body,accounted_bytes) VALUES(?1,?2,?3,?4,?5)",
            params![control.record.conversation,epoch,control.expires_at,body,size as i64])?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_fetch_controls(
        &self,
        group: &str,
        after: u64,
        through: u64,
        time: i64,
    ) -> Result<Vec<SignedGroupControl>> {
        let mut statement = self.connection.prepare("SELECT body FROM server_controls WHERE group_id=?1 AND epoch>?2 AND epoch<=?4 AND expires_at>?3 ORDER BY epoch LIMIT 32")?;
        let mut rows = statement.query(params![
            group,
            i64::try_from(after).context("invalid control epoch")?,
            time,
            i64::try_from(through)?
        ])?;
        let mut page = Vec::new();
        let mut used = 128usize;
        while let Some(row) = rows.next()? {
            let body: Vec<u8> = row.get(0)?;
            if !page.is_empty() && used + body.len() + 1 > SERVER_PAGE_BYTES {
                break;
            }
            used += body.len() + 1;
            ensure!(used < MAX_FRAME_BYTES, "stored control exceeds frame limit");
            page.push(serde_json::from_slice(&body)?);
        }
        Ok(page)
    }

    pub(crate) fn server_put_inbox(&self, record: &SignedInboxRecord) -> Result<()> {
        let body = serde_json::to_vec(record)?;
        let digest = Sha256::digest(&body).to_vec();
        let transaction = self.transaction()?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT digest FROM server_inbox WHERE id=?1",
                [&record.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                existing == digest,
                "inbox ID already exists with different content"
            );
            return Ok(());
        }
        let count: usize = transaction
            .query_row("SELECT count(*) FROM server_inbox", [], |row| {
                row.get::<_, i64>(0)
            })?
            .try_into()?;
        ensure!(count < MAX_INBOX_RECORDS, "server control inbox is full");
        let mailbox = self.server_group_mailbox(&record.group_id)?.0;
        let size = body.len() + RECORD_OVERHEAD;
        check_capacity(
            &transaction,
            &mailbox,
            size,
            self.limits.mailbox_bytes,
            self.limits.total_bytes,
        )?;
        transaction.execute("INSERT INTO server_inbox(id,group_id,recipient,expires_at,digest,body,accounted_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![record.id,record.group_id,record.recipient,record.expires_at,digest,body,size as i64])?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_fetch_inbox(
        &self,
        peer: &str,
        time: i64,
    ) -> Result<Vec<SignedInboxRecord>> {
        let mut statement = self.connection.prepare("SELECT inbox.body,members.removed_epoch FROM server_inbox inbox
            JOIN server_group_members members ON members.group_id=inbox.group_id AND members.identity=inbox.recipient
            WHERE members.endpoint=?1 AND inbox.expires_at>?2 AND inbox.delivered=0 ORDER BY inbox.sequence")?;
        let mut rows = statement.query(params![peer, time])?;
        let mut page = Vec::new();
        let mut used = 128usize;
        while let Some(row) = rows.next()? {
            let body: Vec<u8> = row.get(0)?;
            let removed_epoch = row
                .get::<_, Option<i64>>(1)?
                .map(u64::try_from)
                .transpose()?;
            let record: SignedInboxRecord = serde_json::from_slice(&body)?;
            if let Some(epoch) = removed_epoch
                && !matches!(&record.control, crate::server_protocol::HostedControl::Control { record } if record.epoch == epoch)
            {
                continue;
            }
            if !page.is_empty() && used + body.len() + 1 > SERVER_PAGE_BYTES {
                break;
            }
            used += body.len() + 1;
            ensure!(
                used < MAX_FRAME_BYTES,
                "stored inbox control exceeds frame limit"
            );
            page.push(record);
            if page.len() == SERVER_PAGE_RECORDS {
                break;
            }
        }
        Ok(page)
    }

    pub(crate) fn server_ack_inbox(&self, peer: &str, ids: &[String]) -> Result<()> {
        ensure!(
            ids.len() <= SERVER_PAGE_RECORDS
                && ids.iter().all(|id| !id.is_empty() && id.len() <= 128),
            "invalid control acknowledgement batch"
        );
        let transaction = self.transaction()?;
        for id in ids {
            // Keep the signed-body digest until original expiry so retransmission
            // after a lost ACK cannot resurrect already processed membership work.
            transaction.execute("UPDATE server_inbox SET body=NULL, delivered=1, accounted_bytes=?3 WHERE id=?1
                AND EXISTS(SELECT 1 FROM server_group_members members WHERE members.group_id=server_inbox.group_id
                    AND members.identity=server_inbox.recipient AND members.endpoint=?2)",
                params![id,peer,RECORD_OVERHEAD as i64])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn server_purge(&self, time: i64) -> Result<usize> {
        let transaction = self.transaction()?;
        let mut removed =
            transaction.execute("DELETE FROM relay_envelopes WHERE expires_at<=?1", [time])?;
        removed += media_store::purge_relay(&transaction, time)?;
        removed +=
            transaction.execute("DELETE FROM server_controls WHERE expires_at<=?1", [time])?;
        removed += transaction.execute("DELETE FROM server_inbox WHERE expires_at<=?1", [time])?;
        transaction.commit()?;
        Ok(removed)
    }

    pub(crate) fn server_counts(&self) -> Result<(usize, usize, usize, usize, usize, usize)> {
        let mut values = [0usize; 5];
        for (slot, table) in values.iter_mut().zip([
            "server_groups",
            "server_personal_mailboxes",
            "relay_envelopes",
            "relay_media",
            "server_inbox WHERE delivered=0",
        ]) {
            *slot = self
                .connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })?
                .try_into()?;
        }
        let used = total_usage(&self.connection)?;
        Ok((
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            used.try_into()?,
        ))
    }
}

fn total_usage(connection: &Connection) -> Result<i64> {
    Ok(connection.query_row(
        "SELECT
        (SELECT coalesce(sum(accounted_bytes),0) FROM relay_envelopes) +
        (SELECT coalesce(sum(accounted_bytes),0) FROM relay_media) +
        (SELECT coalesce(sum(accounted_bytes),0) FROM server_controls) +
        (SELECT coalesce(sum(accounted_bytes),0) FROM server_inbox)",
        [],
        |row| row.get(0),
    )?)
}

fn check_capacity(
    connection: &Connection,
    mailbox: &str,
    additional: usize,
    per_mailbox: usize,
    total: usize,
) -> Result<()> {
    let (relay_used, _) = media_store::relay_usage(connection, mailbox)?;
    let extra_used: i64 = connection.query_row("SELECT
        (SELECT coalesce(sum(control.accounted_bytes),0) FROM server_controls control JOIN server_groups groups ON groups.id=control.group_id WHERE groups.mailbox_id=?1) +
        (SELECT coalesce(sum(inbox.accounted_bytes),0) FROM server_inbox inbox JOIN server_groups groups ON groups.id=inbox.group_id WHERE groups.mailbox_id=?1)",
        [mailbox], |row| row.get(0))?;
    let additional = i64::try_from(additional)?;
    ensure!(
        relay_used
            .saturating_add(extra_used)
            .saturating_add(additional)
            <= per_mailbox as i64,
        "server mailbox capacity reached"
    );
    ensure!(
        total_usage(connection)?.saturating_add(additional) <= total as i64,
        "server capacity reached"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{ControlRecord, MESSAGE_TTL, now},
        server_protocol::{GroupConfig, HostedControl, ServerMember},
    };

    #[test]
    fn server_controls_inbox_and_ciphertext_share_durable_quotas() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::create(
            &directory.path().join("server.db"),
            "server resource regression",
        )?;
        store.server_initialize(b"{}")?;
        let time = now();
        let identity = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .to_bytes(),
        );
        let server_id = hex::encode([9; 32]);
        let config = SignedGroupConfig::sign(
            GroupConfig {
                server_id: server_id.clone(),
                group_id: "quota".into(),
                owner: identity.clone(),
                revision: 1,
                epoch: 1,
                members: vec![ServerMember {
                    identity: identity.clone(),
                    endpoint: hex::encode([2; 32]),
                    joined_epoch: 0,
                }],
                removal_epochs: Default::default(),
            },
            &[1; 32],
        )?;
        let mailbox = store.allocate("group:quota")?;
        store.server_save_group(&config, &mailbox)?;
        let control = SignedGroupControl {
            server_id: server_id.clone(),
            owner: identity.clone(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            record: ControlRecord {
                conversation: "quota".into(),
                epoch: 1,
                commit: vec![7; 100],
                proposals: vec![],
            },
            signature: Vec::new(),
        }
        .sign(&[1; 32])?;
        let envelope = Envelope {
            id: "ciphertext".into(),
            conversation: "quota".into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![255; 256],
        };
        let control_size = serde_json::to_vec(&control)?.len() + RECORD_OVERHEAD;
        let message_size = serde_json::to_vec(&envelope)?.len() + RECORD_OVERHEAD;
        store.limits.mailbox_bytes = control_size + message_size - 1;
        store.server_put_control(&control)?;
        assert!(
            store
                .server_check_envelope_capacity(&mailbox.0, &envelope)
                .is_err()
        );
        store.server_put_control(&control)?;
        assert_eq!(
            store.server_counts()?.5,
            control_size,
            "duplicate controls consume no additional quota"
        );

        store.limits.mailbox_bytes = usize::MAX / 2;
        store.limits.total_bytes = control_size + message_size - 1;
        let personal = store.allocate("personal:quota")?;
        assert!(
            store
                .server_check_envelope_capacity(&personal.0, &envelope)
                .is_err(),
            "control bytes count against other mailboxes' aggregate quota"
        );
        let inbox = SignedInboxRecord {
            server_id,
            id: "inbox".into(),
            group_id: "quota".into(),
            sender: identity.clone(),
            recipient: identity,
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            control: HostedControl::Control {
                record: control.record.clone(),
            },
            signature: Vec::new(),
        }
        .sign(&[1; 32])?;
        store.limits.total_bytes =
            control_size + serde_json::to_vec(&inbox)?.len() + RECORD_OVERHEAD;
        store.server_put_inbox(&inbox)?;
        let used = store.server_counts()?.5;
        let media = crate::media::MediaChunk {
            media_id: hex::encode([3; 32]),
            index: 0,
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![1; 17],
        };
        assert!(
            store
                .server_check_media_capacity(&personal.0, &media)
                .is_err()
        );
        assert_eq!(store.server_counts()?.5, used);
        store.server_ack_inbox(&hex::encode([2; 32]), &["inbox".into()])?;
        assert_eq!(store.server_counts()?.5, control_size + RECORD_OVERHEAD);
        store.server_put_inbox(&inbox)?;
        assert!(
            store
                .server_fetch_inbox(&hex::encode([2; 32]), time)?
                .is_empty(),
            "ACK survives producer retry"
        );
        store.server_purge(time + MESSAGE_TTL)?;
        assert_eq!(store.server_counts()?.5, 0);
        store.server_check_envelope_capacity(&personal.0, &envelope)?;
        Ok(())
    }
}
