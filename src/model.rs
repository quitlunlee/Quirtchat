use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MESSAGE_TTL: i64 = 72 * 60 * 60;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_GROUP_MEMBERS: usize = 50;
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: String,
    pub conversation: String,
    pub sender: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<crate::media::MediaDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: ChatMessage,
    pub signature: Vec<u8>,
}

impl ChatMessage {
    pub fn validate(&self, time: i64) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.expires_at.checked_sub(self.created_at) == Some(MESSAGE_TTL),
            "invalid message lifetime"
        );
        anyhow::ensure!(
            self.created_at <= time.saturating_add(300),
            "message clock is in the future"
        );
        anyhow::ensure!(self.expires_at > time, "message expired");
        anyhow::ensure!(
            (!self.text.is_empty() || self.attachment.is_some())
                && self.text.len() <= MAX_TEXT_BYTES,
            "invalid message length"
        );
        anyhow::ensure!(
            self.id.len() <= 64 && self.conversation.len() <= 128 && self.sender.len() <= 128,
            "invalid message identifiers"
        );
        if let Some(media) = &self.attachment {
            media.validate(time)?;
            anyhow::ensure!(
                media.created_at == self.created_at && media.expires_at == self.expires_at,
                "media lifetime must match its message"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub conversation: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn validate(&self, time: i64) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.expires_at.checked_sub(self.created_at) == Some(MESSAGE_TTL),
            "invalid envelope lifetime"
        );
        anyhow::ensure!(
            self.created_at <= time.saturating_add(300) && self.expires_at > time,
            "expired or future envelope"
        );
        anyhow::ensure!(
            self.ciphertext.len() <= 128 * 1024 && !self.ciphertext.is_empty(),
            "invalid ciphertext size"
        );
        anyhow::ensure!(
            self.id.len() <= 64 && self.conversation.len() <= 128,
            "invalid envelope identifiers"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<String>,
    pub epoch: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRecord {
    pub conversation: String,
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub proposals: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub node_ticket: String,
    pub mailbox_id: String,
    pub write_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub ticket: String,
    pub key_package: Vec<u8>,
    pub mailboxes: Vec<Mailbox>,
    pub version: u64,
    pub invite_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u16,
    pub contact: Contact,
    pub signature: Vec<u8>,
    pub transport_signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalMailbox {
    pub public: Mailbox,
    pub read_token: String,
    #[serde(default)]
    pub retired_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outgoing {
    pub recipient: String,
    pub envelope: Envelope,
    pub stored_at: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppState {
    pub name: String,
    pub identity_secret: Vec<u8>,
    pub transport_secret: Vec<u8>,
    pub crypto: Vec<u8>,
    pub contacts: BTreeMap<String, Contact>,
    pub conversations: BTreeMap<String, Conversation>,
    pub messages: Vec<ChatMessage>,
    pub outbox: Vec<Outgoing>,
    pub controls: Vec<ControlRecord>,
    pub mailboxes: Vec<LocalMailbox>,
    pub proxy: Option<String>,
    pub relay_enabled: bool,
    pub invite_token: String,
    pub key_package: Vec<u8>,
    pub contact_version: u64,
    pub pending: Vec<Pending>,
    pub peers: Vec<String>,
    pub invitations: BTreeMap<String, Invitation>,
    pub recovery_pending: Vec<String>,
    #[serde(default)]
    pub recovery_packages: BTreeMap<String, Vec<u8>>,
    pub accepted_welcomes: BTreeMap<String, String>,
    pub accepted_recoveries: BTreeMap<String, String>,
    pub issued_packages: BTreeMap<String, Invitation>,
    pub last_rekey: BTreeMap<String, i64>,
    pub pending_updates: BTreeMap<String, Vec<u8>>,
    pub message_signatures: BTreeMap<String, Vec<u8>>,
    pub history_grants: Vec<String>,
    pub deferred: Vec<Envelope>,
    #[serde(default)]
    pub media_uploads: Vec<MediaUpload>,
    #[serde(default)]
    pub media_downloads: Vec<MediaDownload>,
}

impl AppState {
    pub fn purge_expired(&mut self, time: i64) {
        self.messages.retain(|m| m.expires_at > time);
        self.outbox.retain(|m| m.envelope.expires_at > time);
        self.deferred.retain(|m| m.expires_at > time);
        self.media_uploads.retain(|m| m.expires_at > time);
        self.media_downloads.retain(|m| m.expires_at > time);
        let ids: std::collections::BTreeSet<_> = self
            .messages
            .iter()
            .map(|m| format!("{}/{}", m.conversation, m.id))
            .collect();
        self.message_signatures.retain(|id, _| ids.contains(id));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    BlobPut {
        mailbox_id: String,
        write_token: String,
        read_token: String,
        chunk: crate::media::MediaChunk,
    },
    BlobGet {
        media_id: String,
        index: u32,
        read_token: String,
    },
    Hello {
        invitation: Invitation,
        authorization: String,
    },
    Deliver {
        envelope: Envelope,
    },
    Join {
        conversation: Conversation,
        welcome: Vec<u8>,
        contacts: Vec<Invitation>,
    },
    Sync {
        conversation: String,
        after_epoch: u64,
    },
    Control {
        record: ControlRecord,
    },
    Recover {
        conversation: String,
        key_package: Vec<u8>,
    },
    KeyPackage {
        request_id: String,
    },
    Update {
        conversation: String,
        proposal: Vec<u8>,
    },
    History {
        conversation: String,
        after: Option<String>,
    },
    Allocate,
    Store {
        mailbox_id: String,
        write_token: String,
        envelope: Envelope,
    },
    Fetch {
        mailbox_id: String,
        read_token: String,
    },
    Delete {
        mailbox_id: String,
        read_token: String,
        ids: Vec<String>,
    },
    Peers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Blob(Option<crate::media::MediaChunk>),
    Ok,
    Error(String),
    Hello(Invitation),
    Controls(Vec<ControlRecord>),
    Sync {
        controls: Vec<ControlRecord>,
        contacts: Vec<Invitation>,
        current_epoch: u64,
    },
    Mailbox {
        mailbox_id: String,
        write_token: String,
        read_token: String,
    },
    Envelopes(Vec<Envelope>),
    Peers(Vec<String>),
    History {
        messages: Vec<SignedMessage>,
        next: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub recipient: String,
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaUpload {
    pub media_id: String,
    pub mailbox: Mailbox,
    pub read_token: String,
    pub next_chunk: u32,
    pub chunks: u32,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaDownload {
    pub message_id: String,
    pub conversation: String,
    pub media_id: String,
    pub next_chunk: u32,
    pub source_cursor: usize,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ttl_is_absolute_and_checked() {
        let mut message = ChatMessage {
            id: "m".into(),
            conversation: "g".into(),
            sender: "s".into(),
            created_at: 100,
            expires_at: 100 + MESSAGE_TTL,
            text: "hi".into(),
            attachment: None,
        };
        assert!(message.validate(100 + MESSAGE_TTL - 1).is_ok());
        assert!(message.validate(100 + MESSAGE_TTL).is_err());
        message.expires_at += 1;
        assert!(message.validate(100).is_err());
        message.created_at = i64::MIN;
        assert!(message.validate(100).is_err());
    }
}
