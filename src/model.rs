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
    /// None is the direct-message transport. Groups bind an independent ciphertext server.
    #[serde(default)]
    pub server: Option<HostedGroupRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedGroupRoute {
    pub ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalMailbox {
    pub node: String,
    pub mailbox_id: String,
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

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AppState {
    pub name: String,
    pub identity_secret: Vec<u8>,
    pub transport_secret: Vec<u8>,
    pub crypto: Vec<u8>,
    pub contacts: BTreeMap<String, Contact>,
    /// Local, unique display names. Never edit signed contact descriptors for a remark.
    #[serde(default)]
    pub contact_names: BTreeMap<String, String>,
    pub conversations: BTreeMap<String, Conversation>,
    pub messages: Vec<ChatMessage>,
    pub outbox: Vec<Outgoing>,
    pub controls: Vec<ControlRecord>,
    pub mailboxes: Vec<LocalMailbox>,
    #[serde(default)]
    pub personal_mailbox: Option<PersonalMailbox>,
    /// Explicitly trusted group delivery endpoints, including those with pending invitations.
    #[serde(default)]
    pub group_servers: Vec<String>,
    #[serde(default)]
    pub hosted: crate::app::HostedDeliveryState,
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
    #[serde(default)]
    pub issued_package_times: BTreeMap<String, IssuedPackageTime>,
    pub last_rekey: BTreeMap<String, i64>,
    pub pending_updates: BTreeMap<String, Vec<u8>>,
    pub message_signatures: BTreeMap<String, Vec<u8>>,
    /// Locally authenticated membership snapshots, retained for delayed MLS messages.
    #[serde(default)]
    pub history_epoch_members: BTreeMap<String, BTreeMap<u64, Vec<String>>>,
    /// Members authorized at each message's authenticated MLS epoch. Missing means
    /// unknown (including legacy profiles), never permission to share history.
    #[serde(default)]
    pub history_audiences: BTreeMap<String, Vec<String>>,
    pub history_grants: Vec<String>,
    pub deferred: Vec<Envelope>,
    #[serde(default)]
    pub media_uploads: Vec<MediaUpload>,
    #[serde(default)]
    pub media_downloads: Vec<MediaDownload>,
}

impl AppState {
    /// Upgrade legacy profiles deterministically, retaining every already assigned name.
    /// Reserve literal names (for example `Alex_1`) before allocating duplicate suffixes.
    pub fn normalize_contact_names(&mut self) {
        let previous = std::mem::take(&mut self.contact_names);
        let preferred: BTreeMap<_, _> = self
            .contacts
            .iter()
            .map(|(id, contact)| {
                let name = previous
                    .get(id)
                    .filter(|name| valid_contact_name(name))
                    .cloned()
                    .unwrap_or_else(|| {
                        let name = contact.name.trim();
                        if name.is_empty() {
                            "Contact".into()
                        } else {
                            name.into()
                        }
                    });
                (id.clone(), name)
            })
            .collect();
        let reserved: std::collections::BTreeSet<_> = preferred.values().cloned().collect();
        let mut assigned = std::collections::BTreeSet::new();
        // Previously assigned names win over newly imported contacts even when
        // the new identity sorts earlier. The remaining order is deterministic.
        let mut preferred: Vec<_> = preferred.into_iter().collect();
        preferred.sort_by_key(|(id, _)| {
            !previous
                .get(id)
                .is_some_and(|name| valid_contact_name(name))
        });
        for (id, base) in preferred {
            let name = if assigned.contains(&base) {
                unique_contact_name(&base, |name| {
                    assigned.contains(name) || reserved.contains(name)
                })
            } else {
                base
            };
            assigned.insert(name.clone());
            self.contact_names.insert(id, name);
        }
    }

    pub(crate) fn set_contact_name(&mut self, id: &str, base: &str) {
        let name = unique_contact_name(base, |name| {
            self.contact_names
                .iter()
                .any(|(other, existing)| other != id && existing == name)
        });
        self.contact_names.insert(id.to_owned(), name);
    }

    pub fn purge_expired(&mut self, time: i64) {
        self.hosted.purge_expired(time);
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
        self.history_audiences.retain(|id, _| ids.contains(id));
    }
}

pub(crate) fn valid_contact_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}

fn unique_contact_name(base: &str, occupied: impl Fn(&str) -> bool) -> String {
    if !occupied(base) {
        return base.to_owned();
    }
    for number in 1usize.. {
        let suffix = format!("_{number}");
        let mut end = base.len().min(128usize.saturating_sub(suffix.len()));
        while !base.is_char_boundary(end) {
            end -= 1;
        }
        let candidate = format!("{}{suffix}", &base[..end]);
        if !occupied(&candidate) {
            return candidate;
        }
    }
    unreachable!("a finite contact list cannot exhaust suffixes")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    HostedControl {
        record: crate::server_protocol::SignedHostedControl,
    },
    Server(crate::server_protocol::ServerRequest),
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
    Server(crate::server_protocol::ServerResponse),
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
pub struct IssuedPackageTime {
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub consumed_at: Option<i64>,
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
