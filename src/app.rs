use crate::{
    crypto::{CryptoEngine, Processed},
    model::*,
    storage::Store,
    transport::{Transport, ticket_endpoint_id},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

pub type Shared = Arc<Mutex<App>>;

pub struct App {
    pub state: AppState,
    pub crypto: CryptoEngine,
    pub store: Store,
    pub ticket: String,
    pub status: String,
}

fn random_secret() -> Vec<u8> {
    let mut bytes = vec![0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn fingerprint(id: &str) -> String {
    hex::encode(Sha256::digest(id.as_bytes()))
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("").to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

pub const ART_WIDTH: usize = 17;
pub const ART_HEIGHT: usize = 9;
/// Visit counts 0..=14 map to these glyphs; `S` and `E` are drawn over the result.
const ART_CHARS: &[u8] = b" .o+=*BOX@%&#/^";
type ArtGrid = [[u8; ART_WIDTH]; ART_HEIGHT];
type ArtCell = (usize, usize);

/// Raw visit counts of the walk plus its start and end cells.
fn art_walk(id: &str) -> (ArtGrid, ArtCell, ArtCell) {
    let digest = Sha256::digest(id.as_bytes());
    let mut grid = [[0u8; ART_WIDTH]; ART_HEIGHT];
    let start = (ART_WIDTH / 2, ART_HEIGHT / 2);
    let (mut x, mut y) = start;
    for byte in digest.iter() {
        let mut bits = *byte;
        for _ in 0..4 {
            x = if bits & 1 == 0 {
                x.saturating_sub(1)
            } else {
                (x + 1).min(ART_WIDTH - 1)
            };
            y = if bits & 2 == 0 {
                y.saturating_sub(1)
            } else {
                (y + 1).min(ART_HEIGHT - 1)
            };
            grid[y][x] = grid[y][x].saturating_add(1);
            bits >>= 2;
        }
    }
    (grid, start, (x, y))
}

/// OpenSSH-style "drunken bishop" walk over SHA-256(id). Rows are `ART_WIDTH` cells,
/// ASCII only. `S` marks the start and `E` the end of the walk.
pub fn randomart(id: &str) -> Vec<String> {
    let (grid, start, end) = art_walk(id);
    (0..ART_HEIGHT)
        .map(|y| {
            (0..ART_WIDTH)
                .map(|x| match (x, y) {
                    p if p == end => 'E',
                    p if p == start => 'S',
                    _ => ART_CHARS[usize::from(grid[y][x]).min(ART_CHARS.len() - 1)] as char,
                })
                .collect()
        })
        .collect()
}

/// Per-cell visit counts for colouring, same shape as `randomart`.
pub fn randomart_heat(id: &str) -> Vec<Vec<u8>> {
    art_walk(id).0.iter().map(|row| row.to_vec()).collect()
}

/// Four lines of 4x4 hex digits, the same text `fingerprint` prints on one line.
pub fn fingerprint_lines(id: &str) -> Vec<String> {
    let hex = hex::encode(Sha256::digest(id.as_bytes()));
    hex.as_bytes()
        .chunks(16)
        .map(|line| {
            line.chunks(4)
                .map(|group| std::str::from_utf8(group).unwrap_or(""))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// Plain-text card: framed randomart with the contact name and fingerprint below.
pub fn identity_card(name: &str, id: &str) -> String {
    // `[ ` and ` ]` take four columns, and at least one dash stays on each side.
    let room = ART_WIDTH.saturating_sub(6);
    let mut label = String::new();
    let mut used = 0;
    for c in name.chars().filter(|c| !c.is_control()) {
        let cells = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + cells > room {
            break;
        }
        used += cells;
        label.push(c);
    }
    let title = format!("[ {label} ]");
    let title_cells = used + 4;
    let left = (ART_WIDTH - title_cells) / 2;
    let right = ART_WIDTH - title_cells - left;
    let mut lines = vec![format!(
        "+{}{title}{}+",
        "-".repeat(left),
        "-".repeat(right)
    )];
    lines.extend(randomart(id).into_iter().map(|row| format!("|{row}|")));
    let tag = "[SHA256]";
    let left = (ART_WIDTH - tag.len()) / 2;
    let right = ART_WIDTH - tag.len() - left;
    lines.push(format!("+{}{tag}{}+", "-".repeat(left), "-".repeat(right)));
    lines.extend(fingerprint_lines(id));
    lines.join("\n")
}

/// Invitation file: identity card first, then the `clichat1:` token on its own line.
pub fn encode_invitation_file(invitation: &Invitation) -> Result<String> {
    let card = identity_card(&invitation.contact.name, &invitation.contact.id);
    Ok(format!("{card}\n{}\n", encode_invitation(invitation)?))
}

pub fn encode_invitation(invitation: &Invitation) -> Result<String> {
    Ok(format!(
        "clichat1:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(invitation)?)
    ))
}

/// Accepts a bare token, a one-line file, or a file with the identity card above the
/// token. The card is decoration: the displayed art is always recomputed from the id.
pub fn decode_invitation(text: &str) -> Result<Invitation> {
    ensure!(text.len() <= 256 * 1024, "invitation too large");
    let token = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("clichat1:"))
        .context("invalid invitation prefix")?;
    let bytes = URL_SAFE_NO_PAD.decode(&token["clichat1:".len()..])?;
    let invitation: Invitation = serde_json::from_slice(&bytes)?;
    verify_invitation(&invitation)?;
    Ok(invitation)
}

fn verify_invitation(invitation: &Invitation) -> Result<()> {
    ensure!(invitation.version == 1, "unsupported invitation version");
    let c = &invitation.contact;
    ensure!(
        !c.name.is_empty() && c.name.len() <= 128 && !c.name.chars().any(char::is_control),
        "invalid contact name"
    );
    ensure!(
        c.mailboxes.len() <= 3 && c.key_package.len() <= 64 * 1024 && c.invite_token.len() == 64,
        "invalid invitation fields"
    );
    let endpoint = crate::transport::decode_ticket(&c.ticket)?.id;
    let signed = serde_json::to_vec(&(invitation.version, c))?;
    let public: [u8; 32] = hex::decode(&c.id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid identity"))?;
    VerifyingKey::from_bytes(&public)?
        .verify_strict(&signed, &Signature::from_slice(&invitation.signature)?)?;
    VerifyingKey::from_bytes(endpoint.as_bytes())?.verify_strict(
        &signed,
        &Signature::from_slice(&invitation.transport_signature)?,
    )?;
    for mailbox in &c.mailboxes {
        ticket_endpoint_id(&mailbox.node_ticket)?;
    }
    Ok(())
}

fn signed_message_bytes(message: &ChatMessage) -> Result<Vec<u8>> {
    let mut bytes = b"clichat/message/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(message)?);
    Ok(bytes)
}

fn verify_message(signed: &SignedMessage) -> Result<()> {
    signed.message.validate(now())?;
    let key: [u8; 32] = hex::decode(&signed.message.sender)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid sender identity"))?;
    VerifyingKey::from_bytes(&key)?.verify_strict(
        &signed_message_bytes(&signed.message)?,
        &Signature::from_slice(&signed.signature)?,
    )?;
    Ok(())
}

impl App {
    pub fn initialize(store: Store, name: String) -> Result<Self> {
        ensure!(
            !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
            "invalid display name"
        );
        let secret = random_secret();
        let mut crypto = CryptoEngine::new(&secret)?;
        let state = AppState {
            name,
            identity_secret: secret,
            transport_secret: random_secret(),
            key_package: crypto.key_package()?,
            invite_token: hex::encode(random_secret()),
            relay_enabled: true,
            contact_version: 1,
            ..Default::default()
        };
        let mut app = Self {
            state,
            crypto,
            store,
            ticket: String::new(),
            status: "Initialized".into(),
        };
        app.save()?;
        Ok(app)
    }

    pub fn load(store: Store) -> Result<Self> {
        let mut state = store.load_state()?.context("profile is not initialized")?;
        state.normalize_contact_names();
        let crypto = CryptoEngine::from_snapshot(&state.crypto)?;
        let secret: [u8; 32] = state.identity_secret.as_slice().try_into()?;
        ensure!(
            hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
                == crypto.identity(),
            "profile identity does not match MLS state"
        );
        state.purge_expired(now());
        store.purge(now())?;
        let mut app = Self {
            state,
            crypto,
            store,
            ticket: String::new(),
            status: "Starting".into(),
        };
        // A legacy snapshot proves only its current MLS membership. Do not infer
        // audiences for already stored messages or for any older epoch.
        let owned: Vec<_> = app
            .state
            .conversations
            .values()
            .filter(|group| group.active && group.owner == app.id())
            .map(|group| group.id.clone())
            .collect();
        for id in owned {
            app.record_history_epoch(&id)?;
        }
        app.save()?;
        Ok(app)
    }

    pub fn id(&self) -> &str {
        self.crypto.identity()
    }

    pub fn save(&mut self) -> Result<()> {
        self.state.normalize_contact_names();
        self.state.purge_expired(now());
        self.maintain_key_packages(now())?;
        self.crypto.prune_expired_secrets()?;
        ensure!(
            serde_json::to_vec(&self.state.pending)?.len() <= 32 * 1024 * 1024,
            "pending control queue is full"
        );
        self.state.crypto = self.crypto.snapshot()?;
        self.store.save_state(&self.state)
    }

    pub fn atomic<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let previous = self.state.clone();
        match work(self).and_then(|result| {
            self.save()?;
            Ok(result)
        }) {
            Ok(result) => Ok(result),
            Err(error) => {
                self.crypto = CryptoEngine::from_snapshot(&previous.crypto)
                    .context("cannot restore crypto state after failed operation")?;
                self.state = previous;
                Err(error)
            }
        }
    }

    pub fn invitation(&self) -> Result<Invitation> {
        ensure!(!self.ticket.is_empty(), "network endpoint is not ready");
        let contact = Contact {
            id: self.id().to_owned(),
            name: self.state.name.clone(),
            ticket: self.ticket.clone(),
            key_package: self.state.key_package.clone(),
            mailboxes: self
                .state
                .mailboxes
                .iter()
                .filter(|m| m.retired_at.is_none())
                .map(|m| m.public.clone())
                .collect(),
            version: self.state.contact_version,
            invite_token: self.state.invite_token.clone(),
        };
        let key: [u8; 32] = self.state.identity_secret.as_slice().try_into()?;
        let signature = SigningKey::from_bytes(&key)
            .sign(&serde_json::to_vec(&(1u16, &contact))?)
            .to_bytes()
            .to_vec();
        let transport_key: [u8; 32] = self.state.transport_secret.as_slice().try_into()?;
        let transport_signature = SigningKey::from_bytes(&transport_key)
            .sign(&serde_json::to_vec(&(1u16, &contact))?)
            .to_bytes()
            .to_vec();
        Ok(Invitation {
            version: 1,
            contact,
            signature,
            transport_signature,
        })
    }

    pub fn import_contact(&mut self, invitation: Invitation) -> Result<String> {
        verify_invitation(&invitation)?;
        ensure!(
            CryptoEngine::contact_key_package_identity(&invitation.contact.key_package)?
                == invitation.contact.id,
            "key package identity mismatch"
        );
        let contact = &invitation.contact;
        ensure!(contact.id != self.id(), "cannot add yourself as a contact");
        let endpoint = ticket_endpoint_id(&contact.ticket)?;
        ensure!(
            !self.state.contacts.values().any(|old| old.id != contact.id
                && ticket_endpoint_id(&old.ticket).ok().as_deref() == Some(&endpoint)),
            "endpoint is already bound to another contact"
        );
        ensure!(
            self.state.contacts.len() < 512 || self.state.contacts.contains_key(&contact.id),
            "contact limit reached"
        );
        if let Some(old) = self.state.contacts.get(&contact.id) {
            ensure!(contact.version >= old.version, "stale contact descriptor");
        }
        let id = contact.id.clone();
        // Refreshing key packages or peer metadata must never rename a local contact.
        self.state.normalize_contact_names();
        self.state.contacts.insert(id.clone(), contact.clone());
        self.state.invitations.insert(id.clone(), invitation);
        self.state.normalize_contact_names();
        Ok(id)
    }

    /// Import a signed invitation and optionally assign a local remark. An empty
    /// remark retains an existing name, or uses the remote display name for a new contact.
    /// Call through `atomic` when the result must be persisted.
    pub fn import_contact_named(&mut self, invitation: Invitation, remark: &str) -> Result<String> {
        let remark = remark.trim();
        ensure!(
            remark.is_empty() || valid_contact_name(remark),
            "invalid contact remark"
        );
        let id = self.import_contact(invitation)?;
        if !remark.is_empty() {
            self.state.set_contact_name(&id, remark);
        }
        Ok(id)
    }

    pub fn contact_name<'a>(&'a self, id: &'a str) -> &'a str {
        self.state
            .contact_names
            .get(id)
            .map(String::as_str)
            .or_else(|| {
                self.state
                    .contacts
                    .get(id)
                    .map(|contact| contact.name.as_str())
            })
            .unwrap_or(id)
    }

    /// UI commands use exact local names, including spaces, without ID-prefix guessing.
    pub fn resolve_contact_name_exact(&self, name: &str) -> Result<String> {
        let mut matches = self
            .state
            .contacts
            .keys()
            .filter(|id| self.contact_name(id) == name);
        let id = matches.next().context("contact name not found")?;
        ensure!(matches.next().is_none(), "contact name is ambiguous");
        Ok(id.clone())
    }

    pub fn resolve_contact(&self, query: &str) -> Result<String> {
        if self.state.contacts.contains_key(query) {
            return Ok(query.to_owned());
        }
        if let Ok(id) = self.resolve_contact_name_exact(query) {
            return Ok(id);
        }
        let matches: Vec<_> = self
            .state
            .contacts
            .values()
            .filter(|c| c.id.starts_with(query))
            .collect();
        ensure!(
            matches.len() == 1,
            "contact not found or ambiguous; use its full identity"
        );
        Ok(matches[0].id.clone())
    }

    pub fn resolve_group(&self, query: &str) -> Result<String> {
        let matches: Vec<_> = self
            .state
            .conversations
            .values()
            .filter(|c| c.id == query || c.name == query || c.id.starts_with(query))
            .collect();
        ensure!(matches.len() == 1, "conversation not found or ambiguous");
        Ok(matches[0].id.clone())
    }

    pub fn create_direct(&mut self, name: String, member: String) -> Result<String> {
        self.create_conversation(name, vec![member])
    }

    fn create_conversation(&mut self, name: String, members: Vec<String>) -> Result<String> {
        ensure!(
            !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
            "invalid group name"
        );
        ensure!(
            members.len() < MAX_GROUP_MEMBERS,
            "group member limit reached"
        );
        ensure!(
            self.state.conversations.len() < 128,
            "conversation limit reached"
        );
        let id = uuid::Uuid::new_v4().to_string();
        self.crypto.create_group(&id)?;
        self.state.conversations.insert(
            id.clone(),
            Conversation {
                id: id.clone(),
                name,
                owner: self.id().into(),
                members: vec![self.id().into()],
                epoch: 0,
                active: true,
                server: None,
            },
        );
        self.record_history_epoch(&id)?;
        for member in members {
            self.add_member(&id, &member)?;
        }
        Ok(id)
    }

    fn directory(&self, group: &Conversation) -> Vec<Invitation> {
        let mut contacts: Vec<_> = group
            .members
            .iter()
            .filter_map(|id| self.state.invitations.get(id).cloned())
            .collect();
        if let Ok(invite) = self.invitation() {
            contacts.push(invite);
        }
        contacts
    }

    fn owner_group(&self, id: &str) -> Result<Conversation> {
        let group = self
            .state
            .conversations
            .get(id)
            .context("unknown conversation")?;
        ensure!(
            group.owner == self.id() && group.active,
            "only the active group owner can do this"
        );
        Ok(group.clone())
    }

    /// Only MLS state verified locally can establish a history audience. Keep
    /// enough snapshots for every past epoch for which we retain decrypting keys.
    fn record_history_epoch(&mut self, id: &str) -> Result<()> {
        let epoch = self.crypto.epoch(id)?;
        let members = self.crypto.members(id)?;
        let epochs = self
            .state
            .history_epoch_members
            .entry(id.into())
            .or_default();
        epochs.insert(epoch, members);
        while epochs.len() > crate::crypto::PAST_EPOCHS + 1 {
            epochs.pop_first();
        }
        Ok(())
    }

    fn record_commit(
        &mut self,
        id: &str,
        bytes: Vec<u8>,
        recipients: &[String],
        proposals: Vec<Vec<u8>>,
    ) -> Result<()> {
        let record = ControlRecord {
            conversation: id.into(),
            epoch: self.crypto.epoch(id)?,
            commit: bytes,
            proposals,
        };
        let total: usize = self
            .state
            .controls
            .iter()
            .filter(|r| r.conversation == id)
            .map(|r| r.commit.len() + r.proposals.iter().map(Vec::len).sum::<usize>())
            .sum();
        if total + record.commit.len() + record.proposals.iter().map(Vec::len).sum::<usize>()
            > 32 * 1024 * 1024
        {
            self.state.controls.retain(|r| r.conversation != id);
        }
        self.state.controls.push(record.clone());
        let own = self.id().to_string();
        for recipient in recipients.iter().filter(|r| **r != own) {
            self.state.pending.retain(|p| !(p.recipient == *recipient && matches!(&p.request, Request::Control { record } if record.conversation == id)));
            self.state.pending.push(Pending {
                recipient: recipient.clone(),
                request: Request::Control {
                    record: record.clone(),
                },
            });
        }
        let group = self
            .state
            .conversations
            .get_mut(id)
            .context("unknown conversation")?;
        group.epoch = self.crypto.epoch(id)?;
        group.members = self.crypto.members(id)?;
        self.record_history_epoch(id)?;
        self.stage_hosted_group(id)?;
        Ok(())
    }

    pub fn add_member(&mut self, id: &str, member: &str) -> Result<()> {
        let before = self.owner_group(id)?;
        ensure!(
            before.server.is_some() || before.members.len() < 2,
            "host this conversation on a group server before adding more members"
        );
        ensure!(
            before.members.len() < MAX_GROUP_MEMBERS && !before.members.iter().any(|m| m == member),
            "member exists or group is full"
        );
        let contact = self
            .state
            .contacts
            .get(member)
            .context("unknown contact")?
            .clone();
        let (commit, welcome) = self.crypto.add_member(id, &contact.key_package)?;
        ensure!(
            self.crypto.members(id)?.iter().any(|m| m == member),
            "key package identity does not match contact"
        );
        self.record_commit(id, commit, &before.members, vec![])?;
        let conversation = self.state.conversations.get(id).unwrap().clone();
        let contacts = self.directory(&conversation);
        self.state.pending.push(Pending {
            recipient: member.into(),
            request: Request::Join {
                conversation,
                welcome,
                contacts,
            },
        });
        self.stage_hosted_group(id)?;
        Ok(())
    }

    pub fn remove_member(&mut self, id: &str, member: &str) -> Result<()> {
        let before = self.owner_group(id)?;
        ensure!(
            member != self.id(),
            "owner cannot leave; create a replacement group"
        );
        ensure!(before.members.iter().any(|m| m == member), "not a member");
        let commit = self.crypto.remove_member(id, member)?;
        self.record_commit(id, commit, &before.members, vec![])?;
        self.state
            .outbox
            .retain(|o| !(o.envelope.conversation == id && o.recipient == member));
        self.state
            .history_grants
            .retain(|g| g != &format!("{id}/{member}"));
        Ok(())
    }

    pub fn send(&mut self, id: &str, text: String) -> Result<String> {
        self.send_content(id, text, None, now())
    }

    fn send_content(
        &mut self,
        id: &str,
        text: String,
        attachment: Option<crate::media::MediaDescriptor>,
        time: i64,
    ) -> Result<String> {
        let group = self
            .state
            .conversations
            .get(id)
            .context("unknown conversation")?
            .clone();
        ensure!(group.active, "you are no longer a member");
        ensure!(
            group.server.is_some() || group.members.len() <= 2,
            "this legacy group needs a server; its owner must run group host first"
        );
        ensure!(
            !self.state.recovery_pending.iter().any(|g| g == id),
            "key recovery is in progress; wait for the owner before sending"
        );
        ensure!(
            self.state.outbox.len()
                + if group.server.is_some() {
                    1
                } else {
                    group.members.len().saturating_sub(1)
                }
                <= 10_000,
            "outbox is full"
        );
        let message = ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            conversation: id.into(),
            sender: self.id().into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            text,
            attachment,
        };
        message.validate(now())?;
        let key: [u8; 32] = self.state.identity_secret.as_slice().try_into()?;
        let signature = SigningKey::from_bytes(&key)
            .sign(&signed_message_bytes(&message)?)
            .to_bytes()
            .to_vec();
        let signed = SignedMessage {
            message: message.clone(),
            signature: signature.clone(),
        };
        let ciphertext = self.crypto.encrypt(id, &serde_json::to_vec(&signed)?)?;
        let envelope = Envelope {
            id: message.id.clone(),
            conversation: id.into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext,
        };
        let own = self.id().to_string();
        let recipients: Vec<_> = if group.server.is_some() {
            vec![group.id.clone()]
        } else {
            group
                .members
                .iter()
                .filter(|member| **member != own)
                .cloned()
                .collect()
        };
        for recipient in recipients {
            self.state.outbox.push(Outgoing {
                recipient,
                envelope: envelope.clone(),
                stored_at: vec![],
            });
        }
        let id = message.id.clone();
        self.state.message_signatures.insert(
            format!("{}/{}", message.conversation, message.id),
            signature,
        );
        self.state.history_audiences.insert(
            format!("{}/{}", message.conversation, message.id),
            self.crypto.members(&message.conversation)?,
        );
        self.state.messages.push(message);
        Ok(id)
    }

    fn receive(&mut self, envelope: Envelope) -> Result<()> {
        envelope.validate(now())?;
        if self
            .state
            .messages
            .iter()
            .any(|m| m.id == envelope.id && m.conversation == envelope.conversation)
        {
            return Ok(());
        }
        let group = self
            .state
            .conversations
            .get(&envelope.conversation)
            .context("unknown conversation; synchronize first")?
            .clone();
        ensure!(group.active, "not an active member");
        match self
            .crypto
            .process(&group.id, &envelope.ciphertext, &group.owner)?
        {
            Processed::Application { sender, plaintext } => {
                ensure!(
                    group.members.contains(&sender),
                    "message from removed member"
                );
                let signed: SignedMessage = serde_json::from_slice(&plaintext)?;
                verify_message(&signed)?;
                let message = signed.message;
                ensure!(
                    message.sender == sender
                        && message.id == envelope.id
                        && message.conversation == group.id
                        && message.created_at == envelope.created_at
                        && message.expires_at == envelope.expires_at,
                    "envelope does not match authenticated content"
                );
                self.state.message_signatures.insert(
                    format!("{}/{}", message.conversation, message.id),
                    signed.signature,
                );
                // The wire epoch is trusted only after MLS authentication and
                // signed-content validation above. Current membership must never
                // substitute for an unknown delayed message's older audience.
                let epoch = CryptoEngine::message_epoch(&envelope.ciphertext)?;
                if let Some(members) = self
                    .state
                    .history_epoch_members
                    .get(&group.id)
                    .and_then(|epochs| epochs.get(&epoch))
                {
                    self.state.history_audiences.insert(
                        format!("{}/{}", message.conversation, message.id),
                        members.clone(),
                    );
                }
                self.state.messages.push(message);
            }
            _ => bail!("control messages cannot use the chat mailbox"),
        }
        Ok(())
    }

    fn apply_control(&mut self, record: ControlRecord) -> Result<()> {
        let group = self
            .state
            .conversations
            .get(&record.conversation)
            .context("unknown conversation")?
            .clone();
        if record.epoch <= group.epoch {
            let known = self
                .state
                .controls
                .iter()
                .find(|r| r.conversation == record.conversation && r.epoch == record.epoch);
            ensure!(
                known.is_some_and(|r| r.commit == record.commit),
                "conflicting or unverifiable old commit"
            );
            return Ok(());
        }
        ensure!(
            record.epoch == group.epoch + 1,
            "missing control records; synchronize first"
        );
        ensure!(
            record.proposals.len() <= MAX_GROUP_MEMBERS,
            "too many update proposals"
        );
        for proposal in &record.proposals {
            if self.state.pending_updates.get(&group.id) != Some(proposal) {
                ensure!(
                    matches!(
                        self.crypto.process(&group.id, proposal, &group.owner)?,
                        Processed::Proposal { .. }
                    ),
                    "invalid commit dependency"
                );
            }
        }
        match self
            .crypto
            .process(&group.id, &record.commit, &group.owner)?
        {
            Processed::Commit {
                removed,
                updated_members,
                ..
            } => {
                let members = if removed {
                    Vec::new()
                } else {
                    self.crypto.members(&group.id)?
                };
                let entry = self.state.conversations.get_mut(&group.id).unwrap();
                entry.epoch = record.epoch;
                entry.active = !removed;
                entry.members = members;
                if self.state.pending_updates.contains_key(&group.id) {
                    if updated_members.iter().any(|member| member == self.id()) {
                        self.state.last_rekey.insert(group.id.clone(), now());
                    } else {
                        self.state.last_rekey.remove(&group.id);
                    }
                }
                let total: usize = self
                    .state
                    .controls
                    .iter()
                    .filter(|r| r.conversation == group.id)
                    .map(|r| r.commit.len() + r.proposals.iter().map(Vec::len).sum::<usize>())
                    .sum();
                if total
                    + record.commit.len()
                    + record.proposals.iter().map(Vec::len).sum::<usize>()
                    > 32 * 1024 * 1024
                {
                    self.state.controls.retain(|r| r.conversation != group.id);
                }
                self.state.controls.push(record);
                self.state.pending_updates.remove(&group.id);
                self.state.pending.retain(|p| !matches!(&p.request, Request::Update { conversation, .. } if conversation == &group.id));
                if removed {
                    self.state
                        .outbox
                        .retain(|o| o.envelope.conversation != group.id);
                }
            }
            _ => bail!("expected an owner commit"),
        }
        Ok(())
    }

    fn known_peer(&self, peer: &str) -> Result<String> {
        self.state
            .contacts
            .values()
            .find(|c| ticket_endpoint_id(&c.ticket).ok().as_deref() == Some(peer))
            .map(|c| c.id.clone())
            .context("unknown peer; exchange invitations first")
    }

    pub fn handle(&mut self, peer: &str, request: Request) -> Result<Response> {
        match request {
            Request::HostedControl { record } => {
                ensure!(
                    self.known_peer(peer)? == record.sender,
                    "hosted control peer mismatch"
                );
                self.accept_hosted_control(record)?;
                Ok(Response::Ok)
            }
            Request::Server(_) => {
                bail!("this endpoint is a client; configure an independent server")
            }
            Request::BlobPut {
                mailbox_id,
                write_token,
                read_token,
                chunk,
            } => {
                ensure!(self.state.relay_enabled, "cache participation disabled");
                self.store.store_relay_media(
                    &mailbox_id,
                    &write_token,
                    &read_token,
                    &chunk,
                    now(),
                )?;
                Ok(Response::Ok)
            }
            Request::BlobGet {
                media_id,
                index,
                read_token,
            } => {
                let chunk = self
                    .store
                    .get_local_media(&media_id, index, &read_token, now())?;
                let chunk = match chunk {
                    Some(chunk) => Some(chunk),
                    None => self
                        .store
                        .get_relay_media(&media_id, index, &read_token, now())?,
                };
                Ok(Response::Blob(chunk))
            }
            Request::Allocate => {
                ensure!(self.state.relay_enabled, "cache participation disabled");
                let (mailbox_id, write_token, read_token) = self.store.allocate(peer)?;
                Ok(Response::Mailbox {
                    mailbox_id,
                    write_token,
                    read_token,
                })
            }
            Request::Store {
                mailbox_id,
                write_token,
                envelope,
            } => {
                ensure!(self.state.relay_enabled, "cache participation disabled");
                self.store
                    .store(&mailbox_id, &write_token, &envelope, now())?;
                Ok(Response::Ok)
            }
            Request::Fetch {
                mailbox_id,
                read_token,
            } => Ok(Response::Envelopes(self.store.fetch(
                &mailbox_id,
                &read_token,
                peer,
                now(),
            )?)),
            Request::Delete {
                mailbox_id,
                read_token,
                ids,
            } => {
                self.store.delete(&mailbox_id, &read_token, peer, &ids)?;
                Ok(Response::Ok)
            }
            Request::Peers => {
                let mut peers = self.state.peers.clone();
                peers.push(self.ticket.clone());
                peers.truncate(32);
                Ok(Response::Peers(peers))
            }
            Request::Hello {
                invitation,
                authorization,
            } => {
                verify_invitation(&invitation)?;
                ensure!(
                    ticket_endpoint_id(&invitation.contact.ticket)? == peer,
                    "invitation endpoint mismatch"
                );
                let known = self.state.contacts.contains_key(&invitation.contact.id);
                ensure!(
                    known || authorization == self.state.invite_token,
                    "invitation authorization required"
                );
                self.atomic(|app| {
                    app.import_contact(invitation)?;
                    Ok(Response::Hello(app.invitation()?))
                })
            }
            Request::KeyPackage { request_id } => {
                let sender = self.known_peer(peer)?;
                self.issue_key_package(&sender, &request_id, now())
            }
            Request::Deliver { envelope } => {
                self.known_peer(peer)?;
                self.atomic(|app| {
                    app.receive(envelope)?;
                    Ok(Response::Ok)
                })
            }
            Request::Join {
                conversation,
                welcome,
                contacts,
            } => {
                let sender = self.known_peer(peer)?;
                ensure!(
                    sender == conversation.owner && conversation.members.len() <= MAX_GROUP_MEMBERS,
                    "invalid group owner or size"
                );
                ensure!(
                    contacts.len() <= MAX_GROUP_MEMBERS
                        && conversation.name.len() <= 128
                        && !conversation.name.chars().any(char::is_control),
                    "invalid group metadata"
                );
                let welcome_hash = hex::encode(Sha256::digest(&welcome));
                if self.state.accepted_welcomes.get(&conversation.id) == Some(&welcome_hash) {
                    return Ok(Response::Ok);
                }
                if let Some(existing) = self.state.conversations.get(&conversation.id) {
                    ensure!(existing.owner == sender, "group owner cannot change");
                    ensure!(
                        self.state.recovery_pending.contains(&conversation.id),
                        "already joined; refusing state rollback"
                    );
                } else {
                    ensure!(
                        self.state.conversations.len() < 128,
                        "conversation limit reached"
                    );
                }
                self.atomic(|app| {
                    let id = if app.state.conversations.contains_key(&conversation.id) {
                        app.crypto.rejoin_from(&welcome, &conversation.id, &sender)?
                    } else {
                        app.crypto.join_from(&welcome, &sender)?
                    };
                    ensure!(id == conversation.id, "welcome group mismatch");
                    let members = app.crypto.members(&id)?;
                    ensure!(members.contains(&sender) && members.contains(&app.id().to_string()), "invalid welcome membership");
                    for invite in contacts {
                        if invite.contact.id != app.id() && members.contains(&invite.contact.id) {
                            verify_invitation(&invite)?;
                            if app.state.contacts.get(&invite.contact.id).is_some_and(|old| old.version > invite.contact.version) { continue; }
                            app.import_contact(invite)?;
                        }
                    }
                    let recovering = app.state.recovery_pending.contains(&conversation.id);
                    let mut group = conversation;
                    group.members = members;
                    group.epoch = app.crypto.epoch(&id)?;
                    group.active = true;
                    app.state.recovery_pending.retain(|g| g != &id);
                    app.state.recovery_packages.remove(&id);
                    app.state.pending_updates.remove(&id);
                    app.state.pending.retain(|p| !matches!(&p.request, Request::Update { conversation, .. } | Request::Recover { conversation, .. } if conversation == &id));
                    app.state.last_rekey.insert(id.clone(), now());
                    app.state.accepted_welcomes.insert(id.clone(), welcome_hash);
                    app.state.conversations.insert(id.clone(), group);
                    if recovering {
                        app.state.pending.push(Pending { recipient: sender.clone(), request: Request::History { conversation: id, after: None } });
                    }
                    app.state.key_package = app.crypto.key_package()?;
                    app.state.contact_version += 1;
                    Ok(Response::Ok)
                })
            }
            Request::Control { record } => {
                self.known_peer(peer)?;
                self.atomic(|app| {
                    app.apply_control(record)?;
                    Ok(Response::Ok)
                })
            }
            Request::Sync {
                conversation,
                after_epoch,
            } => {
                let sender = self.known_peer(peer)?;
                let group = self
                    .state
                    .conversations
                    .get(&conversation)
                    .context("unknown conversation")?;
                ensure!(
                    group.active && group.members.contains(&sender),
                    "not a current member"
                );
                let contacts = self.directory(group);
                let mut budget = serde_json::to_vec(&contacts)?.len() + 256;
                let mut controls = Vec::new();
                for record in self
                    .state
                    .controls
                    .iter()
                    .filter(|r| r.conversation == conversation && r.epoch > after_epoch)
                    .take(32)
                {
                    let bytes = serde_json::to_vec(record)?.len();
                    if !controls.is_empty() && budget + bytes > 384 * 1024 {
                        break;
                    }
                    budget += bytes;
                    controls.push(record.clone());
                }
                Ok(Response::Sync {
                    controls,
                    contacts,
                    current_epoch: group.epoch,
                })
            }
            Request::Recover {
                conversation,
                key_package,
            } => {
                let sender = self.known_peer(peer)?;
                let group = self.owner_group(&conversation)?;
                ensure!(
                    group.members.contains(&sender),
                    "removed members cannot recover"
                );
                let recovery_id = format!("{conversation}/{sender}");
                let recovery_hash = hex::encode(Sha256::digest(&key_package));
                if self.state.accepted_recoveries.get(&recovery_id) == Some(&recovery_hash) {
                    return Ok(Response::Ok);
                }
                self.atomic(|app| {
                    app.state.pending.retain(|p| !(p.recipient == sender && matches!(&p.request, Request::Join { conversation: c, .. } if c.id == conversation)));
                    app.remove_member(&conversation, &sender)?;
                    app.state.contacts.get_mut(&sender).context("unknown member")?.key_package = key_package;
                    app.add_member(&conversation, &sender)?;
                    // The recovering device cannot process the missing old epochs.
                    // Its fresh Welcome must not sit behind an impossible Remove.
                    app.state.pending.retain(|p| !(p.recipient == sender && matches!(&p.request, Request::Control { record } if record.conversation == conversation)));
                    app.state.accepted_recoveries.insert(recovery_id, recovery_hash);
                    app.state.history_grants.push(format!("{conversation}/{sender}"));
                    Ok(Response::Ok)
                })
            }
            Request::Update {
                conversation,
                proposal,
            } => self.accept_update(peer, &conversation, proposal),
            Request::History {
                conversation,
                after,
            } => {
                let sender = self.known_peer(peer)?;
                let group = self.owner_group(&conversation)?;
                ensure!(
                    group.members.contains(&sender)
                        && self
                            .state
                            .history_grants
                            .contains(&format!("{conversation}/{sender}")),
                    "history requires an authorized recovery"
                );
                let mut available = self
                    .state
                    .messages
                    .iter()
                    .filter(|m| {
                        m.conversation == conversation
                            && m.expires_at > now()
                            && after.as_ref().is_none_or(|a| &m.id > a)
                            && self
                                .state
                                .history_audiences
                                .get(&format!("{}/{}", m.conversation, m.id))
                                .is_some_and(|members| members.contains(&sender))
                    })
                    .collect::<Vec<_>>();
                available.sort_by(|a, b| a.id.cmp(&b.id));
                let mut messages = vec![];
                let mut total = 0;
                let mut next = None;
                for message in available {
                    if let Some(signature) = self
                        .state
                        .message_signatures
                        .get(&format!("{}/{}", message.conversation, message.id))
                    {
                        let signed = SignedMessage {
                            message: message.clone(),
                            signature: signature.clone(),
                        };
                        let length = serde_json::to_vec(&signed)?.len();
                        if total + length > 384 * 1024 {
                            next = messages
                                .last()
                                .map(|m: &SignedMessage| m.message.id.clone());
                            break;
                        }
                        total += length;
                        messages.push(signed);
                    }
                }
                Ok(Response::History { messages, next })
            }
        }
    }

    pub fn prepare_recovery(&mut self, id: &str) -> Result<Request> {
        let group = self
            .state
            .conversations
            .get(id)
            .context("unknown conversation")?;
        ensure!(
            group.active && group.owner != self.id(),
            "only an existing non-owner member can recover"
        );
        let owner = group.owner.clone();
        if !self.state.recovery_packages.contains_key(id) {
            self.state
                .recovery_packages
                .insert(id.into(), self.crypto.key_package()?);
        }
        if !self.state.recovery_pending.iter().any(|g| g == id) {
            self.state.recovery_pending.push(id.into());
        }
        self.state.pending_updates.remove(id);
        self.state.pending.retain(|p| !(p.recipient == owner && matches!(&p.request,
            Request::Update { conversation, .. } | Request::History { conversation, .. } | Request::Recover { conversation, .. } if conversation == id)));
        Ok(Request::Recover {
            conversation: id.into(),
            key_package: self.state.recovery_packages[id].clone(),
        })
    }

    fn import_history(&mut self, conversation: &str, messages: Vec<SignedMessage>) -> Result<()> {
        let group = self
            .state
            .conversations
            .get(conversation)
            .context("unknown conversation")?
            .clone();
        ensure!(group.active, "not a current member");
        for signed in messages {
            if signed.message.expires_at <= now() {
                continue;
            }
            verify_message(&signed)?;
            ensure!(
                signed.message.conversation == conversation,
                "cross-conversation history"
            );
            if self
                .state
                .messages
                .iter()
                .any(|m| m.id == signed.message.id && m.conversation == conversation)
            {
                continue;
            }
            self.state.message_signatures.insert(
                format!("{}/{}", conversation, signed.message.id),
                signed.signature,
            );
            self.state.messages.push(signed.message);
        }
        self.state.messages.sort_by_key(|m| m.created_at);
        Ok(())
    }
}

pub async fn connect_contact(shared: &Shared, transport: &Transport, id: &str) -> Result<()> {
    let (contact, invitation) = {
        let app = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock failed"))?;
        (
            app.state
                .contacts
                .get(id)
                .context("unknown contact")?
                .clone(),
            app.invitation()?,
        )
    };
    let response = transport
        .request(
            &contact.ticket,
            Request::Hello {
                invitation,
                authorization: contact.invite_token,
            },
        )
        .await?;
    if let Response::Hello(invitation) = response {
        ensure!(invitation.contact.id == id, "unexpected remote identity");
        ensure!(
            ticket_endpoint_id(&invitation.contact.ticket)? == ticket_endpoint_id(&contact.ticket)?,
            "remote endpoint mismatch"
        );
        shared.lock().unwrap().atomic(|app| {
            app.import_contact(invitation)?;
            Ok(())
        })?;
    } else {
        bail!("contact handshake rejected: unexpected response");
    }
    Ok(())
}

pub async fn acquire_key_package(shared: &Shared, transport: &Transport, id: &str) -> Result<()> {
    connect_contact(shared, transport, id).await?;
    let ticket = shared
        .lock()
        .unwrap()
        .state
        .contacts
        .get(id)
        .context("unknown contact")?
        .ticket
        .clone();
    let request_id = uuid::Uuid::new_v4().to_string();
    match transport
        .request(&ticket, Request::KeyPackage { request_id })
        .await?
    {
        Response::Hello(invitation) => {
            ensure!(invitation.contact.id == id, "key package identity mismatch");
            shared.lock().unwrap().atomic(|app| {
                app.import_contact(invitation)?;
                Ok(())
            })
        }
        _ => bail!("cannot obtain a fresh key package"),
    }
}

#[path = "group_delivery.rs"]
mod group_delivery;
#[path = "key_packages.rs"]
mod key_packages;
pub use group_delivery::{HostedDeliveryState, group_delivery_tick};
#[path = "personal_mailbox.rs"]
mod personal_mailbox;
pub use personal_mailbox::attach_personal_mailbox;
#[path = "rekey.rs"]
mod rekey;
#[path = "ticker.rs"]
mod ticker;
pub use ticker::{network_tick, synchronize};

#[path = "media_app.rs"]
mod media_app;
pub use media_app::{media_tick, send_media};
