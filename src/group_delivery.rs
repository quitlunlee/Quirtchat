//! Hosted groups keep MLS keys on clients. The server stores only authenticated
//! membership metadata, encrypted MLS traffic, and encrypted attachment chunks.
use super::*;
use crate::{
    media::MediaDescriptor,
    server_protocol::{
        GroupConfig, HostedControl, SERVER_PAGE_RECORDS, SequencedEnvelope, ServerInvitation,
        ServerMember, ServerRequest, ServerResponse, SignedGroupConfig, SignedGroupControl,
        SignedHostedControl,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::OnceLock,
    time::{Duration, Instant},
};

const MAX_HOSTED_INBOX: usize = 4096;
const MAX_GROUP_SERVERS: usize = 32;

#[derive(Clone, Serialize, Deserialize)]
pub struct HostedMediaUpload {
    pub conversation: String,
    pub media_id: String,
    pub read_token: String,
    pub next_chunk: u32,
    pub chunks: u32,
    pub expires_at: i64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostedDeliveryState {
    pub configs: BTreeMap<String, SignedGroupConfig>,
    pub config_acks: BTreeMap<String, String>,
    pub provisioning_tokens: BTreeMap<String, String>,
    pub control_outbox: BTreeMap<String, SignedGroupControl>,
    pub control_epochs: BTreeMap<String, u64>,
    pub inbox_outbox: BTreeMap<String, SignedHostedControl>,
    pub inbox_acks: BTreeMap<String, Vec<String>>,
    pub received_inbox: BTreeMap<String, i64>,
    pub cursors: BTreeMap<String, u64>,
    pub media_uploads: Vec<HostedMediaUpload>,
}

impl HostedDeliveryState {
    pub fn expiring_item_count(&self) -> usize {
        self.control_outbox.len()
            + self.inbox_outbox.len()
            + self.received_inbox.len()
            + self.media_uploads.len()
    }

    pub fn purge_expired(&mut self, time: i64) {
        self.received_inbox.retain(|_, expiry| *expiry > time);
        self.inbox_outbox
            .retain(|_, record| record.expires_at > time);
        self.media_uploads.retain(|upload| upload.expires_at > time);
        let expired: Vec<_> = self
            .control_outbox
            .iter()
            .filter(|(_, control)| control.expires_at <= time)
            .map(|(key, control)| {
                (
                    key.clone(),
                    control.record.conversation.clone(),
                    control.record.epoch,
                )
            })
            .collect();
        for (key, group, epoch) in expired {
            self.control_outbox.remove(&key);
            let done = self.control_epochs.entry(group).or_default();
            *done = (*done).max(epoch);
        }
    }
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn control_key(group: &str, epoch: u64) -> String {
    format!("{group}/{epoch:020}")
}

impl App {
    pub fn create_hosted_group(
        &mut self,
        name: String,
        members: Vec<String>,
        server: ServerInvitation,
    ) -> Result<String> {
        ensure!(
            members.len() < MAX_GROUP_MEMBERS,
            "group member limit reached"
        );
        server.validate()?;
        let id = self.create_conversation(name, Vec::new())?;
        self.bind_group_server(&id, server, false)?;
        for member in members {
            self.add_member(&id, &member)?;
        }
        self.stage_hosted_group(&id)?;
        Ok(id)
    }

    /// Explicit migration. Moving an already hosted group to another deployment
    /// needs a separate migration protocol and is intentionally not implicit.
    pub fn host_existing_group(&mut self, id: &str, server: ServerInvitation) -> Result<()> {
        self.bind_group_server(id, server, true)?;
        self.stage_hosted_group(id)
    }

    fn bind_group_server(
        &mut self,
        id: &str,
        server: ServerInvitation,
        notify: bool,
    ) -> Result<()> {
        server.validate()?;
        let group = self.owner_group(id)?;
        let server_id = server.server_id()?;
        let mut migrating_media = Vec::new();
        if group.server.is_none() {
            let epoch = self.crypto.epoch(id)?;
            for outgoing in self.state.outbox.iter().filter(|outgoing| {
                outgoing.envelope.conversation == id
                    && outgoing.envelope.expires_at > now()
                    && group.members.contains(&outgoing.recipient)
            }) {
                let authorized_since = self.earliest_member_epoch(id, &outgoing.recipient, epoch);
                ensure!(
                    CryptoEngine::message_epoch(&outgoing.envelope.ciphertext)? >= authorized_since,
                    "deliver queued message {} before hosting; its recipient's older membership cannot be proven",
                    outgoing.envelope.id
                );
            }
            for message in self.state.messages.iter().filter(|message| {
                message.conversation == id
                    && message.expires_at > now()
                    && message.attachment.is_some()
            }) {
                ensure!(
                    self.media_bytes(message)?.is_some(),
                    "download attachment {} before moving this conversation to a group server",
                    message.id
                );
                let descriptor = message.attachment.as_ref().unwrap();
                if !migrating_media
                    .iter()
                    .any(|known: &MediaDescriptor| known.id == descriptor.id)
                {
                    migrating_media.push(descriptor.clone());
                }
            }
        }
        if let Some(old) = &group.server {
            ensure!(
                ticket_endpoint_id(&old.ticket)? == server_id,
                "moving an existing hosted group to another server is unsupported"
            );
        }
        self.register_group_server(&server.ticket)?;
        if let Some(existing) =
            self.state.group_servers.iter_mut().find(|ticket| {
                ticket_endpoint_id(ticket).ok().as_deref() == Some(server_id.as_str())
            })
        {
            *existing = server.ticket.clone();
        }
        self.state.conversations.get_mut(id).unwrap().server = Some(HostedGroupRoute {
            ticket: server.ticket.clone(),
        });
        self.state
            .hosted
            .provisioning_tokens
            .insert(id.into(), server.provisioning_token);
        for descriptor in &migrating_media {
            self.hosted_media_upload(id, descriptor)?;
        }
        // Existing signed descriptors retain their original bytes and TTL. Once
        // hosted, clients fetch their encrypted chunks from the group server.
        let replaced_media: Vec<_> = migrating_media
            .iter()
            .filter(|descriptor| {
                !self.state.messages.iter().any(|message| {
                    message.conversation != id
                        && message.expires_at > now()
                        && message
                            .attachment
                            .as_ref()
                            .is_some_and(|other| other.id == descriptor.id)
                        && self
                            .state
                            .conversations
                            .get(&message.conversation)
                            .is_some_and(|other| other.server.is_none())
                })
            })
            .map(|descriptor| descriptor.id.clone())
            .collect();
        self.state
            .media_uploads
            .retain(|upload| !replaced_media.contains(&upload.media_id));
        // Old unsent group copies become one server upload, preserving each
        // original envelope and its absolute expiry.
        let mut copies = Vec::new();
        let mut message_ids = std::collections::BTreeSet::new();
        self.state.outbox.retain(|outgoing| {
            if outgoing.envelope.conversation == id {
                if message_ids.insert(outgoing.envelope.id.clone()) {
                    copies.push(outgoing.envelope.clone());
                }
                false
            } else {
                true
            }
        });
        self.state
            .outbox
            .extend(copies.into_iter().map(|envelope| Outgoing {
                recipient: id.into(),
                envelope,
                stored_at: Vec::new(),
            }));
        for pending in &mut self.state.pending {
            if let Request::Join { conversation, .. } = &mut pending.request
                && conversation.id == id
            {
                conversation.server = Some(HostedGroupRoute {
                    ticket: server.ticket.clone(),
                });
            }
        }
        if notify {
            let own = self.id().to_owned();
            for recipient in group.members.iter().filter(|member| **member != own) {
                self.queue_hosted_control(
                    recipient,
                    HostedControl::Configure {
                        conversation: id.into(),
                        server_ticket: server.ticket.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn register_group_server(&mut self, ticket: &str) -> Result<()> {
        let endpoint = ticket_endpoint_id(ticket)?;
        if self
            .state
            .group_servers
            .iter()
            .any(|value| ticket_endpoint_id(value).ok().as_deref() == Some(&endpoint))
        {
            // A delayed signed Welcome must not overwrite a more recent server
            // address the user already trusted for this same endpoint.
            return Ok(());
        } else {
            ensure!(
                self.state.group_servers.len() < MAX_GROUP_SERVERS,
                "too many group servers"
            );
            self.state.group_servers.push(ticket.into());
        }
        Ok(())
    }

    fn earliest_member_epoch(&self, group: &str, member: &str, current: u64) -> u64 {
        let mut earliest = current;
        let mut expected = current;
        if let Some(epochs) = self.state.history_epoch_members.get(group) {
            for (epoch, members) in epochs.range(..=current).rev() {
                if *epoch != expected || !members.iter().any(|identity| identity == member) {
                    break;
                }
                earliest = *epoch;
                let Some(previous) = epoch.checked_sub(1) else {
                    break;
                };
                expected = previous;
            }
        }
        earliest
    }

    /// Called in the same transaction as an owner's MLS Commit. The signed
    /// copies keep their initial TTL across retries, saves and restarts.
    pub(super) fn stage_hosted_group(&mut self, id: &str) -> Result<()> {
        let group = self
            .state
            .conversations
            .get(id)
            .context("unknown group")?
            .clone();
        let Some(route) = &group.server else {
            return Ok(());
        };
        if !group.active || group.owner != self.id() {
            return Ok(());
        }
        let server_id = ticket_endpoint_id(&route.ticket)?;
        let own = self.id().to_owned();
        let secret: [u8; 32] = self.state.identity_secret.as_slice().try_into()?;
        let epoch = self.crypto.epoch(id)?;
        let mut members = Vec::new();
        for identity in self.crypto.members(id)? {
            let ticket = if identity == own {
                &self.ticket
            } else {
                &self
                    .state
                    .contacts
                    .get(&identity)
                    .context("missing group contact")?
                    .ticket
            };
            let joined_epoch = self
                .state
                .hosted
                .configs
                .get(id)
                .and_then(|old| {
                    old.config
                        .members
                        .iter()
                        .find(|member| member.identity == identity)
                })
                .map(|member| member.joined_epoch)
                .unwrap_or_else(|| self.earliest_member_epoch(id, &identity, epoch));
            members.push(ServerMember {
                identity,
                endpoint: ticket_endpoint_id(ticket)?,
                joined_epoch,
            });
        }
        let mut removal_epochs = self
            .state
            .hosted
            .configs
            .get(id)
            .map(|old| old.config.removal_epochs.clone())
            .unwrap_or_default();
        if let Some(old) = self.state.hosted.configs.get(id) {
            for removed in old.config.members.iter().filter(|old_member| {
                !members
                    .iter()
                    .any(|member| member.identity == old_member.identity)
            }) {
                removal_epochs.insert(removed.identity.clone(), epoch);
            }
        }
        removal_epochs
            .retain(|identity, _| !members.iter().any(|member| &member.identity == identity));
        let mut config = GroupConfig {
            server_id: server_id.clone(),
            group_id: id.into(),
            owner: own.clone(),
            revision: 1,
            epoch,
            members,
            removal_epochs,
        };
        if let Some(old) = self.state.hosted.configs.get(id) {
            config.revision = old.config.revision;
            if config != old.config {
                config.revision = config
                    .revision
                    .checked_add(1)
                    .context("group revision exhausted")?;
            }
        }
        if self
            .state
            .hosted
            .configs
            .get(id)
            .is_none_or(|old| old.config != config)
        {
            self.state
                .hosted
                .configs
                .insert(id.into(), SignedGroupConfig::sign(config, &secret)?);
        }
        let time = now();
        let completed = self
            .state
            .hosted
            .control_epochs
            .get(id)
            .copied()
            .unwrap_or(0);
        for record in self
            .state
            .controls
            .iter()
            .filter(|record| record.conversation == id && record.epoch > completed)
        {
            let key = control_key(id, record.epoch);
            if let std::collections::btree_map::Entry::Vacant(entry) =
                self.state.hosted.control_outbox.entry(key)
            {
                entry.insert(
                    SignedGroupControl {
                        server_id: server_id.clone(),
                        owner: own.clone(),
                        created_at: time,
                        expires_at: time + MESSAGE_TTL,
                        record: record.clone(),
                        signature: Vec::new(),
                    }
                    .sign(&secret)?,
                );
            }
        }
        Ok(())
    }

    fn queue_hosted_control(&mut self, recipient: &str, control: HostedControl) -> Result<()> {
        let id = control.group_id().to_owned();
        let route = self
            .state
            .conversations
            .get(&id)
            .and_then(|group| group.server.as_ref())
            .context("group has no server")?;
        let server_id = ticket_endpoint_id(&route.ticket)?;
        let sender = self.id().to_owned();
        let record_id = digest(&(&server_id, &sender, recipient, &control))?;
        if self.state.hosted.inbox_outbox.contains_key(&record_id) {
            return Ok(());
        }
        ensure!(
            self.state.hosted.inbox_outbox.len() < MAX_HOSTED_INBOX,
            "group control outbox is full"
        );
        let secret: [u8; 32] = self.state.identity_secret.as_slice().try_into()?;
        let time = now();
        let record = SignedHostedControl {
            server_id,
            id: record_id.clone(),
            group_id: id,
            sender,
            recipient: recipient.into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            control,
            signature: Vec::new(),
        }
        .sign(&secret)?;
        record.verify(time)?;
        self.state.hosted.inbox_outbox.insert(record_id, record);
        Ok(())
    }

    fn stage_hosted_pending(&mut self) -> Result<()> {
        let mut retained = Vec::new();
        for pending in std::mem::take(&mut self.state.pending) {
            let hosted = super::ticker::request_conversation(&pending.request)
                .and_then(|conversation| self.state.conversations.get(conversation))
                .is_some_and(|group| group.server.is_some());
            if !hosted {
                retained.push(pending);
                continue;
            }
            let control = match pending.request {
                Request::Join {
                    conversation,
                    welcome,
                    contacts,
                } => HostedControl::Join {
                    conversation,
                    welcome,
                    contacts,
                },
                Request::Update {
                    conversation,
                    proposal,
                } => HostedControl::Update {
                    conversation,
                    proposal,
                },
                Request::Recover {
                    conversation,
                    key_package,
                } => HostedControl::Recover {
                    conversation,
                    key_package,
                },
                // Current members use the shared log. A removed member also
                // receives its final Commit through its private control inbox.
                Request::Control { record } => {
                    if self.state.conversations[&record.conversation]
                        .members
                        .contains(&pending.recipient)
                    {
                        continue;
                    }
                    HostedControl::Control { record }
                }
                request => {
                    retained.push(Pending {
                        recipient: pending.recipient,
                        request,
                    });
                    continue;
                }
            };
            self.queue_hosted_control(&pending.recipient, control)?;
        }
        self.state.pending = retained;
        Ok(())
    }

    /// Both direct bootstrap delivery and a server inbox use this identical
    /// signature/recipient check before the existing MLS handlers run.
    pub fn accept_hosted_control(&mut self, record: SignedHostedControl) -> Result<()> {
        record.verify(now())?;
        ensure!(
            record.recipient == self.id(),
            "hosted control is for another member"
        );
        let receipt_key = digest(&(&record.server_id, &record.sender, &record.id))?;
        if self.state.hosted.received_inbox.contains_key(&receipt_key) {
            return Ok(());
        }
        ensure!(
            self.state.hosted.received_inbox.len() < MAX_HOSTED_INBOX,
            "hosted inbox receipt limit reached"
        );
        let sender_ticket = self
            .state
            .contacts
            .get(&record.sender)
            .context("unknown hosted control sender")?
            .ticket
            .clone();
        let sender_endpoint = ticket_endpoint_id(&sender_ticket)?;
        let request = match record.control.clone() {
            HostedControl::Configure {
                conversation,
                server_ticket,
            } => {
                ensure!(
                    ticket_endpoint_id(&server_ticket)? == record.server_id,
                    "group route server mismatch"
                );
                let group = self
                    .state
                    .conversations
                    .get(&conversation)
                    .context("unknown configured group")?;
                ensure!(
                    group.owner == record.sender,
                    "only the owner may configure the group server"
                );
                ensure!(
                    group.active && group.members.contains(&self.id().to_owned()),
                    "only an active group member may accept its server route"
                );
                if let Some(old) = &group.server {
                    ensure!(
                        ticket_endpoint_id(&old.ticket)? == record.server_id,
                        "unexpected group server migration"
                    );
                }
                self.atomic(|app| {
                    app.register_group_server(&server_ticket)?;
                    app.state
                        .conversations
                        .get_mut(&conversation)
                        .unwrap()
                        .server = Some(HostedGroupRoute {
                        ticket: server_ticket,
                    });
                    Ok(())
                })?;
                None
            }
            HostedControl::Join {
                conversation,
                welcome,
                contacts,
            } => {
                ensure!(
                    conversation.owner == record.sender,
                    "invalid hosted group owner"
                );
                let route = conversation
                    .server
                    .as_ref()
                    .context("hosted welcome lacks a server")?;
                ensure!(
                    ticket_endpoint_id(&route.ticket)? == record.server_id,
                    "welcome server mismatch"
                );
                Some(Request::Join {
                    conversation,
                    welcome,
                    contacts,
                })
            }
            control => {
                let group = self
                    .state
                    .conversations
                    .get(&record.group_id)
                    .context("unknown hosted group")?;
                let route = group.server.as_ref().context("group has no server")?;
                ensure!(
                    ticket_endpoint_id(&route.ticket)? == record.server_id,
                    "control server mismatch"
                );
                Some(match control {
                    HostedControl::Control { record } => Request::Control { record },
                    HostedControl::Update {
                        conversation,
                        proposal,
                    } => Request::Update {
                        conversation,
                        proposal,
                    },
                    HostedControl::Recover {
                        conversation,
                        key_package,
                    } => Request::Recover {
                        conversation,
                        key_package,
                    },
                    _ => unreachable!(),
                })
            }
        };
        if let Some(request) = request {
            ensure!(
                matches!(self.handle(&sender_endpoint, request)?, Response::Ok),
                "hosted control was not acknowledged"
            );
        }
        self.atomic(|app| {
            if let Some(route) = app
                .state
                .conversations
                .get(&record.group_id)
                .and_then(|group| group.server.clone())
            {
                app.register_group_server(&route.ticket)?;
            }
            app.state
                .hosted
                .received_inbox
                .insert(receipt_key, record.expires_at);
            Ok(())
        })
    }

    pub fn hosted_media_upload(
        &mut self,
        conversation: &str,
        descriptor: &MediaDescriptor,
    ) -> Result<()> {
        descriptor.validate(now())?;
        ensure!(
            self.state
                .conversations
                .get(conversation)
                .is_some_and(|group| group.server.is_some()),
            "group has no server"
        );
        if let Some(existing) =
            self.state.hosted.media_uploads.iter().find(|upload| {
                upload.conversation == conversation && upload.media_id == descriptor.id
            })
        {
            ensure!(
                existing.read_token == descriptor.read_token
                    && existing.chunks == descriptor.chunks
                    && existing.expires_at == descriptor.expires_at,
                "conflicting hosted media upload"
            );
            return Ok(());
        }
        ensure!(
            self.state.hosted.media_uploads.len() < 384,
            "hosted media upload queue is full"
        );
        self.state.hosted.media_uploads.push(HostedMediaUpload {
            conversation: conversation.into(),
            media_id: descriptor.id.clone(),
            read_token: descriptor.read_token.clone(),
            next_chunk: 0,
            chunks: descriptor.chunks,
            expires_at: descriptor.expires_at,
        });
        Ok(())
    }

    fn maintain_hosted(&mut self) -> Result<()> {
        self.state.hosted.purge_expired(now());
        let groups: Vec<_> = self
            .state
            .conversations
            .values()
            .filter(|group| group.server.is_some())
            .map(|group| group.id.clone())
            .collect();
        for group in groups {
            self.stage_hosted_group(&group)?;
        }
        self.prune_obsolete_hosted_inbox();
        self.stage_hosted_pending()?;
        self.prune_obsolete_hosted_inbox();
        Ok(())
    }

    fn prune_obsolete_hosted_inbox(&mut self) {
        let own = self.id().to_owned();
        let configs = &self.state.hosted.configs;
        self.state.hosted.inbox_outbox.retain(|_, record| {
            let Some(config) = configs.get(&record.group_id) else {
                return true;
            };
            if config.config.owner != own || record.sender != own {
                return true;
            }
            let member = config
                .config
                .members
                .iter()
                .find(|member| member.identity == record.recipient);
            match &record.control {
                HostedControl::Join { conversation, .. } => {
                    member.is_some_and(|member| conversation.epoch >= member.joined_epoch)
                }
                HostedControl::Configure { .. } => member.is_some(),
                HostedControl::Control { record: control } => {
                    member.is_none()
                        && config.config.removal_epochs.get(&record.recipient)
                            == Some(&control.epoch)
                }
                _ => true,
            }
        });
    }
}

#[derive(Clone)]
enum Kind {
    Configure {
        group: String,
        digest: String,
    },
    ControlPut {
        key: String,
        group: String,
        epoch: u64,
    },
    InboxPut {
        id: String,
    },
    InboxDirect,
    InboxFetch {
        server: String,
    },
    InboxAck {
        server: String,
        ids: Vec<String>,
    },
    Controls {
        group: String,
        after: u64,
    },
    GroupPut {
        group: String,
        message: String,
    },
    GroupFetch {
        group: String,
        after: u64,
    },
    MediaPut {
        group: String,
        media: String,
        index: u32,
    },
}

#[derive(Clone)]
struct Job {
    key: String,
    ticket: String,
    request: Request,
    kind: Kind,
}

fn server_job(ticket: &str, key: String, request: ServerRequest, kind: Kind) -> Job {
    Job {
        key,
        ticket: ticket.into(),
        request: Request::Server(request),
        kind,
    }
}

fn jobs(app: &App) -> Result<Vec<Job>> {
    let mut jobs = Vec::new();
    let own = app.id();
    for ticket in &app.state.group_servers {
        let server = ticket_endpoint_id(ticket)?;
        if let Some(ids) = app
            .state
            .hosted
            .inbox_acks
            .get(&server)
            .filter(|ids| !ids.is_empty())
        {
            let ids: Vec<_> = ids.iter().take(SERVER_PAGE_RECORDS).cloned().collect();
            jobs.push(server_job(
                ticket,
                format!("inbox-ack:{server}"),
                ServerRequest::InboxAck { ids: ids.clone() },
                Kind::InboxAck {
                    server: server.clone(),
                    ids,
                },
            ));
        }
        jobs.push(server_job(
            ticket,
            format!("inbox-fetch:{server}"),
            ServerRequest::InboxFetch,
            Kind::InboxFetch { server },
        ));
    }
    for group in app
        .state
        .conversations
        .values()
        .filter(|group| group.active)
    {
        let Some(route) = &group.server else {
            continue;
        };
        let owner = group.owner == own;
        if owner {
            let config = app
                .state
                .hosted
                .configs
                .get(&group.id)
                .context("missing hosted configuration")?;
            let hash = digest(config)?;
            if app.state.hosted.config_acks.get(&group.id) != Some(&hash) {
                jobs.push(server_job(
                    &route.ticket,
                    format!("configure:{}", group.id),
                    ServerRequest::ConfigureGroup {
                        provisioning_token: app
                            .state
                            .hosted
                            .provisioning_tokens
                            .get(&group.id)
                            .cloned()
                            .unwrap_or_default(),
                        config: config.clone(),
                    },
                    Kind::Configure {
                        group: group.id.clone(),
                        digest: hash,
                    },
                ));
                continue;
            }
            if let Some((key, control)) = app
                .state
                .hosted
                .control_outbox
                .iter()
                .find(|(_, control)| control.record.conversation == group.id)
            {
                jobs.push(server_job(
                    &route.ticket,
                    format!("control:{key}"),
                    ServerRequest::GroupControlPut {
                        control: control.clone(),
                    },
                    Kind::ControlPut {
                        key: key.clone(),
                        group: group.id.clone(),
                        epoch: control.record.epoch,
                    },
                ));
            }
        } else {
            jobs.push(server_job(
                &route.ticket,
                format!("controls:{}", group.id),
                ServerRequest::GroupControls {
                    group_id: group.id.clone(),
                    after_epoch: group.epoch,
                },
                Kind::Controls {
                    group: group.id.clone(),
                    after: group.epoch,
                },
            ));
        }
        for record in app
            .state
            .hosted
            .inbox_outbox
            .values()
            .filter(|record| record.group_id == group.id)
        {
            jobs.push(server_job(
                &route.ticket,
                format!("inbox-put:{}", record.id),
                ServerRequest::InboxPut {
                    record: record.clone(),
                },
                Kind::InboxPut {
                    id: record.id.clone(),
                },
            ));
            // This optional bootstrap lets an online contact discover the server.
            // Only a server ACK removes the persisted upload; a direct ACK does not.
            if matches!(
                record.control,
                HostedControl::Join { .. } | HostedControl::Configure { .. }
            ) && let Some(contact) = app.state.contacts.get(&record.recipient)
            {
                jobs.push(Job {
                    key: format!("inbox-direct:{}", record.id),
                    ticket: contact.ticket.clone(),
                    request: Request::HostedControl {
                        record: record.clone(),
                    },
                    kind: Kind::InboxDirect,
                });
            }
        }
        for upload in app
            .state
            .hosted
            .media_uploads
            .iter()
            .filter(|upload| upload.conversation == group.id)
            .take(1)
        {
            if let Some(chunk) = app.store.get_local_media(
                &upload.media_id,
                upload.next_chunk,
                &upload.read_token,
                now(),
            )? {
                jobs.push(server_job(
                    &route.ticket,
                    format!("media:{}:{}", group.id, upload.media_id),
                    ServerRequest::GroupBlobPut {
                        group_id: group.id.clone(),
                        read_token: upload.read_token.clone(),
                        chunk,
                    },
                    Kind::MediaPut {
                        group: group.id.clone(),
                        media: upload.media_id.clone(),
                        index: upload.next_chunk,
                    },
                ));
            }
        }
        let controls_ready = !owner
            || !app
                .state
                .hosted
                .control_outbox
                .values()
                .any(|control| control.record.conversation == group.id);
        if controls_ready
            && let Some(outgoing) = app
                .state
                .outbox
                .iter()
                .find(|outgoing| {
                    outgoing.envelope.conversation == group.id
                        && outgoing.envelope.expires_at > now()
                })
                .filter(|outgoing| {
                    !app.state
                        .messages
                        .iter()
                        .find(|message| {
                            message.id == outgoing.envelope.id && message.conversation == group.id
                        })
                        .and_then(|message| message.attachment.as_ref())
                        .is_some_and(|descriptor| {
                            app.state.hosted.media_uploads.iter().any(|upload| {
                                upload.conversation == group.id && upload.media_id == descriptor.id
                            })
                        })
                })
        {
            jobs.push(server_job(
                &route.ticket,
                format!("group-put:{}:{}", group.id, outgoing.envelope.id),
                ServerRequest::GroupPut {
                    group_id: group.id.clone(),
                    envelope: outgoing.envelope.clone(),
                },
                Kind::GroupPut {
                    group: group.id.clone(),
                    message: outgoing.envelope.id.clone(),
                },
            ));
        }
        let after = app
            .state
            .hosted
            .cursors
            .get(&group.id)
            .copied()
            .unwrap_or(0);
        jobs.push(server_job(
            &route.ticket,
            format!("group-fetch:{}", group.id),
            ServerRequest::GroupFetch {
                group_id: group.id.clone(),
                after,
            },
            Kind::GroupFetch {
                group: group.id.clone(),
                after,
            },
        ));
    }
    for job in &mut jobs {
        job.ticket = super::ticker::current_node_ticket(&app.state, &job.ticket).to_owned();
    }
    Ok(jobs)
}

fn receive_page(
    app: &mut App,
    group: &str,
    after: u64,
    envelopes: Vec<SequencedEnvelope>,
    next: u64,
) -> Result<()> {
    ensure!(
        envelopes.len() <= SERVER_PAGE_RECORDS,
        "group page is too large"
    );
    let mut previous = after;
    for item in &envelopes {
        ensure!(
            item.sequence > previous && item.envelope.conversation == group,
            "invalid group page order or conversation"
        );
        previous = item.sequence;
    }
    ensure!(
        next == previous,
        "group page skipped an unreturned sequence"
    );
    for item in envelopes {
        if app.state.hosted.cursors.get(group).copied().unwrap_or(0) >= item.sequence {
            continue;
        }
        let accepted = app.atomic(|app| {
            if item.envelope.expires_at > now() {
                app.receive(item.envelope.clone())?;
            }
            app.state.hosted.cursors.insert(group.into(), item.sequence);
            Ok(())
        });
        if accepted.is_err() {
            let retained = app.atomic(|app| {
                let retained =
                    super::ticker::defer_envelope(&mut app.state, item.envelope.clone())?;
                if retained {
                    app.state.hosted.cursors.insert(group.into(), item.sequence);
                }
                Ok(retained)
            })?;
            if !retained {
                break;
            }
        }
    }
    Ok(())
}

fn apply_response(app: &mut App, job: &Job, response: Response) -> Result<()> {
    if let Response::Error(message) = response {
        bail!("{message}");
    }
    match (&job.kind, response) {
        (Kind::Configure { group, digest }, Response::Ok) => app.atomic(|app| {
            app.state
                .hosted
                .config_acks
                .insert(group.clone(), digest.clone());
            Ok(())
        }),
        (Kind::ControlPut { key, group, epoch }, Response::Ok) => app.atomic(|app| {
            app.state.hosted.control_outbox.remove(key);
            let completed = app
                .state
                .hosted
                .control_epochs
                .entry(group.clone())
                .or_default();
            *completed = (*completed).max(*epoch);
            Ok(())
        }),
        (Kind::InboxPut { id }, Response::Ok) => app.atomic(|app| {
            app.state.hosted.inbox_outbox.remove(id);
            Ok(())
        }),
        (Kind::InboxDirect, Response::Ok) => Ok(()),
        (Kind::InboxAck { server, ids }, Response::Ok) => app.atomic(|app| {
            if let Some(pending) = app.state.hosted.inbox_acks.get_mut(server) {
                pending.retain(|id| !ids.contains(id));
            }
            Ok(())
        }),
        (Kind::InboxFetch { server }, Response::Server(ServerResponse::Inbox { records })) => {
            ensure!(
                records.len() <= SERVER_PAGE_RECORDS,
                "hosted inbox page is too large"
            );
            let mut last_error = None;
            for record in records {
                if &record.server_id != server {
                    last_error = Some(anyhow::anyhow!("inbox record belongs to another server"));
                    continue;
                }
                let id = record.id.clone();
                // Application/crypto state is durable before an inbox ACK is staged.
                // A delayed removal may need the server's earlier Commit chain;
                // retain it remotely while allowing unrelated inbox items through.
                if let Err(error) = app.accept_hosted_control(record) {
                    last_error = Some(error);
                    continue;
                }
                app.atomic(|app| {
                    let acks = app
                        .state
                        .hosted
                        .inbox_acks
                        .entry(server.clone())
                        .or_default();
                    if !acks.contains(&id) {
                        ensure!(
                            acks.len() < MAX_HOSTED_INBOX,
                            "inbox acknowledgement queue full"
                        );
                        acks.push(id);
                    }
                    Ok(())
                })?;
            }
            last_error.map_or(Ok(()), Err)
        }
        (
            Kind::Controls { group, after },
            Response::Server(ServerResponse::Controls {
                records,
                current_epoch,
            }),
        ) => {
            ensure!(
                records.len() <= SERVER_PAGE_RECORDS && current_epoch >= *after,
                "invalid hosted control page"
            );
            let known = app
                .state
                .conversations
                .get(group)
                .context("unknown group")?
                .clone();
            let server = ticket_endpoint_id(&job.ticket)?;
            if records.is_empty() && current_epoch > app.state.conversations[group].epoch {
                queue_recovery(app, group, &known.owner)?;
            }
            let mut previous = *after;
            for signed in records {
                signed.verify(now())?;
                ensure!(
                    signed.server_id == server
                        && signed.owner == known.owner
                        && signed.record.conversation == *group,
                    "hosted control author or group mismatch"
                );
                ensure!(
                    signed.record.epoch > previous && signed.record.epoch <= current_epoch,
                    "invalid hosted control order"
                );
                previous = signed.record.epoch;
                let epoch = app.state.conversations[group].epoch;
                if signed.record.epoch > epoch + 1 {
                    queue_recovery(app, group, &known.owner)?;
                    break;
                }
                if signed.record.epoch > epoch {
                    app.atomic(|app| app.apply_control(signed.record.clone()))?;
                }
            }
            super::ticker::retry_deferred(app)
        }
        (Kind::GroupPut { group, message }, Response::Ok) => app.atomic(|app| {
            app.state.outbox.retain(|outgoing| {
                outgoing.envelope.conversation != *group || outgoing.envelope.id != *message
            });
            Ok(())
        }),
        (
            Kind::GroupFetch { group, after },
            Response::Server(ServerResponse::GroupPage { envelopes, next }),
        ) => receive_page(app, group, *after, envelopes, next),
        (
            Kind::MediaPut {
                group,
                media,
                index,
            },
            Response::Ok,
        ) => app.atomic(|app| {
            if let Some(upload) = app
                .state
                .hosted
                .media_uploads
                .iter_mut()
                .find(|upload| upload.conversation == *group && upload.media_id == *media)
                && upload.next_chunk == *index
            {
                upload.next_chunk += 1;
            }
            app.state
                .hosted
                .media_uploads
                .retain(|upload| upload.next_chunk < upload.chunks);
            Ok(())
        }),
        _ => bail!("unexpected group server response"),
    }
}

fn queue_recovery(app: &mut App, group: &str, owner: &str) -> Result<()> {
    if !app.state.recovery_pending.contains(&group.to_owned()) {
        app.atomic(|app| {
            let request = app.prepare_recovery(group)?;
            app.state.pending.push(Pending {
                recipient: owner.into(),
                request,
            });
            Ok(())
        })?;
    }
    Ok(())
}

#[derive(Default)]
struct Schedule {
    cursor: usize,
    retry: BTreeMap<String, (u32, Instant)>,
}
#[derive(Default)]
struct Runtime {
    gate: tokio::sync::Mutex<()>,
    schedule: Mutex<Schedule>,
}
fn runtime(id: &str) -> Arc<Runtime> {
    static RUNTIMES: OnceLock<Mutex<BTreeMap<String, Arc<Runtime>>>> = OnceLock::new();
    RUNTIMES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(id.into())
        .or_default()
        .clone()
}

async fn request(transport: &Transport, job: Option<Job>) -> Option<(Job, Result<Response>)> {
    let job = job?;
    let response = transport.request(&job.ticket, job.request.clone()).await;
    Some((job, response))
}

pub async fn group_delivery_tick(shared: &Shared, transport: &Transport) -> Result<()> {
    let id = {
        let app = shared.lock().unwrap();
        if app.state.group_servers.is_empty()
            && !app
                .state
                .conversations
                .values()
                .any(|group| group.server.is_some())
        {
            return Ok(());
        }
        app.id().to_owned()
    };
    let runtime = runtime(&id);
    let Ok(_guard) = runtime.gate.try_lock() else {
        return Ok(());
    };
    let candidates = {
        let mut app = shared.lock().unwrap();
        app.atomic(|app| app.maintain_hosted())?;
        jobs(&app)?
    };
    let selected = {
        let mut schedule = runtime.schedule.lock().unwrap();
        let time = Instant::now();
        schedule
            .retry
            .retain(|_, (_, due)| time.saturating_duration_since(*due) < Duration::from_secs(3600));
        let mut selected = Vec::new();
        if !candidates.is_empty() {
            for offset in 0..candidates.len() {
                let index = (schedule.cursor + offset) % candidates.len();
                let job = &candidates[index];
                if schedule
                    .retry
                    .get(&job.key)
                    .is_none_or(|(_, due)| *due <= time)
                {
                    selected.push(job.clone());
                    if selected.len() == 4 {
                        schedule.cursor = (index + 1) % candidates.len();
                        break;
                    }
                }
            }
        }
        selected
    };
    let mut selected = selected.into_iter();
    let (a, b, c, d) = tokio::join!(
        request(transport, selected.next()),
        request(transport, selected.next()),
        request(transport, selected.next()),
        request(transport, selected.next())
    );
    for (job, result) in [a, b, c, d].into_iter().flatten() {
        let result =
            result.and_then(|response| apply_response(&mut shared.lock().unwrap(), &job, response));
        let mut schedule = runtime.schedule.lock().unwrap();
        if let Err(error) = result {
            let failures = schedule
                .retry
                .get(&job.key)
                .map(|(failures, _)| *failures)
                .unwrap_or(0)
                .saturating_add(1);
            let delay = Duration::from_secs(1u64 << failures.min(6));
            schedule
                .retry
                .insert(job.key, (failures, Instant::now() + delay));
            shared.lock().unwrap().status = format!("Group server pending: {error}");
        } else {
            schedule.retry.remove(&job.key);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::Store, transport::encode_ticket};

    fn profile(directory: &std::path::Path, name: &str) -> Result<App> {
        let store = Store::create(
            &directory.join(format!("{name}.db")),
            "hosted unit test passphrase",
        )?;
        let mut app = App::initialize(store, name.into())?;
        let seed = app.state.transport_secret.as_slice().try_into()?;
        app.ticket = encode_ticket(
            &iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(seed).public())
                .with_ip_addr("127.0.0.1:9".parse()?),
        )?;
        app.save()?;
        Ok(app)
    }

    fn pair(owner: &mut App, member: &mut App) -> Result<String> {
        owner.atomic(|app| app.import_contact(member.invitation()?))?;
        member.atomic(|app| app.import_contact(owner.invitation()?))?;
        let group = owner.atomic(|app| app.create_direct("pair".into(), member.id().into()))?;
        let welcome = owner
            .state
            .pending
            .iter()
            .find_map(|pending| match &pending.request {
                Request::Join { conversation, .. } if conversation.id == group => {
                    Some(pending.request.clone())
                }
                _ => None,
            })
            .context("missing welcome")?;
        member.handle(&ticket_endpoint_id(&owner.ticket)?, welcome)?;
        Ok(group)
    }

    fn configure(
        owner: &App,
        member: &App,
        group: &str,
        server: &str,
        id: &str,
    ) -> Result<SignedHostedControl> {
        let time = now();
        SignedHostedControl {
            server_id: ticket_endpoint_id(server)?,
            id: id.into(),
            group_id: group.into(),
            sender: owner.id().into(),
            recipient: member.id().into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            control: HostedControl::Configure {
                conversation: group.into(),
                server_ticket: server.into(),
            },
            signature: Vec::new(),
        }
        .sign(owner.state.identity_secret.as_slice().try_into()?)
    }

    #[test]
    fn inbox_ids_are_scoped_to_the_signed_sender_and_server() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let mut carol = profile(directory.path(), "Carol")?;
        let server = profile(directory.path(), "Server")?;
        let first = pair(&mut alice, &mut bob)?;
        let second = pair(&mut carol, &mut bob)?;
        let record = configure(&alice, &bob, &first, &server.ticket, "same-id")?;
        bob.accept_hosted_control(record.clone())?;
        bob.accept_hosted_control(record)?;
        bob.accept_hosted_control(configure(&carol, &bob, &second, &server.ticket, "same-id")?)?;
        assert!(bob.state.conversations[&first].server.is_some());
        assert!(bob.state.conversations[&second].server.is_some());
        assert_eq!(bob.state.hosted.received_inbox.len(), 2);
        Ok(())
    }

    #[test]
    fn removed_member_cannot_accept_a_fresh_route_configuration() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let server = profile(directory.path(), "Server")?;
        let group = pair(&mut alice, &mut bob)?;
        let bob_id = bob.id().to_owned();
        bob.atomic(|app| {
            let group = app.state.conversations.get_mut(&group).unwrap();
            group.active = false;
            group.members.retain(|member| member != &bob_id);
            Ok(())
        })?;
        assert!(
            bob.accept_hosted_control(configure(&alice, &bob, &group, &server.ticket, "new-id")?)
                .is_err()
        );
        assert!(bob.state.conversations[&group].server.is_none());
        Ok(())
    }

    #[test]
    fn an_empty_expired_control_log_requests_recovery_once() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let server = profile(directory.path(), "Server")?;
        let group = pair(&mut alice, &mut bob)?;
        bob.accept_hosted_control(configure(&alice, &bob, &group, &server.ticket, "route")?)?;
        let epoch = bob.state.conversations[&group].epoch;
        let job = server_job(
            &server.ticket,
            "controls".into(),
            ServerRequest::GroupControls {
                group_id: group.clone(),
                after_epoch: epoch,
            },
            Kind::Controls {
                group: group.clone(),
                after: epoch,
            },
        );
        for _ in 0..2 {
            apply_response(
                &mut bob,
                &job,
                Response::Server(ServerResponse::Controls {
                    records: Vec::new(),
                    current_epoch: epoch + 3,
                }),
            )?;
        }
        assert!(bob.state.recovery_pending.contains(&group));
        assert_eq!(
            bob.state
                .pending
                .iter()
                .filter(|pending| matches!(&pending.request,
            Request::Recover { conversation, .. } if conversation == &group))
                .count(),
            1
        );
        let saved = bob.store.load_state()?.unwrap();
        assert!(saved.recovery_pending.contains(&group));
        Ok(())
    }

    #[test]
    fn expired_signed_controls_are_not_resigned_with_a_new_deadline() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let server = profile(directory.path(), "Server")?;
        let group = pair(&mut alice, &mut bob)?;
        alice.atomic(|app| {
            app.host_existing_group(
                &group,
                ServerInvitation {
                    ticket: server.ticket.clone(),
                    provisioning_token: "ab".repeat(32),
                },
            )
        })?;
        let deadline = alice
            .state
            .hosted
            .control_outbox
            .values()
            .map(|control| control.expires_at)
            .max()
            .context("missing signed Commit")?;
        let last_epoch = alice.state.conversations[&group].epoch;
        alice.atomic(|app| {
            app.state.hosted.purge_expired(deadline);
            app.stage_hosted_group(&group)
        })?;
        assert!(alice.state.hosted.control_outbox.is_empty());
        assert_eq!(alice.state.hosted.control_epochs[&group], last_epoch);
        alice.atomic(|app| app.stage_hosted_group(&group))?;
        assert!(alice.state.hosted.control_outbox.is_empty());
        Ok(())
    }

    #[test]
    fn group_cursor_advances_only_after_ciphertext_is_durable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let group = pair(&mut alice, &mut bob)?;
        let time = now();
        let envelope = Envelope {
            id: "unavailable-epoch".into(),
            conversation: group.clone(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![1],
        };
        bob.atomic(|app| {
            app.state.deferred = (0..256)
                .map(|index| Envelope {
                    id: format!("existing-{index}"),
                    ..envelope.clone()
                })
                .collect();
            Ok(())
        })?;
        let page = || {
            vec![SequencedEnvelope {
                sequence: 1,
                envelope: envelope.clone(),
            }]
        };
        receive_page(&mut bob, &group, 0, page(), 1)?;
        assert_eq!(bob.state.hosted.cursors.get(&group), None);
        assert_eq!(bob.state.deferred.len(), 256);
        assert!(bob.state.deferred.iter().all(|item| item.id != envelope.id));
        bob.atomic(|app| {
            app.state.deferred.pop();
            Ok(())
        })?;
        receive_page(&mut bob, &group, 0, page(), 1)?;
        let saved = bob.store.load_state()?.unwrap();
        assert_eq!(saved.hosted.cursors[&group], 1);
        assert_eq!(saved.deferred.len(), 256);
        let retained = saved
            .deferred
            .iter()
            .find(|item| item.id == envelope.id)
            .unwrap();
        assert_eq!(retained.ciphertext, envelope.ciphertext);
        assert_eq!(retained.expires_at, envelope.expires_at);
        Ok(())
    }

    #[test]
    fn a_delayed_bootstrap_preserves_the_users_newer_server_address() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let server = profile(directory.path(), "Server")?;
        let group = pair(&mut alice, &mut bob)?;
        let seed = server.state.transport_secret.as_slice().try_into()?;
        let fresh = encode_ticket(
            &iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(seed).public())
                .with_ip_addr("127.0.0.1:10".parse()?),
        )?;
        bob.atomic(|app| {
            app.state.group_servers.push(fresh.clone());
            Ok(())
        })?;
        bob.accept_hosted_control(configure(
            &alice,
            &bob,
            &group,
            &server.ticket,
            "old-bootstrap",
        )?)?;
        assert_eq!(bob.state.group_servers, vec![fresh.clone()]);
        assert!(jobs(&bob)?.iter().all(|job| job.ticket == fresh));
        Ok(())
    }

    #[test]
    fn hosting_migrates_complete_media_and_rejects_missing_cached_chunks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let server = profile(directory.path(), "Server")?;
        let group = pair(&mut alice, &mut bob)?;
        let file = directory.path().join("migration.png");
        std::fs::write(
            &file,
            hex::decode(
                "89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082",
            )?,
        )?;
        let prepared =
            crate::media::prepare_file(&file, std::slice::from_ref(&alice.ticket), now())?;
        alice.send_attachment(&group, prepared.clone(), "attachment".into())?;
        let invitation = ServerInvitation {
            ticket: server.ticket.clone(),
            provisioning_token: "ab".repeat(32),
        };
        alice.store.delete_local_media(&prepared.descriptor.id)?;
        let failure = alice.atomic(|app| app.host_existing_group(&group, invitation.clone()));
        assert!(
            failure
                .unwrap_err()
                .to_string()
                .contains("download attachment")
        );
        assert!(alice.state.conversations[&group].server.is_none());
        alice
            .store
            .store_local_media(&prepared.chunks, &prepared.descriptor.read_token, now())?;
        alice.atomic(|app| app.host_existing_group(&group, invitation))?;
        assert_eq!(alice.state.hosted.media_uploads.len(), 1);
        let upload = &alice.state.hosted.media_uploads[0];
        assert_eq!(upload.media_id, prepared.descriptor.id);
        assert_eq!(upload.expires_at, prepared.descriptor.expires_at);
        alice.hosted_media_upload(&group, &prepared.descriptor)?;
        assert_eq!(alice.state.hosted.media_uploads.len(), 1);
        Ok(())
    }

    #[test]
    fn migration_preserves_proven_old_epoch_deliveries_and_rejects_unknown_legacy_audiences()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let mut bob = profile(directory.path(), "Bob")?;
        let mut server = crate::server::Server::initialize(Store::create(
            &directory.path().join("host.db"),
            "hosted unit test passphrase",
        )?)?;
        let ticket = encode_ticket(
            &iroh::EndpointAddr::new(
                iroh::SecretKey::from_bytes(&server.transport_secret()?).public(),
            )
            .with_ip_addr("127.0.0.1:10".parse()?),
        )?;
        let invitation = server.invitation(&ticket)?;
        let group = pair(&mut alice, &mut bob)?;
        let join_epoch = alice.state.conversations[&group].epoch;
        let message =
            alice.atomic(|app| app.send(&group, "queued before migration rekey".into()))?;
        let envelope = alice.state.outbox[0].envelope.clone();
        alice.maybe_rekey(now() + 25 * 60 * 60)?;
        let proven = alice.state.history_epoch_members.clone();
        alice.atomic(|app| {
            app.state.history_epoch_members.clear();
            Ok(())
        })?;
        assert!(
            alice
                .atomic(|app| app.host_existing_group(&group, invitation.clone()))
                .is_err()
        );
        assert!(alice.state.conversations[&group].server.is_none());
        alice.atomic(|app| {
            app.state.history_epoch_members = proven;
            Ok(())
        })?;
        alice.atomic(|app| app.host_existing_group(&group, invitation.clone()))?;
        let config = alice.state.hosted.configs[&group].clone();
        assert_eq!(
            config
                .config
                .members
                .iter()
                .find(|member| member.identity == bob.id())
                .unwrap()
                .joined_epoch,
            join_epoch
        );
        server.handle(
            &ticket_endpoint_id(&alice.ticket)?,
            Request::Server(ServerRequest::ConfigureGroup {
                provisioning_token: invitation.provisioning_token,
                config,
            }),
        )?;
        server.handle(
            &ticket_endpoint_id(&alice.ticket)?,
            Request::Server(ServerRequest::GroupPut {
                group_id: group.clone(),
                envelope: envelope.clone(),
            }),
        )?;
        let Response::Server(ServerResponse::GroupPage { envelopes, .. }) = server.handle(
            &ticket_endpoint_id(&bob.ticket)?,
            Request::Server(ServerRequest::GroupFetch {
                group_id: group,
                after: 0,
            }),
        )?
        else {
            bail!("missing migrated group page");
        };
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].envelope.id, message);
        assert_eq!(envelopes[0].envelope.ciphertext, envelope.ciphertext);
        assert_eq!(envelopes[0].envelope.expires_at, envelope.expires_at);
        Ok(())
    }

    #[test]
    fn stale_welcomes_do_not_hide_later_inbox_candidates() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut alice = profile(directory.path(), "Alice")?;
        let bob = profile(directory.path(), "Bob")?;
        let carol = profile(directory.path(), "Carol")?;
        let dave = profile(directory.path(), "Dave")?;
        let server = profile(directory.path(), "Server")?;
        for member in [&bob, &carol, &dave] {
            alice.atomic(|app| app.import_contact(member.invitation()?))?;
        }
        let group = alice.atomic(|app| {
            app.create_hosted_group(
                "inbox fairness".into(),
                vec![bob.id().into(), carol.id().into(), dave.id().into()],
                ServerInvitation {
                    ticket: server.ticket.clone(),
                    provisioning_token: "ab".repeat(32),
                },
            )
        })?;
        alice.atomic(|app| {
            app.maintain_hosted()?;
            app.state
                .hosted
                .config_acks
                .insert(group.clone(), digest(&app.state.hosted.configs[&group])?);
            Ok(())
        })?;
        assert_eq!(
            jobs(&alice)?
                .iter()
                .filter(|job| matches!(job.kind, Kind::InboxPut { .. }))
                .count(),
            3
        );
        alice.atomic(|app| app.remove_member(&group, bob.id()))?;
        alice.atomic(|app| app.remove_member(&group, carol.id()))?;
        alice.atomic(|app| app.maintain_hosted())?;
        let outgoing = &alice.state.hosted.inbox_outbox;
        assert_eq!(
            outgoing
                .values()
                .filter(|record| matches!(record.control, HostedControl::Join { .. }))
                .count(),
            1
        );
        assert!(outgoing.values().any(|record| record.recipient == dave.id()
            && matches!(record.control, HostedControl::Join { .. })));
        assert_eq!(
            outgoing
                .values()
                .filter(|record| matches!(record.control, HostedControl::Control { .. }))
                .count(),
            2
        );
        Ok(())
    }
}
