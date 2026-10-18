//! Fair, bounded background work. Each job performs exactly one network request.

use super::*;
use std::{
    collections::BTreeMap,
    sync::OnceLock,
    time::{Duration, Instant},
};

#[path = "routing.rs"]
mod routing;
use routing::RouteQuality;

const BATCH: usize = 4;
const MAX_LOCAL_MAILBOXES: usize = 12;
const MAX_DEFERRED_MESSAGES: usize = 256;
const MAX_DEFERRED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct Retry {
    failures: u32,
    first_failure: Instant,
    due: Instant,
}

#[derive(Default)]
struct Schedule {
    cursors: [usize; 6],
    retries: BTreeMap<String, Retry>,
    acknowledgements: BTreeMap<String, Vec<String>>,
    announced: BTreeMap<String, u64>,
    routes: RouteQuality,
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
        .entry(id.to_owned())
        .or_default()
        .clone()
}

impl Schedule {
    fn ready(&self, key: &str) -> bool {
        self.retries
            .get(key)
            .is_none_or(|retry| retry.due <= Instant::now())
    }

    fn failed(&mut self, key: String) {
        let now = Instant::now();
        let retry = self.retries.entry(key).or_insert(Retry {
            failures: 0,
            first_failure: now,
            due: now,
        });
        retry.failures = retry.failures.saturating_add(1);
        retry.due = now + Duration::from_secs((10_u64 << retry.failures.min(5)).min(300));
    }

    fn succeeded(&mut self, key: String, cooldown: u64) {
        if cooldown == 0 {
            self.retries.remove(&key);
        } else {
            let now = Instant::now();
            self.retries.insert(
                key,
                Retry {
                    failures: 0,
                    first_failure: now,
                    due: now + Duration::from_secs(cooldown),
                },
            );
        }
    }

    fn replaceable(&self, mailbox: &LocalMailbox) -> bool {
        let Ok(key) = mailbox_key(&mailbox.public) else {
            return false;
        };
        self.retries
            .get(&format!("fetch:{key}"))
            .is_some_and(|retry| {
                retry.failures >= 3 && retry.first_failure.elapsed() >= Duration::from_secs(60)
            })
    }

    fn order(&mut self, category: usize, len: usize) -> Vec<usize> {
        if len == 0 {
            return vec![];
        }
        let first = self.cursors[category] % len;
        self.cursors[category] = (first + BATCH) % len;
        (0..len).map(|offset| (first + offset) % len).collect()
    }
}

enum Kind {
    Fetch(LocalMailbox),
    Delete {
        mailbox: String,
        ids: Vec<String>,
    },
    Pending {
        recipient: String,
        digest: Vec<u8>,
    },
    Deliver {
        recipient: String,
        message: String,
    },
    Store {
        recipient: String,
        message: String,
        mailbox: String,
    },
    Sync {
        group: String,
        peer: String,
    },
    Hello {
        contact: String,
        version: u64,
    },
    Peers,
    Allocate {
        replace: Option<String>,
    },
}

struct Job {
    ticket: String,
    node: String,
    key: String,
    request: Request,
    kind: Kind,
}

fn mailbox_key(mailbox: &Mailbox) -> Result<String> {
    // IDs are selected by independent, potentially untrusted storage nodes.
    Ok(format!(
        "{}/{}",
        ticket_endpoint_id(&mailbox.node_ticket)?,
        mailbox.mailbox_id
    ))
}

pub(super) fn current_node_ticket<'a>(state: &'a AppState, ticket: &'a str) -> &'a str {
    let Ok(node) = ticket_endpoint_id(ticket) else {
        return ticket;
    };
    // Verified contacts and explicitly trusted server addresses can refresh an
    // established endpoint's route. PEX cannot replace an authorized route.
    state
        .contacts
        .values()
        .find(|contact| ticket_endpoint_id(&contact.ticket).ok().as_deref() == Some(node.as_str()))
        .map(|contact| contact.ticket.as_str())
        .or_else(|| {
            state
                .group_servers
                .iter()
                .find(|server| ticket_endpoint_id(server).ok().as_deref() == Some(node.as_str()))
                .map(String::as_str)
        })
        .unwrap_or(ticket)
}

fn refresh_mailbox_tickets(app: &mut App) -> Result<()> {
    let updates: Vec<_> = app
        .state
        .mailboxes
        .iter()
        .enumerate()
        .filter_map(|(index, mailbox)| {
            let ticket = current_node_ticket(&app.state, &mailbox.public.node_ticket);
            (ticket != mailbox.public.node_ticket).then(|| (index, ticket.to_owned()))
        })
        .collect();
    if updates.is_empty() {
        return Ok(());
    }
    app.atomic(|app| {
        for (index, ticket) in updates {
            app.state.mailboxes[index].public.node_ticket = ticket;
        }
        app.state.contact_version = app
            .state
            .contact_version
            .checked_add(1)
            .context("contact version exhausted")?;
        Ok(())
    })
}

fn add_job(
    jobs: &mut Vec<Job>,
    nodes: &mut BTreeSet<String>,
    schedule: &Schedule,
    ticket: &str,
    key: String,
    request: Request,
    kind: Kind,
) {
    if jobs.len() >= BATCH || !schedule.ready(&key) {
        return;
    }
    let Ok(node) = ticket_endpoint_id(ticket) else {
        return;
    };
    if !schedule.ready(&format!("node:{node}")) || !nodes.insert(node.clone()) {
        return;
    }
    jobs.push(Job {
        ticket: ticket.to_owned(),
        node,
        key,
        request,
        kind,
    });
}

fn select_fetch(app: &App, schedule: &mut Schedule) -> Vec<Job> {
    let mut jobs = vec![];
    let mut nodes = BTreeSet::new();
    for index in schedule.order(0, app.state.mailboxes.len()) {
        let mailbox = &app.state.mailboxes[index];
        let id = &mailbox.public.mailbox_id;
        let Ok(key) = mailbox_key(&mailbox.public) else {
            continue;
        };
        if let Some(ids) = schedule
            .acknowledgements
            .get(&key)
            .filter(|ids| !ids.is_empty())
        {
            let ids: Vec<_> = ids.iter().take(128).cloned().collect();
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                &mailbox.public.node_ticket,
                format!("delete:{key}"),
                Request::Delete {
                    mailbox_id: id.clone(),
                    read_token: mailbox.read_token.clone(),
                    ids: ids.clone(),
                },
                Kind::Delete { mailbox: key, ids },
            );
        } else {
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                &mailbox.public.node_ticket,
                format!("fetch:{key}"),
                Request::Fetch {
                    mailbox_id: id.clone(),
                    read_token: mailbox.read_token.clone(),
                },
                Kind::Fetch(mailbox.clone()),
            );
        }
        if jobs.len() == BATCH {
            break;
        }
    }
    jobs
}

pub(super) fn request_conversation(request: &Request) -> Option<&str> {
    match request {
        Request::HostedControl { record } => Some(&record.group_id),
        Request::Join { conversation, .. } => Some(&conversation.id),
        Request::Control { record } => Some(&record.conversation),
        Request::Sync { conversation, .. }
        | Request::Recover { conversation, .. }
        | Request::Update { conversation, .. }
        | Request::History { conversation, .. } => Some(conversation),
        Request::Deliver { envelope } | Request::Store { envelope, .. } => {
            Some(&envelope.conversation)
        }
        _ => None,
    }
}

fn pending_heads<'a>(pending: impl IntoIterator<Item = (usize, &'a Pending)>) -> Vec<usize> {
    let mut seen = BTreeSet::new();
    pending
        .into_iter()
        .filter_map(|(index, item)| {
            seen.insert((item.recipient.as_str(), request_conversation(&item.request)))
                .then_some(index)
        })
        .collect()
}

fn pending_index(state: &AppState, recipient: &str, digest: &[u8]) -> Option<usize> {
    state.pending.iter().position(|item| {
        item.recipient == recipient
            && serde_json::to_vec(&item.request)
                .is_ok_and(|bytes| &Sha256::digest(bytes)[..] == digest)
    })
}

fn select_pending(app: &App, schedule: &mut Schedule) -> Vec<Job> {
    let mut jobs = vec![];
    let mut nodes = BTreeSet::new();
    // Preserve order within each conversation, without letting one broken group
    // prevent the same recipient from receiving control traffic for other groups.
    let heads = pending_heads(app.state.pending.iter().enumerate().filter(|(_, pending)| {
        // Hosted controls use the independent server. Authorized plaintext history
        // stays on the direct owner channel and must not queue behind those controls.
        matches!(pending.request, Request::History { .. })
            || !request_conversation(&pending.request)
                .and_then(|id| app.state.conversations.get(id))
                .is_some_and(|group| group.server.is_some())
    }));
    for index in schedule.order(1, heads.len()) {
        let pending = &app.state.pending[heads[index]];
        let Some(contact) = app.state.contacts.get(&pending.recipient) else {
            continue;
        };
        let Ok(bytes) = serde_json::to_vec(&pending.request) else {
            continue;
        };
        let digest = Sha256::digest(bytes).to_vec();
        add_job(
            &mut jobs,
            &mut nodes,
            schedule,
            &contact.ticket,
            format!("pending:{}:{}", pending.recipient, hex::encode(&digest)),
            pending.request.clone(),
            Kind::Pending {
                recipient: pending.recipient.clone(),
                digest,
            },
        );
        if jobs.len() == BATCH {
            break;
        }
    }
    jobs
}

fn select_sync(app: &App, schedule: &mut Schedule) -> Vec<Job> {
    let mut jobs = vec![];
    let mut nodes = BTreeSet::new();
    let groups: Vec<_> = app
        .state
        .conversations
        .values()
        .filter(|group| {
            group.active
                && group.server.is_none()
                && !app.state.recovery_pending.contains(&group.id)
        })
        .collect();
    for index in schedule.order(2, groups.len()) {
        let group = groups[index];
        let mut members = vec![group.owner.as_str()];
        members.extend(
            group
                .members
                .iter()
                .map(String::as_str)
                .filter(|member| *member != group.owner),
        );
        // Each tick tries at most one available member per group. Failed owners are
        // backed off, allowing another member to provide its authenticated MLS log.
        for member in members {
            let Some(contact) = app.state.contacts.get(member) else {
                continue;
            };
            let before = jobs.len();
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                &contact.ticket,
                format!("sync:{}:{member}", group.id),
                Request::Sync {
                    conversation: group.id.clone(),
                    after_epoch: group.epoch,
                },
                Kind::Sync {
                    group: group.id.clone(),
                    peer: member.to_owned(),
                },
            );
            if jobs.len() != before {
                break;
            }
        }
        if jobs.len() == BATCH {
            break;
        }
    }
    jobs
}

fn select_outbox(app: &App, schedule: &mut Schedule) -> Vec<Job> {
    let mut jobs = vec![];
    let mut nodes = BTreeSet::new();
    let mut recipients = BTreeSet::new();
    for index in schedule.order(3, app.state.outbox.len()) {
        let item = &app.state.outbox[index];
        // Hosted groups publish once through group_delivery_tick, never through
        // recipient contact routes or cooperative private-message mailboxes.
        if app
            .state
            .conversations
            .get(&item.envelope.conversation)
            .is_some_and(|group| group.server.is_some())
        {
            continue;
        }
        if recipients.contains(&item.recipient) {
            continue;
        }
        if item.envelope.expires_at <= now() {
            continue;
        }
        let Some(contact) = app.state.contacts.get(&item.recipient) else {
            continue;
        };
        let recipient = &item.recipient;
        let message = &item.envelope.id;
        let before = jobs.len();
        // Prepare cache routes before direct delivery: a known healthy cache can
        // accept the first copy immediately even while the recipient is offline.
        let candidates = {
            // Only locations advertised by the recipient may receive the ciphertext.
            // Multiple mailbox IDs on one endpoint still count as one replica.
            let stored_nodes: BTreeSet<_> = item
                .stored_at
                .iter()
                .filter_map(|key| key.split_once('/').map(|(node, _)| node))
                .collect();
            let mut candidate_nodes = BTreeSet::new();
            let mut candidates = Vec::new();
            for mailbox in &contact.mailboxes {
                let Ok(key) = mailbox_key(mailbox) else {
                    continue;
                };
                let Ok(node) = ticket_endpoint_id(&mailbox.node_ticket) else {
                    continue;
                };
                if item.stored_at.contains(&key)
                    || stored_nodes.contains(node.as_str())
                    || nodes.contains(&node)
                    || !schedule.ready(&format!("node:{node}"))
                    || !schedule.ready(&format!("store:{recipient}:{message}:{key}"))
                    || !candidate_nodes.insert(node.clone())
                {
                    continue;
                }
                candidates.push((mailbox, key, node));
            }
            candidates
        };
        let direct_node = ticket_endpoint_id(&contact.ticket).unwrap_or_default();
        let prefer_cache = candidates
            .iter()
            .any(|(_, _, node)| schedule.routes.prefer_cache(node, &direct_node));
        if !prefer_cache {
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                &contact.ticket,
                format!("deliver:{recipient}:{message}"),
                Request::Deliver {
                    envelope: item.envelope.clone(),
                },
                Kind::Deliver {
                    recipient: recipient.clone(),
                    message: message.clone(),
                },
            );
        }
        if prefer_cache || jobs.len() == before {
            let route_nodes: Vec<_> = candidates
                .iter()
                .map(|(_, _, node)| node.as_str())
                .collect();
            if let Some(index) = schedule.routes.choose(recipient, &route_nodes) {
                let (mailbox, key, _) = &candidates[index];
                add_job(
                    &mut jobs,
                    &mut nodes,
                    schedule,
                    &mailbox.node_ticket,
                    format!("store:{recipient}:{message}:{key}"),
                    Request::Store {
                        mailbox_id: mailbox.mailbox_id.clone(),
                        write_token: mailbox.write_token.clone(),
                        envelope: item.envelope.clone(),
                    },
                    Kind::Store {
                        recipient: recipient.clone(),
                        message: message.clone(),
                        mailbox: key.clone(),
                    },
                );
            }
        }
        if jobs.len() != before {
            recipients.insert(item.recipient.clone());
        }
        if jobs.len() == BATCH {
            break;
        }
    }
    jobs
}

fn candidate_peers(app: &App) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let own = ticket_endpoint_id(&app.ticket).ok();
    app.state
        .contacts
        .values()
        .map(|contact| contact.ticket.clone())
        .chain(app.state.peers.iter().cloned())
        .filter(|ticket| {
            ticket_endpoint_id(ticket).is_ok_and(|id| Some(&id) != own.as_ref() && seen.insert(id))
        })
        .take(576)
        .collect()
}

fn select_discovery(app: &App, schedule: &mut Schedule, discover: bool) -> Vec<Job> {
    let mut jobs = vec![];
    let mut nodes = BTreeSet::new();
    let peers = candidate_peers(app);
    let active = app
        .state
        .mailboxes
        .iter()
        .filter(|mailbox| mailbox.retired_at.is_none())
        .count();
    let replace = app
        .state
        .mailboxes
        .iter()
        .find(|mailbox| {
            mailbox.retired_at.is_none()
                && schedule.replaceable(mailbox)
                && !app.state.personal_mailbox.as_ref().is_some_and(|personal| {
                    personal.mailbox_id == mailbox.public.mailbox_id
                        && ticket_endpoint_id(&mailbox.public.node_ticket)
                            .ok()
                            .as_ref()
                            == Some(&personal.node)
                })
        })
        .and_then(|mailbox| mailbox_key(&mailbox.public).ok());
    if discover
        && app.state.mailboxes.len() < MAX_LOCAL_MAILBOXES
        && (active < 3 || replace.is_some())
    {
        let mut candidates = Vec::new();
        for index in schedule.order(4, peers.len()) {
            let ticket = &peers[index];
            let Ok(node) = ticket_endpoint_id(ticket) else {
                continue;
            };
            if app.state.mailboxes.iter().any(|mailbox| {
                ticket_endpoint_id(&mailbox.public.node_ticket)
                    .ok()
                    .as_ref()
                    == Some(&node)
            }) || !schedule.ready(&format!("node:{node}"))
                || !schedule.ready(&format!("allocate:{node}"))
            {
                continue;
            }
            candidates.push((ticket, node));
        }
        let route_nodes: Vec<_> = candidates.iter().map(|(_, node)| node.as_str()).collect();
        if let Some(index) = schedule.routes.choose("allocate", &route_nodes) {
            let (ticket, node) = &candidates[index];
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                ticket,
                format!("allocate:{node}"),
                Request::Allocate,
                Kind::Allocate {
                    replace: replace.clone(),
                },
            );
        }
    }
    // Newly signed descriptors are announced even on ticks that don't perform PEX.
    if let Ok(invitation) = app.invitation() {
        let contacts: Vec<_> = app.state.contacts.values().collect();
        for index in schedule.order(5, contacts.len()) {
            let contact = contacts[index];
            if !discover && schedule.announced.get(&contact.id) == Some(&app.state.contact_version)
            {
                continue;
            }
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                &contact.ticket,
                format!("hello:{}", contact.id),
                Request::Hello {
                    invitation: invitation.clone(),
                    authorization: contact.invite_token.clone(),
                },
                Kind::Hello {
                    contact: contact.id.clone(),
                    version: app.state.contact_version,
                },
            );
            if jobs.len() >= 3 {
                break;
            }
        }
    }
    if discover {
        for index in schedule.order(4, peers.len()) {
            let ticket = &peers[index];
            add_job(
                &mut jobs,
                &mut nodes,
                schedule,
                ticket,
                format!("peers:{}", ticket_endpoint_id(ticket).unwrap_or_default()),
                Request::Peers,
                Kind::Peers,
            );
            if jobs.len() == BATCH {
                break;
            }
        }
    }
    jobs
}

async fn run_batch(
    shared: &Shared,
    transport: &Transport,
    runtime: &Runtime,
    jobs: Vec<Job>,
) -> Result<()> {
    let mut jobs = jobs.into_iter();
    let results = tokio::join!(
        run_job(shared, transport, runtime, jobs.next()),
        run_job(shared, transport, runtime, jobs.next()),
        run_job(shared, transport, runtime, jobs.next()),
        run_job(shared, transport, runtime, jobs.next()),
    );
    results.0?;
    results.1?;
    results.2?;
    results.3?;
    Ok(())
}

async fn run_job(
    shared: &Shared,
    transport: &Transport,
    runtime: &Runtime,
    job: Option<Job>,
) -> Result<()> {
    let Some(mut job) = job else { return Ok(()) };
    {
        let app = shared.lock().unwrap();
        // A sender may know a signed storage-node address newer than the
        // recipient's last mailbox announcement. The authenticated ID is fixed.
        job.ticket = current_node_ticket(&app.state, &job.ticket).to_owned();
    }
    // No state or scheduler lock is held while awaiting the network.
    let started = Instant::now();
    let response = transport.request(&job.ticket, job.request.clone()).await;
    let elapsed = started.elapsed();
    let network_failed = response.is_err();
    let result = response.and_then(|response| apply_response(shared, runtime, &job, response));
    let mut schedule = runtime.schedule.lock().unwrap();
    // Application-level MLS/authorization failures do not establish cache health.
    // Cache operations and transport failures do; PEX contributes only measured RPC
    // behavior, never a score supplied by another node.
    if network_failed
        || matches!(
            job.kind,
            Kind::Allocate { .. }
                | Kind::Fetch(_)
                | Kind::Delete { .. }
                | Kind::Store { .. }
                | Kind::Peers
        )
        || (result.is_ok() && matches!(job.kind, Kind::Deliver { .. }))
    {
        schedule.routes.observe(&job.node, elapsed, result.is_ok());
    }
    match result {
        Ok(cooldown) => {
            schedule.succeeded(job.key, cooldown);
            schedule.succeeded(format!("node:{}", job.node), 0);
        }
        Err(error) => {
            schedule.failed(job.key);
            if network_failed {
                schedule.failed(format!("node:{}", job.node));
            }
            // The operation remains queued. Other recipients continue in this batch.
            drop(schedule);
            shared.lock().unwrap().status = format!("Background retry: {error}");
        }
    }
    Ok(())
}

fn apply_response(
    shared: &Shared,
    runtime: &Runtime,
    job: &Job,
    response: Response,
) -> Result<u64> {
    if let Response::Error(message) = &response {
        bail!("{message}");
    }
    match (&job.kind, response) {
        (Kind::Fetch(mailbox), Response::Envelopes(envelopes)) => {
            let mut ids = vec![];
            // Bound synchronous crypto/database work as well as network work.
            for envelope in envelopes.into_iter().take(128) {
                let id = envelope.id.clone();
                if id.len() > 64 {
                    continue;
                }
                let mut app = shared.lock().unwrap();
                // Malformed/expired data can never become valid after MLS synchronization.
                if envelope.validate(now()).is_err() {
                    ids.push(id);
                    continue;
                }
                if app.atomic(|app| app.receive(envelope.clone())).is_ok() {
                    ids.push(id);
                } else {
                    // A remote copy can be deleted only while a durable local copy remains.
                    // When missing epochs fill the inbox, leave this item on the relay.
                    // Later items in the same bounded page may already be decryptable.
                    let retained = app.atomic(|app| defer_envelope(&mut app.state, envelope))?;
                    if !retained {
                        app.status = "Deferred inbox full; waiting messages kept on relay".into();
                        continue;
                    }
                    ids.push(id);
                }
            }
            if !ids.is_empty() {
                let mut schedule = runtime.schedule.lock().unwrap();
                let ack = schedule
                    .acknowledgements
                    .entry(mailbox_key(&mailbox.public)?)
                    .or_default();
                for id in ids {
                    if !ack.contains(&id) {
                        ack.push(id);
                    }
                }
            }
            Ok(10)
        }
        (Kind::Delete { mailbox, ids }, Response::Ok) => {
            if let Some(ack) = runtime
                .schedule
                .lock()
                .unwrap()
                .acknowledgements
                .get_mut(mailbox)
            {
                ack.retain(|id| !ids.contains(id));
            }
            Ok(0)
        }
        (Kind::Pending { recipient, digest }, Response::Ok) => {
            ensure!(
                !matches!(&job.request, Request::History { .. }),
                "history request requires a history response"
            );
            shared.lock().unwrap().atomic(|app| {
                // Only remove the exact acknowledged item; another conversation may
                // precede this one in the recipient's overall queue.
                if let Some(index) = pending_index(&app.state, recipient, digest) {
                    app.state.pending.remove(index);
                }
                Ok(())
            })?;
            Ok(0)
        }
        (Kind::Pending { recipient, digest }, Response::History { messages, next }) => {
            let Request::History {
                conversation,
                after,
            } = &job.request
            else {
                bail!("unsolicited history response");
            };
            ensure!(
                serde_json::to_vec(&messages)?.len() <= 400 * 1024,
                "history page too large"
            );
            let mut previous = after.as_deref();
            for signed in &messages {
                ensure!(
                    signed.message.conversation == *conversation
                        && previous.is_none_or(|previous| signed.message.id.as_str() > previous),
                    "invalid history order or conversation"
                );
                previous = Some(&signed.message.id);
            }
            if let Some(next) = &next {
                ensure!(
                    next.len() <= 64
                        && Some(next.as_str()) == previous
                        && after.as_ref().is_none_or(|after| next > after),
                    "invalid history cursor"
                );
                ensure!(!messages.is_empty(), "history cursor did not advance");
            }
            shared.lock().unwrap().atomic(|app| {
                let owner = &app
                    .state
                    .conversations
                    .get(conversation)
                    .context("unknown history conversation")?
                    .owner;
                ensure!(owner == recipient, "history must come from the group owner");
                let contact = app
                    .state
                    .contacts
                    .get(recipient)
                    .context("unknown history owner")?;
                ensure!(
                    ticket_endpoint_id(&contact.ticket)? == job.node,
                    "history owner endpoint mismatch"
                );
                let Some(index) = pending_index(&app.state, recipient, digest) else {
                    return Ok(());
                };
                app.import_history(conversation, messages)?;
                app.state.pending.remove(index);
                if let Some(after) = next {
                    app.state.pending.push(Pending {
                        recipient: recipient.clone(),
                        request: Request::History {
                            conversation: conversation.clone(),
                            after: Some(after),
                        },
                    });
                }
                Ok(())
            })?;
            Ok(0)
        }
        (Kind::Deliver { recipient, message }, Response::Ok) => {
            shared.lock().unwrap().atomic(|app| {
                app.state
                    .outbox
                    .retain(|item| &item.recipient != recipient || &item.envelope.id != message);
                Ok(())
            })?;
            Ok(0)
        }
        (
            Kind::Store {
                recipient,
                message,
                mailbox,
            },
            Response::Ok,
        ) => {
            shared.lock().unwrap().atomic(|app| {
                if let Some(item) = app
                    .state
                    .outbox
                    .iter_mut()
                    .find(|item| &item.recipient == recipient && &item.envelope.id == message)
                    && !item.stored_at.contains(mailbox)
                {
                    item.stored_at.push(mailbox.clone());
                }
                Ok(())
            })?;
            Ok(0)
        }
        (
            Kind::Sync { group, peer },
            Response::Sync {
                controls,
                contacts,
                current_epoch,
            },
        ) => {
            ensure!(
                controls.len() <= 32 && contacts.len() <= MAX_GROUP_MEMBERS,
                "invalid sync page"
            );
            let mut app = shared.lock().unwrap();
            let current = app
                .state
                .conversations
                .get(group)
                .context("unknown sync conversation")?
                .clone();
            ensure!(
                controls.iter().all(|record| &record.conversation == group),
                "cross-group sync response"
            );
            ensure!(
                controls.iter().all(|record| record.epoch <= current_epoch),
                "invalid sync epoch"
            );
            let mut expected = current.epoch;
            let mut has_gap = false;
            for control in controls
                .iter()
                .filter(|record| record.epoch > current.epoch)
            {
                if control.epoch != expected.saturating_add(1) {
                    has_gap = true;
                    break;
                }
                expected = control.epoch;
            }
            has_gap |= expected == current.epoch && current_epoch > current.epoch;
            if has_gap {
                if peer == &current.owner && !app.state.recovery_pending.contains(group) {
                    let owner = current.owner.clone();
                    app.atomic(|app| {
                        let request = app.prepare_recovery(group)?;
                        app.state.pending.push(Pending {
                            recipient: owner,
                            request,
                        });
                        Ok(())
                    })?;
                    app.status = "Owner log has a gap; membership recovery queued".into();
                    return Ok(30);
                }
                bail!("sync log has a gap; waiting for owner");
            }
            let changed = controls.iter().any(|record| record.epoch > current.epoch);
            app.atomic(|app| {
                for control in controls {
                    let epoch = app
                        .state
                        .conversations
                        .get(group)
                        .context("missing sync group")?
                        .epoch;
                    if control.epoch > epoch {
                        app.apply_control(control)?;
                    }
                }
                let members = app
                    .state
                    .conversations
                    .get(group)
                    .context("missing sync group")?
                    .members
                    .clone();
                for invitation in contacts {
                    if invitation.contact.id != app.id() && members.contains(&invitation.contact.id)
                    {
                        // An older directory must not roll back a fresher signed descriptor.
                        let stale = app
                            .state
                            .contacts
                            .get(&invitation.contact.id)
                            .is_some_and(|known| invitation.contact.version < known.version);
                        if !stale {
                            app.import_contact(invitation)?;
                        }
                    }
                }
                Ok(())
            })?;
            Ok(if changed { 0 } else { 15 })
        }
        (Kind::Hello { contact, version }, Response::Hello(invitation)) => {
            ensure!(
                &invitation.contact.id == contact,
                "unexpected remote identity"
            );
            ensure!(
                ticket_endpoint_id(&invitation.contact.ticket)? == job.node,
                "remote endpoint mismatch"
            );
            shared.lock().unwrap().atomic(|app| {
                app.import_contact(invitation)?;
                Ok(())
            })?;
            runtime
                .schedule
                .lock()
                .unwrap()
                .announced
                .insert(contact.clone(), *version);
            Ok(15)
        }
        (Kind::Peers, Response::Peers(peers)) => {
            let mut app = shared.lock().unwrap();
            let own = ticket_endpoint_id(&app.ticket).ok();
            let mut seen = BTreeSet::new();
            let peers: Vec<_> = peers
                .into_iter()
                .take(32)
                .chain(app.state.peers.iter().cloned())
                .filter(|ticket| {
                    ticket_endpoint_id(ticket)
                        .is_ok_and(|id| Some(&id) != own.as_ref() && seen.insert(id))
                })
                .take(64)
                .collect();
            app.atomic(|app| {
                app.state.peers = peers;
                Ok(())
            })?;
            Ok(60)
        }
        (
            Kind::Allocate { replace },
            Response::Mailbox {
                mailbox_id,
                write_token,
                read_token,
            },
        ) => {
            ensure!(
                mailbox_id.len() == 32
                    && write_token.len() == 64
                    && read_token.len() == 64
                    && hex::decode(&mailbox_id).is_ok()
                    && hex::decode(&write_token).is_ok()
                    && hex::decode(&read_token).is_ok()
                    && !read_token.eq_ignore_ascii_case(&write_token),
                "invalid mailbox capabilities"
            );
            shared.lock().unwrap().atomic(|app| {
                ensure!(
                    app.state.mailboxes.len() < MAX_LOCAL_MAILBOXES,
                    "mailbox rotation limit reached"
                );
                if app.state.mailboxes.iter().any(|mailbox| {
                    ticket_endpoint_id(&mailbox.public.node_ticket)
                        .ok()
                        .as_ref()
                        == Some(&job.node)
                }) {
                    return Ok(());
                }
                let active = app
                    .state
                    .mailboxes
                    .iter()
                    .filter(|mailbox| mailbox.retired_at.is_none())
                    .count();
                if active >= 3 {
                    // The user may pin a mailbox while allocation is in flight.
                    let protected = app
                        .state
                        .personal_mailbox
                        .as_ref()
                        .map(|personal| format!("{}/{}", personal.node, personal.mailbox_id));
                    ensure!(
                        protected
                            .as_ref()
                            .is_none_or(|key| replace.as_ref() != Some(key)),
                        "personal mailbox cannot be replaced automatically"
                    );
                    let old = app
                        .state
                        .mailboxes
                        .iter_mut()
                        .find(|mailbox| {
                            mailbox_key(&mailbox.public).ok().as_ref() == replace.as_ref()
                                && mailbox.retired_at.is_none()
                        })
                        .context("mailbox replacement no longer applies")?;
                    old.retired_at = Some(now());
                }
                app.state.mailboxes.push(LocalMailbox {
                    public: Mailbox {
                        node_ticket: job.ticket.clone(),
                        mailbox_id,
                        write_token,
                    },
                    read_token,
                    retired_at: None,
                });
                app.state.contact_version += 1;
                Ok(())
            })?;
            Ok(0)
        }
        _ => bail!("unexpected response type"),
    }
}

pub async fn synchronize(shared: &Shared, transport: &Transport) {
    let runtime = runtime(&transport.endpoint_id());
    let Ok(_guard) = runtime.gate.try_lock() else {
        return;
    };
    if let Err(error) = super::group_delivery_tick(shared, transport).await {
        shared.lock().unwrap().status = format!("Hosted groups: {error}");
    }
    let jobs = {
        let app = shared.lock().unwrap();
        select_sync(&app, &mut runtime.schedule.lock().unwrap())
    };
    let _ = run_batch(shared, transport, &runtime, jobs).await;
    let mut app = shared.lock().unwrap();
    if let Err(error) = retry_deferred(&mut app) {
        app.status = format!("Deferred inbox: {error}");
    }
}

pub async fn network_tick(shared: &Shared, transport: &Transport, discover: bool) -> Result<()> {
    let runtime = runtime(&transport.endpoint_id());
    let Ok(_guard) = runtime.gate.try_lock() else {
        return Ok(());
    };
    {
        let mut app = shared.lock().unwrap();
        let time = now();
        app.state.purge_expired(time);
        app.store.purge(time)?;
        if let Ok(ticket) = transport.ticket()
            && ticket != app.ticket
        {
            app.atomic(|app| {
                app.state.contact_version = app
                    .state
                    .contact_version
                    .checked_add(1)
                    .context("contact version exhausted")?;
                Ok(())
            })?;
            app.ticket = ticket;
        }
        refresh_mailbox_tickets(&mut app)?;
        if let Err(error) = app.maybe_rekey(time) {
            app.status = format!("Rekey pending: {error}");
        }
    }
    {
        // Old completed/expired message retry keys must not accumulate forever.
        let mut schedule = runtime.schedule.lock().unwrap();
        let time = Instant::now();
        schedule.retries.retain(|_, retry| {
            time.saturating_duration_since(retry.due) < Duration::from_secs(3600)
        });
    }
    // Service hosted groups before direct peers whose connection attempts may time out.
    if let Err(error) = super::group_delivery_tick(shared, transport).await {
        shared.lock().unwrap().status = format!("Hosted groups: {error}");
    }
    // Persist outgoing copies before an offline peer's sync can consume its whole
    // timeout. Each category still gets one bounded turn; four background RPCs
    // leave transport permits for inbound application requests.
    for category in [3, 0, 1, 2, 4] {
        let jobs = {
            let app = shared.lock().unwrap();
            let mut schedule = runtime.schedule.lock().unwrap();
            match category {
                0 => select_fetch(&app, &mut schedule),
                1 => select_pending(&app, &mut schedule),
                2 => select_sync(&app, &mut schedule),
                3 => select_outbox(&app, &mut schedule),
                _ => select_discovery(&app, &mut schedule, discover),
            }
        };
        run_batch(shared, transport, &runtime, jobs).await?;
        if category == 2 {
            retry_deferred(&mut shared.lock().unwrap())?;
        }
    }
    shared.lock().unwrap().save()?;
    Ok(())
}

fn same_envelope(left: &Envelope, right: &Envelope) -> bool {
    left.id == right.id
        && left.conversation == right.conversation
        && left.created_at == right.created_at
        && left.expires_at == right.expires_at
        && left.ciphertext == right.ciphertext
}

fn deferred_size(envelope: &Envelope) -> usize {
    // Conservative JSON representation size: each byte can require three digits
    // plus a comma; identifiers can expand to six-character JSON escapes.
    envelope
        .ciphertext
        .len()
        .saturating_mul(4)
        .saturating_add(envelope.id.len().saturating_mul(6))
        .saturating_add(envelope.conversation.len().saturating_mul(6))
        .saturating_add(256)
}

/// Returns whether this exact ciphertext is retained and can be acknowledged.
pub(super) fn defer_envelope(state: &mut AppState, envelope: Envelope) -> Result<bool> {
    envelope.validate(now())?;
    if state
        .deferred
        .iter()
        .any(|known| same_envelope(known, &envelope))
    {
        return Ok(true);
    }
    let size = deferred_size(&envelope);
    ensure!(
        size <= MAX_DEFERRED_BYTES,
        "deferred envelope exceeds capacity"
    );
    let total = state.deferred.iter().map(deferred_size).sum::<usize>();
    if state.deferred.len() >= MAX_DEFERRED_MESSAGES
        || total.saturating_add(size) > MAX_DEFERRED_BYTES
    {
        return Ok(false);
    }
    state.deferred.push(envelope);
    Ok(true)
}

pub(super) fn retry_deferred(app: &mut App) -> Result<()> {
    let count = app.state.deferred.len().min(BATCH);
    for _ in 0..count {
        let Some(envelope) = app.state.deferred.first().cloned() else {
            break;
        };
        let result = app.atomic(|app| {
            if envelope.expires_at > now() {
                app.receive(envelope.clone())?;
            }
            app.state
                .deferred
                .retain(|known| !same_envelope(known, &envelope));
            Ok(())
        });
        if result.is_err() {
            app.atomic(|app| {
                if let Some(index) = app
                    .state
                    .deferred
                    .iter()
                    .position(|known| same_envelope(known, &envelope))
                {
                    let envelope = app.state.deferred.remove(index);
                    app.state.deferred.push(envelope);
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/transport/deferred_inbox.rs"]
mod deferred_inbox;

#[cfg(test)]
#[path = "../tests/transport/routing_selection.rs"]
mod routing_selection;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_selection_keeps_per_recipient_and_conversation_fifo() {
        let pending = [
            Pending {
                recipient: "offline".into(),
                request: Request::History {
                    conversation: "one".into(),
                    after: None,
                },
            },
            Pending {
                recipient: "offline".into(),
                request: Request::History {
                    conversation: "one".into(),
                    after: Some("page2".into()),
                },
            },
            Pending {
                recipient: "offline".into(),
                request: Request::History {
                    conversation: "two".into(),
                    after: None,
                },
            },
            Pending {
                recipient: "online".into(),
                request: Request::Peers,
            },
            Pending {
                recipient: "offline".into(),
                request: Request::Peers,
            },
            Pending {
                recipient: "offline".into(),
                request: Request::Allocate,
            },
        ];
        assert_eq!(pending_heads(pending.iter().enumerate()), vec![0, 2, 3, 4]);
    }

    #[test]
    fn pending_ack_matches_the_original_request_after_queue_changes() {
        let request = Request::History {
            conversation: "one".into(),
            after: None,
        };
        let digest = Sha256::digest(serde_json::to_vec(&request).unwrap());
        let mut state = AppState::default();
        state.pending.push(Pending {
            recipient: "other".into(),
            request: request.clone(),
        });
        state.pending.push(Pending {
            recipient: "owner".into(),
            request: Request::Peers,
        });
        state.pending.push(Pending {
            recipient: "owner".into(),
            request,
        });
        assert_eq!(pending_index(&state, "owner", &digest), Some(2));
        state.pending.remove(1);
        assert_eq!(pending_index(&state, "owner", &digest), Some(1));
        state.pending.remove(1);
        assert_eq!(pending_index(&state, "owner", &digest), None);
    }

    #[test]
    fn mailbox_cache_keys_are_scoped_to_authenticated_storage_nodes() {
        let mailbox = |seed| {
            let addr = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&[seed; 32]).public())
                .with_ip_addr("127.0.0.1:9".parse().unwrap());
            Mailbox {
                node_ticket: crate::transport::encode_ticket(&addr).unwrap(),
                mailbox_id: "same-id".into(),
                write_token: "unused".into(),
            }
        };
        assert_ne!(
            mailbox_key(&mailbox(1)).unwrap(),
            mailbox_key(&mailbox(2)).unwrap()
        );
    }

    fn envelope(id: usize, payload: usize) -> Envelope {
        let time = now();
        Envelope {
            id: id.to_string(),
            conversation: "test".into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![255; payload],
        }
    }

    #[test]
    fn deferred_rejects_invalid_input_and_deduplicates_only_exact_ciphertext() {
        let mut state = AppState::default();
        let first = envelope(1, 8);
        assert!(defer_envelope(&mut state, first.clone()).unwrap());
        assert!(defer_envelope(&mut state, first.clone()).unwrap());
        assert_eq!(state.deferred.len(), 1);
        let mut changed = first.clone();
        changed.ciphertext[0] = 0;
        defer_envelope(&mut state, changed).unwrap();
        assert_eq!(
            state.deferred.len(),
            2,
            "an untrusted message ID cannot suppress different ciphertext"
        );
        let mut invalid = first;
        invalid.expires_at += 1;
        assert!(defer_envelope(&mut state, invalid).is_err());
        assert_eq!(state.deferred.len(), 2);
    }

    #[test]
    fn deferred_capacity_preserves_accepted_messages_and_bounds_serialized_bytes() {
        let mut state = AppState::default();
        for id in 0..MAX_DEFERRED_MESSAGES {
            let mut item = envelope(id, 1);
            if id == 17 {
                item.created_at -= 100;
                item.expires_at -= 100;
            }
            assert!(defer_envelope(&mut state, item).unwrap());
        }
        let before = serde_json::to_vec(&state.deferred).unwrap();
        assert!(!defer_envelope(&mut state, envelope(999, 1)).unwrap());
        assert_eq!(state.deferred.len(), MAX_DEFERRED_MESSAGES);
        assert_eq!(serde_json::to_vec(&state.deferred).unwrap(), before);
        let duplicate = state.deferred[17].clone();
        assert!(defer_envelope(&mut state, duplicate).unwrap());

        state.deferred.clear();
        for id in 0..32 {
            let before = serde_json::to_vec(&state.deferred).unwrap();
            if !defer_envelope(&mut state, envelope(id, 128 * 1024)).unwrap() {
                assert_eq!(serde_json::to_vec(&state.deferred).unwrap(), before);
            }
        }
        assert!(state.deferred.len() < 32);
        assert_eq!(state.deferred.first().unwrap().id, "0");
        assert!(state.deferred.iter().map(deferred_size).sum::<usize>() <= MAX_DEFERRED_BYTES);
        assert!(serde_json::to_vec(&state.deferred).unwrap().len() <= MAX_DEFERRED_BYTES);

        let expiry = state
            .deferred
            .iter()
            .map(|item| item.expires_at)
            .max()
            .unwrap();
        state.purge_expired(expiry);
        assert!(state.deferred.is_empty());
        assert!(defer_envelope(&mut state, envelope(999, 128 * 1024)).unwrap());
    }

    #[test]
    fn retry_backoff_and_round_robin_do_not_pin_queue_front() {
        let mut schedule = Schedule::default();
        schedule.failed("offline".into());
        assert!(!schedule.ready("offline"));
        assert!(schedule.ready("online"));
        assert_eq!(schedule.order(0, 9)[0], 0);
        assert_eq!(schedule.order(0, 9)[0], 4);
        assert_eq!(schedule.order(0, 9)[0], 8);
        schedule.succeeded("offline".into(), 0);
        assert!(schedule.ready("offline"));
    }
}
