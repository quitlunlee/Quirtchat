//! Media bytes stay in bounded SQLCipher tables; only small descriptors enter MLS.
use super::*;
use crate::media::{self, MediaDescriptor, PreparedMedia};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

impl App {
    /// Stages ciphertext, then atomically publishes the MLS descriptor and upload jobs.
    pub fn send_attachment(
        &mut self,
        conversation: &str,
        prepared: PreparedMedia,
        caption: String,
    ) -> Result<String> {
        let time = now();
        prepared.descriptor.validate(time)?;
        // Also validates every chunk and the final digest before advertising the file.
        drop(media::decrypt_complete(
            &prepared.descriptor,
            &prepared.chunks,
            time,
        )?);
        let mut descriptor = prepared.descriptor;
        if let Some(route) = self
            .state
            .conversations
            .get(conversation)
            .and_then(|group| group.server.as_ref())
        {
            descriptor.sources = vec![route.ticket.clone()];
        }
        ensure!(
            self.store.media_progress(&descriptor.id, time)? == 0,
            "media identifier already exists"
        );
        if self
            .state
            .conversations
            .get(conversation)
            .is_some_and(|group| group.server.is_none())
        {
            ensure!(
                self.state.media_uploads.len() < 384,
                "media upload queue is full"
            );
        }
        self.store
            .store_local_media(&prepared.chunks, &descriptor.read_token, time)?;
        let result = self.atomic(|app| {
            let message = app.send_content(
                conversation,
                caption,
                Some(descriptor.clone()),
                descriptor.created_at,
            )?;
            if app.state.conversations[conversation].server.is_some() {
                app.hosted_media_upload(conversation, &descriptor)?;
                return Ok(message);
            }
            for mailbox in app
                .state
                .mailboxes
                .iter()
                .filter(|m| m.retired_at.is_none())
                .take(3)
            {
                if descriptor.sources.iter().any(|source| {
                    ticket_endpoint_id(source).ok()
                        == ticket_endpoint_id(&mailbox.public.node_ticket).ok()
                }) {
                    app.state.media_uploads.push(MediaUpload {
                        media_id: descriptor.id.clone(),
                        mailbox: mailbox.public.clone(),
                        read_token: descriptor.read_token.clone(),
                        next_chunk: 0,
                        chunks: descriptor.chunks,
                        expires_at: descriptor.expires_at,
                    });
                }
            }
            Ok(message)
        });
        if result.is_err() {
            self.store.delete_local_media(&descriptor.id)?;
        }
        result
    }

    pub fn media_message(&self, query: &str, conversation: Option<&str>) -> Result<ChatMessage> {
        let mut messages = self.state.messages.iter().rev().filter(|m| {
            m.expires_at > now()
                && m.attachment.is_some()
                && conversation.is_none_or(|id| id == m.conversation)
                && (query.is_empty() || m.id.starts_with(query))
        });
        let message = messages
            .next()
            .context("no matching unexpired media message")?;
        ensure!(
            query.is_empty() || messages.next().is_none(),
            "ambiguous message prefix"
        );
        Ok(message.clone())
    }

    /// Calling this is sufficient to persist a download; it is safe to repeat.
    pub fn request_media(
        &mut self,
        query: &str,
        conversation: Option<&str>,
    ) -> Result<ChatMessage> {
        let message = self.media_message(query, conversation)?;
        let descriptor = message.attachment.as_ref().unwrap();
        descriptor.validate(now())?;
        // A shared media ID does not prove that this message's descriptor matches
        // the cached file. Authenticate complete cached data before declaring it ready.
        if self.media_bytes(&message)?.is_none()
            && !self
                .state
                .media_downloads
                .iter()
                .any(|d| d.message_id == message.id && d.conversation == message.conversation)
        {
            ensure!(
                self.state.media_downloads.len() < 128,
                "media download queue is full"
            );
            self.atomic(|app| {
                app.state.media_downloads.push(MediaDownload {
                    message_id: message.id.clone(),
                    conversation: message.conversation.clone(),
                    media_id: descriptor.id.clone(),
                    next_chunk: 0,
                    source_cursor: 0,
                    expires_at: descriptor.expires_at,
                });
                Ok(())
            })?;
        }
        Ok(message)
    }

    pub fn media_bytes(&self, message: &ChatMessage) -> Result<Option<Zeroizing<Vec<u8>>>> {
        message.validate(now())?;
        let descriptor = message
            .attachment
            .as_ref()
            .context("message has no attachment")?;
        if self.store.media_progress(&descriptor.id, now())? < descriptor.chunks as usize {
            return Ok(None);
        }
        let mut chunks = Vec::with_capacity(descriptor.chunks as usize);
        for index in 0..descriptor.chunks {
            match self.store.get_local_media(
                &descriptor.id,
                index,
                &descriptor.read_token,
                now(),
            )? {
                Some(chunk) => chunks.push(chunk),
                None => return Ok(None),
            }
        }
        Ok(Some(media::decrypt_complete(descriptor, &chunks, now())?))
    }
}

pub async fn send_media(
    shared: &Shared,
    conversation: &str,
    path: PathBuf,
    caption: String,
) -> Result<String> {
    let sources = {
        let app = shared.lock().unwrap();
        if let Some(route) = app
            .state
            .conversations
            .get(conversation)
            .and_then(|group| group.server.as_ref())
        {
            vec![route.ticket.clone()]
        } else {
            let mut sources = Vec::new();
            if !app.ticket.is_empty() {
                sources.push(app.ticket.clone());
            }
            for mailbox in app
                .state
                .mailboxes
                .iter()
                .filter(|m| m.retired_at.is_none())
                .take(3)
            {
                if !sources.contains(&mailbox.public.node_ticket) {
                    sources.push(mailbox.public.node_ticket.clone());
                }
            }
            sources
        }
    };
    let shared = shared.clone();
    let conversation = conversation.to_owned();
    tokio::task::spawn_blocking(move || {
        let prepared = media::prepare_file(&path, &sources, now())?;
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("profile state lock failed"))?
            .send_attachment(&conversation, prepared, caption)
    })
    .await
    .context("attachment preparation worker stopped")?
}

#[derive(Default)]
struct Scheduler {
    cursor: usize,
    retry: BTreeMap<String, (u32, Instant)>,
}
#[derive(Default)]
struct Runtime {
    gate: tokio::sync::Mutex<()>,
    schedule: Mutex<Scheduler>,
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
#[derive(Clone)]
enum Job {
    Upload(MediaUpload),
    Download(MediaDownload, MediaDescriptor, Vec<String>),
}
impl Job {
    fn key(&self) -> String {
        match self {
            Self::Upload(job) => format!(
                "u/{}/{}/{}",
                job.media_id,
                ticket_endpoint_id(&job.mailbox.node_ticket).unwrap_or_default(),
                job.mailbox.mailbox_id
            ),
            Self::Download(job, _, _) => format!("d/{}/{}", job.conversation, job.message_id),
        }
    }
}

fn upload_ticket(app: &App, upload: &MediaUpload) -> String {
    let node = ticket_endpoint_id(&upload.mailbox.node_ticket).ok();
    let ticket = app
        .state
        .mailboxes
        .iter()
        .find(|mailbox| {
            mailbox.public.mailbox_id == upload.mailbox.mailbox_id
                && ticket_endpoint_id(&mailbox.public.node_ticket).ok() == node
        })
        .map_or(upload.mailbox.node_ticket.as_str(), |mailbox| {
            mailbox.public.node_ticket.as_str()
        });
    super::ticker::current_node_ticket(&app.state, ticket).to_owned()
}

fn download_sources(app: &App, message: &ChatMessage, descriptor: &MediaDescriptor) -> Vec<String> {
    if let Some(route) = app
        .state
        .conversations
        .get(&message.conversation)
        .and_then(|group| group.server.as_ref())
    {
        return vec![route.ticket.clone()];
    }
    let own = ticket_endpoint_id(&app.ticket).ok();
    let mut seen = BTreeSet::new();
    app.state
        .contacts
        .get(&message.sender)
        .map(|contact| &contact.ticket)
        .into_iter()
        .chain(descriptor.sources.iter())
        .map(|source| super::ticker::current_node_ticket(&app.state, source))
        .filter(|source| {
            ticket_endpoint_id(source)
                .is_ok_and(|node| Some(&node) != own.as_ref() && seen.insert(node))
        })
        .map(str::to_owned)
        .collect()
}

/// At most two chunk RPCs per tick, sharing the transport bandwidth and concurrency cap.
pub async fn media_tick(shared: &Shared, transport: &Transport) -> Result<()> {
    let own = shared.lock().unwrap().id().to_owned();
    let runtime = runtime(&own);
    let Ok(_gate) = runtime.gate.try_lock() else {
        return Ok(());
    };
    let jobs =
        {
            let app = shared.lock().unwrap();
            let mut jobs = Vec::new();
            for upload in app
                .state
                .media_uploads
                .iter()
                .filter(|job| job.expires_at > now())
            {
                jobs.push(Job::Upload(upload.clone()));
            }
            for download in app
                .state
                .media_downloads
                .iter()
                .filter(|job| job.expires_at > now())
            {
                let Some(message) = app.state.messages.iter().find(|m| {
                    m.id == download.message_id && m.conversation == download.conversation
                }) else {
                    continue;
                };
                let Some(descriptor) = message.attachment.as_ref() else {
                    continue;
                };
                let sources = download_sources(&app, message, descriptor);
                jobs.push(Job::Download(download.clone(), descriptor.clone(), sources));
            }
            jobs
        };
    let selected = {
        let mut scheduler = runtime.schedule.lock().unwrap();
        scheduler
            .retry
            .retain(|key, _| jobs.iter().any(|job| &job.key() == key));
        let mut selected = Vec::new();
        for offset in 0..jobs.len() {
            let index = (scheduler.cursor + offset) % jobs.len();
            let job = &jobs[index];
            if scheduler
                .retry
                .get(&job.key())
                .is_none_or(|(_, due)| *due <= Instant::now())
            {
                selected.push(job.clone());
                if selected.len() == 2 {
                    break;
                }
            }
        }
        if !jobs.is_empty() {
            scheduler.cursor = (scheduler.cursor + selected.len().max(1)) % jobs.len();
        }
        selected
    };
    // Futures are polled concurrently without keeping the profile mutex over I/O.
    let mut selected = selected.into_iter();
    let execute = |job: Option<Job>| async move {
        match job {
            Some(job) => Some((job.key(), run_job(shared, transport, job).await)),
            None => None,
        }
    };
    let (first, second) = tokio::join!(execute(selected.next()), execute(selected.next()));
    for (key, result) in [first, second].into_iter().flatten() {
        let mut scheduler = runtime.schedule.lock().unwrap();
        if let Err(error) = result {
            let failures = scheduler.retry.get(&key).map_or(1, |(n, _)| (n + 1).min(6));
            scheduler.retry.insert(
                key,
                (
                    failures,
                    Instant::now() + Duration::from_secs(1 << failures),
                ),
            );
            shared.lock().unwrap().status = format!("Media waiting; retrying: {error}");
        } else {
            scheduler.retry.remove(&key);
        }
    }
    Ok(())
}

async fn run_job(shared: &Shared, transport: &Transport, job: Job) -> Result<()> {
    match job {
        Job::Upload(upload) => {
            let (chunk, ticket) = {
                let app = shared.lock().unwrap();
                let chunk = app
                    .store
                    .get_local_media(
                        &upload.media_id,
                        upload.next_chunk,
                        &upload.read_token,
                        now(),
                    )?
                    .context("local media chunk unavailable")?;
                (chunk, upload_ticket(&app, &upload))
            };
            match transport
                .request(
                    &ticket,
                    Request::BlobPut {
                        mailbox_id: upload.mailbox.mailbox_id.clone(),
                        write_token: upload.mailbox.write_token.clone(),
                        read_token: upload.read_token.clone(),
                        chunk,
                    },
                )
                .await?
            {
                Response::Ok => {}
                Response::Error(error) => bail!("cache refused media: {error}"),
                _ => bail!("unexpected media upload response"),
            }
            let shared = shared.clone();
            tokio::task::spawn_blocking(move || {
                shared
                    .lock()
                    .map_err(|_| anyhow::anyhow!("profile state lock failed"))?
                    .atomic(|app| {
                        if let Some(current) = app.state.media_uploads.iter_mut().find(|j| {
                            j.media_id == upload.media_id
                                && j.mailbox.mailbox_id == upload.mailbox.mailbox_id
                                && ticket_endpoint_id(&j.mailbox.node_ticket).ok()
                                    == ticket_endpoint_id(&upload.mailbox.node_ticket).ok()
                                && j.next_chunk == upload.next_chunk
                        }) {
                            current.next_chunk += 1;
                        }
                        app.state
                            .media_uploads
                            .retain(|j| j.next_chunk < j.chunks && j.expires_at > now());
                        Ok(())
                    })
            })
            .await
            .context("media upload persistence worker stopped")??;
        }
        Job::Download(download, descriptor, sources) => {
            descriptor.validate(now())?;
            let existing = shared.lock().unwrap().store.get_local_media(
                &descriptor.id,
                download.next_chunk,
                &descriptor.read_token,
                now(),
            )?;
            let chunk = if let Some(chunk) = existing {
                chunk
            } else {
                ensure!(!sources.is_empty(), "no source is available for this file");
                let source = {
                    let app = shared.lock().unwrap();
                    super::ticker::current_node_ticket(
                        &app.state,
                        &sources[download.source_cursor % sources.len()],
                    )
                    .to_owned()
                };
                let request = if shared
                    .lock()
                    .unwrap()
                    .state
                    .conversations
                    .get(&download.conversation)
                    .is_some_and(|group| group.server.is_some())
                {
                    Request::Server(crate::server_protocol::ServerRequest::GroupBlobGet {
                        group_id: download.conversation.clone(),
                        media_id: descriptor.id.clone(),
                        index: download.next_chunk,
                        read_token: descriptor.read_token.clone(),
                    })
                } else {
                    Request::BlobGet {
                        media_id: descriptor.id.clone(),
                        index: download.next_chunk,
                        read_token: descriptor.read_token.clone(),
                    }
                };
                let response = transport.request(&source, request).await;
                let result = (|| -> Result<media::MediaChunk> {
                    let chunk = match response? {
                        Response::Blob(Some(chunk)) => chunk,
                        _ => bail!("source does not currently have this chunk"),
                    };
                    ensure!(
                        chunk.index == download.next_chunk,
                        "wrong media chunk index"
                    );
                    drop(media::decrypt_chunk(&descriptor, &chunk, now())?);
                    Ok(chunk)
                })();
                if result.is_err() {
                    // Rotate on failure (including invalid AEAD); retain a working source.
                    shared.lock().unwrap().atomic(|app| {
                        if let Some(job) = app.state.media_downloads.iter_mut().find(|j| {
                            j.message_id == download.message_id
                                && j.conversation == download.conversation
                        }) {
                            job.source_cursor = (job.source_cursor + 1) % sources.len();
                        }
                        Ok(())
                    })?;
                }
                result?
            };
            ensure!(
                chunk.index == download.next_chunk,
                "wrong media chunk index"
            );
            drop(media::decrypt_chunk(&descriptor, &chunk, now())?);
            let shared = shared.clone();
            tokio::task::spawn_blocking(move || {
                let mut app = shared
                    .lock()
                    .map_err(|_| anyhow::anyhow!("profile state lock failed"))?;
                finish_download_chunk(&mut app, &download, &descriptor, chunk)
            })
            .await
            .context("media download persistence worker stopped")??;
        }
    }
    Ok(())
}

/// Runs on a blocking worker. A valid cached chunk survives a progress-save failure
/// and is authenticated again before a retry advances the durable cursor.
fn finish_download_chunk(
    app: &mut App,
    download: &MediaDownload,
    descriptor: &MediaDescriptor,
    chunk: media::MediaChunk,
) -> Result<()> {
    // Another job for this file may have rejected its descriptor while this RPC
    // was in flight. Do not recreate the rejected ciphertext after that cleanup.
    if !app.state.media_downloads.iter().any(|job| {
        job.message_id == download.message_id
            && job.conversation == download.conversation
            && job.next_chunk == download.next_chunk
    }) {
        return Ok(());
    }
    descriptor.validate(now())?;
    ensure!(
        chunk.index == download.next_chunk,
        "wrong media chunk index"
    );
    drop(media::decrypt_chunk(descriptor, &chunk, now())?);
    app.store
        .store_local_media(&[chunk], &descriptor.read_token, now())?;
    if download.next_chunk + 1 == descriptor.chunks {
        let message = app.media_message(&download.message_id, Some(&download.conversation))?;
        message.validate(now())?;
        ensure!(
            message.attachment.as_ref() == Some(descriptor),
            "media descriptor changed during download"
        );
        // Storage errors and missing chunks remain retryable; only a complete
        // authenticated file that fails final validation is permanently rejected.
        let mut chunks = Vec::with_capacity(descriptor.chunks as usize);
        for index in 0..descriptor.chunks {
            chunks.push(
                app.store
                    .get_local_media(&descriptor.id, index, &descriptor.read_token, now())?
                    .context("media incomplete after download")?,
            );
        }
        if media::decrypt_complete(descriptor, &chunks, now()).is_err() {
            reject_descriptor(app, descriptor)?;
            app.status = "Attachment rejected: integrity check failed".into();
            return Ok(());
        }
        app.atomic(|app| {
            app.state.media_downloads.retain(|job| {
                job.message_id != download.message_id || job.conversation != download.conversation
            });
            Ok(())
        })?;
        app.status = format!(
            "{} downloaded; /open {}",
            descriptor.name,
            &download.message_id[..8.min(download.message_id.len())]
        );
    } else {
        app.atomic(|app| {
            if let Some(job) = app.state.media_downloads.iter_mut().find(|job| {
                job.message_id == download.message_id
                    && job.conversation == download.conversation
                    && job.next_chunk == download.next_chunk
            }) {
                job.next_chunk += 1;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn reject_descriptor(app: &mut App, descriptor: &MediaDescriptor) -> Result<()> {
    // An authenticated sender can copy another message's media ID and change its
    // digest or filename. Reject only references to this exact descriptor: another
    // descriptor may still authenticate the shared ciphertext successfully.
    let rejected: BTreeSet<_> = app
        .state
        .messages
        .iter()
        .filter(|message| message.attachment.as_ref() == Some(descriptor))
        .map(|message| (message.conversation.clone(), message.id.clone()))
        .collect();
    let shared_file = app.state.messages.iter().any(|message| {
        message.expires_at > now()
            && message
                .attachment
                .as_ref()
                .is_some_and(|other| other.id == descriptor.id && other != descriptor)
    }) || app
        .state
        .media_uploads
        .iter()
        .any(|upload| upload.media_id == descriptor.id && upload.expires_at > now())
        || app
            .state
            .hosted
            .media_uploads
            .iter()
            .any(|upload| upload.media_id == descriptor.id && upload.expires_at > now());
    if !shared_file {
        // Chunk deletion and profile saves use separate transactions. Persist a
        // restartable cursor before deletion so a crash or failed final save can
        // retry an exclusively referenced rejected file from chunk zero.
        app.atomic(|app| {
            for job in &mut app.state.media_downloads {
                if rejected.contains(&(job.conversation.clone(), job.message_id.clone())) {
                    job.next_chunk = 0;
                }
            }
            Ok(())
        })?;
        app.store.delete_local_media(&descriptor.id)?;
    }
    app.atomic(|app| {
        app.state
            .media_downloads
            .retain(|job| !rejected.contains(&(job.conversation.clone(), job.message_id.clone())));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_complete_file(
        format_mismatch: bool,
    ) -> Result<(tempfile::TempDir, App, PreparedMedia, Vec<MediaDownload>)> {
        let directory = tempfile::tempdir()?;
        let store = Store::create(
            &directory.path().join("profile.db"),
            "media rejection test password",
        )?;
        let mut app = App::initialize(store, "Authenticated sender".into())?;
        let group =
            app.atomic(|app| app.create_conversation("Invalid attachment".into(), vec![]))?;
        let mut bytes = vec![0xa5; media::CHUNK_SIZE + 7];
        bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        bytes[8..12].copy_from_slice(&13u32.to_be_bytes());
        bytes[12..16].copy_from_slice(b"IHDR");
        bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        let path = directory.path().join("image.png");
        std::fs::write(&path, &bytes)?;
        let mut prepared = media::prepare_file(&path, &[], now())?;
        if format_mismatch {
            // Filename is authenticated in MLS, but the sender can still lie.
            prepared.descriptor.name = "mislabelled.jpg".into();
        } else {
            prepared.descriptor.sha256 = "0".repeat(64);
        }
        // The whole-file metadata is bad while every chunk retains valid AEAD.
        for chunk in &prepared.chunks {
            assert!(media::decrypt_chunk(&prepared.descriptor, chunk, now()).is_ok());
        }
        for _ in 0..2 {
            let message_id = app.atomic(|app| {
                app.send_content(
                    &group,
                    String::new(),
                    Some(prepared.descriptor.clone()),
                    prepared.descriptor.created_at,
                )
            })?;
            app.request_media(&message_id, Some(&group))?;
            let message = app.media_message(&message_id, Some(&group))?;
            verify_message(&SignedMessage {
                signature: app.state.message_signatures[&format!("{group}/{message_id}")].clone(),
                message,
            })?;
        }
        app.store.store_local_media(
            &prepared.chunks[..1],
            &prepared.descriptor.read_token,
            now(),
        )?;
        app.atomic(|app| {
            for job in &mut app.state.media_downloads {
                job.next_chunk = 1;
            }
            Ok(())
        })?;
        let jobs = app.state.media_downloads.clone();
        Ok((directory, app, prepared, jobs))
    }

    #[test]
    fn authenticated_bad_digest_or_format_is_rejected_without_endless_retry() -> Result<()> {
        for format_mismatch in [false, true] {
            let (_directory, mut app, prepared, jobs) = invalid_complete_file(format_mismatch)?;
            finish_download_chunk(
                &mut app,
                &jobs[0],
                &prepared.descriptor,
                prepared.chunks[1].clone(),
            )?;
            assert!(app.state.media_downloads.is_empty());
            assert_eq!(app.store.media_progress(&prepared.descriptor.id, now())?, 0);
            assert_eq!(app.status, "Attachment rejected: integrity check failed");
            assert_eq!(
                app.state.messages.len(),
                2,
                "rejection must retain chat metadata"
            );
            let durable = app.store.load_state()?.context("profile missing")?;
            assert!(durable.media_downloads.is_empty());
            assert_eq!(durable.messages.len(), 2);
            // A second already-selected RPC must not resurrect the deleted data.
            finish_download_chunk(
                &mut app,
                &jobs[1],
                &prepared.descriptor,
                prepared.chunks[1].clone(),
            )?;
            assert_eq!(app.store.media_progress(&prepared.descriptor.id, now())?, 0);
            // A later explicit /open can retry, starting at chunk zero.
            app.request_media(&jobs[0].message_id, Some(&jobs[0].conversation))?;
            assert_eq!(app.state.media_downloads.len(), 1);
            assert_eq!(app.state.media_downloads[0].next_chunk, 0);
        }
        Ok(())
    }

    #[test]
    fn rejected_attachment_remains_retryable_if_state_persistence_fails() -> Result<()> {
        let (_directory, mut app, prepared, jobs) = invalid_complete_file(false)?;
        app.state.pending.push(Pending {
            recipient: app.id().to_owned(),
            request: Request::Update {
                conversation: jobs[0].conversation.clone(),
                proposal: vec![255; 9 * 1024 * 1024],
            },
        });
        assert!(
            finish_download_chunk(
                &mut app,
                &jobs[0],
                &prepared.descriptor,
                prepared.chunks[1].clone()
            )
            .is_err()
        );
        assert_eq!(app.state.media_downloads.len(), 2);
        assert!(
            app.state
                .media_downloads
                .iter()
                .all(|job| job.next_chunk == 1)
        );
        assert_eq!(app.store.media_progress(&prepared.descriptor.id, now())?, 2);
        let durable = app.store.load_state()?.context("profile missing")?;
        assert_eq!(durable.media_downloads.len(), 2);
        assert!(
            durable
                .media_downloads
                .iter()
                .all(|job| job.next_chunk == 1)
        );
        assert!(!app.status.starts_with("Attachment rejected"));
        app.state.pending.pop();
        finish_download_chunk(
            &mut app,
            &jobs[0],
            &prepared.descriptor,
            prepared.chunks[1].clone(),
        )?;
        assert!(app.state.media_downloads.is_empty());
        assert_eq!(app.store.media_progress(&prepared.descriptor.id, now())?, 0);
        assert_eq!(app.status, "Attachment rejected: integrity check failed");
        Ok(())
    }

    #[test]
    fn rejected_descriptor_preserves_a_pending_hosted_upload() -> Result<()> {
        let (_directory, mut app, prepared, jobs) = invalid_complete_file(false)?;
        app.state
            .hosted
            .media_uploads
            .push(super::super::group_delivery::HostedMediaUpload {
                conversation: jobs[0].conversation.clone(),
                media_id: prepared.descriptor.id.clone(),
                read_token: prepared.descriptor.read_token.clone(),
                next_chunk: 0,
                chunks: prepared.descriptor.chunks,
                expires_at: prepared.descriptor.expires_at,
            });
        finish_download_chunk(
            &mut app,
            &jobs[0],
            &prepared.descriptor,
            prepared.chunks[1].clone(),
        )?;
        assert!(app.state.media_downloads.is_empty());
        assert_eq!(app.store.media_progress(&prepared.descriptor.id, now())?, 2);
        assert_eq!(app.state.hosted.media_uploads.len(), 1);
        Ok(())
    }

    #[test]
    fn rejected_descriptor_preserves_other_descriptors_cache_and_download() -> Result<()> {
        for format_mismatch in [false, true] {
            for good_finishes_first in [false, true] {
                let (directory, mut app, rejected, bad_jobs) =
                    invalid_complete_file(format_mismatch)?;
                let mut valid = rejected.descriptor.clone();
                if format_mismatch {
                    valid.name = "image.png".into();
                } else {
                    use sha2::Digest;
                    valid.sha256 = hex::encode(sha2::Sha256::digest(std::fs::read(
                        directory.path().join("image.png"),
                    )?));
                }
                let group = &bad_jobs[0].conversation;
                let good_id = app.atomic(|app| {
                    app.send_content(group, String::new(), Some(valid.clone()), valid.created_at)
                })?;
                let good_message = app.request_media(&good_id, Some(group))?;
                app.atomic(|app| {
                    app.state.media_downloads.last_mut().unwrap().next_chunk = 1;
                    Ok(())
                })?;
                let good_job = app.state.media_downloads.last().unwrap().clone();
                if good_finishes_first {
                    finish_download_chunk(&mut app, &good_job, &valid, rejected.chunks[1].clone())?;
                }
                finish_download_chunk(
                    &mut app,
                    &bad_jobs[0],
                    &rejected.descriptor,
                    rejected.chunks[1].clone(),
                )?;
                assert_eq!(app.store.media_progress(&valid.id, now())?, 2);
                assert!(app.media_bytes(&good_message)?.is_some());
                assert_eq!(
                    app.state.media_downloads.len(),
                    usize::from(!good_finishes_first)
                );
                if !good_finishes_first {
                    assert_eq!(app.state.media_downloads[0].message_id, good_id);
                    assert_eq!(app.state.media_downloads[0].next_chunk, 1);
                    finish_download_chunk(&mut app, &good_job, &valid, rejected.chunks[1].clone())?;
                }
                // Already selected duplicate rejection cannot remove the good file.
                finish_download_chunk(
                    &mut app,
                    &bad_jobs[1],
                    &rejected.descriptor,
                    rejected.chunks[1].clone(),
                )?;
                assert!(app.state.media_downloads.is_empty());
                assert!(
                    app.request_media(&bad_jobs[0].message_id, Some(group))
                        .is_err()
                );
                assert!(app.request_media(&good_id, Some(group)).is_ok());
                drop(app);
                let mut app = App::load(Store::open(
                    &directory.path().join("profile.db"),
                    "media rejection test password",
                )?)?;
                assert!(app.state.media_downloads.is_empty());
                assert!(app.media_bytes(&good_message)?.is_some());
                assert!(
                    app.request_media(&bad_jobs[0].message_id, Some(group))
                        .is_err()
                );
            }
        }
        Ok(())
    }
}
