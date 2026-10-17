//! Real localhost Iroh + MLS attachment publication + bounded media scheduler.

use super::*;
use crate::{
    app::{App, Shared, connect_contact, media_tick, network_tick, send_media},
    media::CHUNK_SIZE,
    model::{LocalMailbox, Mailbox, now},
    storage::Store,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const PASSWORD: &str = "real media transport integration password";

#[derive(Default)]
struct Requests {
    puts: AtomicUsize,
    gets: AtomicUsize,
}

struct Node {
    app: Shared,
    transport: Transport,
    worker: JoinHandle<()>,
    requests: Arc<Requests>,
    path: PathBuf,
}

impl Node {
    async fn create(directory: &Path, name: &str) -> Result<Self> {
        let path = directory.join(format!("{name}.db"));
        let app = App::initialize(Store::create(&path, PASSWORD)?, name.into())?;
        Self::start(app, path).await
    }

    async fn reopen(path: PathBuf) -> Result<Self> {
        Self::start(App::load(Store::open(&path, PASSWORD)?)?, path).await
    }

    async fn start(mut app: App, path: PathBuf) -> Result<Self> {
        let secret = app.state.transport_secret.as_slice().try_into()?;
        let mut transport = Transport::from_builder(
            base_builder(secret)
                .relay_mode(RelayMode::Disabled)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")?,
            false,
            TransportLimits {
                request_timeout: Duration::from_secs(2),
                ..Default::default()
            },
        )
        .await?;
        app.ticket = tests::local_ticket(&transport).await?;
        app.state.contact_version += 1;
        app.save()?;
        let app = Arc::new(StdMutex::new(app));
        let requests = Arc::new(Requests::default());
        let serving = app.clone();
        let observed = requests.clone();
        let mut incoming = transport.take_incoming().context("no incoming channel")?;
        let worker = tokio::spawn(async move {
            while let Some(incoming) = incoming.recv().await {
                match &incoming.request {
                    Request::BlobPut { .. } => {
                        observed.puts.fetch_add(1, Ordering::Relaxed);
                    }
                    Request::BlobGet { .. } => {
                        observed.gets.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                let response = serving
                    .lock()
                    .unwrap()
                    .handle(&incoming.peer_id, incoming.request)
                    .unwrap_or_else(|error| Response::Error(error.to_string()));
                let _ = incoming.reply.send(response);
            }
        });
        Ok(Self {
            app,
            transport,
            worker,
            requests,
            path,
        })
    }

    async fn stop(self) -> Result<PathBuf> {
        let Self {
            app,
            transport,
            worker,
            path,
            ..
        } = self;
        transport.close().await;
        worker.abort();
        let _ = worker.await;
        ensure!(
            Arc::strong_count(&app) == 1,
            "server retained the encrypted profile"
        );
        drop(app);
        drop(transport);
        Ok(path)
    }
}

fn image_bytes() -> Vec<u8> {
    let mut bytes = vec![0xa3; CHUNK_SIZE + 71];
    bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    bytes[8..12].copy_from_slice(&13u32.to_be_bytes());
    bytes[12..16].copy_from_slice(b"IHDR");
    bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn media_scheduler_uploads_then_resumes_cached_download_with_sender_offline() -> Result<()> {
    timeout(Duration::from_secs(75), async {
        let directory = tempfile::tempdir()?;
        let alice = Node::create(directory.path(), "Alice").await?;
        let bob = Node::create(directory.path(), "Bob").await?;
        let cache = Node::create(directory.path(), "Cache").await?;
        let invitation = bob.app.lock().unwrap().invitation()?;
        let bob_id = invitation.contact.id.clone();
        alice
            .app
            .lock()
            .unwrap()
            .atomic(|app| app.import_contact(invitation))?;
        connect_contact(&alice.app, &alice.transport, &bob_id).await?;
        let cache_ticket = cache.transport.ticket()?;
        let mailbox = match alice
            .transport
            .request(&cache_ticket, Request::Allocate)
            .await?
        {
            Response::Mailbox {
                mailbox_id,
                write_token,
                read_token,
            } => LocalMailbox {
                public: Mailbox {
                    node_ticket: cache_ticket.clone(),
                    mailbox_id,
                    write_token,
                },
                read_token,
                retired_at: None,
            },
            other => bail!("allocation failed: {other:?}"),
        };
        alice.app.lock().unwrap().atomic(|app| {
            app.state.mailboxes.push(mailbox);
            Ok(())
        })?;
        let group = alice.app.lock().unwrap().atomic(|app| {
            let group = app.create_group("real media pair".into(), vec![bob_id])?;
            app.state.last_rekey.insert(group.clone(), now());
            Ok(group)
        })?;
        network_tick(&alice.app, &alice.transport, false).await?;
        assert!(bob.app.lock().unwrap().state.conversations[&group].active);

        let path = directory.path().join("private.png");
        let bytes = image_bytes();
        std::fs::write(&path, &bytes)?;
        let message_id =
            send_media(&alice.app, &group, path, "real scheduler attachment".into()).await?;
        let original = alice
            .app
            .lock()
            .unwrap()
            .state
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .context("sender has no descriptor")?
            .clone();
        let descriptor = original
            .attachment
            .as_ref()
            .context("attachment missing")?
            .clone();
        assert_eq!(descriptor.chunks, 2);
        assert!(descriptor.sources.contains(&cache_ticket));
        assert!(!alice.app.lock().unwrap().state.media_uploads.is_empty());

        // This calls the production scheduler, not manual BlobPut/store operations.
        loop {
            media_tick(&alice.app, &alice.transport).await?;
            if alice.app.lock().unwrap().state.media_uploads.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(cache.requests.puts.load(Ordering::Relaxed) >= descriptor.chunks as usize);
        for index in 0..descriptor.chunks {
            assert!(
                cache
                    .app
                    .lock()
                    .unwrap()
                    .store
                    .get_relay_media(&descriptor.id, index, &descriptor.read_token, now(),)?
                    .is_some()
            );
        }
        loop {
            network_tick(&alice.app, &alice.transport, false).await?;
            if bob
                .app
                .lock()
                .unwrap()
                .state
                .messages
                .iter()
                .any(|message| message.id == message_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(bob.app.lock().unwrap().media_bytes(&original)?.is_none());
        assert!(cache.app.lock().unwrap().state.conversations.is_empty());
        assert!(cache.app.lock().unwrap().state.messages.is_empty());
        alice.stop().await?;

        bob.app
            .lock()
            .unwrap()
            .request_media(&message_id, Some(&group))?;
        // The first source is now offline. A failed RPC must rotate to the cache.
        loop {
            media_tick(&bob.app, &bob.transport).await?;
            if bob
                .app
                .lock()
                .unwrap()
                .store
                .media_progress(&descriptor.id, now())?
                == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        {
            let app = bob.app.lock().unwrap();
            assert_eq!(app.state.media_downloads.len(), 1);
            assert_eq!(app.state.media_downloads[0].next_chunk, 1);
            assert!(app.media_bytes(&original)?.is_none());
        }
        let bob = Node::reopen(bob.stop().await?).await?;
        assert_eq!(
            bob.app.lock().unwrap().state.media_downloads[0].next_chunk,
            1
        );
        loop {
            media_tick(&bob.app, &bob.transport).await?;
            if bob.app.lock().unwrap().state.media_downloads.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        {
            let app = bob.app.lock().unwrap();
            let received = app
                .state
                .messages
                .iter()
                .find(|message| message.id == message_id)
                .context("receiver lost the media message")?;
            assert_eq!(received, &original);
            assert_eq!(
                &*app
                    .media_bytes(received)?
                    .context("media did not assemble")?,
                &bytes
            );
        }
        assert!(cache.requests.gets.load(Ordering::Relaxed) >= descriptor.chunks as usize);

        let denied = bob
            .transport
            .request(
                &cache_ticket,
                Request::BlobGet {
                    media_id: descriptor.id.clone(),
                    index: 0,
                    read_token: "0".repeat(64),
                },
            )
            .await?;
        assert!(matches!(denied, Response::Error(_)));
        cache
            .app
            .lock()
            .unwrap()
            .store
            .purge(descriptor.expires_at)?;
        let expired = bob
            .transport
            .request(
                &cache_ticket,
                Request::BlobGet {
                    media_id: descriptor.id.clone(),
                    index: 0,
                    read_token: descriptor.read_token.clone(),
                },
            )
            .await?;
        assert!(matches!(expired, Response::Blob(None)));

        bob.stop().await?;
        cache.stop().await?;
        Ok(())
    })
    .await
    .context("three-node media scheduler flow exceeded its deadline")?
}
