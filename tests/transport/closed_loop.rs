//! Exercises the real transport, SQLCipher profile, MLS and background queues.
//! Included as a transport unit-test module to keep local-only builders private.

use super::*;
use crate::{
    app::{App, Shared, acquire_key_package, connect_contact, network_tick},
    model::{LocalMailbox, MESSAGE_TTL, Mailbox, now},
    storage::Store,
};
use std::{
    path::{Path, PathBuf},
    sync::Mutex as StdMutex,
};

const PASSWORD: &str = "network integration test passphrase";

struct Node {
    app: Shared,
    transport: Transport,
    worker: JoinHandle<()>,
    path: PathBuf,
}

impl Node {
    async fn create(directory: &Path, name: &str) -> Result<Self> {
        let path = directory.join(format!("{name}.db"));
        let app = App::initialize(Store::create(&path, PASSWORD)?, name.to_owned())?;
        Self::start(app, path).await
    }

    async fn reopen(path: PathBuf) -> Result<Self> {
        Self::start(App::load(Store::open(&path, PASSWORD)?)?, path).await
    }

    async fn start(mut app: App, path: PathBuf) -> Result<Self> {
        let secret = app.state.transport_secret.as_slice().try_into()?;
        let limits = TransportLimits {
            request_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let mut transport = Transport::from_builder(
            base_builder(secret)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")?,
            false,
            limits,
        )
        .await?;
        app.ticket = tests::local_ticket(&transport).await?;
        app.state.contact_version += 1;
        app.save()?;
        let app = Arc::new(StdMutex::new(app));
        let serving = app.clone();
        let mut incoming = transport
            .take_incoming()
            .context("missing incoming channel")?;
        let worker = tokio::spawn(async move {
            while let Some(incoming) = incoming.recv().await {
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
            path,
        })
    }

    async fn stop(self) -> Result<PathBuf> {
        let Self {
            app,
            transport,
            worker,
            path,
        } = self;
        transport.close().await;
        worker.abort();
        let _ = worker.await;
        // The production profile lock must be released before reopening it.
        ensure!(
            Arc::strong_count(&app) == 1,
            "test server retained a profile reference"
        );
        drop(app);
        drop(transport);
        Ok(path)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_deliver_cached_ciphertext_after_profile_restart() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        let directory = tempfile::tempdir()?;
        let alice = Node::create(directory.path(), "Alice").await?;
        let bob = Node::create(directory.path(), "Bob").await?;
        let cache = Node::create(directory.path(), "Cache").await?;
        let alice_id = alice.app.lock().unwrap().id().to_owned();
        let bob_invitation = bob.app.lock().unwrap().invitation()?;
        let bob_id = bob_invitation.contact.id.clone();
        alice.app.lock().unwrap().atomic(|app| app.import_contact(bob_invitation))?;
        connect_contact(&alice.app, &alice.transport, &bob_id).await?;
        assert!(bob.app.lock().unwrap().state.contacts.contains_key(&alice_id));

        // Allocation and the signed publication of its write capability both use
        // the real wire protocol. The cache is not a member of the MLS group.
        let cache_ticket = cache.transport.ticket()?;
        let mailbox = match bob.transport.request(&cache_ticket, Request::Allocate).await? {
            Response::Mailbox { mailbox_id, write_token, read_token } => LocalMailbox {
                public: Mailbox { node_ticket: cache_ticket.clone(), mailbox_id, write_token },
                read_token, retired_at: None,
            },
            other => bail!("allocation failed: {other:?}"),
        };
        bob.app.lock().unwrap().atomic(|app| {
            app.state.mailboxes.push(mailbox.clone());
            app.state.contact_version += 1;
            Ok(())
        })?;
        connect_contact(&bob.app, &bob.transport, &alice_id).await?;
        acquire_key_package(&alice.app, &alice.transport, &bob_id).await?;
        let group = alice.app.lock().unwrap().atomic(|app| {
            let group = app.create_direct("network pair".into(), bob_id.clone())?;
            app.state.last_rekey.insert(group.clone(), now());
            Ok(group)
        })?;
        network_tick(&alice.app, &alice.transport, false).await?;
        assert!(bob.app.lock().unwrap().state.conversations[&group].active);
        assert!(cache.app.lock().unwrap().state.conversations.is_empty());

        let online_id = alice.app.lock().unwrap().atomic(|app| app.send(&group, "online over QUIC".into()))?;
        network_tick(&alice.app, &alice.transport, false).await?;
        assert!(bob.app.lock().unwrap().state.messages.iter().any(|message| message.id == online_id));

        // Close the receiver's endpoint and encrypted database, so neither a
        // live connection nor retained in-memory MLS state can deliver this one.
        let bob_path = bob.stop().await?;
        let message_id = alice.app.lock().unwrap().atomic(|app| app.send(&group, "cached while offline".into()))?;
        let original = alice.app.lock().unwrap().state.messages.iter()
            .find(|message| message.id == message_id).context("missing sent message")?.clone();
        network_tick(&alice.app, &alice.transport, false).await?; // Failed direct path.
        network_tick(&alice.app, &alice.transport, false).await?; // Backoff permits store fallback.
        assert!(!alice.app.lock().unwrap().state.outbox.iter()
            .find(|item| item.envelope.id == message_id).context("missing queued delivery")?.stored_at.is_empty());

        let bob = Node::reopen(bob_path).await?;
        let fetch = || Request::Fetch { mailbox_id: mailbox.public.mailbox_id.clone(), read_token: mailbox.read_token.clone() };
        let cached = match bob.transport.request(&cache_ticket, fetch()).await? {
            Response::Envelopes(envelopes) => envelopes,
            other => bail!("fetch failed: {other:?}"),
        };
        assert_eq!(cached.len(), 1);
        assert_eq!((cached[0].created_at, cached[0].expires_at), (original.created_at, original.expires_at));
        assert!(bob.app.lock().unwrap().state.messages.iter().all(|message| message.id != message_id));

        network_tick(&bob.app, &bob.transport, false).await?; // Fetch, decrypt, persist.
        {
            let app = bob.app.lock().unwrap();
            let received = app.state.messages.iter().find(|message| message.id == message_id)
                .context("ticker did not decrypt cached message")?;
            assert_eq!(received, &original);
            assert_eq!(received.expires_at - received.created_at, MESSAGE_TTL);
            assert!(app.state.deferred.is_empty());
            let saved = app.store.load_state()?.context("missing persisted receiver state")?;
            assert!(saved.messages.iter().any(|message| message == &original));
        }
        network_tick(&bob.app, &bob.transport, false).await?; // Delete ACK after persistence.
        assert!(matches!(bob.transport.request(&cache_ticket, fetch()).await?, Response::Envelopes(envelopes) if envelopes.is_empty()));
        assert!(cache.app.lock().unwrap().state.messages.is_empty(), "the cache must not decrypt chat content");

        alice.stop().await?;
        bob.stop().await?;
        cache.stop().await?;
        Ok(())
    }).await.context("three-node network flow exceeded its deadline")?
}
