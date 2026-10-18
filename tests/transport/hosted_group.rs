//! Real local QUIC delivery with no owner or recipient online at the same time.

use super::*;
use crate::{
    app::{App, Shared, acquire_key_package, connect_contact, group_delivery_tick, media_tick},
    media,
    model::{MESSAGE_TTL, now},
    server::Server,
    server_protocol::{ServerInvitation, ServerRequest, ServerResponse},
    storage::Store,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex as StateMutex,
};

const PASSWORD: &str = "hosted group network regression passphrase";

async fn local_transport(secret: [u8; 32], address: SocketAddr) -> Result<Transport> {
    Transport::from_builder(
        base_builder(secret)
            .clear_ip_transports()
            .bind_addr(address)?,
        false,
        TransportLimits {
            request_timeout: Duration::from_secs(2),
            ..Default::default()
        },
    )
    .await
}

struct Client {
    app: Shared,
    transport: Transport,
    worker: JoinHandle<()>,
    path: PathBuf,
}

impl Client {
    async fn create(directory: &Path, name: &str) -> Result<Self> {
        let path = directory.join(format!("{name}.db"));
        let app = App::initialize(Store::create(&path, PASSWORD)?, name.into())?;
        Self::start(app, path).await
    }

    async fn reopen(path: PathBuf) -> Result<Self> {
        Self::start(App::load(Store::open(&path, PASSWORD)?)?, path).await
    }

    async fn start(mut app: App, path: PathBuf) -> Result<Self> {
        let mut transport = local_transport(
            app.state.transport_secret.as_slice().try_into()?,
            "127.0.0.1:0".parse()?,
        )
        .await?;
        app.ticket = tests::local_ticket(&transport).await?;
        app.state.contact_version += 1;
        app.save()?;
        let app = Arc::new(StateMutex::new(app));
        let serving = app.clone();
        let mut incoming = transport
            .take_incoming()
            .context("missing client receiver")?;
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
        self.transport.close().await;
        self.worker.abort();
        let _ = self.worker.await;
        ensure!(
            Arc::strong_count(&self.app) == 1,
            "client retained profile reference"
        );
        drop(self.app);
        Ok(self.path)
    }
}

struct GroupServer {
    server: Arc<StateMutex<Server>>,
    transport: Transport,
    worker: JoinHandle<()>,
    invitation: ServerInvitation,
    path: PathBuf,
}

impl GroupServer {
    async fn create(directory: &Path) -> Result<Self> {
        let path = directory.join("group-server.db");
        let server = Server::initialize(Store::create(&path, PASSWORD)?)?;
        Self::start(server, path, "127.0.0.1:0".parse()?).await
    }

    async fn reopen(path: PathBuf, address: SocketAddr) -> Result<Self> {
        Self::start(Server::load(Store::open(&path, PASSWORD)?)?, path, address).await
    }

    async fn start(server: Server, path: PathBuf, address: SocketAddr) -> Result<Self> {
        let mut transport = local_transport(server.transport_secret()?, address).await?;
        let invitation = server.invitation(&tests::local_ticket(&transport).await?)?;
        let server = Arc::new(StateMutex::new(server));
        let serving = server.clone();
        let mut incoming = transport
            .take_incoming()
            .context("missing server receiver")?;
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
            server,
            transport,
            worker,
            invitation,
            path,
        })
    }

    async fn stop(self) -> Result<(PathBuf, SocketAddr)> {
        let address = decode_ticket(&self.invitation.ticket)?
            .ip_addrs()
            .next()
            .copied()
            .context("server has no local socket")?;
        self.transport.close().await;
        self.worker.abort();
        let _ = self.worker.await;
        ensure!(
            Arc::strong_count(&self.server) == 1,
            "server retained profile reference"
        );
        drop(self.server);
        Ok((self.path, address))
    }
}

async fn connect(owner: &Client, member: &Client) -> Result<String> {
    let invitation = member.app.lock().unwrap().invitation()?;
    let id = invitation.contact.id.clone();
    owner
        .app
        .lock()
        .unwrap()
        .atomic(|app| app.import_contact(invitation))?;
    connect_contact(&owner.app, &owner.transport, &id).await?;
    acquire_key_package(&owner.app, &owner.transport, &id).await?;
    Ok(id)
}

async fn flush_owner(owner: &Client, group: &str) -> Result<()> {
    for _ in 0..80 {
        group_delivery_tick(&owner.app, &owner.transport).await?;
        let app = owner.app.lock().unwrap();
        if app
            .state
            .outbox
            .iter()
            .all(|item| item.envelope.conversation != group)
            && app.state.hosted.control_outbox.is_empty()
            && app.state.hosted.inbox_outbox.is_empty()
            && app.state.hosted.media_uploads.is_empty()
        {
            return Ok(());
        }
    }
    bail!(
        "hosted owner queues did not drain: {}",
        owner.app.lock().unwrap().status
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_delivers_first_join_messages_and_media_after_owner_exit_and_enforces_removal()
-> Result<()> {
    timeout(Duration::from_secs(150), async {
        let directory = tempfile::tempdir()?;
        let alice = Client::create(directory.path(), "Alice").await?;
        let bob = Client::create(directory.path(), "Bob").await?;
        let carol = Client::create(directory.path(), "Carol").await?;
        let server = GroupServer::create(directory.path()).await?;
        let bob_id = connect(&alice, &bob).await?;
        let carol_id = connect(&alice, &carol).await?;
        bob.app.lock().unwrap().atomic(|app| {
            app.state.group_servers.push(server.invitation.ticket.clone());
            Ok(())
        })?;
        let bob_path = bob.stop().await?;
        let group = alice.app.lock().unwrap().atomic(|app| {
            app.create_hosted_group("private hosted group".into(), vec![bob_id.clone()], server.invitation.clone())
        })?;
        let old_message = alice.app.lock().unwrap().atomic(|app| app.send(&group, "before Carol joined".into()))?;
        alice.app.lock().unwrap().atomic(|app| app.add_member(&group, &carol_id))?;
        let text_id = alice.app.lock().unwrap().atomic(|app| app.send(&group, "owner is offline when this arrives".into()))?;
        let file = directory.path().join("shared.png");
        let plaintext = hex::decode("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")?;
        std::fs::write(&file, &plaintext)?;
        let prepared = media::prepare_file(&file, std::slice::from_ref(&server.invitation.ticket), now())?;
        let attachment_id = alice.app.lock().unwrap().send_attachment(&group, prepared, "offline attachment".into())?;
        let originals = alice.app.lock().unwrap().state.messages.clone();
        assert_eq!(alice.app.lock().unwrap().state.outbox.len(), 3, "one encrypted copy per group message");
        flush_owner(&alice, &group).await?;
        let Response::Server(ServerResponse::GroupPage { envelopes, .. }) = carol.transport.request(
            &server.invitation.ticket, Request::Server(ServerRequest::GroupFetch { group_id: group.clone(), after: 0 })).await? else {
            bail!("new member could not fetch hosted messages");
        };
        assert_eq!(envelopes.len(), 2);
        assert!(envelopes.iter().all(|envelope| envelope.envelope.id != old_message),
            "new members must not fill their deferred queue with undecryptable pre-join ciphertext");
        let alice_path = alice.stop().await?;
        let (server_path, address) = server.stop().await?;
        let server = GroupServer::reopen(server_path, address).await?;
        let bob = Client::reopen(bob_path).await?;
        assert!(!bob.app.lock().unwrap().state.conversations.contains_key(&group));

        for _ in 0..60 {
            group_delivery_tick(&bob.app, &bob.transport).await?;
            if bob.app.lock().unwrap().state.messages.iter().any(|message| message.id == attachment_id) { break; }
        }
        let received_media = {
            let mut app = bob.app.lock().unwrap();
            for original in &originals {
                let received = app.state.messages.iter().find(|message| message.id == original.id)
                    .context("server did not deliver offline group content")?;
                assert_eq!(received, original);
                assert_eq!(received.expires_at - received.created_at, MESSAGE_TTL);
            }
            assert_eq!(app.state.conversations[&group].members.len(), 3);
            app.atomic(|app| app.request_media(&attachment_id, Some(&group)))?
        };
        for _ in 0..20 {
            media_tick(&bob.app, &bob.transport).await?;
            if bob.app.lock().unwrap().media_bytes(&received_media)?.is_some() { break; }
        }
        assert_eq!(bob.app.lock().unwrap().media_bytes(&received_media)?.context("missing downloaded media")?.as_slice(), plaintext.as_slice());
        for _ in 0..4 { group_delivery_tick(&bob.app, &bob.transport).await?; }
        assert!(matches!(bob.transport.request(&server.invitation.ticket, Request::Server(ServerRequest::InboxFetch)).await?,
            Response::Server(ServerResponse::Inbox { records }) if records.is_empty()));
        let cursor = bob.app.lock().unwrap().state.hosted.cursors[&group];
        let bob_path = bob.stop().await?;
        let bob = Client::reopen(bob_path).await?;
        assert_eq!(bob.app.lock().unwrap().state.hosted.cursors[&group], cursor);
        assert!(bob.app.lock().unwrap().state.messages.iter().any(|message| message.id == text_id));

        // The server receives one later manifest containing both an unseen
        // rekey and removal, followed by yet another epoch. Its removal boundary
        // must remain the actual removal Commit, even when configurations coalesce.
        let alice = Client::reopen(alice_path).await?;
        alice.app.lock().unwrap().maybe_rekey(now() + 25 * 60 * 60)?;
        alice.app.lock().unwrap().atomic(|app| app.remove_member(&group, &bob_id))?;
        let removed_epoch = alice.app.lock().unwrap().state.conversations[&group].epoch;
        alice.app.lock().unwrap().maybe_rekey(now() + 50 * 60 * 60)?;
        let secret_message = alice.app.lock().unwrap().atomic(|app| app.send(&group, "after Bob was removed".into()))?;
        flush_owner(&alice, &group).await?;
        alice.stop().await?;
        for _ in 0..40 {
            group_delivery_tick(&bob.app, &bob.transport).await?;
            if !bob.app.lock().unwrap().state.conversations[&group].active { break; }
        }
        {
            let app = bob.app.lock().unwrap();
            assert!(!app.state.conversations[&group].active, "removed client missed its final Commit: {}", app.status);
            assert_eq!(app.state.conversations[&group].epoch, removed_epoch);
            assert!(app.state.messages.iter().all(|message| message.id != secret_message));
        }
        assert!(matches!(bob.transport.request(&server.invitation.ticket, Request::Server(ServerRequest::GroupFetch {
            group_id: group.clone(), after: 0,
        })).await?, Response::Error(_)));
        let descriptor = received_media.attachment.unwrap();
        assert!(matches!(bob.transport.request(&server.invitation.ticket, Request::Server(ServerRequest::GroupBlobGet {
            group_id: group, media_id: descriptor.id, index: 0, read_token: descriptor.read_token,
        })).await?, Response::Error(_)));
        bob.stop().await?;
        carol.stop().await?;
        server.stop().await?;
        Ok(())
    }).await.context("hosted group network flow exceeded its deadline")?
}
