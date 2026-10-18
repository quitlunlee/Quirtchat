//! Dedicated personal-server delivery over real local QUIC, MLS and SQLCipher.

use super::*;
use crate::{
    app::{
        App, Shared, acquire_key_package, attach_personal_mailbox, connect_contact, network_tick,
    },
    model::{MESSAGE_TTL, now},
    server::Server,
    server_protocol::{MailboxBinding, ServerInvitation, ServerRequest, SignedMailboxBinding},
    storage::Store,
};
use std::{
    path::{Path, PathBuf},
    sync::Mutex as StateMutex,
};

const PASSWORD: &str = "personal mailbox network regression passphrase";

async fn local_transport(secret: [u8; 32]) -> Result<Transport> {
    Transport::from_builder(
        base_builder(secret)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")?,
        false,
        TransportLimits {
            request_timeout: Duration::from_secs(3),
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
        let mut transport =
            local_transport(app.state.transport_secret.as_slice().try_into()?).await?;
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
        let Self {
            app,
            transport,
            worker,
            path,
        } = self;
        transport.close().await;
        worker.abort();
        let _ = worker.await;
        ensure!(
            Arc::strong_count(&app) == 1,
            "client retained a profile reference"
        );
        drop(app);
        Ok(path)
    }
}

struct PersonalServer {
    server: Arc<StateMutex<Server>>,
    transport: Transport,
    worker: JoinHandle<()>,
    invitation: ServerInvitation,
    path: PathBuf,
}

impl PersonalServer {
    async fn create(directory: &Path) -> Result<Self> {
        let path = directory.join("personal-server.db");
        let server = Server::initialize(Store::create(&path, PASSWORD)?)?;
        let mut transport = local_transport(server.transport_secret()?).await?;
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

    async fn stop(self) -> Result<PathBuf> {
        let Self {
            server,
            transport,
            worker,
            path,
            ..
        } = self;
        transport.close().await;
        worker.abort();
        let _ = worker.await;
        ensure!(
            Arc::strong_count(&server) == 1,
            "server retained a profile reference"
        );
        drop(server);
        Ok(path)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personal_mailbox_binds_identity_and_delivers_after_sender_exit_and_receiver_restart()
-> Result<()> {
    timeout(Duration::from_secs(90), async {
        let directory = tempfile::tempdir()?;
        let alice = Client::create(directory.path(), "Alice").await?;
        let bob = Client::create(directory.path(), "Bob").await?;
        let server = PersonalServer::create(directory.path()).await?;
        attach_personal_mailbox(&bob.app, &bob.transport, server.invitation.clone()).await?;
        let mailbox = {
            let app = bob.app.lock().unwrap();
            let personal = app.state.personal_mailbox.as_ref().context("missing personal binding")?;
            assert_eq!(personal.node, server.transport.endpoint_id());
            assert_eq!(app.invitation()?.contact.mailboxes.len(), 1);
            app.state.mailboxes.iter().find(|mailbox| mailbox.public.mailbox_id == personal.mailbox_id)
                .context("missing personal mailbox")?.clone()
        };

        // A valid Bob signature cannot be repurposed to bind Alice's authenticated endpoint.
        let mut forged = {
            let app = bob.app.lock().unwrap();
            SignedMailboxBinding::sign(MailboxBinding {
                server_id: server.transport.endpoint_id(),
                identity: app.id().to_owned(),
                endpoint: bob.transport.endpoint_id(),
                revision: app.state.contact_version + 1,
            }, app.state.identity_secret.as_slice().try_into()?)?
        };
        forged.binding.endpoint = alice.transport.endpoint_id();
        assert!(matches!(alice.transport.request(&server.invitation.ticket, Request::Server(ServerRequest::BindMailbox {
            provisioning_token: server.invitation.provisioning_token.clone(),
            binding: forged,
        })).await?, Response::Error(_)));

        let bob_invitation = bob.app.lock().unwrap().invitation()?;
        let bob_id = bob_invitation.contact.id.clone();
        alice.app.lock().unwrap().atomic(|app| app.import_contact(bob_invitation))?;
        connect_contact(&alice.app, &alice.transport, &bob_id).await?;
        acquire_key_package(&alice.app, &alice.transport, &bob_id).await?;
        let group = alice.app.lock().unwrap().atomic(|app| {
            let group = app.create_direct("personal mailbox DM".into(), bob_id)?;
            app.state.last_rekey.insert(group.clone(), now());
            Ok(group)
        })?;
        network_tick(&alice.app, &alice.transport, false).await?;
        assert!(bob.app.lock().unwrap().state.conversations[&group].active);
        let bob_path = bob.stop().await?;
        let message_id = alice.app.lock().unwrap().atomic(|app| app.send(&group, "offline through my personal server".into()))?;
        let original = alice.app.lock().unwrap().state.messages.iter()
            .find(|message| message.id == message_id).context("missing sent message")?.clone();
        network_tick(&alice.app, &alice.transport, false).await?;
        network_tick(&alice.app, &alice.transport, false).await?;
        assert!(!alice.app.lock().unwrap().state.outbox.iter()
            .find(|outgoing| outgoing.envelope.id == message_id).context("missing queued ciphertext")?.stored_at.is_empty());

        // Even possession of the read capability is insufficient at the wrong endpoint.
        let fetch = || Request::Fetch {
            mailbox_id: mailbox.public.mailbox_id.clone(),
            read_token: mailbox.read_token.clone(),
        };
        assert!(matches!(alice.transport.request(&server.invitation.ticket, fetch()).await?, Response::Error(_)));
        assert!(matches!(alice.transport.request(&server.invitation.ticket, Request::Delete {
            mailbox_id: mailbox.public.mailbox_id.clone(),
            read_token: mailbox.read_token.clone(),
            ids: vec![message_id.clone()],
        }).await?, Response::Error(_)));
        alice.stop().await?;

        // The sender is now gone. Expiry minus one second must preserve the server copy.
        server.server.lock().unwrap().purge(original.expires_at - 1)?;
        let bob = Client::reopen(bob_path).await?;
        let cached = bob.transport.request(&server.invitation.ticket, fetch()).await?;
        assert!(matches!(cached, Response::Envelopes(envelopes) if envelopes.len() == 1 && envelopes[0].id == message_id));
        network_tick(&bob.app, &bob.transport, false).await?;
        {
            let app = bob.app.lock().unwrap();
            assert!(app.state.messages.contains(&original));
            assert_eq!(original.expires_at - original.created_at, MESSAGE_TTL);
            assert!(app.store.load_state()?.context("missing persisted receiver")?.messages.contains(&original));
        }
        // The first tick persists the message; its Delete ACK has not run yet.
        assert!(matches!(bob.transport.request(&server.invitation.ticket, fetch()).await?, Response::Envelopes(envelopes) if envelopes.len() == 1));
        server.server.lock().unwrap().purge(original.expires_at)?;
        assert!(matches!(bob.transport.request(&server.invitation.ticket, fetch()).await?, Response::Envelopes(envelopes) if envelopes.is_empty()));
        bob.app.lock().unwrap().atomic(|app| {
            app.state.purge_expired(original.expires_at);
            Ok(())
        })?;
        assert!(bob.app.lock().unwrap().state.messages.is_empty());
        bob.stop().await?;
        let server_path = server.stop().await?;
        let store = Store::open(&server_path, PASSWORD)?;
        assert!(store.load_state()?.is_none(), "a personal server must not contain a user AppState or MLS private state");
        Ok(())
    }).await.context("personal mailbox delivery exceeded its deadline")?
}
