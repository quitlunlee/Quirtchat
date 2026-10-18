//! MLS attachment metadata plus ciphertext-cache delivery through production handlers.
//! The transfer loop is in-process; these tests do not claim real network coverage.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, ensure};
use clichat::{
    app::App,
    media::{CHUNK_SIZE, MediaChunk, PreparedMedia, decrypt_chunk, prepare_file},
    model::{LocalMailbox, MESSAGE_TTL, Mailbox, Pending, Request, Response, now},
    storage::Store,
    transport::{encode_ticket, ticket_endpoint_id},
};
use iroh::{EndpointAddr, SecretKey};
use tempfile::TempDir;

const PASSWORD: &str = "media flow integration profile password";

struct Profile {
    // Drop the SQLite connection before deleting its directory on Windows.
    app: App,
    directory: TempDir,
    peer: String,
    port: u16,
}

impl Profile {
    fn new(name: &str, port: u16) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let store = Store::create(&directory.path().join("profile.db"), PASSWORD)?;
        let mut profile = Self {
            app: App::initialize(store, name.into())?,
            directory,
            peer: String::new(),
            port,
        };
        profile.set_ticket()?;
        Ok(profile)
    }

    fn set_ticket(&mut self) -> Result<()> {
        let seed: [u8; 32] = self.app.state.transport_secret.as_slice().try_into()?;
        let endpoint = SecretKey::from_bytes(&seed).public();
        self.peer = endpoint.to_string();
        self.app.ticket = encode_ticket(
            &EndpointAddr::new(endpoint)
                .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))),
        )?;
        Ok(())
    }

    fn restart(self) -> Result<Self> {
        let Self {
            app,
            directory,
            port,
            ..
        } = self;
        drop(app);
        let mut profile = Self {
            app: App::load(Store::open(&directory.path().join("profile.db"), PASSWORD)?)?,
            directory,
            peer: String::new(),
            port,
        };
        profile.set_ticket()?;
        Ok(profile)
    }
}

fn expect_ok(response: Response) -> Result<()> {
    ensure!(
        matches!(response, Response::Ok),
        "expected successful acknowledgement"
    );
    Ok(())
}

fn connect_pair(alice: &mut Profile, bob: &mut Profile) -> Result<String> {
    let alice_invitation = alice.app.invitation()?;
    let bob_invitation = bob.app.invitation()?;
    alice.app.atomic(|app| app.import_contact(bob_invitation))?;
    bob.app.atomic(|app| app.import_contact(alice_invitation))?;
    let bob_id = bob.app.id().to_string();
    let group = alice
        .app
        .atomic(|app| app.create_direct("Attachments".into(), bob_id.clone()))?;
    let joins: Vec<_> = alice
        .app
        .state
        .pending
        .iter()
        .filter(|pending| {
            pending.recipient == bob_id && matches!(&pending.request, Request::Join { .. })
        })
        .map(|pending| pending.request.clone())
        .collect();
    ensure!(joins.len() == 1, "expected the initial Welcome");
    expect_ok(bob.app.handle(&alice.peer, joins[0].clone())?)?;
    alice.app.atomic(|app| {
        app.state
            .pending
            .retain(|pending| pending.recipient != bob_id);
        Ok(())
    })?;
    Ok(group)
}

fn allocate_cache(owner: &mut Profile, cache: &mut Profile) -> Result<Mailbox> {
    let Response::Mailbox {
        mailbox_id,
        write_token,
        read_token,
    } = cache.app.handle(&owner.peer, Request::Allocate)?
    else {
        anyhow::bail!("expected a cache mailbox");
    };
    let mailbox = Mailbox {
        node_ticket: cache.app.ticket.clone(),
        mailbox_id,
        write_token,
    };
    owner.app.atomic(|app| {
        app.state.mailboxes.push(LocalMailbox {
            public: mailbox.clone(),
            read_token,
            retired_at: None,
        });
        Ok(())
    })?;
    Ok(mailbox)
}

fn png_bytes(size: usize) -> Vec<u8> {
    assert!(size >= 33);
    let mut bytes = vec![0x5a; size];
    bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    bytes[8..12].copy_from_slice(&13u32.to_be_bytes());
    bytes[12..16].copy_from_slice(b"IHDR");
    bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
    bytes
}

fn prepare(
    profile: &Profile,
    size: usize,
    sources: &[String],
    created_at: i64,
) -> Result<PreparedMedia> {
    let path = profile.directory.path().join("attachment.png");
    std::fs::write(&path, png_bytes(size))?;
    prepare_file(&path, sources, created_at)
}

fn deliver_metadata(sender: &mut Profile, recipient: &mut Profile, message_id: &str) -> Result<()> {
    let envelope = sender
        .app
        .state
        .outbox
        .iter()
        .find(|outgoing| {
            outgoing.recipient == recipient.app.id() && outgoing.envelope.id == message_id
        })
        .context("missing MLS attachment envelope")?
        .envelope
        .clone();
    expect_ok(
        recipient
            .app
            .handle(&sender.peer, Request::Deliver { envelope })?,
    )?;
    Ok(())
}

fn blob_get(
    cache: &mut Profile,
    peer: &str,
    media_id: &str,
    index: u32,
    read_token: &str,
) -> Result<Option<MediaChunk>> {
    match cache.app.handle(
        peer,
        Request::BlobGet {
            media_id: media_id.into(),
            index,
            read_token: read_token.into(),
        },
    )? {
        Response::Blob(chunk) => Ok(chunk),
        _ => anyhow::bail!("expected media response"),
    }
}

#[test]
fn encrypted_attachment_survives_sender_offline_and_receiver_restart_via_cache() -> Result<()> {
    let mut alice = Profile::new("Alice", 34001)?;
    let mut bob = Profile::new("Bob", 34002)?;
    let mut cache = Profile::new("Cache", 34003)?;
    let group = connect_pair(&mut alice, &mut bob)?;
    let mailbox = allocate_cache(&mut alice, &mut cache)?;
    let prepared = prepare(
        &alice,
        CHUNK_SIZE * 2 + 13,
        &[cache.app.ticket.clone()],
        now() - 120,
    )?;
    let original = prepared.descriptor.clone();
    let chunks = prepared.chunks.clone();
    let message_id = alice
        .app
        .send_attachment(&group, prepared, "A private picture".into())?;
    let sent = alice
        .app
        .state
        .messages
        .iter()
        .find(|m| m.id == message_id)
        .context("sender did not persist attachment")?
        .clone();
    assert_eq!(sent.created_at, original.created_at);
    assert_eq!(sent.expires_at, original.expires_at);
    assert_eq!(sent.expires_at - sent.created_at, MESSAGE_TTL);
    let sent_descriptor = sent
        .attachment
        .as_ref()
        .context("missing sent descriptor")?;
    assert_eq!(sent_descriptor.id, original.id);
    assert_eq!(sent_descriptor.key, original.key);
    assert!(sent_descriptor.sources.contains(&cache.app.ticket));
    assert_eq!(
        &*alice
            .app
            .media_bytes(&sent)?
            .context("sender has no local media")?,
        &png_bytes(CHUNK_SIZE * 2 + 13)
    );

    // Only ciphertext, capabilities and absolute times reach the non-member cache.
    for chunk in &chunks {
        expect_ok(cache.app.handle(
            &alice.peer,
            Request::BlobPut {
                mailbox_id: mailbox.mailbox_id.clone(),
                write_token: mailbox.write_token.clone(),
                read_token: original.read_token.clone(),
                chunk: chunk.clone(),
            },
        )?)?;
    }
    assert!(!cache.app.state.conversations.contains_key(&group));
    assert!(cache.app.state.messages.is_empty());
    deliver_metadata(&mut alice, &mut bob, &message_id)?;
    drop(alice);
    cache = cache.restart()?;
    bob = bob.restart()?;
    let received = bob
        .app
        .state
        .messages
        .iter()
        .find(|m| m.id == message_id)
        .context("receiver lost attachment metadata across restart")?
        .clone();
    assert_eq!(received, sent);
    assert!(bob.app.media_bytes(&received)?.is_none());
    let selected = bob.app.request_media(&message_id, Some(&group))?;
    assert_eq!(selected, received);
    assert!(
        bob.app
            .state
            .media_downloads
            .iter()
            .any(|download| download.media_id == original.id)
    );
    assert_eq!(
        ticket_endpoint_id(
            received
                .attachment
                .as_ref()
                .unwrap()
                .sources
                .iter()
                .find(|ticket| *ticket == &cache.app.ticket)
                .context("cache absent from descriptor")?
        )?,
        cache.peer
    );

    let descriptor = received.attachment.as_ref().unwrap();
    for index in 0..descriptor.chunks {
        let chunk = blob_get(
            &mut cache,
            &bob.peer,
            &descriptor.id,
            index,
            &descriptor.read_token,
        )?
        .context("cached chunk unavailable while sender is offline")?;
        // Do not admit arbitrary cache bytes into the immutable local ciphertext cache.
        decrypt_chunk(descriptor, &chunk, now())?;
        bob.app
            .store
            .store_local_media(&[chunk], &descriptor.read_token, now())?;
        if index + 1 < descriptor.chunks {
            assert!(bob.app.media_bytes(&received)?.is_none());
        }
    }
    assert_eq!(
        &*bob
            .app
            .media_bytes(&received)?
            .context("completed media did not decrypt")?,
        &png_bytes(CHUNK_SIZE * 2 + 13)
    );
    bob = bob.restart()?;
    assert_eq!(
        &*bob
            .app
            .media_bytes(&received)?
            .context("local media lost across restart")?,
        &png_bytes(CHUNK_SIZE * 2 + 13)
    );
    Ok(())
}

#[test]
fn cache_capabilities_conflicts_and_absolute_expiry_are_enforced() -> Result<()> {
    let mut sender = Profile::new("Sender", 34101)?;
    let mut cache = Profile::new("Cache", 34102)?;
    let reader = Profile::new("Reader", 34103)?;
    let mailbox = allocate_cache(&mut sender, &mut cache)?;
    let media = prepare(&sender, 64, &[], now())?;
    let chunk = media.chunks[0].clone();
    let put = |write_token: String, read_token: String, chunk: MediaChunk| Request::BlobPut {
        mailbox_id: mailbox.mailbox_id.clone(),
        write_token,
        read_token,
        chunk,
    };
    assert!(
        cache
            .app
            .handle(
                &sender.peer,
                put(
                    "0".repeat(64),
                    media.descriptor.read_token.clone(),
                    chunk.clone()
                )
            )
            .is_err()
    );
    expect_ok(cache.app.handle(
        &sender.peer,
        put(
            mailbox.write_token.clone(),
            media.descriptor.read_token.clone(),
            chunk.clone(),
        ),
    )?)?;
    expect_ok(cache.app.handle(
        &sender.peer,
        put(
            mailbox.write_token.clone(),
            media.descriptor.read_token.clone(),
            chunk.clone(),
        ),
    )?)?;
    assert!(
        blob_get(
            &mut cache,
            &reader.peer,
            &media.descriptor.id,
            0,
            &"0".repeat(64)
        )
        .is_err()
    );
    assert!(
        blob_get(
            &mut cache,
            &reader.peer,
            &media.descriptor.id,
            0,
            "bad-token"
        )
        .is_err()
    );
    let mut modified = chunk.clone();
    modified.ciphertext[0] ^= 1;
    assert!(
        cache
            .app
            .handle(
                &sender.peer,
                put(
                    mailbox.write_token.clone(),
                    media.descriptor.read_token.clone(),
                    modified
                )
            )
            .is_err()
    );
    let mut extended = chunk.clone();
    extended.created_at += 1;
    extended.expires_at += 1;
    assert!(
        cache
            .app
            .handle(
                &sender.peer,
                put(
                    mailbox.write_token.clone(),
                    media.descriptor.read_token.clone(),
                    extended
                )
            )
            .is_err()
    );
    assert_eq!(
        blob_get(
            &mut cache,
            &reader.peer,
            &media.descriptor.id,
            0,
            &media.descriptor.read_token
        )?,
        Some(chunk)
    );
    assert!(
        cache
            .app
            .store
            .get_relay_media(
                &media.descriptor.id,
                0,
                &media.descriptor.read_token,
                media.descriptor.expires_at - 1
            )?
            .is_some()
    );
    assert!(
        cache
            .app
            .store
            .get_relay_media(
                &media.descriptor.id,
                0,
                &media.descriptor.read_token,
                media.descriptor.expires_at
            )?
            .is_none()
    );
    cache.app.store.purge(media.descriptor.expires_at)?;
    assert!(
        blob_get(
            &mut cache,
            &reader.peer,
            &media.descriptor.id,
            0,
            &media.descriptor.read_token
        )?
        .is_none()
    );

    // A structurally authentic old file is still refused by today's live handler.
    let old = prepare(&sender, 64, &[], now() - MESSAGE_TTL - 10)?;
    assert!(
        cache
            .app
            .handle(
                &sender.peer,
                put(
                    mailbox.write_token.clone(),
                    old.descriptor.read_token.clone(),
                    old.chunks[0].clone()
                )
            )
            .is_err()
    );
    cache.app.store.store_relay_media(
        &mailbox.mailbox_id,
        &mailbox.write_token,
        &old.descriptor.read_token,
        &old.chunks[0],
        old.descriptor.created_at,
    )?;
    assert!(
        blob_get(
            &mut cache,
            &reader.peer,
            &old.descriptor.id,
            0,
            &old.descriptor.read_token
        )?
        .is_none()
    );
    Ok(())
}

#[test]
fn attachment_save_failure_rolls_back_mls_message_outbox_and_staged_chunks() -> Result<()> {
    let mut alice = Profile::new("Alice", 34201)?;
    let mut bob = Profile::new("Bob", 34202)?;
    let group = connect_pair(&mut alice, &mut bob)?;
    let media = prepare(&alice, 64, &[], now())?;
    let descriptor = media.descriptor.clone();
    let before = alice.app.crypto.snapshot()?;
    let durable_before = alice
        .app
        .store
        .load_state()?
        .context("missing durable state")?;
    let messages_before = alice.app.state.messages.len();
    let outbox_before = alice.app.state.outbox.len();
    // Force a production admission failure in App::save *after* encryption ran.
    alice.app.state.pending.push(Pending {
        recipient: bob.app.id().into(),
        request: Request::Update {
            conversation: group.clone(),
            proposal: vec![255; 9 * 1024 * 1024],
        },
    });
    assert!(
        alice
            .app
            .send_attachment(&group, media, "must not escape failed save".into())
            .is_err()
    );
    assert_eq!(alice.app.crypto.snapshot()?, before);
    assert_eq!(alice.app.state.messages.len(), messages_before);
    assert_eq!(alice.app.state.outbox.len(), outbox_before);
    assert!(
        !alice
            .app
            .state
            .media_uploads
            .iter()
            .any(|upload| upload.media_id == descriptor.id)
    );
    assert_eq!(alice.app.store.media_progress(&descriptor.id, now())?, 0);
    let durable_after = alice
        .app
        .store
        .load_state()?
        .context("missing durable state")?;
    assert_eq!(
        serde_json::to_vec(&durable_after)?,
        serde_json::to_vec(&durable_before)?
    );

    // A fresh attempt remains usable after rollback; the failed send consumed no ratchet state.
    alice.app.state.pending.pop();
    let good = prepare(&alice, 64, &[], now())?;
    let id = alice.app.send_attachment(&group, good, String::new())?;
    deliver_metadata(&mut alice, &mut bob, &id)?;
    let received = bob
        .app
        .state
        .messages
        .iter()
        .find(|message| message.id == id)
        .unwrap();
    assert!(received.attachment.is_some());
    assert!(received.text.is_empty());
    Ok(())
}

#[test]
fn invalid_or_expired_attachment_does_not_advance_the_send_ratchet() -> Result<()> {
    let mut alice = Profile::new("Alice", 34301)?;
    let mut bob = Profile::new("Bob", 34302)?;
    let group = connect_pair(&mut alice, &mut bob)?;
    let before = alice.app.crypto.snapshot()?;
    let expired = prepare(&alice, 64, &[], now() - MESSAGE_TTL - 10)?;
    let expired_id = expired.descriptor.id.clone();
    assert!(
        alice
            .app
            .send_attachment(&group, expired, String::new())
            .is_err()
    );
    assert_eq!(alice.app.crypto.snapshot()?, before);
    assert_eq!(alice.app.store.media_progress(&expired_id, now())?, 0);
    let mut damaged = prepare(&alice, CHUNK_SIZE + 1, &[], now())?;
    let damaged_id = damaged.descriptor.id.clone();
    damaged.chunks[1].ciphertext[0] ^= 1;
    assert!(
        alice
            .app
            .send_attachment(&group, damaged, "corrupt prepared data".into())
            .is_err()
    );
    assert_eq!(alice.app.crypto.snapshot()?, before);
    assert_eq!(alice.app.store.media_progress(&damaged_id, now())?, 0);
    assert!(alice.app.state.messages.is_empty());
    assert!(alice.app.state.outbox.is_empty());
    assert!(bob.app.request_media("unknown-id", Some(&group)).is_err());
    assert!(bob.app.state.media_downloads.is_empty());
    Ok(())
}
