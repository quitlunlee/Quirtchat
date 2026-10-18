//! The production Fetch/ACK/Sync handlers with real MLS and SQLCipher storage.
//! Network delivery is driven explicitly so missing epochs and full queues are deterministic.

use super::*;

fn profile(directory: &std::path::Path, name: &str) -> Result<App> {
    let store = Store::create(
        &directory.join(format!("{name}.db")),
        "deferred inbox regression passphrase",
    )?;
    let mut app = App::initialize(store, name.into())?;
    let secret = app.state.transport_secret.as_slice().try_into()?;
    let addr = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&secret).public())
        .with_ip_addr("127.0.0.1:9".parse()?);
    app.ticket = crate::transport::encode_ticket(&addr)?;
    Ok(app)
}

fn fetch_and_ack(
    shared: &Shared,
    runtime: &Runtime,
    cache: &Store,
    mailbox: &LocalMailbox,
    owner: &str,
) -> Result<usize> {
    let request = Request::Fetch {
        mailbox_id: mailbox.public.mailbox_id.clone(),
        read_token: mailbox.read_token.clone(),
    };
    let node = ticket_endpoint_id(&mailbox.public.node_ticket)?;
    let key = mailbox_key(&mailbox.public)?;
    let envelopes = cache.fetch(
        &mailbox.public.mailbox_id,
        &mailbox.read_token,
        owner,
        now(),
    )?;
    apply_response(
        shared,
        runtime,
        &Job {
            ticket: mailbox.public.node_ticket.clone(),
            node: node.clone(),
            key: format!("fetch:{key}"),
            request,
            kind: Kind::Fetch(mailbox.clone()),
        },
        Response::Envelopes(envelopes),
    )?;
    let ids = runtime
        .schedule
        .lock()
        .unwrap()
        .acknowledgements
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let count = ids.len();
    cache.delete(&mailbox.public.mailbox_id, &mailbox.read_token, owner, &ids)?;
    apply_response(
        shared,
        runtime,
        &Job {
            ticket: mailbox.public.node_ticket.clone(),
            node,
            key: format!("delete:{key}"),
            request: Request::Delete {
                mailbox_id: mailbox.public.mailbox_id.clone(),
                read_token: mailbox.read_token.clone(),
                ids: ids.clone(),
            },
            kind: Kind::Delete { mailbox: key, ids },
        },
        Response::Ok,
    )?;
    Ok(count)
}

#[test]
fn missing_epoch_inbox_keeps_overflow_on_relay_and_resumes_after_sync() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut sender = profile(directory.path(), "sender")?;
    let mut receiver = profile(directory.path(), "receiver")?;
    let receiver_id = receiver.id().to_owned();
    let sender_id = sender.id().to_owned();
    let receiver_peer = ticket_endpoint_id(&receiver.ticket)?;
    let sender_peer = ticket_endpoint_id(&sender.ticket)?;
    sender.atomic(|app| app.import_contact(receiver.invitation()?))?;
    receiver.atomic(|app| app.import_contact(sender.invitation()?))?;
    let group = sender.atomic(|app| app.create_direct("offline inbox".into(), receiver_id))?;
    let join = sender
        .state
        .pending
        .iter()
        .find(|pending| matches!(&pending.request, Request::Join { conversation, .. } if conversation.id == group))
        .context("missing Welcome")?
        .request
        .clone();
    receiver.handle(&sender_peer, join)?;
    let old_epoch = receiver.state.conversations[&group].epoch;
    sender.atomic(|app| {
        let members = app.state.conversations[&group].members.clone();
        let commit = app.crypto.commit_updates(&group)?;
        app.record_commit(&group, commit, &members, vec![])?;
        for index in 0..=MAX_DEFERRED_MESSAGES {
            app.send(&group, format!("offline message {index}"))?;
        }
        Ok(())
    })?;
    assert!(sender.state.conversations[&group].epoch > old_epoch);

    let cache = Store::create(
        &directory.path().join("cache.db"),
        "deferred cache regression passphrase",
    )?;
    let (mailbox_id, write_token, read_token) = cache.allocate(&receiver_peer)?;
    let addr = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&[77; 32]).public())
        .with_ip_addr("127.0.0.1:9".parse()?);
    let mailbox = LocalMailbox {
        public: Mailbox {
            node_ticket: crate::transport::encode_ticket(&addr)?,
            mailbox_id,
            write_token,
        },
        read_token,
        retired_at: None,
    };
    for outgoing in &sender.state.outbox {
        cache.store(
            &mailbox.public.mailbox_id,
            &mailbox.public.write_token,
            &outgoing.envelope,
            now(),
        )?;
    }
    receiver.atomic(|app| {
        app.state.mailboxes.push(mailbox.clone());
        Ok(())
    })?;
    let shared = Arc::new(Mutex::new(receiver));
    let runtime = Runtime::default();
    let mut acknowledged = 0;
    for _ in 0..10 {
        let count = fetch_and_ack(&shared, &runtime, &cache, &mailbox, &receiver_peer)?;
        acknowledged += count;
        if count == 0 {
            break;
        }
    }
    assert_eq!(acknowledged, MAX_DEFERRED_MESSAGES);
    let remaining = cache.fetch(
        &mailbox.public.mailbox_id,
        &mailbox.read_token,
        &receiver_peer,
        now(),
    )?;
    assert_eq!(remaining.len(), 1, "overflow must remain on the relay");
    {
        let app = shared.lock().unwrap();
        assert!(app.state.messages.is_empty());
        assert_eq!(app.state.deferred.len(), MAX_DEFERRED_MESSAGES);
        let saved = app.store.load_state()?.context("missing saved receiver")?;
        assert_eq!(saved.deferred.len(), MAX_DEFERRED_MESSAGES);
        let retained: BTreeSet<_> = saved
            .deferred
            .iter()
            .chain(&remaining)
            .map(|envelope| envelope.id.as_str())
            .collect();
        assert_eq!(retained.len(), MAX_DEFERRED_MESSAGES + 1);
        assert!(
            sender
                .state
                .messages
                .iter()
                .all(|message| retained.contains(message.id.as_str()))
        );
    }
    // Repeated fetches while the epoch is still missing must not lose another copy.
    assert_eq!(
        fetch_and_ack(&shared, &runtime, &cache, &mailbox, &receiver_peer)?,
        0
    );

    // A blocked first item must not starve a healthy conversation later in the same page.
    let invitation = shared.lock().unwrap().invitation()?;
    let healthy_group = sender.atomic(|app| {
        let receiver = app.import_contact(invitation)?;
        app.create_direct("healthy inbox".into(), receiver)
    })?;
    let join = sender
        .state
        .pending
        .iter()
        .find(|pending| matches!(&pending.request, Request::Join { conversation, .. } if conversation.id == healthy_group))
        .context("missing healthy Welcome")?
        .request
        .clone();
    shared.lock().unwrap().handle(&sender_peer, join)?;
    let healthy_message = sender.atomic(|app| {
        app.send_content(
            &healthy_group,
            "deliver despite another group's backlog".into(),
            None,
            now().max(remaining[0].created_at + 1),
        )
    })?;
    let healthy_envelope = &sender
        .state
        .outbox
        .iter()
        .find(|outgoing| outgoing.envelope.id == healthy_message)
        .context("missing healthy envelope")?
        .envelope;
    cache.store(
        &mailbox.public.mailbox_id,
        &mailbox.public.write_token,
        healthy_envelope,
        now(),
    )?;
    let mixed_page = cache.fetch(
        &mailbox.public.mailbox_id,
        &mailbox.read_token,
        &receiver_peer,
        now(),
    )?;
    assert_eq!(mixed_page.len(), 2);
    assert_eq!(mixed_page[0].id, remaining[0].id);
    assert_eq!(mixed_page[1].id, healthy_message);
    assert_eq!(
        fetch_and_ack(&shared, &runtime, &cache, &mailbox, &receiver_peer)?,
        1,
        "only the decryptable conversation should be acknowledged"
    );
    {
        let app = shared.lock().unwrap();
        assert_eq!(app.state.deferred.len(), MAX_DEFERRED_MESSAGES);
        assert_eq!(app.state.messages.len(), 1);
        assert_eq!(app.state.messages[0].id, healthy_message);
    }
    let blocked = cache.fetch(
        &mailbox.public.mailbox_id,
        &mailbox.read_token,
        &receiver_peer,
        now(),
    )?;
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].id, remaining[0].id);

    let request = Request::Sync {
        conversation: group.clone(),
        after_epoch: old_epoch,
    };
    let response = sender.handle(&receiver_peer, request.clone())?;
    apply_response(
        &shared,
        &runtime,
        &Job {
            ticket: sender.ticket.clone(),
            node: sender_peer,
            key: format!("sync:{group}:{sender_id}"),
            request,
            kind: Kind::Sync {
                group,
                peer: sender_id,
            },
        },
        response,
    )?;
    retry_deferred(&mut shared.lock().unwrap())?;
    assert_eq!(
        fetch_and_ack(&shared, &runtime, &cache, &mailbox, &receiver_peer)?,
        1
    );
    for _ in 0..MAX_DEFERRED_MESSAGES / BATCH {
        retry_deferred(&mut shared.lock().unwrap())?;
    }
    let app = shared.lock().unwrap();
    assert!(app.state.deferred.is_empty());
    assert_eq!(app.state.messages.len(), MAX_DEFERRED_MESSAGES + 2);
    assert!(
        sender
            .state
            .messages
            .iter()
            .all(|message| app.state.messages.contains(message))
    );
    assert!(
        cache
            .fetch(
                &mailbox.public.mailbox_id,
                &mailbox.read_token,
                &receiver_peer,
                now()
            )?
            .is_empty()
    );
    Ok(())
}
