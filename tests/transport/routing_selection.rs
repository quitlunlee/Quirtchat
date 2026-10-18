//! Exercise the scheduler's actual authorization, backoff and replica filtering.

use super::*;

fn ticket(seed: u8) -> String {
    let addr = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&[seed; 32]).public())
        .with_ip_addr("127.0.0.1:9".parse().unwrap());
    crate::transport::encode_ticket(&addr).unwrap()
}

fn mailbox(seed: u8, name: &str) -> Mailbox {
    Mailbox {
        node_ticket: ticket(seed),
        mailbox_id: name.into(),
        write_token: "write-capability".into(),
    }
}

fn recipient(id: &str, seed: u8, mailboxes: Vec<Mailbox>) -> Contact {
    Contact {
        id: id.into(),
        name: id.into(),
        ticket: ticket(seed),
        key_package: vec![],
        mailboxes,
        version: 1,
        invite_token: "invitation-capability".into(),
    }
}

fn queued(recipient: &str, id: &str) -> Outgoing {
    let time = now();
    Outgoing {
        recipient: recipient.into(),
        envelope: Envelope {
            id: id.into(),
            conversation: "direct-message".into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![1],
        },
        stored_at: vec![],
    }
}

fn profile(directory: &std::path::Path) -> Result<App> {
    App::initialize(
        Store::create(
            &directory.join("routing.db"),
            "routing regression passphrase",
        )?,
        "router".into(),
    )
}

#[test]
fn cache_allocation_uses_observed_quality_without_bypassing_backoff_or_existing_nodes() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let mut app = profile(directory.path())?;
    app.state.peers = vec![ticket(1), ticket(2), ticket(3)];
    let slow = ticket_endpoint_id(&ticket(1))?;
    let fast = ticket_endpoint_id(&ticket(2))?;
    let unknown = ticket_endpoint_id(&ticket(3))?;
    let mut schedule = Schedule::default();
    schedule
        .routes
        .observe(&slow, Duration::from_millis(300), true);
    schedule
        .routes
        .observe(&fast, Duration::from_millis(15), true);
    let selected = select_discovery(&app, &mut schedule, true);
    assert!(matches!(selected[0].kind, Kind::Allocate { .. }));
    assert_eq!(selected[0].node, fast);

    schedule.failed(format!("node:{fast}"));
    let selected = select_discovery(&app, &mut schedule, true);
    assert_eq!(selected[0].node, slow);
    assert!(selected.iter().all(|job| job.node != fast));

    app.state.mailboxes.push(LocalMailbox {
        public: mailbox(1, "existing"),
        read_token: "read-capability".into(),
        retired_at: None,
    });
    let selected = select_discovery(&app, &mut schedule, true);
    assert!(matches!(selected[0].kind, Kind::Allocate { .. }));
    assert_eq!(selected[0].node, unknown);
    Ok(())
}

#[test]
fn cache_store_prefers_fast_signed_routes_and_counts_replicas_by_endpoint() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut app = profile(directory.path())?;
    let slow = mailbox(11, "slow");
    let fast = mailbox(12, "fast");
    let fast_duplicate = mailbox(12, "another-mailbox-on-fast");
    let contact = recipient(
        "recipient",
        10,
        vec![slow.clone(), fast.clone(), fast_duplicate],
    );
    let direct_node = ticket_endpoint_id(&contact.ticket)?;
    let slow_node = ticket_endpoint_id(&slow.node_ticket)?;
    let fast_node = ticket_endpoint_id(&fast.node_ticket)?;
    app.state.contacts.insert(contact.id.clone(), contact);
    app.state.outbox.push(queued("recipient", "message"));
    let shared = Arc::new(Mutex::new(app));
    let runtime = Runtime::default();
    {
        let mut schedule = runtime.schedule.lock().unwrap();
        schedule.failed(format!("node:{direct_node}"));
        schedule
            .routes
            .observe(&slow_node, Duration::from_millis(300), true);
        schedule
            .routes
            .observe(&fast_node, Duration::from_millis(15), true);
        // A fast PEX candidate is not an authorized destination for this recipient.
        schedule.routes.observe(
            &ticket_endpoint_id(&ticket(99))?,
            Duration::from_millis(1),
            true,
        );
    }
    let mut jobs = select_outbox(
        &shared.lock().unwrap(),
        &mut runtime.schedule.lock().unwrap(),
    );
    assert_eq!(jobs.len(), 1);
    let job = jobs.remove(0);
    assert_eq!(job.node, fast_node);
    assert!(matches!(job.kind, Kind::Store { .. }));
    apply_response(&shared, &runtime, &job, Response::Ok)?;

    let mut jobs = select_outbox(
        &shared.lock().unwrap(),
        &mut runtime.schedule.lock().unwrap(),
    );
    assert_eq!(jobs.len(), 1);
    let job = jobs.remove(0);
    assert_eq!(
        job.node, slow_node,
        "another mailbox on the same endpoint is not another replica"
    );
    apply_response(&shared, &runtime, &job, Response::Ok)?;
    assert!(
        select_outbox(
            &shared.lock().unwrap(),
            &mut runtime.schedule.lock().unwrap()
        )
        .is_empty()
    );
    let app = shared.lock().unwrap();
    let saved = app.store.load_state()?.context("missing saved outbox")?;
    assert_eq!(saved.outbox[0].stored_at.len(), 2);
    assert_eq!(
        saved.outbox[0].envelope.expires_at,
        app.state.outbox[0].envelope.expires_at
    );
    Ok(())
}

#[test]
fn cache_selection_preserves_batch_bounds_distinct_nodes_and_recipient_rotation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut app = profile(directory.path())?;
    let mut schedule = Schedule::default();
    for seed in 1..=6 {
        let id = format!("recipient-{seed}");
        let contact = recipient(&id, seed, vec![mailbox(seed + 10, &id)]);
        schedule.failed(format!("node:{}", ticket_endpoint_id(&contact.ticket)?));
        app.state.contacts.insert(id.clone(), contact);
        app.state
            .outbox
            .push(queued(&id, &format!("message-{seed}")));
    }
    let first = select_outbox(&app, &mut schedule);
    let second = select_outbox(&app, &mut schedule);
    for batch in [&first, &second] {
        assert_eq!(batch.len(), BATCH);
        assert_eq!(
            batch
                .iter()
                .map(|job| &job.node)
                .collect::<BTreeSet<_>>()
                .len(),
            BATCH
        );
    }
    let recipients: BTreeSet<_> = first
        .iter()
        .chain(&second)
        .map(|job| match &job.kind {
            Kind::Store { recipient, .. } => recipient,
            _ => panic!("expected a cache store"),
        })
        .collect();
    assert_eq!(
        recipients.len(),
        6,
        "route scoring must not pin the recipient queue front"
    );
    Ok(())
}

#[test]
fn cache_rotation_never_replaces_a_temporarily_unreachable_personal_mailbox() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut app = profile(directory.path())?;
    for seed in 1..=3 {
        app.state.mailboxes.push(LocalMailbox {
            public: mailbox(seed, &format!("mailbox-{seed}")),
            read_token: "read-capability".into(),
            retired_at: None,
        });
    }
    let personal = &app.state.mailboxes[0].public;
    app.state.personal_mailbox = Some(PersonalMailbox {
        node: ticket_endpoint_id(&personal.node_ticket)?,
        mailbox_id: personal.mailbox_id.clone(),
    });
    app.state.peers.push(ticket(4));
    let mut schedule = Schedule::default();
    let failure = Retry {
        failures: 3,
        first_failure: Instant::now() - Duration::from_secs(61),
        due: Instant::now(),
    };
    schedule
        .retries
        .insert(format!("fetch:{}", mailbox_key(personal)?), failure.clone());
    assert!(
        select_discovery(&app, &mut schedule, true)
            .iter()
            .all(|job| !matches!(job.kind, Kind::Allocate { .. }))
    );

    let replaceable = mailbox_key(&app.state.mailboxes[1].public)?;
    schedule
        .retries
        .insert(format!("fetch:{replaceable}"), failure);
    let mut jobs = select_discovery(&app, &mut schedule, true);
    assert!(matches!(&jobs[0].kind, Kind::Allocate { replace: Some(key) } if key == &replaceable));
    // Recheck protection after the request: a user can pin its target while it is in flight.
    let newly_pinned = &app.state.mailboxes[1].public;
    app.state.personal_mailbox = Some(PersonalMailbox {
        node: ticket_endpoint_id(&newly_pinned.node_ticket)?,
        mailbox_id: newly_pinned.mailbox_id.clone(),
    });
    let shared = Arc::new(Mutex::new(app));
    assert!(
        apply_response(
            &shared,
            &Runtime::default(),
            &jobs.remove(0),
            Response::Mailbox {
                mailbox_id: "11".repeat(16),
                write_token: "22".repeat(32),
                read_token: "33".repeat(32),
            },
        )
        .is_err()
    );
    let app = shared.lock().unwrap();
    assert_eq!(app.state.mailboxes.len(), 3);
    assert!(
        app.state
            .mailboxes
            .iter()
            .all(|mailbox| mailbox.retired_at.is_none())
    );
    Ok(())
}

#[test]
fn hosted_conversations_bypass_private_cache_and_sync_but_keep_direct_history() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut app = profile(directory.path())?;
    let owner = recipient("owner", 21, vec![mailbox(22, "private-cache")]);
    app.state.contacts.insert(owner.id.clone(), owner);
    app.state.conversations.insert(
        "hosted".into(),
        Conversation {
            id: "hosted".into(),
            owner: "owner".into(),
            active: true,
            server: Some(HostedGroupRoute { ticket: ticket(23) }),
            ..Default::default()
        },
    );
    app.state.pending.push(Pending {
        recipient: "owner".into(),
        request: Request::Update {
            conversation: "hosted".into(),
            proposal: vec![1],
        },
    });
    app.state.pending.push(Pending {
        recipient: "owner".into(),
        request: Request::History {
            conversation: "hosted".into(),
            after: None,
        },
    });
    let mut hosted_message = queued("owner", "hosted-message");
    hosted_message.envelope.conversation = "hosted".into();
    app.state.outbox.push(hosted_message);
    let mut schedule = Schedule::default();
    let pending = select_pending(&app, &mut schedule);
    assert_eq!(pending.len(), 1);
    assert!(
        matches!(pending[0].request, Request::History { .. }),
        "hosted Update must not block direct recovery history"
    );
    assert!(select_sync(&app, &mut schedule).is_empty());
    assert!(select_outbox(&app, &mut schedule).is_empty());

    app.state.conversations.insert(
        "direct-message".into(),
        Conversation {
            id: "direct-message".into(),
            owner: "owner".into(),
            active: true,
            ..Default::default()
        },
    );
    app.state.outbox.push(queued("owner", "private-message"));
    let sync = select_sync(&app, &mut schedule);
    assert_eq!(sync.len(), 1);
    assert!(
        matches!(&sync[0].request, Request::Sync { conversation, .. } if conversation == "direct-message")
    );
    let outgoing = select_outbox(&app, &mut schedule);
    assert_eq!(outgoing.len(), 1);
    assert!(
        matches!(&outgoing[0].request, Request::Deliver { envelope } if envelope.id == "private-message")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn measured_cache_accepts_first_copy_without_waiting_for_direct_timeout() -> Result<()> {
    use crate::transport::{
        TransportLimits,
        tests::{local_ticket, local_transport},
    };

    tokio::time::timeout(Duration::from_secs(180), async {
        let directory = tempfile::tempdir()?;
        let mut app = profile(directory.path())?;
        let limits = TransportLimits {
            request_timeout: Duration::from_secs(30),
            ..Default::default()
        };
        let sender = local_transport([71; 32], limits).await?;
        let mut direct = local_transport([72; 32], limits).await?;
        let mut relay = local_transport([73; 32], limits).await?;
        let direct_ticket = local_ticket(&direct).await?;
        let relay_ticket = local_ticket(&relay).await?;
        let mut direct_incoming = direct.take_incoming().context("direct receiver")?;
        let relay_store =
            Store::create(&directory.path().join("relay.db"), "routing relay password")?;
        let (mailbox_id, write_token, read_token) = relay_store.allocate("recipient")?;
        let public = Mailbox {
            node_ticket: relay_ticket.clone(),
            mailbox_id: mailbox_id.clone(),
            write_token,
        };
        let mut contact = recipient("recipient", 72, vec![public]);
        contact.ticket = direct_ticket;
        app.state.contacts.insert(contact.id.clone(), contact);
        app.state.conversations.insert(
            "direct-message".into(),
            Conversation {
                id: "direct-message".into(),
                owner: "recipient".into(),
                active: true,
                ..Default::default()
            },
        );
        app.state
            .outbox
            .push(queued("recipient", "first-offline-message"));
        app.save()?;
        let shared = Arc::new(Mutex::new(app));
        let runtime = runtime(&sender.endpoint_id());
        // A prior timeout identifies this recipient as a slow route. Keep it
        // eligible (no backoff) so choosing direct first would still be visible.
        runtime.schedule.lock().unwrap().routes.observe(
            &direct.endpoint_id(),
            Duration::from_secs(60),
            false,
        );
        #[derive(Debug, PartialEq, Eq)]
        enum Event {
            CachePersisted,
            DirectSync,
            DirectDeliver,
            DirectOther,
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let direct_events = events.clone();
        let direct_worker = tokio::spawn(async move {
            while let Some(incoming) = direct_incoming.recv().await {
                let event = match incoming.request {
                    Request::Sync { .. } => Event::DirectSync,
                    Request::Deliver { .. } => Event::DirectDeliver,
                    _ => Event::DirectOther,
                };
                direct_events.lock().unwrap().push(event);
                let _ = incoming
                    .reply
                    .send(Response::Error("recipient unavailable".into()));
            }
        });
        let relay_store = Arc::new(Mutex::new(relay_store));
        let serving = relay_store.clone();
        let mut incoming = relay.take_incoming().context("relay receiver")?;
        let relay_events = events.clone();
        let worker = tokio::spawn(async move {
            while let Some(incoming) = incoming.recv().await {
                let result = match incoming.request {
                    Request::Peers => Ok(Response::Peers(vec![])),
                    Request::Store {
                        mailbox_id,
                        write_token,
                        envelope,
                    } => {
                        let stored = serving.lock().unwrap().store(
                            &mailbox_id,
                            &write_token,
                            &envelope,
                            now(),
                        );
                        if stored.is_ok() {
                            // Record only after Store committed, and before the
                            // RPC acknowledgement lets the sender advance.
                            relay_events.lock().unwrap().push(Event::CachePersisted);
                        }
                        stored.map(|_| Response::Ok)
                    }
                    _ => anyhow::bail!("unexpected relay request"),
                };
                let _ = incoming
                    .reply
                    .send(result.unwrap_or_else(|error| Response::Error(error.to_string())));
            }
            Ok::<_, anyhow::Error>(())
        });
        // Warm quality with an actual successful RPC through run_job, not an
        // injected cache score. The direct endpoint remains eligible despite its
        // prior observed timeout, so this exercises quality selection itself.
        run_job(
            &shared,
            &sender,
            &runtime,
            Some(Job {
                ticket: relay_ticket,
                node: relay.endpoint_id(),
                key: "quality-probe".into(),
                request: Request::Peers,
                kind: Kind::Peers,
            }),
        )
        .await?;
        let jobs = select_outbox(
            &shared.lock().unwrap(),
            &mut runtime.schedule.lock().unwrap(),
        );
        assert_eq!(jobs.len(), 1);
        assert!(matches!(jobs[0].kind, Kind::Store { .. }));
        // Exercise the entire tick. Packet order, rather than elapsed time,
        // proves neither direct delivery nor synchronization gates durable Store.
        // Heavy concurrent SQLCipher tests may slow either endpoint arbitrarily.
        network_tick(&shared, &sender, false).await?;
        {
            let events = events.lock().unwrap();
            assert_eq!(
                events.first(),
                Some(&Event::CachePersisted),
                "direct RPC preceded durable cache storage: {events:?}"
            );
            assert!(
                events.contains(&Event::DirectSync),
                "fixture must exercise the later sync category: {events:?}"
            );
            assert!(
                !events.contains(&Event::DirectDeliver),
                "first delivery bypassed the preferred cache: {events:?}"
            );
        }
        assert_eq!(shared.lock().unwrap().state.outbox[0].stored_at.len(), 1);
        let copies =
            relay_store
                .lock()
                .unwrap()
                .fetch(&mailbox_id, &read_token, "recipient", now())?;
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].id, "first-offline-message");
        // Once the only cache copy is durable, the next opportunity still tries
        // the recipient; fast storage cannot permanently starve direct delivery.
        runtime
            .schedule
            .lock()
            .unwrap()
            .succeeded(format!("node:{}", direct.endpoint_id()), 0);
        let jobs = select_outbox(
            &shared.lock().unwrap(),
            &mut runtime.schedule.lock().unwrap(),
        );
        assert_eq!(jobs.len(), 1);
        assert!(matches!(jobs[0].kind, Kind::Deliver { .. }));
        sender.close().await;
        direct.close().await;
        relay.close().await;
        worker.abort();
        let _ = worker.await;
        direct_worker.abort();
        let _ = direct_worker.await;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("local cache routing regression timed out")?
}
