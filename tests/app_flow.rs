//! Full application/SQLCipher/MLS flows without depending on a public relay.
//! Requests use authenticated test transport identities and the production handler.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, ensure};
use clichat::{
    app::App,
    model::{Envelope, MESSAGE_TTL, Request, Response, SignedMessage, now},
    storage::Store,
    transport::encode_ticket,
};
use ed25519_dalek::{Signature, VerifyingKey};
use iroh::{EndpointAddr, SecretKey};
use tempfile::TempDir;

const PASSWORD: &str = "integration test profile passphrase";

struct Profile {
    app: App,
    // Close the Store/SQLite file before TempDir attempts Windows cleanup.
    directory: TempDir,
    peer_id: String,
    port: u16,
}

impl Profile {
    fn new(name: &str, port: u16) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let store = Store::create(&directory.path().join("profile.db"), PASSWORD)?;
        let app = App::initialize(store, name.into())?;
        let mut profile = Self {
            directory,
            app,
            peer_id: String::new(),
            port,
        };
        profile.set_ticket()?;
        Ok(profile)
    }

    fn set_ticket(&mut self) -> Result<()> {
        let seed: [u8; 32] = self.app.state.transport_secret.as_slice().try_into()?;
        let endpoint = SecretKey::from_bytes(&seed).public();
        self.peer_id = endpoint.to_string();
        let address = EndpointAddr::new(endpoint)
            .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)));
        self.app.ticket = encode_ticket(&address)?;
        Ok(())
    }

    fn restart(self) -> Result<Self> {
        let Self {
            directory,
            app,
            port,
            ..
        } = self;
        drop(app); // Release the single-instance profile lock before reopening.
        let store = Store::open(&directory.path().join("profile.db"), PASSWORD)?;
        let app = App::load(store)?;
        let mut profile = Self {
            directory,
            app,
            peer_id: String::new(),
            port,
        };
        profile.set_ticket()?;
        Ok(profile)
    }
}

fn exchange(left: &mut Profile, right: &mut Profile) -> Result<()> {
    let left_invitation = left.app.invitation()?;
    let right_invitation = right.app.invitation()?;
    left.app
        .atomic(|app| app.import_contact(right_invitation))?;
    right
        .app
        .atomic(|app| app.import_contact(left_invitation))?;
    Ok(())
}

fn expect_ok(response: Response) -> Result<()> {
    ensure!(
        matches!(response, Response::Ok),
        "expected a committed acknowledgement"
    );
    Ok(())
}

fn is_control(request: &Request) -> bool {
    matches!(
        request,
        Request::Join { .. } | Request::Control { .. } | Request::Update { .. }
    )
}

fn catch_up_control_gap(
    sender: &mut Profile,
    recipient: &mut Profile,
    request: &Request,
) -> Result<()> {
    let Request::Control { record } = request else {
        return Ok(());
    };
    loop {
        let epoch = recipient
            .app
            .state
            .conversations
            .get(&record.conversation)
            .context("control recipient has not joined the group")?
            .epoch;
        if record.epoch <= epoch.saturating_add(1) {
            return Ok(());
        }
        let response = sender.app.handle(
            &recipient.peer_id,
            Request::Sync {
                conversation: record.conversation.clone(),
                after_epoch: epoch,
            },
        )?;
        let Response::Sync { controls, .. } = response else {
            anyhow::bail!("expected owner synchronization response");
        };
        ensure!(
            !controls.is_empty(),
            "owner has no records for the missing epochs"
        );
        for control in controls {
            ensure!(
                control.conversation == record.conversation,
                "cross-group synchronization record"
            );
            // Every record uses the production path: contiguous epochs, MLS
            // authentication, owner checks, and an atomic database commit.
            expect_ok(
                recipient
                    .app
                    .handle(&sender.peer_id, Request::Control { record: control })?,
            )?;
        }
        ensure!(
            recipient.app.state.conversations[&record.conversation].epoch > epoch,
            "synchronization did not advance the recipient"
        );
    }
}

/// Delivers persisted group controls in queue order, then persists their ACKs.
/// History requests remain queued for explicit response assertions below.
fn deliver_pending(sender: &mut Profile, recipient: &mut Profile) -> Result<Vec<Request>> {
    let recipient_id = recipient.app.id().to_string();
    let requests: Vec<_> = sender
        .app
        .state
        .pending
        .iter()
        .filter(|pending| pending.recipient == recipient_id && is_control(&pending.request))
        .map(|pending| pending.request.clone())
        .collect();
    for request in &requests {
        catch_up_control_gap(sender, recipient, request)?;
        // Sync may already have applied the queued Commit. Check its exact
        // repeat through the handler before acknowledging that original request.
        expect_ok(recipient.app.handle(&sender.peer_id, request.clone())?)?;
        let acknowledged = serde_json::to_vec(request)?;
        sender.app.atomic(|app| {
            app.state.pending.retain(|pending| {
                pending.recipient != recipient_id
                    || serde_json::to_vec(&pending.request).ok().as_ref() != Some(&acknowledged)
            });
            Ok(())
        })?;
    }
    Ok(requests)
}

fn deliver_outbox(sender: &mut Profile, recipient: &mut Profile) -> Result<Vec<Envelope>> {
    let recipient_id = recipient.app.id().to_string();
    let envelopes: Vec<_> = sender
        .app
        .state
        .outbox
        .iter()
        .filter(|outgoing| outgoing.recipient == recipient_id)
        .map(|outgoing| outgoing.envelope.clone())
        .collect();
    for envelope in &envelopes {
        expect_ok(recipient.app.handle(
            &sender.peer_id,
            Request::Deliver {
                envelope: envelope.clone(),
            },
        )?)?;
    }
    sender.app.atomic(|app| {
        app.state
            .outbox
            .retain(|outgoing| outgoing.recipient != recipient_id);
        Ok(())
    })?;
    Ok(envelopes)
}

fn pending_join(sender: &Profile, recipient: &Profile) -> Result<Request> {
    sender
        .app
        .state
        .pending
        .iter()
        .find(|pending| {
            pending.recipient == recipient.app.id()
                && matches!(&pending.request, Request::Join { .. })
        })
        .map(|pending| pending.request.clone())
        .context("expected a queued welcome")
}

/// Verify the returned history independently of MLS and of the owner's identity.
/// This binds its bytes to the original sender, including its original expiry.
fn verify_history_signature(signed: &SignedMessage) -> Result<()> {
    signed.message.validate(now())?;
    let public: [u8; 32] = hex::decode(&signed.message.sender)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid sender public key"))?;
    let mut bytes = b"clichat/message/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&signed.message)?);
    VerifyingKey::from_bytes(&public)?
        .verify_strict(&bytes, &Signature::from_slice(&signed.signature)?)?;
    Ok(())
}

#[test]
fn three_members_chat_restart_preserve_expiry_and_enforce_removal() -> Result<()> {
    let mut alice = Profile::new("Alice", 31001)?;
    let mut bob = Profile::new("Bob", 31002)?;
    let mut carol = Profile::new("Carol", 31003)?;
    exchange(&mut alice, &mut bob)?;
    exchange(&mut alice, &mut carol)?;
    exchange(&mut bob, &mut carol)?;
    let alice_id = alice.app.id().to_string();
    let bob_id = bob.app.id().to_string();
    let carol_id = carol.app.id().to_string();

    let group = alice
        .app
        .atomic(|app| app.create_group("Small group".into(), vec![bob_id.clone()]))?;
    deliver_pending(&mut alice, &mut bob)?;
    assert_eq!(bob.app.state.conversations[&group].members.len(), 2);
    alice.app.atomic(|app| app.add_member(&group, &carol_id))?;
    deliver_pending(&mut alice, &mut bob)?;
    deliver_pending(&mut alice, &mut carol)?;
    for app in [&alice.app, &bob.app, &carol.app] {
        assert_eq!(app.state.conversations[&group].members.len(), 3);
        assert_eq!(app.state.conversations[&group].epoch, 2);
    }

    let bob_message = bob
        .app
        .atomic(|app| app.send(&group, "hello from Bob".into()))?;
    deliver_outbox(&mut bob, &mut alice)?;
    deliver_outbox(&mut bob, &mut carol)?;
    assert!(
        alice
            .app
            .state
            .messages
            .iter()
            .any(|message| message.id == bob_message && message.sender == bob_id)
    );
    assert!(
        carol
            .app
            .state
            .messages
            .iter()
            .any(|message| message.id == bob_message && message.text == "hello from Bob")
    );

    let message_id = alice
        .app
        .atomic(|app| app.send(&group, "an absolute expiry".into()))?;
    let envelope = alice
        .app
        .state
        .outbox
        .iter()
        .find(|outgoing| outgoing.recipient == bob_id && outgoing.envelope.id == message_id)
        .context("missing persisted outgoing message")?
        .envelope
        .clone();
    assert_eq!(envelope.expires_at - envelope.created_at, MESSAGE_TTL);

    // A relay can edit outer metadata, but cannot extend the authenticated inner TTL.
    // The failed decryption/validation must also roll the receive ratchet back.
    let mut extended = envelope.clone();
    extended.created_at += 1;
    extended.expires_at += 1;
    assert!(
        bob.app
            .handle(&alice.peer_id, Request::Deliver { envelope: extended })
            .is_err()
    );
    assert!(
        !bob.app
            .state
            .messages
            .iter()
            .any(|message| message.id == message_id)
    );
    deliver_outbox(&mut alice, &mut bob)?;
    deliver_outbox(&mut alice, &mut carol)?;
    let received = bob
        .app
        .state
        .messages
        .iter()
        .find(|message| message.id == message_id)
        .unwrap();
    assert_eq!(
        (received.created_at, received.expires_at),
        (envelope.created_at, envelope.expires_at)
    );
    expect_ok(bob.app.handle(
        &alice.peer_id,
        Request::Deliver {
            envelope: envelope.clone(),
        },
    )?)?;
    assert_eq!(
        bob.app
            .state
            .messages
            .iter()
            .filter(|message| message.id == message_id)
            .count(),
        1
    );

    bob = bob.restart()?;
    assert_eq!(bob.app.id(), bob_id);
    assert_eq!(bob.app.state.conversations[&group].epoch, 2);
    assert_eq!(
        bob.app
            .state
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .unwrap()
            .expires_at,
        envelope.expires_at
    );

    alice
        .app
        .atomic(|app| app.remove_member(&group, &carol_id))?;
    deliver_pending(&mut alice, &mut bob)?;
    deliver_pending(&mut alice, &mut carol)?;
    assert!(!carol.app.state.conversations[&group].active);
    assert!(
        carol
            .app
            .atomic(|app| app.send(&group, "should fail".into()))
            .is_err()
    );
    assert!(
        carol
            .app
            .atomic(|app| app.prepare_recovery(&group))
            .is_err()
    );
    let malicious_recovery = Request::Recover {
        conversation: group.clone(),
        key_package: carol.app.state.key_package.clone(),
    };
    assert!(
        alice
            .app
            .handle(&carol.peer_id, malicious_recovery)
            .is_err()
    );
    assert!(
        !alice.app.state.conversations[&group]
            .members
            .contains(&carol_id)
    );

    let current_message = alice
        .app
        .atomic(|app| app.send(&group, "remaining members".into()))?;
    let current_envelope = alice
        .app
        .state
        .outbox
        .iter()
        .find(|outgoing| outgoing.envelope.id == current_message)
        .unwrap()
        .envelope
        .clone();
    assert!(
        carol
            .app
            .handle(
                &alice.peer_id,
                Request::Deliver {
                    envelope: current_envelope
                }
            )
            .is_err()
    );
    deliver_outbox(&mut alice, &mut bob)?;
    assert!(
        bob.app
            .state
            .messages
            .iter()
            .any(|message| message.id == current_message && message.sender == alice_id)
    );

    bob.app.atomic(|app| {
        app.state.purge_expired(envelope.expires_at);
        Ok(())
    })?;
    bob = bob.restart()?;
    assert!(
        !bob.app
            .state
            .messages
            .iter()
            .any(|message| message.id == message_id)
    );
    assert!(
        !bob.app
            .state
            .message_signatures
            .contains_key(&format!("{group}/{message_id}"))
    );
    assert!(bob.app.state.conversations[&group].active);
    Ok(())
}

#[test]
fn forged_directory_rolls_back_join_and_exact_welcome_retry_is_idempotent() -> Result<()> {
    let mut alice = Profile::new("Alice", 32001)?;
    let mut bob = Profile::new("Bob", 32002)?;
    let mut carol = Profile::new("Carol", 32003)?;
    exchange(&mut alice, &mut bob)?;
    exchange(&mut alice, &mut carol)?;
    let bob_id = bob.app.id().to_string();
    let carol_id = carol.app.id().to_string();

    // Bob learns Carol from the signed group directory, not a prior direct invite.
    let group = alice.app.atomic(|app| {
        app.create_group("Signed directory".into(), vec![carol_id.clone(), bob_id])
    })?;
    deliver_pending(&mut alice, &mut carol)?;
    let original = pending_join(&alice, &bob)?;
    let mut forged = original.clone();
    if let Request::Join { contacts, .. } = &mut forged {
        let entry = contacts
            .iter_mut()
            .find(|invite| invite.contact.id == carol_id)
            .context("Carol absent from directory")?;
        entry.contact.ticket = bob.app.ticket.clone();
    } else {
        unreachable!();
    }
    let before = bob.app.state.crypto.clone();
    assert!(bob.app.handle(&alice.peer_id, forged).is_err());
    assert_eq!(bob.app.state.crypto, before);
    assert!(!bob.app.state.contacts.contains_key(&carol_id));
    assert!(!bob.app.state.conversations.contains_key(&group));

    expect_ok(bob.app.handle(&alice.peer_id, original.clone())?)?;
    assert_eq!(bob.app.state.contacts[&carol_id].ticket, carol.app.ticket);
    assert_eq!(bob.app.state.conversations[&group].members.len(), 3);
    bob = bob.restart()?;
    let after_join = bob.app.state.crypto.clone();
    let version = bob.app.state.contact_version;
    // This is the sender retrying after an ACK was lost, including across restart.
    expect_ok(bob.app.handle(&alice.peer_id, original.clone())?)?;
    assert_eq!(bob.app.state.crypto, after_join);
    assert_eq!(bob.app.state.contact_version, version);
    deliver_pending(&mut alice, &mut bob)?;
    assert!(
        alice
            .app
            .state
            .pending
            .iter()
            .all(|pending| pending.recipient != bob.app.id())
    );
    Ok(())
}

#[test]
fn recovery_retries_do_not_advance_epochs_and_accept_a_fresh_welcome() -> Result<()> {
    let mut alice = Profile::new("Alice", 33001)?;
    let mut bob = Profile::new("Bob", 33002)?;
    let mut carol = Profile::new("Carol", 33003)?;
    exchange(&mut alice, &mut bob)?;
    exchange(&mut alice, &mut carol)?;
    exchange(&mut bob, &mut carol)?;
    let bob_id = bob.app.id().to_string();
    let carol_id = carol.app.id().to_string();
    let group = alice
        .app
        .atomic(|app| app.create_group("Recovery".into(), vec![bob_id.clone(), carol_id]))?;
    let old_welcome = pending_join(&alice, &bob)?;
    deliver_pending(&mut alice, &mut bob)?;
    deliver_pending(&mut alice, &mut carol)?;
    let old_epoch = bob.app.state.conversations[&group].epoch;

    // Merely joining does not authorize a history download, even for a member
    // whose endpoint and signing identity are already trusted contacts.
    assert!(
        alice
            .app
            .handle(
                &bob.peer_id,
                Request::History {
                    conversation: group.clone(),
                    after: None
                }
            )
            .is_err()
    );
    let missed_alice = alice
        .app
        .atomic(|app| app.send(&group, "sent while Bob was offline".into()))?;
    deliver_outbox(&mut alice, &mut carol)?;
    let missed_carol = carol
        .app
        .atomic(|app| app.send(&group, "Carol's original signed message".into()))?;
    deliver_outbox(&mut carol, &mut alice)?;
    assert!(bob.app.state.messages.is_empty());
    let original_history: Vec<_> = alice
        .app
        .state
        .messages
        .iter()
        .map(|message| SignedMessage {
            message: message.clone(),
            signature: alice.app.state.message_signatures
                [&format!("{}/{}", message.conversation, message.id)]
                .clone(),
        })
        .collect();
    assert_eq!(original_history.len(), 2);

    let recovery = bob.app.atomic(|app| app.prepare_recovery(&group))?;
    let repeated = bob.app.atomic(|app| app.prepare_recovery(&group))?;
    assert_eq!(
        serde_json::to_vec(&recovery)?,
        serde_json::to_vec(&repeated)?
    );
    expect_ok(alice.app.handle(&bob.peer_id, recovery.clone())?)?;
    let recovered_epoch = alice.app.state.conversations[&group].epoch;
    assert!(recovered_epoch > old_epoch);
    let pending_before_retry = alice.app.state.pending.len();
    expect_ok(alice.app.handle(&bob.peer_id, recovery.clone())?)?;
    assert_eq!(alice.app.state.conversations[&group].epoch, recovered_epoch);
    assert_eq!(alice.app.state.pending.len(), pending_before_retry);

    alice = alice.restart()?;
    expect_ok(alice.app.handle(&bob.peer_id, recovery)?)?;
    assert_eq!(alice.app.state.conversations[&group].epoch, recovered_epoch);
    let new_welcome = pending_join(&alice, &bob)?;
    bob = bob.restart()?;
    // Missing control history is exactly why recovery exists. Accept the newer
    // owner Welcome without first applying the intermediate removal Commit.
    expect_ok(bob.app.handle(&alice.peer_id, new_welcome.clone())?)?;
    assert!(bob.app.state.conversations[&group].active);
    assert_eq!(bob.app.state.conversations[&group].epoch, recovered_epoch);
    assert!(!bob.app.state.recovery_pending.contains(&group));
    let recovered_state = bob.app.state.crypto.clone();
    expect_ok(bob.app.handle(&alice.peer_id, new_welcome)?)?;
    assert_eq!(bob.app.state.crypto, recovered_state);
    assert!(bob.app.handle(&alice.peer_id, old_welcome).is_err());
    assert_eq!(bob.app.state.crypto, recovered_state);

    // The production recovery flow queues this authenticated History request.
    // Test the owner's actual response; saving it into the recipient is ticker's job.
    bob = bob.restart()?;
    let history_request = bob.app.state.pending.iter().find(|pending| {
        pending.recipient == alice.app.id()
            && matches!(&pending.request, Request::History { conversation, after: None } if conversation == &group)
    }).context("recovery did not queue a history request")?.request.clone();
    let response = alice.app.handle(&bob.peer_id, history_request)?;
    let Response::History { messages, next } = response else {
        anyhow::bail!("expected history for the authorized recovering member");
    };
    assert!(next.is_none());
    assert_eq!(messages.len(), 2);
    for signed in &messages {
        verify_history_signature(signed)?;
        let original = original_history
            .iter()
            .find(|original| original.message.id == signed.message.id)
            .context("unexpected historical message")?;
        assert_eq!(signed.message, original.message);
        assert_eq!(signed.signature, original.signature);
        assert_eq!(
            signed.message.expires_at - signed.message.created_at,
            MESSAGE_TTL
        );
    }
    assert!(
        messages
            .iter()
            .any(|signed| signed.message.id == missed_alice)
    );
    assert!(
        messages
            .iter()
            .any(|signed| signed.message.id == missed_carol)
    );
    assert!(
        alice
            .app
            .handle(
                &carol.peer_id,
                Request::History {
                    conversation: group.clone(),
                    after: None
                }
            )
            .is_err()
    );

    let queued_carol_controls: Vec<_> = alice
        .app
        .state
        .pending
        .iter()
        .filter_map(|pending| {
            if pending.recipient != carol.app.id() {
                return None;
            }
            if let Request::Control { record } = &pending.request {
                Some(record.epoch)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(queued_carol_controls, vec![recovered_epoch]);
    assert!(recovered_epoch > carol.app.state.conversations[&group].epoch + 1);
    deliver_pending(&mut alice, &mut carol)?;
    assert_eq!(carol.app.state.conversations[&group].epoch, recovered_epoch);
    assert!(
        carol
            .app
            .state
            .controls
            .iter()
            .any(|record| record.conversation == group && record.epoch == recovered_epoch - 1)
    );
    assert!(
        carol
            .app
            .state
            .controls
            .iter()
            .any(|record| record.conversation == group && record.epoch == recovered_epoch)
    );
    let message_id = bob
        .app
        .atomic(|app| app.send(&group, "back after recovery".into()))?;
    deliver_outbox(&mut bob, &mut alice)?;
    deliver_outbox(&mut bob, &mut carol)?;
    assert!(
        alice
            .app
            .state
            .messages
            .iter()
            .any(|message| message.id == message_id)
    );
    assert!(
        carol
            .app
            .state
            .messages
            .iter()
            .any(|message| message.id == message_id)
    );
    alice.app.atomic(|app| app.remove_member(&group, &bob_id))?;
    assert!(
        alice
            .app
            .handle(
                &bob.peer_id,
                Request::History {
                    conversation: group,
                    after: None
                }
            )
            .is_err()
    );
    Ok(())
}
