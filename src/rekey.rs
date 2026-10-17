//! Periodic MLS key refresh. The coordinator remains the only Commit author;
//! other members submit authenticated Update proposals for it to commit.

use super::App;
use crate::{
    crypto::Processed,
    model::{MAX_FRAME_BYTES, Pending, Request, Response, now},
};
use anyhow::{Result, bail, ensure};

const REKEY_INTERVAL: i64 = 24 * 60 * 60;

impl App {
    /// Does no network I/O and schedules at most one group per tick. Offline
    /// coordinators delay member updates; a queued proposal is not a completed rekey.
    pub fn maybe_rekey(&mut self, time: i64) -> Result<()> {
        let own = self.id().to_owned();
        let next = self
            .state
            .conversations
            .values()
            .find(|group| {
                group.active
                    && !self.state.recovery_pending.contains(&group.id)
                    && !self.state.pending_updates.contains_key(&group.id)
                    && self
                        .state
                        .last_rekey
                        .get(&group.id)
                        .is_none_or(|last| time.saturating_sub(*last) >= REKEY_INTERVAL)
            })
            .cloned();
        let Some(group) = next else {
            return Ok(());
        };
        self.atomic(|app| {
            if group.owner == own {
                app.owner_group(&group.id)?;
                let commit = app.crypto.commit_updates(&group.id)?;
                app.record_commit(&group.id, commit, &group.members, Vec::new())?;
            } else {
                let proposal = app.crypto.propose_update(&group.id)?;
                app.state
                    .pending_updates
                    .insert(group.id.clone(), proposal.clone());
                app.state.pending.push(Pending {
                    recipient: group.owner.clone(),
                    request: Request::Update {
                        conversation: group.id.clone(),
                        proposal,
                    },
                });
            }
            app.state.last_rekey.insert(group.id.clone(), time);
            Ok(())
        })
    }

    pub fn accept_update(
        &mut self,
        peer: &str,
        conversation: &str,
        proposal: Vec<u8>,
    ) -> Result<Response> {
        ensure!(
            !proposal.is_empty() && proposal.len() <= MAX_FRAME_BYTES,
            "invalid Update size"
        );
        let peer_identity = self.known_peer(peer)?;
        let group = self.owner_group(conversation)?;
        ensure!(
            peer_identity != self.id() && group.members.contains(&peer_identity),
            "Update peer is not a current member"
        );

        // An ACK may be lost after committing. The authenticated bytes in this
        // archive were already verified before their first acceptance. Repeating
        // them grants no authority and must not create another Commit.
        if self.state.controls.iter().any(|record| {
            record.conversation == conversation
                && record
                    .proposals
                    .iter()
                    .any(|accepted| accepted == &proposal)
        }) {
            return Ok(Response::Ok);
        }

        self.atomic(|app| {
            match app.crypto.process(conversation, &proposal, &group.owner)? {
                Processed::Proposal { sender } => ensure!(
                    sender == peer_identity,
                    "Update sender does not match the authenticated transport peer"
                ),
                _ => bail!("expected an MLS Update proposal"),
            }
            let commit = app.crypto.commit_updates(conversation)?;
            // Other recipients may have been offline when the proposal was
            // created. Retain it with the Commit so every reference is resolvable.
            app.record_commit(conversation, commit, &group.members, vec![proposal])?;
            app.state.last_rekey.insert(conversation.to_owned(), now());
            Ok(Response::Ok)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::Store,
        transport::{encode_ticket, ticket_endpoint_id},
    };

    fn profile(directory: &std::path::Path, name: &str) -> App {
        let store =
            Store::create(&directory.join(format!("{name}.db")), "rekey test password").unwrap();
        let mut app = App::initialize(store, name.to_owned()).unwrap();
        let seed: [u8; 32] = app.state.transport_secret.as_slice().try_into().unwrap();
        let addr = iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&seed).public())
            .with_ip_addr("127.0.0.1:9".parse().unwrap());
        app.ticket = encode_ticket(&addr).unwrap();
        app
    }

    fn join_request(owner: &App, group: &str) -> Request {
        owner
            .state
            .pending
            .iter()
            .rev()
            .find_map(|pending| match &pending.request {
                Request::Join { conversation, .. } if conversation.id == group => {
                    Some(pending.request.clone())
                }
                _ => None,
            })
            .unwrap()
    }

    fn pair_group(owner: &mut App, member: &mut App, name: &str) -> String {
        owner
            .atomic(|app| app.import_contact(member.invitation().unwrap()))
            .unwrap();
        member
            .atomic(|app| app.import_contact(owner.invitation().unwrap()))
            .unwrap();
        let member_id = member.id().to_owned();
        let group = owner
            .atomic(|app| app.create_group(name.to_owned(), vec![member_id]))
            .unwrap();
        member
            .handle(
                &ticket_endpoint_id(&owner.ticket).unwrap(),
                join_request(owner, &group),
            )
            .unwrap();
        group
    }

    #[test]
    fn daily_owner_refresh_advances_only_one_group_per_tick() {
        let directory = tempfile::tempdir().unwrap();
        let mut owner = profile(directory.path(), "owner");
        for name in ["one", "two", "three"] {
            owner
                .atomic(|app| app.create_group(name.to_owned(), Vec::new()))
                .unwrap();
        }
        let time = now();
        for expected_refreshed in 1..=3 {
            owner.maybe_rekey(time).unwrap();
            assert_eq!(
                owner
                    .state
                    .conversations
                    .values()
                    .filter(|group| group.epoch == 1)
                    .count(),
                expected_refreshed
            );
        }
        owner.maybe_rekey(time + REKEY_INTERVAL - 1).unwrap();
        assert!(
            owner
                .state
                .conversations
                .values()
                .all(|group| group.epoch == 1)
        );
        owner.maybe_rekey(time + REKEY_INTERVAL).unwrap();
        assert_eq!(
            owner
                .state
                .conversations
                .values()
                .filter(|group| group.epoch == 2)
                .count(),
            1
        );
    }

    #[test]
    fn member_refresh_is_persisted_committed_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let mut owner = profile(directory.path(), "owner");
        let mut member = profile(directory.path(), "member");
        let group = pair_group(&mut owner, &mut member, "pair");
        let owner_peer = ticket_endpoint_id(&owner.ticket).unwrap();
        let member_peer = ticket_endpoint_id(&member.ticket).unwrap();

        let time = now() + REKEY_INTERVAL;
        member.maybe_rekey(time).unwrap();
        let proposal = member.state.pending_updates.get(&group).unwrap().clone();
        let persisted = member.store.load_state().unwrap().unwrap();
        assert_eq!(persisted.pending_updates.get(&group), Some(&proposal));
        let queued = member.state.pending.len();
        member.maybe_rekey(time + REKEY_INTERVAL).unwrap();
        assert_eq!(
            member.state.pending.len(),
            queued,
            "a pending proposal must not be regenerated"
        );
        assert!(
            owner
                .accept_update("unknown-peer", &group, proposal.clone())
                .is_err()
        );

        assert!(matches!(
            owner
                .accept_update(&member_peer, &group, proposal.clone())
                .unwrap(),
            Response::Ok
        ));
        let epoch = owner.crypto.epoch(&group).unwrap();
        let record = owner.state.controls.last().unwrap().clone();
        assert_eq!(record.proposals, vec![proposal.clone()]);
        assert!(matches!(
            owner.accept_update(&member_peer, &group, proposal).unwrap(),
            Response::Ok
        ));
        assert_eq!(
            owner.crypto.epoch(&group).unwrap(),
            epoch,
            "retry must not create an extra epoch"
        );
        member
            .handle(&owner_peer, Request::Control { record })
            .unwrap();
        assert!(!member.state.pending_updates.contains_key(&group));
        assert!(
            !member
                .state
                .pending
                .iter()
                .any(|pending| matches!(&pending.request,
            Request::Update { conversation, .. } if conversation == &group))
        );
        assert_eq!(member.crypto.epoch(&group).unwrap(), epoch);
        let message = member
            .crypto
            .encrypt(&group, b"after scheduled rekey")
            .unwrap();
        let owner_id = owner.id().to_owned();
        match owner.crypto.process(&group, &message, &owner_id).unwrap() {
            Processed::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"after scheduled rekey")
            }
            _ => panic!("expected application message"),
        }
    }

    #[test]
    fn concurrent_group_recovery_keeps_distinct_packages_and_clears_old_updates() {
        let directory = tempfile::tempdir().unwrap();
        let mut owner = profile(directory.path(), "owner");
        let mut member = profile(directory.path(), "member");
        let first = pair_group(&mut owner, &mut member, "first");
        let second = pair_group(&mut owner, &mut member, "second");
        let owner_peer = ticket_endpoint_id(&owner.ticket).unwrap();
        let member_peer = ticket_endpoint_id(&member.ticket).unwrap();
        let old_second_welcome = join_request(&owner, &second);
        member.maybe_rekey(now() + REKEY_INTERVAL).unwrap();
        assert_eq!(member.state.pending_updates.len(), 1);

        let queue_recovery = |app: &mut App, group: &str| {
            app.atomic(|app| {
                let request = app.prepare_recovery(group)?;
                app.state.pending.push(Pending {
                    recipient: app.state.conversations[group].owner.clone(),
                    request: request.clone(),
                });
                Ok(request)
            })
            .unwrap()
        };
        let request_first = queue_recovery(&mut member, &first);
        let request_second = queue_recovery(&mut member, &second);
        let package_first = member.state.recovery_packages[&first].clone();
        let package_second = member.state.recovery_packages[&second].clone();
        assert_ne!(package_first, package_second);
        assert!(member.state.pending_updates.is_empty());
        assert!(
            !member
                .state
                .pending
                .iter()
                .any(|p| matches!(&p.request, Request::Update { .. }))
        );

        // A separate caller obtaining a fresh invitation must not replace either
        // group's outstanding recovery material.
        member
            .handle(
                &owner_peer,
                Request::KeyPackage {
                    request_id: "another-operation".into(),
                },
            )
            .unwrap();
        let retried = queue_recovery(&mut member, &first);
        match retried {
            Request::Recover { key_package, .. } => assert_eq!(key_package, package_first),
            _ => panic!("expected recovery request"),
        }
        assert_eq!(
            member
                .store
                .load_state()
                .unwrap()
                .unwrap()
                .recovery_packages[&second],
            package_second
        );

        owner.handle(&member_peer, request_first).unwrap();
        member
            .handle(&owner_peer, join_request(&owner, &first))
            .unwrap();
        assert!(!member.state.recovery_packages.contains_key(&first));
        assert!(!member.state.pending_updates.contains_key(&first));
        assert!(member.state.last_rekey.contains_key(&first));
        owner.handle(&member_peer, request_second).unwrap();
        let latest_second_welcome = join_request(&owner, &second);
        member
            .handle(&owner_peer, latest_second_welcome.clone())
            .unwrap();
        assert!(member.state.recovery_packages.is_empty());
        assert!(member.state.recovery_pending.is_empty());
        assert_eq!(
            member.crypto.epoch(&first).unwrap(),
            owner.crypto.epoch(&first).unwrap()
        );
        assert_eq!(
            member.crypto.epoch(&second).unwrap(),
            owner.crypto.epoch(&second).unwrap()
        );

        // A later kick revokes recovery permission even if the member presents a
        // valid identity and fresh KeyPackage. An old Welcome cannot undo it.
        let member_id = member.id().to_owned();
        owner
            .atomic(|app| app.remove_member(&second, &member_id))
            .unwrap();
        let remove = owner.state.controls.last().unwrap().clone();
        member
            .handle(&owner_peer, Request::Control { record: remove })
            .unwrap();
        assert!(!member.state.conversations[&second].active);
        let before = owner.crypto.snapshot().unwrap();
        let package = member.atomic(|app| app.crypto.key_package()).unwrap();
        assert!(
            owner
                .handle(
                    &member_peer,
                    Request::Recover {
                        conversation: second.clone(),
                        key_package: package
                    }
                )
                .is_err()
        );
        assert_eq!(owner.crypto.snapshot().unwrap(), before);
        assert!(member.handle(&owner_peer, old_second_welcome).is_err());
        assert!(!member.state.conversations[&second].active);
        assert!(matches!(
            member.handle(&owner_peer, latest_second_welcome).unwrap(),
            Response::Ok
        ));
        assert!(
            !member.state.conversations[&second].active,
            "an idempotent Welcome ACK must not reactivate a removed member"
        );
    }

    #[test]
    fn failed_app_save_rolls_back_commit_and_outbox_together() {
        let directory = tempfile::tempdir().unwrap();
        let mut owner = profile(directory.path(), "owner");
        let group = owner
            .atomic(|app| app.create_group("rollback".into(), Vec::new()))
            .unwrap();
        let before_crypto = owner.crypto.snapshot().unwrap();
        let before_state = serde_json::to_vec(&owner.state).unwrap();
        let error = owner.atomic(|app| {
            let commit = app.crypto.commit_updates(&group)?;
            app.record_commit(&group, commit, &[], Vec::new())?;
            // JSON encodes each 255 in four bytes. This exceeds save's 32 MiB
            // admission bound after the commit has been merged in memory.
            app.state.pending.push(Pending {
                recipient: app.id().to_owned(),
                request: Request::Update {
                    conversation: group.clone(),
                    proposal: vec![255; 9 * 1024 * 1024],
                },
            });
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(owner.crypto.snapshot().unwrap(), before_crypto);
        assert_eq!(serde_json::to_vec(&owner.state).unwrap(), before_state);
        let persisted = owner.store.load_state().unwrap().unwrap();
        assert_eq!(persisted.crypto, before_crypto);
        assert!(persisted.pending.is_empty());
    }

    #[test]
    fn identity_signature_cannot_claim_someone_elses_transport_endpoint() {
        use ed25519_dalek::{Signer, SigningKey};

        let directory = tempfile::tempdir().unwrap();
        let attacker = profile(directory.path(), "attacker");
        let victim = profile(directory.path(), "victim");
        let mut forged = attacker.invitation().unwrap();
        super::super::verify_invitation(&forged).unwrap();
        forged.contact.ticket = victim.ticket.clone();
        let bytes = serde_json::to_vec(&(forged.version, &forged.contact)).unwrap();
        let identity_seed: [u8; 32] = attacker
            .state
            .identity_secret
            .as_slice()
            .try_into()
            .unwrap();
        forged.signature = SigningKey::from_bytes(&identity_seed)
            .sign(&bytes)
            .to_bytes()
            .to_vec();
        assert!(super::super::verify_invitation(&forged).is_err());

        // Even re-signing both fields using the attacker's real private keys
        // cannot prove possession of the victim's advertised transport key.
        let transport_seed: [u8; 32] = attacker
            .state
            .transport_secret
            .as_slice()
            .try_into()
            .unwrap();
        forged.transport_signature = SigningKey::from_bytes(&transport_seed)
            .sign(&bytes)
            .to_bytes()
            .to_vec();
        assert!(super::super::verify_invitation(&forged).is_err());
    }
}
