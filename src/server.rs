//! An independent ciphertext service: transport keys and public ACLs, never MLS
//! or chat identity secrets. Every request uses the authenticated transport peer.

use anyhow::{Context, Result, bail, ensure};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    model::{Request, Response, now},
    server_protocol::{
        HostedControl, ServerInvitation, ServerRequest, ServerResponse, SignedGroupConfig,
        SignedInboxRecord, validate_hex32,
    },
    storage::{RELAY_TOTAL_BYTES, Store},
    transport::ticket_endpoint_id,
};

#[derive(Serialize, Deserialize)]
struct ServerState {
    version: u32,
    transport_secret: [u8; 32],
    provisioning_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        media::MediaChunk,
        model::{ControlRecord, Envelope, MESSAGE_TTL},
        server_protocol::{
            GroupConfig, MailboxBinding, ServerMember, SignedGroupControl, SignedMailboxBinding,
        },
    };

    const PASSWORD: &str = "server regression passphrase";

    fn identity(seed: u8) -> String {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn endpoint(seed: u8) -> String {
        iroh::SecretKey::from_bytes(&[seed; 32])
            .public()
            .to_string()
    }

    fn member(seed: u8) -> ServerMember {
        ServerMember {
            identity: identity(seed),
            endpoint: endpoint(seed + 20),
            joined_epoch: 0,
        }
    }

    fn config(
        server: &Server,
        group: &str,
        revision: u64,
        epoch: u64,
        seeds: &[u8],
    ) -> SignedGroupConfig {
        let members: Vec<_> = seeds.iter().copied().map(member).collect();
        let mut removal_epochs = std::collections::BTreeMap::new();
        if let Some(previous) = server.store.server_group(group).unwrap() {
            removal_epochs = previous.config.removal_epochs;
            for old in previous.config.members {
                if !members.iter().any(|member| member.identity == old.identity) {
                    removal_epochs.insert(old.identity, epoch);
                }
            }
        }
        removal_epochs
            .retain(|identity, _| !members.iter().any(|member| &member.identity == identity));
        SignedGroupConfig::sign(
            GroupConfig {
                server_id: server.id(),
                group_id: group.into(),
                owner: identity(1),
                revision,
                epoch,
                members,
                removal_epochs,
            },
            &[1; 32],
        )
        .unwrap()
    }

    fn send(server: &mut Server, peer: u8, request: ServerRequest, time: i64) -> Result<Response> {
        server.handle_at(&endpoint(peer + 20), Request::Server(request), time)
    }

    fn configure(server: &mut Server, config: SignedGroupConfig, time: i64) -> Result<Response> {
        let provisioning_token = server.state.provisioning_token.clone();
        send(
            server,
            1,
            ServerRequest::ConfigureGroup {
                provisioning_token,
                config,
            },
            time,
        )
    }

    fn envelope(group: &str, id: &str, time: i64) -> Envelope {
        Envelope {
            id: id.into(),
            conversation: group.into(),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![255; 1024],
        }
    }

    fn control(server: &Server, group: &str, epoch: u64, time: i64) -> SignedGroupControl {
        SignedGroupControl {
            server_id: server.id(),
            owner: identity(1),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            record: ControlRecord {
                conversation: group.into(),
                epoch,
                commit: vec![epoch as u8; 32],
                proposals: Vec::new(),
            },
            signature: Vec::new(),
        }
        .sign(&[1; 32])
        .unwrap()
    }

    fn inbox(server: &Server, _id: &str, epoch: u64, time: i64) -> SignedInboxRecord {
        let mut record = SignedInboxRecord {
            server_id: server.id(),
            id: String::new(),
            group_id: "group-a".into(),
            sender: identity(1),
            recipient: identity(2),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            control: HostedControl::Control {
                record: control(server, "group-a", epoch, time).record,
            },
            signature: Vec::new(),
        };
        record.id = record.canonical_id().unwrap();
        record.sign(&[1; 32]).unwrap()
    }

    #[test]
    fn personal_binding_survives_restart_and_rejects_endpoint_and_revision_replays() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("server.db");
        let mut server = Server::initialize(Store::create(&path, PASSWORD)?)?;
        assert!(server.store.load_state()?.is_none());
        let time = now();
        let id = server.id();
        let token = server.state.provisioning_token.clone();
        let bind = |revision, endpoint| {
            SignedMailboxBinding::sign(
                MailboxBinding {
                    server_id: id.clone(),
                    identity: identity(1),
                    endpoint,
                    revision,
                },
                &[1; 32],
            )
            .unwrap()
        };
        let request = |binding| {
            Request::Server(ServerRequest::BindMailbox {
                provisioning_token: token.clone(),
                binding,
            })
        };
        assert!(
            server
                .handle_at(&endpoint(21), Request::Allocate, time)
                .is_err()
        );
        assert!(
            server
                .handle_at(&endpoint(22), request(bind(1, endpoint(21))), time)
                .is_err()
        );
        assert!(
            server
                .handle_at(
                    &endpoint(21),
                    Request::Server(ServerRequest::BindMailbox {
                        provisioning_token: hex::encode([0; 32]),
                        binding: bind(1, endpoint(21)),
                    }),
                    time
                )
                .is_err()
        );
        let response = server.handle_at(&endpoint(21), request(bind(1, endpoint(21))), time)?;
        let Response::Mailbox {
            mailbox_id,
            write_token,
            read_token,
        } = response
        else {
            panic!("mailbox response")
        };
        let allocations = server.store.server_mailbox_count()?;
        for seed in 2..=5 {
            let conflicting = SignedMailboxBinding::sign(
                MailboxBinding {
                    server_id: id.clone(),
                    identity: identity(seed),
                    endpoint: endpoint(21),
                    revision: 1,
                },
                &[seed; 32],
            )?;
            assert!(
                server
                    .handle_at(&endpoint(21), request(conflicting), time)
                    .is_err()
            );
            assert_eq!(
                server.store.server_mailbox_count()?,
                allocations,
                "rejected bindings must not leave orphan mailbox allocations"
            );
        }
        let repeated = server.handle_at(&endpoint(21), request(bind(1, endpoint(21))), time)?;
        assert!(
            matches!(repeated, Response::Mailbox { mailbox_id: ref repeated_id, .. } if repeated_id == &mailbox_id)
        );
        server.handle_at(
            &endpoint(22),
            Request::Store {
                mailbox_id: mailbox_id.clone(),
                write_token,
                envelope: envelope("private", "message", time),
            },
            time,
        )?;
        let fetch = || Request::Fetch {
            mailbox_id: mailbox_id.clone(),
            read_token: read_token.clone(),
        };
        assert!(server.handle_at(&endpoint(22), fetch(), time).is_err());
        assert!(
            server
                .handle_at(&endpoint(22), request(bind(1, endpoint(22))), time)
                .is_err()
        );
        server.handle_at(&endpoint(22), request(bind(2, endpoint(22))), time)?;
        assert!(server.handle_at(&endpoint(21), fetch(), time).is_err());
        assert!(
            server
                .handle_at(&endpoint(21), request(bind(1, endpoint(21))), time)
                .is_err()
        );
        assert!(
            server
                .handle_at(
                    &endpoint(21),
                    Request::Delete {
                        mailbox_id: mailbox_id.clone(),
                        read_token: read_token.clone(),
                        ids: vec!["message".into()],
                    },
                    time
                )
                .is_err()
        );
        drop(server);
        let mut server = Server::load(Store::open(&path, PASSWORD)?)?;
        assert_eq!(server.id(), id);
        assert_eq!(server.state.provisioning_token, token);
        assert!(server.store.load_state()?.is_none());
        assert!(
            matches!(server.handle_at(&endpoint(22), fetch(), time)?, Response::Envelopes(ref page) if page.len() == 1)
        );
        server.purge(time + MESSAGE_TTL)?;
        assert!(
            matches!(server.handle_at(&endpoint(22), fetch(), time + MESSAGE_TTL)?, Response::Envelopes(ref page) if page.is_empty())
        );
        Ok(())
    }

    #[test]
    fn group_pages_are_durable_ordered_deduplicated_and_group_scoped() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("server.db");
        let mut server = Server::initialize(Store::create(&path, PASSWORD)?)?;
        let time = now();
        let first = config(&server, "group-a", 1, 1, &[1, 2]);
        configure(&mut server, first.clone(), time)?;
        configure(&mut server, first, time)?;
        let another = config(&server, "group-b", 1, 1, &[1, 3]);
        configure(&mut server, another, time)?;
        assert!(
            send(
                &mut server,
                3,
                ServerRequest::GroupFetch {
                    group_id: "group-a".into(),
                    after: 0
                },
                time
            )
            .is_err()
        );
        assert!(
            send(
                &mut server,
                2,
                ServerRequest::GroupPut {
                    group_id: "group-a".into(),
                    envelope: envelope("group-b", "wrong", time),
                },
                time
            )
            .is_err()
        );
        let mut crypto = crate::crypto::CryptoEngine::new(&[1; 32])?;
        crypto.create_group("group-a")?;
        for index in 0..3 {
            let mut message = envelope("group-a", &format!("m{index}"), time);
            message.ciphertext = crypto.encrypt("group-a", &vec![255; 64 * 1024])?;
            let request = ServerRequest::GroupPut {
                group_id: "group-a".into(),
                envelope: message.clone(),
            };
            send(&mut server, 2, request.clone(), time)?;
            send(&mut server, 2, request, time)?;
            message.ciphertext[0] ^= 1;
            assert!(
                send(
                    &mut server,
                    2,
                    ServerRequest::GroupPut {
                        group_id: "group-a".into(),
                        envelope: message
                    },
                    time
                )
                .is_err()
            );
        }
        drop(server);
        let mut server = Server::load(Store::open(&path, PASSWORD)?)?;
        let mut after = 0;
        for index in 0..3 {
            let response = send(
                &mut server,
                1,
                ServerRequest::GroupFetch {
                    group_id: "group-a".into(),
                    after,
                },
                time,
            )?;
            let Response::Server(ServerResponse::GroupPage { envelopes, next }) = response else {
                panic!("group page")
            };
            assert_eq!(
                envelopes.len(),
                1,
                "a large first record must still make page progress"
            );
            assert_eq!(envelopes[0].envelope.id, format!("m{index}"));
            assert_eq!(next, envelopes[0].sequence);
            assert!(next > after);
            after = next;
        }
        assert!(
            matches!(send(&mut server, 1, ServerRequest::GroupFetch { group_id: "group-a".into(), after }, time)?,
            Response::Server(ServerResponse::GroupPage { ref envelopes, next }) if envelopes.is_empty() && next == after)
        );
        assert_eq!(server.status()?.envelopes, 3);
        let delayed = crypto.encrypt("group-a", b"created before the new member joined")?;
        let mut newcomer = crate::crypto::CryptoEngine::new(&[3; 32])?;
        crypto.add_member("group-a", &newcomer.key_package()?)?;
        let mut joined = config(&server, "group-a", 2, crypto.epoch("group-a")?, &[1, 2, 3]).config;
        joined
            .members
            .iter_mut()
            .find(|member| member.identity == identity(3))
            .unwrap()
            .joined_epoch = crypto.epoch("group-a")?;
        configure(
            &mut server,
            SignedGroupConfig::sign(joined, &[1; 32])?,
            time,
        )?;
        for (id, ciphertext) in [
            ("late-old", delayed),
            ("new", crypto.encrypt("group-a", b"current member message")?),
        ] {
            let mut message = envelope("group-a", id, time);
            message.ciphertext = ciphertext;
            send(
                &mut server,
                1,
                ServerRequest::GroupPut {
                    group_id: "group-a".into(),
                    envelope: message,
                },
                time,
            )?;
        }
        assert!(
            matches!(send(&mut server, 3, ServerRequest::GroupFetch { group_id: "group-a".into(), after: 0 }, time)?,
            Response::Server(ServerResponse::GroupPage { ref envelopes, next })
                if envelopes.len() == 1 && envelopes[0].envelope.id == "new" && next == envelopes[0].sequence),
            "new members must not receive older MLS epochs, even when those uploads arrive after their admission"
        );
        server.purge(time + MESSAGE_TTL)?;
        assert_eq!(server.status()?.envelopes, 0);
        Ok(())
    }

    #[test]
    fn removal_blocks_messages_and_blobs_but_allows_only_prior_commit_chain() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut server = Server::initialize(Store::create(
            &directory.path().join("server.db"),
            PASSWORD,
        )?)?;
        let time = now();
        let initial = config(&server, "group-a", 1, 1, &[1, 2]);
        configure(&mut server, initial.clone(), time)?;
        let read_token = hex::encode([13; 32]);
        let chunk = MediaChunk {
            media_id: hex::encode([12; 32]),
            index: 0,
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            ciphertext: vec![7; 32],
        };
        send(
            &mut server,
            1,
            ServerRequest::GroupBlobPut {
                group_id: "group-a".into(),
                read_token: read_token.clone(),
                chunk: chunk.clone(),
            },
            time,
        )?;
        let blob = || ServerRequest::GroupBlobGet {
            group_id: "group-a".into(),
            media_id: chunk.media_id.clone(),
            index: 0,
            read_token: read_token.clone(),
        };
        assert!(matches!(
            send(&mut server, 2, blob(), time)?,
            Response::Blob(Some(_))
        ));
        assert!(
            server
                .handle_at(
                    &endpoint(22),
                    Request::BlobGet {
                        media_id: chunk.media_id.clone(),
                        index: 0,
                        read_token: read_token.clone(),
                    },
                    time
                )
                .is_err()
        );
        let old_inbox = inbox(&server, "old", 1, time);
        send(
            &mut server,
            1,
            ServerRequest::InboxPut { record: old_inbox },
            time,
        )?;
        let mut latest = config(&server, "group-a", 2, 2, &[1]).config;
        latest.revision = 3;
        latest.epoch = 3;
        // The server missed the intermediate removal config while offline.
        // Its cutoff must still be the signed epoch 2, never observed epoch 3.
        configure(
            &mut server,
            SignedGroupConfig::sign(latest, &[1; 32])?,
            time,
        )?;
        assert!(configure(&mut server, initial, time).is_err());
        for epoch in 1..=3 {
            let signed = control(&server, "group-a", epoch, time);
            send(
                &mut server,
                1,
                ServerRequest::GroupControlPut { control: signed },
                time,
            )?;
        }
        assert!(send(&mut server, 2, blob(), time).is_err());
        assert!(
            send(
                &mut server,
                2,
                ServerRequest::GroupFetch {
                    group_id: "group-a".into(),
                    after: 0
                },
                time
            )
            .is_err()
        );
        let response = send(
            &mut server,
            2,
            ServerRequest::GroupControls {
                group_id: "group-a".into(),
                after_epoch: 0,
            },
            time,
        )?;
        assert!(
            matches!(response, Response::Server(ServerResponse::Controls { ref records, current_epoch: 2 })
            if records.iter().map(|record| record.record.epoch).collect::<Vec<_>>() == vec![1,2])
        );
        let removal = inbox(&server, "removal", 2, time);
        let removal_id = removal.id.clone();
        send(
            &mut server,
            1,
            ServerRequest::InboxPut {
                record: removal.clone(),
            },
            time,
        )?;
        let later = inbox(&server, "later", 3, time);
        assert!(
            send(
                &mut server,
                1,
                ServerRequest::InboxPut { record: later },
                time
            )
            .is_err()
        );
        send(
            &mut server,
            3,
            ServerRequest::InboxAck {
                ids: vec![removal_id.clone()],
            },
            time,
        )?;
        assert!(
            matches!(send(&mut server, 2, ServerRequest::InboxFetch, time)?,
            Response::Server(ServerResponse::Inbox { ref records }) if records.len() == 1 && records[0].id == removal_id)
        );
        send(
            &mut server,
            2,
            ServerRequest::InboxAck {
                ids: vec![removal_id],
            },
            time,
        )?;
        send(
            &mut server,
            1,
            ServerRequest::InboxPut { record: removal },
            time,
        )?;
        assert!(
            matches!(send(&mut server, 2, ServerRequest::InboxFetch, time)?,
            Response::Server(ServerResponse::Inbox { ref records }) if records.is_empty())
        );
        server.purge(time + MESSAGE_TTL)?;
        assert_eq!(server.status()?.used_bytes, 0);
        Ok(())
    }

    #[test]
    fn another_group_owner_cannot_reserve_a_pending_inbox_id() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut server = Server::initialize(Store::create(
            &directory.path().join("server.db"),
            PASSWORD,
        )?)?;
        let time = now();
        let legitimate = config(&server, "group-a", 1, 1, &[1, 2]);
        configure(&mut server, legitimate, time)?;
        let attacker_config = SignedGroupConfig::sign(
            GroupConfig {
                server_id: server.id(),
                group_id: "attacker-group".into(),
                owner: identity(3),
                revision: 1,
                epoch: 1,
                members: vec![member(3)],
                removal_epochs: Default::default(),
            },
            &[3; 32],
        )?;
        let token = server.state.provisioning_token.clone();
        send(
            &mut server,
            3,
            ServerRequest::ConfigureGroup {
                provisioning_token: token,
                config: attacker_config,
            },
            time,
        )?;
        let legitimate = inbox(&server, "legitimate", 1, time);
        let mut attacker = SignedInboxRecord {
            server_id: server.id(),
            id: legitimate.id.clone(),
            group_id: "attacker-group".into(),
            sender: identity(3),
            recipient: identity(3),
            created_at: time,
            expires_at: time + MESSAGE_TTL,
            control: HostedControl::Control {
                record: ControlRecord {
                    conversation: "attacker-group".into(),
                    epoch: 1,
                    commit: vec![1],
                    proposals: vec![],
                },
            },
            signature: Vec::new(),
        }
        .sign(&[3; 32])?;
        assert!(
            send(
                &mut server,
                3,
                ServerRequest::InboxPut {
                    record: attacker.clone()
                },
                time
            )
            .is_err()
        );
        assert_eq!(server.status()?.pending_controls, 0);
        attacker.id = attacker.canonical_id()?;
        let attacker = attacker.sign(&[3; 32])?;
        send(
            &mut server,
            3,
            ServerRequest::InboxPut {
                record: attacker.clone(),
            },
            time,
        )?;
        send(
            &mut server,
            1,
            ServerRequest::InboxPut {
                record: legitimate.clone(),
            },
            time,
        )?;
        send(
            &mut server,
            2,
            ServerRequest::InboxAck {
                ids: vec![legitimate.id.clone()],
            },
            time,
        )?;
        send(
            &mut server,
            1,
            ServerRequest::InboxPut { record: legitimate },
            time,
        )?;
        assert!(
            matches!(send(&mut server, 2, ServerRequest::InboxFetch, time)?,
            Response::Server(ServerResponse::Inbox { ref records }) if records.is_empty())
        );
        assert!(
            matches!(send(&mut server, 3, ServerRequest::InboxFetch, time)?,
            Response::Server(ServerResponse::Inbox { ref records }) if records.len() == 1 && records[0].id == attacker.id)
        );
        Ok(())
    }

    #[test]
    fn owner_signatures_bind_deployment_endpoint_and_config_revision() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut server = Server::initialize(Store::create(
            &directory.path().join("server.db"),
            PASSWORD,
        )?)?;
        let time = now();
        let initial = config(&server, "group-a", 1, 1, &[1, 2]);
        let token = server.state.provisioning_token.clone();
        assert!(
            send(
                &mut server,
                2,
                ServerRequest::ConfigureGroup {
                    provisioning_token: token.clone(),
                    config: initial.clone()
                },
                time
            )
            .is_err()
        );
        let mut tampered = initial.clone();
        tampered.config.members[1].endpoint = endpoint(23);
        assert!(configure(&mut server, tampered, time).is_err());
        let mut other_deployment = initial.config.clone();
        other_deployment.server_id = endpoint(99);
        assert!(
            configure(
                &mut server,
                SignedGroupConfig::sign(other_deployment, &[1; 32])?,
                time
            )
            .is_err()
        );
        configure(&mut server, initial.clone(), time)?;
        let mut conflicting = initial.config;
        conflicting.members = vec![member(1)];
        assert!(
            configure(
                &mut server,
                SignedGroupConfig::sign(conflicting, &[1; 32])?,
                time
            )
            .is_err()
        );
        let signed = control(&server, "group-a", 1, time);
        assert!(
            send(
                &mut server,
                2,
                ServerRequest::GroupControlPut {
                    control: signed.clone()
                },
                time
            )
            .is_err()
        );
        send(
            &mut server,
            1,
            ServerRequest::GroupControlPut {
                control: signed.clone(),
            },
            time,
        )?;
        let mut conflicting = signed;
        conflicting.record.commit[0] ^= 1;
        let conflicting = conflicting.sign(&[1; 32])?;
        assert!(
            send(
                &mut server,
                1,
                ServerRequest::GroupControlPut {
                    control: conflicting
                },
                time
            )
            .is_err()
        );
        Ok(())
    }
}

impl Drop for ServerState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.transport_secret.zeroize();
        self.provisioning_token.zeroize();
    }
}

pub struct Server {
    store: Store,
    state: ServerState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub server_id: String,
    pub groups: usize,
    pub personal_mailboxes: usize,
    pub envelopes: usize,
    pub media_chunks: usize,
    pub pending_controls: usize,
    pub used_bytes: usize,
    pub capacity_bytes: usize,
}

impl Server {
    pub fn initialize(store: Store) -> Result<Self> {
        let mut secret = [0u8; 32];
        let mut token = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut secret);
        OsRng.fill_bytes(&mut token[..]);
        let state = ServerState {
            version: 1,
            transport_secret: secret,
            provisioning_token: hex::encode(&token[..]),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&state)?);
        store.server_initialize(&bytes)?;
        Ok(Self { store, state })
    }

    pub fn load(store: Store) -> Result<Self> {
        let bytes = Zeroizing::new(store.server_load()?);
        let state: ServerState = serde_json::from_slice(&bytes)?;
        ensure!(state.version == 1, "unsupported server state version");
        validate_hex32(&state.provisioning_token)?;
        let server = Self { store, state };
        server.purge(now())?;
        Ok(server)
    }

    pub fn transport_secret(&self) -> Result<[u8; 32]> {
        Ok(self.state.transport_secret)
    }

    pub fn id(&self) -> String {
        iroh::SecretKey::from_bytes(&self.state.transport_secret)
            .public()
            .to_string()
    }

    pub fn invitation(&self, ticket: &str) -> Result<ServerInvitation> {
        ensure!(
            ticket_endpoint_id(ticket)? == self.id(),
            "server ticket endpoint mismatch"
        );
        Ok(ServerInvitation {
            ticket: ticket.to_owned(),
            provisioning_token: self.state.provisioning_token.clone(),
        })
    }

    pub fn status(&self) -> Result<ServerStatus> {
        let (groups, personal_mailboxes, envelopes, media_chunks, pending_controls, used_bytes) =
            self.store.server_counts()?;
        Ok(ServerStatus {
            server_id: self.id(),
            groups,
            personal_mailboxes,
            envelopes,
            media_chunks,
            pending_controls,
            used_bytes,
            capacity_bytes: RELAY_TOTAL_BYTES,
        })
    }

    pub fn purge(&self, time: i64) -> Result<usize> {
        self.store.server_purge(time)
    }

    pub fn handle(&mut self, peer: &str, request: Request) -> Result<Response> {
        self.handle_at(peer, request, now())
    }

    fn handle_at(&mut self, peer: &str, request: Request, time: i64) -> Result<Response> {
        validate_hex32(peer)?;
        self.purge(time)?;
        match request {
            Request::Server(request) => self.handle_server(peer, request, time),
            Request::Store {
                mailbox_id,
                write_token,
                envelope,
            } => {
                self.store.server_personal_owner(&mailbox_id, None)?;
                envelope.validate(time)?;
                self.store
                    .server_check_envelope_capacity(&mailbox_id, &envelope)?;
                self.store
                    .store(&mailbox_id, &write_token, &envelope, time)?;
                Ok(Response::Ok)
            }
            Request::Fetch {
                mailbox_id,
                read_token,
            } => {
                let owner = self.store.server_personal_owner(&mailbox_id, Some(peer))?;
                Ok(Response::Envelopes(self.store.fetch(
                    &mailbox_id,
                    &read_token,
                    &owner,
                    time,
                )?))
            }
            Request::Delete {
                mailbox_id,
                read_token,
                ids,
            } => {
                let owner = self.store.server_personal_owner(&mailbox_id, Some(peer))?;
                self.store.delete(&mailbox_id, &read_token, &owner, &ids)?;
                Ok(Response::Ok)
            }
            Request::BlobPut {
                mailbox_id,
                write_token,
                read_token,
                chunk,
            } => {
                self.store.server_personal_owner(&mailbox_id, None)?;
                chunk.validate(time)?;
                self.store
                    .server_check_media_capacity(&mailbox_id, &chunk)?;
                self.store.store_relay_media(
                    &mailbox_id,
                    &write_token,
                    &read_token,
                    &chunk,
                    time,
                )?;
                Ok(Response::Ok)
            }
            Request::BlobGet {
                media_id,
                index,
                read_token,
            } => {
                ensure!(
                    self.store.server_media_group(&media_id)?.is_none(),
                    "group attachments require group authorization"
                );
                Ok(Response::Blob(self.store.get_relay_media(
                    &media_id,
                    index,
                    &read_token,
                    time,
                )?))
            }
            Request::Peers => Ok(Response::Peers(Vec::new())),
            Request::Allocate => bail!("server mailboxes require signed provisioning"),
            _ => bail!("request is not supported by a ciphertext server"),
        }
    }

    fn provision(&self, token: &str) -> Result<()> {
        validate_hex32(token)?;
        ensure!(
            bool::from(
                token
                    .as_bytes()
                    .ct_eq(self.state.provisioning_token.as_bytes())
            ),
            "invalid server provisioning capability"
        );
        Ok(())
    }

    fn authorized_group(&self, group: &str, peer: &str) -> Result<(SignedGroupConfig, String)> {
        let config = self
            .store
            .server_group(group)?
            .context("unknown hosted group")?;
        let identity = config
            .config
            .members
            .iter()
            .find(|member| member.endpoint == peer)
            .context("endpoint is not a current group member")?
            .identity
            .clone();
        Ok((config, identity))
    }

    fn handle_server(&mut self, peer: &str, request: ServerRequest, time: i64) -> Result<Response> {
        match request {
            ServerRequest::ConfigureGroup {
                provisioning_token,
                config,
            } => {
                self.provision(&provisioning_token)?;
                config.verify()?;
                ensure!(
                    config.config.server_id == self.id(),
                    "group config targets another server"
                );
                ensure!(
                    config.config.epoch <= i64::MAX as u64,
                    "group epoch is too large"
                );
                ensure!(
                    config
                        .config
                        .members
                        .iter()
                        .any(|member| member.identity == config.config.owner
                            && member.endpoint == peer),
                    "group config must be published by its owner endpoint"
                );
                if let Some(previous) = self.store.server_group(&config.config.group_id)? {
                    ensure!(
                        previous.config.owner == config.config.owner,
                        "group owner cannot change"
                    );
                    ensure!(
                        config.config.revision >= previous.config.revision,
                        "stale group config revision"
                    );
                    if config.config.revision == previous.config.revision {
                        ensure!(
                            config.config == previous.config,
                            "conflicting group config revision"
                        );
                        return Ok(Response::Ok);
                    }
                    ensure!(
                        config.config.epoch >= previous.config.epoch,
                        "group epoch cannot decrease"
                    );
                    for member in &previous.config.members {
                        ensure!(
                            config
                                .config
                                .members
                                .iter()
                                .any(|current| current.identity == member.identity)
                                || config.config.removal_epochs.contains_key(&member.identity),
                            "removed member is missing its signed removal epoch"
                        );
                    }
                } else {
                    ensure!(self.status()?.groups < 128, "server group limit reached");
                }
                let owner = format!(
                    "group:{}",
                    hex::encode(Sha256::digest(config.config.group_id.as_bytes()))
                );
                let mailbox = self.store.allocate(&owner)?;
                self.store.server_save_group(&config, &mailbox)?;
                Ok(Response::Ok)
            }
            ServerRequest::BindMailbox {
                provisioning_token,
                binding,
            } => {
                self.provision(&provisioning_token)?;
                binding.verify()?;
                ensure!(
                    binding.binding.server_id == self.id(),
                    "mailbox binding targets another server"
                );
                ensure!(
                    binding.binding.endpoint == peer,
                    "mailbox binding endpoint mismatch"
                );
                if let Some(previous) = self.store.server_binding(&binding.binding.identity)? {
                    ensure!(
                        binding.binding.revision >= previous.binding.revision,
                        "stale mailbox binding revision"
                    );
                    if binding.binding.revision == previous.binding.revision {
                        ensure!(
                            binding.binding == previous.binding,
                            "conflicting mailbox binding revision"
                        );
                    }
                } else {
                    ensure!(
                        self.status()?.personal_mailboxes < 512,
                        "personal mailbox limit reached"
                    );
                }
                // Requests are serialized through &mut Server. Check the unique
                // endpoint before allocation so rejected identities cannot spend
                // relay mailbox slots without creating a personal binding.
                self.store.server_check_binding_endpoint(&binding)?;
                let owner = format!("personal:{}", binding.binding.identity);
                let (mailbox_id, write_token, read_token) = self.store.allocate(&owner)?;
                self.store.server_save_binding(&binding, &mailbox_id)?;
                Ok(Response::Mailbox {
                    mailbox_id,
                    write_token,
                    read_token,
                })
            }
            ServerRequest::GroupPut { group_id, envelope } => {
                let (config, _) = self.authorized_group(&group_id, peer)?;
                ensure!(envelope.conversation == group_id, "cross-group envelope");
                envelope.validate(time)?;
                // Public MLS framing is only a delivery filter. The recipient
                // still authenticates the ciphertext and its epoch with MLS.
                let epoch = crate::crypto::CryptoEngine::message_epoch(&envelope.ciphertext)?;
                ensure!(
                    epoch <= config.config.epoch,
                    "message exceeds configured group epoch"
                );
                let (mailbox, write, _) = self.store.server_group_mailbox(&group_id)?;
                self.store
                    .server_check_envelope_capacity(&mailbox, &envelope)?;
                self.store.store(&mailbox, &write, &envelope, time)?;
                // A crash between these writes is repaired by an idempotent retry;
                // success is returned only after the durable sequence is present.
                self.store
                    .server_index_message(&group_id, &mailbox, &envelope.id, epoch)?;
                Ok(Response::Ok)
            }
            ServerRequest::GroupFetch { group_id, after } => {
                let (config, identity) = self.authorized_group(&group_id, peer)?;
                let joined_epoch = config
                    .config
                    .members
                    .iter()
                    .find(|member| member.identity == identity)
                    .context("missing authorized group member")?
                    .joined_epoch;
                let (envelopes, next) =
                    self.store
                        .server_fetch_group(&group_id, after, joined_epoch, time)?;
                Ok(Response::Server(ServerResponse::GroupPage {
                    envelopes,
                    next,
                }))
            }
            ServerRequest::GroupControlPut { control } => {
                control.verify(time)?;
                ensure!(
                    control.server_id == self.id(),
                    "control targets another server"
                );
                let (config, identity) =
                    self.authorized_group(&control.record.conversation, peer)?;
                ensure!(
                    identity == config.config.owner && control.owner == identity,
                    "only the group owner may publish commits"
                );
                ensure!(
                    control.record.epoch <= config.config.epoch,
                    "control exceeds configured group epoch"
                );
                self.store.server_put_control(&control)?;
                Ok(Response::Ok)
            }
            ServerRequest::GroupControls {
                group_id,
                after_epoch,
            } => {
                let config = self
                    .store
                    .server_group(&group_id)?
                    .context("unknown hosted group")?;
                let current_epoch = if config
                    .config
                    .members
                    .iter()
                    .any(|member| member.endpoint == peer)
                {
                    config.config.epoch
                } else {
                    // A previously offline member needs the preceding encrypted
                    // commits to authenticate its removal, but never later epochs.
                    self.store.server_former_member_epoch(&group_id, peer)?
                };
                let records = self.store.server_fetch_controls(
                    &group_id,
                    after_epoch,
                    current_epoch,
                    time,
                )?;
                Ok(Response::Server(ServerResponse::Controls {
                    records,
                    current_epoch,
                }))
            }
            ServerRequest::InboxPut { record } => {
                self.validate_inbox(peer, &record, time)?;
                self.store.server_put_inbox(&record)?;
                Ok(Response::Ok)
            }
            ServerRequest::InboxFetch => Ok(Response::Server(ServerResponse::Inbox {
                records: self.store.server_fetch_inbox(peer, time)?,
            })),
            ServerRequest::InboxAck { ids } => {
                self.store.server_ack_inbox(peer, &ids)?;
                Ok(Response::Ok)
            }
            ServerRequest::GroupBlobPut {
                group_id,
                read_token,
                chunk,
            } => {
                self.authorized_group(&group_id, peer)?;
                chunk.validate(time)?;
                let (mailbox, write, _) = self.store.server_group_mailbox(&group_id)?;
                self.store.server_check_media_capacity(&mailbox, &chunk)?;
                self.store
                    .store_relay_media(&mailbox, &write, &read_token, &chunk, time)?;
                Ok(Response::Ok)
            }
            ServerRequest::GroupBlobGet {
                group_id,
                media_id,
                index,
                read_token,
            } => {
                self.authorized_group(&group_id, peer)?;
                let stored_group = self.store.server_media_group(&media_id)?;
                if let Some(stored_group) = stored_group {
                    ensure!(
                        stored_group == group_id,
                        "attachment belongs to another group"
                    );
                    Ok(Response::Blob(self.store.get_relay_media(
                        &media_id,
                        index,
                        &read_token,
                        time,
                    )?))
                } else {
                    Ok(Response::Blob(None))
                }
            }
        }
    }

    fn validate_inbox(&self, peer: &str, record: &SignedInboxRecord, time: i64) -> Result<()> {
        record.verify(time)?;
        ensure!(
            record.id == record.canonical_id()?,
            "inbox ID does not match its sender, recipient and content"
        );
        ensure!(
            record.server_id == self.id(),
            "inbox record targets another server"
        );
        let (config, identity) = self.authorized_group(&record.group_id, peer)?;
        ensure!(record.sender == identity, "inbox sender endpoint mismatch");
        ensure!(
            self.store
                .server_known_member(&record.group_id, &record.recipient)?,
            "unknown group control recipient"
        );
        if let Some(removed_epoch) = self
            .store
            .server_removed_epoch(&record.group_id, &record.recipient)?
        {
            ensure!(
                identity == config.config.owner
                    && matches!(&record.control, HostedControl::Control { record } if record.epoch == removed_epoch),
                "removed members may receive only their removal commit"
            );
        }
        match &record.control {
            HostedControl::Configure { server_ticket, .. } => {
                ensure!(
                    identity == config.config.owner,
                    "only the owner may configure hosting"
                );
                ensure!(
                    ticket_endpoint_id(server_ticket)? == self.id(),
                    "configuration ticket targets another server"
                );
            }
            HostedControl::Join {
                conversation,
                welcome,
                ..
            } => {
                ensure!(
                    identity == config.config.owner && conversation.owner == identity,
                    "only the owner may invite group members"
                );
                ensure!(
                    !welcome.is_empty()
                        && config
                            .config
                            .members
                            .iter()
                            .any(|member| member.identity == record.recipient),
                    "invalid hosted welcome recipient"
                );
                ensure!(
                    conversation.epoch <= config.config.epoch,
                    "welcome exceeds configured group epoch"
                );
            }
            HostedControl::Control { record: control } => {
                ensure!(
                    identity == config.config.owner,
                    "only the owner may publish commits"
                );
                ensure!(
                    !control.commit.is_empty() && control.epoch <= config.config.epoch,
                    "invalid hosted commit epoch"
                );
            }
            HostedControl::Update { proposal, .. } => {
                ensure!(
                    record.recipient == config.config.owner && !proposal.is_empty(),
                    "invalid update recipient or proposal"
                );
            }
            HostedControl::Recover { key_package, .. } => {
                ensure!(
                    record.recipient == config.config.owner && !key_package.is_empty(),
                    "invalid recovery recipient or key package"
                );
            }
        }
        Ok(())
    }
}
