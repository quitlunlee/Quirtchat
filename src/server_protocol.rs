//! Public, signed authorization for a ciphertext-only hosted service.
//! Signatures bind the deployment endpoint as well as the target group or user.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    media::MediaChunk,
    model::{ControlRecord, Conversation, Envelope, Invitation, MAX_GROUP_MEMBERS, MESSAGE_TTL},
    transport::{decode_ticket, ticket_endpoint_id},
};

pub const SERVER_PAGE_BYTES: usize = 384 * 1024;
pub const SERVER_PAGE_RECORDS: usize = 128;
pub const MAX_SERVER_CONTROL_BYTES: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerInvitation {
    pub ticket: String,
    pub provisioning_token: String,
}

impl std::fmt::Debug for ServerInvitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerInvitation")
            .field("ticket", &self.ticket)
            .field("provisioning_token", &"[REDACTED]")
            .finish()
    }
}

impl ServerInvitation {
    pub fn validate(&self) -> Result<()> {
        decode_ticket(&self.ticket)?;
        validate_hex32(&self.provisioning_token)?;
        Ok(())
    }

    pub fn server_id(&self) -> Result<String> {
        ticket_endpoint_id(&self.ticket)
    }
}

pub fn encode_server_invitation(invitation: &ServerInvitation) -> Result<String> {
    invitation.validate()?;
    Ok(format!(
        "clichat-server1:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(invitation)?)
    ))
}

pub fn decode_server_invitation(text: &str) -> Result<ServerInvitation> {
    ensure!(text.len() <= 32 * 1024, "server invitation is too large");
    let encoded = text
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("clichat-server1:"))
        .context("invalid server invitation prefix")?;
    let invitation: ServerInvitation = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
    invitation.validate()?;
    Ok(invitation)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerMember {
    pub identity: String,
    pub endpoint: String,
    #[serde(default)]
    pub joined_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupConfig {
    pub server_id: String,
    pub group_id: String,
    pub owner: String,
    pub revision: u64,
    pub epoch: u64,
    pub members: Vec<ServerMember>,
    /// Exact removal epochs survive multiple owner commits while the server is
    /// offline, so its authorization boundary never depends on polling timing.
    #[serde(default)]
    pub removal_epochs: std::collections::BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGroupConfig {
    pub config: GroupConfig,
    pub signature: Vec<u8>,
}

impl SignedGroupConfig {
    pub fn sign(config: GroupConfig, secret: &[u8; 32]) -> Result<Self> {
        ensure!(
            identity(secret) == config.owner,
            "group owner signing key mismatch"
        );
        let signature = sign_bytes(b"clichat/server/group-config/v1\0", &config, secret)?;
        let signed = Self { config, signature };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<()> {
        validate_hex32(&self.config.server_id)?;
        validate_group_id(&self.config.group_id)?;
        ensure!(
            self.config.revision > 0,
            "group config revision must be positive"
        );
        ensure!(
            !self.config.members.is_empty() && self.config.members.len() <= MAX_GROUP_MEMBERS,
            "invalid server group size"
        );
        let mut identities = std::collections::BTreeSet::new();
        let mut endpoints = std::collections::BTreeSet::new();
        for member in &self.config.members {
            validate_hex32(&member.identity)?;
            validate_hex32(&member.endpoint)?;
            ensure!(
                member.joined_epoch <= self.config.epoch,
                "member join epoch exceeds group epoch"
            );
            ensure!(
                identities.insert(&member.identity) && endpoints.insert(&member.endpoint),
                "duplicate group identity or endpoint"
            );
        }
        ensure!(
            identities.contains(&self.config.owner),
            "owner is absent from group config"
        );
        ensure!(
            self.config.removal_epochs.len() <= 512,
            "group removal history is too large"
        );
        for (identity, epoch) in &self.config.removal_epochs {
            validate_hex32(identity)?;
            ensure!(
                !identities.contains(identity) && *epoch <= self.config.epoch,
                "invalid member removal boundary"
            );
        }
        verify_bytes(
            b"clichat/server/group-config/v1\0",
            &self.config,
            &self.config.owner,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxBinding {
    pub server_id: String,
    pub identity: String,
    pub endpoint: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMailboxBinding {
    pub binding: MailboxBinding,
    pub signature: Vec<u8>,
}

impl SignedMailboxBinding {
    pub fn sign(binding: MailboxBinding, secret: &[u8; 32]) -> Result<Self> {
        ensure!(
            identity(secret) == binding.identity,
            "mailbox signing key mismatch"
        );
        let signature = sign_bytes(b"clichat/server/mailbox-binding/v1\0", &binding, secret)?;
        let signed = Self { binding, signature };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<()> {
        validate_hex32(&self.binding.server_id)?;
        validate_hex32(&self.binding.identity)?;
        validate_hex32(&self.binding.endpoint)?;
        ensure!(
            self.binding.revision > 0,
            "mailbox revision must be positive"
        );
        verify_bytes(
            b"clichat/server/mailbox-binding/v1\0",
            &self.binding,
            &self.binding.identity,
            &self.signature,
        )
    }
}

/// Only membership material may use the server inbox. In particular, plaintext
/// History and application messages cannot accidentally be forwarded this way.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HostedControl {
    Configure {
        conversation: String,
        server_ticket: String,
    },
    Join {
        conversation: Conversation,
        welcome: Vec<u8>,
        contacts: Vec<Invitation>,
    },
    Control {
        record: ControlRecord,
    },
    Update {
        conversation: String,
        proposal: Vec<u8>,
    },
    Recover {
        conversation: String,
        key_package: Vec<u8>,
    },
}

impl HostedControl {
    pub fn group_id(&self) -> &str {
        match self {
            Self::Join { conversation, .. } => &conversation.id,
            Self::Control { record } => &record.conversation,
            Self::Configure { conversation, .. }
            | Self::Update { conversation, .. }
            | Self::Recover { conversation, .. } => conversation,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedInboxRecord {
    pub server_id: String,
    pub id: String,
    pub group_id: String,
    pub sender: String,
    pub recipient: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub control: HostedControl,
    pub signature: Vec<u8>,
}

pub type SignedHostedControl = SignedInboxRecord;

impl SignedInboxRecord {
    /// Stable sender/recipient/content scope for retries and acknowledgements.
    /// A publisher cannot reserve a different group's pending control ID.
    pub fn canonical_id(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
            &self.server_id,
            &self.sender,
            &self.recipient,
            &self.control,
        ))?)))
    }

    fn body(&self) -> Result<Vec<u8>> {
        canonical(
            b"clichat/server/inbox/v1\0",
            &(
                &self.server_id,
                &self.id,
                &self.group_id,
                &self.sender,
                &self.recipient,
                self.created_at,
                self.expires_at,
                &self.control,
            ),
        )
    }

    /// Fill the signature after constructing the record with an empty signature.
    pub fn sign(mut self, secret: &[u8; 32]) -> Result<Self> {
        ensure!(
            identity(secret) == self.sender,
            "inbox signing key mismatch"
        );
        self.signature = SigningKey::from_bytes(secret)
            .sign(&self.body()?)
            .to_bytes()
            .to_vec();
        Ok(self)
    }

    pub fn verify(&self, time: i64) -> Result<()> {
        validate_hex32(&self.server_id)?;
        validate_hex32(&self.sender)?;
        validate_hex32(&self.recipient)?;
        validate_group_id(&self.group_id)?;
        ensure!(
            !self.id.is_empty() && self.id.len() <= 128,
            "invalid inbox record ID"
        );
        validate_lifetime(self.created_at, self.expires_at, time)?;
        ensure!(
            self.control.group_id() == self.group_id,
            "cross-group hosted control"
        );
        ensure!(
            serde_json::to_vec(&self.control)?.len() <= MAX_SERVER_CONTROL_BYTES,
            "hosted control is too large"
        );
        verify_raw(&self.body()?, &self.sender, &self.signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGroupControl {
    pub server_id: String,
    pub owner: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub record: ControlRecord,
    pub signature: Vec<u8>,
}

impl SignedGroupControl {
    fn body(&self) -> Result<Vec<u8>> {
        canonical(
            b"clichat/server/group-control/v1\0",
            &(
                &self.server_id,
                &self.owner,
                self.created_at,
                self.expires_at,
                &self.record,
            ),
        )
    }

    pub fn sign(mut self, secret: &[u8; 32]) -> Result<Self> {
        ensure!(
            identity(secret) == self.owner,
            "control signing key mismatch"
        );
        self.signature = SigningKey::from_bytes(secret)
            .sign(&self.body()?)
            .to_bytes()
            .to_vec();
        Ok(self)
    }

    pub fn verify(&self, time: i64) -> Result<()> {
        validate_hex32(&self.server_id)?;
        validate_group_id(&self.record.conversation)?;
        validate_lifetime(self.created_at, self.expires_at, time)?;
        ensure!(
            !self.record.commit.is_empty() && self.record.proposals.len() <= MAX_GROUP_MEMBERS,
            "invalid hosted group control"
        );
        ensure!(
            serde_json::to_vec(&self.record)?.len() <= MAX_SERVER_CONTROL_BYTES,
            "hosted group control is too large"
        );
        verify_raw(&self.body()?, &self.owner, &self.signature)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ServerRequest {
    ConfigureGroup {
        provisioning_token: String,
        config: SignedGroupConfig,
    },
    BindMailbox {
        provisioning_token: String,
        binding: SignedMailboxBinding,
    },
    GroupPut {
        group_id: String,
        envelope: Envelope,
    },
    GroupFetch {
        group_id: String,
        after: u64,
    },
    GroupControlPut {
        control: SignedGroupControl,
    },
    GroupControls {
        group_id: String,
        after_epoch: u64,
    },
    InboxPut {
        record: SignedInboxRecord,
    },
    InboxFetch,
    InboxAck {
        ids: Vec<String>,
    },
    GroupBlobPut {
        group_id: String,
        read_token: String,
        chunk: MediaChunk,
    },
    GroupBlobGet {
        group_id: String,
        media_id: String,
        index: u32,
        read_token: String,
    },
}

impl std::fmt::Debug for ServerRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ConfigureGroup { .. } => "ConfigureGroup",
            Self::BindMailbox { .. } => "BindMailbox",
            Self::GroupPut { .. } => "GroupPut",
            Self::GroupFetch { .. } => "GroupFetch",
            Self::GroupControlPut { .. } => "GroupControlPut",
            Self::GroupControls { .. } => "GroupControls",
            Self::InboxPut { .. } => "InboxPut",
            Self::InboxFetch => "InboxFetch",
            Self::InboxAck { .. } => "InboxAck",
            Self::GroupBlobPut { .. } => "GroupBlobPut",
            Self::GroupBlobGet { .. } => "GroupBlobGet",
        };
        formatter.debug_struct(name).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequencedEnvelope {
    pub sequence: u64,
    pub envelope: Envelope,
}

/// Successful mutations use the ordinary Response::Ok; BindMailbox returns the
/// ordinary Response::Mailbox and GroupBlobGet the ordinary Response::Blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerResponse {
    GroupPage {
        envelopes: Vec<SequencedEnvelope>,
        next: u64,
    },
    Controls {
        records: Vec<SignedGroupControl>,
        current_epoch: u64,
    },
    Inbox {
        records: Vec<SignedInboxRecord>,
    },
}

pub(crate) fn validate_group_id(group: &str) -> Result<()> {
    ensure!(
        !group.is_empty() && group.len() <= 128 && !group.chars().any(char::is_control),
        "invalid server group identifier"
    );
    Ok(())
}

pub(crate) fn validate_hex32(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid public identity or capability"
    );
    Ok(())
}

pub(crate) fn validate_lifetime(created: i64, expires: i64, time: i64) -> Result<()> {
    ensure!(
        created >= 0
            && expires.checked_sub(created) == Some(MESSAGE_TTL)
            && created <= time.saturating_add(300)
            && expires > time,
        "invalid or expired server record lifetime"
    );
    Ok(())
}

fn identity(secret: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn canonical(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(bytes)
}

fn sign_bytes(domain: &[u8], value: &impl Serialize, secret: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(SigningKey::from_bytes(secret)
        .sign(&canonical(domain, value)?)
        .to_bytes()
        .to_vec())
}

fn verify_bytes(
    domain: &[u8],
    value: &impl Serialize,
    identity: &str,
    signature: &[u8],
) -> Result<()> {
    verify_raw(&canonical(domain, value)?, identity, signature)
}

fn verify_raw(body: &[u8], identity: &str, signature: &[u8]) -> Result<()> {
    validate_hex32(identity)?;
    let public: [u8; 32] = hex::decode(identity)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key"))?;
    VerifyingKey::from_bytes(&public)?.verify_strict(body, &Signature::from_slice(signature)?)?;
    Ok(())
}
