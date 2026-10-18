//! MLS 1.0 state kept in memory. Snapshots contain private keys and MUST only be
//! persisted by the caller inside the encrypted database, together with its outbox.

use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

use crate::model::{MAX_FRAME_BYTES, MAX_GROUP_MEMBERS, MESSAGE_TTL};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const SNAPSHOT_VERSION: u32 = 1;
// These bounds deliberately trade unlimited reordering for bounded memory use.
pub(crate) const PAST_EPOCHS: usize = 256;
const OUT_OF_ORDER: u32 = 1024;
const MAX_FORWARD: u32 = 4096;

pub enum Processed {
    Application {
        sender: String,
        plaintext: Vec<u8>,
    },
    Commit {
        sender: String,
        epoch: u64,
        removed: bool,
        updated_members: Vec<String>,
    },
    Proposal {
        sender: String,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    identity_secret: Vec<u8>,
    groups: Vec<String>,
    // JSON maps cannot have binary keys; store sorted key/value entries instead.
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.identity_secret.zeroize();
        for (key, value) in &mut self.storage {
            key.zeroize();
            value.zeroize();
        }
    }
}

// Intentionally no Debug implementation: neither keys nor MLS state belong in logs.
pub struct CryptoEngine {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    identity_secret: Zeroizing<[u8; 32]>,
    identity: String,
    groups: BTreeMap<String, MlsGroup>,
}

impl Drop for CryptoEngine {
    fn drop(&mut self) {
        // MemoryStorage itself stores ordinary byte vectors, not zeroizing buffers.
        if let Ok(mut storage) = self.provider.storage().values.write() {
            for (mut key, mut value) in storage.drain() {
                key.zeroize();
                value.zeroize();
            }
        }
    }
}

impl CryptoEngine {
    pub fn new(identity_secret: &[u8]) -> Result<Self> {
        let secret: [u8; 32] = identity_secret
            .try_into()
            .map_err(|_| anyhow!("identity secret must be a 32-byte Ed25519 seed"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public = signing_key.verifying_key().to_bytes();
        let signer =
            SignatureKeyPair::from_raw(SignatureScheme::ED25519, secret.to_vec(), public.to_vec());
        let provider = OpenMlsRustCrypto::default();
        signer
            .store(provider.storage())
            .context("store MLS identity")?;
        Ok(Self {
            provider,
            signer,
            identity_secret: Zeroizing::new(secret),
            identity: hex::encode(public),
            groups: BTreeMap::new(),
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Restores a trusted, decrypted database snapshot; never accept this over the network.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let mut snapshot: Snapshot =
            serde_json::from_slice(bytes).context("decode MLS snapshot")?;
        ensure!(
            snapshot.version == SNAPSHOT_VERSION,
            "unsupported MLS snapshot version"
        );
        let mut engine = Self::new(&snapshot.identity_secret)?;
        {
            let mut storage = engine
                .provider
                .storage()
                .values
                .write()
                .map_err(|_| anyhow!("MLS storage lock poisoned"))?;
            storage.clear();
            for (key, value) in snapshot.storage.drain(..) {
                ensure!(
                    storage.insert(key, value).is_none(),
                    "duplicate snapshot storage entry"
                );
            }
        }
        for id in &snapshot.groups {
            validate_group_id(id)?;
            let group = MlsGroup::load(
                engine.provider.storage(),
                &GroupId::from_slice(id.as_bytes()),
            )?
            .ok_or_else(|| anyhow!("incomplete MLS snapshot for group {id}"))?;
            ensure!(group.ciphersuite() == SUITE, "unsupported MLS ciphersuite");
            let members = validate_members(group.members())?;
            ensure!(
                !group.is_active() || members.contains(&engine.identity),
                "snapshot identity is not a group member"
            );
            ensure!(
                engine.groups.insert(id.clone(), group).is_none(),
                "duplicate snapshot group"
            );
        }
        Ok(engine)
    }

    /// The returned bytes contain secrets. Persist atomically with generated wire messages.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let storage = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| anyhow!("MLS storage lock poisoned"))?;
        let mut entries: Vec<_> = storage
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            identity_secret: self.identity_secret.as_slice().to_vec(),
            groups: self.groups.keys().cloned().collect(),
            storage: entries,
        };
        serde_json::to_vec(&snapshot).context("encode MLS snapshot")
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.identity.as_bytes().to_vec()).into(),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// Issues a fresh, single-use KeyPackage. Save the resulting snapshot before sharing it.
    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        self.key_package_with_lifetime(Lifetime::default())
    }

    pub(crate) fn key_package_with_lifetime(&mut self, lifetime: Lifetime) -> Result<Vec<u8>> {
        self.transaction(|this| {
            let package = KeyPackage::builder().key_package_lifetime(lifetime).build(
                SUITE,
                &this.provider,
                &this.signer,
                this.credential(),
            )?;
            Ok(package.key_package().tls_serialize_detached()?)
        })
    }

    /// Checks both the MLS signature and the public-key identity binding in an invite.
    pub fn key_package_identity(bytes: &[u8]) -> Result<String> {
        ensure!(bytes.len() <= MAX_FRAME_BYTES, "KeyPackage too large");
        let provider = OpenMlsRustCrypto::default();
        let package = KeyPackageIn::tls_deserialize_exact(bytes)?
            .validate(provider.crypto(), ProtocolVersion::Mls10)?;
        ensure!(
            package.ciphersuite() == SUITE,
            "unsupported MLS ciphersuite"
        );
        leaf_identity(package.leaf_node())
    }

    /// A signed contact directory may outlive its one-use joining material. Only
    /// the precise expired-lifetime error is tolerated; OpenMLS 0.9.1 verifies
    /// both signatures and the other package fields before checking lifetime.
    /// Group admission still uses the strict validator in `add_member`.
    pub fn contact_key_package_identity(bytes: &[u8]) -> Result<String> {
        ensure!(bytes.len() <= MAX_FRAME_BYTES, "KeyPackage too large");
        let input = KeyPackageIn::tls_deserialize_exact(bytes)?;
        let credential = input.unverified_credential();
        let provider = OpenMlsRustCrypto::default();
        match input.validate(provider.crypto(), ProtocolVersion::Mls10) {
            Ok(package) => {
                ensure!(
                    package.ciphersuite() == SUITE,
                    "unsupported MLS ciphersuite"
                );
                leaf_identity(package.leaf_node())
            }
            Err(KeyPackageVerifyError::LifetimeError(
                openmls::treesync::errors::LifetimeError::Expired { .. },
            )) => bound_identity(&credential.credential, credential.signature_key.as_slice()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn key_package_valid_until(bytes: &[u8]) -> Result<i64> {
        ensure!(bytes.len() <= MAX_FRAME_BYTES, "KeyPackage too large");
        let provider = OpenMlsRustCrypto::default();
        let input = KeyPackageIn::tls_deserialize_exact(bytes)?;
        let expires = match input.validate(provider.crypto(), ProtocolVersion::Mls10) {
            Ok(package) => package.life_time().not_after(),
            Err(KeyPackageVerifyError::LifetimeError(
                openmls::treesync::errors::LifetimeError::Expired { not_after, .. },
            )) => not_after,
            Err(error) => return Err(error.into()),
        };
        Ok(expires.try_into()?)
    }

    /// Whether the private, single-use package bundle is still waiting for a Welcome.
    pub(crate) fn key_package_available(&self, bytes: &[u8]) -> Result<bool> {
        let package = KeyPackageIn::tls_deserialize_exact(bytes)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)?;
        let reference = package.hash_ref(self.provider.crypto())?;
        Ok(self
            .provider
            .storage()
            .key_package::<_, KeyPackageBundle>(&reference)?
            .is_some())
    }

    pub fn create_group(&mut self, id: &str) -> Result<()> {
        validate_group_id(id)?;
        ensure!(!self.groups.contains_key(id), "group already exists");
        self.transaction(|this| {
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(SUITE)
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .padding_size(64)
                .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(PAST_EPOCHS))
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    OUT_OF_ORDER,
                    MAX_FORWARD,
                ))
                .build();
            let group = MlsGroup::new_with_group_id(
                &this.provider,
                &this.signer,
                &config,
                GroupId::from_slice(id.as_bytes()),
                this.credential(),
            )?;
            this.groups.insert(id.to_owned(), group);
            Ok(())
        })
    }

    pub fn add_member(&mut self, id: &str, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        ensure!(key_package.len() <= MAX_FRAME_BYTES, "KeyPackage too large");
        self.transaction(|this| {
            let kp = KeyPackageIn::tls_deserialize_exact(key_package)?
                .validate(this.provider.crypto(), ProtocolVersion::Mls10)?;
            ensure!(kp.ciphersuite() == SUITE, "unsupported MLS ciphersuite");
            let added_identity = leaf_identity(kp.leaf_node())?;
            let group = this.groups.get_mut(id).context("unknown group")?;
            let members = validate_members(group.members())?;
            ensure!(
                members.len() < MAX_GROUP_MEMBERS,
                "group member limit reached"
            );
            ensure!(
                !members.contains(&added_identity),
                "identity is already a group member"
            );
            let (commit, welcome, _) = group.add_members(&this.provider, &this.signer, &[kp])?;
            let output = (
                commit.tls_serialize_detached()?,
                welcome.tls_serialize_detached()?,
            );
            group.merge_pending_commit(&this.provider)?;
            Ok(output)
        })
    }

    pub fn remove_member(&mut self, id: &str, identity: &str) -> Result<Vec<u8>> {
        ensure!(
            identity != self.identity,
            "the coordinator cannot remove itself"
        );
        self.transaction(|this| {
            let group = this.groups.get_mut(id).context("unknown group")?;
            let target = group
                .members()
                .find(|member| member.credential.serialized_content() == identity.as_bytes())
                .context("identity is not a group member")?;
            let (commit, _, _) =
                group.remove_members(&this.provider, &this.signer, &[target.index])?;
            let bytes = commit.tls_serialize_detached()?;
            group.merge_pending_commit(&this.provider)?;
            Ok(bytes)
        })
    }

    /// For trusted local callers. Network invitations should use `join_from`.
    pub fn join(&mut self, welcome: &[u8]) -> Result<String> {
        self.join_inner(welcome, None, None)
    }

    pub fn join_from(&mut self, welcome: &[u8], expected_owner: &str) -> Result<String> {
        self.join_inner(welcome, Some(expected_owner), None)
    }

    /// Only call after the user explicitly requested recovery for this group.
    /// Discards old epoch keys; it does not restore pre-rejoin message history.
    pub fn rejoin_from(
        &mut self,
        welcome: &[u8],
        expected_group_id: &str,
        expected_owner: &str,
    ) -> Result<String> {
        validate_group_id(expected_group_id)?;
        ensure!(
            self.groups.contains_key(expected_group_id),
            "recovery requires an existing group"
        );
        self.join_inner(welcome, Some(expected_owner), Some(expected_group_id))
    }

    fn join_inner(
        &mut self,
        bytes: &[u8],
        expected_owner: Option<&str>,
        recovery_group: Option<&str>,
    ) -> Result<String> {
        ensure!(bytes.len() <= MAX_FRAME_BYTES, "Welcome too large");
        self.transaction(|this| {
            let welcome = match MlsMessageIn::tls_deserialize_exact(bytes)?.extract() {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => bail!("expected an MLS Welcome"),
            };
            // OpenMLS refuses to stage a Welcome while the same group ID is
            // present in storage. Only an explicitly authorized recovery may
            // temporarily remove it. The surrounding transaction restores both
            // the old group and consumed KeyPackage on any validation failure.
            let recovery_epoch = if let Some(id) = recovery_group {
                let old = this.groups.get_mut(id).context("unknown recovery group")?;
                let epoch = old.epoch().as_u64();
                old.delete(this.provider.storage())?;
                Some(epoch)
            } else {
                None
            };
            let config = MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .padding_size(64)
                .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(PAST_EPOCHS))
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                    OUT_OF_ORDER,
                    MAX_FORWARD,
                ))
                .build();
            let staged = StagedWelcome::new_from_welcome(&this.provider, &config, welcome, None)?;
            ensure!(
                staged.group_context().ciphersuite() == SUITE,
                "unsupported MLS ciphersuite"
            );
            let id = String::from_utf8(staged.group_context().group_id().as_slice().to_vec())?;
            validate_group_id(&id)?;
            if let Some(expected_id) = recovery_group {
                ensure!(id == expected_id, "recovery Welcome has the wrong group ID");
                ensure!(
                    staged.group_context().epoch().as_u64()
                        > recovery_epoch.context("missing recovery epoch")?,
                    "recovery Welcome must advance the group epoch"
                );
            } else {
                ensure!(
                    !this.groups.contains_key(&id),
                    "group already exists; explicit recovery is required"
                );
            }
            let members = validate_members(staged.members())?;
            ensure!(
                members.contains(&this.identity),
                "Welcome has the wrong identity"
            );
            ensure!(
                leaf_identity(staged.own_leaf_node().context("Welcome lacks own leaf")?)?
                    == this.identity,
                "Welcome has the wrong own leaf"
            );
            if let Some(owner) = expected_owner {
                ensure!(
                    leaf_identity(staged.welcome_sender()?)? == owner,
                    "Welcome is not signed by the expected coordinator"
                );
            }
            let group = staged.into_group(&this.provider)?;
            this.groups.insert(id.clone(), group);
            Ok(id)
        })
    }

    pub fn encrypt(&mut self, id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !plaintext.is_empty() && plaintext.len() <= 64 * 1024,
            "invalid plaintext size"
        );
        self.transaction(|this| {
            let group = this.groups.get_mut(id).context("unknown group")?;
            prune_past_secrets(group, &this.provider)?;
            Ok(group
                .create_message(&this.provider, &this.signer, plaintext)?
                .tls_serialize_detached()?)
        })
    }

    /// Verifies MLS authentication and application policy before merging any commit.
    /// Rejected input restores all in-memory ratchets as well as group state.
    pub fn process(&mut self, id: &str, bytes: &[u8], expected_owner: &str) -> Result<Processed> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES,
            "invalid MLS message size"
        );
        self.transaction(|this| {
            let message =
                MlsMessageIn::tls_deserialize_exact(bytes)?.try_into_protocol_message()?;
            ensure!(
                message.group_id().as_slice() == id.as_bytes(),
                "MLS group mismatch"
            );
            let group = this.groups.get_mut(id).context("unknown group")?;
            let current_members: BTreeMap<_, _> = group
                .members()
                .map(|m| {
                    bound_identity(&m.credential, &m.signature_key)
                        .map(|identity| (m.index, identity))
                })
                .collect::<Result<_>>()?;
            ensure!(
                current_members.values().any(|id| id == expected_owner),
                "coordinator is not a current member"
            );
            prune_past_secrets(group, &this.provider)?;
            let processed = group.process_message(&this.provider, message)?;
            let sender = credential_identity(processed.credential())?;
            ensure!(
                matches!(processed.sender(), Sender::Member(_)),
                "external MLS senders are disabled"
            );
            ensure!(
                current_members.values().any(|id| id == &sender),
                "sender is no longer a group member"
            );
            let sender_index = match processed.sender() {
                Sender::Member(index) => *index,
                _ => unreachable!(),
            };
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(application) => {
                    Ok(Processed::Application {
                        sender,
                        plaintext: application.into_bytes(),
                    })
                }
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    ensure!(sender == expected_owner, "only the coordinator may commit");
                    validate_staged_commit(&staged, &current_members, expected_owner)?;
                    let removed = staged.self_removed();
                    let epoch = staged.epoch().as_u64();
                    // The transport's proposal sidecar is not authenticated as a
                    // set. Report only updates actually covered by this Commit.
                    let mut updated_members = BTreeSet::new();
                    for update in staged.update_proposals() {
                        updated_members
                            .insert(leaf_identity(update.update_proposal().leaf_node())?);
                    }
                    if staged.update_path_leaf_node().is_some() {
                        updated_members.insert(sender.clone());
                    }
                    group.merge_staged_commit(&this.provider, *staged)?;
                    Ok(Processed::Commit {
                        sender,
                        epoch,
                        removed,
                        updated_members: updated_members.into_iter().collect(),
                    })
                }
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    let Proposal::Update(update) = proposal.proposal() else {
                        bail!("only member Update proposals are accepted");
                    };
                    ensure!(
                        leaf_identity(update.leaf_node())? == sender,
                        "Update cannot change the member identity"
                    );
                    ensure!(
                        current_members.get(&sender_index) == Some(&sender),
                        "Update leaf mismatch"
                    );
                    ensure!(
                        !group
                            .proposal_store()
                            .proposals()
                            .any(|p| p.sender() == proposal.sender()),
                        "member already has a pending proposal"
                    );
                    group.store_pending_proposal(this.provider.storage(), *proposal)?;
                    Ok(Processed::Proposal { sender })
                }
                _ => bail!("unsupported or already processed MLS message"),
            }
        })
    }

    /// Reads routing metadata only. Callers must authenticate these exact bytes with
    /// `process` before using this epoch for authorization decisions.
    pub fn message_epoch(bytes: &[u8]) -> Result<u64> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES,
            "invalid MLS message size"
        );
        Ok(MlsMessageIn::tls_deserialize_exact(bytes)?
            .try_into_protocol_message()?
            .epoch()
            .as_u64())
    }

    /// Archive and deliver this proposal to every member before its referencing Commit.
    pub fn propose_update(&mut self, id: &str) -> Result<Vec<u8>> {
        self.transaction(|this| {
            let group = this.groups.get_mut(id).context("unknown group")?;
            ensure!(
                !group
                    .proposal_store()
                    .proposals()
                    .any(|p| p.sender() == &Sender::Member(group.own_leaf_index())),
                "own Update is already pending"
            );
            let (message, _) = group.propose_self_update(
                &this.provider,
                &this.signer,
                LeafNodeParameters::default(),
            )?;
            Ok(message.tls_serialize_detached()?)
        })
    }

    /// Coordinator-only at the application layer. Also refreshes the coordinator's leaf.
    pub fn commit_updates(&mut self, id: &str) -> Result<Vec<u8>> {
        self.transaction(|this| {
            let group = this.groups.get_mut(id).context("unknown group")?;
            let bundle =
                group.self_update(&this.provider, &this.signer, LeafNodeParameters::default())?;
            let bytes = bundle.into_commit().tls_serialize_detached()?;
            group.merge_pending_commit(&this.provider)?;
            Ok(bytes)
        })
    }

    pub fn epoch(&self, id: &str) -> Result<u64> {
        Ok(self
            .groups
            .get(id)
            .context("unknown group")?
            .epoch()
            .as_u64())
    }

    pub fn members(&self, id: &str) -> Result<Vec<String>> {
        Ok(
            validate_members(self.groups.get(id).context("unknown group")?.members())?
                .into_iter()
                .collect(),
        )
    }

    pub fn is_active(&self, id: &str) -> Result<bool> {
        Ok(self.groups.get(id).context("unknown group")?.is_active())
    }

    /// Used by the application's periodic expiry maintenance even when no traffic arrives.
    pub fn prune_expired_secrets(&mut self) -> Result<()> {
        self.transaction(|this| {
            for group in this.groups.values_mut() {
                prune_past_secrets(group, &this.provider)?;
            }
            // MemoryStorage uses the KeyPackage label for serialized bundles.
            // These are local trusted records, not unverified network input.
            let time = crate::model::now() as u64;
            let mut storage = this
                .provider
                .storage()
                .values
                .write()
                .map_err(|_| anyhow!("MLS storage lock poisoned"))?;
            let expired = storage
                .iter()
                .filter_map(|(key, value)| {
                    if !key.starts_with(b"KeyPackage") {
                        return None;
                    }
                    let bundle: KeyPackageBundle = serde_json::from_slice(value).ok()?;
                    (bundle.key_package().life_time().not_after() <= time).then(|| key.clone())
                })
                .collect::<Vec<_>>();
            for key in expired {
                if let Some(mut value) = storage.remove(&key) {
                    value.zeroize();
                }
            }
            Ok(())
        })
    }

    fn transaction<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let backup = Zeroizing::new(self.snapshot()?);
        let result = action(self);
        if result.is_err() {
            *self = Self::from_snapshot(&backup)
                .context("restore MLS state after rejected operation")?;
        }
        result
    }
}

fn validate_group_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control),
        "invalid group ID"
    );
    Ok(())
}

fn credential_identity(credential: &Credential) -> Result<String> {
    ensure!(
        credential.credential_type() == CredentialType::Basic,
        "only BasicCredentials are supported"
    );
    let identity = std::str::from_utf8(credential.serialized_content())?;
    ensure!(
        identity.len() == 64
            && identity
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid public-key identity"
    );
    Ok(identity.to_owned())
}

fn bound_identity(credential: &Credential, signature_key: &[u8]) -> Result<String> {
    let identity = credential_identity(credential)?;
    ensure!(
        signature_key.len() == 32 && identity == hex::encode(signature_key),
        "credential identity does not match its signing key"
    );
    Ok(identity)
}

fn leaf_identity(leaf: &LeafNode) -> Result<String> {
    bound_identity(leaf.credential(), leaf.signature_key().as_slice())
}

fn validate_members(members: impl Iterator<Item = Member>) -> Result<BTreeSet<String>> {
    let mut identities = BTreeSet::new();
    for member in members {
        ensure!(
            identities.insert(bound_identity(&member.credential, &member.signature_key)?),
            "duplicate group identity"
        );
        ensure!(
            identities.len() <= MAX_GROUP_MEMBERS,
            "group member limit exceeded"
        );
    }
    ensure!(!identities.is_empty(), "empty group");
    Ok(identities)
}

fn validate_staged_commit(
    staged: &StagedCommit,
    current: &BTreeMap<LeafNodeIndex, String>,
    owner: &str,
) -> Result<()> {
    let mut projected = current.clone();
    for queued in staged.queued_proposals() {
        match queued.proposal() {
            Proposal::Add(_) | Proposal::Remove(_) | Proposal::Update(_) => {}
            _ => bail!("unsupported group-management proposal"),
        }
    }
    for remove in staged.remove_proposals() {
        let removed = projected
            .remove(&remove.remove_proposal().removed())
            .context("unknown removed leaf")?;
        ensure!(removed != owner, "coordinator removal is unsupported");
    }
    for update in staged.update_proposals() {
        let Sender::Member(index) = update.sender() else {
            bail!("external Update is unsupported");
        };
        ensure!(
            current.get(index) == Some(&leaf_identity(update.update_proposal().leaf_node())?),
            "Update cannot change the member identity"
        );
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        ensure!(
            leaf_identity(leaf)? == owner,
            "coordinator identity changed"
        );
    }
    let mut identities: BTreeSet<_> = projected.into_values().collect();
    for add in staged.add_proposals() {
        ensure!(
            identities.insert(leaf_identity(add.add_proposal().key_package().leaf_node())?),
            "duplicate group identity"
        );
    }
    ensure!(
        identities.len() <= MAX_GROUP_MEMBERS,
        "group member limit exceeded"
    );
    Ok(())
}

fn prune_past_secrets(group: &mut MlsGroup, provider: &OpenMlsRustCrypto) -> Result<()> {
    group.delete_past_epoch_secrets(
        provider,
        PastEpochDeletion::older_than_duration(Duration::from_secs(MESSAGE_TTL as u64))
            .max_past_epochs(PAST_EPOCHS),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(seed: u8) -> CryptoEngine {
        CryptoEngine::new(&[seed; 32]).unwrap()
    }

    fn pair() -> (CryptoEngine, CryptoEngine, String) {
        let mut alice = engine(1);
        let mut bob = engine(2);
        let owner = alice.identity().to_owned();
        alice.create_group("group").unwrap();
        let (_, welcome) = alice
            .add_member("group", &bob.key_package().unwrap())
            .unwrap();
        assert_eq!(bob.join_from(&welcome, &owner).unwrap(), "group");
        (alice, bob, owner)
    }

    fn plaintext(result: Processed) -> Vec<u8> {
        match result {
            Processed::Application { plaintext, .. } => plaintext,
            _ => panic!("expected application"),
        }
    }

    #[test]
    fn two_members_reordering_replay_and_restart() {
        let (mut alice, mut bob, owner) = pair();
        let one = alice.encrypt("group", b"one").unwrap();
        let two = alice.encrypt("group", b"two").unwrap();
        bob = CryptoEngine::from_snapshot(&bob.snapshot().unwrap()).unwrap();
        assert_eq!(
            plaintext(bob.process("group", &two, &owner).unwrap()),
            b"two"
        );
        assert_eq!(
            plaintext(bob.process("group", &one, &owner).unwrap()),
            b"one"
        );
        assert!(bob.process("group", &one, &owner).is_err());
        alice = CryptoEngine::from_snapshot(&alice.snapshot().unwrap()).unwrap();
        let reply = bob.encrypt("group", b"reply").unwrap();
        assert_eq!(
            plaintext(alice.process("group", &reply, &owner).unwrap()),
            b"reply"
        );
    }

    #[test]
    fn third_member_removal_and_old_epoch_sender_rejection() {
        let (mut alice, mut bob, owner) = pair();
        let mut charlie = engine(3);
        let (add, welcome) = alice
            .add_member("group", &charlie.key_package().unwrap())
            .unwrap();
        bob.process("group", &add, &owner).unwrap();
        charlie.join_from(&welcome, &owner).unwrap();
        let delayed = bob
            .encrypt("group", b"delayed from removed member")
            .unwrap();
        let remove = alice.remove_member("group", bob.identity()).unwrap();
        assert!(matches!(
            bob.process("group", &remove, &owner).unwrap(),
            Processed::Commit { removed: true, .. }
        ));
        charlie.process("group", &remove, &owner).unwrap();
        assert!(charlie.process("group", &delayed, &owner).is_err());
        let message = alice.encrypt("group", b"after removal").unwrap();
        assert!(bob.process("group", &message, &owner).is_err());
        assert!(bob.encrypt("group", b"forbidden").is_err());
        assert_eq!(
            plaintext(charlie.process("group", &message, &owner).unwrap()),
            b"after removal"
        );
    }

    #[test]
    fn commits_require_coordinator_and_order_without_mutating_rejected_state() {
        let (mut alice, mut bob, owner) = pair();
        let before = alice.snapshot().unwrap();
        let unauthorized = bob.commit_updates("group").unwrap();
        assert!(alice.process("group", &unauthorized, &owner).is_err());
        assert_eq!(alice.snapshot().unwrap(), before);
        // Restore Bob to the legitimate branch before exercising ordered catch-up.
        let (mut alice, mut bob, owner) = pair();
        let first = alice.commit_updates("group").unwrap();
        let second = alice.commit_updates("group").unwrap();
        let before = bob.snapshot().unwrap();
        assert!(bob.process("group", &second, &owner).is_err());
        assert_eq!(bob.snapshot().unwrap(), before);
        bob.process("group", &first, &owner).unwrap();
        bob.process("group", &second, &owner).unwrap();
        assert_eq!(alice.epoch("group").unwrap(), bob.epoch("group").unwrap());
    }

    #[test]
    fn welcome_owner_binding_and_keypackage_survive_restart() {
        let mut alice = engine(1);
        let mut bob = engine(2);
        let kp = bob.key_package().unwrap();
        assert_eq!(
            CryptoEngine::key_package_identity(&kp).unwrap(),
            bob.identity()
        );
        bob = CryptoEngine::from_snapshot(&bob.snapshot().unwrap()).unwrap();
        alice.create_group("group").unwrap();
        let (_, welcome) = alice.add_member("group", &kp).unwrap();
        assert!(bob.join_from(&welcome, &hex::encode([0; 32])).is_err());
        bob.join_from(&welcome, alice.identity()).unwrap();
        assert!(bob.join_from(&welcome, alice.identity()).is_err());
    }

    #[test]
    fn pruning_key_packages_preserves_unconsumed_welcome_keys() {
        let mut alice = engine(1);
        let mut bob = engine(2);
        let time = crate::model::now() as u64;
        bob.key_package_with_lifetime(Lifetime::init(time - 100, time - 1))
            .unwrap();
        let live_package = bob.key_package().unwrap();
        let bundle_count = |engine: &CryptoEngine| {
            engine
                .provider
                .storage()
                .values
                .read()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.starts_with(b"KeyPackage"))
                .count()
        };
        assert_eq!(bundle_count(&bob), 2);
        bob.prune_expired_secrets().unwrap();
        assert_eq!(bundle_count(&bob), 1);
        bob = CryptoEngine::from_snapshot(&bob.snapshot().unwrap()).unwrap();
        assert_eq!(bundle_count(&bob), 1);
        assert!(bob.key_package_available(&live_package).unwrap());
        alice.create_group("delayed-welcome").unwrap();
        let (_, welcome) = alice.add_member("delayed-welcome", &live_package).unwrap();
        bob.join_from(&welcome, alice.identity()).unwrap();
    }

    #[test]
    fn member_update_proposal_and_commit() {
        let (mut alice, mut bob, owner) = pair();
        let proposal = bob.propose_update("group").unwrap();
        assert!(matches!(
            alice.process("group", &proposal, &owner).unwrap(),
            Processed::Proposal { .. }
        ));
        let commit = alice.commit_updates("group").unwrap();
        bob.process("group", &commit, &owner).unwrap();
        let message = bob.encrypt("group", b"updated").unwrap();
        assert_eq!(
            plaintext(alice.process("group", &message, &owner).unwrap()),
            b"updated"
        );
    }

    #[test]
    fn delayed_legitimate_message_and_invalid_ciphertext_do_not_destroy_ratchets() {
        let (mut alice, mut bob, owner) = pair();
        let delayed = alice.encrypt("group", b"before update").unwrap();
        let commit = alice.commit_updates("group").unwrap();
        bob.process("group", &commit, &owner).unwrap();
        assert_eq!(
            plaintext(bob.process("group", &delayed, &owner).unwrap()),
            b"before update"
        );
        let valid = alice.encrypt("group", b"authentic").unwrap();
        let mut invalid = valid.clone();
        let last = invalid.len() - 1;
        invalid[last] ^= 1;
        let before = bob.snapshot().unwrap();
        assert!(bob.process("group", &invalid, &owner).is_err());
        assert_eq!(bob.snapshot().unwrap(), before);
        assert_eq!(
            plaintext(bob.process("group", &valid, &owner).unwrap()),
            b"authentic"
        );
    }

    #[test]
    fn signed_keypackage_cannot_claim_another_identity() {
        let attacker = engine(4);
        let package = KeyPackage::builder()
            .build(
                SUITE,
                &attacker.provider,
                &attacker.signer,
                CredentialWithKey {
                    credential: BasicCredential::new(engine(1).identity().as_bytes().to_vec())
                        .into(),
                    signature_key: attacker.signer.to_public_vec().into(),
                },
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        assert!(CryptoEngine::key_package_identity(&package).is_err());
        let mut alice = engine(1);
        alice.create_group("group").unwrap();
        let before = alice.snapshot().unwrap();
        assert!(alice.add_member("group", &package).is_err());
        assert_eq!(alice.snapshot().unwrap(), before);
    }

    #[test]
    fn explicit_rejoin_uses_fresh_keys_and_does_not_restore_old_messages() {
        let (mut alice, mut bob, owner) = pair();
        let old_message = alice.encrypt("group", b"old history").unwrap();
        let fresh_package = bob.key_package().unwrap();
        alice.remove_member("group", bob.identity()).unwrap();
        let (_, welcome) = alice.add_member("group", &fresh_package).unwrap();
        let before = bob.snapshot().unwrap();
        assert!(bob.join_from(&welcome, &owner).is_err());
        assert_eq!(bob.snapshot().unwrap(), before);
        assert!(
            bob.rejoin_from(&welcome, "group", &hex::encode([0; 32]))
                .is_err()
        );
        assert_eq!(bob.snapshot().unwrap(), before);
        bob.rejoin_from(&welcome, "group", &owner).unwrap();
        assert!(bob.process("group", &old_message, &owner).is_err());
        let fresh = alice.encrypt("group", b"fresh").unwrap();
        assert_eq!(
            plaintext(bob.process("group", &fresh, &owner).unwrap()),
            b"fresh"
        );
        bob = CryptoEngine::from_snapshot(&bob.snapshot().unwrap()).unwrap();
        assert_eq!(bob.epoch("group").unwrap(), alice.epoch("group").unwrap());
    }

    #[test]
    fn offline_member_catches_up_with_archived_update_dependency() {
        let (mut alice, mut bob, owner) = pair();
        let mut charlie = engine(3);
        let (add, welcome) = alice
            .add_member("group", &charlie.key_package().unwrap())
            .unwrap();
        bob.process("group", &add, &owner).unwrap();
        charlie.join_from(&welcome, &owner).unwrap();
        let offline_snapshot = charlie.snapshot().unwrap();

        let proposal = bob.propose_update("group").unwrap();
        alice.process("group", &proposal, &owner).unwrap();
        let commit = alice.commit_updates("group").unwrap();
        // Bob already stored his own proposal when creating it and must not
        // attempt to decrypt the network copy of his own private handshake.
        bob.process("group", &commit, &owner).unwrap();

        charlie = CryptoEngine::from_snapshot(&offline_snapshot).unwrap();
        assert!(charlie.process("group", &commit, &owner).is_err());
        assert_eq!(charlie.snapshot().unwrap(), offline_snapshot);
        charlie.process("group", &proposal, &owner).unwrap();
        charlie.process("group", &commit, &owner).unwrap();
        assert_eq!(
            charlie.epoch("group").unwrap(),
            alice.epoch("group").unwrap()
        );
        let message = bob.encrypt("group", b"after offline catch-up").unwrap();
        assert_eq!(
            plaintext(charlie.process("group", &message, &owner).unwrap()),
            b"after offline catch-up"
        );
    }

    #[test]
    fn commit_reports_only_updates_it_authenticates() {
        let (mut alice, mut bob, owner) = pair();
        let bob_identity = bob.identity().to_owned();
        let _uncommitted = bob.propose_update("group").unwrap();
        // Alice has not received Bob's proposal. Bob's local proposal store,
        // or an unauthenticated transport sidecar, is not proof it was committed.
        let commit = alice.commit_updates("group").unwrap();
        match bob.process("group", &commit, &owner).unwrap() {
            Processed::Commit {
                updated_members, ..
            } => {
                assert!(updated_members.contains(&owner));
                assert!(!updated_members.contains(&bob_identity));
            }
            _ => panic!("expected commit"),
        }
        assert!(
            bob.propose_update("group").is_ok(),
            "uncommitted Update can be replaced in the new epoch"
        );
    }

    #[test]
    #[ignore = "50-member real MLS interoperability and resource test"]
    fn fifty_members_exchange_messages_and_reject_fifty_first() {
        let mut members: Vec<_> = (1..=50).map(engine).collect();
        let owner = members[0].identity().to_owned();
        members[0].create_group("fifty").unwrap();
        for joining in 1..members.len() {
            let package = members[joining].key_package().unwrap();
            let (commit, welcome) = members[0].add_member("fifty", &package).unwrap();
            for existing in members.iter_mut().take(joining).skip(1) {
                existing.process("fifty", &commit, &owner).unwrap();
            }
            members[joining].join_from(&welcome, &owner).unwrap();
        }
        for member in &members {
            assert_eq!(member.members("fifty").unwrap().len(), MAX_GROUP_MEMBERS);
            assert_eq!(member.epoch("fifty").unwrap(), 49);
        }
        for sender_index in 0..members.len() {
            let sender = members[sender_index].identity().to_owned();
            let text = format!("member {sender_index} to all 49 peers");
            let message = members[sender_index]
                .encrypt("fifty", text.as_bytes())
                .unwrap();
            for (recipient_index, recipient) in members.iter_mut().enumerate() {
                if recipient_index == sender_index {
                    continue;
                }
                match recipient.process("fifty", &message, &owner).unwrap() {
                    Processed::Application {
                        sender: authenticated,
                        plaintext,
                    } => {
                        assert_eq!(authenticated, sender);
                        assert_eq!(plaintext, text.as_bytes());
                    }
                    _ => panic!("expected an application message"),
                }
            }
        }
        let mut extra = engine(51);
        let before = members[0].snapshot().unwrap();
        assert!(
            members[0]
                .add_member("fifty", &extra.key_package().unwrap())
                .is_err()
        );
        assert_eq!(members[0].snapshot().unwrap(), before);
    }
}
