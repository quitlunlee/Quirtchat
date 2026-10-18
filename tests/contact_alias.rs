//! Local aliases must survive signed descriptor refreshes and old profile upgrades.
use anyhow::Result;
use clichat::{
    app::{App, decode_invitation, encode_invitation},
    model::{AppState, Contact},
    storage::Store,
    transport::encode_ticket,
};
use iroh::{EndpointAddr, SecretKey};
use tempfile::TempDir;

const PASSWORD: &str = "local aliases integration test password";

struct Profile {
    app: App,
    directory: TempDir,
}

impl Profile {
    fn new(name: &str) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let store = Store::create(&directory.path().join("profile.db"), PASSWORD)?;
        let mut app = App::initialize(store, name.into())?;
        let seed: [u8; 32] = app.state.transport_secret.as_slice().try_into()?;
        let address = EndpointAddr::new(SecretKey::from_bytes(&seed).public())
            .with_ip_addr("127.0.0.1:4000".parse()?);
        app.ticket = encode_ticket(&address)?;
        Ok(Self { app, directory })
    }

    fn restart(self) -> Result<Self> {
        let Self { app, directory } = self;
        drop(app);
        let store = Store::open(&directory.path().join("profile.db"), PASSWORD)?;
        Ok(Self {
            app: App::load(store)?,
            directory,
        })
    }
}

fn legacy_contact(id: &str, name: &str) -> Contact {
    Contact {
        id: id.into(),
        name: name.into(),
        ticket: String::new(),
        key_package: vec![],
        mailboxes: vec![],
        version: 1,
        invite_token: String::new(),
    }
}

#[test]
fn legacy_names_migrate_without_stealing_literal_suffixes_or_existing_aliases() -> Result<()> {
    let mut old = AppState::default();
    for (id, name) in [("a", "Alex"), ("b", "Alex"), ("c", "Alex_1")] {
        old.contacts.insert(id.into(), legacy_contact(id, name));
    }
    let mut json = serde_json::to_value(&old)?;
    json.as_object_mut().unwrap().remove("contact_names");
    let mut state: AppState = serde_json::from_value(json)?;
    assert!(state.contact_names.is_empty());
    state.normalize_contact_names();
    assert_eq!(state.contact_names["a"], "Alex");
    assert_eq!(state.contact_names["b"], "Alex_2");
    assert_eq!(state.contact_names["c"], "Alex_1");
    let aliases = state.contact_names.clone();
    state.normalize_contact_names();
    assert_eq!(aliases, state.contact_names);
    // This identity sorts first but must not rename anyone already assigned.
    state
        .contacts
        .insert("0".into(), legacy_contact("0", "Alex"));
    state.normalize_contact_names();
    assert_eq!(state.contact_names["0"], "Alex_3");
    for (id, name) in aliases {
        assert_eq!(state.contact_names[&id], name);
    }
    Ok(())
}

#[test]
fn remarks_preserve_signatures_survive_refresh_and_persist() -> Result<()> {
    let mut local = Profile::new("Local")?;
    let mut remote = Profile::new("Remote")?;
    let invitation = remote.app.invitation()?;
    let signed_bytes = serde_json::to_vec(&invitation)?;
    let id = local
        .app
        .atomic(|app| app.import_contact_named(invitation, "  小明 Work  "))?;
    assert_eq!(local.app.contact_name(&id), "小明 Work");
    assert_eq!(local.app.resolve_contact_name_exact("小明 Work")?, id);
    assert!(local.app.resolve_contact_name_exact("小明").is_err());
    assert!(local.app.resolve_contact_name_exact(&id).is_err());
    assert_eq!(local.app.resolve_contact(&id)?, id);
    assert_eq!(local.app.resolve_contact(&id[..12])?, id);
    assert_eq!(local.app.state.contacts[&id].name, "Remote");
    assert_eq!(
        serde_json::to_vec(&local.app.state.invitations[&id])?,
        signed_bytes
    );
    let token = encode_invitation(&local.app.state.invitations[&id])?;
    assert_eq!(decode_invitation(&token)?.contact.id, id);

    // Network updates replace signed metadata while the user remark stays local.
    remote.app.state.name = "Changed remotely".into();
    remote.app.state.contact_version += 1;
    remote.app.state.key_package = remote.app.crypto.key_package()?;
    local
        .app
        .atomic(|app| app.import_contact(remote.app.invitation()?))?;
    assert_eq!(local.app.contact_name(&id), "小明 Work");
    assert_eq!(local.app.state.contacts[&id].name, "Changed remotely");
    local
        .app
        .atomic(|app| app.import_contact_named(remote.app.invitation()?, ""))?;
    local = local.restart()?;
    assert_eq!(local.app.contact_name(&id), "小明 Work");
    assert_eq!(local.app.state.contacts.len(), 1);
    assert_eq!(local.app.state.invitations.len(), 1);
    // Simulate loading a pre-alias encrypted profile: the normal load path must
    // populate the local name map and persist the upgrade, without a UI action.
    local.app.state.contact_names.clear();
    local.app.store.save_state(&local.app.state)?;
    local = local.restart()?;
    assert_eq!(local.app.contact_name(&id), "Changed remotely");
    assert_eq!(local.app.state.contact_names.len(), 1);
    local = local.restart()?;
    assert_eq!(local.app.contact_name(&id), "Changed remotely");
    Ok(())
}

#[test]
fn duplicate_default_and_explicit_names_remain_unique_and_reimports_are_stable() -> Result<()> {
    let mut local = Profile::new("Local")?;
    let a = Profile::new("Alex")?;
    let b = Profile::new("Alex")?;
    let c = Profile::new("Alex_1")?;
    let a_id = local.app.import_contact_named(a.app.invitation()?, "")?;
    let c_id = local.app.import_contact_named(c.app.invitation()?, "")?;
    let b_id = local.app.import_contact_named(b.app.invitation()?, "")?;
    assert_eq!(local.app.contact_name(&a_id), "Alex");
    assert_eq!(local.app.contact_name(&c_id), "Alex_1");
    assert_eq!(local.app.contact_name(&b_id), "Alex_2");
    local
        .app
        .import_contact_named(b.app.invitation()?, "Alex")?;
    assert_eq!(local.app.contact_name(&b_id), "Alex_2");
    local
        .app
        .import_contact_named(b.app.invitation()?, "Alex_1")?;
    assert_eq!(local.app.contact_name(&b_id), "Alex_1_1");
    local
        .app
        .import_contact_named(b.app.invitation()?, "Alex_1_1")?;
    assert_eq!(local.app.contact_name(&b_id), "Alex_1_1");
    local.app.import_contact_named(b.app.invitation()?, "")?;
    assert_eq!(local.app.contact_name(&b_id), "Alex_1_1");
    assert_eq!(local.app.state.contacts.len(), 3);

    let wide = format!("{}ab", "猫".repeat(42));
    local.app.import_contact_named(a.app.invitation()?, &wide)?;
    local.app.import_contact_named(b.app.invitation()?, &wide)?;
    assert_eq!(
        local.app.contact_name(&b_id),
        format!("{}_1", "猫".repeat(42))
    );
    assert!(local.app.contact_name(&b_id).len() <= 128);
    // An exact local alias is preferred to an unrelated identity prefix.
    local
        .app
        .import_contact_named(a.app.invitation()?, &b_id[..12])?;
    assert_eq!(local.app.resolve_contact(&b_id[..12])?, a_id);
    assert_eq!(local.app.resolve_contact(&b_id)?, b_id);
    Ok(())
}

#[test]
fn invalid_remark_cannot_partially_import_a_contact() -> Result<()> {
    let mut local = Profile::new("Local")?;
    let remote = Profile::new("Remote")?;
    assert!(
        local
            .app
            .import_contact_named(remote.app.invitation()?, "two\nnames")
            .is_err()
    );
    assert!(
        local
            .app
            .import_contact_named(remote.app.invitation()?, &"x".repeat(129))
            .is_err()
    );
    assert!(local.app.state.contacts.is_empty());
    assert!(local.app.state.invitations.is_empty());
    assert!(local.app.state.contact_names.is_empty());
    Ok(())
}
