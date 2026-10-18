//! Bounded per-contact issuance and renewal of public joining material.

use super::*;

const PACKAGES_PER_CONTACT: usize = 16;
const CONSUMED_RETRY_WINDOW: i64 = 60 * 60;
const PUBLIC_REFRESH_MARGIN: i64 = 7 * 24 * 60 * 60;

impl App {
    pub(super) fn maintain_key_packages(&mut self, time: i64) -> Result<()> {
        // Existing profiles predate issuance metadata. Recover expiry from the
        // signed package and conservatively start its retry window at migration.
        for (key, invitation) in &self.state.issued_packages {
            if !self.state.issued_package_times.contains_key(key) {
                self.state.issued_package_times.insert(
                    key.clone(),
                    IssuedPackageTime {
                        issued_at: time,
                        expires_at: CryptoEngine::key_package_valid_until(
                            &invitation.contact.key_package,
                        )?,
                        consumed_at: None,
                    },
                );
            }
        }
        self.state.issued_packages.retain(|key, _| {
            self.state
                .issued_package_times
                .get(key)
                .is_some_and(|entry| entry.expires_at > time)
        });
        self.state
            .issued_package_times
            .retain(|key, _| self.state.issued_packages.contains_key(key));

        // An expired public package must not prevent Hello from reaching the
        // endpoint that issues its replacement. Rotate locally before publishing.
        let expires = CryptoEngine::key_package_valid_until(&self.state.key_package)?;
        if expires <= time.saturating_add(PUBLIC_REFRESH_MARGIN) {
            self.state.key_package = self.crypto.key_package()?;
            self.state.contact_version = self
                .state
                .contact_version
                .checked_add(1)
                .context("contact version exhausted")?;
        }
        Ok(())
    }

    pub(super) fn issue_key_package(
        &mut self,
        sender: &str,
        request_id: &str,
        time: i64,
    ) -> Result<Response> {
        ensure!(
            !request_id.is_empty() && request_id.len() <= 64,
            "invalid package request"
        );
        let key = format!("{sender}/{request_id}");
        let prefix = format!("{sender}/");
        // Persist maintenance even when the caller is still over quota, so a
        // rejected issuance cannot roll back the start of its reclamation window.
        self.atomic(|app| {
            app.maintain_key_packages(time)?;
            // Release only consumed packages after a bounded retry window.
            // Unconsumed private bundles remain available for delayed Welcomes
            // until their actual MLS lifetime ends.
            let mut completed = Vec::new();
            for (id, invitation) in app
                .state
                .issued_packages
                .iter()
                .filter(|(id, _)| id.starts_with(&prefix))
            {
                let issued = app
                    .state
                    .issued_package_times
                    .get_mut(id)
                    .context("missing package metadata")?;
                if !app
                    .crypto
                    .key_package_available(&invitation.contact.key_package)?
                {
                    let consumed_at = *issued.consumed_at.get_or_insert(time);
                    if time.saturating_sub(consumed_at) >= CONSUMED_RETRY_WINDOW {
                        completed.push(id.clone());
                    }
                }
            }
            for id in completed {
                app.state.issued_packages.remove(&id);
                app.state.issued_package_times.remove(&id);
            }
            Ok(())
        })?;
        if let Some(invitation) = self.state.issued_packages.get(&key) {
            return Ok(Response::Hello(invitation.clone()));
        }
        // Contacts are already limited to 512. A contact can occupy only its
        // own slots; it cannot exhaust a shared lifetime issuance counter.
        ensure!(
            self.state
                .issued_packages
                .keys()
                .filter(|id| id.starts_with(&prefix))
                .count()
                < PACKAGES_PER_CONTACT,
            "contact key package quota reached; retry after packages are used or expire"
        );
        self.atomic(|app| {
            app.state.key_package = app.crypto.key_package()?;
            app.state.contact_version = app
                .state
                .contact_version
                .checked_add(1)
                .context("contact version exhausted")?;
            let invitation = app.invitation()?;
            let expires_at =
                CryptoEngine::key_package_valid_until(&invitation.contact.key_package)?;
            app.state
                .issued_packages
                .insert(key.clone(), invitation.clone());
            app.state.issued_package_times.insert(
                key,
                IssuedPackageTime {
                    issued_at: time,
                    expires_at,
                    consumed_at: None,
                },
            );
            Ok(Response::Hello(invitation))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::Lifetime;

    fn profile(path: &std::path::Path, name: &str) -> Result<App> {
        let mut app = App::initialize(
            Store::create(&path.join(format!("{name}.db")), "package lifecycle tests")?,
            name.into(),
        )?;
        let secret: [u8; 32] = app.state.transport_secret.as_slice().try_into()?;
        app.ticket = crate::transport::encode_ticket(
            &iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&secret).public())
                .with_ip_addr("127.0.0.1:9".parse()?),
        )?;
        Ok(app)
    }

    fn exchange(a: &mut App, b: &mut App) -> Result<()> {
        a.atomic(|a| a.import_contact(b.invitation()?))?;
        b.atomic(|b| b.import_contact(a.invitation()?))?;
        Ok(())
    }

    #[test]
    fn issuance_quota_is_per_contact_persistent_and_retries_are_idempotent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut recipient = profile(dir.path(), "recipient")?;
        let mut alice = profile(dir.path(), "alice")?;
        let mut bob = profile(dir.path(), "bob")?;
        exchange(&mut recipient, &mut alice)?;
        exchange(&mut recipient, &mut bob)?;
        let peer = ticket_endpoint_id(&alice.ticket)?;
        let request = Request::KeyPackage {
            request_id: "0".into(),
        };
        let first = recipient.handle(&peer, request.clone())?;
        for index in 1..PACKAGES_PER_CONTACT {
            recipient.handle(
                &peer,
                Request::KeyPackage {
                    request_id: index.to_string(),
                },
            )?;
        }
        assert!(
            recipient
                .handle(
                    &peer,
                    Request::KeyPackage {
                        request_id: "overflow".into()
                    }
                )
                .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&first)?,
            serde_json::to_vec(&recipient.handle(&peer, request.clone())?)?
        );
        recipient.handle(
            &ticket_endpoint_id(&bob.ticket)?,
            Request::KeyPackage {
                request_id: "independent".into(),
            },
        )?;
        let ticket = recipient.ticket.clone();
        drop(recipient);
        let mut recipient = App::load(Store::open(
            &dir.path().join("recipient.db"),
            "package lifecycle tests",
        )?)?;
        recipient.ticket = ticket;
        assert_eq!(
            serde_json::to_vec(&first)?,
            serde_json::to_vec(&recipient.handle(&peer, request)?)?
        );
        assert!(
            recipient
                .handle(
                    &peer,
                    Request::KeyPackage {
                        request_id: "overflow".into()
                    }
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn consumed_packages_release_slots_without_deleting_delayed_welcome_keys() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut recipient = profile(dir.path(), "recipient")?;
        let mut owner = profile(dir.path(), "owner")?;
        exchange(&mut recipient, &mut owner)?;
        let peer = ticket_endpoint_id(&owner.ticket)?;
        let Response::Hello(invitation) = recipient.handle(
            &peer,
            Request::KeyPackage {
                request_id: "used".into(),
            },
        )?
        else {
            bail!("expected package");
        };
        let original_package = invitation.contact.key_package.clone();
        owner.atomic(|app| app.import_contact(invitation))?;
        let group =
            owner.atomic(|app| app.create_direct("group".into(), recipient.id().to_owned()))?;
        let join = owner.state.pending.iter().find(|pending| matches!(&pending.request, Request::Join { conversation, .. } if conversation.id == group)).context("missing Welcome")?.request.clone();
        // A Welcome may arrive long after issuance. Consuming it must not make
        // the response disappear immediately on a retry of the original request.
        let used_key = format!("{}/used", owner.id());
        recipient
            .state
            .issued_package_times
            .get_mut(&used_key)
            .unwrap()
            .issued_at = now() - 2 * 24 * 60 * 60;
        recipient.handle(&peer, join)?;
        let retry = recipient.handle(
            &peer,
            Request::KeyPackage {
                request_id: "used".into(),
            },
        )?;
        let Response::Hello(retry) = retry else {
            bail!("expected cached package");
        };
        assert_eq!(retry.contact.key_package, original_package);
        assert!(
            recipient.state.issued_package_times[&used_key]
                .consumed_at
                .is_some()
        );
        for index in 1..PACKAGES_PER_CONTACT {
            recipient.handle(
                &peer,
                Request::KeyPackage {
                    request_id: index.to_string(),
                },
            )?;
        }
        // A full quota must still persist a newly observed consumption clock.
        recipient
            .state
            .issued_package_times
            .get_mut(&used_key)
            .unwrap()
            .consumed_at = None;
        assert!(
            recipient
                .handle(
                    &peer,
                    Request::KeyPackage {
                        request_id: "replacement".into()
                    }
                )
                .is_err()
        );
        assert!(
            recipient.store.load_state()?.unwrap().issued_package_times[&used_key]
                .consumed_at
                .is_some()
        );
        recipient
            .state
            .issued_package_times
            .get_mut(&used_key)
            .unwrap()
            .consumed_at = Some(now() - CONSUMED_RETRY_WINDOW);
        recipient.handle(
            &peer,
            Request::KeyPackage {
                request_id: "replacement".into(),
            },
        )?;
        assert!(!recipient.state.issued_packages.contains_key(&used_key));
        let pending_key = format!("{}/1", owner.id());
        assert!(
            recipient.crypto.key_package_available(
                &recipient.state.issued_packages[&pending_key]
                    .contact
                    .key_package
            )?
        );
        assert_eq!(recipient.state.issued_packages.len(), PACKAGES_PER_CONTACT);
        Ok(())
    }

    #[test]
    fn expired_public_package_can_handshake_but_cannot_add_a_member() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut recipient = profile(dir.path(), "recipient")?;
        let mut owner = profile(dir.path(), "owner")?;
        let time = now() as u64;
        recipient.state.key_package = recipient
            .crypto
            .key_package_with_lifetime(Lifetime::init(time - 100, time - 1))?;
        let expired = recipient.invitation()?;
        assert!(CryptoEngine::key_package_identity(&expired.contact.key_package).is_err());
        owner.atomic(|app| app.import_contact(expired.clone()))?;
        assert!(
            owner
                .atomic(|app| app.create_direct("expired".into(), recipient.id().to_owned()))
                .is_err()
        );
        let mut corrupt = expired.contact.key_package.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(CryptoEngine::contact_key_package_identity(&corrupt).is_err());
        let future = recipient
            .crypto
            .key_package_with_lifetime(Lifetime::init(time + 3600, time + 7200))?;
        assert!(CryptoEngine::contact_key_package_identity(&future).is_err());

        recipient.save()?;
        assert!(CryptoEngine::key_package_identity(&recipient.state.key_package).is_ok());
        let response = recipient.handle(
            &ticket_endpoint_id(&owner.ticket)?,
            Request::Hello {
                invitation: owner.invitation()?,
                authorization: recipient.state.invite_token.clone(),
            },
        )?;
        let Response::Hello(fresh) = response else {
            bail!("expected Hello");
        };
        owner.atomic(|app| app.import_contact(fresh))?;
        let response = recipient.handle(
            &ticket_endpoint_id(&owner.ticket)?,
            Request::KeyPackage {
                request_id: "after-expiry".into(),
            },
        )?;
        let Response::Hello(fresh) = response else {
            bail!("expected package");
        };
        owner.atomic(|app| app.import_contact(fresh))?;
        owner.atomic(|app| app.create_direct("fresh".into(), recipient.id().to_owned()))?;
        Ok(())
    }

    #[test]
    fn expired_issuance_and_old_profile_metadata_are_reclaimed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut app = profile(dir.path(), "recipient")?;
        let time = now() as u64;
        app.state.key_package = app
            .crypto
            .key_package_with_lifetime(Lifetime::init(time - 100, time - 1))?;
        app.state
            .issued_packages
            .insert("legacy/old".into(), app.invitation()?);
        assert!(app.state.issued_package_times.is_empty());
        app.save()?;
        assert!(app.state.issued_packages.is_empty());
        assert!(app.state.issued_package_times.is_empty());
        assert!(
            CryptoEngine::key_package_valid_until(&app.state.key_package)?
                > now() + PUBLIC_REFRESH_MARGIN
        );
        Ok(())
    }
}
