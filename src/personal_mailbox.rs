//! A personal mailbox delegates delivery to a server, never the user's private keys.

use super::*;
use crate::server_protocol::{
    MailboxBinding, ServerInvitation, ServerRequest, SignedMailboxBinding,
};

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_credentials(mailbox: &str, write: &str, read: &str) -> Result<()> {
    ensure!(
        valid_hex(mailbox, 32)
            && valid_hex(write, 64)
            && valid_hex(read, 64)
            && !write.eq_ignore_ascii_case(read),
        "invalid mailbox credentials"
    );
    Ok(())
}

pub async fn attach_personal_mailbox(
    shared: &Shared,
    transport: &Transport,
    invitation: ServerInvitation,
) -> Result<()> {
    invitation.validate()?;
    let server_id = invitation.server_id()?;
    ensure!(
        server_id != transport.endpoint_id(),
        "personal mailbox requires an independent server"
    );
    let binding = {
        let mut app = shared.lock().unwrap();
        ensure!(
            app.state.mailboxes.len() < 12
                || app.state.mailboxes.iter().any(|mailbox| ticket_endpoint_id(
                    &mailbox.public.node_ticket
                )
                .ok()
                .as_ref()
                    == Some(&server_id)),
            "mailbox history is full; existing unread mailboxes must be drained first"
        );
        app.atomic(|app| {
            app.state.contact_version = app
                .state
                .contact_version
                .checked_add(1)
                .context("contact version exhausted")?;
            let secret = app.state.identity_secret.as_slice().try_into()?;
            SignedMailboxBinding::sign(
                MailboxBinding {
                    server_id: server_id.clone(),
                    identity: app.id().to_owned(),
                    endpoint: transport.endpoint_id(),
                    revision: app.state.contact_version,
                },
                secret,
            )
        })?
    };
    let response = transport
        .request(
            &invitation.ticket,
            Request::Server(ServerRequest::BindMailbox {
                provisioning_token: invitation.provisioning_token,
                binding,
            }),
        )
        .await?;
    let Response::Mailbox {
        mailbox_id,
        write_token,
        read_token,
    } = response
    else {
        if let Response::Error(error) = response {
            bail!("mailbox binding rejected: {error}");
        }
        bail!("unexpected mailbox binding response");
    };
    validate_credentials(&mailbox_id, &write_token, &read_token)?;
    shared.lock().unwrap().atomic(|app| {
        let previous = app.state.personal_mailbox.take();
        if let Some(previous) = previous {
            for mailbox in &mut app.state.mailboxes {
                if mailbox.public.mailbox_id == previous.mailbox_id
                    && ticket_endpoint_id(&mailbox.public.node_ticket)
                        .ok()
                        .as_ref()
                        == Some(&previous.node)
                {
                    mailbox.retired_at = Some(now());
                }
            }
        }
        let existing = app.state.mailboxes.iter().position(|mailbox| {
            mailbox.public.mailbox_id == mailbox_id
                && ticket_endpoint_id(&mailbox.public.node_ticket)
                    .ok()
                    .as_ref()
                    == Some(&server_id)
        });
        if existing.is_none() {
            ensure!(app.state.mailboxes.len() < 12, "mailbox history is full");
        }
        // One personal server occupies one of the three advertised replica slots.
        // A displaced cooperative mailbox remains readable for previously sent mail.
        while app
            .state
            .mailboxes
            .iter()
            .enumerate()
            .filter(|(index, mailbox)| Some(*index) != existing && mailbox.retired_at.is_none())
            .count()
            >= 3
        {
            let mailbox = app
                .state
                .mailboxes
                .iter_mut()
                .enumerate()
                .rev()
                .find(|(index, mailbox)| Some(*index) != existing && mailbox.retired_at.is_none())
                .context("missing active mailbox")?
                .1;
            mailbox.retired_at = Some(now());
        }
        let mailbox = LocalMailbox {
            public: Mailbox {
                node_ticket: invitation.ticket,
                mailbox_id: mailbox_id.clone(),
                write_token,
            },
            read_token,
            retired_at: None,
        };
        if let Some(index) = existing {
            app.state.mailboxes[index] = mailbox;
        } else {
            app.state.mailboxes.push(mailbox);
        }
        app.state.personal_mailbox = Some(PersonalMailbox {
            node: server_id,
            mailbox_id,
        });
        app.state.contact_version = app
            .state
            .contact_version
            .checked_add(1)
            .context("contact version exhausted")?;
        Ok(())
    })
}

impl App {
    pub fn detach_personal_mailbox(&mut self) -> Result<()> {
        let pinned = self
            .state
            .personal_mailbox
            .take()
            .context("no personal mailbox configured")?;
        for mailbox in &mut self.state.mailboxes {
            if mailbox.public.mailbox_id == pinned.mailbox_id
                && ticket_endpoint_id(&mailbox.public.node_ticket)
                    .ok()
                    .as_ref()
                    == Some(&pinned.node)
            {
                mailbox.retired_at = Some(now());
            }
        }
        self.state.contact_version = self
            .state
            .contact_version
            .checked_add(1)
            .context("contact version exhausted")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_mailbox_credentials_match_protocol_widths_and_separate_capabilities() {
        let mailbox = "12".repeat(16);
        let write = "a1".repeat(32);
        let read = "b2".repeat(32);
        assert!(validate_credentials(&mailbox, &write, &read).is_ok());
        for invalid in [String::new(), "12".repeat(32), "z1".repeat(16)] {
            assert!(validate_credentials(&invalid, &write, &read).is_err());
        }
        assert!(validate_credentials(&mailbox, "short", &read).is_err());
        assert!(validate_credentials(&mailbox, &write, &"z1".repeat(32)).is_err());
        assert!(validate_credentials(&mailbox, &write, &write).is_err());
        assert!(validate_credentials(&mailbox, &write, &write.to_ascii_uppercase()).is_err());
    }
}
