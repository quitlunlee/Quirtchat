//! Deployment and client configuration for independent ciphertext servers.

use super::{Cli, password};
use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use clichat::{
    app::App,
    model::{Response, now},
    server::Server,
    server_protocol::{ServerInvitation, decode_server_invitation, encode_server_invitation},
    storage::Store,
    transport::{Transport, decode_ticket, ticket_endpoint_id},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Subcommand)]
pub(crate) enum ServerCommand {
    /// Create a server identity and encrypted database; no chat identity is created.
    Init,
    /// Run a server for hosted groups and optional personal mailboxes.
    Run {
        /// Write the private provisioning invitation to this file, replacing its previous value.
        #[arg(long)]
        invite_file: Option<PathBuf>,
        #[arg(long)]
        proxy: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum MailboxCommand {
    /// Bind a self-hosted mailbox using its private provisioning invitation.
    Attach {
        server: String,
    },
    /// Stop advertising this mailbox while continuing to drain already cached messages.
    Detach,
    List,
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn input_text(value: &str) -> Result<String> {
    let value = value.trim().trim_matches('"');
    if value.starts_with("clichat-server1:") || decode_ticket(value).is_ok() {
        return Ok(value.to_owned());
    }
    ensure!(
        fs::metadata(value)?.len() <= 64 * 1024,
        "server invitation file too large"
    );
    Ok(fs::read_to_string(value)?.trim().to_owned())
}

pub(crate) fn read_server_invitation(value: &str) -> Result<ServerInvitation> {
    decode_server_invitation(&input_text(value)?)
}

pub(crate) fn read_server_ticket(value: &str) -> Result<String> {
    let text = input_text(value)?;
    if let Ok(invitation) = decode_server_invitation(&text) {
        return Ok(invitation.ticket);
    }
    decode_ticket(&text)?;
    Ok(text)
}

pub(crate) fn trust_server(app: &mut App, ticket: String) -> Result<()> {
    let node = ticket_endpoint_id(&ticket)?;
    ensure!(
        app.state.group_servers.len() < 32
            || app
                .state
                .group_servers
                .iter()
                .any(|known| ticket_endpoint_id(known).ok().as_ref() == Some(&node)),
        "group server limit reached"
    );
    if let Some(known) = app
        .state
        .group_servers
        .iter_mut()
        .find(|known| ticket_endpoint_id(known).ok().as_ref() == Some(&node))
    {
        *known = ticket;
    } else {
        app.state.group_servers.push(ticket);
    }
    Ok(())
}

pub(crate) fn forget_server(app: &mut App, node: &str) -> Result<()> {
    ensure!(
        !app.state.conversations.values().any(|group| group.active
            && group
                .server
                .as_ref()
                .is_some_and(
                    |route| ticket_endpoint_id(&route.ticket).ok().as_deref() == Some(node)
                )),
        "an active group still uses this server"
    );
    let before = app.state.group_servers.len();
    app.state
        .group_servers
        .retain(|ticket| ticket_endpoint_id(ticket).ok().as_deref() != Some(node));
    ensure!(
        app.state.group_servers.len() < before,
        "server endpoint not found"
    );
    Ok(())
}

fn write_provisioning_file(path: &Path, invitation: &ServerInvitation) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        !path.is_symlink(),
        "provisioning file must not be a symlink"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{}", encode_server_invitation(invitation)?)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

pub(crate) async fn run_server(cli: &Cli, path: &Path, command: &ServerCommand) -> Result<()> {
    let creating = matches!(command, ServerCommand::Init);
    if creating {
        private_directory(path)?;
    }
    let database = path.join("server.db");
    ensure!(
        creating || database.exists(),
        "server not found; run server init first"
    );
    let passphrase = password(cli, creating)?;
    let mut server = if creating {
        Server::initialize(Store::create(&database, &passphrase)?)?
    } else {
        Server::load(Store::open(&database, &passphrase)?)?
    };
    drop(passphrase);
    if creating {
        println!(
            "Created ciphertext server. Run server run --invite-file PRIVATE_FILE to provision groups or a personal mailbox."
        );
        return Ok(());
    }
    let ServerCommand::Run { invite_file, proxy } = command else {
        unreachable!()
    };
    let mut transport = Transport::bind(server.transport_secret()?, proxy.as_deref()).await?;
    let _ = transport.online().await;
    let mut published = String::new();
    let mut incoming = transport
        .take_incoming()
        .context("missing server receiver")?;
    let mut maintenance = tokio::time::interval(Duration::from_secs(30));
    loop {
        if let Ok(ticket) = transport.ticket()
            && ticket != published
        {
            if let Some(path) = invite_file {
                write_provisioning_file(path, &server.invitation(&ticket)?)?;
            }
            println!("Server address: {ticket}");
            published = ticket;
        }
        tokio::select! {
            request = incoming.recv() => {
                let Some(request) = request else { bail!("server transport stopped") };
                let reply = server.handle(&request.peer_id, request.request)
                    .unwrap_or_else(|error| Response::Error(error.to_string()));
                let _ = request.reply.send(reply);
            }
            _ = maintenance.tick() => { server.purge(now())?; }
            signal = tokio::signal::ctrl_c() => { signal?; break; }
        }
    }
    transport.close().await;
    Ok(())
}

pub(crate) fn show_mailboxes(app: &App) {
    for mailbox in &app.state.mailboxes {
        let node = ticket_endpoint_id(&mailbox.public.node_ticket).unwrap_or_default();
        let personal = app.state.personal_mailbox.as_ref().is_some_and(|pinned| {
            pinned.node == node && pinned.mailbox_id == mailbox.public.mailbox_id
        });
        println!(
            "{}  {}  {}",
            node,
            if personal { "personal" } else { "cooperative" },
            if mailbox.retired_at.is_none() {
                "active"
            } else {
                "draining"
            }
        );
    }
}
