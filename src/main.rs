use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use clichat::{
    app::{
        App, Shared, acquire_key_package, connect_contact, decode_invitation, encode_invitation,
        encode_invitation_file, fingerprint, identity_card, media_tick, network_tick, send_media,
    },
    model::{Pending, Response, now},
    storage::Store,
    transport::Transport,
};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

mod media_view;
mod ui;

#[derive(Parser)]
#[command(version, about = "Terminal chat")]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Use a separate encrypted profile directory"
    )]
    data_dir: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Read the profile password from a private file instead of prompting"
    )]
    password_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        name: String,
    },
    Chat,
    Serve,
    Invite {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Contact {
        #[command(subcommand)]
        command: ContactCommand,
    },
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    Send {
        conversation: String,
        text: String,
    },
    Attach {
        conversation: String,
        file: PathBuf,
        #[arg(long, default_value = "")]
        caption: String,
    },
    History {
        conversation: String,
    },
    Status,
    Config {
        key: String,
        value: String,
    },
}

#[derive(Subcommand)]
enum ContactCommand {
    Add { invitation: String },
    List,
}

#[derive(Subcommand)]
enum GroupCommand {
    Create {
        name: String,
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    Add {
        conversation: String,
        contact: String,
    },
    Remove {
        conversation: String,
        contact: String,
    },
    List,
    Recover {
        conversation: String,
    },
}

fn password(cli: &Cli, create: bool) -> Result<Zeroizing<String>> {
    let value = if let Some(path) = &cli.password_file {
        ensure!(fs::metadata(path)?.len() <= 4096, "password file too large");
        Zeroizing::new(
            fs::read_to_string(path)?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        )
    } else {
        let value = Zeroizing::new(rpassword::prompt_password("Profile password: ")?);
        if create {
            let confirm = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
            ensure!(*value == *confirm, "passwords do not match");
        }
        value
    };
    ensure!(!value.is_empty(), "password cannot be empty");
    Ok(value)
}

pub(crate) fn read_invitation(value: &str) -> Result<clichat::model::Invitation> {
    if value.trim_start().starts_with("clichat1:") {
        decode_invitation(value)
    } else {
        let value = value.trim().trim_matches('"');
        ensure!(
            fs::metadata(value)?.len() <= 256 * 1024,
            "invitation file too large"
        );
        decode_invitation(&fs::read_to_string(value)?)
    }
}

/// Decodes and verifies an invitation without importing it. Returns the name, the
/// identity and the canonical token: confirming imports that token, never the file again.
pub(crate) fn preview_invitation(value: &str) -> Result<(String, String, String)> {
    let invitation = read_invitation(value)?;
    let token = encode_invitation(&invitation)?;
    Ok((invitation.contact.name, invitation.contact.id, token))
}

pub(crate) fn export_invitation(shared: &Shared, output: Option<PathBuf>) -> Result<String> {
    let invitation = shared.lock().unwrap().invitation()?;
    let token = encode_invitation(&invitation)?;
    if let Some(path) = output {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .context("cannot create invitation file (existing files are not overwritten)")?;
        file.write_all(encode_invitation_file(&invitation)?.as_bytes())?;
        Ok(format!("saved {}", path.display()))
    } else {
        Ok(token)
    }
}

/// Shared by `clichat config proxy` and the in-app Proxy item.
fn set_proxy(app: &mut App, value: &str) -> Result<()> {
    if value == "off" {
        app.state.proxy = None;
        return Ok(());
    }
    // A bare host:port is accepted as an HTTP proxy.
    let value = if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    };
    let url = url::Url::parse(&value)?;
    ensure!(
        ["http", "https"].contains(&url.scheme()) && url.host_str().is_some(),
        "proxy must be HTTP/HTTPS"
    );
    app.state.proxy = Some(value);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let _ = media_view::cleanup_expired(now());
    let path = cli.data_dir.clone().unwrap_or_else(|| {
        directories::ProjectDirs::from("org", "clichat", "clichat")
            .expect("home directory unavailable")
            .data_dir()
            .to_owned()
    });
    let creating = matches!(cli.command, Some(Command::Init { .. }));
    if creating {
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
    }
    let db = path.join("profile.db");
    ensure!(
        creating || db.exists(),
        "profile not found; run clichat init --name YOUR_NAME first"
    );
    let password = password(&cli, creating)?;
    let mut app = if let Some(Command::Init { name }) = &cli.command {
        App::initialize(Store::create(&db, &password)?, name.clone())?
    } else {
        App::load(Store::open(&db, &password)?)?
    };
    drop(password);
    if creating {
        println!(
            "Created profile for {}\nIdentity: {}\nFingerprint: {}\n{}\nStart with: clichat chat",
            app.state.name,
            app.id(),
            fingerprint(app.id()),
            identity_card(&app.state.name, app.id())
        );
        return Ok(());
    }
    match &cli.command {
        Some(Command::Config { key, value }) => {
            app.atomic(|app| {
                match key.as_str() {
                    "proxy" => set_proxy(app, value)?,
                    "cache" => {
                        app.state.relay_enabled = match value.as_str() {
                            "on" => true,
                            "off" => false,
                            _ => bail!("use on or off"),
                        }
                    }
                    _ => bail!("supported settings: proxy URL|off; cache on|off"),
                }
                Ok(())
            })?;
            println!("Configuration saved for the next start.");
            return Ok(());
        }
        Some(Command::Status) => {
            println!(
                "Name: {}\nIdentity: {}\nContacts: {}\nConversations: {}\nQueued deliveries: {}\nActive cache replicas: {}/3\nProxy: {}\nPublic cache participation: {}",
                app.state.name,
                app.id(),
                app.state.contacts.len(),
                app.state.conversations.len(),
                app.state.outbox.len(),
                app.state
                    .mailboxes
                    .iter()
                    .filter(|m| m.retired_at.is_none())
                    .count(),
                if app.state.proxy.is_some() {
                    "enabled (strict)"
                } else {
                    "disabled"
                },
                app.state.relay_enabled
            );
            return Ok(());
        }
        Some(Command::History { conversation }) => {
            let id = app.resolve_group(conversation)?;
            for message in app
                .state
                .messages
                .iter()
                .filter(|m| m.conversation == id && m.expires_at > now())
            {
                println!(
                    "{}: {}",
                    &message.sender[..8.min(message.sender.len())],
                    safe(&message.text)
                );
                if let Some(media) = &message.attachment {
                    println!(
                        "  [{} · {} · {} bytes]",
                        &message.id[..8.min(message.id.len())],
                        media.name,
                        media.size
                    );
                }
            }
            return Ok(());
        }
        Some(Command::Contact {
            command: ContactCommand::List,
        }) => {
            for contact in app.state.contacts.values() {
                println!(
                    "{}  {}\n  {}\n{}",
                    contact.name,
                    contact.id,
                    fingerprint(&contact.id),
                    identity_card(&contact.name, &contact.id)
                );
            }
            return Ok(());
        }
        Some(Command::Group {
            command: GroupCommand::List,
        }) => {
            for group in app.state.conversations.values() {
                println!(
                    "{}  {}  {} members  epoch {}  {}",
                    group.id,
                    group.name,
                    group.members.len(),
                    group.epoch,
                    if group.active { "active" } else { "removed" }
                );
            }
            return Ok(());
        }
        _ => {}
    }
    let secret: [u8; 32] = app.state.transport_secret.as_slice().try_into()?;
    let mut transport = Transport::bind(secret, app.state.proxy.as_deref()).await?;
    let _ = transport.online().await;
    app.ticket = transport.ticket().unwrap_or_default();
    app.state.contact_version += 1;
    app.status = if app.ticket.is_empty() {
        "offline".into()
    } else {
        String::new()
    };
    app.save()?;
    let mut incoming = transport
        .take_incoming()
        .context("missing incoming request channel")?;
    let transport = Arc::new(transport);
    let shared = Arc::new(Mutex::new(app));
    let serving = shared.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = incoming.recv().await {
            let response = {
                let mut app = serving.lock().unwrap();
                match app.handle(&incoming.peer_id, incoming.request) {
                    Ok(response) => response,
                    Err(error) => Response::Error(error.to_string()),
                }
            };
            let _ = incoming.reply.send(response);
        }
    });
    let continuous = matches!(
        cli.command,
        None | Some(Command::Chat) | Some(Command::Serve)
    );
    let headless = matches!(cli.command, Some(Command::Serve));
    match cli.command.unwrap_or(Command::Chat) {
        Command::Chat | Command::Serve => {}
        Command::Invite { output } => println!("{}", export_invitation(&shared, output)?),
        Command::Contact {
            command: ContactCommand::Add { invitation },
        } => {
            let invitation = read_invitation(&invitation)?;
            let invitation_name = invitation.contact.name.clone();
            let id = shared
                .lock()
                .unwrap()
                .atomic(|app| app.import_contact(invitation))?;
            println!(
                "Pinned contact {id}\nVerify fingerprint out of band: {}\n{}",
                fingerprint(&id),
                identity_card(&invitation_name, &id)
            );
            if let Err(error) = connect_contact(&shared, &transport, &id).await {
                eprintln!("Saved; peer currently unavailable: {error}");
            }
        }
        Command::Group { command } => match command {
            GroupCommand::Create { name, members } => {
                let members = {
                    let app = shared.lock().unwrap();
                    members
                        .iter()
                        .map(|m| app.resolve_contact(m))
                        .collect::<Result<Vec<_>>>()?
                };
                for id in &members {
                    acquire_key_package(&shared, &transport, id).await?;
                }
                let id = shared
                    .lock()
                    .unwrap()
                    .atomic(|app| app.create_group(name, members))?;
                println!("Created conversation {id}");
            }
            GroupCommand::Add {
                conversation,
                contact,
            } => {
                let (group, member) = {
                    let app = shared.lock().unwrap();
                    (
                        app.resolve_group(&conversation)?,
                        app.resolve_contact(&contact)?,
                    )
                };
                acquire_key_package(&shared, &transport, &member)
                    .await
                    .context("member must be reachable to obtain a fresh invitation")?;
                shared
                    .lock()
                    .unwrap()
                    .atomic(|app| app.add_member(&group, &member))?;
            }
            GroupCommand::Remove {
                conversation,
                contact,
            } => {
                let mut app = shared.lock().unwrap();
                let group = app.resolve_group(&conversation)?;
                let member = app.resolve_contact(&contact)?;
                app.atomic(|app| app.remove_member(&group, &member))?;
            }
            GroupCommand::Recover { conversation } => {
                queue_recovery(&shared, &conversation)?;
            }
            GroupCommand::List => unreachable!(),
        },
        Command::Send { conversation, text } => {
            clichat::app::synchronize(&shared, &transport).await;
            let mut app = shared.lock().unwrap();
            let id = app.resolve_group(&conversation)?;
            let message = app.atomic(|app| app.send(&id, text))?;
            println!("Queued {message}; expires in 72 hours.");
        }
        Command::Attach {
            conversation,
            file,
            caption,
        } => {
            clichat::app::synchronize(&shared, &transport).await;
            let id = shared.lock().unwrap().resolve_group(&conversation)?;
            let message = send_media(&shared, &id, file, caption).await?;
            println!(
                "Queued attachment {message}; run clichat chat or serve to keep transfers online."
            );
        }
        _ => unreachable!(),
    }
    if continuous {
        let background = shared.clone();
        let net = transport.clone();
        let worker = tokio::spawn(async move {
            let mut turn = 0u64;
            loop {
                if let Err(error) = network_tick(&background, &net, turn.is_multiple_of(6)).await {
                    background.lock().unwrap().status = format!("Network: {error}");
                }
                turn += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let background = shared.clone();
        let net = transport.clone();
        let media_worker = tokio::spawn(async move {
            let mut last_cleanup = std::time::Instant::now();
            loop {
                if let Err(error) = media_tick(&background, &net).await {
                    background.lock().unwrap().status = format!("Media: {error}");
                }
                if last_cleanup.elapsed() >= Duration::from_secs(1) {
                    let _ = media_view::cleanup_expired(now());
                    last_cleanup = std::time::Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        // serve is also useful when leaving a client online to cache ciphertext.
        if headless {
            println!(
                "Client running. Ctrl-C to stop. Identity: {}",
                shared.lock().unwrap().id()
            );
            tokio::signal::ctrl_c().await?;
        } else {
            ui::run(shared.clone(), transport.clone()).await?;
        }
        worker.abort();
        let _ = worker.await;
        media_worker.abort();
        let _ = media_worker.await;
    } else {
        let _ = tokio::time::timeout(
            Duration::from_secs(15),
            network_tick(&shared, &transport, true),
        )
        .await;
    }
    shared.lock().unwrap().save()?;
    transport.close().await;
    accept.abort();
    Ok(())
}

pub(crate) fn safe(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

pub(crate) fn queue_recovery(shared: &Shared, conversation: &str) -> Result<()> {
    let mut app = shared.lock().unwrap();
    let id = app.resolve_group(conversation)?;
    app.atomic(|app| {
        let request = app.prepare_recovery(&id)?;
        let recipient = app.state.conversations.get(&id).unwrap().owner.clone();
        app.state.pending.push(Pending { recipient, request });
        Ok(())
    })
}

pub(crate) async fn ui_command(
    shared: &Shared,
    transport: &Transport,
    selected: &mut Option<String>,
    input: String,
) -> Result<bool> {
    if !input.starts_with('/') {
        let id = selected.as_ref().context("no conversation")?;
        ensure!(!input.is_empty(), "empty message");
        shared.lock().unwrap().atomic(|app| app.send(id, input))?;
        return Ok(false);
    }
    let (command, rest) = input.split_once(' ').unwrap_or((&input, ""));
    match command {
        "/quit" | "/exit" => return Ok(true),
        "/attach" => {
            let id = selected.as_ref().context("no conversation")?;
            let path = rest.trim().trim_matches('"');
            ensure!(!path.is_empty(), "file required");
            let message = send_media(shared, id, PathBuf::from(path), String::new()).await?;
            shared.lock().unwrap().status = format!("queued {}", &message[..8]);
        }
        "/download" => {
            let mut app = shared.lock().unwrap();
            let message = app.request_media(rest.trim(), selected.as_deref())?;
            app.status = format!("requested {}", &message.id[..8.min(message.id.len())]);
        }
        "/invite" => {
            ensure!(!rest.is_empty(), "file required");
            let status = export_invitation(shared, Some(PathBuf::from(rest)))?;
            shared.lock().unwrap().status = status;
        }
        "/add" => {
            ensure!(!rest.trim().is_empty(), "file or code required");
            let invite = read_invitation(rest)?;
            let id = shared
                .lock()
                .unwrap()
                .atomic(|app| app.import_contact(invite))?;
            let _ = connect_contact(shared, transport, &id).await;
            shared.lock().unwrap().status = format!("added {}", fingerprint(&id));
        }
        "/proxy" => {
            ensure!(!rest.trim().is_empty(), "address or off");
            shared
                .lock()
                .unwrap()
                .atomic(|app| set_proxy(app, rest.trim()))?;
            shared.lock().unwrap().status = "proxy saved; restart".into();
        }
        "/use" => *selected = Some(shared.lock().unwrap().resolve_group(rest)?),
        "/dm" => {
            let member = shared.lock().unwrap().resolve_contact(rest)?;
            let existing = {
                let app = shared.lock().unwrap();
                app.state
                    .conversations
                    .values()
                    .find(|g| g.active && g.members.len() == 2 && g.members.contains(&member))
                    .map(|g| g.id.clone())
            };
            if let Some(id) = existing {
                *selected = Some(id);
            } else {
                acquire_key_package(shared, transport, &member).await?;
                *selected = Some(
                    shared
                        .lock()
                        .unwrap()
                        .atomic(|app| app.create_group(rest.into(), vec![member]))?,
                );
            }
        }
        "/group" => {
            let mut words = rest.split_whitespace();
            let name = words
                .next()
                .context("use /group NAME CONTACT...")?
                .to_owned();
            let members = {
                let app = shared.lock().unwrap();
                words
                    .map(|w| app.resolve_contact(w))
                    .collect::<Result<Vec<_>>>()?
            };
            ensure!(!members.is_empty(), "at least one other member required");
            for id in &members {
                acquire_key_package(shared, transport, id).await?;
            }
            *selected = Some(
                shared
                    .lock()
                    .unwrap()
                    .atomic(|app| app.create_group(name, members))?,
            );
        }
        "/add-member" | "/kick" => {
            let group = selected.as_ref().context("no conversation")?.clone();
            let member = shared.lock().unwrap().resolve_contact(rest)?;
            if command == "/add-member" {
                acquire_key_package(shared, transport, &member).await?;
                shared
                    .lock()
                    .unwrap()
                    .atomic(|app| app.add_member(&group, &member))?;
            } else {
                shared
                    .lock()
                    .unwrap()
                    .atomic(|app| app.remove_member(&group, &member))?;
            }
        }
        "/recover" => queue_recovery(shared, selected.as_deref().context("no conversation")?)?,
        _ => bail!("unknown command"),
    }
    Ok(false)
}
