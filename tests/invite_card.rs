//! Randomart identity cards and the invitation file format.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use clichat::{
    app::{
        ART_HEIGHT, ART_WIDTH, App, decode_invitation, encode_invitation, encode_invitation_file,
        fingerprint, fingerprint_lines, identity_card, randomart, randomart_heat,
    },
    storage::Store,
    transport::encode_ticket,
};
use iroh::{EndpointAddr, SecretKey};
use tempfile::TempDir;

const PASSWORD: &str = "integration test profile passphrase";

fn profile(name: &str) -> Result<(App, TempDir)> {
    let directory = tempfile::tempdir()?;
    let store = Store::create(&directory.path().join("profile.db"), PASSWORD)?;
    let mut app = App::initialize(store, name.into())?;
    let seed: [u8; 32] = app.state.transport_secret.as_slice().try_into()?;
    let address = EndpointAddr::new(SecretKey::from_bytes(&seed).public())
        .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 4000)));
    app.ticket = encode_ticket(&address)?;
    Ok((app, directory))
}

#[test]
fn art_is_deterministic_fixed_size_and_marks_start_and_end() {
    let id = "ab".repeat(32);
    let art = randomart(&id);
    assert_eq!(art, randomart(&id));
    assert_eq!(art.len(), ART_HEIGHT);
    assert!(
        art.iter()
            .all(|row| row.chars().count() == ART_WIDTH && row.is_ascii())
    );
    let joined = art.concat();
    assert_eq!(joined.matches('S').count() + joined.matches('E').count(), 2);
    assert_ne!(art, randomart(&"cd".repeat(32)));
    assert_eq!(randomart_heat(&id).len(), ART_HEIGHT);
}

#[test]
fn card_is_framed_and_matches_the_existing_fingerprint() {
    let id = "ab".repeat(32);
    let card = identity_card("Alex", &id);
    let lines: Vec<_> = card.lines().collect();
    assert_eq!(lines.len(), 1 + ART_HEIGHT + 1 + 4);
    assert!(lines[0].starts_with("+-") && lines[0].contains("[ Alex ]"));
    assert!(
        lines[1..=ART_HEIGHT]
            .iter()
            .all(|l| l.starts_with('|') && l.ends_with('|'))
    );
    // Frame, art rows and footer are all exactly as wide as the art plus two borders.
    assert!(
        lines
            .iter()
            .take(ART_HEIGHT + 2)
            .all(|l| l.chars().count() == ART_WIDTH + 2)
    );
    assert!(lines[ART_HEIGHT + 1].contains("[SHA256]"));
    // Same digest as before: four lines of four groups rejoin into `fingerprint`.
    assert_eq!(fingerprint_lines(&id).join(" "), fingerprint(&id));
}

#[test]
fn long_or_hostile_names_cannot_break_the_frame() {
    let id = "ab".repeat(32);
    let card = identity_card("A\u{1b}[31m very long contact name that overflows", &id);
    assert!(!card.contains('\u{1b}'));
    let first = card.lines().next().unwrap();
    assert_eq!(first.chars().count(), ART_WIDTH + 2);
    // Wide (two-column) characters are measured by display width, not by count.
    let wide = identity_card("你好你好你好你好你好", &id);
    let first = wide.lines().next().unwrap();
    assert!(
        unicode_width::UnicodeWidthStr::width(first) <= ART_WIDTH + 2,
        "{first}"
    );
}

#[test]
fn invitation_files_decode_with_or_without_the_card() -> Result<()> {
    let (app, _directory) = profile("Alex")?;
    let invitation = app.invitation()?;
    let file = encode_invitation_file(&invitation)?;
    assert!(file.starts_with("+-") && file.lines().last().unwrap().starts_with("clichat1:"));
    let decoded = decode_invitation(&file)?;
    assert_eq!(decoded.contact.id, invitation.contact.id);
    // Old single-line files and bare tokens still work.
    let token = encode_invitation(&invitation)?;
    assert_eq!(decode_invitation(&token)?.contact.id, invitation.contact.id);
    assert_eq!(
        decode_invitation(&format!("{token}\n"))?.contact.id,
        invitation.contact.id
    );
    // The drawn art is decoration: a forged card changes nothing about the identity.
    let forged = file.replacen('S', "X", 1);
    assert_eq!(
        decode_invitation(&forged)?.contact.id,
        invitation.contact.id
    );
    assert!(decode_invitation("no token in here").is_err());
    Ok(())
}
