//! Hierarchical opaque menus. Identity selections use stable IDs, never names
//! interpolated into command text. The application owns all business actions.

use super::{
    files::Mode as FileMode,
    theme::{ACCENT, BORDER, MUTED, PANEL, TEXT},
};
use clichat::app::{ART_HEIGHT, ART_WIDTH, fingerprint_lines, randomart};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const QUERY_LIMIT: usize = 256 * 1024;
const CODE_PREFIX: &str = "clichat1:";
const COMMANDS: &[(&str, &str)] = &[
    ("dm", "Direct messages"),
    ("gc", "Groups"),
    ("setting", "Settings"),
    ("profile", "Profile"),
    ("send", "Send current draft"),
    ("q", "Quit"),
];
// Existing CLI capabilities remain reachable without filling the main menu.
const LEGACY: &[&str] = &[
    "add",
    "invite",
    "group",
    "group-host",
    "server-add",
    "mailbox",
    "add-member",
    "use",
    "attach",
    "download",
    "open",
    "kick",
    "proxy",
    "recover",
    "motion",
    "quit",
    "q!",
];

#[derive(Clone, Copy, Debug)]
pub(super) struct Target<'a> {
    pub id: &'a str,
    pub name: &'a str,
}

pub(super) struct Catalog<'a> {
    pub contacts: Vec<Target<'a>>,
    /// Groups only. DMs are selected from all known contacts.
    pub groups: Vec<Target<'a>>,
    /// Credential-free display of the current proxy configuration.
    pub proxy: &'a str,
    pub me: &'a str,
    pub me_id: &'a str,
    pub motion: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PaletteEvent {
    None,
    Run(String),
    Files(FileMode),
    Preview(String),
    SelectContact(String),
    SelectConversation(String),
    OpenCreateGroup,
    OpenJoinGroup,
    OpenMailboxSettings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Main,
    Dm,
    Groups,
    Settings,
    Proxy,
    Profile,
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Main => "Qu1rTChat",
            Self::Dm => "Direct messages",
            Self::Groups => "Groups",
            Self::Settings => "Settings",
            Self::Proxy => "Settings / Network proxy",
            Self::Profile => "Profile",
        }
    }
    fn parent(self) -> Self {
        match self {
            Self::Proxy => Self::Settings,
            _ => Self::Main,
        }
    }
}
#[derive(Clone, Debug)]
enum Act {
    Command(String),
    Contact(String),
    Conversation(String),
    Page(Page),
    Pick(FileMode),
    Preview(String),
    Create,
    Join,
    Mailbox,
    EditProxy,
    DisableProxy,
    Motion,
}
struct Entry {
    label: String,
    act: Act,
}
impl Entry {
    fn new(label: impl Into<String>, act: Act) -> Self {
        Self {
            label: label.into(),
            act,
        }
    }
}

pub(super) struct Palette {
    open: bool,
    since: Instant,
    page: Page,
    command_return: Option<Page>,
    query: String,
    search: Option<String>,
    proxy_edit: bool,
    selected: usize,
    visible_rows: Cell<usize>,
    selected_id: Option<String>,
}
impl Default for Palette {
    fn default() -> Self {
        Self {
            open: false,
            since: Instant::now(),
            page: Page::Main,
            command_return: None,
            query: String::new(),
            search: None,
            proxy_edit: false,
            selected: 0,
            visible_rows: Cell::new(8),
            selected_id: None,
        }
    }
}

impl Palette {
    pub(super) fn open(&mut self) {
        self.since = Instant::now();
        self.open = true;
        self.command_return = None;
        self.change_page(Page::Main);
    }
    pub(super) fn close(&mut self) {
        self.open = false;
    }
    pub(super) fn is_open(&self) -> bool {
        self.open
    }
    pub(super) fn is_visible(&self, _motion: bool) -> bool {
        self.open
    }
    pub(super) fn opened_elapsed(&self) -> Duration {
        self.since.elapsed()
    }
    pub(super) fn resume_dm(&mut self, selected_id: Option<&str>) {
        self.resume(Page::Dm);
        self.selected_id = selected_id.map(str::to_owned);
    }
    pub(super) fn resume_profile(&mut self) {
        self.resume(Page::Profile);
    }
    pub(super) fn resume_gc(&mut self) {
        self.resume(Page::Groups);
    }
    pub(super) fn resume_settings(&mut self) {
        self.resume(Page::Settings);
    }
    fn resume(&mut self, page: Page) {
        self.open = true;
        self.command_return = None;
        self.change_page(page);
    }
    fn change_page(&mut self, page: Page) {
        self.page = page;
        self.selected = 0;
        self.selected_id = None;
        self.query.clear();
        self.search = None;
        self.proxy_edit = false;
    }
    fn editing(&self) -> bool {
        self.page == Page::Main || self.search.is_some() || self.proxy_edit
    }
    fn input_mut(&mut self) -> &mut String {
        if let Some(search) = self.search.as_mut() {
            search
        } else {
            &mut self.query
        }
    }
    fn input(&self) -> &str {
        self.search.as_deref().unwrap_or(&self.query)
    }
    /// Paste is text only, never navigation or command execution.
    pub(super) fn paste(&mut self, text: &str) {
        if !self.open || !self.editing() {
            return;
        }
        let clean: String = text
            .chars()
            .map(|c| {
                if matches!(c, '\r' | '\n' | '\t') {
                    ' '
                } else {
                    c
                }
            })
            .filter(|c| !c.is_control())
            .collect();
        let input = self.input_mut();
        if input.len() + clean.len() <= QUERY_LIMIT {
            input.push_str(&clean);
            self.selected = if self.search.is_some() {
                self.pinned()
            } else {
                0
            };
            self.selected_id = None;
        }
    }
    fn entries(&self, catalog: &Catalog) -> Vec<Entry> {
        let needle = self.search.as_deref().unwrap_or("").to_lowercase();
        match self.page {
            Page::Main => command_entries(&self.query, catalog),
            Page::Dm => {
                let mut rows = vec![Entry::new("Add friend", Act::Pick(FileMode::Open))];
                rows.extend(
                    catalog
                        .contacts
                        .iter()
                        .filter(|c| c.name.to_lowercase().contains(&needle))
                        .map(|c| Entry::new(c.name, Act::Contact(c.id.to_owned()))),
                );
                rows
            }
            Page::Groups => {
                let mut rows = vec![
                    Entry::new("Create group", Act::Create),
                    Entry::new("Join group", Act::Join),
                ];
                rows.extend(
                    catalog
                        .groups
                        .iter()
                        .filter(|g| g.name.to_lowercase().contains(&needle))
                        .map(|g| Entry::new(g.name, Act::Conversation(g.id.to_owned()))),
                );
                rows
            }
            Page::Settings => vec![
                Entry::new(
                    format!("Network proxy  {}", catalog.proxy),
                    Act::Page(Page::Proxy),
                ),
                Entry::new("Personal server mailbox", Act::Mailbox),
                Entry::new(
                    format!(
                        "Animations     {}",
                        if catalog.motion { "On" } else { "Off" }
                    ),
                    Act::Motion,
                ),
            ],
            Page::Proxy => vec![
                Entry::new("Set proxy address", Act::EditProxy),
                Entry::new("Disable proxy", Act::DisableProxy),
            ],
            Page::Profile => vec![Entry::new("Export invite file", Act::Pick(FileMode::Save))],
        }
    }
    fn pinned(&self) -> usize {
        match self.page {
            Page::Dm => 1,
            Page::Groups => 2,
            _ => 0,
        }
    }
    fn selection(&self, entries: &[Entry]) -> usize {
        self.selected_id
            .as_deref()
            .and_then(|id| {
                entries
                    .iter()
                    .position(|e| matches!(&e.act, Act::Contact(candidate) if candidate == id))
            })
            .unwrap_or(self.selected)
            .min(entries.len().saturating_sub(1))
    }
    fn move_selection(&mut self, delta: isize, catalog: &Catalog) {
        let entries = self.entries(catalog);
        if entries.is_empty() {
            return;
        }
        let next = self.selection(&entries) as isize + delta;
        self.selected = next.rem_euclid(entries.len() as isize) as usize;
        self.selected_id = None;
    }
    pub(super) fn key(&mut self, key: KeyEvent, catalog: &Catalog) -> PaletteEvent {
        if !self.open {
            return PaletteEvent::None;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if matches!(key.code, KeyCode::Esc) || (control && key.code == KeyCode::Char('c')) {
            if self.search.take().is_some() {
                self.selected = 0;
            } else if self.proxy_edit {
                self.proxy_edit = false;
                self.query.clear();
            } else if self.page != Page::Main {
                self.change_page(self.page.parent());
            } else if let Some(parent) = self.command_return.take() {
                self.change_page(parent);
            } else {
                self.close();
            }
            return PaletteEvent::None;
        }
        if self.proxy_edit && key.code == KeyCode::Enter {
            let address = self.query.trim().to_owned();
            if address.is_empty() {
                return PaletteEvent::None;
            }
            self.proxy_edit = false;
            self.query.clear();
            return PaletteEvent::Run(format!("/proxy {address}"));
        }
        match key.code {
            KeyCode::Down | KeyCode::Tab => self.move_selection(1, catalog),
            KeyCode::Up | KeyCode::BackTab => self.move_selection(-1, catalog),
            KeyCode::Char('n') if control => self.move_selection(1, catalog),
            KeyCode::Char('p') if control => self.move_selection(-1, catalog),
            KeyCode::PageDown if !self.editing() => {
                self.move_selection(self.visible_rows.get().max(1) as isize, catalog)
            }
            KeyCode::PageUp if !self.editing() => {
                self.move_selection(-(self.visible_rows.get().max(1) as isize), catalog)
            }
            KeyCode::Char('j') if !self.editing() => self.move_selection(1, catalog),
            KeyCode::Char('k') if !self.editing() => self.move_selection(-1, catalog),
            KeyCode::Char('g') | KeyCode::Home if !self.editing() => {
                self.selected = 0;
                self.selected_id = None;
            }
            KeyCode::Char('G') | KeyCode::End if !self.editing() => {
                self.selected = self.entries(catalog).len().saturating_sub(1);
                self.selected_id = None;
            }
            KeyCode::Char('/')
                if !self.editing() && matches!(self.page, Page::Dm | Page::Groups) =>
            {
                self.search = Some(String::new());
                self.selected = self.pinned();
                self.selected_id = None;
            }
            KeyCode::Char(':') if !self.editing() => {
                let parent = self.page;
                self.change_page(Page::Main);
                self.command_return = Some(parent);
            }
            KeyCode::Backspace if self.editing() => {
                if self.input_mut().pop().is_none() && self.page == Page::Main {
                    self.close();
                }
                self.selected = if self.search.is_some() {
                    self.pinned()
                } else {
                    0
                };
                self.selected_id = None;
            }
            KeyCode::Char(c) if !control && !c.is_control() && self.editing() => {
                let input = self.input_mut();
                if input.len() + c.len_utf8() <= QUERY_LIMIT {
                    input.push(c);
                }
                self.selected = if self.search.is_some() {
                    self.pinned()
                } else {
                    0
                };
                self.selected_id = None;
            }
            KeyCode::Enter => {
                let entries = self.entries(catalog);
                if let Some(entry) = entries.get(self.selection(&entries)) {
                    return self.activate(entry.act.clone(), catalog);
                }
            }
            _ => {}
        }
        PaletteEvent::None
    }
    fn activate(&mut self, act: Act, catalog: &Catalog) -> PaletteEvent {
        let event = match act {
            Act::Page(page) => {
                self.change_page(page);
                return PaletteEvent::None;
            }
            Act::EditProxy => {
                self.proxy_edit = true;
                self.query.clear();
                return PaletteEvent::None;
            }
            Act::DisableProxy => return PaletteEvent::Run("/proxy off".into()),
            Act::Motion => return PaletteEvent::Run("/motion toggle".into()),
            Act::Contact(id) => PaletteEvent::SelectContact(id),
            Act::Conversation(id) => PaletteEvent::SelectConversation(id),
            Act::Pick(mode) => PaletteEvent::Files(mode),
            Act::Preview(source) => PaletteEvent::Preview(source),
            Act::Create => PaletteEvent::OpenCreateGroup,
            Act::Join => PaletteEvent::OpenJoinGroup,
            Act::Mailbox => PaletteEvent::OpenMailboxSettings,
            Act::Command(command) => {
                let (word, rest) = split_command(&command);
                match word {
                    "dm" => {
                        let matches: Vec<_> =
                            catalog.contacts.iter().filter(|c| c.name == rest).collect();
                        if !rest.is_empty() && matches.len() == 1 {
                            self.close();
                            return PaletteEvent::SelectContact(matches[0].id.to_owned());
                        }
                        self.change_page(Page::Dm);
                        if !rest.is_empty() {
                            self.search = Some(rest.to_owned());
                            self.selected = 1;
                        }
                        return PaletteEvent::None;
                    }
                    "gc" => {
                        self.change_page(Page::Groups);
                        if !rest.is_empty() {
                            self.search = Some(rest.to_owned());
                            self.selected = 2;
                        }
                        return PaletteEvent::None;
                    }
                    "setting" => {
                        self.change_page(Page::Settings);
                        return PaletteEvent::None;
                    }
                    "profile" => {
                        self.change_page(Page::Profile);
                        return PaletteEvent::None;
                    }
                    "proxy" if rest.is_empty() => {
                        self.change_page(Page::Proxy);
                        return PaletteEvent::None;
                    }
                    "add" if rest.is_empty() => PaletteEvent::Files(FileMode::Open),
                    "add" => PaletteEvent::Preview(rest.to_owned()),
                    "invite" if rest.is_empty() => PaletteEvent::Files(FileMode::Save),
                    "q" | "quit" => PaletteEvent::Run("/q".into()),
                    "q!" => PaletteEvent::Run("/q!".into()),
                    "send" => PaletteEvent::Run("/send".into()),
                    "motion" if rest.is_empty() => PaletteEvent::Run("/motion toggle".into()),
                    _ if rest.is_empty() && !matches!(word, "recover" | "motion") => {
                        self.query = format!("{word} ");
                        self.selected = 0;
                        return PaletteEvent::None;
                    }
                    _ => PaletteEvent::Run(format!("/{}", command.trim())),
                }
            }
        };
        self.close();
        event
    }
    /// Stable frame dimensions keep the penguin in place between child pages.
    pub(super) fn menu_rect(&self, area: Rect) -> Rect {
        menu_rect(area)
    }

    fn prompt(&self, width: u16) -> Option<String> {
        if !self.editing() {
            return None;
        }
        let prefix = if self.proxy_edit {
            "> "
        } else if self.search.is_some() {
            "/"
        } else {
            ":"
        };
        // Share the visible input with cursor placement, keeping its prefix and
        // one blank terminal cell after the text even when the input scrolls.
        let room = usize::from(width.saturating_sub(4));
        let prefix = head(prefix, room);
        let input = tail(self.input(), room.saturating_sub(prefix.len()));
        Some(format!("{prefix}{input}"))
    }

    pub(super) fn render(&self, buffer: &mut Buffer, area: Rect, catalog: &Catalog, _motion: bool) {
        if !self.open {
            return;
        }
        let rect = self.menu_rect(area).intersection(buffer.area);
        if rect.is_empty() {
            return;
        }
        solid_frame(buffer, rect);
        if rect.width < 3 || rect.height < 3 {
            return;
        }
        put(
            buffer,
            rect.x + 2,
            rect.y,
            &head(
                &format!(" {} ", self.page.title()),
                usize::from(rect.width.saturating_sub(4)),
            ),
            MUTED,
            rect,
        );
        let entries = self.entries(catalog);
        let selected = self.selection(&entries);
        let inner = Rect::new(
            rect.x + 1,
            rect.y + 1,
            rect.width.saturating_sub(2),
            rect.height.saturating_sub(2),
        );
        if self.page == Page::Profile {
            self.render_profile(buffer, inner, catalog, &entries);
            return;
        }
        let mut top = inner.y + 1;
        if let Some(prompt) = self.prompt(rect.width) {
            put(buffer, inner.x + 1, inner.y, &prompt, TEXT, inner);
            top += 1;
        }
        if self.page == Page::Proxy && inner.height >= 6 {
            put(
                buffer,
                inner.x + 1,
                top,
                &format!("Configured: {}", catalog.proxy),
                MUTED,
                inner,
            );
            top += 2;
        }
        let capacity = usize::from(inner.bottom().saturating_sub(top)).max(1);
        self.visible_rows.set(capacity);
        let indices = visible_indices(entries.len(), self.pinned(), selected, capacity);
        for (row, index) in indices.iter().copied().enumerate() {
            let y = top + row as u16;
            if y >= inner.bottom() {
                break;
            }
            if let Some(entry) = entries.get(index) {
                draw_entry(buffer, inner, y, &entry.label, index == selected);
            }
        }
        if inner.height < 4
            && let Some(entry) = entries.get(selected)
        {
            draw_entry(buffer, inner, inner.bottom() - 1, &entry.label, true);
        }
    }
    fn render_profile(
        &self,
        buffer: &mut Buffer,
        inner: Rect,
        catalog: &Catalog,
        entries: &[Entry],
    ) {
        if inner.is_empty() {
            return;
        }
        let action_y = inner.bottom().saturating_sub(1);
        let available = action_y.saturating_sub(inner.y);
        if available > 0 {
            centered(buffer, inner, inner.y, catalog.me, TEXT);
        }
        if available >= ART_HEIGHT as u16 + 2 && inner.width >= ART_WIDTH as u16 {
            for (i, line) in randomart(catalog.me_id).iter().enumerate() {
                centered(buffer, inner, inner.y + 2 + i as u16, line, ACCENT);
            }
            if available >= ART_HEIGHT as u16 + 7 {
                for (i, line) in fingerprint_lines(catalog.me_id).iter().enumerate() {
                    centered(
                        buffer,
                        inner,
                        inner.y + ART_HEIGHT as u16 + 3 + i as u16,
                        line,
                        MUTED,
                    );
                }
            }
        } else if available >= 3 {
            let fingerprint = fingerprint_lines(catalog.me_id);
            centered(
                buffer,
                inner,
                inner.y + 2,
                &format!("SHA-256 {}…", fingerprint[0]),
                MUTED,
            );
        }
        draw_entry(buffer, inner, action_y, &entries[0].label, true);
    }
    pub(super) fn cursor(&self, area: Rect, _motion: bool) -> Option<(u16, u16)> {
        if !self.open || !self.editing() {
            return None;
        }
        let rect = self.menu_rect(area);
        if rect.width < 5 || rect.height < 4 {
            return None;
        }
        let prompt = self.prompt(rect.width)?;
        let cells = UnicodeWidthStr::width(prompt.as_str()) as u16;
        Some(((rect.x + 2 + cells).min(rect.right() - 2), rect.y + 1))
    }
}
fn split_command(command: &str) -> (&str, &str) {
    let command = command.trim();
    let (word, rest) = command
        .split_once(char::is_whitespace)
        .unwrap_or((command, ""));
    (word, rest.trim())
}
fn command_entries(query: &str, catalog: &Catalog) -> Vec<Entry> {
    let query = query.trim_start();
    if query.starts_with(CODE_PREFIX) {
        return vec![Entry::new(
            "Import invitation",
            Act::Preview(query.trim().into()),
        )];
    }
    if let Some(needle) = query.strip_prefix('@') {
        return catalog
            .contacts
            .iter()
            .filter(|c| c.name.to_lowercase().contains(&needle.to_lowercase()))
            .map(|c| Entry::new(format!("@{}", c.name), Act::Contact(c.id.into())))
            .collect();
    }
    if let Some(needle) = query.strip_prefix('#') {
        return catalog
            .groups
            .iter()
            .filter(|g| g.name.to_lowercase().contains(&needle.to_lowercase()))
            .map(|g| Entry::new(format!("#{}", g.name), Act::Conversation(g.id.into())))
            .collect();
    }
    let (word, _) = split_command(query);
    let known = COMMANDS.iter().any(|(name, _)| *name == word) || LEGACY.contains(&word);
    if known && query.contains(char::is_whitespace) {
        return vec![Entry::new(head(query, 160), Act::Command(query.into()))];
    }
    let needle = query.to_lowercase();
    let mut rows: Vec<_> = COMMANDS
        .iter()
        .filter(|(name, _)| name.starts_with(&needle))
        .map(|(name, label)| Entry::new(format!(":{name}  {label}"), Act::Command((*name).into())))
        .collect();
    if !needle.is_empty() {
        rows.extend(
            LEGACY
                .iter()
                .filter(|name| name.starts_with(&needle))
                .map(|name| Entry::new(format!(":{name}"), Act::Command((*name).into()))),
        );
    }
    rows
}
/// Pinned actions remain fixed while an arbitrarily long body scrolls.
fn visible_indices(count: usize, pinned: usize, selected: usize, capacity: usize) -> Vec<usize> {
    if capacity == 0 || count == 0 {
        return vec![];
    }
    if capacity <= pinned {
        return vec![selected.min(count - 1)];
    }
    let fixed = pinned.min(count);
    let slots = capacity.saturating_sub(fixed);
    let selected_body = selected.saturating_sub(fixed);
    let offset = selected_body
        .saturating_add(1)
        .saturating_sub(slots)
        .min(count.saturating_sub(fixed + slots));
    (0..fixed)
        .chain((fixed + offset)..count.min(fixed + offset + slots))
        .collect()
}
pub(super) fn menu_rect(area: Rect) -> Rect {
    let width = area
        .width
        .saturating_sub(if area.width > 16 { 4 } else { 0 })
        .min(100);
    // Center the menu together with its shallow mascot band. Small terminals
    // reclaim the decoration space so the active field/list remains usable.
    let band = if area.height >= 28 {
        6
    } else if area.height >= 24 {
        5
    } else if area.height >= 18 {
        4
    } else if area.height >= 12 {
        2
    } else {
        0
    };
    let bottom_margin = u16::from(area.height >= 12);
    let room = area.height.saturating_sub(band + bottom_margin);
    let height = room.min(28);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + band + room.saturating_sub(height) / 2,
        width,
        height,
    )
}
fn solid_frame(buffer: &mut Buffer, rect: Rect) {
    let style = Style::default().fg(BORDER).bg(PANEL);
    for y in rect.top()..rect.bottom() {
        for x in rect.left()..rect.right() {
            buffer[(x, y)].set_symbol(" ").set_style(style);
        }
    }
    if rect.width < 2 || rect.height < 2 {
        return;
    }
    for x in rect.x + 1..rect.right() - 1 {
        buffer[(x, rect.y)].set_symbol("─");
        buffer[(x, rect.bottom() - 1)].set_symbol("─");
    }
    for y in rect.y + 1..rect.bottom() - 1 {
        buffer[(rect.x, y)].set_symbol("│");
        buffer[(rect.right() - 1, y)].set_symbol("│");
    }
    for (x, y, symbol) in [
        (rect.x, rect.y, "╭"),
        (rect.right() - 1, rect.y, "╮"),
        (rect.x, rect.bottom() - 1, "╰"),
        (rect.right() - 1, rect.bottom() - 1, "╯"),
    ] {
        buffer[(x, y)].set_symbol(symbol);
    }
}
fn draw_entry(buffer: &mut Buffer, inner: Rect, y: u16, label: &str, selected: bool) {
    put(
        buffer,
        inner.x,
        y,
        if selected { "›" } else { " " },
        ACCENT,
        inner,
    );
    put(
        buffer,
        inner.x + 2,
        y,
        label,
        if selected { TEXT } else { MUTED },
        inner,
    );
}
fn centered(buffer: &mut Buffer, clip: Rect, y: u16, text: &str, color: Color) {
    let text = head(text, usize::from(clip.width));
    let width = UnicodeWidthStr::width(text.as_str()) as u16;
    put(
        buffer,
        clip.x + clip.width.saturating_sub(width) / 2,
        y,
        &text,
        color,
        clip,
    );
}
fn put(buffer: &mut Buffer, x: u16, y: u16, text: &str, color: Color, clip: Rect) {
    let clip = clip.intersection(buffer.area);
    if x < clip.x || x >= clip.right() || y < clip.y || y >= clip.bottom() {
        return;
    }
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    buffer.set_stringn(
        x,
        y,
        clean,
        usize::from(clip.right() - x),
        Style::default().fg(color).bg(PANEL),
    );
}
fn tail(text: &str, room: usize) -> String {
    let mut used = 0;
    let mut kept = Vec::new();
    for c in text.chars().rev().filter(|c| !c.is_control()) {
        let width = c.width().unwrap_or(0);
        if used + width > room {
            break;
        }
        used += width;
        kept.push(c);
    }
    kept.into_iter().rev().collect()
}
fn head(text: &str, room: usize) -> String {
    let mut used = 0;
    text.chars()
        .filter(|c| !c.is_control())
        .take_while(|c| {
            used += c.width().unwrap_or(0);
            used <= room
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog() -> Catalog<'static> {
        Catalog {
            contacts: vec![
                Target {
                    id: "a",
                    name: "Mira",
                },
                Target {
                    id: "b",
                    name: "Alex 王",
                },
                Target {
                    id: "c",
                    name: "Alex 王_1",
                },
            ],
            groups: vec![
                Target {
                    id: "g1",
                    name: "studio",
                },
                Target {
                    id: "g2",
                    name: "friends",
                },
            ],
            proxy: "127.0.0.1:7890",
            me: "小明",
            me_id: "abcdef",
            motion: true,
        }
    }
    fn press(p: &mut Palette, code: KeyCode) -> PaletteEvent {
        p.key(KeyEvent::new(code, KeyModifiers::NONE), &catalog())
    }
    fn type_text(p: &mut Palette, s: &str) {
        for c in s.chars() {
            press(p, KeyCode::Char(c));
        }
    }
    fn command(p: &mut Palette, s: &str) -> PaletteEvent {
        p.open();
        type_text(p, s);
        press(p, KeyCode::Enter)
    }
    fn text(b: &Buffer) -> String {
        (b.area.y..b.area.bottom())
            .map(|y| {
                // A wide grapheme occupies one symbol cell plus continuation
                // cells reset to spaces by Buffer::set_stringn. Those cells
                // are hidden on a real terminal, not spaces between Chinese.
                let mut x = b.area.x;
                let mut line = String::new();
                while x < b.area.right() {
                    let symbol = b[(x, y)].symbol();
                    line.push_str(symbol);
                    x += UnicodeWidthStr::width(symbol).max(1) as u16;
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    #[test]
    fn long_input_keeps_its_prefix_and_a_blank_cell_for_the_caret() {
        for (width, height) in [(12, 6), (28, 10), (80, 24)] {
            for value in [
                format!("{}Z", "x".repeat(120)),
                format!("{}Z", "猫".repeat(60)),
            ] {
                for prefix in [":", "/", ">"] {
                    let mut palette = Palette::default();
                    match prefix {
                        "/" => {
                            command(&mut palette, "dm");
                            press(&mut palette, KeyCode::Char('/'));
                        }
                        ">" => {
                            command(&mut palette, "proxy");
                            press(&mut palette, KeyCode::Enter);
                        }
                        _ => palette.open(),
                    }
                    palette.paste(&value);
                    let area = Rect::new(3, 2, width, height);
                    let mut buffer = Buffer::empty(area);
                    palette.render(&mut buffer, area, &catalog(), false);
                    let rect = palette.menu_rect(area);
                    let (x, y) = palette.cursor(area, false).unwrap();
                    assert_eq!(buffer[(rect.x + 2, rect.y + 1)].symbol(), prefix);
                    assert_eq!(buffer[(x - 1, y)].symbol(), "Z");
                    assert_eq!(buffer[(x, y)].symbol(), " ");
                    assert!(x < rect.right() - 1);
                }
            }
        }
    }

    #[test]
    fn menus_use_ids_and_keep_fixed_actions() {
        let mut p = Palette::default();
        assert_eq!(command(&mut p, "dm"), PaletteEvent::None);
        assert_eq!(p.entries(&catalog())[0].label, "Add friend");
        press(&mut p, KeyCode::Char('j'));
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::SelectContact("a".into())
        );
        command(&mut p, "gc");
        let entries = p.entries(&catalog());
        assert_eq!(entries[0].label, "Create group");
        assert_eq!(entries[1].label, "Join group");
        assert_eq!(entries.len(), 4);
        press(&mut p, KeyCode::Char('j'));
        press(&mut p, KeyCode::Char('j'));
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::SelectConversation("g1".into())
        );
    }
    #[test]
    fn direct_dm_requires_unique_exact_full_name_including_spaces() {
        let mut p = Palette::default();
        assert_eq!(
            command(&mut p, "dm Alex 王"),
            PaletteEvent::SelectContact("b".into())
        );
        assert_eq!(
            command(&mut p, "dm Alex 王_1"),
            PaletteEvent::SelectContact("c".into())
        );
        assert_eq!(command(&mut p, "dm Alex"), PaletteEvent::None);
        assert!(p.is_open());
        assert_eq!(p.page, Page::Dm);
        assert_eq!(p.entries(&catalog()).len(), 3);
        assert_eq!(command(&mut p, "dm missing"), PaletteEvent::None);
        assert_eq!(p.entries(&catalog()).len(), 1);
        let mut duplicate = catalog();
        duplicate.contacts.push(Target {
            id: "d",
            name: "Mira",
        });
        p.open();
        p.paste("dm Mira");
        assert_eq!(
            p.key(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &duplicate
            ),
            PaletteEvent::None
        );
        assert_eq!(p.page, Page::Dm);
    }
    #[test]
    fn command_letters_are_text_and_search_escape_is_one_layer() {
        let mut p = Palette::default();
        p.open();
        type_text(&mut p, "jkh/l");
        assert_eq!(p.query, "jkh/l");
        command(&mut p, "dm");
        let opened = p.since;
        press(&mut p, KeyCode::Char('/'));
        type_text(&mut p, "Alex");
        assert_eq!(p.search.as_deref(), Some("Alex"));
        press(&mut p, KeyCode::Esc);
        assert_eq!(p.page, Page::Dm);
        assert!(p.search.is_none());
        press(&mut p, KeyCode::Esc);
        assert_eq!(p.page, Page::Main);
        assert!(p.is_open());
        assert_eq!(p.since, opened);
        press(&mut p, KeyCode::Esc);
        assert!(!p.is_open());
    }
    #[test]
    fn all_rows_are_reachable_and_pinned_items_survive_scrolling() {
        let names: Vec<_> = (0..500).map(|i| format!("contact{i:03}")).collect();
        let ids: Vec<_> = (0..500).map(|i| format!("id{i}")).collect();
        let mut c = catalog();
        c.contacts = names
            .iter()
            .zip(&ids)
            .map(|(name, id)| Target { name, id })
            .collect();
        let mut p = Palette::default();
        command(&mut p, "dm");
        p.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE), &c);
        let indices = visible_indices(501, 1, p.selected, 8);
        assert_eq!(indices[0], 0);
        assert!(indices.contains(&500));
        let area = Rect::new(0, 0, 80, 24);
        let mut buffer = Buffer::empty(area);
        p.render(&mut buffer, area, &c, false);
        let rendered = text(&buffer);
        assert!(rendered.contains("Add friend"));
        let rect = p.menu_rect(area);
        assert_eq!(buffer[(rect.x + 3, rect.y + 2)].symbol(), "A");
        assert_eq!(buffer[(rect.x + 4, rect.y + 2)].symbol(), "d");
        assert!(rendered.contains("contact499"));
        assert_eq!(
            p.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &c),
            PaletteEvent::SelectContact("id499".into())
        );
    }
    #[test]
    fn profile_keeps_art_and_export_inside_menu_and_handles_all_small_sizes() {
        let mut p = Palette::default();
        command(&mut p, "profile");
        let area = Rect::new(0, 0, 80, 30);
        let mut buffer = Buffer::empty(area);
        p.render(&mut buffer, area, &catalog(), false);
        let rendered = text(&buffer);
        assert!(rendered.contains("小明"));
        let rect = p.menu_rect(area);
        let name_x = rect.x + 1 + (rect.width - 2 - 4) / 2;
        assert_eq!(buffer[(name_x, rect.y + 1)].symbol(), "小");
        assert_eq!(buffer[(name_x + 2, rect.y + 1)].symbol(), "明");
        assert!(rendered.contains("Export invite file"));
        for line in randomart(catalog().me_id) {
            assert!(rendered.contains(&line));
        }
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::Files(FileMode::Save)
        );
        for width in 0..25 {
            for height in 0..24 {
                let area = Rect::new(2, 3, width, height);
                let mut buffer = Buffer::empty(area);
                p.resume_profile();
                p.render(&mut buffer, area, &catalog(), false);
            }
        }
    }
    #[test]
    fn settings_include_mailbox_and_proxy_editing_and_motion_stays_open() {
        let mut p = Palette::default();
        command(&mut p, "setting");
        press(&mut p, KeyCode::Char('j'));
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::OpenMailboxSettings
        );
        p.resume_settings();
        press(&mut p, KeyCode::Char('j'));
        press(&mut p, KeyCode::Char('j'));
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::Run("/motion toggle".into())
        );
        assert!(p.is_open());
        press(&mut p, KeyCode::Char('g'));
        press(&mut p, KeyCode::Enter);
        assert_eq!(p.page, Page::Proxy);
        press(&mut p, KeyCode::Enter);
        type_text(&mut p, "http://localhost:7890");
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::Run("/proxy http://localhost:7890".into())
        );
        assert!(p.is_open());
        assert!(!p.proxy_edit);
    }
    #[test]
    fn paste_does_not_execute_and_legacy_capabilities_are_preserved() {
        let mut p = Palette::default();
        p.open();
        p.paste("q!\n");
        assert!(p.is_open());
        assert_eq!(p.query, "q! ");
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::Run("/q!".into())
        );
        assert_eq!(command(&mut p, "send"), PaletteEvent::Run("/send".into()));
        assert_eq!(command(&mut p, "q"), PaletteEvent::Run("/q".into()));
        assert_eq!(
            command(&mut p, "server-add server.json"),
            PaletteEvent::Run("/server-add server.json".into())
        );
        assert_eq!(
            command(&mut p, "add example.invite"),
            PaletteEvent::Preview("example.invite".into())
        );
        assert_eq!(
            command(&mut p, "invite"),
            PaletteEvent::Files(FileMode::Save)
        );
    }
    #[test]
    fn opaque_menu_leaves_everything_outside_its_frame_untouched() {
        let mut p = Palette::default();
        p.open();
        let area = Rect::new(0, 0, 80, 30);
        let mut buffer = Buffer::empty(area);
        buffer.set_string(0, 29, "background chat", Style::default());
        p.render(&mut buffer, area, &catalog(), false);
        assert!(text(&buffer).contains("background chat"));
        assert!(p.cursor(area, false).is_some());
        command(&mut p, "dm");
        assert!(p.cursor(area, false).is_none());
    }
    #[test]
    fn return_from_file_picker_preserves_time_and_selects_imported_identity() {
        let mut p = Palette::default();
        command(&mut p, "dm");
        let opened = p.since;
        p.close();
        p.resume_dm(Some("c"));
        assert_eq!(p.since, opened);
        assert_eq!(p.selection(&p.entries(&catalog())), 3);
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::SelectContact("c".into())
        );
    }

    #[test]
    fn pasted_search_selects_the_result_instead_of_the_pinned_action() {
        let mut p = Palette::default();
        command(&mut p, "dm");
        press(&mut p, KeyCode::Char('/'));
        p.paste("Alex 王_1");
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PaletteEvent::SelectContact("c".into())
        );
    }
}
