//! `:` command palette. Every action is translated into an existing `/command`.

use super::{
    effects::{frost, gradient_border},
    files::Mode as FileMode,
    theme::{ACCENT, FAINT, MUTED, TEXT, VIOLET, ease_out, glass_plain},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect, style::Style};
use std::time::{Duration, Instant};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const TRANSITION: Duration = Duration::from_millis(220);
/// Large enough to paste an invitation code (the decoder accepts up to 256 KiB).
const QUERY_LIMIT: usize = 256 * 1024;
const CODE_PREFIX: &str = "clichat1:";
const ROWS: usize = 6;
/// (name, takes an argument)
const COMMANDS: [(&str, bool); 12] = [
    ("add", true),
    ("dm", true),
    ("group", true),
    ("use", true),
    ("invite", true),
    ("attach", true),
    ("open", true),
    ("kick", true),
    ("proxy", true),
    ("recover", false),
    ("motion", false),
    ("quit", false),
];

pub(super) struct Catalog<'a> {
    pub chats: Vec<&'a str>,
    pub contacts: Vec<&'a str>,
    /// Current proxy setting, shown dimmed beside the `proxy` command.
    pub proxy: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PaletteEvent {
    None,
    /// A slash command for `ui_command`.
    Run(String),
    /// Open the file manager.
    Files(FileMode),
    /// Show the confirm card for a file path or pasted code before adding.
    Preview(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Act {
    Run(String),
    Fill(String),
    Pick(FileMode),
    Preview(String),
}

struct Entry {
    label: String,
    act: Act,
}

pub(super) struct Palette {
    open: bool,
    since: Instant,
    query: String,
    selected: usize,
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            open: false,
            since: Instant::now() - TRANSITION,
            query: String::new(),
            selected: 0,
        }
    }
}

impl Palette {
    pub(super) fn open(&mut self) {
        self.query.clear();
        self.selected = 0;
        self.open = true;
        self.since = Instant::now();
    }
    pub(super) fn close(&mut self) {
        if self.open {
            self.open = false;
            self.since = Instant::now();
        }
    }
    pub(super) fn is_open(&self) -> bool {
        self.open
    }
    /// Bracketed paste: control characters are dropped, newlines become spaces, and a
    /// paste that would exceed the limit is rejected whole.
    pub(super) fn paste(&mut self, text: &str) {
        let clean: String = text
            .chars()
            .map(|c| {
                if c == '\n' || c == '\r' || c == '\t' {
                    ' '
                } else {
                    c
                }
            })
            .filter(|c| !c.is_control())
            .collect();
        if self.open && self.query.len() + clean.len() <= QUERY_LIMIT {
            self.query.push_str(clean.trim());
            self.selected = 0;
        }
    }
    /// 0 is hidden, 1 is fully shown; the closing animation runs backwards.
    pub(super) fn level(&self, motion: bool) -> f32 {
        if !motion {
            return if self.open { 1.0 } else { 0.0 };
        }
        let t = (self.since.elapsed().as_secs_f32() / TRANSITION.as_secs_f32()).min(1.0);
        if self.open {
            ease_out(t)
        } else {
            1.0 - ease_out(t)
        }
    }
    pub(super) fn is_visible(&self, motion: bool) -> bool {
        self.level(motion) > 0.0
    }

    fn entries(&self, catalog: &Catalog) -> Vec<Entry> {
        let query = self.query.trim_start();
        let (word, rest) = query.split_once(' ').unwrap_or((query, ""));
        let rest = rest.trim();
        if let Some(name) = query.strip_prefix('#') {
            return pick(&catalog.chats, name, '#', "/use");
        }
        if let Some(name) = query.strip_prefix('@') {
            return pick(&catalog.contacts, name, '@', "/dm");
        }
        // A pasted invitation code goes straight to the confirm card.
        if query.starts_with(CODE_PREFIX) {
            return vec![Entry {
                label: "add".to_owned(),
                act: Act::Preview(query.trim().to_owned()),
            }];
        }
        if query.contains(' ') && COMMANDS.iter().any(|(name, _)| *name == word) {
            let act = match word {
                "add" if !rest.is_empty() => Act::Preview(rest.to_owned()),
                _ if rest.is_empty() => Act::Run(format!("/{word}")),
                _ => Act::Run(format!("/{word} {rest}")),
            };
            return vec![Entry {
                label: head(query, 200),
                act,
            }];
        }
        let needle = word.to_lowercase();
        let mut entries: Vec<Entry> = COMMANDS
            .iter()
            .filter(|(name, _)| name.starts_with(&needle))
            .map(|(name, args)| Entry {
                label: (*name).to_owned(),
                act: match *name {
                    "invite" => Act::Pick(FileMode::Save),
                    "add" => Act::Pick(FileMode::Open),
                    _ if *args => Act::Fill(format!("{name} ")),
                    _ => Act::Run(format!("/{name}")),
                },
            })
            .collect();
        if !needle.is_empty() {
            entries.extend(pick(&catalog.chats, &needle, '#', "/use"));
            entries.extend(pick(&catalog.contacts, &needle, '@', "/dm"));
        }
        entries
    }

    pub(super) fn key(&mut self, key: KeyEvent, catalog: &Catalog) -> PaletteEvent {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let count = self.entries(catalog).len().min(ROWS);
        match key.code {
            KeyCode::Esc => self.close(),
            KeyCode::Char('c') if control => self.close(),
            KeyCode::Down | KeyCode::Tab if count > 0 => {
                self.selected = (self.selected + 1) % count
            }
            KeyCode::Up | KeyCode::BackTab if count > 0 => {
                self.selected = (self.selected + count - 1) % count;
            }
            KeyCode::Backspace => {
                if self.query.pop().is_none() {
                    self.close();
                }
                self.selected = 0;
            }
            KeyCode::Char(c) if !control && !c.is_control() => {
                if self.query.len() + c.len_utf8() <= QUERY_LIMIT {
                    self.query.push(c);
                    self.selected = 0;
                }
            }
            KeyCode::Enter => {
                let entry = self.entries(catalog).into_iter().nth(self.selected);
                match entry.map(|entry| entry.act) {
                    Some(Act::Run(line)) => {
                        self.close();
                        return PaletteEvent::Run(line);
                    }
                    Some(Act::Pick(mode)) => {
                        self.close();
                        return PaletteEvent::Files(mode);
                    }
                    Some(Act::Preview(source)) => {
                        self.close();
                        return PaletteEvent::Preview(source);
                    }
                    Some(Act::Fill(text)) => {
                        self.query = text;
                        self.selected = 0;
                    }
                    None => {}
                }
            }
            _ => {}
        }
        PaletteEvent::None
    }

    fn rect(area: Rect, level: f32) -> Rect {
        // Never narrower than the identity card, so both line up through the transition.
        let floor = super::card::CARD_WIDTH.min(area.width);
        let full = area.width.saturating_sub(8).clamp(12, 60).max(floor);
        let width = ((f32::from(full) * (0.3 + 0.7 * level)).round() as u16).max(8);
        let height = (ROWS as u16 + 3).min(area.height.saturating_sub(2));
        Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 3,
            width.min(area.width),
            height,
        )
    }

    /// Frosts what is already drawn, then lifts the search box out of it.
    pub(super) fn render(&self, buffer: &mut Buffer, area: Rect, catalog: &Catalog, motion: bool) {
        let level = self.level(motion);
        if level <= 0.0 {
            return;
        }
        frost(buffer, area, level);
        let rect = Self::rect(area, level);
        glass_plain(buffer, rect, level);
        gradient_border(buffer, rect, level, false, level);
        if level < 1.0 || rect.width < 12 {
            return;
        }
        let room = usize::from(rect.width).saturating_sub(6);
        put(buffer, rect.x + 2, rect.y + 1, ":", ACCENT, rect);
        // A pasted code can be thousands of characters; show only the tail of one line.
        let shown = tail(self.query.lines().last().unwrap_or(""), room);
        put(buffer, rect.x + 4, rect.y + 1, &shown, TEXT, rect);
        put(
            buffer,
            rect.x + 2,
            rect.y + 2,
            &"─".repeat(room + 2),
            FAINT,
            rect,
        );
        for (index, entry) in self.entries(catalog).iter().take(ROWS).enumerate() {
            let y = rect.y + 3 + index as u16;
            if y >= rect.bottom().saturating_sub(1) {
                break;
            }
            let chosen = index == self.selected;
            if chosen {
                put(buffer, rect.x + 2, y, "›", ACCENT, rect);
            }
            let color = if chosen { TEXT } else { MUTED };
            let mark = entry
                .label
                .chars()
                .next()
                .filter(|c| matches!(c, '#' | '@'));
            let mut x = rect.x + 4;
            let body = if let Some(mark) = mark {
                put(buffer, x, y, &mark.to_string(), VIOLET, rect);
                x += 1;
                &entry.label[1..]
            } else {
                entry.label.as_str()
            };
            put(buffer, x, y, &head(body, room), color, rect);
            if body == "proxy" {
                let value = head(catalog.proxy, room.saturating_sub(12));
                let cells = UnicodeWidthStr::width(value.as_str()) as u16;
                put(
                    buffer,
                    rect.right().saturating_sub(cells + 2),
                    y,
                    &value,
                    FAINT,
                    rect,
                );
            }
        }
    }

    pub(super) fn cursor(&self, area: Rect, motion: bool) -> Option<(u16, u16)> {
        if !self.open || self.level(motion) < 1.0 {
            return None;
        }
        let rect = Self::rect(area, 1.0);
        let room = usize::from(rect.width).saturating_sub(6);
        let shown = tail(self.query.lines().last().unwrap_or(""), room);
        let cells = UnicodeWidthStr::width(shown.as_str()) as u16;
        Some((rect.x + 4 + cells, rect.y + 1))
    }
}

fn pick(names: &[&str], needle: &str, mark: char, command: &str) -> Vec<Entry> {
    let needle = needle.to_lowercase();
    names
        .iter()
        .filter(|name| name.to_lowercase().contains(&needle))
        .map(|name| Entry {
            label: format!("{mark}{name}"),
            act: Act::Run(format!("{command} {name}")),
        })
        .collect()
}

fn put(buffer: &mut Buffer, x: u16, y: u16, text: &str, color: ratatui::style::Color, clip: Rect) {
    if x >= clip.right() || y >= buffer.area.bottom() {
        return;
    }
    let bg = buffer[(x, y)].bg;
    let limit = usize::from(clip.right() - x - 1);
    buffer.set_stringn(x, y, text, limit, Style::default().fg(color).bg(bg));
}

/// Keeps the end of the text visible when it is wider than the box.
fn tail(text: &str, room: usize) -> String {
    let mut used = 0;
    let mut kept: Vec<char> = vec![];
    for c in text.chars().rev() {
        let cells = c.width().unwrap_or(0);
        if used + cells > room {
            break;
        }
        used += cells;
        kept.push(c);
    }
    kept.into_iter().rev().collect()
}

fn head(text: &str, room: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars() {
        let cells = c.width().unwrap_or(0);
        if used + cells > room {
            break;
        }
        used += cells;
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog<'static> {
        Catalog {
            chats: vec!["studio", "friends"],
            contacts: vec!["Mira", "Alex"],
            proxy: "127.0.0.1:7890",
        }
    }

    fn press(palette: &mut Palette, code: KeyCode) -> PaletteEvent {
        palette.key(KeyEvent::new(code, KeyModifiers::NONE), &catalog())
    }

    fn type_text(palette: &mut Palette, text: &str) {
        for c in text.chars() {
            press(palette, KeyCode::Char(c));
        }
    }

    #[test]
    fn chats_contacts_and_commands_become_slash_commands() {
        let mut palette = Palette::default();
        palette.open();
        type_text(&mut palette, "#stu");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Run("/use studio".into()));
        assert!(!palette.is_open());
        palette.open();
        type_text(&mut palette, "@al");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Run("/dm Alex".into()));
        palette.open();
        type_text(&mut palette, "quit");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Run("/quit".into()));
    }

    #[test]
    fn invite_and_add_open_the_file_manager() {
        let mut palette = Palette::default();
        palette.open();
        type_text(&mut palette, "invite");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Files(FileMode::Save));
        palette.open();
        type_text(&mut palette, "add");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Files(FileMode::Open));
    }

    #[test]
    fn add_with_a_path_or_pasted_code_goes_to_the_confirm_card() {
        let mut palette = Palette::default();
        palette.open();
        type_text(&mut palette, "add bob.invite");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Preview("bob.invite".into()));
        palette.open();
        let code = format!("clichat1:{}", "A".repeat(5000));
        type_text(&mut palette, &code);
        assert_eq!(palette.query.len(), code.len());
        assert_eq!(
            press(&mut palette, KeyCode::Enter),
            PaletteEvent::Preview(code)
        );
        palette.open();
        type_text(&mut palette, "invite x.invite");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Run("/invite x.invite".into()));
    }

    #[test]
    fn commands_with_arguments_fill_then_run() {
        let mut palette = Palette::default();
        palette.open();
        type_text(&mut palette, "proxy");
        assert_eq!(press(&mut palette, KeyCode::Enter), PaletteEvent::None);
        type_text(&mut palette, "off");
        let event = press(&mut palette, KeyCode::Enter);
        assert_eq!(event, PaletteEvent::Run("/proxy off".into()));
    }

    #[test]
    fn the_box_is_never_narrower_than_the_card_and_shows_the_proxy() {
        let area = Rect::new(0, 0, 70, 24);
        assert!(Palette::rect(area, 1.0).width >= super::super::card::CARD_WIDTH);
        let mut buffer = Buffer::empty(area);
        let mut palette = Palette::default();
        palette.open();
        type_text(&mut palette, "pro");
        palette.render(&mut buffer, area, &catalog(), false);
        let drawn: String = (0..24)
            .flat_map(|y| (0..70).map(move |x| (x, y)))
            .map(|(x, y)| buffer[(x, y)].symbol().to_owned())
            .collect();
        assert!(drawn.contains("127.0.0.1:7890"));
    }

    #[test]
    fn escape_and_empty_backspace_close() {
        let mut palette = Palette::default();
        palette.open();
        press(&mut palette, KeyCode::Esc);
        assert!(!palette.is_open());
        palette.open();
        press(&mut palette, KeyCode::Backspace);
        assert!(!palette.is_open());
    }

    #[test]
    fn open_palette_frosts_the_background_and_shows_prompt() {
        let area = Rect::new(0, 0, 70, 24);
        let mut buffer = Buffer::empty(area);
        buffer.set_string(0, 20, "secret message secret message", Style::default());
        let mut palette = Palette::default();
        palette.open();
        palette.render(&mut buffer, area, &catalog(), false);
        let row: String = (0..70).map(|x| buffer[(x, 20)].symbol()).collect();
        assert!(!row.contains("secret"));
        let prompt: String = (0..70).map(|x| buffer[(x, 6)].symbol()).collect();
        assert!(prompt.contains(':'), "{prompt}");
        assert!(palette.cursor(area, false).is_some());
    }
}
