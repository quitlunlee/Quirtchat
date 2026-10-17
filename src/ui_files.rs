//! File manager for Invite (choose where to save) and Add (choose an invitation).
//! Directory reads are plain functions so they can be tested and run off the UI thread.

use super::{
    effects::gradient_border,
    theme::{ACCENT, FAINT, MUTED, TEXT, VIOLET, glass_plain},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(super) const MAX_ENTRIES: usize = 2000;
/// Same bound as `decode_invitation`.
pub(super) const MAX_INVITE_BYTES: u64 = 256 * 1024;
pub(super) const INVITE_EXT: &str = "invite";
const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// Pick a folder and a file name.
    Save,
    /// Pick an existing invitation.
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub name: String,
    pub dir: bool,
    pub size: u64,
}

impl Entry {
    /// Open mode can only choose small `.invite` files.
    pub(super) fn selectable(&self, mode: Mode) -> bool {
        match mode {
            Mode::Save => false,
            Mode::Open => !self.dir && self.size <= MAX_INVITE_BYTES && has_invite_ext(&self.name),
        }
    }
}

fn has_invite_ext(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(INVITE_EXT))
}

/// Folders first, then files; each group sorted by name ignoring case.
pub(super) fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.dir
            .cmp(&a.dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

fn hidden(name: &str) -> bool {
    name.starts_with('.')
}

/// Lists a directory. `show_all` includes dot files and, in Open mode, non-invitations.
/// Returns at most `MAX_ENTRIES` entries; unreadable items are skipped.
pub(super) fn list_dir(path: &Path, mode: Mode, show_all: bool) -> std::io::Result<Vec<Entry>> {
    let mut entries = vec![];
    for item in fs::read_dir(path)? {
        let Ok(item) = item else { continue };
        let Ok(name) = item.file_name().into_string() else {
            continue;
        };
        if !show_all && hidden(&name) {
            continue;
        }
        let Ok(meta) = item.metadata() else { continue };
        let dir = meta.is_dir();
        if !dir && !show_all && mode == Mode::Open && !has_invite_ext(&name) {
            continue;
        }
        entries.push(Entry {
            name,
            dir,
            size: if dir { 0 } else { meta.len() },
        });
        if entries.len() >= MAX_ENTRIES * 2 {
            break;
        }
    }
    sort_entries(&mut entries);
    entries.truncate(MAX_ENTRIES);
    Ok(entries)
}

/// Existing drive roots on Windows; empty elsewhere.
pub(super) fn drives() -> Vec<PathBuf> {
    if !cfg!(windows) {
        return vec![];
    }
    ('A'..='Z')
        .map(|letter| PathBuf::from(format!("{letter}:\\")))
        .filter(|root| root.exists())
        .collect()
}

/// The parent folder, or `None` at a root (Windows then shows the drive list).
pub(super) fn parent_of(path: &Path) -> Option<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// Rejects names that are unsafe or invalid on common platforms.
pub(super) fn validate_file_name(name: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err("name required");
    }
    // Reject leading or trailing whitespace instead of silently trimming it away.
    if name != name.trim() {
        return Err("invalid name");
    }
    if name.len() > 128 {
        return Err("name too long");
    }
    if name
        .chars()
        .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return Err("invalid name");
    }
    if name == "." || name == ".." || name.ends_with('.') || name.ends_with(' ') {
        return Err("invalid name");
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Err("reserved name");
    }
    Ok(())
}

/// Adds the `.invite` extension when the user left it off.
pub(super) fn with_invite_ext(name: &str) -> String {
    let name = name.trim();
    if has_invite_ext(name) {
        name.to_owned()
    } else {
        format!("{name}.{INVITE_EXT}")
    }
}

/// The first unused `name-2.invite`, `name-3.invite`, ... shown as a suggestion only.
pub(super) fn free_name(dir: &Path, name: &str) -> String {
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or(INVITE_EXT);
    (2..1000)
        .map(|n| format!("{stem}-{n}.{ext}"))
        .find(|candidate| !dir.join(candidate).exists())
        .unwrap_or_else(|| name.to_owned())
}

/// A file name derived from a display name: safe characters only.
pub(super) fn default_file_name(display: &str) -> String {
    let cleaned: String = display
        .chars()
        .map(|c| {
            if c.is_control() || "\\/:*?\"<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_end_matches('.').trim();
    let base = if cleaned.is_empty() { "me" } else { cleaned };
    let base: String = base.chars().take(100).collect();
    let mut name = with_invite_ext(&base);
    if validate_file_name(&name).is_err() {
        name = with_invite_ext("me");
    }
    name
}

/// Where each mode starts: Documents to save, Downloads to open, else the home folder.
pub(super) fn start_dir(mode: Mode) -> PathBuf {
    let dirs = directories::UserDirs::new();
    let wanted = dirs.as_ref().and_then(|dirs| match mode {
        Mode::Save => dirs.document_dir(),
        Mode::Open => dirs.download_dir(),
    });
    wanted
        .or_else(|| dirs.as_ref().map(directories::UserDirs::home_dir))
        .map(Path::to_path_buf)
        .filter(|path| path.is_dir())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FileEvent {
    None,
    Cancel,
    /// Open mode: the chosen file.
    Open(PathBuf),
    /// Save mode: the full target path, already validated.
    Save(PathBuf),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    Name,
}

pub(super) struct Files {
    pub mode: Mode,
    /// `None` shows the drive list (Windows roots).
    pub dir: Option<PathBuf>,
    pub entries: Vec<Entry>,
    pub selected: usize,
    pub show_all: bool,
    pub name: String,
    pub error: Option<String>,
    focus: Focus,
    pending_g: bool,
}

impl Files {
    pub(super) fn new(mode: Mode, start: PathBuf, display_name: &str) -> Self {
        let mut files = Self {
            mode,
            dir: Some(start),
            entries: vec![],
            selected: 0,
            show_all: false,
            name: default_file_name(display_name),
            error: None,
            focus: if mode == Mode::Save {
                Focus::Name
            } else {
                Focus::List
            },
            pending_g: false,
        };
        files.reload();
        files
    }

    pub(super) fn name_focused(&self) -> bool {
        self.mode == Mode::Save && self.focus == Focus::Name
    }

    fn reload(&mut self) {
        self.selected = 0;
        self.error = None;
        match self.dir.clone() {
            Some(dir) => match list_dir(&dir, self.mode, self.show_all) {
                Ok(entries) => self.entries = entries,
                Err(_) => {
                    self.entries.clear();
                    self.error = Some("cannot read folder".into());
                }
            },
            None => {
                self.entries = drives()
                    .iter()
                    .map(|root| Entry {
                        name: root.display().to_string(),
                        dir: true,
                        size: 0,
                    })
                    .collect();
            }
        }
    }

    fn enter(&mut self, name: &str) {
        let target = match &self.dir {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        };
        if target.is_dir() {
            self.dir = Some(target);
            self.reload();
        }
    }

    fn up(&mut self) {
        let Some(dir) = self.dir.clone() else { return };
        let came_from = dir.file_name().map(|n| n.to_string_lossy().into_owned());
        match parent_of(&dir) {
            Some(parent) => self.dir = Some(parent),
            None if cfg!(windows) => self.dir = None,
            None => return,
        }
        self.reload();
        if let Some(name) = came_from
            && let Some(index) = self.entries.iter().position(|e| e.name == name)
        {
            self.selected = index;
        }
    }

    fn step(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let last = self.entries.len() as isize - 1;
        self.selected = (self.selected as isize + delta).clamp(0, last) as usize;
    }

    fn confirm_save(&mut self) -> FileEvent {
        let Some(dir) = &self.dir else {
            self.error = Some("choose a folder".into());
            return FileEvent::None;
        };
        // Check what the user typed, then the final name with the extension added.
        let name = with_invite_ext(&self.name);
        if let Err(message) =
            validate_file_name(&self.name).and_then(|()| validate_file_name(&name))
        {
            self.error = Some(message.into());
            return FileEvent::None;
        }
        let path = dir.join(&name);
        if path.exists() {
            self.name = free_name(dir, &name);
            self.error = Some("exists".into());
            return FileEvent::None;
        }
        FileEvent::Save(path)
    }
}

impl Files {
    fn name_key(&mut self, code: KeyCode, control: bool) -> FileEvent {
        match code {
            KeyCode::Enter => return self.confirm_save(),
            KeyCode::Tab | KeyCode::Down => self.focus = Focus::List,
            KeyCode::Backspace => {
                self.name.pop();
                self.error = None;
            }
            KeyCode::Char(c) if !control && !c.is_control() && self.name.len() < 128 => {
                self.name.push(c);
                self.error = None;
            }
            _ => {}
        }
        FileEvent::None
    }

    fn choose(&mut self) -> FileEvent {
        let Some(entry) = self.entries.get(self.selected).cloned() else {
            return FileEvent::None;
        };
        if entry.dir {
            self.enter(&entry.name);
        } else if entry.selectable(self.mode) {
            if let Some(dir) = &self.dir {
                return FileEvent::Open(dir.join(&entry.name));
            }
        } else if self.mode == Mode::Open {
            self.error = Some("not an invitation".into());
        }
        FileEvent::None
    }

    pub(super) fn key(&mut self, key: KeyEvent) -> FileEvent {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Esc || (control && key.code == KeyCode::Char('c')) {
            return FileEvent::Cancel;
        }
        if self.name_focused() {
            return self.name_key(key.code, control);
        }
        let pending = std::mem::take(&mut self.pending_g);
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.step(1),
            KeyCode::Char('k') | KeyCode::Up => {
                if self.mode == Mode::Save && self.selected == 0 {
                    self.focus = Focus::Name;
                } else {
                    self.step(-1);
                }
            }
            KeyCode::Char('g') if pending => self.selected = 0,
            KeyCode::Char('g') => self.pending_g = true,
            KeyCode::Char('G') => self.selected = self.entries.len().saturating_sub(1),
            KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => self.up(),
            KeyCode::Char('~') => {
                self.dir = Some(start_dir(self.mode));
                self.reload();
            }
            KeyCode::Char('.') => {
                self.show_all = !self.show_all;
                self.reload();
            }
            KeyCode::Tab if self.mode == Mode::Save => self.focus = Focus::Name,
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => return self.choose(),
            _ => {}
        }
        FileEvent::None
    }
}

fn size_label(size: u64) -> String {
    match size {
        0..=1023 => format!("{size} B"),
        1024..=1_048_575 => format!("{} KB", size / 1024),
        _ => format!("{} MB", size / 1_048_576),
    }
}

fn cut_start(text: &str, room: usize) -> String {
    if UnicodeWidthStr::width(text) <= room {
        return text.to_owned();
    }
    let mut kept: Vec<char> = vec![];
    let mut used = 1;
    for c in text.chars().rev() {
        let cells = c.width().unwrap_or(0);
        if used + cells > room {
            break;
        }
        used += cells;
        kept.push(c);
    }
    format!("…{}", kept.into_iter().rev().collect::<String>())
}

fn cut_end(text: &str, room: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        let cells = c.width().unwrap_or(0);
        if used + cells > room {
            break;
        }
        used += cells;
        out.push(c);
    }
    out
}

fn put(buffer: &mut Buffer, x: u16, y: u16, text: &str, color: Color, clip: Rect) {
    if x >= clip.right() || y >= clip.bottom() {
        return;
    }
    let bg = buffer[(x, y)].bg;
    let room = usize::from(clip.right() - x);
    buffer.set_stringn(x, y, text, room, Style::default().fg(color).bg(bg));
}

impl Files {
    pub(super) fn rect(area: Rect) -> Rect {
        let width = area.width.saturating_sub(8).clamp(20, 64).min(area.width);
        let height = area.height.saturating_sub(4).clamp(8, 18).min(area.height);
        Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        )
    }

    fn list_rows(&self, rect: Rect) -> usize {
        let chrome = if self.mode == Mode::Save { 5 } else { 3 };
        usize::from(rect.height).saturating_sub(chrome).max(1)
    }

    /// Terminal cursor position while the file name is being edited.
    pub(super) fn cursor(&self, area: Rect) -> Option<(u16, u16)> {
        if !self.name_focused() {
            return None;
        }
        let rect = Self::rect(area);
        let room = usize::from(rect.width).saturating_sub(6);
        let cells = UnicodeWidthStr::width(cut_start(&self.name, room).as_str()) as u16;
        Some((rect.x + 4 + cells, rect.bottom().saturating_sub(2)))
    }

    pub(super) fn render(&self, buffer: &mut Buffer, area: Rect, level: f32) {
        let rect = Self::rect(area);
        glass_plain(buffer, rect, level);
        gradient_border(buffer, rect, level, false, level);
        if level < 1.0 || rect.width < 16 {
            return;
        }
        let room = usize::from(rect.width).saturating_sub(6);
        let path = match &self.dir {
            Some(dir) => dir.display().to_string(),
            None => String::new(),
        };
        put(
            buffer,
            rect.x + 2,
            rect.y + 1,
            &cut_start(&path, room),
            MUTED,
            rect,
        );
        let rows = self.list_rows(rect);
        let first = self.selected.saturating_sub(rows.saturating_sub(1));
        let top = rect.y + 2;
        for (offset, entry) in self.entries.iter().skip(first).take(rows).enumerate() {
            let y = top + offset as u16;
            let chosen = first + offset == self.selected && !self.name_focused();
            if chosen {
                put(buffer, rect.x + 2, y, "›", ACCENT, rect);
            }
            let label = if entry.dir {
                format!("{}/", entry.name)
            } else {
                entry.name.clone()
            };
            let usable = entry.dir || entry.selectable(self.mode) || self.mode == Mode::Save;
            let color = match (chosen, usable, entry.dir) {
                (true, _, _) => TEXT,
                (false, _, true) => VIOLET,
                (false, true, false) => MUTED,
                (false, false, false) => FAINT,
            };
            let size = if entry.dir {
                String::new()
            } else {
                size_label(entry.size)
            };
            let size_cells = UnicodeWidthStr::width(size.as_str());
            put(
                buffer,
                rect.x + 4,
                y,
                &cut_end(&label, room.saturating_sub(size_cells + 2)),
                color,
                rect,
            );
            let x = rect.right().saturating_sub(size_cells as u16 + 2);
            put(buffer, x, y, &size, FAINT, rect);
        }
        if self.mode == Mode::Save {
            let y = rect.bottom().saturating_sub(2);
            put(
                buffer,
                rect.x + 2,
                y,
                "›",
                if self.name_focused() { ACCENT } else { FAINT },
                rect,
            );
            put(
                buffer,
                rect.x + 4,
                y,
                &cut_start(&self.name, room),
                TEXT,
                rect,
            );
        }
        if let Some(error) = &self.error {
            let x = rect
                .right()
                .saturating_sub(UnicodeWidthStr::width(error.as_str()) as u16 + 2);
            put(buffer, x, rect.y + 1, error, FAINT, rect);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(files: &mut Files, code: KeyCode) -> FileEvent {
        files.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn names(files: &Files) -> Vec<String> {
        files.entries.iter().map(|e| e.name.clone()).collect()
    }

    fn tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("Zeta")).unwrap();
        fs::create_dir(root.path().join("alpha")).unwrap();
        fs::create_dir(root.path().join(".hidden")).unwrap();
        fs::write(root.path().join("b.invite"), "x").unwrap();
        fs::write(root.path().join("A.INVITE"), "x").unwrap();
        fs::write(root.path().join("notes.txt"), "x").unwrap();
        fs::write(root.path().join(".secret.invite"), "x").unwrap();
        root
    }

    #[test]
    fn folders_first_sorted_ignoring_case_and_hidden_toggle() {
        let root = tree();
        let mut files = Files::new(Mode::Save, root.path().to_path_buf(), "Alex");
        assert_eq!(
            names(&files),
            ["alpha", "Zeta", "A.INVITE", "b.invite", "notes.txt"]
        );
        press(&mut files, KeyCode::Tab);
        press(&mut files, KeyCode::Char('.'));
        assert!(names(&files).contains(&".hidden".to_owned()));
        press(&mut files, KeyCode::Char('.'));
        assert!(!names(&files).contains(&".hidden".to_owned()));
    }

    #[test]
    fn open_mode_lists_only_invitations_and_rejects_oversized_files() {
        let root = tree();
        fs::write(root.path().join("big.invite"), vec![b'x'; 300 * 1024]).unwrap();
        let mut files = Files::new(Mode::Open, root.path().to_path_buf(), "Alex");
        assert_eq!(
            names(&files),
            ["alpha", "Zeta", "A.INVITE", "b.invite", "big.invite"]
        );
        press(&mut files, KeyCode::Char('G'));
        assert_eq!(press(&mut files, KeyCode::Enter), FileEvent::None);
        assert_eq!(files.error.as_deref(), Some("not an invitation"));
        files.selected = 3;
        let event = press(&mut files, KeyCode::Char('l'));
        assert_eq!(event, FileEvent::Open(root.path().join("b.invite")));
    }

    #[test]
    fn navigation_enters_and_leaves_folders_and_remembers_position() {
        let root = tree();
        let mut files = Files::new(Mode::Open, root.path().to_path_buf(), "Alex");
        press(&mut files, KeyCode::Char('l'));
        assert_eq!(
            files.dir.as_deref(),
            Some(root.path().join("alpha").as_path())
        );
        assert!(files.entries.is_empty());
        press(&mut files, KeyCode::Char('h'));
        assert_eq!(files.dir.as_deref(), Some(root.path()));
        assert_eq!(files.entries[files.selected].name, "alpha");
        press(&mut files, KeyCode::Char('G'));
        assert_eq!(files.selected, files.entries.len() - 1);
        press(&mut files, KeyCode::Char('g'));
        press(&mut files, KeyCode::Char('g'));
        assert_eq!(files.selected, 0);
    }

    #[test]
    fn save_validates_names_and_never_overwrites() {
        let root = tree();
        let mut files = Files::new(Mode::Save, root.path().to_path_buf(), "Alex");
        assert!(files.name_focused());
        assert_eq!(files.name, "Alex.invite");
        let event = press(&mut files, KeyCode::Enter);
        assert_eq!(event, FileEvent::Save(root.path().join("Alex.invite")));
        files.name = "b".into();
        assert_eq!(press(&mut files, KeyCode::Enter), FileEvent::None);
        assert_eq!(files.error.as_deref(), Some("exists"));
        assert_eq!(files.name, "b-2.invite");
        for bad in ["", "a/b", "a\\b", "CON", "nul.txt", "x:y", "dots.", "tab\t"] {
            files.name = bad.into();
            assert_eq!(
                press(&mut files, KeyCode::Enter),
                FileEvent::None,
                "{bad:?}"
            );
            assert!(files.error.is_some(), "{bad:?}");
        }
    }

    #[test]
    fn name_helpers_are_safe() {
        assert_eq!(default_file_name("Alex"), "Alex.invite");
        assert_eq!(default_file_name("a/b:c"), "a_b_c.invite");
        assert_eq!(default_file_name("  "), "me.invite");
        assert_eq!(default_file_name("CON"), "me.invite");
        assert_eq!(with_invite_ext("x.INVITE"), "x.INVITE");
        assert!(validate_file_name(&"a".repeat(129)).is_err());
        assert!(parent_of(Path::new("")).is_none());
    }

    #[test]
    fn escape_cancels_and_missing_folder_reports_an_error() {
        let root = tree();
        let mut files = Files::new(Mode::Open, root.path().join("missing"), "Alex");
        assert!(files.entries.is_empty() && files.error.is_some());
        assert_eq!(press(&mut files, KeyCode::Esc), FileEvent::Cancel);
    }
}
