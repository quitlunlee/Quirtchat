//! Small, grapheme-aware Vim draft editor. Registers and undo never reach disk.

use clichat::model::MAX_TEXT_BYTES;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use zeroize::Zeroize;

const UNDO_LIMIT: usize = 64;
const TAB_STOP: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Insert,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Submit(String),
    Scroll(i16),
    Top,
    Bottom,
    Palette,
    Quit,
}

#[derive(Clone, Copy)]
enum Operator {
    Yank,
    Delete,
    Go,
}

struct Snapshot {
    text: String,
    cursor: usize,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

#[derive(Default)]
struct Register {
    text: String,
    linewise: bool,
    occupied: bool,
}

impl Drop for Register {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

pub struct Editor {
    text: String,
    cursor: usize,
    mode: Mode,
    operator: Option<Operator>,
    register: Register,
    undo: Vec<Snapshot>,
    redo: Vec<Snapshot>,
    insert_checkpointed: bool,
    preferred_column: Option<usize>,
}

impl Default for Editor {
    fn default() -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            mode: Mode::Normal,
            operator: None,
            register: Register::default(),
            undo: Vec::new(),
            redo: Vec::new(),
            insert_checkpointed: false,
            preferred_column: None,
        }
    }
}

impl Drop for Editor {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl Editor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn cursor_byte(&self) -> usize {
        self.cursor
    }

    /// Zero-based logical row and terminal display column, before soft wrapping.
    pub fn cursor_position(&self) -> (usize, usize) {
        let mut row = 0;
        let mut column = 0;
        for grapheme in self.text[..self.cursor].graphemes(true) {
            if grapheme == "\n" {
                row += 1;
                column = 0;
            } else {
                column += display_width(grapheme, column);
            }
        }
        (row, column)
    }

    /// Cancels the draft, wiping its undo history and in-memory yank register.
    pub fn clear(&mut self) {
        self.text.zeroize();
        self.text.clear();
        self.cursor = 0;
        self.mode = Mode::Normal;
        self.operator = None;
        self.register = Register::default();
        self.undo.clear();
        self.redo.clear();
        self.insert_checkpointed = false;
        self.preferred_column = None;
    }

    /// Bracketed paste is only text insertion, even for newlines or `/quit`.
    /// Rejects the whole paste if it would exceed the UTF-8 byte limit.
    pub fn insert_text(&mut self, input: &str) -> bool {
        let normalized = normalize_paste(input);
        if normalized.is_empty() {
            return true;
        }
        if self.text.len().saturating_add(normalized.len()) > MAX_TEXT_BYTES {
            return false;
        }
        self.begin_insert();
        self.insert_fragment(&normalized, false)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind == KeyEventKind::Release {
            return Action::None;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if control && matches!(key.code, KeyCode::Char('c' | 'C')) {
            let empty = self.text.is_empty();
            self.clear();
            return if empty { Action::Quit } else { Action::None };
        }
        if key.code == KeyCode::Enter {
            self.operator = None;
            if control || alt {
                if self.mode == Mode::Normal {
                    self.begin_insert();
                }
                self.insert_fragment("\n", true);
                return Action::None;
            }
            if self.text.trim().is_empty() {
                return Action::None;
            }
            let text = std::mem::take(&mut self.text);
            self.clear();
            return Action::Submit(text);
        }
        if key.code == KeyCode::Esc {
            if self.mode == Mode::Insert && self.cursor > self.line_start() {
                self.cursor = self.previous(self.cursor);
            }
            self.mode = Mode::Normal;
            self.operator = None;
            self.insert_checkpointed = false;
            self.normalize_normal_cursor();
            return Action::None;
        }
        if control && matches!(key.code, KeyCode::Char('r' | 'R')) {
            self.redo();
            return Action::None;
        }
        if control
            || alt
            || key
                .modifiers
                .intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META)
        {
            return Action::None;
        }
        match self.mode {
            Mode::Insert => self.insert_key(key.code),
            Mode::Normal => self.normal_key(key.code),
        }
    }

    fn insert_key(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Char(character) if !character.is_control() => {
                let mut buffer = [0; 4];
                self.insert_fragment(character.encode_utf8(&mut buffer), true);
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let start = self.previous(self.cursor);
                self.delete_range(start, self.cursor, true);
            }
            KeyCode::Delete if self.cursor < self.text.len() => {
                self.delete_range(self.cursor, self.next(self.cursor), true);
            }
            KeyCode::Left => self.move_to(self.previous(self.cursor)),
            KeyCode::Right => self.move_to(self.next(self.cursor)),
            KeyCode::Home => self.move_to(self.line_start()),
            KeyCode::End => self.move_to(self.line_end()),
            KeyCode::Up => self.move_vertical(-1),
            KeyCode::Down => self.move_vertical(1),
            _ => {}
        }
        Action::None
    }

    fn normal_key(&mut self, key: KeyCode) -> Action {
        if let Some(operator) = self.operator.take() {
            match (operator, key) {
                (Operator::Go, KeyCode::Char('g')) => return Action::Top,
                (Operator::Yank, KeyCode::Char('y')) => {
                    self.yank_line();
                    return Action::None;
                }
                (Operator::Delete, KeyCode::Char('d')) => {
                    self.delete_line();
                    return Action::None;
                }
                (Operator::Yank | Operator::Delete, KeyCode::Char(motion @ ('w' | '$' | '0'))) => {
                    let (start, end) = match motion {
                        'w' => (self.cursor, self.next_word()),
                        '$' => (self.cursor, self.line_end()),
                        _ => (self.line_start(), self.cursor),
                    };
                    self.set_register(self.text[start..end].to_owned(), false);
                    if matches!(operator, Operator::Delete) {
                        self.delete_range(start, end, false);
                    }
                    return Action::None;
                }
                _ => {}
            }
        }
        match key {
            KeyCode::Char('i') => self.begin_insert(),
            KeyCode::Char('a') => {
                self.cursor = self.next(self.cursor).min(self.line_end());
                self.begin_insert();
            }
            KeyCode::Char('I') => {
                let start = self.line_start();
                let end = self.line_end();
                self.cursor = self.text[start..end]
                    .grapheme_indices(true)
                    .find(|(_, g)| !g.chars().all(char::is_whitespace))
                    .map_or(end, |(offset, _)| start + offset);
                self.begin_insert();
            }
            KeyCode::Char('A') => {
                self.cursor = self.line_end();
                self.begin_insert();
            }
            KeyCode::Char(':') => return Action::Palette,
            KeyCode::Char('/') => {
                self.begin_insert();
                self.insert_fragment("/", true);
            }
            KeyCode::Char('h') | KeyCode::Left => {
                self.move_to(self.previous(self.cursor).max(self.line_start()));
            }
            KeyCode::Char('l') | KeyCode::Right => {
                self.move_to(self.next(self.cursor).min(self.line_end()));
                self.normalize_normal_cursor();
            }
            KeyCode::Char('0') | KeyCode::Home => self.move_to(self.line_start()),
            KeyCode::Char('$') | KeyCode::End => {
                self.move_to(self.line_end());
                self.normalize_normal_cursor();
            }
            KeyCode::Char('w') => {
                self.move_to(self.next_word());
                self.normalize_normal_cursor();
            }
            KeyCode::Char('b') => self.move_to(self.previous_word()),
            KeyCode::Char('x') | KeyCode::Delete => {
                if self.cursor < self.line_end() {
                    let end = self.next(self.cursor);
                    self.set_register(self.text[self.cursor..end].to_owned(), false);
                    self.delete_range(self.cursor, end, false);
                }
            }
            KeyCode::Char('d') => self.operator = Some(Operator::Delete),
            KeyCode::Char('y') => self.operator = Some(Operator::Yank),
            KeyCode::Char('g') => self.operator = Some(Operator::Go),
            KeyCode::Char('p') => self.paste_register(false),
            KeyCode::Char('P') => self.paste_register(true),
            KeyCode::Char('u') => self.undo(),
            KeyCode::Char('j') => return Action::Scroll(1),
            KeyCode::Char('k') => return Action::Scroll(-1),
            KeyCode::Char('G') => return Action::Bottom,
            KeyCode::Up => self.move_vertical(-1),
            KeyCode::Down => self.move_vertical(1),
            _ => {}
        }
        Action::None
    }

    fn begin_insert(&mut self) {
        self.mode = Mode::Insert;
        self.operator = None;
        self.insert_checkpointed = false;
        self.preferred_column = None;
    }

    fn checkpoint(&mut self, grouped: bool) {
        if !grouped || !self.insert_checkpointed {
            self.undo.push(self.snapshot());
            if self.undo.len() > UNDO_LIMIT {
                self.undo.remove(0);
            }
            self.redo.clear();
        }
        self.insert_checkpointed = grouped;
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            text: self.text.clone(),
            cursor: self.cursor,
        }
    }

    fn insert_fragment(&mut self, fragment: &str, grouped: bool) -> bool {
        if fragment.is_empty() {
            return true;
        }
        if self.text.len().saturating_add(fragment.len()) > MAX_TEXT_BYTES {
            return false;
        }
        self.checkpoint(grouped);
        self.text.insert_str(self.cursor, fragment);
        self.cursor += fragment.len();
        // ZWJ and combining-mark insertion can merge adjacent graphemes.
        self.cursor = self
            .text
            .grapheme_indices(true)
            .map(|(index, _)| index)
            .find(|index| *index >= self.cursor)
            .unwrap_or(self.text.len());
        self.preferred_column = None;
        true
    }

    fn delete_range(&mut self, start: usize, end: usize, grouped: bool) {
        if start >= end {
            return;
        }
        self.checkpoint(grouped);
        self.text.replace_range(start..end, "");
        self.cursor = start.min(self.text.len());
        self.cursor = self
            .text
            .grapheme_indices(true)
            .map(|(index, _)| index)
            .take_while(|index| *index <= self.cursor)
            .last()
            .unwrap_or(0);
        if start == self.text.len() {
            self.cursor = self.text.len();
        }
        self.preferred_column = None;
        if self.mode == Mode::Normal {
            self.normalize_normal_cursor();
        }
    }

    fn restore(&mut self, mut snapshot: Snapshot) {
        self.text.zeroize();
        self.text = std::mem::take(&mut snapshot.text);
        self.cursor = snapshot.cursor;
        self.mode = Mode::Normal;
        self.operator = None;
        self.insert_checkpointed = false;
        self.preferred_column = None;
        self.normalize_normal_cursor();
    }

    fn undo(&mut self) {
        if let Some(snapshot) = self.undo.pop() {
            self.redo.push(self.snapshot());
            self.restore(snapshot);
        }
    }

    fn redo(&mut self) {
        if let Some(snapshot) = self.redo.pop() {
            self.undo.push(self.snapshot());
            self.restore(snapshot);
        }
    }

    fn set_register(&mut self, text: String, linewise: bool) {
        self.register = Register {
            text,
            linewise,
            occupied: true,
        };
    }

    fn yank_line(&mut self) {
        self.set_register(
            self.text[self.line_start()..self.line_end()].to_owned(),
            true,
        );
    }

    fn delete_line(&mut self) {
        let start = self.line_start();
        let end = self.line_end();
        self.yank_line();
        if end < self.text.len() {
            self.delete_range(start, end + 1, false);
        } else if start > 0 {
            self.delete_range(start - 1, end, false);
            self.move_to(self.line_start());
        } else {
            self.delete_range(start, end, false);
        }
    }

    fn paste_register(&mut self, before: bool) {
        if !self.register.occupied {
            return;
        }
        let (position, fragment, caret) = if self.register.linewise {
            if self.text.is_empty() {
                (0, self.register.text.clone(), 0)
            } else if before {
                let position = self.line_start();
                (position, format!("{}\n", self.register.text), position)
            } else if self.line_end() < self.text.len() {
                let position = self.line_end() + 1;
                (position, format!("{}\n", self.register.text), position)
            } else {
                let position = self.text.len();
                (position, format!("\n{}", self.register.text), position + 1)
            }
        } else {
            let position = if before {
                self.cursor
            } else {
                self.next(self.cursor).min(self.line_end())
            };
            let fragment = self.register.text.clone();
            let caret = position + fragment.len();
            (position, fragment, caret)
        };
        if self.text.len().saturating_add(fragment.len()) > MAX_TEXT_BYTES || fragment.is_empty() {
            return;
        }
        self.checkpoint(false);
        self.text.insert_str(position, &fragment);
        self.cursor = caret.min(self.text.len());
        if !self.register.linewise {
            self.cursor = self.previous(self.cursor);
        }
        self.preferred_column = None;
        self.normalize_normal_cursor();
    }

    fn line_start(&self) -> usize {
        self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1)
    }

    fn line_end(&self) -> usize {
        self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |index| self.cursor + index)
    }

    fn previous(&self, position: usize) -> usize {
        self.text[..position]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(index, _)| index)
    }

    fn next(&self, position: usize) -> usize {
        self.text[position..]
            .graphemes(true)
            .next()
            .map_or(self.text.len(), |g| position + g.len())
    }

    fn move_to(&mut self, position: usize) {
        self.cursor = position.min(self.text.len());
        self.insert_checkpointed = false;
        self.preferred_column = None;
    }

    fn normalize_normal_cursor(&mut self) {
        let start = self.line_start();
        let end = self.line_end();
        if self.cursor == end && end > start {
            self.cursor = self.previous(end);
        }
    }

    fn next_word(&self) -> usize {
        let mut position = self.cursor;
        if position == self.text.len() {
            return position;
        }
        let class = word_class(self.text[position..].graphemes(true).next().unwrap());
        while position < self.text.len() {
            let g = self.text[position..].graphemes(true).next().unwrap();
            if word_class(g) != class {
                break;
            }
            position += g.len();
        }
        while position < self.text.len() {
            let g = self.text[position..].graphemes(true).next().unwrap();
            if word_class(g) != 0 {
                break;
            }
            position += g.len();
        }
        position
    }

    fn previous_word(&self) -> usize {
        let mut position = self.previous(self.cursor);
        while position > 0 && word_class(self.text[position..].graphemes(true).next().unwrap()) == 0
        {
            position = self.previous(position);
        }
        let Some(g) = self.text[position..].graphemes(true).next() else {
            return 0;
        };
        let class = word_class(g);
        while position > 0 {
            let previous = self.previous(position);
            if word_class(&self.text[previous..position]) != class {
                break;
            }
            position = previous;
        }
        position
    }

    fn move_vertical(&mut self, direction: i16) {
        let wanted = self
            .preferred_column
            .unwrap_or_else(|| self.cursor_position().1);
        let start = self.line_start();
        let target_start = if direction < 0 {
            if start == 0 {
                return;
            }
            self.text[..start - 1]
                .rfind('\n')
                .map_or(0, |index| index + 1)
        } else {
            let end = self.line_end();
            if end == self.text.len() {
                return;
            }
            end + 1
        };
        let target_end = self.text[target_start..]
            .find('\n')
            .map_or(self.text.len(), |index| target_start + index);
        let mut position = target_start;
        let mut column = 0;
        for g in self.text[target_start..target_end].graphemes(true) {
            let width = display_width(g, column);
            if column + width > wanted {
                break;
            }
            position += g.len();
            column += width;
        }
        self.cursor = position;
        self.preferred_column = Some(wanted);
        self.insert_checkpointed = false;
        if self.mode == Mode::Normal {
            self.normalize_normal_cursor();
        }
    }
}

fn word_class(grapheme: &str) -> u8 {
    if grapheme.chars().all(char::is_whitespace) {
        0
    } else if grapheme.chars().any(|c| c.is_alphanumeric() || c == '_') {
        1
    } else {
        2
    }
}

fn display_width(grapheme: &str, column: usize) -> usize {
    if grapheme == "\t" {
        TAB_STOP - column % TAB_STOP
    } else {
        UnicodeWidthStr::width(grapheme)
    }
}

fn normalize_paste(input: &str) -> String {
    let mut result = String::with_capacity(input.len().min(MAX_TEXT_BYTES + 1));
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            result.push('\n');
        } else if c == '\n' || c == '\t' || !c.is_control() {
            result.push(c);
        }
        if result.len() > MAX_TEXT_BYTES {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(editor: &mut Editor, code: KeyCode) -> Action {
        editor.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn normal(editor: &mut Editor, keys: &str) {
        for c in keys.chars() {
            key(editor, KeyCode::Char(c));
        }
    }

    #[test]
    fn starts_normal_and_enter_submits_without_retaining_register_or_undo() {
        let mut editor = Editor::new();
        assert_eq!(editor.mode(), Mode::Normal);
        assert_eq!(key(&mut editor, KeyCode::Char('j')), Action::Scroll(1));
        normal(&mut editor, "ihello");
        key(&mut editor, KeyCode::Esc);
        normal(&mut editor, "yy");
        assert_eq!(
            key(&mut editor, KeyCode::Enter),
            Action::Submit("hello".into())
        );
        assert_eq!(editor.mode(), Mode::Normal);
        normal(&mut editor, "up");
        assert!(editor.text().is_empty());
    }

    #[test]
    fn colon_opens_palette_only_in_normal_mode() {
        let mut editor = Editor::new();
        assert_eq!(key(&mut editor, KeyCode::Char(':')), Action::Palette);
        assert!(editor.text().is_empty());
        normal(&mut editor, "i");
        assert_eq!(key(&mut editor, KeyCode::Char(':')), Action::None);
        assert_eq!(editor.text(), ":");
    }

    #[test]
    fn paste_is_literal_and_modified_enter_only_inserts_newlines() {
        let mut editor = Editor::new();
        assert!(editor.insert_text("/quit\r\n你好\u{1b}\0"));
        assert_eq!(editor.text(), "/quit\n你好");
        assert_eq!(editor.mode(), Mode::Insert);
        assert_eq!(
            editor.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL)),
            Action::None
        );
        assert_eq!(
            editor.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)),
            Action::None
        );
        assert_eq!(editor.text(), "/quit\n你好\n\n");
        assert_eq!(
            key(&mut editor, KeyCode::Enter),
            Action::Submit("/quit\n你好\n\n".into())
        );
    }

    #[test]
    fn unicode_graphemes_move_and_delete_as_complete_characters() {
        let mut editor = Editor::new();
        editor.insert_text("你e\u{301}👩‍💻好");
        assert_eq!(editor.cursor_position(), (0, 7));
        key(&mut editor, KeyCode::Backspace);
        assert_eq!(editor.text(), "你e\u{301}👩‍💻");
        key(&mut editor, KeyCode::Esc);
        assert_eq!(editor.cursor_position(), (0, 3));
        normal(&mut editor, "x");
        assert_eq!(editor.text(), "你e\u{301}");
        normal(&mut editor, "x");
        assert_eq!(editor.text(), "你");
        normal(&mut editor, "u");
        assert_eq!(editor.text(), "你e\u{301}");
    }

    #[test]
    fn yank_word_and_line_paste_preserve_vim_register_kind() {
        let mut editor = Editor::new();
        editor.insert_text("one two");
        key(&mut editor, KeyCode::Esc);
        normal(&mut editor, "0yw$p");
        assert_eq!(editor.text(), "one twoone ");
        normal(&mut editor, "u0yyp");
        assert_eq!(editor.text(), "one two\none two");
        normal(&mut editor, "dd");
        assert_eq!(editor.text(), "one two");
        normal(&mut editor, "P");
        assert_eq!(editor.text(), "one two\none two");
    }

    #[test]
    fn insert_session_is_one_undo_and_redo_restores_it() {
        let mut editor = Editor::new();
        normal(&mut editor, "i你好abc");
        key(&mut editor, KeyCode::Esc);
        normal(&mut editor, "u");
        assert!(editor.text().is_empty());
        editor.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert_eq!(editor.text(), "你好abc");
        normal(&mut editor, "0aX");
        key(&mut editor, KeyCode::Esc);
        assert_eq!(editor.text(), "你X好abc");
        normal(&mut editor, "u");
        assert_eq!(editor.text(), "你好abc");
    }

    #[test]
    fn multiline_motions_delete_line_and_chat_navigation_are_separate() {
        let mut editor = Editor::new();
        editor.insert_text("first\n  你好\nlast");
        key(&mut editor, KeyCode::Esc);
        key(&mut editor, KeyCode::Up);
        normal(&mut editor, "I!");
        key(&mut editor, KeyCode::Esc);
        assert_eq!(editor.text(), "first\n  !你好\nlast");
        normal(&mut editor, "dd");
        assert_eq!(editor.text(), "first\nlast");
        assert_eq!(key(&mut editor, KeyCode::Char('k')), Action::Scroll(-1));
        assert_eq!(key(&mut editor, KeyCode::Char('g')), Action::None);
        assert_eq!(key(&mut editor, KeyCode::Char('g')), Action::Top);
        assert_eq!(key(&mut editor, KeyCode::Char('G')), Action::Bottom);
    }

    #[test]
    fn byte_limit_rejects_whole_paste_and_typing_without_corrupting_unicode() {
        let mut editor = Editor::new();
        assert!(editor.insert_text(&"a".repeat(MAX_TEXT_BYTES - 2)));
        assert!(!editor.insert_text("你"));
        key(&mut editor, KeyCode::Char('你'));
        assert_eq!(editor.text().len(), MAX_TEXT_BYTES - 2);
        assert!(editor.insert_text("ab"));
        assert_eq!(editor.text().len(), MAX_TEXT_BYTES);
        key(&mut editor, KeyCode::Backspace);
        assert_eq!(editor.text().len(), MAX_TEXT_BYTES - 1);
    }

    #[test]
    fn control_c_clears_draft_before_requesting_quit() {
        let mut editor = Editor::new();
        editor.insert_text("draft");
        let interrupt = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(editor.handle_key(interrupt), Action::None);
        assert!(editor.text().is_empty());
        assert_eq!(editor.mode(), Mode::Normal);
        assert_eq!(editor.handle_key(interrupt), Action::Quit);
        assert_eq!(key(&mut editor, KeyCode::Enter), Action::None);
    }
}
