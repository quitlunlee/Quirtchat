//! Small in-palette forms. Validation and input are local; callers own persistence/network work.

use super::theme::{ACCENT, BORDER, MUTED, PANEL, TEXT};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

const INPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FormKind {
    CreateGroup,
    JoinGroup,
    Mailbox { current: Option<String> },
    Remark { name: String, id: String },
    Quit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FormValues {
    CreateGroup {
        name: String,
        server: String,
        members: Vec<String>,
    },
    JoinGroup {
        server: String,
    },
    MailboxAttach {
        server: String,
    },
    MailboxDetach,
    Remark {
        remark: String,
    },
    Quit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FormAction {
    None,
    Cancel,
    Submit(FormValues),
}

pub(super) struct FormState {
    kind: FormKind,
    fields: Vec<String>,
    cursors: Vec<usize>,
    selected: usize,
    editing: bool,
    error: Option<String>,
}

impl FormState {
    pub(super) fn new(kind: FormKind) -> Self {
        let count = match kind {
            FormKind::CreateGroup => 3,
            FormKind::Quit => 0,
            _ => 1,
        };
        Self {
            kind,
            fields: vec![String::new(); count],
            cursors: vec![0; count],
            selected: 0,
            editing: count > 0,
            error: None,
        }
    }

    pub(super) fn kind(&self) -> &FormKind {
        &self.kind
    }

    /// Preserve every input on backend failure so the user can correct and retry.
    pub(super) fn set_error(&mut self, message: String) {
        self.error = Some(safe_text(&message).chars().take(160).collect());
    }

    fn labels(&self) -> &[&str] {
        match self.kind {
            FormKind::CreateGroup => &[
                "Group name",
                "Server invite file / code",
                "Members (optional)",
            ],
            FormKind::JoinGroup => &["Server address / invite file"],
            FormKind::Mailbox { .. } => &["Personal mailbox server invite file / code"],
            FormKind::Remark { .. } => &["Local name"],
            FormKind::Quit => &[],
        }
    }

    fn buttons(&self) -> &[&str] {
        match &self.kind {
            FormKind::CreateGroup => &["Create group"],
            FormKind::JoinGroup => &["Sync invitations"],
            FormKind::Mailbox { current: Some(_) } => &["Bind and enable", "Detach mailbox"],
            FormKind::Mailbox { current: None } => &["Bind and enable"],
            FormKind::Remark { .. } => &["Save friend"],
            FormKind::Quit => &["Back", "Quit"],
        }
    }

    fn move_selection(&mut self, backward: bool) {
        let count = self.fields.len() + self.buttons().len();
        self.selected = if backward {
            (self.selected + count - 1) % count
        } else {
            (self.selected + 1) % count
        };
        self.editing = false;
    }

    pub(super) fn key(&mut self, key: KeyEvent) -> FormAction {
        if key.kind == KeyEventKind::Release
            || (key.kind == KeyEventKind::Repeat && key.code == KeyCode::Enter)
        {
            return FormAction::None;
        }
        if key.code == KeyCode::Esc {
            if self.editing {
                self.editing = false;
                return FormAction::None;
            }
            return FormAction::Cancel;
        }
        if key.code == KeyCode::Tab
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('n'))
        {
            self.move_selection(false);
            return FormAction::None;
        }
        if key.code == KeyCode::BackTab
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.move_selection(true);
            return FormAction::None;
        }
        if key.code == KeyCode::Enter {
            if self.selected < self.fields.len() {
                self.selected += 1;
                self.editing = self.selected < self.fields.len();
                return FormAction::None;
            }
            return self.submit();
        }
        if !self.editing {
            match key.code {
                KeyCode::Char('j') | KeyCode::Down => self.move_selection(false),
                KeyCode::Char('k') | KeyCode::Up => self.move_selection(true),
                KeyCode::Char('i') | KeyCode::Char('a') if self.selected < self.fields.len() => {
                    self.editing = true;
                    if key.code == KeyCode::Char('a') {
                        self.cursors[self.selected] = self.fields[self.selected].len();
                    }
                }
                _ => {}
            }
            return FormAction::None;
        }
        let index = self.selected;
        let text = &mut self.fields[index];
        let cursor = &mut self.cursors[index];
        match key.code {
            KeyCode::Left => *cursor = previous_boundary(text, *cursor),
            KeyCode::Right => *cursor = next_boundary(text, *cursor),
            KeyCode::Home => *cursor = 0,
            KeyCode::End => *cursor = text.len(),
            KeyCode::Backspace if *cursor > 0 => {
                let before = previous_boundary(text, *cursor);
                text.replace_range(before..*cursor, "");
                *cursor = before;
                self.error = None;
            }
            KeyCode::Delete if *cursor < text.len() => {
                let after = next_boundary(text, *cursor);
                text.replace_range(*cursor..after, "");
                self.error = None;
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                text.drain(..*cursor);
                *cursor = 0;
                self.error = None;
            }
            KeyCode::Char(ch)
                if !ch.is_control()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && text.len() + ch.len_utf8() <= INPUT_LIMIT =>
            {
                text.insert(*cursor, ch);
                *cursor += ch.len_utf8();
                self.error = None;
            }
            _ => {}
        }
        FormAction::None
    }

    /// Bracketed paste is text only. It can never accept a form or confirm quitting.
    pub(super) fn paste(&mut self, text: &str) {
        if self.selected >= self.fields.len() {
            return;
        }
        let clean: String = text
            .chars()
            .map(|ch| {
                if matches!(ch, '\r' | '\n' | '\t') {
                    ' '
                } else {
                    ch
                }
            })
            .filter(|ch| !ch.is_control())
            .collect();
        let field = &mut self.fields[self.selected];
        if field.len() + clean.len() > INPUT_LIMIT {
            self.error = Some("Input too long".into());
            return;
        }
        field.insert_str(self.cursors[self.selected], &clean);
        self.cursors[self.selected] += clean.len();
        self.editing = true;
        self.error = None;
    }

    fn submit(&mut self) -> FormAction {
        let values: Vec<_> = self
            .fields
            .iter()
            .map(|text| text.trim().to_owned())
            .collect();
        let field = |index: usize| values[index].clone();
        let missing = match self.kind {
            FormKind::CreateGroup => [0, 1].into_iter().find(|&index| values[index].is_empty()),
            FormKind::JoinGroup => values[0].is_empty().then_some(0),
            FormKind::Mailbox { .. } if self.selected == self.fields.len() => {
                values[0].is_empty().then_some(0)
            }
            _ => None,
        };
        if let Some(index) = missing {
            self.error = Some("This field is required".into());
            self.selected = index;
            self.editing = true;
            return FormAction::None;
        }
        let value = match self.kind {
            FormKind::CreateGroup => {
                if values[0].len() > 128 {
                    self.error = Some("Group name exceeds 128 bytes".into());
                    self.selected = 0;
                    self.editing = true;
                    return FormAction::None;
                }
                let mut members = Vec::new();
                for name in values[2]
                    .split([',', '，'])
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                {
                    if !members.iter().any(|known| known == name) {
                        members.push(name.to_owned());
                    }
                }
                FormValues::CreateGroup {
                    name: field(0),
                    server: field(1),
                    members,
                }
            }
            FormKind::JoinGroup => FormValues::JoinGroup { server: field(0) },
            FormKind::Mailbox { .. } if self.selected > self.fields.len() => {
                FormValues::MailboxDetach
            }
            FormKind::Mailbox { .. } => FormValues::MailboxAttach { server: field(0) },
            FormKind::Remark { .. } => {
                if values[0].len() > 128 {
                    self.error = Some("Local name exceeds 128 bytes".into());
                    self.selected = 0;
                    self.editing = true;
                    return FormAction::None;
                }
                FormValues::Remark { remark: field(0) }
            }
            FormKind::Quit if self.selected == 0 => return FormAction::Cancel,
            FormKind::Quit => FormValues::Quit,
        };
        FormAction::Submit(value)
    }

    pub(super) fn render(&self, frame: &mut Frame, area: Rect) {
        let panel = super::palette::menu_rect(area);
        if panel.width < 4 || panel.height < 4 {
            return;
        }
        let title = match self.kind {
            FormKind::CreateGroup => " Groups / Create group ",
            FormKind::JoinGroup => " Groups / Join group ",
            FormKind::Mailbox { .. } => " Settings / Personal mailbox ",
            FormKind::Remark { .. } => " Direct messages / Add friend ",
            FormKind::Quit => " Quit Qu1rTChat ",
        };
        frame.render_widget(Clear, panel);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(PANEL).fg(TEXT))
            .title(title);
        let inner = block.inner(panel);
        frame.render_widget(block, panel);
        if inner.width < 3 || inner.height == 0 {
            return;
        }
        let inner = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        );
        let mut lines: Vec<Line<'_>> = Vec::new();
        match &self.kind {
            FormKind::Remark { name, id } => {
                lines.push(Line::styled(
                    format!("Contact: {}", safe_text(name)),
                    Style::default().fg(TEXT),
                ));
                lines.push(Line::styled(
                    format!("Identity: {}…", short_identity(id)),
                    Style::default().fg(MUTED),
                ));
            }
            FormKind::Mailbox { current } => {
                lines.push(Line::styled(
                    match current {
                        Some(id) => format!("Enabled: {}…", short_identity(id)),
                        None => "No personal mailbox attached".into(),
                    },
                    Style::default().fg(MUTED),
                ));
            }
            FormKind::CreateGroup | FormKind::JoinGroup => {}
            FormKind::Quit => {
                lines.push(Line::from(
                    "Discard unsent drafts and stop active transfers?",
                ));
            }
        }
        lines.push(Line::default());
        let mut selected_row = 0;
        let mut cursor = None;
        for (index, label) in self.labels().iter().enumerate() {
            let active = index == self.selected;
            lines.push(Line::styled(
                *label,
                Style::default().fg(if active { ACCENT } else { MUTED }),
            ));
            let available = usize::from(inner.width.saturating_sub(2));
            let (visible, column) =
                input_window(&self.fields[index], self.cursors[index], available);
            if active {
                selected_row = lines.len();
                if self.editing {
                    cursor = Some((selected_row, column.saturating_add(2)));
                }
            }
            lines.push(Line::from(vec![
                Span::styled(
                    if active { "> " } else { "  " },
                    Style::default().fg(ACCENT),
                ),
                Span::styled(
                    visible,
                    Style::default().fg(if active { TEXT } else { MUTED }),
                ),
            ]));
        }
        lines.push(Line::default());
        for (index, label) in self.buttons().iter().enumerate() {
            let active = self.selected == self.fields.len() + index;
            if active {
                selected_row = lines.len();
            }
            lines.push(Line::styled(
                format!("{}{}", if active { "> " } else { "  " }, label),
                Style::default()
                    .fg(if active { ACCENT } else { MUTED })
                    .add_modifier(if active {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ));
        }
        let error_rows = u16::from(self.error.is_some() && inner.height >= 2);
        let body_height = inner.height.saturating_sub(error_rows);
        let scroll = selected_row.saturating_sub(usize::from(body_height.saturating_sub(1)));
        frame.render_widget(
            Paragraph::new(lines).scroll((scroll.min(u16::MAX as usize) as u16, 0)),
            Rect {
                height: body_height,
                ..inner
            },
        );
        if let Some(error) = self.error.as_deref().filter(|_| error_rows > 0) {
            frame.render_widget(
                Paragraph::new(Line::styled(error, Style::default().fg(ACCENT))),
                Rect::new(inner.x, inner.y + body_height, inner.width, error_rows),
            );
        }
        if let Some((row, column)) = cursor {
            let row = row.saturating_sub(scroll);
            if row < usize::from(body_height) && column < usize::from(inner.width) {
                super::cursor::render(
                    frame.buffer_mut(),
                    (inner.x + column as u16, inner.y + row as u16),
                    true,
                );
            }
        }
    }
}

fn previous_boundary(text: &str, cursor: usize) -> usize {
    text[..cursor]
        .grapheme_indices(true)
        .next_back()
        .map_or(0, |(index, _)| index)
}

fn next_boundary(text: &str, cursor: usize) -> usize {
    text[cursor..]
        .graphemes(true)
        .next()
        .map_or(text.len(), |cluster| cursor + cluster.len())
}

fn input_window(text: &str, cursor: usize, width: usize) -> (&str, usize) {
    if width == 0 {
        return ("", 0);
    }
    let mut start = cursor;
    let mut column = 0;
    for (offset, cluster) in text[..cursor].grapheme_indices(true).rev() {
        let cells = cluster.width();
        if column + cells >= width {
            break;
        }
        start = offset;
        column += cells;
    }
    (&text[start..], column)
}

fn safe_text(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_control()).collect()
}
fn short_identity(id: &str) -> String {
    id.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .take(16)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn quit_defaults_to_return_and_paste_cannot_confirm() {
        let mut form = FormState::new(FormKind::Quit);
        form.paste("退出\n");
        assert_eq!(form.key(key(KeyCode::Enter)), FormAction::Cancel);
        let mut form = FormState::new(FormKind::Quit);
        form.key(key(KeyCode::Char('j')));
        assert_eq!(
            form.key(key(KeyCode::Enter)),
            FormAction::Submit(FormValues::Quit)
        );
    }

    #[test]
    fn remark_preserves_spaces_and_grapheme_editing() {
        let mut form = FormState::new(FormKind::Remark {
            name: "Alex".into(),
            id: "ab".repeat(32),
        });
        form.paste("猫 工作 e\u{301}");
        form.key(key(KeyCode::Backspace));
        assert_eq!(form.fields[0], "猫 工作 ");
        assert_eq!(form.key(key(KeyCode::Esc)), FormAction::None);
        assert!(!form.editing);
        form.key(key(KeyCode::Enter));
        assert_eq!(
            form.key(key(KeyCode::Enter)),
            FormAction::Submit(FormValues::Remark {
                remark: "猫 工作".into()
            })
        );
    }

    #[test]
    fn group_form_returns_named_values_and_deduplicated_members() {
        let mut form = FormState::new(FormKind::CreateGroup);
        for value in [
            "朋友们",
            "C:\\group invite.txt",
            "小明 Work, Alice, 小明 Work，Bob",
        ] {
            form.paste(value);
            assert_eq!(form.key(key(KeyCode::Enter)), FormAction::None);
        }
        assert_eq!(
            form.key(key(KeyCode::Enter)),
            FormAction::Submit(FormValues::CreateGroup {
                name: "朋友们".into(),
                server: "C:\\group invite.txt".into(),
                members: vec!["小明 Work".into(), "Alice".into(), "Bob".into()],
            })
        );
    }

    #[test]
    fn required_server_and_mailbox_detach_do_not_conflict() {
        let mut empty = FormState::new(FormKind::JoinGroup);
        empty.key(key(KeyCode::Enter));
        assert_eq!(empty.key(key(KeyCode::Enter)), FormAction::None);
        assert_eq!(empty.selected, 0);
        assert!(empty.error.is_some());
        let mut mailbox = FormState::new(FormKind::Mailbox {
            current: Some("ab".repeat(32)),
        });
        mailbox.key(key(KeyCode::Tab));
        mailbox.key(key(KeyCode::Tab));
        assert_eq!(
            mailbox.key(key(KeyCode::Enter)),
            FormAction::Submit(FormValues::MailboxDetach)
        );
    }

    #[test]
    fn backend_error_retains_fields_and_enter_repeat_never_submits() {
        let mut form = FormState::new(FormKind::JoinGroup);
        form.paste("C:\\a server.invite");
        form.key(key(KeyCode::Enter));
        let submitted = FormAction::Submit(FormValues::JoinGroup {
            server: "C:\\a server.invite".into(),
        });
        assert_eq!(form.key(key(KeyCode::Enter)), submitted);
        form.set_error("connection unavailable\u{1b}".into());
        assert_eq!(form.fields[0], "C:\\a server.invite");
        assert_eq!(form.error.as_deref(), Some("connection unavailable"));
        let mut repeated = key(KeyCode::Enter);
        repeated.kind = KeyEventKind::Repeat;
        assert_eq!(form.key(repeated), FormAction::None);
        assert_eq!(form.key(key(KeyCode::Enter)), submitted);
    }

    #[test]
    fn selected_submit_button_scrolls_into_view_at_28_by_10() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(28, 10)).unwrap();
        let mut form = FormState::new(FormKind::CreateGroup);
        for value in ["朋友", "server.invite", "小明 Work"] {
            form.paste(value);
            form.key(key(KeyCode::Enter));
        }
        terminal
            .draw(|frame| form.render(frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .filter(|symbol| *symbol != " ")
            .collect();
        assert!(text.contains(">Creategroup"), "{text}");
    }

    #[test]
    fn all_forms_render_on_tiny_and_large_terminals() {
        use ratatui::{Terminal, backend::TestBackend};
        for (width, height) in [(1, 1), (12, 6), (40, 12), (80, 24), (160, 50)] {
            for kind in [
                FormKind::CreateGroup,
                FormKind::JoinGroup,
                FormKind::Mailbox {
                    current: Some("ab".repeat(32)),
                },
                FormKind::Remark {
                    name: "猫".repeat(40),
                    id: "cd".repeat(32),
                },
                FormKind::Quit,
            ] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                let form = FormState::new(kind);
                terminal
                    .draw(|frame| form.render(frame, frame.area()))
                    .unwrap();
            }
        }
    }
}
