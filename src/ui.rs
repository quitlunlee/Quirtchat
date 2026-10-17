//! Message bodies are borrowed only for the current frame, never cached by the UI.

#[path = "ui_card.rs"]
mod card;
#[path = "editor.rs"]
mod editor;
#[path = "ui_effects.rs"]
mod effects;
#[path = "ui_files.rs"]
mod files;
#[path = "ui_logo.rs"]
mod logo;
#[path = "ui_palette.rs"]
mod palette;
#[path = "ui_theme.rs"]
mod theme;

use crate::media_view::{self, MediaView};
use anyhow::Result;
use clichat::{
    app::{App, Shared},
    media::MediaDescriptor,
    model::{ChatMessage, now},
    transport::Transport,
};
use crossterm::{
    cursor::SetCursorStyle,
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
        PushKeyboardEnhancementFlags,
    },
    execute,
};
use editor::{Action, Editor, Mode};
use effects::{Effects, gradient_border};
use files::{FileEvent, Files, Mode as FileMode};
use palette::{Catalog, Palette, PaletteEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use theme::{ACCENT, FAINT, MUTED, TEXT, VIOLET};
use tokio::task::JoinHandle;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

struct ConversationView<'a> {
    id: &'a str,
    name: &'a str,
}
struct MessageView<'a> {
    id: &'a str,
    conversation: &'a str,
    text: &'a str,
    sender: &'a str,
    own: bool,
    expires: i64,
    delivery: &'static str,
    media: Option<&'a MediaDescriptor>,
    progress: usize,
}
struct View<'a> {
    /// Our own display name and identity, for the card shown after saving an invitation.
    me: (&'a str, &'a str),
    status: &'a str,
    online: bool,
    proxy: &'a str,
    queued: usize,
    groups: Vec<ConversationView<'a>>,
    contacts: Vec<&'a str>,
    messages: Vec<MessageView<'a>>,
}

impl<'a> View<'a> {
    fn from_app(app: &'a App, progress: &BTreeMap<String, (i64, usize)>) -> Self {
        let time = now();
        let mut delivery = BTreeMap::new();
        for item in &app.state.outbox {
            delivery
                .entry(item.envelope.id.as_str())
                .and_modify(|cached| *cached &= !item.stored_at.is_empty())
                .or_insert(!item.stored_at.is_empty());
        }
        Self {
            me: (&app.state.name, app.id()),
            status: &app.status,
            online: !app.ticket.is_empty(),
            proxy: app.state.proxy.as_deref().map_or("off", |url| {
                url.trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
            }),
            queued: app.state.outbox.len(),
            groups: app
                .state
                .conversations
                .values()
                .map(|group| ConversationView {
                    id: &group.id,
                    name: &group.name,
                })
                .collect(),
            contacts: app
                .state
                .contacts
                .values()
                .map(|contact| contact.name.as_str())
                .collect(),
            messages: app
                .state
                .messages
                .iter()
                .filter(|message| message.expires_at > time)
                .map(|message| {
                    let own = message.sender == app.id();
                    let delivery = match delivery.get(message.id.as_str()) {
                        None => "",
                        Some(true) => "cached",
                        Some(_) => "queued",
                    };
                    MessageView {
                        id: &message.id,
                        conversation: &message.conversation,
                        text: &message.text,
                        sender: app
                            .state
                            .contacts
                            .get(&message.sender)
                            .map_or("member", |contact| contact.name.as_str()),
                        own,
                        expires: message.expires_at,
                        delivery,
                        media: message.attachment.as_ref(),
                        progress: message
                            .attachment
                            .as_ref()
                            .and_then(|media| progress.get(&media.id))
                            .map_or(0, |(_, count)| *count),
                    }
                })
                .collect(),
        }
    }
}

/// Pure progress metadata, bounded to 64 recent attachments in the active chat.
/// Database queries run at most four times per second, never once per frame.
struct ProgressCache {
    values: BTreeMap<String, (i64, usize)>,
    refreshed: Instant,
    conversation: Option<String>,
}

impl Default for ProgressCache {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            refreshed: Instant::now() - Duration::from_secs(1),
            conversation: None,
        }
    }
}

impl ProgressCache {
    fn refresh(&mut self, app: &App, conversation: Option<&str>, time: i64) {
        self.values.retain(|_, (expires, _)| *expires > time);
        if self.conversation.as_deref() == conversation
            && self.refreshed.elapsed() < Duration::from_millis(250)
        {
            return;
        }
        self.values.clear();
        self.conversation = conversation.map(str::to_owned);
        self.refreshed = Instant::now();
        for message in app
            .state
            .messages
            .iter()
            .rev()
            .filter(|message| {
                message.expires_at > time && Some(message.conversation.as_str()) == conversation
            })
            .filter_map(|message| message.attachment.as_ref())
            .take(64)
        {
            if let Ok(count) = app.store.media_progress(&message.id, time) {
                self.values
                    .insert(message.id.clone(), (message.expires_at, count));
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Chat,
}

/// One dialog at a time on top of the screen; the palette keeps its own state.
enum Overlay {
    None,
    Files(Files),
    /// An invitation that decoded and verified, waiting for Enter to be added.
    Confirm(Pending),
    /// Our own card, shown after the invitation file was saved.
    Shown {
        name: String,
        id: String,
    },
}

struct Pending {
    name: String,
    id: String,
    /// Canonical token; confirming imports this, never the source file again.
    token: String,
}

struct Ui {
    screen: Screen,
    editor: Editor,
    selected: Option<String>,
    scroll: usize,
    body_height: u16,
    motion: bool,
    effects: Effects,
    overlay: Overlay,
    last_dir: [Option<std::path::PathBuf>; 2],
    me: (String, String),
    palette: Palette,
    composer: Rect,
    proxy: String,
    status_seen: (String, Instant),
    cursor_mode: Option<Mode>,
    media: MediaView,
    media_progress: ProgressCache,
    notice: Option<(String, Instant)>,
    started: Instant,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            screen: Screen::Home,
            editor: Editor::new(),
            selected: None,
            scroll: 0,
            body_height: 10,
            motion: std::env::var_os("CLICHAT_REDUCED_MOTION").is_none(),
            effects: Effects::default(),
            overlay: Overlay::None,
            last_dir: [None, None],
            me: (String::new(), String::new()),
            palette: Palette::default(),
            composer: Rect::default(),
            proxy: "off".into(),
            status_seen: (String::new(), Instant::now()),
            cursor_mode: None,
            media: MediaView::default(),
            media_progress: ProgressCache::default(),
            notice: None,
            started: Instant::now(),
        }
    }
}

impl Ui {
    fn select(&mut self, selected: Option<String>) {
        if self.selected != selected {
            self.selected = selected;
            self.scroll = 0;
            self.effects.clear();
        }
    }
    fn notify(&mut self, message: impl Into<String>) {
        self.notice = Some((message.into(), Instant::now()));
    }
    fn local_command(&mut self, line: &str) -> bool {
        match line.trim() {
            "/motion on" => {
                self.motion = true;
                self.notify("motion on");
            }
            "/motion off" => {
                self.motion = false;
                self.effects.clear();
                self.notify("motion off");
            }
            "/motion" | "/motion toggle" | "/toggle" => {
                self.motion = !self.motion;
                self.effects.clear();
                self.notify(if self.motion {
                    "motion on"
                } else {
                    "motion off"
                });
            }
            _ => return false,
        }
        true
    }
}

struct TerminalFeatures;
impl Drop for TerminalFeatures {
    fn drop(&mut self) {
        let _ = execute!(
            std::io::stdout(),
            DisableBracketedPaste,
            PopKeyboardEnhancementFlags,
            SetCursorStyle::DefaultUserShape
        );
        ratatui::restore();
    }
}

pub async fn run(shared: Shared, transport: Arc<Transport>) -> Result<()> {
    let mut terminal = ratatui::init();
    let _features = TerminalFeatures;
    // Alt+Enter also works when a terminal cannot distinguish Ctrl+Enter.
    let _ = execute!(
        std::io::stdout(),
        EnableBracketedPaste,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    );
    run_inner(&mut terminal, shared, transport).await
}

struct CommandOutcome {
    before: Option<String>,
    after: Option<String>,
    input: String,
    result: Result<bool, String>,
    media: Option<ChatMessage>,
    /// Failed drafts return to the editor only when they came from it.
    restore: bool,
    /// Plain text, not a slash command: a successful run plays the send burst.
    sent: bool,
    /// `/invite` or `/add`: a success shows an identity card.
    card: Option<CardKind>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CardKind {
    Mine,
    Theirs,
}

fn spawn_command(
    shared: &Shared,
    transport: &Arc<Transport>,
    before: Option<String>,
    input: String,
    restore: bool,
) -> JoinHandle<CommandOutcome> {
    let shared = shared.clone();
    let transport = transport.clone();
    tokio::spawn(async move {
        let mut after = before.clone();
        let sent = !input.starts_with('/');
        let card = match input.split_whitespace().next() {
            Some("/invite") => Some(CardKind::Mine),
            Some("/add") => Some(CardKind::Theirs),
            _ => None,
        };
        if input.split_whitespace().next() == Some("/open") {
            let query = input
                .trim_start()
                .strip_prefix("/open")
                .unwrap_or("")
                .trim()
                .to_owned();
            let conversation = before.clone();
            let result = tokio::task::spawn_blocking(move || {
                shared
                    .lock()
                    .map_err(|_| anyhow::anyhow!("profile state lock failed"))?
                    .request_media(&query, conversation.as_deref())
            })
            .await;
            let (media, result) = match result {
                Ok(Ok(message)) => (Some(message), Ok(false)),
                Ok(Err(error)) => (None, Err(error.to_string())),
                Err(error) => (None, Err(error.to_string())),
            };
            return CommandOutcome {
                before,
                after,
                input,
                result,
                media,
                restore,
                sent: false,
                card: None,
            };
        }
        let result = crate::ui_command(&shared, &transport, &mut after, input.clone())
            .await
            .map_err(|error| error.to_string());
        CommandOutcome {
            before,
            after,
            input,
            result,
            media: None,
            restore,
            sent,
            card,
        }
    })
}

async fn run_inner(
    terminal: &mut ratatui::DefaultTerminal,
    shared: Shared,
    transport: Arc<Transport>,
) -> Result<()> {
    let mut ui = Ui::default();
    let mut command: Option<JoinHandle<CommandOutcome>> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(33));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if command.as_ref().is_some_and(JoinHandle::is_finished) {
            match command.take().unwrap().await {
                Ok(outcome) => match outcome.result {
                    Ok(true) => return Ok(()),
                    Ok(false) => {
                        let chosen = outcome.after != outcome.before && outcome.after.is_some();
                        if ui.selected == outcome.before {
                            ui.select(outcome.after);
                        }
                        if chosen {
                            ui.screen = Screen::Chat;
                        }
                        ui.scroll = 0;
                        if outcome.sent {
                            ui.effects.send_burst(ui.composer, ui.motion);
                        }
                        if outcome.card == Some(CardKind::Mine) && !ui.me.1.is_empty() {
                            ui.overlay = Overlay::Shown {
                                name: ui.me.0.clone(),
                                id: ui.me.1.clone(),
                            };
                        }
                        if let Some(message) = outcome.media {
                            ui.media.request(message);
                        }
                    }
                    Err(error) => {
                        ui.notify(error);
                        if outcome.restore && ui.editor.text().is_empty() {
                            ui.editor.insert_text(&outcome.input);
                        }
                    }
                },
                Err(error) => ui.notify(format!("stopped: {error}")),
            }
        }
        match ui.media.poll(&shared).await {
            Ok(Some(playback)) => {
                if let Some(player) = media_view::find_mpv() {
                    // Clear both frame buffers before yielding terminal ownership.
                    // Playback gets its own alternate screen to avoid scrollback.
                    for _ in 0..2 {
                        terminal.draw(|frame| frame.render_widget(Clear, frame.area()))?;
                    }
                    let _ = execute!(
                        std::io::stdout(),
                        DisableBracketedPaste,
                        PopKeyboardEnhancementFlags
                    );
                    ratatui::restore();
                    let _ = execute!(
                        std::io::stdout(),
                        crossterm::terminal::EnterAlternateScreen,
                        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
                    );
                    let result = media_view::play_terminal(playback, &player).await;
                    let _ = execute!(
                        std::io::stdout(),
                        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
                        crossterm::terminal::LeaveAlternateScreen
                    );
                    *terminal = ratatui::init();
                    let _ = execute!(
                        std::io::stdout(),
                        EnableBracketedPaste,
                        PushKeyboardEnhancementFlags(
                            KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                        )
                    );
                    ui.notify(match result {
                        Ok(message) => message,
                        Err(error) => error.to_string(),
                    });
                } else {
                    ui.media.offer_external(playback);
                }
            }
            Ok(None) => {}
            Err(error) => ui.notify(error.to_string()),
        }
        // Block in normal mode, bar while writing; set only when the mode changes.
        let mode = ui.editor.mode();
        if ui.cursor_mode != Some(mode) {
            ui.cursor_mode = Some(mode);
            let _ = execute!(
                std::io::stdout(),
                if mode == Mode::Insert {
                    SetCursorStyle::SteadyBar
                } else {
                    SetCursorStyle::SteadyBlock
                }
            );
        }
        terminal.draw(|frame| {
            // Do not block rendering on database/crypto work or retain an expired
            // previous frame while waiting for its lock.
            if let Ok(app) = shared.try_lock() {
                if ui.selected.is_none() {
                    ui.select(app.state.conversations.keys().next().cloned());
                }
                ui.media_progress
                    .refresh(&app, ui.selected.as_deref(), now());
                let view = View::from_app(&app, &ui.media_progress.values);
                render(frame, &mut ui, Some(&view), command.is_some(), now());
            } else {
                render(frame, &mut ui, None, command.is_some(), now());
            }
        })?;
        for _ in 0..32 {
            if !event::poll(Duration::ZERO)? {
                break;
            }
            match event::read()? {
                Event::Paste(text) => {
                    if ui.palette.is_open() {
                        ui.palette.paste(&text);
                        continue;
                    }
                    let writable = ui.screen == Screen::Chat
                        && matches!(ui.overlay, Overlay::None)
                        && !ui.media.is_open();
                    if writable && !ui.editor.insert_text(&text) {
                        ui.notify("draft limit 16 KiB");
                    }
                }
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if ui.media.is_open() {
                        match key.code {
                            KeyCode::Esc => ui.media.close(),
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                ui.media.close()
                            }
                            KeyCode::Char('O') if ui.media.has_external() => {
                                match ui.media.open_external() {
                                    Ok(()) => ui.notify("opened outside clichat"),
                                    Err(error) => ui.notify(error.to_string()),
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }
                    let control = key.modifiers.contains(KeyModifiers::CONTROL);
                    if !matches!(ui.overlay, Overlay::None) {
                        overlay_key(&mut ui, &mut command, &shared, &transport, key);
                        continue;
                    }
                    if ui.palette.is_open() {
                        let event = palette_key(&mut ui, &shared, key);
                        palette_event(&mut ui, &mut command, &shared, &transport, event);
                        continue;
                    }
                    if ui.screen == Screen::Home {
                        if key.code == KeyCode::Char(':') {
                            ui.palette.open();
                        } else if control && key.code == KeyCode::Char('c') {
                            if let Some(task) = command.take() {
                                task.abort();
                            }
                            return Ok(());
                        }
                        continue;
                    }
                    if key.code == KeyCode::Esc && ui.editor.mode() == Mode::Normal {
                        ui.editor.handle_key(key);
                        ui.screen = Screen::Home;
                        continue;
                    }
                    match key.code {
                        KeyCode::Tab | KeyCode::BackTab => {
                            if let Ok(app) = shared.try_lock() {
                                let ids: Vec<_> = app.state.conversations.keys().cloned().collect();
                                if !ids.is_empty() {
                                    let current = ui
                                        .selected
                                        .as_ref()
                                        .and_then(|id| ids.iter().position(|value| value == id))
                                        .unwrap_or(0);
                                    let next = if key.code == KeyCode::BackTab {
                                        (current + ids.len() - 1) % ids.len()
                                    } else {
                                        (current + 1) % ids.len()
                                    };
                                    ui.select(Some(ids[next].clone()));
                                }
                            }
                            continue;
                        }
                        KeyCode::PageUp => {
                            ui.scroll = ui
                                .scroll
                                .saturating_add(usize::from(ui.body_height / 2).max(1));
                            continue;
                        }
                        KeyCode::PageDown => {
                            ui.scroll = ui
                                .scroll
                                .saturating_sub(usize::from(ui.body_height / 2).max(1));
                            continue;
                        }
                        KeyCode::Enter
                            if command.is_some()
                                && !key
                                    .modifiers
                                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            ui.notify("busy; draft kept");
                            continue;
                        }
                        _ => {}
                    }
                    match ui.editor.handle_key(key) {
                        Action::None => {}
                        Action::Scroll(lines) => {
                            if lines > 0 {
                                ui.scroll = ui.scroll.saturating_sub(lines as usize);
                            } else {
                                ui.scroll = ui.scroll.saturating_add(lines.unsigned_abs() as usize);
                            }
                        }
                        Action::Top => ui.scroll = usize::MAX,
                        Action::Bottom => ui.scroll = 0,
                        Action::Quit => {
                            if let Some(task) = command.take() {
                                task.abort();
                            }
                            return Ok(());
                        }
                        Action::Palette => ui.palette.open(),
                        Action::Submit(input) => {
                            run_line(&mut ui, &mut command, &shared, &transport, input, true);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Feeds a key to the palette with a fresh catalog of chats and contacts.
fn palette_key(ui: &mut Ui, shared: &Shared, key: crossterm::event::KeyEvent) -> PaletteEvent {
    let Ok(app) = shared.try_lock() else {
        let empty = Catalog {
            chats: vec![],
            contacts: vec![],
            proxy: "",
        };
        return ui.palette.key(key, &empty);
    };
    let catalog = Catalog {
        chats: app
            .state
            .conversations
            .values()
            .map(|g| g.name.as_str())
            .collect(),
        contacts: app
            .state
            .contacts
            .values()
            .map(|c| c.name.as_str())
            .collect(),
        proxy: &ui.proxy,
    };
    ui.palette.key(key, &catalog)
}

fn palette_event(
    ui: &mut Ui,
    command: &mut Option<JoinHandle<CommandOutcome>>,
    shared: &Shared,
    transport: &Arc<Transport>,
    event: PaletteEvent,
) {
    match event {
        PaletteEvent::None => {}
        PaletteEvent::Run(line) => run_line(ui, command, shared, transport, line, false),
        PaletteEvent::Files(mode) => open_files(ui, shared, mode),
        PaletteEvent::Preview(source) => preview(ui, source),
    }
}

fn slot(mode: FileMode) -> usize {
    usize::from(mode == FileMode::Open)
}

fn open_files(ui: &mut Ui, shared: &Shared, mode: FileMode) {
    if let Ok(app) = shared.try_lock() {
        ui.me = (app.state.name.clone(), app.id().to_owned());
    }
    let start = ui.last_dir[slot(mode)]
        .clone()
        .filter(|path| path.is_dir())
        .unwrap_or_else(|| files::start_dir(mode));
    ui.overlay = Overlay::Files(Files::new(mode, start, &ui.me.0));
}

/// Decodes and verifies off the UI thread's critical path; nothing is imported yet.
fn preview(ui: &mut Ui, source: String) {
    match crate::preview_invitation(&source) {
        Ok((name, id, token)) => ui.overlay = Overlay::Confirm(Pending { name, id, token }),
        Err(error) => ui.notify(short_error(&error)),
    }
}

fn short_error(error: &anyhow::Error) -> String {
    let text = error.to_string();
    let first = text.lines().next().unwrap_or("error");
    first.chars().take(60).collect()
}

fn overlay_key(
    ui: &mut Ui,
    command: &mut Option<JoinHandle<CommandOutcome>>,
    shared: &Shared,
    transport: &Arc<Transport>,
    key: crossterm::event::KeyEvent,
) {
    match &mut ui.overlay {
        Overlay::None => {}
        Overlay::Shown { .. } => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                ui.overlay = Overlay::None;
            }
        }
        Overlay::Confirm(pending) => match key.code {
            KeyCode::Enter => {
                let line = format!("/add {}", pending.token);
                ui.overlay = Overlay::None;
                run_line(ui, command, shared, transport, line, false);
            }
            KeyCode::Esc => ui.overlay = Overlay::None,
            _ => {}
        },
        Overlay::Files(files) => {
            let mode = files.mode;
            let event = files.key(key);
            if let Some(dir) = files.dir.clone() {
                ui.last_dir[slot(mode)] = Some(dir);
            }
            match event {
                FileEvent::None => {}
                FileEvent::Cancel => ui.overlay = Overlay::None,
                FileEvent::Save(path) => {
                    ui.overlay = Overlay::None;
                    let line = format!("/invite {}", path.display());
                    run_line(ui, command, shared, transport, line, false);
                }
                FileEvent::Open(path) => {
                    ui.overlay = Overlay::None;
                    preview(ui, path.display().to_string());
                }
            }
        }
    }
}

/// Runs one line from the composer, palette or dialogs. Local commands stay local.
fn run_line(
    ui: &mut Ui,
    command: &mut Option<JoinHandle<CommandOutcome>>,
    shared: &Shared,
    transport: &Arc<Transport>,
    line: String,
    restore: bool,
) {
    if ui.local_command(&line) {
        return;
    }
    if command.is_some() {
        ui.notify("busy");
        return;
    }
    *command = Some(spawn_command(
        shared,
        transport,
        ui.selected.clone(),
        line,
        restore,
    ));
}

fn render(frame: &mut Frame, ui: &mut Ui, view: Option<&View<'_>>, busy: bool, time: i64) {
    let screen = frame.area();
    theme::paint_base(frame.buffer_mut(), screen);
    if screen.width < 28 || screen.height < 10 {
        frame.render_widget(
            Paragraph::new("resize").style(Style::default().fg(MUTED)),
            screen,
        );
        ui.effects.clear();
        return;
    }
    let status = visible_status(ui, view);
    match ui.screen {
        Screen::Home => render_home(frame, ui, status.as_deref()),
        Screen::Chat => render_chat(frame, ui, view, status.as_deref(), busy, time),
    }
    if let Some(view) = view {
        ui.proxy = view.proxy.to_owned();
        if ui.me.1 != view.me.1 || ui.me.0 != view.me.0 {
            ui.me = (view.me.0.to_owned(), view.me.1.to_owned());
        }
    }
    render_overlay(frame, ui);
    let catalog = match view {
        Some(view) => Catalog {
            chats: view.groups.iter().map(|group| group.name).collect(),
            contacts: view.contacts.clone(),
            proxy: view.proxy,
        },
        None => Catalog {
            chats: vec![],
            contacts: vec![],
            proxy: "",
        },
    };
    ui.palette
        .render(frame.buffer_mut(), screen, &catalog, ui.motion);
    let file_cursor = match &ui.overlay {
        Overlay::Files(files) => files.cursor(screen),
        _ => None,
    };
    if let Some(position) = ui.palette.cursor(screen, ui.motion).or(file_cursor) {
        frame.set_cursor_position(position);
    }
    let inset = Rect::new(
        screen.x + 2,
        screen.y,
        screen.width.saturating_sub(4),
        screen.height,
    );
    ui.media.render(frame, inset, time);
}

/// Notices and background status fade after a few seconds; the default is blank.
fn visible_status(ui: &mut Ui, view: Option<&View<'_>>) -> Option<String> {
    if let Some(view) = view
        && view.status != ui.status_seen.0
    {
        ui.status_seen = (view.status.to_owned(), Instant::now());
    }
    if let Some((text, at)) = &ui.notice
        && at.elapsed() < Duration::from_secs(12)
    {
        return Some(crate::safe(text));
    }
    let (text, at) = &ui.status_seen;
    (!text.is_empty() && at.elapsed() < Duration::from_secs(8)).then(|| crate::safe(text))
}

fn render_status(frame: &mut Frame, area: Rect, status: Option<&str>) {
    if let Some(text) = status {
        let line = text.lines().next().unwrap_or("");
        frame.render_widget(
            Paragraph::new(line.to_owned()).style(Style::default().fg(MUTED)),
            area,
        );
    }
}

fn render_home(frame: &mut Frame, ui: &mut Ui, status: Option<&str>) {
    let screen = frame.area();
    ui.effects.clear();
    logo::render(frame.buffer_mut(), screen, ui.started.elapsed(), ui.motion);
    let row = screen.bottom().saturating_sub(2);
    let width = screen.width.saturating_sub(4);
    render_status(frame, Rect::new(screen.x + 2, row, width, 1), status);
}

/// Dialogs sit above the screen and below the palette's frost.
fn render_overlay(frame: &mut Frame, ui: &Ui) {
    let screen = frame.area();
    let phase = if ui.motion {
        ui.started.elapsed().as_secs_f32() * 0.09
    } else {
        0.0
    };
    match &ui.overlay {
        Overlay::None => {}
        Overlay::Files(files) => files.render(frame.buffer_mut(), screen, 1.0),
        Overlay::Confirm(pending) => {
            card::render(
                frame.buffer_mut(),
                screen,
                &pending.name,
                &pending.id,
                phase,
            );
        }
        Overlay::Shown { name, id } => {
            card::render(frame.buffer_mut(), screen, name, id, phase);
        }
    }
}

fn render_chat(
    frame: &mut Frame,
    ui: &mut Ui,
    view: Option<&View<'_>>,
    status: Option<&str>,
    busy: bool,
    time: i64,
) {
    let screen = frame.area();
    let area = Rect::new(
        screen.x + 2,
        screen.y + 1,
        screen.width.saturating_sub(4),
        screen.height.saturating_sub(2),
    );
    let draft = wrap_text(
        ui.editor.text(),
        area.width.saturating_sub(6).max(1),
        Some(ui.editor.cursor_byte()),
    );
    let input_height =
        (draft.lines.len().clamp(1, 5) as u16 + 2).min(area.height.saturating_sub(5).max(3));
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
        Constraint::Length(1),
        Constraint::Length(input_height),
    ])
    .split(area);
    render_header(frame, rows[0], ui, view);
    ui.body_height = rows[2].height;
    render_messages(frame, rows[2], ui, view, time);
    render_status(frame, rows[3], status);
    ui.composer = rows[4];
    let phase = if ui.motion {
        ui.started.elapsed().as_secs_f32() * 0.09
    } else {
        0.0
    };
    theme::glass(frame.buffer_mut(), rows[4], 1.0);
    gradient_border(frame.buffer_mut(), rows[4], phase, busy, 1.0);
    let show_cursor = !ui.media.is_open()
        && !ui.palette.is_visible(ui.motion)
        && matches!(ui.overlay, Overlay::None);
    render_editor(frame, rows[4], &ui.editor, &draft, show_cursor);
    ui.effects.render(frame, area, ui.motion);
}

fn render_header(frame: &mut Frame, area: Rect, ui: &Ui, view: Option<&View<'_>>) {
    let Some(view) = view else { return };
    let name = ui
        .selected
        .as_deref()
        .and_then(|id| view.groups.iter().find(|group| group.id == id))
        .map(|group| crate::safe(group.name))
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(name).style(Style::default().fg(MUTED)),
        Rect::new(area.x + 1, area.y, area.width.saturating_sub(12), 1),
    );
    let (dot, color) = if view.online {
        ("●", ACCENT)
    } else {
        ("○", FAINT)
    };
    let mut spans = vec![];
    if view.queued > 0 {
        spans.push(Span::styled(
            format!("{}  ", view.queued),
            Style::default().fg(FAINT),
        ));
    }
    spans.push(Span::styled(dot, Style::default().fg(color)));
    let width: usize = spans.iter().map(Span::width).sum();
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect::new(
            area.right().saturating_sub(width as u16 + 1),
            area.y,
            width as u16,
            1,
        ),
    );
}

fn render_messages(frame: &mut Frame, area: Rect, ui: &mut Ui, view: Option<&View<'_>>, time: i64) {
    ui.effects.begin_frame(time, ui.motion);
    let Some(view) = view else { return };
    let messages: Vec<_> = view
        .messages
        .iter()
        .filter(|message| {
            Some(message.conversation) == ui.selected.as_deref() && message.expires > time
        })
        .collect();
    if messages.is_empty() {
        ui.effects.end_frame();
        return;
    }
    let width = area.width.saturating_sub(4).max(1);
    // This body-layout boundary can accept media cards without changing the
    // composer or retaining message content in the expiry-effect state.
    let wrapped: Vec<_> = messages
        .iter()
        .map(|message| {
            let mut lines = if message.text.is_empty() {
                vec![]
            } else {
                wrap_text(&crate::safe(message.text), width, None).lines
            };
            if let Some(media) = message.media {
                let card = format!(
                    "╭ {}  {}  {}",
                    media_view::kind_label(&media.kind),
                    crate::safe(&media.name),
                    media_view::size_label(media.size)
                );
                lines.extend(wrap_text(&card, width, None).lines);
                let progress = message.progress.min(media.chunks as usize);
                let state = if progress == media.chunks as usize {
                    "ready".to_owned()
                } else if progress == 0 {
                    String::new()
                } else {
                    format!("{progress}/{}", media.chunks)
                };
                let open = format!("/open {}", message.id.chars().take(8).collect::<String>());
                let line = if state.is_empty() {
                    format!("╰ {open}")
                } else {
                    format!("╰ {state}  {open}")
                };
                lines.extend(wrap_text(&line, width, None).lines);
            }
            lines
        })
        .collect();
    let total: usize = wrapped.iter().map(|lines| lines.len() + 2).sum();
    let viewport = usize::from(area.height);
    ui.scroll = ui.scroll.min(total.saturating_sub(viewport));
    let start = total.saturating_sub(viewport).saturating_sub(ui.scroll);
    let padding = viewport.saturating_sub(total);
    let mut position = 0usize;
    for (message, body) in messages.iter().zip(wrapped) {
        let count = body.len() + 2;
        if position + count > start && position < start + viewport {
            let remaining = (message.expires - time).max(0);
            let ttl = if remaining >= 3600 {
                format!("{}h", (remaining + 3599) / 3600)
            } else {
                format!("{}m", (remaining + 59) / 60)
            };
            let mut header = vec![];
            if !message.own {
                header.push(Span::styled(
                    crate::safe(message.sender),
                    Style::default().fg(VIOLET).add_modifier(Modifier::BOLD),
                ));
            }
            let marker = match message.delivery {
                "" => None,
                "cached" => Some("●"),
                _ => Some("○"),
            };
            if let Some(marker) = marker {
                header.push(Span::styled(
                    if message.own {
                        marker.to_owned()
                    } else {
                        format!(" {marker}")
                    },
                    Style::default().fg(FAINT),
                ));
            }
            let mut lines = vec![Line::from(header)];
            lines.extend(
                body.into_iter()
                    .map(|text| Line::from(Span::styled(text, Style::default().fg(TEXT)))),
            );
            lines.push(Line::from(""));
            let clip = start.saturating_sub(position);
            let row = padding + position.saturating_sub(start);
            let height = count.saturating_sub(clip).min(viewport.saturating_sub(row));
            if height > 0 {
                let rect = Rect::new(area.x + 2, area.y + row as u16, width, height as u16);
                frame.render_widget(
                    Paragraph::new(
                        lines
                            .into_iter()
                            .skip(clip)
                            .take(height)
                            .collect::<Vec<_>>(),
                    ),
                    rect,
                );
                let ttl_width = UnicodeWidthStr::width(ttl.as_str()) as u16;
                if clip == 0 {
                    frame.render_widget(
                        Paragraph::new(ttl).style(Style::default().fg(FAINT)),
                        Rect::new(rect.right().saturating_sub(ttl_width), rect.y, ttl_width, 1),
                    );
                }
                if message.own {
                    let shown = height.min(count.saturating_sub(1 + clip));
                    for offset in 0..shown as u16 {
                        frame.buffer_mut()[(area.x, rect.y + offset)]
                            .set_symbol("│")
                            .set_fg(ACCENT);
                    }
                }
                ui.effects
                    .observe(message.conversation, message.id, message.expires, rect);
            }
        }
        position += count;
    }
    if ui.scroll > 0 {
        frame.render_widget(
            Paragraph::new("↑").style(Style::default().fg(FAINT)),
            Rect::new(area.right().saturating_sub(2), area.y, 1, 1),
        );
    }
    ui.effects.end_frame();
}

struct Wrapped {
    lines: Vec<String>,
    cursor: (usize, usize),
}

fn wrap_text(text: &str, width: u16, cursor: Option<usize>) -> Wrapped {
    let width = usize::from(width.max(1));
    let mut lines = vec![String::new()];
    let mut column = 0usize;
    let mut position = (0, 0);
    for (index, grapheme) in text.grapheme_indices(true) {
        if grapheme == "\n" || grapheme == "\r\n" {
            if cursor == Some(index) {
                position = (lines.len() - 1, column.min(width - 1));
            }
            lines.push(String::new());
            column = 0;
            continue;
        }
        let mut rendered = if grapheme == "\t" {
            " ".repeat(4 - column % 4)
        } else {
            grapheme.to_owned()
        };
        let cells = UnicodeWidthStr::width(rendered.as_str());
        if column + cells > width && column > 0 {
            lines.push(String::new());
            column = 0;
            if grapheme == "\t" {
                rendered = " ".repeat(width.min(4));
            }
        }
        if cursor == Some(index) {
            position = (lines.len() - 1, column.min(width - 1));
        }
        column += UnicodeWidthStr::width(rendered.as_str());
        lines.last_mut().unwrap().push_str(&rendered);
    }
    if cursor == Some(text.len()) {
        if column >= width {
            lines.push(String::new());
            column = 0;
        }
        position = (lines.len() - 1, column.min(width - 1));
    }
    Wrapped {
        lines,
        cursor: position,
    }
}

fn render_editor(
    frame: &mut Frame,
    area: Rect,
    editor: &Editor,
    wrapped: &Wrapped,
    show_cursor: bool,
) {
    let inner = Rect::new(
        area.x + 4,
        area.y + 1,
        area.width.saturating_sub(6),
        area.height.saturating_sub(2),
    );
    let prompt = if editor.mode() == Mode::Insert {
        ACCENT
    } else {
        FAINT
    };
    frame.buffer_mut()[(area.x + 2, area.y + 1)]
        .set_symbol("›")
        .set_fg(prompt);
    let first = wrapped
        .cursor
        .0
        .saturating_sub(usize::from(inner.height.saturating_sub(1)));
    let lines: Vec<_> = wrapped
        .lines
        .iter()
        .skip(first)
        .take(inner.height as usize)
        .cloned()
        .map(Line::from)
        .collect();
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(TEXT)),
        inner,
    );
    if show_cursor && inner.width > 0 && inner.height > 0 {
        frame.set_cursor_position((
            inner.x + wrapped.cursor.1.min(inner.width.saturating_sub(1) as usize) as u16,
            inner.y
                + wrapped
                    .cursor
                    .0
                    .saturating_sub(first)
                    .min(inner.height.saturating_sub(1) as usize) as u16,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend, style::Color};

    fn snapshot(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn wraps_unicode_drafts_and_keeps_cursor_inside_viewport() {
        let text = "你好吗\nhello 👩‍💻";
        let wrapped = wrap_text(text, 6, Some(text.len()));
        assert_eq!(wrapped.lines[0], "你好吗");
        assert!(wrapped.cursor.1 < 6);
        assert_eq!(wrapped.lines.concat(), "你好吗hello 👩‍💻");
        assert_eq!(wrap_text("abcdef", 6, Some(6)).cursor, (1, 0));
    }

    fn media(time: i64) -> MediaDescriptor {
        MediaDescriptor {
            id: "a".repeat(64),
            name: "海边的傍晚 · camera original image.png".into(),
            kind: clichat::media::MediaKind::Image,
            size: 1024 * 1024,
            chunks: 16,
            sha256: "b".repeat(64),
            key: vec![0; 32],
            nonce_prefix: vec![0; 16],
            read_token: "c".repeat(64),
            created_at: time - 10,
            expires_at: time + 60,
            sources: vec![],
        }
    }

    fn message<'a>(
        id: &'a str,
        text: &'a str,
        own: bool,
        expires: i64,
        delivery: &'static str,
    ) -> MessageView<'a> {
        MessageView {
            id,
            conversation: "studio",
            text,
            sender: "Mira",
            own,
            expires,
            delivery,
            media: None,
            progress: 0,
        }
    }

    fn view<'a>(messages: Vec<MessageView<'a>>) -> View<'a> {
        View {
            me: ("Alex", "ab"),
            status: "",
            online: true,
            proxy: "off",
            queued: 1,
            groups: vec![ConversationView {
                id: "studio",
                name: "studio",
            }],
            contacts: vec!["Mira", "Alex"],
            messages,
        }
    }

    fn chat_ui() -> Ui {
        let mut ui = Ui {
            motion: false,
            screen: Screen::Chat,
            ..Ui::default()
        };
        ui.select(Some("studio".into()));
        ui
    }

    /// Every visible cell has a solid background. The trailing half of a wide
    /// glyph is skipped: the terminal paints it with the first half's colour.
    fn assert_dark(terminal: &Terminal<TestBackend>) {
        let buffer = terminal.backend().buffer();
        for y in 0..buffer.area.height {
            let mut skip = 0;
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                skip = UnicodeWidthStr::width(cell.symbol()).saturating_sub(1);
                assert!(cell.bg != Color::Reset, "({x},{y}) {:?}", cell.symbol());
            }
        }
    }

    #[test]
    fn home_shows_only_the_wordmark() -> Result<()> {
        let mut terminal = Terminal::new(TestBackend::new(100, 28))?;
        let mut ui = Ui {
            motion: false,
            ..Ui::default()
        };
        let view = view(vec![]);
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
        let text = snapshot(&terminal);
        assert!(text.contains("╭─╴ ╷   ╶┬╴ ╭─╴ ╷ ╷ ╭─╮ ╶┬╴"), "{text}");
        let allowed = "╭╮╰╯─│╴╶╷╵├┤┬┴ \n";
        assert!(text.chars().all(|c| allowed.contains(c)), "{text}");
        assert_dark(&terminal);
        Ok(())
    }

    #[test]
    fn chat_has_no_filler_text_and_hides_expired_content() -> Result<()> {
        let time = 1_800_000_000;
        let view = view(vec![
            message("expired", "EXPIRED_SECRET_MUST_NOT_RENDER", false, time, ""),
            message("first", "A quieter place to talk.", false, time + 7200, ""),
            message(
                "second",
                "喜欢这个简单的界面。",
                true,
                time + 259_180,
                "cached",
            ),
        ]);
        let mut ui = chat_ui();
        ui.editor.insert_text("One more thought…");
        let mut terminal = Terminal::new(TestBackend::new(100, 28))?;
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
        let text = snapshot(&terminal);
        assert!(text.contains("A quieter place to talk."));
        assert!(text.contains("2h") && text.contains("72h"), "{text}");
        assert!(text.contains("Mira") && text.contains("studio"));
        for removed in [
            "EXPIRED_SECRET",
            "private",
            "encrypted",
            "NORMAL",
            "INSERT",
            "Press i",
            "/help",
            "members",
            "queued",
            "cache",
            "p2p",
            "ago",
            "left",
            "you",
            "Tab",
        ] {
            assert!(!text.contains(removed), "{removed}\n{text}");
        }
        assert_dark(&terminal);
        println!("\n{text}\n");
        if let Some(path) = std::env::var_os("CLICHAT_UI_PREVIEW") {
            std::fs::write(path, text)?;
        }
        Ok(())
    }

    #[test]
    fn palette_frosts_chat_and_chat_fits_small_terminals() -> Result<()> {
        let time = 1_800_000_000;
        let media = media(time);
        let mut item = message("1234567890", "A moment from today.", false, time + 60, "");
        item.media = Some(&media);
        item.progress = 7;
        let view = view(vec![item]);
        for (width, height) in [(85, 24), (42, 18), (28, 10)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height))?;
            let mut ui = chat_ui();
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
            if width >= 42 {
                assert!(snapshot(&terminal).contains("/open 12345678"));
            }
            ui.palette.open();
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
            let text = snapshot(&terminal);
            assert!(!text.contains("A moment from today."), "{text}");
            assert!(text.contains(':'));
            assert_dark(&terminal);
        }
        Ok(())
    }

    #[test]
    fn too_small_terminals_only_ask_to_resize() -> Result<()> {
        let mut ui = Ui {
            motion: false,
            ..Ui::default()
        };
        let view = view(vec![]);
        let mut tiny = Terminal::new(TestBackend::new(20, 6))?;
        tiny.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
        assert!(snapshot(&tiny).contains("resize"));
        Ok(())
    }

    #[test]
    fn file_manager_and_cards_fit_every_terminal_size() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("bob.invite"), "x")?;
        std::fs::create_dir(root.path().join("文档 folder"))?;
        let view = view(vec![]);
        let id = "ab".repeat(32);
        for (width, height) in [(100, 40), (85, 24), (42, 18), (28, 10)] {
            for mode in [FileMode::Save, FileMode::Open] {
                let mut ui = Ui {
                    motion: false,
                    ..Ui::default()
                };
                ui.overlay = Overlay::Files(Files::new(mode, root.path().to_path_buf(), "Alex"));
                let mut terminal = Terminal::new(TestBackend::new(width, height))?;
                terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
                assert_dark(&terminal);
                if width >= 85 {
                    // The test buffer pads wide glyphs with a blank cell; ignore spaces.
                    let text: String = snapshot(&terminal)
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    assert!(
                        text.contains("bob.invite") && text.contains("文档folder/"),
                        "{text}"
                    );
                    assert_eq!(
                        text.contains("Alex.invite"),
                        mode == FileMode::Save,
                        "{text}"
                    );
                }
            }
            let mut ui = Ui {
                motion: false,
                overlay: Overlay::Confirm(Pending {
                    name: "Bob".into(),
                    id: id.clone(),
                    token: String::new(),
                }),
                ..Ui::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height))?;
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
            assert_dark(&terminal);
            if height >= 24 {
                let text = snapshot(&terminal);
                assert!(
                    text.contains(&clichat::app::fingerprint_lines(&id)[0]) || height < 24,
                    "{text}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_invitations_never_open_the_confirm_card() {
        let mut ui = Ui::default();
        preview(&mut ui, "clichat1:not-valid".into());
        assert!(matches!(ui.overlay, Overlay::None));
        assert!(ui.notice.is_some());
        preview(&mut ui, "C:\\definitely\\missing\\file.invite".into());
        assert!(matches!(ui.overlay, Overlay::None));
    }
}
