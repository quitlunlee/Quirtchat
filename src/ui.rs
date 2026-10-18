//! Message bodies are borrowed only for the current frame, never cached by the UI.

#[path = "ui_avatar.rs"]
mod avatar;
#[path = "ui_cursor.rs"]
mod cursor;
#[path = "editor.rs"]
mod editor;
#[path = "ui_effects.rs"]
mod effects;
#[path = "ui_files.rs"]
mod files;
#[path = "ui_forms.rs"]
mod forms;
#[path = "ui_logo.rs"]
mod logo;
#[path = "ui_mascot.rs"]
mod mascot;
#[path = "ui_palette.rs"]
mod palette;
#[path = "ui_pixels.rs"]
mod pixels;
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
use forms::{FormAction, FormKind, FormState, FormValues};
use palette::{Catalog, Palette, PaletteEvent, Target};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    group: bool,
}
struct MessageView<'a> {
    id: &'a str,
    conversation: &'a str,
    text: &'a str,
    sender: &'a str,
    identity: &'a str,
    created: i64,
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
    proxy: String,
    queued: usize,
    groups: Vec<ConversationView<'a>>,
    contacts: Vec<Target<'a>>,
    messages: Vec<MessageView<'a>>,
    live_ids: BTreeSet<&'a str>,
}

fn proxy_label(value: &str) -> String {
    let Ok(url) = url::Url::parse(value) else {
        return "configured".into();
    };
    let Some(host) = url.host_str() else {
        return "configured".into();
    };
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
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
            proxy: app
                .state
                .proxy
                .as_deref()
                .map_or_else(|| "off".into(), proxy_label),
            queued: app.state.outbox.len(),
            groups: app
                .state
                .conversations
                .values()
                .map(|group| ConversationView {
                    id: &group.id,
                    name: if group.server.is_none() && group.members.len() == 2 {
                        group
                            .members
                            .iter()
                            .find(|id| id.as_str() != app.id())
                            .map_or(group.name.as_str(), |id| app.contact_name(id))
                    } else {
                        &group.name
                    },
                    group: group.server.is_some() || group.members.len() != 2,
                })
                .collect(),
            contacts: app
                .state
                .contacts
                .values()
                .map(|contact| Target {
                    id: &contact.id,
                    name: app.contact_name(&contact.id),
                })
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
                        sender: if own {
                            &app.state.name
                        } else {
                            app.contact_name(&message.sender)
                        },
                        identity: &message.sender,
                        created: message.created_at,
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
            live_ids: app
                .state
                .messages
                .iter()
                .map(|message| message.id.as_str())
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
    Form(FormState),
}

type ReadAnchor = Option<(String, usize)>;
type SavedDraft = (Editor, usize, ReadAnchor);

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
    media: MediaView,
    media_progress: ProgressCache,
    notice: Option<(String, Instant)>,
    started: Instant,
    drafts: BTreeMap<String, SavedDraft>,
    pending_invite: Option<String>,
    pending_sends: BTreeMap<String, String>,
    visible_messages: Vec<VisibleMessage>,
    gaps: Vec<RemovalGap>,
    anchor: Option<(String, usize)>,
    cat_started: Instant,
    cat_leaving: bool,
    last_mode: Mode,
    quit: bool,
    color_depth: theme::ColorDepth,
}

struct VisibleMessage {
    id: String,
    conversation: String,
    index: usize,
    height: usize,
    expires: i64,
    header: bool,
    date: bool,
}
struct RemovalGap {
    id: String,
    index: usize,
    height: usize,
    at: Instant,
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
            media: MediaView::default(),
            media_progress: ProgressCache::default(),
            notice: None,
            started: Instant::now(),
            drafts: BTreeMap::new(),
            pending_invite: None,
            pending_sends: BTreeMap::new(),
            visible_messages: vec![],
            gaps: vec![],
            anchor: None,
            cat_started: Instant::now(),
            cat_leaving: false,
            last_mode: Mode::Normal,
            quit: false,
            color_depth: theme::detect_color_depth(),
        }
    }
}

impl Ui {
    fn select(&mut self, selected: Option<String>) {
        if self.selected != selected {
            if let Some(id) = self.selected.take() {
                self.drafts.insert(
                    id,
                    (
                        std::mem::take(&mut self.editor),
                        self.scroll,
                        self.anchor.take(),
                    ),
                );
            }
            self.selected = selected;
            let (mut editor, scroll, anchor) = self
                .selected
                .as_ref()
                .and_then(|id| self.drafts.remove(id))
                .unwrap_or_default();
            editor.handle_key(crossterm::event::KeyEvent::new(
                KeyCode::Esc,
                KeyModifiers::NONE,
            ));
            self.editor = editor;
            self.scroll = scroll;
            self.effects.clear();
            self.visible_messages.clear();
            self.gaps.clear();
            self.anchor = anchor;
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
    fn restore_draft(&mut self, chat: Option<String>, text: &str) {
        let editor = if chat == self.selected {
            &mut self.editor
        } else if let Some(id) = chat {
            &mut self.drafts.entry(id).or_default().0
        } else {
            return;
        };
        if editor.text().is_empty() {
            editor.insert_text(text);
        } else {
            editor.insert_text(&format!("\n{text}"));
        }
    }
}

struct TerminalFeatures;
impl Drop for TerminalFeatures {
    fn drop(&mut self) {
        let _ = execute!(
            std::io::stdout(),
            DisableBracketedPaste,
            PopKeyboardEnhancementFlags
        );
        ratatui::restore();
    }
}

pub async fn run(shared: Shared, transport: Arc<Transport>) -> Result<()> {
    let mut terminal = ratatui::init();
    let _features = TerminalFeatures;
    // Bracketed paste stays literal; Ctrl+S submits and Enter adds a newline.
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
    /// A committed message ID; delivery state determines when its burst may play.
    sent: Option<String>,
    completed: Option<Completed>,
}

enum Completed {
    Contact(String),
    Form,
    Export,
    Join,
    Chat,
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
        let exported = !restore && input.split_whitespace().next() == Some("/invite");
        if !restore && input.split_whitespace().next() == Some("/open") {
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
                sent: None,
                completed: None,
            };
        }
        let mut sent = None;
        let result = if restore {
            match before.as_deref() {
                Some(id) => {
                    let synced = crate::sync_hosted_before_send(&shared, &transport, id).await;
                    synced
                        .and_then(|()| {
                            shared
                                .lock()
                                .unwrap()
                                .atomic(|app| app.send(id, input.clone()))
                        })
                        .map(|id| {
                            sent = Some(id);
                            false
                        })
                        .map_err(|error| error.to_string())
                }
                None => Err("choose a chat first".into()),
            }
        } else if let Some(path) = input.strip_prefix("/attach ") {
            let result: Result<String> = async {
                let id = before
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("choose a chat first"))?;
                let path = path.trim().trim_matches('"');
                anyhow::ensure!(!path.is_empty(), "file required");
                crate::sync_hosted_before_send(&shared, &transport, id).await?;
                clichat::app::send_media(&shared, id, std::path::PathBuf::from(path), String::new())
                    .await
            }
            .await;
            result
                .map(|id| {
                    sent = Some(id);
                    false
                })
                .map_err(|error| error.to_string())
        } else {
            crate::ui_command(&shared, &transport, &mut after, input.clone())
                .await
                .map_err(|error| error.to_string())
        };
        CommandOutcome {
            before,
            after,
            input,
            result,
            media: None,
            restore,
            sent,
            completed: if exported {
                Some(Completed::Export)
            } else {
                None
            },
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
    let mut interval = tokio::time::interval(Duration::from_millis(67));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if ui.quit {
            if let Some(task) = command.take() {
                task.abort();
                let _ = task.await;
            }
            return Ok(());
        }
        if command.as_ref().is_some_and(JoinHandle::is_finished) {
            match command.take().unwrap().await {
                Ok(outcome) => match outcome.result {
                    Ok(true) => return Ok(()),
                    Ok(false) => {
                        let chosen = outcome.after != outcome.before && outcome.after.is_some();
                        if ui.selected == outcome.before {
                            ui.select(outcome.after.clone());
                        }
                        if chosen || outcome.input.starts_with("/dm ") {
                            ui.screen = Screen::Chat;
                        }
                        if let Some(id) = outcome.sent {
                            if ui.selected == outcome.before {
                                ui.scroll = 0;
                                ui.anchor = None;
                            }
                            if let Some(chat) = outcome.before {
                                ui.pending_sends.insert(id, chat);
                            }
                        }
                        match outcome.completed {
                            Some(Completed::Contact(id)) => {
                                ui.overlay = Overlay::None;
                                ui.pending_invite = None;
                                ui.palette.resume_dm(Some(&id));
                            }
                            Some(Completed::Export) => {
                                ui.overlay = Overlay::None;
                                ui.palette.resume_profile();
                                ui.notify("invite saved");
                            }
                            Some(Completed::Form) => {
                                ui.overlay = Overlay::None;
                                if chosen {
                                    ui.palette.close();
                                } else {
                                    ui.palette.resume_settings();
                                }
                            }
                            Some(Completed::Join) => {
                                ui.overlay = Overlay::None;
                                ui.palette.resume_gc();
                            }
                            Some(Completed::Chat) => {
                                ui.screen = Screen::Chat;
                                ui.palette.close();
                            }
                            None => {}
                        }
                        if let Some(message) = outcome.media {
                            ui.media.request(message);
                        }
                    }
                    Err(error) => {
                        if let Overlay::Form(form) = &mut ui.overlay {
                            form.set_error(error.clone());
                        }
                        ui.notify(error);
                        if outcome.restore {
                            ui.restore_draft(outcome.before, &outcome.input);
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
        terminal.draw(|frame| {
            // Do not block rendering on database/crypto work or retain an expired
            // previous frame while waiting for its lock.
            if let Ok(app) = shared.try_lock() {
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
                    if let Overlay::Form(form) = &mut ui.overlay {
                        if command.is_none() {
                            form.paste(&text);
                        }
                    } else if let Overlay::Files(files) = &mut ui.overlay {
                        files.paste(&text);
                    } else if ui.palette.is_open() {
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
                            KeyCode::Char('O') | KeyCode::Enter if ui.media.has_external() => {
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
                            request_quit(&mut ui, &shared, command.is_some(), false);
                        }
                        continue;
                    }
                    if key.code == KeyCode::Esc && ui.editor.mode() == Mode::Normal {
                        ui.editor.handle_key(key);
                        ui.screen = Screen::Home;
                        continue;
                    }
                    match key.code {
                        KeyCode::Tab | KeyCode::BackTab if ui.editor.mode() == Mode::Normal => {
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
                            ui.anchor = None;
                            ui.scroll = ui
                                .scroll
                                .saturating_add(usize::from(ui.body_height / 2).max(1));
                            continue;
                        }
                        KeyCode::PageDown => {
                            ui.anchor = None;
                            ui.scroll = ui
                                .scroll
                                .saturating_sub(usize::from(ui.body_height / 2).max(1));
                            continue;
                        }
                        KeyCode::Char('s' | 'S') if command.is_some() && control => {
                            ui.notify("busy; draft kept");
                            continue;
                        }
                        _ => {}
                    }
                    match ui.editor.handle_key(key) {
                        Action::None => {}
                        Action::Scroll(lines) => {
                            ui.anchor = None;
                            if lines > 0 {
                                ui.scroll = ui.scroll.saturating_sub(lines as usize);
                            } else {
                                ui.scroll = ui.scroll.saturating_add(lines.unsigned_abs() as usize);
                            }
                        }
                        Action::Top => {
                            ui.scroll = usize::MAX;
                            ui.anchor = None;
                        }
                        Action::Bottom => {
                            ui.scroll = 0;
                            ui.anchor = None;
                        }
                        Action::Quit => request_quit(&mut ui, &shared, command.is_some(), false),
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
        return PaletteEvent::None;
    };
    let catalog = Catalog {
        groups: app
            .state
            .conversations
            .values()
            .filter(|g| g.server.is_some() || g.members.len() != 2)
            .map(|g| Target {
                id: &g.id,
                name: &g.name,
            })
            .collect(),
        contacts: app
            .state
            .contacts
            .values()
            .map(|c| Target {
                id: &c.id,
                name: app.contact_name(&c.id),
            })
            .collect(),
        proxy: &ui.proxy,
        me: &app.state.name,
        me_id: app.id(),
        motion: ui.motion,
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
        PaletteEvent::SelectContact(id) => {
            if command.is_some() {
                ui.notify("busy; try again shortly");
                return;
            }
            let before = ui.selected.clone();
            let shared = shared.clone();
            let transport = transport.clone();
            *command = Some(tokio::spawn(async move {
                let result = crate::open_direct_id(&shared, &transport, id).await;
                let (result, after) = match result {
                    Ok(id) => (Ok(false), Some(id)),
                    Err(error) => (Err(error.to_string()), before.clone()),
                };
                CommandOutcome {
                    before,
                    after,
                    input: String::new(),
                    result,
                    media: None,
                    restore: false,
                    sent: None,
                    completed: Some(Completed::Chat),
                }
            }));
        }
        PaletteEvent::SelectConversation(id) => {
            ui.select(Some(id));
            ui.screen = Screen::Chat;
        }
        PaletteEvent::OpenCreateGroup => {
            ui.overlay = Overlay::Form(FormState::new(FormKind::CreateGroup))
        }
        PaletteEvent::OpenJoinGroup => {
            ui.overlay = Overlay::Form(FormState::new(FormKind::JoinGroup))
        }
        PaletteEvent::OpenMailboxSettings => {
            let current = shared.try_lock().ok().and_then(|app| {
                app.state
                    .personal_mailbox
                    .as_ref()
                    .map(|mailbox| mailbox.node.clone())
            });
            ui.overlay = Overlay::Form(FormState::new(FormKind::Mailbox { current }));
        }
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
        Ok((name, id, token)) => {
            ui.pending_invite = Some(token);
            ui.overlay = Overlay::Form(FormState::new(FormKind::Remark { name, id }));
        }
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
        Overlay::Form(form) => {
            if command.is_some() {
                if key.code == KeyCode::Esc {
                    if let Some(task) = command.take() {
                        task.abort();
                    }
                    form.set_error("Stopped waiting; any saved changes are kept. Review the current settings before retrying.".into());
                }
                return;
            }
            match form.key(key) {
                FormAction::None => {}
                FormAction::Cancel => {
                    let kind = form.kind().clone();
                    ui.overlay = Overlay::None;
                    match kind {
                        FormKind::Remark { .. } => {
                            ui.pending_invite = None;
                            ui.palette.resume_dm(None);
                        }
                        FormKind::CreateGroup | FormKind::JoinGroup => ui.palette.resume_gc(),
                        FormKind::Mailbox { .. } => ui.palette.resume_settings(),
                        FormKind::Quit => {}
                    }
                }
                FormAction::Submit(FormValues::Quit) => ui.quit = true,
                FormAction::Submit(values) => {
                    *command = Some(spawn_form(
                        shared,
                        transport,
                        ui.selected.clone(),
                        values,
                        ui.pending_invite.clone(),
                    ));
                }
            }
        }
        Overlay::Files(files) => {
            let mode = files.mode;
            let event = files.key(key);
            if let Some(dir) = files.dir.clone() {
                ui.last_dir[slot(mode)] = Some(dir);
            }
            match event {
                FileEvent::None => {}
                FileEvent::Cancel => {
                    ui.overlay = Overlay::None;
                    if mode == FileMode::Save {
                        ui.palette.resume_profile();
                    } else {
                        ui.palette.resume_dm(None);
                    }
                }
                FileEvent::Save(path) => {
                    ui.overlay = Overlay::None;
                    let line = format!("/invite {}", path.display());
                    run_line(ui, command, shared, transport, line, false);
                }
                FileEvent::Open(path) => {
                    match crate::preview_invitation(&path.display().to_string()) {
                        Ok((name, id, token)) => {
                            ui.pending_invite = Some(token);
                            ui.overlay =
                                Overlay::Form(FormState::new(FormKind::Remark { name, id }));
                        }
                        Err(error) => files.error = Some(short_error(&error)),
                    }
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
    if !restore && matches!(line.as_str(), "/q" | "/q!" | "/quit" | "/exit") {
        request_quit(ui, shared, command.is_some(), line == "/q!");
        return;
    }
    if !restore && line == "/send" {
        if command.is_some() {
            ui.notify("busy; draft kept");
            return;
        }
        if ui.screen != Screen::Chat {
            ui.notify("choose a chat first");
            return;
        }
        if let Action::Submit(text) = ui.editor.submit() {
            run_line(ui, command, shared, transport, text, true);
        }
        return;
    }
    if !restore && ui.local_command(&line) {
        return;
    }
    if command.is_some() {
        if restore {
            ui.restore_draft(ui.selected.clone(), &line);
        }
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

fn request_quit(ui: &mut Ui, shared: &Shared, busy: bool, force: bool) {
    let transfers = shared.try_lock().map_or(true, |app| {
        !app.state.media_uploads.is_empty() || !app.state.media_downloads.is_empty()
    });
    let drafts = !ui.editor.text().is_empty()
        || ui
            .drafts
            .values()
            .any(|(editor, _, _)| !editor.text().is_empty());
    if !force && (busy || transfers || drafts) {
        ui.overlay = Overlay::Form(FormState::new(FormKind::Quit));
    } else {
        ui.quit = true;
    }
}

fn spawn_form(
    shared: &Shared,
    transport: &Arc<Transport>,
    before: Option<String>,
    values: FormValues,
    token: Option<String>,
) -> JoinHandle<CommandOutcome> {
    let shared = shared.clone();
    let transport = transport.clone();
    tokio::spawn(async move {
        let mut after = before.clone();
        let result: Result<Completed> = async {
            match values {
                FormValues::Remark { remark } => {
                    let invitation = crate::read_invitation(token.as_deref().ok_or_else(|| anyhow::anyhow!("invitation missing"))?)?;
                    let id = shared.lock().unwrap().atomic(|app| app.import_contact_named(invitation, &remark))?;
                    shared.lock().unwrap().status = "friend added".into();
                    Ok(Completed::Contact(id))
                }
                FormValues::CreateGroup { name, server, members } => {
                    let invitation = crate::service_cli::read_server_invitation(&server)?;
                    let members = {
                        let app = shared.lock().unwrap();
                        members.iter().map(|name| app.resolve_contact_name_exact(name)).collect::<Result<Vec<_>>>()?
                    };
                    for id in &members { crate::acquire_key_package(&shared, &transport, id).await?; }
                    let id = shared.lock().unwrap().atomic(|app| app.create_hosted_group(name, members, invitation))?;
                    after = Some(id);
                    Ok(Completed::Form)
                }
                FormValues::JoinGroup { server } => {
                    let ticket = crate::service_cli::read_server_ticket(&server)?;
                    shared.lock().unwrap().atomic(|app| crate::service_cli::trust_server(app, ticket))?;
                    shared.lock().unwrap().status = "server saved; background invitation sync enabled (the group owner must invite your identity)".into();
                    clichat::app::group_delivery_tick(&shared, &transport).await?;
                    Ok(Completed::Join)
                }
                FormValues::MailboxAttach { server } => {
                    let invitation = crate::service_cli::read_server_invitation(&server)?;
                    clichat::app::attach_personal_mailbox(&shared, &transport, invitation).await?;
                    shared.lock().unwrap().status = "personal mailbox bound and enabled".into();
                    Ok(Completed::Form)
                }
                FormValues::MailboxDetach => {
                    shared.lock().unwrap().atomic(App::detach_personal_mailbox)?;
                    shared.lock().unwrap().status = "personal mailbox detached; old cached messages will still be collected".into();
                    Ok(Completed::Form)
                }
                FormValues::Quit => unreachable!(),
            }
        }.await;
        let (result, completed) = match result {
            Ok(done) => (Ok(false), Some(done)),
            Err(error) => (Err(error.to_string()), None),
        };
        CommandOutcome {
            before,
            after,
            input: String::new(),
            result,
            media: None,
            restore: false,
            sent: None,
            completed,
        }
    })
}

fn render(frame: &mut Frame, ui: &mut Ui, view: Option<&View<'_>>, busy: bool, time: i64) {
    let screen = frame.area();
    theme::paint_base(frame.buffer_mut(), screen);
    if screen.width < 12 || screen.height < 4 {
        frame.render_widget(
            Paragraph::new("resize").style(Style::default().fg(MUTED)),
            screen,
        );
        ui.effects.clear();
        return;
    }
    let status = visible_status(ui, view);
    match ui.screen {
        Screen::Home => {
            settle_sends(ui, view, false);
            render_home(frame, ui, status.as_deref());
        }
        Screen::Chat => render_chat(frame, ui, view, status.as_deref(), busy, time),
    }
    if let Some(view) = view {
        ui.proxy = view.proxy.to_owned();
        if ui.me.1 != view.me.1 || ui.me.0 != view.me.0 {
            ui.me = (view.me.0.to_owned(), view.me.1.to_owned());
        }
    }
    let catalog = match view {
        Some(view) => Catalog {
            groups: view
                .groups
                .iter()
                .filter(|group| group.group)
                .map(|group| Target {
                    id: group.id,
                    name: group.name,
                })
                .collect(),
            contacts: view.contacts.clone(),
            proxy: &view.proxy,
            me: view.me.0,
            me_id: view.me.1,
            motion: ui.motion,
        },
        None => Catalog {
            groups: vec![],
            contacts: vec![],
            proxy: "",
            me: &ui.me.0,
            me_id: &ui.me.1,
            motion: ui.motion,
        },
    };
    if matches!(ui.overlay, Overlay::None) {
        ui.palette
            .render(frame.buffer_mut(), screen, &catalog, ui.motion);
    }
    render_overlay(frame, ui);
    if ui.palette.is_open() || !matches!(ui.overlay, Overlay::None) {
        let border = match &ui.overlay {
            Overlay::Files(_) => Files::rect(screen),
            _ => palette::menu_rect(screen),
        };
        mascot::render(
            frame.buffer_mut(),
            screen,
            border,
            mascot::Kind::Penguin,
            ui.palette.opened_elapsed(),
            ui.motion,
            false,
        );
    }
    let file_cursor = match &ui.overlay {
        Overlay::Files(files) => files.cursor(screen),
        _ => None,
    };
    let palette_cursor = if matches!(ui.overlay, Overlay::None) {
        ui.palette.cursor(screen, ui.motion)
    } else {
        None
    };
    if let Some(position) = palette_cursor.or(file_cursor) {
        cursor::render(frame.buffer_mut(), position, true);
    }
    let inset = Rect::new(
        screen.x + 2,
        screen.y,
        screen.width.saturating_sub(4),
        screen.height,
    );
    ui.media.render(frame, inset, time);
    theme::adapt_colors(frame.buffer_mut(), ui.color_depth);
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

/// Dialogs reuse the same opaque floating surface as the menu.
fn render_overlay(frame: &mut Frame, ui: &Ui) {
    let screen = frame.area();
    match &ui.overlay {
        Overlay::None => {}
        Overlay::Form(form) => form.render(frame, screen),
        Overlay::Files(files) => files.render(frame.buffer_mut(), screen, 1.0),
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
    let input_height = (draft.lines.len().max(1) as u16 + 2)
        .min((area.height / 4).max(3))
        .min(area.height);
    let decoration = if area.height >= 26 && area.width >= 36 {
        6
    } else if area.height >= 22 && area.width >= 30 {
        5
    } else if area.height >= 20 && area.width >= 30 {
        4
    } else {
        0
    };
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
        Constraint::Length(1),
        Constraint::Length(decoration),
        Constraint::Length(input_height),
    ])
    .split(area);
    render_header(frame, rows[0], ui, view);
    ui.body_height = rows[2].height;
    render_messages(frame, rows[2], ui, view, time);
    render_status(frame, rows[3], status);
    ui.composer = rows[5];
    let phase = if ui.motion {
        ui.started.elapsed().as_secs_f32() * 0.09
    } else {
        0.0
    };
    theme::glass(frame.buffer_mut(), rows[5], 1.0);
    gradient_border(frame.buffer_mut(), rows[5], phase, busy, 1.0);
    let show_cursor = !ui.media.is_open()
        && !ui.palette.is_visible(ui.motion)
        && matches!(ui.overlay, Overlay::None);
    render_editor(frame, rows[5], &ui.editor, &draft, show_cursor);
    let mode = ui.editor.mode();
    if mode != ui.last_mode {
        ui.cat_started = Instant::now();
        ui.cat_leaving = false;
        ui.last_mode = mode;
    }
    settle_sends(
        ui,
        view,
        matches!(ui.overlay, Overlay::None) && !ui.palette.is_open(),
    );
    if rows[4].height >= 4
        && (mode == Mode::Insert
            || (ui.cat_leaving && ui.cat_started.elapsed() < Duration::from_millis(450)))
    {
        mascot::render(
            frame.buffer_mut(),
            rows[4],
            rows[5],
            mascot::Kind::Cat,
            ui.cat_started.elapsed(),
            ui.motion,
            ui.cat_leaving,
        );
    }
    ui.effects.render(frame, area, ui.motion);
}

fn settle_sends(ui: &mut Ui, view: Option<&View<'_>>, visible: bool) {
    if let Some(view) = view {
        ui.pending_sends.retain(|id, chat| {
            let Some(message) = view.messages.iter().find(|message| message.id == id) else {
                return view.live_ids.contains(id.as_str());
            };
            if message.delivery == "queued" {
                return true;
            }
            if visible && Some(chat.as_str()) == ui.selected.as_deref() {
                ui.effects.send_burst(ui.composer, ui.motion);
                if ui.editor.mode() == Mode::Normal {
                    ui.cat_started = Instant::now();
                    ui.cat_leaving = true;
                }
            }
            false
        });
    }
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
    let Some(view) = view else { return };
    ui.effects.begin_frame(time, ui.motion);
    ui.gaps
        .retain(|gap| ui.motion && gap.at.elapsed() < Duration::from_millis(400));
    // Only actual application removals trigger a burst. RPC acknowledgements and
    // scrolling are unrelated. The retained layout contains IDs and dimensions only.
    let prior_layout: BTreeMap<_, _> = ui
        .visible_messages
        .iter()
        .map(|item| (item.id.clone(), (item.header, item.date)))
        .collect();
    let mut expiring = vec![];
    for previous in std::mem::take(&mut ui.visible_messages) {
        if !view.live_ids.contains(previous.id.as_str()) {
            if ui
                .effects
                .removed(&previous.conversation, &previous.id, ui.motion)
                .is_some()
            {
                ui.gaps.push(RemovalGap {
                    id: previous.id.clone(),
                    index: previous.index,
                    height: previous.height,
                    at: Instant::now(),
                });
            }
        } else if previous.expires <= time {
            // Hide expired plaintext immediately, but keep its blank visible slot
            // until the app's next purge confirms the actual removal.
            expiring.push(previous);
        }
    }
    let messages: Vec<_> = view
        .messages
        .iter()
        .filter(|message| {
            Some(message.conversation) == ui.selected.as_deref() && message.expires > time
        })
        .collect();
    let avatar_width = if area.width >= 34 { 7 } else { 0 };
    let width = area.width.saturating_sub(avatar_width).max(1);
    // (message, lines, avatar starts here). No message text survives this frame.
    let mut items: Vec<(Option<&MessageView<'_>>, Vec<Line<'_>>, bool, String)> = vec![];
    for (index, message) in messages.iter().enumerate() {
        let previous = index.checked_sub(1).and_then(|i| messages.get(i));
        let mut same_day = previous
            .is_some_and(|p| p.created.div_euclid(86400) == message.created.div_euclid(86400));
        let mut grouped = same_day
            && previous.is_some_and(|p| {
                p.identity == message.identity
                    && message.created.saturating_sub(p.created) <= 300
                    && p.delivery.is_empty()
                    && message.delivery.is_empty()
            });
        if (!ui.gaps.is_empty() || !expiring.is_empty())
            && let Some((header, date)) = prior_layout.get(message.id)
        {
            grouped = !header;
            same_day = !date;
        }
        let mut lines = vec![];
        if !same_day {
            lines.push(Line::styled(
                date_label(message.created),
                Style::default().fg(FAINT),
            ));
        }
        if !grouped {
            let seconds = message.created.rem_euclid(86400);
            let author = crate::safe(message.sender)
                .chars()
                .take(48)
                .collect::<String>();
            let delivery = match message.delivery {
                "queued" => " · queued",
                "cached" => " · cached",
                _ => "",
            };
            lines.push(Line::from(vec![
                Span::styled(
                    author,
                    Style::default()
                        .fg(if message.own { ACCENT } else { VIOLET })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  {:02}:{:02} UTC{}",
                        seconds / 3600,
                        seconds / 60 % 60,
                        delivery
                    ),
                    Style::default().fg(FAINT),
                ),
            ]));
        }
        for text in wrap_text(&crate::safe(message.text), width, None).lines {
            lines.push(Line::styled(text, Style::default().fg(TEXT)));
        }
        if let Some(media) = message.media {
            let title = format!(
                "{}  {}  {}",
                media_view::kind_label(&media.kind),
                crate::safe(&media.name),
                media_view::size_label(media.size)
            );
            for text in wrap_text(&title, width, None).lines {
                lines.push(Line::styled(text, Style::default().fg(MUTED)));
            }
            let progress = message.progress.min(media.chunks as usize);
            let state = if progress == media.chunks as usize {
                "ready".into()
            } else if progress > 0 {
                format!("{progress}/{}", media.chunks)
            } else {
                String::new()
            };
            lines.push(Line::styled(
                format!(
                    "#{}  {state}",
                    message.id.chars().take(8).collect::<String>()
                ),
                Style::default().fg(ACCENT),
            ));
        }
        if !grouped && avatar_width > 0 {
            while lines.len() < 3 + usize::from(!same_day) {
                lines.push(Line::from(""));
            }
        }
        lines.push(Line::from(""));
        items.push((Some(*message), lines, !grouped, message.id.to_owned()));
    }
    let mut gaps: Vec<_> = ui.gaps.iter().collect();
    gaps.sort_by_key(|gap| gap.index);
    for gap in gaps {
        items.insert(
            gap.index.min(items.len()),
            (
                None,
                vec![Line::from(""); gap.height],
                false,
                gap.id.clone(),
            ),
        );
    }
    for pending in &expiring {
        items.insert(
            pending.index.min(items.len()),
            (
                None,
                vec![Line::from(""); pending.height],
                false,
                pending.id.clone(),
            ),
        );
    }
    let total = items
        .iter()
        .map(|(_, lines, _, _)| lines.len())
        .sum::<usize>();
    let viewport = usize::from(area.height);
    ui.scroll = ui.scroll.min(total.saturating_sub(viewport));
    let mut start = total.saturating_sub(viewport).saturating_sub(ui.scroll);
    if ui.scroll > 0
        && let Some((id, offset)) = &ui.anchor
    {
        let mut position = 0;
        for (_, lines, _, item_id) in &items {
            if item_id == id {
                start = (position + offset).min(total.saturating_sub(viewport));
                break;
            }
            position += lines.len();
        }
        ui.scroll = total.saturating_sub(viewport).saturating_sub(start);
    }
    let padding = viewport.saturating_sub(total);
    let mut position = 0usize;
    ui.anchor = None;
    for (index, (message, lines, show_avatar, id)) in items.into_iter().enumerate() {
        let count = lines.len();
        if position + count > start && position < start + viewport {
            let clip = start.saturating_sub(position);
            let row = padding + position.saturating_sub(start);
            let height = count.saturating_sub(clip).min(viewport.saturating_sub(row));
            if ui.anchor.is_none() && ui.scroll > 0 {
                ui.anchor = Some((id.clone(), clip));
            }
            if height > 0
                && let Some(message) = message
            {
                let rect = Rect::new(area.x, area.y + row as u16, area.width, height as u16);
                let has_date = lines
                    .first()
                    .is_some_and(|line| line.to_string() == date_label(message.created));
                let avatar_top = usize::from(has_date);
                if show_avatar && avatar_width > 0 {
                    let avatar_lines = avatar::rows(message.identity);
                    for (i, line) in avatar_lines.into_iter().enumerate() {
                        let at = avatar_top + i;
                        if at >= clip && at - clip < height {
                            frame.render_widget(
                                Paragraph::new(line),
                                Rect::new(rect.x, rect.y + (at - clip) as u16, 5, 1),
                            );
                        }
                    }
                }
                frame.render_widget(
                    Paragraph::new(
                        lines
                            .into_iter()
                            .skip(clip)
                            .take(height)
                            .collect::<Vec<_>>(),
                    ),
                    Rect::new(rect.x + avatar_width, rect.y, width, height as u16),
                );
                ui.effects
                    .observe(message.conversation, message.id, message.expires, rect);
                ui.visible_messages.push(VisibleMessage {
                    id,
                    conversation: message.conversation.into(),
                    index,
                    height: count,
                    expires: message.expires,
                    header: show_avatar,
                    date: has_date,
                });
            } else if height > 0
                && let Some(pending) = expiring.iter().find(|pending| pending.id == id)
            {
                let rect = Rect::new(area.x, area.y + row as u16, area.width, height as u16);
                ui.effects
                    .observe(&pending.conversation, &pending.id, pending.expires, rect);
                ui.visible_messages.push(VisibleMessage {
                    id,
                    conversation: pending.conversation.clone(),
                    index,
                    height: count,
                    expires: pending.expires,
                    header: pending.header,
                    date: pending.date,
                });
            }
        }
        position += count;
    }
    if ui.scroll > 0 && area.width > 0 && area.height > 0 {
        frame.render_widget(
            Paragraph::new("↑").style(Style::default().fg(FAINT)),
            Rect::new(area.right() - 1, area.y, 1, 1),
        );
    }
    ui.effects.end_frame();
}

/// Gregorian date from the message's UTC day, independent of OS timezone APIs.
fn date_label(timestamp: i64) -> String {
    let z = timestamp.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
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
    if area.width < 7 || area.height < 3 {
        return;
    }
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
        let position = (
            inner.x + wrapped.cursor.1.min(inner.width.saturating_sub(1) as usize) as u16,
            inner.y
                + wrapped
                    .cursor
                    .0
                    .saturating_sub(first)
                    .min(inner.height.saturating_sub(1) as usize) as u16,
        );
        cursor::render(frame.buffer_mut(), position, editor.mode() == Mode::Insert);
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

    fn export_snapshot(terminal: &Terminal<TestBackend>, name: &str) {
        let Some(directory) = std::env::var_os("CLICHAT_UI_SNAPSHOTS") else {
            return;
        };
        let buffer = terminal.backend().buffer();
        let cells: Vec<_> = buffer
            .content
            .iter()
            .map(|cell| {
                let rgb = |color| match color {
                    Color::Rgb(r, g, b) => [r, g, b],
                    _ => [7, 10, 15],
                };
                serde_json::json!({"text": cell.symbol(), "fg": rgb(cell.fg), "bg": rgb(cell.bg),
                "underline": cell.modifier.contains(Modifier::UNDERLINED)})
            })
            .collect();
        let path = std::path::PathBuf::from(directory).join(format!("review-{name}.json"));
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "width": buffer.area.width, "height": buffer.area.height, "cells": cells
            }))
            .unwrap(),
        )
        .unwrap();
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
            identity: if own { "ab" } else { "cd" },
            created: expires - 259200,
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
            proxy: "off".into(),
            queued: 1,
            groups: vec![ConversationView {
                id: "studio",
                name: "studio",
                group: true,
            }],
            contacts: vec![
                Target {
                    id: "cd",
                    name: "Mira",
                },
                Target {
                    id: "ab",
                    name: "Alex",
                },
            ],
            live_ids: messages.iter().map(|message| message.id).collect(),
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
    fn home_shows_logo_and_earth_without_menu_labels() -> Result<()> {
        let mut terminal = Terminal::new(TestBackend::new(100, 28))?;
        let mut ui = Ui {
            motion: false,
            color_depth: theme::ColorDepth::TrueColor,
            ..Ui::default()
        };
        let view = view(vec![]);
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
        export_snapshot(&terminal, "home");
        let text = snapshot(&terminal);
        assert!(!text.trim().is_empty());
        for label in ["私聊", "设置", "NORMAL", "INSERT"] {
            assert!(!text.contains(label));
        }
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
        ui.color_depth = theme::ColorDepth::TrueColor;
        ui.editor
            .handle_key(event::KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
        ui.editor.insert_text("One more thought…");
        let mut terminal = Terminal::new(TestBackend::new(100, 28))?;
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
        let text = snapshot(&terminal);
        assert!(text.contains("A quieter place to talk."));
        assert!(text.contains("UTC"), "{text}");
        assert!(text.contains("Mira") && text.contains("studio"));
        for removed in [
            "EXPIRED_SECRET",
            "private",
            "encrypted",
            "Press i",
            "/help",
            "members",
            "p2p",
            "ago",
            "left",
            "you",
            "Tab",
            "NORMAL",
            "INSERT",
        ] {
            assert!(!text.contains(removed), "{removed}\n{text}");
        }
        assert_dark(&terminal);
        export_snapshot(&terminal, "chat");
        println!("\n{text}\n");
        if let Some(path) = std::env::var_os("CLICHAT_UI_PREVIEW") {
            std::fs::write(path, text)?;
        }
        Ok(())
    }

    #[test]
    fn text_inputs_keep_the_terminal_cursor_hidden() -> Result<()> {
        let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
        let mut ui = chat_ui();
        let view = view(vec![]);
        for mode in [Mode::Normal, Mode::Insert] {
            if mode == Mode::Insert {
                ui.editor
                    .handle_key(event::KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
            }
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
            assert!(!terminal.backend().cursor_visible());
        }
        ui.palette.open();
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
        assert!(!terminal.backend().cursor_visible());
        ui.overlay = Overlay::Form(FormState::new(FormKind::CreateGroup));
        terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
        assert!(!terminal.backend().cursor_visible());
        Ok(())
    }

    #[test]
    fn palette_is_opaque_and_chat_fits_small_terminals() -> Result<()> {
        let time = 1_800_000_000;
        let media = media(time);
        let mut item = message("1234567890", "A moment from today.", false, time + 60, "");
        item.media = Some(&media);
        item.progress = 7;
        let view = view(vec![item]);
        for (width, height) in [(85, 24), (42, 18), (28, 10)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height))?;
            let mut ui = chat_ui();
            ui.color_depth = theme::ColorDepth::TrueColor;
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
            if width >= 42 {
                assert!(snapshot(&terminal).contains("#12345678"));
            }
            ui.palette.open();
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, time))?;
            export_snapshot(&terminal, &format!("menu-{width}x{height}"));
            let text = snapshot(&terminal);
            let rect = palette::menu_rect(terminal.backend().buffer().area);
            let buffer = terminal.backend().buffer();
            assert_eq!(
                buffer[(rect.x, rect.y)].bg,
                match ui.color_depth {
                    theme::ColorDepth::TrueColor => theme::PANEL,
                    _ => buffer[(rect.x + 1, rect.y)].bg,
                }
            );
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
        let mut tiny = Terminal::new(TestBackend::new(8, 3))?;
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
                overlay: Overlay::Form(FormState::new(FormKind::Remark {
                    name: "Bob".into(),
                    id: id.clone(),
                })),
                ..Ui::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height))?;
            terminal.draw(|frame| render(frame, &mut ui, Some(&view), false, 1_800_000_000))?;
            assert_dark(&terminal);
            if height >= 24 {
                let text = snapshot(&terminal);
                assert!(text.contains("Bob"), "{text}");
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

    #[test]
    fn chat_switch_preserves_drafts_read_anchor_and_failed_send_origin() {
        let mut ui = chat_ui();
        ui.editor.insert_text("draft A :q /motion off");
        ui.scroll = 12;
        ui.anchor = Some(("old-message".into(), 2));
        ui.select(Some("other".into()));
        assert!(ui.editor.text().is_empty());
        ui.editor.insert_text("draft B");
        ui.restore_draft(Some("studio".into()), "failed A");
        assert_eq!(ui.editor.text(), "draft B");
        ui.select(Some("studio".into()));
        assert!(ui.editor.text().contains("draft A :q /motion off"));
        assert!(ui.editor.text().contains("failed A"));
        assert_eq!(ui.editor.mode(), Mode::Normal);
        assert_eq!(ui.scroll, 12);
        assert_eq!(ui.anchor, Some(("old-message".into(), 2)));
    }

    #[test]
    fn expired_plaintext_disappears_before_actual_purge_then_animates_once() -> Result<()> {
        let time = 1_800_000_000;
        let initial = view(vec![message(
            "expiring",
            "SECRET_BODY",
            false,
            time + 1,
            "",
        )]);
        let mut ui = chat_ui();
        ui.motion = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
        terminal.draw(|frame| render(frame, &mut ui, Some(&initial), false, time))?;
        assert!(snapshot(&terminal).contains("SECRET_BODY"));
        terminal.draw(|frame| render(frame, &mut ui, Some(&initial), false, time + 1))?;
        assert!(!snapshot(&terminal).contains("SECRET_BODY"));
        assert!(ui.gaps.is_empty());
        assert_eq!(ui.visible_messages.len(), 1);
        let removed = view(vec![]);
        terminal.draw(|frame| render(frame, &mut ui, Some(&removed), false, time + 2))?;
        assert_eq!(ui.gaps.len(), 1);
        assert_eq!(ui.effects.removal_regions().len(), 1);
        terminal.draw(|frame| render(frame, &mut ui, Some(&removed), false, time + 2))?;
        assert_eq!(ui.gaps.len(), 1);
        assert!(!snapshot(&terminal).contains("SECRET_BODY"));
        Ok(())
    }

    #[test]
    fn deleting_group_header_keeps_surviving_text_at_same_row_during_effect() -> Result<()> {
        let time = 1_800_000_000;
        let initial = view(vec![
            message("first", "FIRST", false, time + 60, ""),
            message("second", "SURVIVOR", false, time + 61, ""),
        ]);
        let mut ui = chat_ui();
        ui.motion = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
        terminal.draw(|frame| render(frame, &mut ui, Some(&initial), false, time))?;
        let before = snapshot(&terminal)
            .lines()
            .position(|line| line.contains("SURVIVOR"));
        let remaining = view(vec![message("second", "SURVIVOR", false, time + 61, "")]);
        terminal.draw(|frame| render(frame, &mut ui, Some(&remaining), false, time))?;
        assert_eq!(ui.gaps.len(), 1);
        let after = snapshot(&terminal)
            .lines()
            .position(|line| line.contains("SURVIVOR"));
        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn send_success_is_consumed_offscreen_and_queueing_is_not_success() {
        let mut ui = chat_ui();
        ui.pending_sends.insert("sent".into(), "studio".into());
        let queued = view(vec![message("sent", "text", true, 1_900_000_000, "queued")]);
        settle_sends(&mut ui, Some(&queued), true);
        assert_eq!(ui.pending_sends.len(), 1);
        assert!(!ui.cat_leaving);
        let stored = view(vec![message("sent", "text", true, 1_900_000_000, "cached")]);
        settle_sends(&mut ui, Some(&stored), false);
        assert!(ui.pending_sends.is_empty());
        settle_sends(&mut ui, Some(&stored), true);
        assert!(!ui.cat_leaving);
    }

    #[test]
    fn proxy_labels_hide_credentials_and_dates_are_utc() {
        assert_eq!(
            proxy_label("https://alice:secret@example.org:8443"),
            "https://example.org:8443"
        );
        assert_eq!(date_label(0), "1970-01-01");
        assert_eq!(date_label(-1), "1969-12-31");
    }
}
