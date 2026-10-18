//! Content-free effects: only message IDs, deadlines and rectangles survive a frame.

use super::theme::{ACCENT, BLACK, BORDER, MUTED, VIOLET, mix};
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    hash::{DefaultHasher, Hash, Hasher},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use unicode_width::UnicodeWidthStr;

const EXPIRY_LIFETIME: Duration = Duration::from_millis(400);
const SEND_LIFETIME: Duration = Duration::from_millis(300);
const PARTICLE_CAP: usize = 96;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Expiry,
    Send,
}
struct Visible {
    rect: Rect,
}
struct Burst {
    kind: Kind,
    rect: Rect,
    seed: u64,
    born: Instant,
    count: usize,
}
impl Burst {
    fn lifetime(&self) -> Duration {
        match self.kind {
            Kind::Expiry => EXPIRY_LIFETIME,
            Kind::Send => SEND_LIFETIME,
        }
    }
}

#[derive(Default)]
pub(super) struct Effects {
    visible: BTreeMap<(String, String), Visible>,
    seen: BTreeSet<(String, String)>,
    bursts: Vec<Burst>,
}

impl Effects {
    pub(super) fn clear(&mut self) {
        self.visible.clear();
        self.seen.clear();
        self.bursts.clear();
    }
    fn used(&self) -> usize {
        self.bursts.iter().map(|burst| burst.count).sum()
    }
    fn prune(&mut self) {
        self.bursts
            .retain(|burst| burst.born.elapsed() < burst.lifetime());
    }
    fn spawn(&mut self, kind: Kind, rect: Rect, seed: u64, wanted: usize) {
        self.prune();
        let count = wanted.min(PARTICLE_CAP.saturating_sub(self.used()));
        if count > 0 && !rect.is_empty() {
            self.bursts.push(Burst {
                kind,
                rect,
                seed,
                born: Instant::now(),
                count,
            });
        }
    }
    pub(super) fn begin_frame(&mut self, _time: i64, motion: bool) {
        self.seen.clear();
        self.prune();
        if !motion {
            self.bursts.clear();
        }
    }
    /// Call only after the application has really removed this message. A delivery
    /// acknowledgement is not a removal. Off-screen/unknown messages do nothing.
    /// Returns the former visible region, which the layout may reserve until fade-out.
    pub(super) fn removed(&mut self, conversation: &str, id: &str, motion: bool) -> Option<Rect> {
        let key = (conversation.to_owned(), id.to_owned());
        let visible = self.visible.remove(&key)?;
        self.seen.remove(&key);
        if !motion {
            return None;
        }
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let area = usize::from(visible.rect.width) * usize::from(visible.rect.height);
        self.spawn(
            Kind::Expiry,
            visible.rect,
            hasher.finish(),
            (area / 2).clamp(16, 32),
        );
        Some(visible.rect)
    }
    #[cfg(test)]
    pub(super) fn removal_regions(&self) -> Vec<Rect> {
        self.bursts
            .iter()
            .filter(|burst| burst.kind == Kind::Expiry && burst.born.elapsed() < burst.lifetime())
            .map(|burst| burst.rect)
            .collect()
    }
    /// Particles leave the composer only after a confirmed successful send.
    pub(super) fn send_burst(&mut self, source: Rect, motion: bool) {
        if !motion || source.width < 4 {
            return;
        }
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        let seed = noise(clock ^ (u64::from(source.y) << 32));
        self.spawn(Kind::Send, source, seed, 12 + (noise(seed) % 9) as usize);
    }
    pub(super) fn observe(&mut self, conversation: &str, id: &str, _expires: i64, rect: Rect) {
        if rect.is_empty() {
            return;
        }
        let key = (conversation.to_owned(), id.to_owned());
        self.seen.insert(key.clone());
        self.visible.insert(key, Visible { rect });
    }
    pub(super) fn end_frame(&mut self) {
        self.visible.retain(|key, _| self.seen.contains(key));
    }
    pub(super) fn render(&mut self, frame: &mut Frame, viewport: Rect, motion: bool) {
        self.prune();
        if !motion {
            return;
        }
        let buffer = frame.buffer_mut();
        for burst in &self.bursts {
            let progress = burst.born.elapsed().as_secs_f32() / burst.lifetime().as_secs_f32();
            if progress >= 1.0 {
                continue;
            }
            for index in 0..burst.count {
                let random = noise(burst.seed.wrapping_add(index as u64 * 0x9e37));
                let (x, y, symbol, color) = match burst.kind {
                    Kind::Expiry => expiry_particle(burst.rect, random, progress),
                    Kind::Send => send_particle(burst.rect, random, progress),
                };
                put(buffer, viewport, x, y, symbol, color);
            }
        }
    }
}

fn put(buffer: &mut Buffer, viewport: Rect, x: i32, y: i32, symbol: &str, color: Color) {
    let viewport = viewport.intersection(buffer.area);
    if x < i32::from(viewport.x)
        || y < i32::from(viewport.y)
        || x >= i32::from(viewport.right())
        || y >= i32::from(viewport.bottom())
    {
        return;
    }
    // A wide glyph's continuation cell looks blank in a Ratatui buffer. Leave
    // it untouched as well, otherwise particles can split Chinese/emoji text.
    if x > i32::from(buffer.area.x)
        && UnicodeWidthStr::width(buffer[(x as u16 - 1, y as u16)].symbol()) > 1
    {
        return;
    }
    let cell = &mut buffer[(x as u16, y as u16)];
    // Decorations must never replace message text, input, a mascot or a border.
    if !cell.symbol().trim().is_empty() {
        return;
    }
    cell.set_symbol(symbol)
        .set_style(Style::default().fg(color));
}

/// The body is already gone. Only anonymous dust lifts from its former rectangle.
fn expiry_particle(rect: Rect, random: u64, progress: f32) -> (i32, i32, &'static str, Color) {
    let width = u64::from(rect.width.max(1));
    let origin_x = rect.x + (random % width) as u16;
    let origin_y = rect.y + ((random >> 16) % u64::from(rect.height.max(1))) as u16;
    let wave = f32::from(origin_x - rect.x) / width as f32 * 0.25;
    let local = ((progress - wave) / 0.75).clamp(0.0, 1.0);
    let drift = (((random >> 8) % 7) as f32 - 3.0) * local;
    let x = (f32::from(origin_x) + drift).round() as i32;
    let y = (f32::from(origin_y) - 2.0 * local * local).round() as i32;
    let symbol = if local < 0.35 {
        ":"
    } else if local < 0.7 {
        "·"
    } else {
        "."
    };
    (x, y, symbol, mix(MUTED, BLACK, local))
}

/// A small outward spray stays close to the composer's upper edge.
fn send_particle(rect: Rect, random: u64, progress: f32) -> (i32, i32, &'static str, Color) {
    let start = f32::from(rect.x) + (random % u64::from(rect.width.max(1))) as f32;
    let centre = f32::from(rect.x) + f32::from(rect.width) / 2.0;
    let eased = 1.0 - (1.0 - progress) * (1.0 - progress);
    let drift = ((start - centre) / f32::from(rect.width.max(1))) * 5.0;
    let x = (start + drift * eased).round() as i32;
    let y = (f32::from(rect.y) - 1.0 - (1.0 + ((random >> 12) % 3) as f32) * eased).round() as i32;
    let symbol = ["*", "+", "·", "."][((progress * 4.0) as usize).min(3)];
    let hue = mix(ACCENT, VIOLET, (progress * 1.6).min(1.0));
    (x, y, symbol, mix(hue, BLACK, progress))
}

pub(super) fn noise(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

/// All surfaces share this static, single-colour, thin border.
pub(super) fn gradient_border(
    buffer: &mut Buffer,
    rect: Rect,
    _phase: f32,
    _busy: bool,
    _alpha: f32,
) {
    if rect.width < 2 || rect.height < 2 {
        return;
    }
    let mut draw = |x: u16, y: u16, symbol: &str| {
        if buffer.area.contains((x, y).into()) {
            buffer[(x, y)].set_symbol(symbol).set_fg(BORDER);
        }
    };
    for offset in 1..rect.width - 1 {
        draw(rect.x + offset, rect.y, "─");
        draw(rect.x + offset, rect.bottom() - 1, "─");
    }
    for offset in 1..rect.height - 1 {
        draw(rect.x, rect.y + offset, "│");
        draw(rect.right() - 1, rect.y + offset, "│");
    }
    draw(rect.x, rect.y, "╭");
    draw(rect.right() - 1, rect.y, "╮");
    draw(rect.x, rect.bottom() - 1, "╰");
    draw(rect.right() - 1, rect.bottom() - 1, "╯");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_real_removals_animate_once_and_visible_only() {
        let mut effects = Effects::default();
        effects.begin_frame(10, true);
        effects.observe("group", "message", 11, Rect::new(1, 1, 20, 3));
        effects.end_frame();
        effects.begin_frame(12, true);
        assert!(
            effects.bursts.is_empty(),
            "a deadline alone is not an application removal"
        );
        assert!(effects.removed("group", "message", true).is_some());
        assert_eq!(effects.bursts.len(), 1);
        assert!(effects.removed("group", "message", true).is_none());
        assert!(effects.removed("other", "offscreen", true).is_none());
        effects.begin_frame(12, false);
        assert!(effects.bursts.is_empty());
    }
    #[test]
    fn scrolling_away_never_means_deletion() {
        let mut effects = Effects::default();
        effects.observe("group", "message", 99, Rect::new(1, 1, 20, 3));
        effects.begin_frame(10, true);
        effects.end_frame();
        assert!(effects.removed("group", "message", true).is_none());
        assert!(effects.bursts.is_empty());
    }
    #[test]
    fn effects_are_short_bounded_and_disabled_with_reduced_motion() {
        let mut effects = Effects::default();
        effects.send_burst(Rect::new(2, 20, 60, 3), false);
        assert_eq!(effects.used(), 0);
        for _ in 0..10 {
            effects.send_burst(Rect::new(2, 20, 60, 3), true);
        }
        assert!((12..=PARTICLE_CAP).contains(&effects.used()));
        assert_eq!(PARTICLE_CAP, 96);
        assert_eq!(SEND_LIFETIME, Duration::from_millis(300));
        assert_eq!(EXPIRY_LIFETIME, Duration::from_millis(400));
        effects.begin_frame(0, false);
        assert_eq!(effects.used(), 0);
    }
    #[test]
    fn particles_clip_and_leave_existing_text_alone() {
        let area = Rect::new(3, 4, 10, 6);
        let mut buffer = Buffer::empty(area);
        buffer[(4, 5)].set_symbol("猫");
        put(&mut buffer, Rect::new(0, 0, 100, 100), 0, 0, "*", ACCENT);
        put(&mut buffer, area, 4, 5, "*", ACCENT);
        put(&mut buffer, area, 5, 5, "*", ACCENT);
        put(&mut buffer, area, 6, 5, "*", ACCENT);
        assert_eq!(buffer[(4, 5)].symbol(), "猫");
        assert_eq!(buffer[(5, 5)].symbol(), " ");
        assert_eq!(buffer[(6, 5)].symbol(), "*");
    }

    #[test]
    fn particles_render_in_test_backend_and_expire_without_retaining_rows() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(40, 14)).unwrap();
        let mut effects = Effects::default();
        effects.observe("group", "removed", 10, Rect::new(4, 4, 20, 3));
        effects.removed("group", "removed", true);
        effects.send_burst(Rect::new(2, 11, 34, 3), true);
        terminal
            .draw(|frame| {
                let area = frame.area();
                effects.render(frame, area, true);
            })
            .unwrap();
        assert!(
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .any(|cell| cell.symbol() != " ")
        );
        assert_eq!(effects.removal_regions().len(), 1);
        for burst in &mut effects.bursts {
            burst.born = Instant::now() - Duration::from_secs(1);
        }
        effects.begin_frame(11, true);
        assert!(effects.removal_regions().is_empty());
        assert_eq!(effects.used(), 0);
        effects.clear();
        assert!(effects.visible.is_empty());
    }
    #[test]
    fn border_is_static_and_safe_when_partially_outside_buffer() {
        let area = Rect::new(2, 2, 10, 5);
        let mut first = Buffer::empty(area);
        let mut second = first.clone();
        gradient_border(&mut first, Rect::new(0, 0, 20, 4), 0.0, false, 1.0);
        gradient_border(&mut second, Rect::new(0, 0, 20, 4), 0.8, true, 0.1);
        assert_eq!(first, second);
        assert!(
            first
                .content
                .iter()
                .filter(|cell| cell.symbol() != " ")
                .all(|cell| cell.fg == BORDER)
        );
    }
}
