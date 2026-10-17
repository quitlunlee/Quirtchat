//! Content-free effects: only message IDs, deadlines and rectangles survive a frame.

use super::theme::{ACCENT, BLACK, MUTED, VIOLET, mix};
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

const EXPIRY_LIFETIME: Duration = Duration::from_millis(550);
const SEND_LIFETIME: Duration = Duration::from_millis(600);
const PARTICLE_CAP: usize = 160;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Expiry,
    Send,
}

struct Visible {
    expires: i64,
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
    fn spawn(&mut self, kind: Kind, rect: Rect, seed: u64, wanted: usize) {
        let count = wanted.min(PARTICLE_CAP.saturating_sub(self.used()));
        if count > 0 {
            self.bursts.push(Burst {
                kind,
                rect,
                seed,
                born: Instant::now(),
                count,
            });
        }
    }
    pub(super) fn begin_frame(&mut self, time: i64, motion: bool) {
        self.seen.clear();
        self.bursts
            .retain(|burst| burst.born.elapsed() < burst.lifetime());
        let expired: Vec<_> = self
            .visible
            .iter()
            .filter(|(_, visible)| visible.expires <= time)
            .map(|(key, visible)| (key.clone(), visible.rect))
            .collect();
        for (key, rect) in expired {
            self.visible.remove(&key);
            if motion {
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                let area = usize::from(rect.width) * usize::from(rect.height);
                self.spawn(
                    Kind::Expiry,
                    rect,
                    hasher.finish(),
                    (area / 2).clamp(12, 64),
                );
            }
        }
        if !motion {
            self.bursts.clear();
        }
    }
    /// Particles rise from the composer's top edge after a successful send.
    pub(super) fn send_burst(&mut self, source: Rect, motion: bool) {
        if !motion || source.width < 4 {
            return;
        }
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        let seed = noise(clock ^ (u64::from(source.y) << 32));
        let wanted = 24 + (noise(seed) % 25) as usize;
        self.spawn(Kind::Send, source, seed, wanted);
    }
    pub(super) fn observe(&mut self, conversation: &str, id: &str, expires: i64, rect: Rect) {
        let key = (conversation.to_owned(), id.to_owned());
        self.seen.insert(key.clone());
        self.visible.insert(key, Visible { expires, rect });
    }
    pub(super) fn end_frame(&mut self) {
        self.visible.retain(|key, _| self.seen.contains(key));
    }
    pub(super) fn render(&mut self, frame: &mut Frame, viewport: Rect, motion: bool) {
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
    #[cfg(test)]
    fn particles(&self) -> usize {
        self.used()
    }
}

fn put(buffer: &mut Buffer, viewport: Rect, x: i32, y: i32, symbol: &str, color: Color) {
    if x < i32::from(viewport.x)
        || y < i32::from(viewport.y)
        || x >= i32::from(viewport.right())
        || y >= i32::from(viewport.bottom())
    {
        return;
    }
    buffer[(x as u16, y as u16)]
        .set_symbol(symbol)
        .set_style(Style::default().fg(color));
}

/// Text is already gone; dust lifts off from left to right in a soft wave.
fn expiry_particle(rect: Rect, random: u64, progress: f32) -> (i32, i32, &'static str, Color) {
    let width = u64::from(rect.width.max(1));
    let origin_x = rect.x + (random % width) as u16;
    let origin_y = rect.y + ((random >> 16) % u64::from(rect.height.max(1))) as u16;
    let wave = f32::from(origin_x - rect.x) / width as f32 * 0.4;
    let local = ((progress - wave) / 0.6).clamp(0.0, 1.0);
    let drift = (((random >> 8) % 7) as f32 - 3.0) * local;
    let x = (f32::from(origin_x) + drift).round() as i32;
    let y = (f32::from(origin_y) - 3.0 * local * local).round() as i32;
    let symbol = if local < 0.35 {
        "⠄"
    } else if local < 0.7 {
        "⠂"
    } else {
        "·"
    };
    (x, y, symbol, mix(MUTED, BLACK, local))
}

/// Particles leave the composer's top edge, drift up and converge before fading.
fn send_particle(rect: Rect, random: u64, progress: f32) -> (i32, i32, &'static str, Color) {
    let start = f32::from(rect.x) + (random % u64::from(rect.width.max(1))) as f32;
    let centre = f32::from(rect.x) + f32::from(rect.width) / 2.0;
    let rise = 3.0 + ((random >> 12) % 6) as f32;
    let eased = 1.0 - (1.0 - progress) * (1.0 - progress);
    let x = (start + (centre - start) * eased * 0.6).round() as i32;
    let y = (f32::from(rect.y) - 1.0 - rise * eased).round() as i32;
    let symbol = ["●", "•", "∙", "·"][((progress * 4.0) as usize).min(3)];
    let hue = mix(ACCENT, VIOLET, (progress * 1.6).min(1.0));
    let fade = ((progress - 0.5) * 2.0).clamp(0.0, 1.0);
    (x, y, symbol, mix(hue, BLACK, fade))
}

pub(super) fn noise(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

/// Dims and frosts a region. `level` runs from 0 (untouched) to 1 (fully frosted).
/// Replacement glyphs depend only on the cell position, so they never flicker.
pub(super) fn frost(buffer: &mut Buffer, rect: Rect, level: f32) {
    let rect = rect.intersection(buffer.area);
    let level = level.clamp(0.0, 1.0);
    if level == 0.0 {
        return;
    }
    for y in rect.top()..rect.bottom() {
        for x in rect.left()..rect.right() {
            let random = noise(u64::from(x) << 16 | u64::from(y));
            let cell = &mut buffer[(x, y)];
            let covered = !cell.symbol().trim().is_empty();
            if covered && (random % 100) as f32 / 100.0 < level {
                cell.set_symbol(if random & 0x100 == 0 { "░" } else { "▒" });
            }
            let fg = mix(cell.fg, BLACK, level * 0.7);
            cell.set_fg(fg);
            let bg = mix(cell.bg, BLACK, level * 0.5);
            cell.set_bg(bg);
        }
    }
}

pub(super) fn gradient_border(buffer: &mut Buffer, rect: Rect, phase: f32, busy: bool, alpha: f32) {
    if rect.width < 2 || rect.height < 2 || !buffer.area.contains(rect.as_position()) {
        return;
    }
    let width = u32::from(rect.width);
    let height = u32::from(rect.height);
    let perimeter = (2 * (width + height)) as f32;
    let mut draw = |x: u16, y: u16, symbol: &str, offset: u32| {
        let t = ((offset as f32 / perimeter + phase) * std::f32::consts::TAU).sin() * 0.5 + 0.5;
        let intensity = if busy { 0.7 } else { 1.0 };
        let color = mix(ACCENT, VIOLET, t * 0.8);
        let color = mix(BLACK, color, intensity * alpha);
        buffer[(x, y)].set_symbol(symbol).set_fg(color);
    };
    for offset in 1..rect.width - 1 {
        draw(rect.x + offset, rect.y, "─", u32::from(offset));
        draw(
            rect.x + offset,
            rect.bottom() - 1,
            "─",
            2 * width + height - u32::from(offset),
        );
    }
    for offset in 1..rect.height - 1 {
        draw(
            rect.x,
            rect.y + offset,
            "│",
            2 * width + 2 * height - u32::from(offset),
        );
        draw(
            rect.right() - 1,
            rect.y + offset,
            "│",
            width + u32::from(offset),
        );
    }
    draw(rect.x, rect.y, "╭", 0);
    draw(rect.right() - 1, rect.y, "╮", width);
    draw(rect.x, rect.bottom() - 1, "╰", width + 2 * height);
    draw(rect.right() - 1, rect.bottom() - 1, "╯", width + height);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_tracks_only_metadata_and_respects_motion_toggle() {
        let mut effects = Effects::default();
        effects.begin_frame(10, true);
        effects.observe("group", "message", 11, Rect::new(1, 1, 20, 3));
        effects.end_frame();
        effects.begin_frame(11, true);
        assert!(effects.visible.is_empty());
        assert_eq!(effects.bursts.len(), 1);
        effects.begin_frame(11, false);
        assert!(effects.bursts.is_empty());
    }

    #[test]
    fn send_burst_is_bounded_and_off_without_motion() {
        let mut effects = Effects::default();
        effects.send_burst(Rect::new(2, 20, 60, 3), false);
        assert_eq!(effects.particles(), 0);
        for _ in 0..10 {
            effects.send_burst(Rect::new(2, 20, 60, 3), true);
        }
        assert!((24..=PARTICLE_CAP).contains(&effects.particles()));
        effects.begin_frame(0, false);
        assert_eq!(effects.particles(), 0);
    }

    #[test]
    fn frost_dims_and_replaces_text_deterministically() {
        let area = Rect::new(0, 0, 20, 3);
        let mut first = Buffer::empty(area);
        first.set_string(
            0,
            1,
            "secret secret secret",
            Style::default().fg(Color::Rgb(255, 255, 255)),
        );
        let mut second = first.clone();
        frost(&mut first, area, 1.0);
        frost(&mut second, area, 1.0);
        assert_eq!(first, second);
        let text: String = (0..20).map(|x| first[(x, 1)].symbol()).collect();
        assert!(!text.contains("secret"));
        assert!(first[(0, 1)].fg != Color::Rgb(255, 255, 255));
    }
}
