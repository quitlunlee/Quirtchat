//! Solid surfaces and restrained colours shared by every screen.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};

pub(super) const BLACK: Color = Color::Rgb(7, 10, 15);
pub(super) const TEXT: Color = Color::Rgb(230, 233, 239);
pub(super) const MUTED: Color = Color::Rgb(139, 147, 161);
pub(super) const FAINT: Color = Color::Rgb(75, 84, 99);
pub(super) const ACCENT: Color = Color::Rgb(111, 207, 207);
pub(super) const VIOLET: Color = Color::Rgb(185, 163, 244);
pub(super) const PANEL: Color = Color::Rgb(15, 19, 26);
pub(super) const BORDER: Color = Color::Rgb(103, 113, 129);

pub(super) fn mix(from: Color, to: Color, t: f32) -> Color {
    let (Color::Rgb(a, b, c), Color::Rgb(x, y, z)) = (from, to) else {
        return to;
    };
    let t = t.clamp(0.0, 1.0);
    let lerp = |p: u8, q: u8| (f32::from(p) + (f32::from(q) - f32::from(p)) * t).round() as u8;
    Color::Rgb(lerp(a, x), lerp(b, y), lerp(c, z))
}

fn fill(buffer: &mut Buffer, rect: Rect, background: Color) {
    let rect = rect.intersection(buffer.area);
    for y in rect.top()..rect.bottom() {
        for x in rect.left()..rect.right() {
            buffer[(x, y)]
                .set_symbol(" ")
                .set_style(Style::default().fg(TEXT).bg(background));
        }
    }
}

pub(super) fn paint_base(buffer: &mut Buffer, area: Rect) {
    fill(buffer, area, BLACK);
}

/// An opaque, uniform surface: the old alpha argument is deliberately ignored.
pub(super) fn glass(buffer: &mut Buffer, rect: Rect, _alpha: f32) {
    fill(buffer, rect, PANEL);
}
pub(super) fn glass_plain(buffer: &mut Buffer, rect: Rect, _alpha: f32) {
    fill(buffer, rect, PANEL);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ColorDepth {
    TrueColor,
    Ansi256,
    Ansi16,
    Mono,
}

/// Inspect once when creating the UI, rather than probing the terminal per frame.
pub(super) fn detect_color_depth() -> ColorDepth {
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorDepth::Mono;
    }
    let term = std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let colorterm = std::env::var("COLORTERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if term == "dumb" {
        ColorDepth::Mono
    } else if colorterm.contains("truecolor")
        || colorterm.contains("24bit")
        || term.contains("direct")
        || std::env::var_os("WT_SESSION").is_some()
    {
        ColorDepth::TrueColor
    } else if term.contains("256color") {
        ColorDepth::Ansi256
    } else {
        ColorDepth::Ansi16
    }
}

const ANSI: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (128, 0, 0),
    (0, 128, 0),
    (128, 128, 0),
    (0, 0, 128),
    (128, 0, 128),
    (0, 128, 128),
    (192, 192, 192),
    (128, 128, 128),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (0, 0, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
];

fn indexed_rgb(index: u8) -> (u8, u8, u8) {
    if index < 16 {
        ANSI[usize::from(index)]
    } else if index >= 232 {
        let level = 8 + (index - 232) * 10;
        (level, level, level)
    } else {
        let index = index - 16;
        let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
        (level(index / 36), level(index / 6 % 6), level(index % 6))
    }
}

fn nearest(rgb: (u8, u8, u8), range: std::ops::Range<u16>) -> u8 {
    range
        .min_by_key(|index| {
            let candidate = indexed_rgb(*index as u8);
            let dr = i32::from(rgb.0) - i32::from(candidate.0);
            let dg = i32::from(rgb.1) - i32::from(candidate.1);
            let db = i32::from(rgb.2) - i32::from(candidate.2);
            dr * dr + dg * dg + db * db
        })
        .unwrap_or(0) as u8
}

fn reduced(color: Color, depth: ColorDepth) -> Color {
    let rgb = match color {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Indexed(index) => indexed_rgb(index),
        _ => return color,
    };
    match depth {
        ColorDepth::TrueColor => color,
        ColorDepth::Ansi256 => Color::Indexed(nearest(rgb, 16..256)),
        ColorDepth::Ansi16 => Color::Indexed(nearest(rgb, 0..16)),
        ColorDepth::Mono => {
            if u16::from(rgb.0) + u16::from(rgb.1) + u16::from(rgb.2) < 180 {
                Color::Black
            } else {
                Color::Gray
            }
        }
    }
}

/// Apply after drawing so that text, avatars and animations share the fallback.
pub(super) fn adapt_colors(buffer: &mut Buffer, depth: ColorDepth) {
    if depth == ColorDepth::TrueColor {
        return;
    }
    let mut cache = std::collections::HashMap::new();
    for cell in &mut buffer.content {
        cell.fg = *cache
            .entry(cell.fg)
            .or_insert_with(|| reduced(cell.fg, depth));
        cell.bg = *cache
            .entry(cell.bg)
            .or_insert_with(|| reduced(cell.bg, depth));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn surfaces_are_uniform_opaque_and_clipped() {
        let area = Rect::new(3, 4, 8, 6);
        let mut first = Buffer::empty(area);
        let mut second = first.clone();
        glass(&mut first, Rect::new(0, 0, 40, 40), 0.1);
        glass_plain(&mut second, area, 1.0);
        assert_eq!(first, second);
        assert!(
            first
                .content
                .iter()
                .all(|c| c.symbol() == " " && c.bg == PANEL)
        );
    }
    #[test]
    fn colour_fallback_never_leaks_rgb() {
        for depth in [ColorDepth::Ansi256, ColorDepth::Ansi16, ColorDepth::Mono] {
            let mut buffer = Buffer::empty(Rect::new(0, 0, 2, 1));
            paint_base(&mut buffer, Rect::new(0, 0, 2, 1));
            buffer[(1, 0)].set_fg(ACCENT);
            adapt_colors(&mut buffer, depth);
            assert!(
                buffer
                    .content
                    .iter()
                    .all(|c| !matches!(c.fg, Color::Rgb(..)) && !matches!(c.bg, Color::Rgb(..)))
            );
            assert_ne!(buffer[(1, 0)].fg, buffer[(1, 0)].bg);
        }
    }
}
