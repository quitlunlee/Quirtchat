//! Palette and glass material shared by every screen.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};

pub(super) const BLACK: Color = Color::Rgb(0, 0, 0);
pub(super) const TEXT: Color = Color::Rgb(230, 233, 239);
pub(super) const MUTED: Color = Color::Rgb(139, 147, 161);
pub(super) const FAINT: Color = Color::Rgb(75, 84, 99);
pub(super) const ACCENT: Color = Color::Rgb(111, 207, 207);
pub(super) const VIOLET: Color = Color::Rgb(185, 163, 244);
pub(super) const GLASS: Color = Color::Rgb(12, 16, 24);
const HIGHLIGHT: Color = Color::Rgb(58, 68, 86);

pub(super) fn mix(from: Color, to: Color, t: f32) -> Color {
    let (Color::Rgb(a, b, c), Color::Rgb(x, y, z)) = (from, to) else {
        return to;
    };
    let t = t.clamp(0.0, 1.0);
    let lerp = |p: u8, q: u8| (f32::from(p) + (f32::from(q) - f32::from(p)) * t).round() as u8;
    Color::Rgb(lerp(a, x), lerp(b, y), lerp(c, z))
}

/// Fills the whole buffer with the solid black base.
pub(super) fn paint_base(buffer: &mut Buffer, area: Rect) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            buffer[(x, y)]
                .set_symbol(" ")
                .set_style(Style::default().fg(TEXT).bg(BLACK));
        }
    }
}

/// Dark, slightly lifted pane with a bright top edge and a faint dotted texture.
pub(super) fn glass(buffer: &mut Buffer, rect: Rect, alpha: f32) {
    glass_textured(buffer, rect, alpha, true);
}

/// A pane that holds lists or text: the same tint and edge, without the dot texture,
/// so rows of text stay contiguous and easy to read.
pub(super) fn glass_plain(buffer: &mut Buffer, rect: Rect, alpha: f32) {
    glass_textured(buffer, rect, alpha, false);
}

fn glass_textured(buffer: &mut Buffer, rect: Rect, alpha: f32, texture: bool) {
    let rect = rect.intersection(buffer.area);
    let base = mix(BLACK, GLASS, alpha);
    for y in rect.top()..rect.bottom() {
        for x in rect.left()..rect.right() {
            let cell = &mut buffer[(x, y)];
            let dot = texture && (x + 2 * y) % 6 == 0 && y > rect.top();
            cell.set_symbol(if dot { "·" } else { " " }).set_style(
                Style::default()
                    .fg(mix(base, FAINT, if dot { 0.35 * alpha } else { 0.0 }))
                    .bg(base),
            );
        }
    }
    // The border row sits on a brighter strip, like light catching the glass edge.
    if rect.height > 0 {
        let edge = mix(base, HIGHLIGHT, 0.35 * alpha);
        for x in rect.left()..rect.right() {
            buffer[(x, rect.top())].set_bg(edge);
        }
    }
}

pub(super) fn ease_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t) * (1.0 - t) * (1.0 - t)
}
