//! Randomart identity card: glass pane sized to the 17x9 art, with a graceful fallback
//! for small terminals. Colours follow how often the walk visited each cell.

use super::{
    effects::gradient_border,
    theme::{ACCENT, FAINT, MUTED, TEXT, VIOLET, glass, mix},
};
use clichat::app::{ART_HEIGHT, ART_WIDTH, fingerprint_lines, randomart, randomart_heat};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Art columns plus padding and the border on each side.
pub(super) const CARD_WIDTH: u16 = ART_WIDTH as u16 + 8;
const FULL_HEIGHT: u16 = ART_HEIGHT as u16 + 9;
const ART_ONLY_HEIGHT: u16 = ART_HEIGHT as u16 + 4;

/// What fits: the art with name and fingerprint, the art alone, or one short line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Detail {
    Full,
    ArtOnly,
    Line,
}

pub(super) fn detail_for(area: Rect) -> Detail {
    if area.width >= CARD_WIDTH && area.height >= FULL_HEIGHT + 2 {
        Detail::Full
    } else if area.width >= CARD_WIDTH && area.height >= ART_ONLY_HEIGHT + 2 {
        Detail::ArtOnly
    } else {
        Detail::Line
    }
}

pub(super) fn card_rect(area: Rect, detail: Detail) -> Rect {
    let (width, height) = match detail {
        Detail::Full => (CARD_WIDTH, FULL_HEIGHT),
        Detail::ArtOnly => (CARD_WIDTH, ART_ONLY_HEIGHT),
        Detail::Line => (area.width.saturating_sub(4).clamp(8, 40), 3),
    };
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    )
}

fn heat(count: u8) -> Color {
    let t = (f32::from(count) / 6.0).min(1.0);
    if t < 0.5 {
        mix(FAINT, ACCENT, t * 2.0)
    } else {
        mix(ACCENT, VIOLET, (t - 0.5) * 2.0)
    }
}

fn put(buffer: &mut Buffer, x: u16, y: u16, text: &str, color: Color) {
    if x >= buffer.area.right() || y >= buffer.area.bottom() {
        return;
    }
    let bg = buffer[(x, y)].bg;
    let room = usize::from(buffer.area.right() - x);
    buffer.set_stringn(x, y, text, room, Style::default().fg(color).bg(bg));
}

fn clip(text: &str, room: usize) -> String {
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

/// Draws the card for `id`. `name` is clipped to the card, never wrapped.
pub(super) fn render(buffer: &mut Buffer, area: Rect, name: &str, id: &str, phase: f32) {
    let detail = detail_for(area);
    let rect = card_rect(area, detail);
    glass(buffer, rect, 1.0);
    gradient_border(buffer, rect, phase, false, 1.0);
    let inner = rect.width.saturating_sub(4);
    if detail == Detail::Line {
        let hex = fingerprint_lines(id);
        let short = format!("{} {}", hex[0], hex[1]);
        let line = clip(&short, usize::from(inner));
        put(buffer, rect.x + 2, rect.y + 1, &line, MUTED);
        return;
    }
    let label = clip(name, usize::from(inner).saturating_sub(2));
    let label_width = UnicodeWidthStr::width(label.as_str()) as u16;
    let title_x = rect.x + 2 + inner.saturating_sub(label_width + 2) / 2;
    put(buffer, title_x, rect.y, &format!(" {label} "), TEXT);
    let art = randomart(id);
    let counts = randomart_heat(id);
    for (y, row) in art.iter().enumerate() {
        for (x, glyph) in row.chars().enumerate() {
            let color = match glyph {
                'S' | 'E' => TEXT,
                ' ' => FAINT,
                _ => heat(counts[y][x]),
            };
            let (px, py) = (rect.x + 4 + x as u16, rect.y + 2 + y as u16);
            put(buffer, px, py, &glyph.to_string(), color);
        }
    }
    if detail == Detail::Full {
        let base = rect.y + 3 + ART_HEIGHT as u16;
        for (index, line) in fingerprint_lines(id).iter().enumerate() {
            let cells = UnicodeWidthStr::width(line.as_str()) as u16;
            let x = rect.x + 2 + inner.saturating_sub(cells) / 2;
            put(buffer, x, base + index as u16, line, MUTED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(buffer: &Buffer) -> String {
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
    fn card_fits_the_art_exactly_and_degrades_in_order() {
        assert_eq!(CARD_WIDTH, 25);
        assert_eq!(detail_for(Rect::new(0, 0, 85, 30)), Detail::Full);
        assert_eq!(
            detail_for(Rect::new(0, 0, 85, FULL_HEIGHT + 2)),
            Detail::Full
        );
        assert_eq!(
            detail_for(Rect::new(0, 0, 85, FULL_HEIGHT + 1)),
            Detail::ArtOnly
        );
        assert_eq!(
            detail_for(Rect::new(0, 0, 85, ART_ONLY_HEIGHT + 2)),
            Detail::ArtOnly
        );
        assert_eq!(
            detail_for(Rect::new(0, 0, 85, ART_ONLY_HEIGHT + 1)),
            Detail::Line
        );
        assert_eq!(detail_for(Rect::new(0, 0, 42, 14)), Detail::Line);
        assert_eq!(detail_for(Rect::new(0, 0, 24, 40)), Detail::Line);
    }

    #[test]
    fn full_card_shows_art_name_and_fingerprint_inside_its_frame() {
        let id = "ab".repeat(32);
        let area = Rect::new(0, 0, 60, 30);
        let mut buffer = Buffer::empty(area);
        render(&mut buffer, area, "Alex", &id, 0.0);
        let drawn = text(&buffer);
        assert!(drawn.contains("Alex"));
        assert!(drawn.contains(&fingerprint_lines(&id)[0]));
        let rect = card_rect(area, Detail::Full);
        let row = randomart(&id)[3].clone();
        let drawn_row: String = (0..ART_WIDTH as u16)
            .map(|x| buffer[(rect.x + 4 + x, rect.y + 2 + 3)].symbol())
            .collect();
        assert_eq!(drawn_row, row);
        for y in 0..area.height {
            for x in 0..area.width {
                let inside = x >= rect.x && x < rect.right() && y >= rect.y && y < rect.bottom();
                if !inside {
                    assert_eq!(buffer[(x, y)].symbol(), " ");
                }
            }
        }
    }

    #[test]
    fn small_terminals_never_overflow() {
        let id = "ab".repeat(32);
        for (w, h) in [(85, 24), (42, 18), (28, 10), (12, 6)] {
            let area = Rect::new(0, 0, w, h);
            let mut buffer = Buffer::empty(area);
            render(
                &mut buffer,
                area,
                "A very long contact name indeed",
                &id,
                0.0,
            );
        }
    }
}
