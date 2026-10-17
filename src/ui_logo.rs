//! Home wordmark: one-time decode on start, then a slow highlight sweep.

use super::{
    effects::noise,
    theme::{ACCENT, BLACK, FAINT, TEXT, VIOLET, mix},
};
use ratatui::{buffer::Buffer, layout::Rect, style::Style};
use std::time::Duration;
use unicode_width::UnicodeWidthStr;

const LETTERS: [[&str; 3]; 7] = [
    ["╭─╴", "│  ", "╰─╴"],
    ["╷  ", "│  ", "╰─╴"],
    ["╶┬╴", " │ ", "╶┴╴"],
    ["╭─╴", "│  ", "╰─╴"],
    ["╷ ╷", "├─┤", "╵ ╵"],
    ["╭─╮", "├─┤", "╵ ╵"],
    ["╶┬╴", " │ ", " ╵ "],
];
const NOISE: [&str; 6] = ["─", "│", "╴", "╶", "╷", "╵"];
const DECODE: Duration = Duration::from_millis(800);
const SWEEP_PERIOD: f32 = 6.0;
const SWEEP_SPAN: f32 = 1.2;
/// Letters are 3 cells wide with one cell between them.
pub(super) const WIDTH: u16 = 27;
const COMPACT: &str = "clichat";

fn cells() -> Vec<(u16, u16, char)> {
    let mut cells = vec![];
    for (index, letter) in LETTERS.iter().enumerate() {
        for (row, line) in letter.iter().enumerate() {
            for (column, glyph) in line.chars().enumerate() {
                if glyph != ' ' {
                    cells.push((index as u16 * 4 + column as u16, row as u16, glyph));
                }
            }
        }
    }
    cells
}

fn compact_cells() -> Vec<(u16, u16, char)> {
    COMPACT
        .chars()
        .enumerate()
        .map(|(index, glyph)| (index as u16, 0, glyph))
        .collect()
}

fn shade(column: f32, span: f32, elapsed: Duration, motion: bool) -> ratatui::style::Color {
    let base = mix(ACCENT, VIOLET, column / span.max(1.0));
    if !motion {
        return base;
    }
    let after = elapsed.saturating_sub(DECODE).as_secs_f32();
    let phase = after % SWEEP_PERIOD;
    if after <= 0.0 || phase > SWEEP_SPAN {
        return base;
    }
    let position = (phase / SWEEP_SPAN) * (span + 8.0) - 4.0;
    let glow = (1.0 - (column - position).abs() / 4.0).max(0.0);
    mix(base, TEXT, glow)
}

/// Draws the wordmark centred slightly above the middle and returns its rectangle.
pub(super) fn render(buffer: &mut Buffer, area: Rect, elapsed: Duration, motion: bool) -> Rect {
    let compact = area.width < WIDTH + 4;
    let (width, height) = if compact {
        (UnicodeWidthStr::width(COMPACT) as u16, 1)
    } else {
        (WIDTH, 3)
    };
    let x = area.x + area.width.saturating_sub(width) / 2;
    let lift = area.height / 12;
    let y = area.y + (area.height.saturating_sub(height) / 2).saturating_sub(lift);
    let rect = Rect::new(x, y, width.min(area.width), height);
    let mut glyphs = if compact { compact_cells() } else { cells() };
    // Left-to-right settle order, top to bottom within a column.
    glyphs.sort_by_key(|(x, y, _)| (*x, *y));
    let total = glyphs.len().max(1) as f32;
    for (rank, (x, y, glyph)) in glyphs.into_iter().enumerate() {
        if x >= rect.width {
            continue;
        }
        let settle = DECODE.as_secs_f32() * rank as f32 / total;
        let (symbol, color) = if motion && elapsed.as_secs_f32() < settle {
            let tick = (elapsed.as_millis() / 60) as u64;
            let seed = (u64::from(x) << 8) | u64::from(y) | (tick << 16);
            let pick = noise(seed) as usize % NOISE.len();
            (NOISE[pick].to_owned(), mix(BLACK, FAINT, 0.9))
        } else {
            let color = shade(f32::from(x), f32::from(rect.width), elapsed, motion);
            (glyph.to_string(), color)
        };
        buffer[(rect.x + x, rect.y + y)]
            .set_symbol(&symbol)
            .set_style(Style::default().fg(color).bg(BLACK));
    }
    rect
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn wordmark_settles_into_exact_glyphs_and_matches_width() {
        let area = Rect::new(0, 0, 60, 20);
        let mut buffer = Buffer::empty(area);
        let rect = render(&mut buffer, area, Duration::from_secs(3), true);
        assert_eq!((rect.width, rect.height), (WIDTH, 3));
        for line in 0..3 {
            let joined: Vec<_> = LETTERS.iter().map(|letter| letter[line]).collect();
            let expected = format!("{}{}", " ".repeat(usize::from(rect.x)), joined.join(" "));
            assert_eq!(
                row(&buffer, rect.y + line as u16).trim_end(),
                expected.trim_end()
            );
        }
        for line in LETTERS.iter().flatten() {
            assert_eq!(UnicodeWidthStr::width(*line), 3);
        }
    }

    #[test]
    fn narrow_screens_use_the_compact_name() {
        let area = Rect::new(0, 0, 20, 8);
        let mut buffer = Buffer::empty(area);
        let rect = render(&mut buffer, area, Duration::from_secs(3), false);
        assert_eq!(rect.height, 1);
        assert!(row(&buffer, rect.y).contains(COMPACT));
    }
}
