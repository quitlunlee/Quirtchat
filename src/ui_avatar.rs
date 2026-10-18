//! Compact 5x5 identicons derived from the same identity bytes as profile randomart.

use super::theme::BLACK;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use sha2::{Digest, Sha256};

pub(super) const WIDTH: u16 = 5;
pub(super) const HEIGHT: u16 = 3;

fn pixels(identity: &str) -> ([[bool; 5]; 5], Color) {
    // app::fingerprint and app::randomart deliberately hash the canonical public
    // identity string. Do not substitute the local contact alias here.
    let digest = Sha256::digest(identity.as_bytes());
    let mut grid = [[false; 5]; 5];
    for (y, row) in grid.iter_mut().enumerate() {
        for x in 0..3 {
            let bit = y * 3 + x;
            let on = digest[bit / 8] & (1 << (bit % 8)) != 0;
            row[x] = on;
            row[4 - x] = on;
        }
    }
    // Preserve a recognisable mark even for the all-clear 15-bit pattern.
    if grid.iter().flatten().all(|on| !on) {
        grid[2][2] = true;
    }
    let color = Color::Rgb(
        96 + digest[16] % 144,
        96 + digest[17] % 144,
        96 + digest[18] % 144,
    );
    (grid, color)
}

pub(super) fn rows(identity: &str) -> Vec<Line<'static>> {
    let (grid, color) = pixels(identity);
    (0..usize::from(HEIGHT))
        .map(|row| {
            let spans: Vec<_> = (0..usize::from(WIDTH))
                .map(|column| {
                    let top = grid[row * 2][column];
                    let bottom = row * 2 + 1 < 5 && grid[row * 2 + 1][column];
                    let symbol = match (top, bottom) {
                        (true, true) => "█",
                        (true, false) => "▀",
                        (false, true) => "▄",
                        _ => " ",
                    };
                    Span::styled(symbol, Style::default().fg(color).bg(BLACK))
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identities_are_stable_symmetric_and_use_public_identity_hash() {
        let identity = "identity-public-key-123";
        let (grid, color) = pixels(identity);
        assert_eq!(pixels(identity), (grid, color));
        assert_ne!(pixels("another-key"), (grid, color));
        assert!(grid.iter().all(|row| row.iter().eq(row.iter().rev())));
        let digest = Sha256::digest(identity.as_bytes());
        assert_eq!(grid[0][0], digest[0] & 1 != 0);
        assert_eq!(
            color,
            Color::Rgb(
                96 + digest[16] % 144,
                96 + digest[17] % 144,
                96 + digest[18] % 144
            )
        );
    }
    #[test]
    fn half_blocks_pack_five_pixels_into_three_text_rows() {
        let lines = rows("identity");
        assert_eq!(lines.len(), usize::from(HEIGHT));
        assert!(lines.iter().all(|line| line.width() == usize::from(WIDTH)));
        assert!(
            lines[2]
                .spans
                .iter()
                .all(|span| matches!(span.content.as_ref(), "▀" | " "))
        );
    }
    #[test]
    fn avatar_clips_without_touching_surroundings() {
        use ratatui::{
            buffer::Buffer,
            layout::Rect,
            widgets::{Paragraph, Widget},
        };
        let area = Rect::new(2, 3, 10, 6);
        let mut buffer = Buffer::empty(area);
        Paragraph::new(rows("identity")).render(Rect::new(2, 3, 3, 2), &mut buffer);
        assert_eq!(buffer[(6, 4)].symbol(), " ");
        assert_eq!(buffer[(4, 5)].symbol(), " ");
    }
}
