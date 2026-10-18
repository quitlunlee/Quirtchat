//! Small cached pixel surfaces, drawn with two vertical pixels per terminal cell.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PixelFrame {
    width: u16,
    height: u16,
    pixels: Vec<Option<Color>>,
}

impl PixelFrame {
    pub(super) fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            pixels: vec![None; usize::from(width) * usize::from(height)],
        }
    }

    pub(super) fn width(&self) -> u16 {
        self.width
    }
    pub(super) fn height(&self) -> u16 {
        self.height
    }

    pub(super) fn set(&mut self, x: u16, y: u16, color: Color) {
        if x < self.width && y < self.height {
            self.pixels[usize::from(y) * usize::from(self.width) + usize::from(x)] = Some(color);
        }
    }

    pub(super) fn get(&self, x: u16, y: u16) -> Option<Color> {
        if x < self.width && y < self.height {
            self.pixels[usize::from(y) * usize::from(self.width) + usize::from(x)]
        } else {
            None
        }
    }

    /// `rect` anchors the image; clipping never shifts its source coordinates.
    /// Transparent pixels become the requested opaque surface color.
    pub(super) fn render(&self, buffer: &mut Buffer, rect: Rect, background: Color) {
        let target = Rect::new(
            rect.x,
            rect.y,
            rect.width.min(self.width()),
            rect.height.min(self.height().div_ceil(2)),
        );
        let clip = target.intersection(buffer.area);
        for y in clip.top()..clip.bottom() {
            for x in clip.left()..clip.right() {
                let px = x - rect.x;
                let py = (y - rect.y) * 2;
                let upper = self.get(px, py).unwrap_or(background);
                let lower = self.get(px, py + 1).unwrap_or(background);
                let cell = &mut buffer[(x, y)];
                cell.reset();
                if upper == lower && upper == background {
                    cell.set_char(' ')
                        .set_style(Style::default().bg(background));
                } else if upper == lower {
                    cell.set_char('█')
                        .set_style(Style::default().fg(upper).bg(background));
                } else {
                    cell.set_char('▀')
                        .set_style(Style::default().fg(upper).bg(lower));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_without_repositioning_and_preserves_both_pixel_colors() {
        let mut image = PixelFrame::new(4, 3);
        image.set(2, 0, Color::Red);
        image.set(2, 1, Color::Blue);
        image.set(3, 2, Color::Green);
        let mut buffer = Buffer::empty(Rect::new(2, 0, 2, 3));
        image.render(&mut buffer, Rect::new(0, 0, 4, 2), Color::Black);
        assert_eq!(buffer[(2, 0)].symbol(), "▀");
        assert_eq!(buffer[(2, 0)].fg, Color::Red);
        assert_eq!(buffer[(2, 0)].bg, Color::Blue);
        assert_eq!(buffer[(3, 1)].fg, Color::Green);
        assert_eq!(buffer[(3, 1)].bg, Color::Black);
        assert_eq!(buffer[(2, 2)], ratatui::buffer::Cell::default());
    }

    #[test]
    fn transparent_pixels_clear_old_symbols_and_modifiers() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 1, 1));
        buffer[(0, 0)]
            .set_char('x')
            .set_style(Style::default().add_modifier(ratatui::style::Modifier::BOLD));
        PixelFrame::new(1, 2).render(&mut buffer, Rect::new(0, 0, 1, 1), Color::Black);
        assert_eq!(buffer[(0, 0)].symbol(), " ");
        assert!(buffer[(0, 0)].modifier.is_empty());
        assert_eq!(buffer[(0, 0)].bg, Color::Black);
    }
}
