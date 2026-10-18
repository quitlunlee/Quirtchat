//! A steady caret painted with the frame, independent of terminal blink settings.

use super::theme::{ACCENT, PANEL};
use ratatui::{buffer::Buffer, style::Modifier};
use unicode_width::UnicodeWidthStr;

pub(super) fn render(buffer: &mut Buffer, position: (u16, u16), insert: bool) {
    let (x, y) = position;
    if !buffer.area.contains(position.into()) {
        return;
    }
    let width = UnicodeWidthStr::width(buffer[position].symbol()).max(1) as u16;
    for column in x..x.saturating_add(width).min(buffer.area.right()) {
        let cell = &mut buffer[(column, y)];
        cell.modifier
            .remove(Modifier::SLOW_BLINK | Modifier::RAPID_BLINK);
        if insert {
            cell.set_fg(ACCENT);
            cell.modifier.insert(Modifier::UNDERLINED);
        } else {
            cell.set_fg(PANEL).set_bg(ACCENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{layout::Rect, style::Style};

    #[test]
    fn caret_preserves_wide_text_and_stays_inside_buffer() {
        let mut buffer = Buffer::empty(Rect::new(3, 2, 6, 1));
        buffer.set_string(3, 2, "猫a", Style::default());
        render(&mut buffer, (3, 2), true);
        assert_eq!(buffer[(3, 2)].symbol(), "猫");
        assert_eq!(buffer[(5, 2)].symbol(), "a");
        assert!(buffer[(3, 2)].modifier.contains(Modifier::UNDERLINED));
        assert!(buffer[(4, 2)].modifier.contains(Modifier::UNDERLINED));
        render(&mut buffer, (8, 2), false);
        assert_eq!(buffer[(8, 2)].bg, ACCENT);
        let before = buffer.clone();
        render(&mut buffer, (9, 2), true);
        assert_eq!(buffer, before);
    }
}
