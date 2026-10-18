//! Original low, wide pixel companions, cached as timed animation frames.

use super::{pixels::PixelFrame, theme::PANEL};
use ratatui::{buffer::Buffer, layout::Rect, style::Color};
use std::{
    collections::VecDeque,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

pub(super) const HEIGHT: u16 = 6;
const PIXEL_HEIGHT: u16 = HEIGHT * 2;
const FRAMES: usize = 72;
const FRAME_MILLIS: u128 = 100;
const ENTER: Duration = Duration::from_millis(360);
const LEAVE: Duration = Duration::from_millis(420);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Cat,
    Penguin,
}

type CacheKey = (Kind, u16, u16);
type CachedFrames = Arc<Vec<PixelFrame>>;
static CACHE: LazyLock<Mutex<VecDeque<(CacheKey, CachedFrames)>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

fn dot(image: &mut PixelFrame, x: i32, y: i32, color: Color) {
    if x >= 0 && y >= 0 {
        image.set(x as u16, y as u16, color);
    }
}

fn ellipse(image: &mut PixelFrame, cx: f32, cy: f32, rx: f32, ry: f32, color: Color) {
    for y in (cy - ry).floor() as i32..=(cy + ry).ceil() as i32 {
        for x in (cx - rx).floor() as i32..=(cx + rx).ceil() as i32 {
            if ((x as f32 - cx) / rx).powi(2) + ((y as f32 - cy) / ry).powi(2) <= 1.0 {
                dot(image, x, y, color);
            }
        }
    }
}

fn line(image: &mut PixelFrame, a: (i32, i32), b: (i32, i32), thickness: i32, color: Color) {
    let steps = (b.0 - a.0).abs().max((b.1 - a.1).abs()).max(1);
    for step in 0..=steps {
        let x = a.0 + (b.0 - a.0) * step / steps;
        let y = a.1 + (b.1 - a.1) * step / steps;
        for offset in 0..thickness {
            dot(image, x, y + offset, color);
        }
    }
}

fn cat_sprite(width: u16, phase: usize) -> PixelFrame {
    let mut image = PixelFrame::new(width, PIXEL_HEIGHT);
    let ink = Color::Rgb(59, 43, 58);
    let shadow = Color::Rgb(137, 88, 80);
    let fur = Color::Rgb(220, 159, 112);
    let light = Color::Rgb(252, 201, 150);
    let cream = Color::Rgb(255, 227, 183);
    let pink = Color::Rgb(222, 133, 137);
    let stripe = Color::Rgb(165, 102, 81);
    let eye = Color::Rgb(56, 66, 56);
    let iris = Color::Rgb(156, 203, 139);
    let w = i32::from(width);
    // The reclining body is bounded so the silhouette remains a cat even on
    // very wide terminals. A separate translation explores the whole band.
    let body_end = (w - 13).clamp(26, 65);
    let radius = (body_end - 17) as f32 / 2.0;
    let body_center = 17.0 + radius;
    let breath = if (phase / 18).is_multiple_of(2) {
        0.0
    } else {
        0.5
    };
    let tail_y = [6, 5, 4, 3, 4, 5][phase / 12];
    let tail_end = w - 3;
    let tail_mid = body_end + (tail_end - body_end) * 2 / 3;
    line(&mut image, (body_end - 3, 9), (tail_mid, 9), 3, ink);
    line(&mut image, (tail_mid, 9), (tail_end, tail_y + 1), 3, ink);
    line(
        &mut image,
        (tail_end, tail_y + 1),
        (tail_end - 3, tail_y - 1),
        3,
        ink,
    );
    line(&mut image, (body_end - 3, 9), (tail_mid, 9), 2, fur);
    line(
        &mut image,
        (tail_mid, 9),
        (tail_end - 1, tail_y + 1),
        2,
        fur,
    );
    line(
        &mut image,
        (tail_end - 1, tail_y + 1),
        (tail_end - 3, tail_y),
        1,
        light,
    );
    ellipse(
        &mut image,
        body_center,
        10.0,
        radius + 1.0,
        5.0 + breath,
        ink,
    );
    ellipse(&mut image, body_center, 9.5, radius, 4.0 + breath, shadow);
    ellipse(
        &mut image,
        body_center - 1.0,
        8.7,
        radius - 0.5,
        3.1 + breath,
        fur,
    );
    ellipse(&mut image, body_center - 2.0, 8.0, radius - 2.0, 1.5, light);
    for x in (23..body_end - 2).step_by(7) {
        line(&mut image, (x, 6), (x + 1, 8), 1, stripe);
        dot(&mut image, x + 2, 8, shadow);
    }
    for y in 0..5 {
        line(&mut image, (8, y + 1), (8 + y, y + 1), 1, ink);
        line(&mut image, (23 - y, y + 1), (23, y + 1), 1, ink);
    }
    line(&mut image, (9, 2), (11, 4), 1, pink);
    line(&mut image, (22, 2), (20, 4), 1, pink);
    ellipse(&mut image, 15.5, 7.1, 8.5, 4.6, ink);
    ellipse(&mut image, 15.5, 6.9, 7.5, 3.9, fur);
    ellipse(&mut image, 15.0, 6.0, 6.4, 2.4, light);
    ellipse(&mut image, 15.5, 8.8, 4.5, 2.0, cream);
    for (x, y) in [(14, 3), (14, 4), (16, 3), (17, 3), (17, 4), (8, 6), (23, 6)] {
        dot(&mut image, x, y, stripe);
    }
    let blink = matches!(phase, 31 | 32 | 61);
    let look = if (40..56).contains(&phase) { 1 } else { 0 };
    if blink {
        line(&mut image, (10, 7), (12, 7), 1, eye);
        line(&mut image, (19, 7), (21, 7), 1, eye);
    } else {
        for x in [10, 19] {
            line(&mut image, (x, 6), (x + 2, 6), 2, eye);
            dot(&mut image, x + 1 + look, 6, iris);
            dot(&mut image, x + 1 + look, 7, iris);
            dot(&mut image, x + 1, 6, cream);
        }
    }
    dot(&mut image, 15, 8, pink);
    dot(&mut image, 16, 8, pink);
    dot(&mut image, 15, 9, shadow);
    dot(&mut image, 14, 10, shadow);
    dot(&mut image, 16, 10, shadow);
    for (a, b) in [
        ((4, 7), (8, 8)),
        ((3, 9), (8, 9)),
        ((23, 8), (27, 7)),
        ((23, 9), (28, 9)),
    ] {
        line(&mut image, a, b, 1, cream);
    }
    for x in [9, 21] {
        ellipse(&mut image, x as f32, 11.2, 3.6, 1.6, ink);
        line(&mut image, (x - 2, 11), (x + 2, 11), 1, cream);
        dot(&mut image, x, 11, fur);
    }
    image
}

fn cat(width: u16, phase: usize) -> PixelFrame {
    let sprite = cat_sprite(width.min(58), phase);
    let mut image = PixelFrame::new(width, PIXEL_HEIGHT);
    let travel = width.saturating_sub(sprite.width());
    let cycle = phase as f32 / FRAMES as f32 * std::f32::consts::TAU;
    let offset = ((0.5 - cycle.cos() * 0.5) * f32::from(travel)).round() as u16;
    for y in 0..sprite.height() {
        for x in 0..sprite.width() {
            if let Some(color) = sprite.get(x, y) {
                image.set(x + offset, y, color);
            }
        }
    }
    image
}

fn penguin(width: u16, phase: usize) -> PixelFrame {
    let mut image = PixelFrame::new(width, PIXEL_HEIGHT);
    let ink = Color::Rgb(32, 46, 62);
    let shadow = Color::Rgb(42, 67, 87);
    let blue = Color::Rgb(65, 101, 121);
    let rim = Color::Rgb(116, 169, 184);
    let snow = Color::Rgb(233, 240, 225);
    let white = Color::Rgb(255, 252, 235);
    let cheek = Color::Rgb(239, 173, 138);
    let gold = Color::Rgb(251, 193, 84);
    let beak_shadow = Color::Rgb(214, 125, 56);
    // Translation lets the character explore the full frame without stretching
    // its face; the flippers have a separate, shorter animation cycle.
    let travel = i32::from(width.saturating_sub(34));
    let cycle = phase as f32 / FRAMES as f32 * std::f32::consts::TAU;
    let center = 17 + ((cycle.sin() * 0.5 + 0.5) * travel as f32).round() as i32;
    let wave = [0, 1, 2, 3, 2, 1][(phase / 3) % 6];
    let left_tip = (center - 15, 8 - wave);
    let right_tip = (center + 15, 8 - (3 - wave));
    for (tip, root) in [(left_tip, (center - 6, 9)), (right_tip, (center + 6, 9))] {
        line(&mut image, root, tip, 3, ink);
        line(&mut image, root, tip, 1, rim);
        line(
            &mut image,
            (root.0, root.1 + 1),
            (tip.0, tip.1 + 1),
            1,
            blue,
        );
    }
    ellipse(&mut image, center as f32, 8.8, 8.2, 8.3, ink);
    ellipse(&mut image, center as f32, 8.3, 7.4, 7.1, shadow);
    ellipse(&mut image, center as f32 - 1.0, 6.0, 6.0, 4.8, blue);
    line(&mut image, (center - 3, 1), (center + 1, 1), 1, rim);
    dot(&mut image, center - 4, 2, rim);
    ellipse(&mut image, center as f32 - 3.0, 7.4, 3.6, 4.2, snow);
    ellipse(&mut image, center as f32 + 3.0, 7.4, 3.6, 4.2, snow);
    ellipse(&mut image, center as f32 - 3.0, 6.7, 2.7, 3.3, white);
    ellipse(&mut image, center as f32 + 3.0, 6.7, 2.7, 3.3, white);
    ellipse(&mut image, center as f32, 11.0, 5.5, 2.5, snow);
    let blink = matches!(phase, 27 | 28 | 59);
    for x in [center - 3, center + 3] {
        line(
            &mut image,
            (x - 1, 6),
            (x, 6),
            if blink { 1 } else { 2 },
            ink,
        );
        if !blink {
            dot(&mut image, x - 1, 6, blue);
        }
    }
    for x in [center - 5, center + 5] {
        dot(&mut image, x, 8, cheek);
    }
    line(&mut image, (center - 1, 8), (center + 1, 8), 1, gold);
    dot(&mut image, center, 9, beak_shadow);
    for x in [center - 7, center + 7] {
        line(&mut image, (x - 1, 11), (x + 1, 11), 1, rim);
    }
    image
}

fn frames(kind: Kind, width: u16, rows: u16) -> CachedFrames {
    let key = (kind, width, rows);
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, frames)) = cache.iter().find(|(candidate, _)| *candidate == key) {
        return Arc::clone(frames);
    }
    let height = rows * 2;
    let source_width =
        (u32::from(width) * u32::from(PIXEL_HEIGHT)).div_ceil(u32::from(height)) as u16;
    let frames = Arc::new(
        (0..FRAMES)
            .map(|phase| {
                let source = match kind {
                    Kind::Cat => cat(source_width, phase),
                    Kind::Penguin => penguin(source_width, phase),
                };
                if height == PIXEL_HEIGHT {
                    return source;
                }
                let mut target = PixelFrame::new(width, height);
                for y in 0..height {
                    for x in 0..width {
                        let sx = u32::from(x) * u32::from(source_width) / u32::from(width);
                        let sy = u32::from(y) * u32::from(PIXEL_HEIGHT) / u32::from(height);
                        if let Some(color) = source.get(sx as u16, sy as u16) {
                            target.set(x, y, color);
                        }
                    }
                }
                target
            })
            .collect(),
    );
    if cache.len() == 6 {
        cache.pop_front();
    }
    cache.push_back((key, Arc::clone(&frames)));
    frames
}

/// Draw directly above a surface, never over its contents. The animation clock
/// survives submenu transitions; reduced motion always selects frame zero.
pub(super) fn render(
    buffer: &mut Buffer,
    clip: Rect,
    border: Rect,
    kind: Kind,
    elapsed: Duration,
    motion: bool,
    leaving: bool,
) -> Option<Rect> {
    let clip = clip.intersection(buffer.area);
    let rows = border.y.saturating_sub(clip.y).min(HEIGHT);
    let width = border.width.saturating_sub(4);
    if rows < 3 || width < 24 || (leaving && (!motion || elapsed >= LEAVE)) {
        return None;
    }
    let reserved = Rect::new(border.x + 2, border.y - rows, width, rows);
    if reserved.intersection(clip) != reserved {
        return None;
    }
    let visible = if !motion {
        rows
    } else if leaving {
        ((1.0 - elapsed.as_secs_f32() / LEAVE.as_secs_f32()) * f32::from(rows)).ceil() as u16
    } else {
        (elapsed.as_secs_f32() / ENTER.as_secs_f32() * f32::from(rows))
            .ceil()
            .min(f32::from(rows)) as u16
    };
    if visible == 0 {
        return None;
    }
    // Clear stale logo characters before drawing the opaque pixel strip.
    PixelFrame::new(width, rows * 2).render(buffer, reserved, PANEL);
    let frames = frames(kind, width, rows);
    let index = if motion {
        let frame_millis = if kind == Kind::Cat {
            FRAME_MILLIS * 2
        } else {
            FRAME_MILLIS
        };
        ((elapsed.as_millis() / frame_millis) % FRAMES as u128) as usize
    } else {
        0
    };
    let rect = Rect::new(reserved.x, border.y - visible, width, visible);
    frames[index].render(buffer, rect, PANEL);
    Some(rect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detailed_frames_are_cached_and_motion_changes_pixels() {
        for kind in [Kind::Cat, Kind::Penguin] {
            let first = frames(kind, 72, 6);
            assert!(Arc::ptr_eq(&first, &frames(kind, 72, 6)));
            assert_ne!(first[0], first[27]);
            let colors: std::collections::HashSet<_> = (0..12)
                .flat_map(|y| {
                    (0..72).filter_map({
                        let frame = &first[0];
                        move |x| frame.get(x, y)
                    })
                })
                .collect();
            assert!(colors.len() >= 8);
        }
    }

    #[test]
    fn companions_adapt_to_available_band_without_touching_border() {
        for rows in [3, 4, 5, 6] {
            let area = Rect::new(0, 0, 80, 24);
            let border = Rect::new(2, rows, 76, 24 - rows);
            let mut buffer = Buffer::filled(area, ratatui::buffer::Cell::new("x"));
            let rect = render(
                &mut buffer,
                area,
                border,
                Kind::Penguin,
                Duration::from_secs(1),
                true,
                false,
            )
            .unwrap();
            assert_eq!(rect.bottom(), border.top());
            assert_eq!(rect.width, 72);
            for y in border.top()..area.bottom() {
                for x in 0..area.width {
                    assert_eq!(buffer[(x, y)].symbol(), "x");
                }
            }
        }
    }

    #[test]
    fn reduced_motion_is_static_and_retreat_immediate() {
        let area = Rect::new(0, 0, 80, 24);
        let border = Rect::new(2, 6, 76, 18);
        let mut first = Buffer::empty(area);
        let mut second = first.clone();
        render(
            &mut first,
            area,
            border,
            Kind::Cat,
            Duration::ZERO,
            false,
            false,
        );
        render(
            &mut second,
            area,
            border,
            Kind::Cat,
            Duration::from_secs(5),
            false,
            false,
        );
        assert_eq!(first, second);
        assert!(
            render(
                &mut second,
                area,
                border,
                Kind::Cat,
                Duration::ZERO,
                false,
                true
            )
            .is_none()
        );
    }

    #[test]
    fn entry_and_retreat_are_bounded_and_small_screens_hide_companions() {
        let area = Rect::new(0, 0, 80, 24);
        let border = Rect::new(2, 6, 76, 18);
        let mut buffer = Buffer::empty(area);
        assert!(
            render(
                &mut buffer,
                area,
                border,
                Kind::Cat,
                Duration::ZERO,
                true,
                false
            )
            .is_none()
        );
        let partial = render(
            &mut buffer,
            area,
            border,
            Kind::Cat,
            Duration::from_millis(100),
            true,
            false,
        )
        .unwrap();
        assert!(partial.height < HEIGHT);
        assert!(render(&mut buffer, area, border, Kind::Cat, LEAVE, true, true).is_none());
        assert!(
            render(
                &mut buffer,
                area,
                Rect::new(1, 2, 20, 10),
                Kind::Cat,
                Duration::from_secs(1),
                true,
                false
            )
            .is_none()
        );
    }
}
