//! A right-leaning wordmark with a local yellow/green marquee above a turning globe.

use super::{
    pixels::PixelFrame,
    theme::{BLACK, mix},
};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
};
use std::{cell::RefCell, time::Duration};

const NAME: &str = "Qu1rTChat";
// The capitalisation is intentional: Q u 1 r T C h a t.
const LETTERS: [[&str; 5]; 9] = [
    [" ### ", "#   #", "#   #", "# # #", " ###\\"],
    ["     ", "#   #", "#   #", "#   #", " ####"],
    ["  #  ", " ##  ", "  #  ", "  #  ", " ### "],
    ["     ", "# ## ", "##  #", "#    ", "#    "],
    ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    [" ####", "#    ", "#    ", "#    ", " ####"],
    ["#    ", "#    ", "# ## ", "##  #", "#   #"],
    ["     ", " ### ", "    #", " ####", "#  ##"],
    ["  #  ", " ### ", "  #  ", "  #  ", "   ##"],
];
const HEIGHT: u16 = 5;
pub(super) const WIDTH: u16 = 55;
const YELLOW: Color = Color::Rgb(248, 218, 88);
const GREEN: Color = Color::Rgb(105, 221, 116);

fn shade(column: u16, span: u16, elapsed: Duration, motion: bool) -> Color {
    let phase = if motion {
        (elapsed.as_secs_f32() % 4.0) / 4.0
    } else {
        0.18
    };
    let position = (f32::from(column) / f32::from(span.max(1)) - phase).rem_euclid(1.0);
    // A bright yellow band occupies only part of the otherwise green wordmark.
    let distance = position.min(1.0 - position);
    let yellow = (1.0 - distance / 0.22).clamp(0.0, 1.0);
    mix(GREEN, YELLOW, yellow)
}

fn wordmark(buffer: &mut Buffer, rect: Rect, elapsed: Duration, motion: bool, compact: bool) {
    if compact {
        for (column, glyph) in NAME.chars().enumerate().take(usize::from(rect.width)) {
            buffer[(rect.x + column as u16, rect.y)]
                .set_char(glyph)
                .set_style(
                    Style::default()
                        .fg(shade(column as u16, rect.width, elapsed, motion))
                        .bg(BLACK)
                        .add_modifier(Modifier::ITALIC | Modifier::BOLD),
                );
        }
        return;
    }
    for (letter, rows) in LETTERS.iter().enumerate() {
        for (row, cells) in rows.iter().enumerate() {
            let lean = (HEIGHT - 1 - row as u16) / 2;
            for (column, glyph) in cells.chars().enumerate() {
                if glyph == ' ' {
                    continue;
                }
                let x = letter as u16 * 6 + column as u16 + lean;
                if x >= rect.width || row as u16 >= rect.height {
                    continue;
                }
                buffer[(rect.x + x, rect.y + row as u16)]
                    .set_symbol(if glyph == '\\' { "╲" } else { "█" })
                    .set_style(
                        Style::default()
                            .fg(shade(x, rect.width, elapsed, motion))
                            .bg(BLACK),
                    );
            }
        }
    }
}

// Original low-resolution coastlines, sampled on the sphere rather than screen space.
const CONTINENTS: &[&[(f32, f32)]] = &[
    &[
        (-168., 70.),
        (-132., 70.),
        (-115., 80.),
        (-55., 54.),
        (-65., 45.),
        (-82., 24.),
        (-97., 16.),
        (-111., 30.),
        (-125., 49.),
        (-150., 59.),
    ],
    &[
        (-81., 12.),
        (-63., 10.),
        (-48., -1.),
        (-35., -8.),
        (-44., -23.),
        (-54., -34.),
        (-69., -55.),
        (-75., -42.),
        (-78., -8.),
    ],
    &[
        (-52., 60.),
        (-42., 60.),
        (-20., 80.),
        (-45., 84.),
        (-62., 75.),
    ],
    &[
        (-12., 36.),
        (-10., 59.),
        (12., 72.),
        (29., 70.),
        (40., 58.),
        (80., 74.),
        (130., 70.),
        (175., 61.),
        (145., 45.),
        (130., 33.),
        (121., 20.),
        (107., 5.),
        (98., 20.),
        (80., 7.),
        (68., 24.),
        (50., 12.),
        (35., 30.),
        (25., 40.),
        (10., 35.),
    ],
    &[
        (-17., 34.),
        (8., 37.),
        (34., 30.),
        (43., 13.),
        (51., 11.),
        (41., -12.),
        (30., -34.),
        (18., -35.),
        (10., -6.),
        (-5., 5.),
        (-17., 15.),
    ],
    &[
        (112., -11.),
        (135., -11.),
        (154., -23.),
        (150., -38.),
        (130., -34.),
        (114., -22.),
    ],
    &[(47., -13.), (51., -17.), (47., -26.), (44., -22.)],
    &[(130., 32.), (141., 45.), (146., 43.), (138., 32.)],
];

fn in_polygon(lon: f32, lat: f32, points: &[(f32, f32)]) -> bool {
    let mut inside = false;
    let mut previous = points[points.len() - 1];
    for &current in points {
        if (current.1 > lat) != (previous.1 > lat)
            && lon
                < (previous.0 - current.0) * (lat - current.1) / (previous.1 - current.1)
                    + current.0
        {
            inside = !inside;
        }
        previous = current;
    }
    inside
}

const GLOBE_FRAMES: usize = 300;
const GLOBE_PERIOD_MS: u128 = 30_000;

#[derive(Default)]
struct GlobeCache {
    size: (u16, u16),
    frames: Vec<Option<PixelFrame>>,
}

thread_local! {
    // Populate only frames that are actually shown. Resizing discards the old size,
    // so the cache stays bounded even when the terminal is resized continuously.
    static GLOBE_CACHE: RefCell<GlobeCache> = RefCell::new(GlobeCache::default());
}

fn land_at(lon: f32, lat: f32) -> bool {
    lat < -73.0 || CONTINENTS.iter().any(|points| in_polygon(lon, lat, points))
}

fn globe_frame(width: u16, height: u16, index: usize) -> PixelFrame {
    let mut frame = PixelFrame::new(width, height);
    let rotation = index as f32 * std::f32::consts::TAU / GLOBE_FRAMES as f32;
    let half_x = f32::from(width - 1) / 2.0;
    let half_y = f32::from(height - 1) / 2.0;
    for row in 0..height {
        for column in 0..width {
            let nx = (f32::from(column) - half_x) / half_x;
            let ny = (f32::from(row) - half_y) / half_y;
            let radius = nx * nx + ny * ny;
            if radius > 1.0 {
                continue;
            }
            // A single crisp atmospheric rim surrounds the shaded surface.
            if radius > 0.89 {
                let light = (-nx * 0.5 - ny * 0.65 + 0.3).clamp(0.0, 1.0);
                frame.set(
                    column,
                    row,
                    mix(Color::Rgb(13, 35, 61), Color::Rgb(94, 191, 218), light),
                );
                continue;
            }
            let sx = nx / 0.945;
            let sy = ny / 0.945;
            let sz = (1.0 - sx * sx - sy * sy).max(0.0).sqrt();
            // The axial tilt is part of the projection; continents and clouds
            // move together instead of shimmering with a screen-space pattern.
            let tilted_x = sx * 0.978 - sy * 0.208;
            let tilted_y = sy * 0.978 + sx * 0.208;
            let lon =
                ((tilted_x.atan2(sz) + rotation).to_degrees() + 180.0).rem_euclid(360.0) - 180.0;
            let lat = (-tilted_y).clamp(-1.0, 1.0).asin().to_degrees();
            let land = land_at(lon, lat);
            let texture = (lon.to_radians() * 13.0).sin() * (lat.to_radians() * 19.0).cos();
            let base = if lat.abs() > 70.0 {
                mix(
                    Color::Rgb(157, 201, 204),
                    Color::Rgb(223, 240, 222),
                    (lat.abs() - 70.0) / 16.0,
                )
            } else if land {
                let desert = ((lat - 25.0).abs() < 12.0 && (-18.0..65.0).contains(&lon))
                    || ((lat + 25.0).abs() < 10.0 && (114.0..145.0).contains(&lon));
                if desert {
                    mix(
                        Color::Rgb(154, 148, 83),
                        Color::Rgb(209, 189, 116),
                        texture * 0.25 + 0.5,
                    )
                } else {
                    mix(
                        Color::Rgb(48, 124, 90),
                        Color::Rgb(121, 185, 116),
                        texture * 0.28 + 0.5,
                    )
                }
            } else {
                let coastal = land_at(lon - 3.0, lat)
                    || land_at(lon + 3.0, lat)
                    || land_at(lon, lat - 3.0)
                    || land_at(lon, lat + 3.0);
                if coastal {
                    Color::Rgb(42, 135, 156)
                } else {
                    mix(
                        Color::Rgb(26, 72, 132),
                        Color::Rgb(45, 115, 177),
                        texture * 0.24 + 0.5,
                    )
                }
            };
            // Several broad, curved cloud fronts leave the geography readable.
            let cloud_wave = (lon.to_radians() * 7.0 + (lat.to_radians() * 6.0).sin() * 1.6).sin()
                + (lat.to_radians() * 12.0 - lon.to_radians() * 3.0).cos() * 0.72;
            let cloud = ((cloud_wave - 1.13) * 1.6).clamp(0.0, 0.82);
            let cloud = if lat.abs() < 66.0 {
                cloud
            } else {
                cloud * 0.25
            };
            let surface = mix(base, Color::Rgb(216, 232, 220), cloud);
            // Quantized light preserves the deliberate pixel-art appearance.
            let light = ((-sx * 0.40 - sy * 0.45 + sz * 0.78).clamp(0.0, 1.0) * 7.0).round() / 7.0;
            let color = mix(Color::Rgb(9, 23, 40), surface, 0.22 + light * 0.78);
            frame.set(column, row, color);
        }
    }
    frame
}

fn globe(buffer: &mut Buffer, rect: Rect, elapsed: Duration, motion: bool) {
    if rect.width < 5 || rect.height < 3 {
        return;
    }
    let index = if motion {
        ((elapsed.as_millis() % GLOBE_PERIOD_MS) * GLOBE_FRAMES as u128 / GLOBE_PERIOD_MS) as usize
    } else {
        0
    };
    let size = (rect.width, rect.height.saturating_mul(2));
    GLOBE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.size != size {
            cache.size = size;
            cache.frames.clear();
            cache.frames.resize_with(GLOBE_FRAMES, || None);
        }
        cache.frames[index]
            .get_or_insert_with(|| globe_frame(size.0, size.1, index))
            .render(buffer, rect, BLACK);
    });
}

/// Draw the centred home composition. The returned rectangle includes the globe.
pub(super) fn render(buffer: &mut Buffer, area: Rect, elapsed: Duration, motion: bool) -> Rect {
    let area = area.intersection(buffer.area);
    if area.is_empty() {
        return area;
    }
    let compact = area.width < WIDTH + 2 || area.height < 12;
    let logo_width = if compact { NAME.len() as u16 } else { WIDTH }.min(area.width);
    let logo_height = if compact { 1 } else { HEIGHT };
    let available = area.height.saturating_sub(logo_height + 2);
    let globe_height = available.min(21).min(area.width.saturating_sub(1) / 2);
    let globe_height = if globe_height >= 3 { globe_height } else { 0 };
    let gap = if globe_height > 0 { 2 } else { 0 };
    let total_height = logo_height + gap + globe_height;
    let total_width = logo_width.max(globe_height.saturating_mul(2).saturating_sub(1));
    let group = Rect::new(
        area.x + (area.width - total_width) / 2,
        area.y + area.height.saturating_sub(total_height) / 2,
        total_width,
        total_height,
    );
    let logo = Rect::new(
        area.x + (area.width - logo_width) / 2,
        group.y,
        logo_width,
        logo_height,
    );
    wordmark(buffer, logo, elapsed, motion, compact);
    if globe_height > 0 {
        let width = globe_height * 2 - 1;
        globe(
            buffer,
            Rect::new(
                area.x + (area.width - width) / 2,
                group.y + logo_height + gap,
                width,
                globe_height,
            ),
            elapsed,
            motion,
        );
    }
    group
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn brand_is_exact_on_small_screens_and_large_letters_lean_right() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 30, 8));
        let rect = render(&mut buffer, Rect::new(0, 0, 30, 8), Duration::ZERO, false);
        let row: String = (0..30).map(|x| buffer[(x, rect.y)].symbol()).collect();
        assert!(row.contains(NAME));
        assert_eq!(LETTERS.len(), NAME.len());
        assert!(LETTERS.iter().flatten().all(|row| row.len() == 5));
        assert_eq!(WIDTH, 9 * 6 - 1 + 2);
    }

    #[test]
    fn static_mode_is_time_independent_and_motion_is_local() {
        let area = Rect::new(0, 0, 80, 30);
        let mut first = Buffer::empty(area);
        let mut second = Buffer::empty(area);
        render(&mut first, area, Duration::ZERO, false);
        render(&mut second, area, Duration::from_secs(9), false);
        assert_eq!(first, second);
        let mut animated = Buffer::empty(area);
        render(&mut animated, area, Duration::from_secs(1), true);
        assert_ne!(first, animated);
        assert_ne!(
            shade(2, WIDTH, Duration::ZERO, true),
            shade(25, WIDTH, Duration::ZERO, true)
        );
        assert_eq!(
            shade(2, WIDTH, Duration::ZERO, true),
            shade(2, WIDTH, Duration::from_secs(4), true)
        );
    }

    #[test]
    fn rendering_survives_tiny_and_offset_viewports() {
        for (width, height) in [(1, 1), (8, 2), (10, 4), (40, 12), (80, 24)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render(frame.buffer_mut(), area, Duration::from_secs(3), true);
                })
                .unwrap();
        }
        let area = Rect::new(5, 7, 50, 18);
        let mut buffer = Buffer::empty(area);
        let rect = render(&mut buffer, area, Duration::ZERO, false);
        assert_eq!(rect.intersection(area), rect);
    }

    #[test]
    fn globe_has_land_and_water_and_turns_once_in_thirty_seconds() {
        let area = Rect::new(0, 0, 33, 17);
        let mut first = Buffer::empty(area);
        let mut half = Buffer::empty(area);
        let mut full = Buffer::empty(area);
        globe(&mut first, area, Duration::ZERO, true);
        globe(&mut half, area, Duration::from_secs(15), true);
        globe(&mut full, area, Duration::from_secs(30), true);
        assert_ne!(first, half);
        let land = first
            .content
            .iter()
            .any(|cell| matches!(cell.fg, Color::Rgb(r,g,b) if g > b && g > r));
        let water = first
            .content
            .iter()
            .any(|cell| matches!(cell.fg, Color::Rgb(r,g,b) if b > g && b > r));
        assert!(land && water);
        assert_eq!(first, full);
    }

    #[test]
    fn globe_uses_two_pixel_rows_and_keeps_each_frame_steady() {
        let area = Rect::new(0, 0, 33, 17);
        let mut first = Buffer::empty(area);
        let mut same_frame = Buffer::empty(area);
        globe(&mut first, area, Duration::from_millis(400), true);
        globe(&mut same_frame, area, Duration::from_millis(499), true);
        assert_eq!(first, same_frame);
        assert!(
            first
                .content
                .iter()
                .any(|cell| cell.symbol() == "▀" && cell.fg != cell.bg)
        );
        assert!(
            first
                .content
                .iter()
                .all(|cell| matches!(cell.symbol(), "▀" | " " | "█"))
        );
    }

    #[test]
    fn resize_replaces_cached_size_instead_of_retaining_old_frames() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 33, 17));
        globe(&mut buffer, Rect::new(0, 0, 33, 17), Duration::ZERO, true);
        globe(
            &mut buffer,
            Rect::new(0, 0, 21, 11),
            Duration::from_secs(1),
            true,
        );
        GLOBE_CACHE.with(|cache| {
            let cache = cache.borrow();
            assert_eq!(cache.size, (21, 22));
            assert_eq!(cache.frames.len(), GLOBE_FRAMES);
            assert_eq!(
                cache.frames.iter().filter(|frame| frame.is_some()).count(),
                1
            );
        });
    }
}
