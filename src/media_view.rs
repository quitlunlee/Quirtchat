//! Bounded terminal previews. Plaintext image buffers are zeroized; media files
//! live only in an owned temporary namespace and never use an incoming filename.

use anyhow::{Context, Result, bail, ensure};
use clichat::{
    app::Shared,
    media::MediaKind,
    model::{ChatMessage, now},
};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};
use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{process::Command, task::JoinHandle};
use zeroize::{Zeroize, Zeroizing};

const IMAGE_SIDE_LIMIT: u32 = 4096;
const IMAGE_ALLOC_LIMIT: u64 = 64 * 1024 * 1024;
const PREVIEW_SIDE: u32 = 640;
const PREFIX: &str = "clichat-";

struct ImagePreview {
    pixels: Zeroizing<Vec<u8>>,
    width: u32,
    height: u32,
    name: String,
    expires: i64,
}

struct TemporaryMedia {
    path: PathBuf,
    expires: i64,
}
impl Drop for TemporaryMedia {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) struct Playback {
    file: TemporaryMedia,
    kind: MediaKind,
    name: String,
}

enum Loaded {
    Waiting(usize),
    Image(ImagePreview),
    Playback(Playback),
}

pub(crate) struct MediaView {
    message: Option<ChatMessage>,
    loading: Option<JoinHandle<Result<Loaded>>>,
    loading_cancelled: bool,
    image: Option<ImagePreview>,
    external: Option<Playback>,
    opened: Vec<Playback>,
    expires: Option<i64>,
    progress: usize,
    last_attempt: Instant,
    last_cleanup: Instant,
}

impl Default for MediaView {
    fn default() -> Self {
        let _ = cleanup_expired(now());
        Self {
            message: None,
            loading: None,
            loading_cancelled: false,
            image: None,
            external: None,
            opened: vec![],
            expires: None,
            progress: 0,
            last_attempt: Instant::now() - Duration::from_secs(1),
            last_cleanup: Instant::now(),
        }
    }
}

impl Drop for MediaView {
    fn drop(&mut self) {
        self.close();
    }
}

impl MediaView {
    pub(crate) fn request(&mut self, message: ChatMessage) {
        self.close();
        self.expires = Some(message.expires_at);
        self.message = Some(message);
        self.last_attempt = Instant::now() - Duration::from_secs(1);
    }

    pub(crate) fn is_open(&self) -> bool {
        self.message.is_some()
            || (self.loading.is_some() && !self.loading_cancelled)
            || self.image.is_some()
            || self.external.is_some()
    }

    pub(crate) fn has_external(&self) -> bool {
        self.external.is_some()
    }

    pub(crate) fn close(&mut self) {
        if let Some(mut message) = self.message.take() {
            wipe_message(&mut message);
        }
        // A running spawn_blocking job cannot be interrupted. Keep its handle
        // until it finishes, so repeated Esc/open never starts parallel decoders.
        if let Some(task) = &self.loading {
            task.abort();
            self.loading_cancelled = true;
        }
        self.image = None;
        self.external = None;
        self.expires = None;
        self.progress = 0;
    }

    pub(crate) fn offer_external(&mut self, playback: Playback) {
        self.close();
        self.expires = Some(playback.file.expires);
        self.external = Some(playback);
    }

    /// All hashing, decryption, decoding and file I/O happen off the render task.
    pub(crate) async fn poll(&mut self, shared: &Shared) -> Result<Option<Playback>> {
        let time = now();
        if self.last_cleanup.elapsed() >= Duration::from_secs(1) {
            self.opened.retain(|playback| playback.file.expires > time);
            let _ = cleanup_expired(time);
            self.last_cleanup = Instant::now();
        }
        if self.expires.is_some_and(|expires| expires <= time) {
            self.close();
            bail!("Media expired; preview cleared");
        }
        if self.loading.as_ref().is_some_and(JoinHandle::is_finished) {
            let result = self.loading.take().unwrap().await;
            if std::mem::take(&mut self.loading_cancelled) {
                drop(result); // Zeroizing bytes / owned temporary file drop here.
            } else {
                match result {
                    Err(error) => {
                        self.close();
                        return Err(error).context("preview worker stopped");
                    }
                    Ok(result) => match result {
                        Ok(Loaded::Waiting(progress)) => self.progress = progress,
                        Ok(Loaded::Image(image)) => {
                            if let Some(mut message) = self.message.take() {
                                wipe_message(&mut message);
                            }
                            if image.expires <= now() {
                                self.close();
                                bail!("Media expired while decoding");
                            }
                            self.image = Some(image);
                        }
                        Ok(Loaded::Playback(playback)) => {
                            if let Some(mut message) = self.message.take() {
                                wipe_message(&mut message);
                            }
                            self.expires = None;
                            if playback.file.expires <= now() {
                                bail!("Media expired while preparing playback");
                            }
                            return Ok(Some(playback));
                        }
                        Err(error) => {
                            self.close();
                            return Err(error);
                        }
                    },
                }
            }
        }
        if self.loading.is_none()
            && let Some(message) = self.message.as_ref()
            && self.last_attempt.elapsed() >= Duration::from_millis(500)
        {
            let shared = shared.clone();
            let mut message = message.clone();
            self.loading = Some(tokio::task::spawn_blocking(move || {
                let result = load(&shared, &message);
                wipe_message(&mut message);
                result
            }));
            self.last_attempt = Instant::now();
        }
        Ok(None)
    }

    /// Launching an external viewer is a second explicit action (O), because an
    /// external program controls its own caches and cannot enforce our TTL.
    pub(crate) fn open_external(&mut self) -> Result<()> {
        ensure!(
            self.opened.len() < 8,
            "at most 8 external previews can remain open until expiry"
        );
        let playback = self
            .external
            .take()
            .context("no external preview waiting")?;
        ensure!(playback.file.expires > now(), "media expired");
        #[cfg(target_os = "windows")]
        let mut command = Command::new("explorer.exe");
        #[cfg(target_os = "macos")]
        let mut command = Command::new("open");
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let mut command = Command::new("xdg-open");
        let mut child = command
            .arg(&playback.file.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("could not open the system media app")?;
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        self.opened.push(playback);
        self.expires = None;
        Ok(())
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect, time: i64) {
        // Check again immediately before rendering, even if a worker just finished.
        if self.expires.is_some_and(|expires| expires <= time) {
            self.close();
            return;
        }
        if !self.is_open() || area.width < 8 || area.height < 5 {
            return;
        }
        frame.render_widget(Clear, area);
        let border = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(115, 218, 205)))
            .style(Style::default().bg(Color::Reset));
        let inner = border.inner(area);
        frame.render_widget(border, area);
        if let Some(image) = &self.image {
            if image.expires <= now() {
                self.close();
                return;
            }
            let title = format!(" {}", crate::safe(&image.name));
            frame.render_widget(
                Paragraph::new(title).style(Style::default().fg(Color::Rgb(218, 224, 236))),
                Rect::new(inner.x, inner.y, inner.width, 1),
            );
            render_image(
                frame,
                Rect::new(
                    inner.x + 1,
                    inner.y + 2,
                    inner.width.saturating_sub(2),
                    inner.height.saturating_sub(3),
                ),
                image,
            );
        } else {
            let text = if let Some(playback) = &self.external {
                vec![
                    Line::from(crate::safe(&playback.name)),
                    Line::from(""),
                    Line::from("mpv was not found on PATH."),
                    Line::from("[ Open externally ]"),
                ]
            } else {
                let name = self
                    .message
                    .as_ref()
                    .and_then(|message| message.attachment.as_ref())
                    .map_or("media", |media| media.name.as_str());
                let chunks = self
                    .message
                    .as_ref()
                    .and_then(|message| message.attachment.as_ref())
                    .map_or(0, |media| media.chunks);
                vec![
                    Line::from(crate::safe(name)),
                    Line::from(""),
                    Line::from(format!(
                        "Preparing encrypted media…  {}/{} chunks",
                        self.progress, chunks
                    )),
                ]
            };
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(Color::Rgb(170, 184, 207))),
                Rect::new(
                    inner.x + 2,
                    inner.y + 2,
                    inner.width.saturating_sub(4),
                    inner.height.saturating_sub(4),
                ),
            );
        }
    }
}

fn wipe_message(message: &mut ChatMessage) {
    message.text.zeroize();
    if let Some(media) = message.attachment.as_mut() {
        media.key.zeroize();
        media.nonce_prefix.zeroize();
        media.read_token.zeroize();
    }
}

fn load(shared: &Shared, message: &ChatMessage) -> Result<Loaded> {
    ensure!(message.expires_at > now(), "media expired");
    let media = message
        .attachment
        .as_ref()
        .context("message has no attachment")?;
    let bytes = {
        let app = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("profile state lock failed"))?;
        let Some(bytes) = app.media_bytes(message)? else {
            return Ok(Loaded::Waiting(app.store.media_progress(&media.id, now())?));
        };
        bytes
    };
    ensure!(message.expires_at > now(), "media expired");
    if media.kind == MediaKind::Image {
        Ok(Loaded::Image(decode_image(
            bytes,
            &media.name,
            media.expires_at,
        )?))
    } else {
        let file = write_temporary(&bytes, &media.name, media.expires_at)?;
        Ok(Loaded::Playback(Playback {
            file,
            kind: media.kind.clone(),
            name: media.name.clone(),
        }))
    }
}

fn decode_image(bytes: Zeroizing<Vec<u8>>, name: &str, expires: i64) -> Result<ImagePreview> {
    ensure!(expires > now(), "image expired");
    let mut reader =
        image::ImageReader::new(Cursor::new(bytes.as_slice())).with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(IMAGE_SIDE_LIMIT);
    limits.max_image_height = Some(IMAGE_SIDE_LIMIT);
    limits.max_alloc = Some(IMAGE_ALLOC_LIMIT);
    reader.limits(limits);
    // GIF/WebP display a static decoded frame; animation never creates an
    // unbounded sequence of retained images.
    let image = reader
        .decode()
        .context("image could not be decoded within preview limits")?
        .into_rgba8();
    let (width, height) = image.dimensions();
    let original = Zeroizing::new(image.into_raw());
    ensure!(
        width > 0 && height > 0 && width <= IMAGE_SIDE_LIMIT && height <= IMAGE_SIDE_LIMIT,
        "image dimensions exceed preview limits"
    );
    ensure!(
        original.len() as u64 <= IMAGE_ALLOC_LIMIT,
        "decoded image exceeds preview memory limit"
    );
    let (width, height, pixels) = if width <= PREVIEW_SIDE && height <= PREVIEW_SIDE {
        (width, height, original)
    } else {
        let longest = width.max(height);
        let target_width = (width * PREVIEW_SIDE / longest).max(1);
        let target_height = (height * PREVIEW_SIDE / longest).max(1);
        let borrowed =
            image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width, height, original.as_slice())
                .context("invalid decoded image")?;
        let thumbnail = image::imageops::thumbnail(&borrowed, target_width, target_height);
        (
            target_width,
            target_height,
            Zeroizing::new(thumbnail.into_raw()),
        )
    };
    ensure!(expires > now(), "image expired while decoding");
    Ok(ImagePreview {
        pixels,
        width,
        height,
        name: name.to_owned(),
        expires,
    })
}

fn render_image(frame: &mut Frame, area: Rect, image: &ImagePreview) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let scale = (f32::from(area.width) / image.width as f32)
        .min(f32::from(area.height) * 2.0 / image.height as f32);
    let width = ((image.width as f32 * scale).floor() as u16)
        .max(1)
        .min(area.width);
    let pixel_height = ((image.height as f32 * scale).floor() as u16)
        .max(1)
        .min(area.height.saturating_mul(2));
    let rows = pixel_height.div_ceil(2);
    let x0 = area.x + (area.width - width) / 2;
    let y0 = area.y + (area.height - rows) / 2;
    let pixel = |x: u16, y: u16| {
        let sx = (u32::from(x) * image.width / u32::from(width)).min(image.width - 1);
        let sy = (u32::from(y) * image.height / u32::from(pixel_height)).min(image.height - 1);
        let index = ((sy * image.width + sx) * 4) as usize;
        &image.pixels[index..index + 4]
    };
    for y in 0..rows {
        for x in 0..width {
            let top = pixel(x, y * 2);
            let bottom = pixel(x, (y * 2 + 1).min(pixel_height - 1));
            let rgb = |p: &[u8]| Color::Rgb(p[0], p[1], p[2]);
            let (symbol, fg, bg) = match (top[3] >= 128, bottom[3] >= 128) {
                (true, true) => ("▀", rgb(top), rgb(bottom)),
                (true, false) => ("▀", rgb(top), Color::Reset),
                (false, true) => ("▄", rgb(bottom), Color::Reset),
                (false, false) => (" ", Color::Reset, Color::Reset),
            };
            frame.buffer_mut()[(x0 + x, y0 + y)]
                .set_symbol(symbol)
                .set_style(Style::default().fg(fg).bg(bg));
        }
    }
}

pub(crate) fn find_mpv() -> Option<PathBuf> {
    let name = if cfg!(windows) { "mpv.exe" } else { "mpv" };
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_absolute() && path.is_file())
}

/// Called only after the TUI relinquishes raw mode and the alternate screen.
pub(crate) async fn play_terminal(playback: Playback, player: &Path) -> Result<String> {
    ensure!(playback.file.expires > now(), "media expired");
    let mut command = Command::new(player);
    command.args([
        "--no-config",
        "--load-scripts=no",
        "--ytdl=no",
        "--access-references=no",
        "--save-position-on-quit=no",
        "--network-timeout=5",
        "--really-quiet",
    ]);
    if playback.kind == MediaKind::Video {
        command.args(["--vo=tct", "--profile=sw-fast", "--vo-tct-buffering=frame"]);
    } else {
        command.arg("--no-video");
    }
    let mut child = command
        .arg("--")
        .arg(&playback.file.path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("could not start mpv")?;
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            status = child.wait() => {
                ensure!(status?.success(), "mpv could not play this media");
                return Ok("Playback finished".into());
            }
            _ = tokio::signal::ctrl_c() => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Ok("Playback stopped".into());
            }
            _ = tick.tick() => {
                let _ = cleanup_expired(now());
                if playback.file.expires <= now() {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Ok("Media expired; playback stopped".into());
                }
            }
        }
    }
}

fn preview_directory() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let base =
            directories::BaseDirs::new().context("cannot locate the user's cache directory")?;
        user_preview_directory(base.cache_dir())
    }
    #[cfg(not(unix))]
    {
        // Windows already provides a per-user temporary directory. Retain the
        // previous location so cleanup also finds previews left by older builds.
        prepare_preview_directory(std::env::temp_dir().join("clichat-previews"))
    }
}

#[cfg(any(unix, test))]
fn user_preview_directory(cache_base: &Path) -> Result<PathBuf> {
    let parent = cache_base.join("clichat");
    // Do not change permissions on an existing cache directory or its parents.
    fs::create_dir_all(&parent)?;
    // A shared /tmp/clichat-previews can belong to another user, so do not
    // migrate or clean that old namespace while opening this private location.
    prepare_preview_directory(parent.join("previews"))
}

fn prepare_preview_directory(directory: PathBuf) -> Result<PathBuf> {
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "preview directory must be a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

fn safe_extension(name: &str) -> Result<&str> {
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .context("missing media extension")?;
    ensure!(
        matches!(
            extension.to_ascii_lowercase().as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "mp3"
                | "wav"
                | "flac"
                | "ogg"
                | "opus"
                | "m4a"
                | "mp4"
                | "mov"
                | "webm"
        ),
        "unsupported media extension"
    );
    Ok(extension)
}

fn write_temporary(bytes: &[u8], name: &str, expires: i64) -> Result<TemporaryMedia> {
    ensure!(expires > now(), "media expired");
    let extension = safe_extension(name)?.to_ascii_lowercase();
    let path = preview_directory()?.join(format!(
        "{PREFIX}{expires}-{}.{}",
        uuid::Uuid::new_v4().simple(),
        extension
    ));
    let temporary = TemporaryMedia { path, expires };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary.path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    ensure!(expires > now(), "media expired while preparing preview");
    Ok(temporary)
}

fn temporary_expiry(name: &str) -> Option<i64> {
    let (base, extension) = name.rsplit_once('.')?;
    safe_extension(&format!("file.{extension}")).ok()?;
    let (time, nonce) = base.strip_prefix(PREFIX)?.split_once('-')?;
    if time.is_empty()
        || time.len() > 12
        || !time.bytes().all(|ch| ch.is_ascii_digit())
        || nonce.len() != 32
        || !nonce.bytes().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    time.parse().ok()
}

pub(crate) fn cleanup_expired(time: i64) -> Result<usize> {
    let directory = preview_directory()?;
    let mut removed = 0;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if temporary_expiry(&name).is_some_and(|expires| expires <= time)
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

pub(crate) fn kind_label(kind: &MediaKind) -> &'static str {
    match kind {
        MediaKind::Image => "IMAGE",
        MediaKind::Audio => "AUDIO",
        MediaKind::Video => "VIDEO",
    }
}

pub(crate) fn size_label(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{:.1} MiB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.0} KiB", size as f64 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_directories_are_isolated_by_supplied_user_cache_base() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = user_preview_directory(&root.path().join("first-user"))?;
        let second = user_preview_directory(&root.path().join("second-user"))?;
        assert_eq!(first, root.path().join("first-user/clichat/previews"));
        assert_eq!(second, root.path().join("second-user/clichat/previews"));
        assert_ne!(first, second);
        assert!(first.is_dir() && second.is_dir());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_preview_leaf_preserves_parent_permissions_and_rejects_symlinks() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir()?;
        let parent = root.path().join("clichat");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750))?;
        let directory = user_preview_directory(root.path())?;
        assert_eq!(
            fs::metadata(&directory)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&parent)?.permissions().mode() & 0o777, 0o750);
        fs::remove_dir(&directory)?;
        let other = root.path().join("other");
        fs::create_dir(&other)?;
        symlink(&other, &directory)?;
        assert!(user_preview_directory(root.path()).is_err());
        Ok(())
    }

    #[test]
    fn cleanup_recognizes_only_owned_filenames() {
        assert_eq!(
            temporary_expiry("clichat-123-0123456789abcdef0123456789abcdef.mp4"),
            Some(123)
        );
        for name in [
            "holiday.mp4",
            "clichat-123-secret.mp4",
            "clichat-123-0123456789abcdef0123456789abcdef.exe",
            "../clichat-1-0123456789abcdef0123456789abcdef.png",
        ] {
            assert!(temporary_expiry(name).is_none());
        }
    }
    #[test]
    fn image_decoder_is_bounded_and_rejects_expired_input() {
        assert!(decode_image(Zeroizing::new(vec![0; 20]), "bad.png", now() + 60).is_err());
        assert!(decode_image(Zeroizing::new(vec![0; 20]), "expired.png", now()).is_err());
    }

    #[test]
    fn image_thumbnail_preserves_aspect_ratio() -> Result<()> {
        use image::ImageEncoder;
        let mut encoded = Vec::new();
        image::codecs::png::PngEncoder::new(&mut encoded).write_image(
            &vec![128; 1024 * 128 * 4],
            1024,
            128,
            image::ExtendedColorType::Rgba8,
        )?;
        let image = decode_image(Zeroizing::new(encoded), "panorama.png", now() + 60)?;
        assert_eq!((image.width, image.height), (640, 80));
        assert_eq!(image.pixels.len(), 640 * 80 * 4);
        Ok(())
    }

    #[test]
    fn png_pixels_render_in_color_and_expiry_drops_preview() -> Result<()> {
        use image::ImageEncoder;
        use ratatui::{Terminal, backend::TestBackend};
        let mut encoded = Vec::new();
        image::codecs::png::PngEncoder::new(&mut encoded).write_image(
            &[
                255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255,
            ],
            2,
            2,
            image::ExtendedColorType::Rgba8,
        )?;
        let expires = now() + 60;
        let image = decode_image(Zeroizing::new(encoded), "sample.png", expires)?;
        let mut terminal = Terminal::new(TestBackend::new(2, 1))?;
        terminal.draw(|frame| render_image(frame, frame.area(), &image))?;
        let first = &terminal.backend().buffer()[(0, 0)];
        assert_eq!(first.symbol(), "▀");
        assert_eq!(first.fg, Color::Rgb(255, 0, 0));
        assert_eq!(first.bg, Color::Rgb(0, 0, 255));
        let mut view = MediaView::default();
        view.expires = Some(expires);
        view.image = Some(image);
        let mut terminal = Terminal::new(TestBackend::new(85, 24))?;
        terminal.draw(|frame| view.render(frame, frame.area(), expires - 1))?;
        assert!(
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .any(|cell| matches!(cell.bg, Color::Rgb(..)))
        );
        terminal.draw(|frame| view.render(frame, frame.area(), expires))?;
        assert!(!view.is_open());
        assert!(view.image.is_none());
        assert!(
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .all(|cell| cell.bg == Color::Reset)
        );
        Ok(())
    }
}
