/// Lightweight LAN HTTP media server for AirPlay 2 video casting & live screen HLS.
///
/// Apple TV fetches media directly from `Content-Location` over HTTP:
/// - Local video files (`/media/{token}/{filename}`) are served with full HTTP `Range`
///   (`206 Partial Content`) support so AVPlayer can buffer & seek MP4/MOV/M4V smoothly.
/// - Live screen casts (`/hls/{id}/stream.m3u8` + `.ts` segments) are transcoded on-the-fly
///   using local `ffmpeg` (`x11grab` + PipeWire/Pulse audio -> low-latency H.264/AAC HLS).

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use crate::audio::pulse::{ScreenAudioRoute, SCREEN_SINK_MONITOR};
use tracing::{info, warn};

/// Which audio to capture alongside a screen cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenAudio {
    /// What's playing through the speakers (monitor of the default output).
    #[default]
    Desktop,
    /// Desktop audio mixed with the default microphone.
    DesktopAndMic,
    None,
}

impl ScreenAudio {
    pub fn is_enabled(self) -> bool {
        self != ScreenAudio::None
    }
}

#[derive(Clone)]
pub struct MediaServer {
    port: u16,
    files: Arc<RwLock<HashMap<String, PathBuf>>>,
    hls_dirs: Arc<RwLock<HashMap<String, PathBuf>>>,
    screen_proc: Arc<Mutex<Option<(String, Child, PathBuf)>>>,
    /// Desktop audio redirected to the TV for the running HLS screen cast.
    screen_audio_route: Arc<Mutex<Option<ScreenAudioRoute>>>,
}

impl MediaServer {
    pub fn start(port: u16) -> Arc<Self> {
        let srv = Arc::new(Self {
            port,
            files: Arc::new(RwLock::new(HashMap::new())),
            hls_dirs: Arc::new(RwLock::new(HashMap::new())),
            screen_proc: Arc::new(Mutex::new(None)),
            screen_audio_route: Arc::new(Mutex::new(None)),
        });

        let state = srv.clone();
        tokio::spawn(async move {
            let app = Router::new()
                .route("/media/{token}/{filename}", get(serve_media_file))
                .route("/hls/{id}/{filename}", get(serve_hls_file))
                .with_state(state);

            let bind_addr = format!("0.0.0.0:{port}");
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    info!("NixPlay LAN Media Server listening on http://{bind_addr}");
                    if let Err(e) = axum::serve(listener, app).await {
                        warn!("LAN Media Server error: {e}");
                    }
                }
                Err(e) => {
                    warn!("Could not bind LAN Media Server on {bind_addr}: {e}");
                }
            }
        });

        srv
    }

    /// Detect our best LAN IPv4 address (skipping loopback, link-local, and Tailscale/CGNAT 100.64.0.0/10)
    /// so Apple TV can reach our local media server directly over Wi-Fi / Ethernet.
    pub fn lan_ip() -> IpAddr {
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in &ifaces {
                if iface.is_loopback() {
                    continue;
                }
                if let IpAddr::V4(v4) = iface.ip() {
                    let o = v4.octets();
                    let is_cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
                    let is_link_local = o[0] == 169 && o[1] == 254;
                    if !is_cgnat && !is_link_local {
                        return IpAddr::V4(v4);
                    }
                }
            }
        }
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    pub fn has_ffmpeg() -> bool {
        std::process::Command::new("ffmpeg")
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Prefer a user-local, up-to-date yt-dlp (installed by `install.sh` into `~/.local/bin`)
    /// over the distro package, which is usually far too old for YouTube.
    pub fn ytdlp_bin() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            let local = home.join(".local/bin/yt-dlp");
            if local.is_file() {
                return local;
            }
        }
        PathBuf::from("yt-dlp")
    }

    pub fn has_ytdlp() -> bool {
        std::process::Command::new(Self::ytdlp_bin())
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Resolve YouTube, Vimeo, Twitch, Reddit, or other supported streaming page URLs
    /// into a direct Apple-TV-compatible MP4/HLS stream URL + video title using `yt-dlp`.
    /// Direct `.mp4`/`.mov`/`.m4v`/`.m3u8`/`.ts` URLs are returned unchanged.
    pub async fn resolve_streaming_url(url: &str) -> Result<(String, Option<String>)> {
        let trimmed = url.trim();
        let path_part = trimmed.split('?').next().unwrap_or(trimmed).to_lowercase();
        let is_direct_media = path_part.ends_with(".mp4")
            || path_part.ends_with(".m4v")
            || path_part.ends_with(".mov")
            || path_part.ends_with(".m3u8")
            || path_part.ends_with(".ts")
            || path_part.ends_with(".mp3")
            || path_part.ends_with(".m4a");

        if is_direct_media || !Self::has_ytdlp() {
            return Ok((trimmed.to_string(), None));
        }

        info!("Resolving streaming URL via yt-dlp: {}", trimmed);
        // Prefer H.264 HLS: Apple TV's AVPlayer handles the HLS *master* manifest natively
        // (adaptive bitrate + separate audio rendition). YouTube no longer serves muxed
        // progressive MP4s, so its only Apple-playable option is the visionOS/iOS HLS manifest.
        let out = Command::new(Self::ytdlp_bin())
            .args([
                "--no-playlist",
                "--no-warnings",
                "-f",
                "best[protocol^=m3u8][vcodec^=avc]/bv*[protocol^=m3u8][vcodec^=avc]\
                 /best[ext=mp4][vcodec^=avc][acodec!=none]/best[ext=mp4][acodec!=none]\
                 /best[protocol^=m3u8]/best",
                "--print",
                "title",
                "--print",
                "url",
                "--print",
                "%(manifest_url)s",
                "--print",
                "%(protocol)s",
                trimmed,
            ])
            .output()
            .await
            .context("failed to run yt-dlp")?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            warn!("yt-dlp resolution failed ({}), falling back to raw URL", err.trim());
            return Ok((trimmed.to_string(), None));
        }

        let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
            .unwrap_or("")
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        let is_http = |l: &str| l.starts_with("http://") || l.starts_with("https://");
        if lines.len() >= 2 && is_http(lines[1]) {
            let title = lines[0].to_string();
            // For HLS formats hand Apple TV the master manifest (has audio + all variants)
            // rather than a single video-only variant playlist.
            let is_hls = lines.get(3).is_some_and(|p| p.starts_with("m3u8"));
            let resolved = match lines.get(2) {
                Some(m) if is_hls && is_http(m) => m.to_string(),
                _ => lines[1].to_string(),
            };
            info!("Resolved '{}' -> direct stream URL", title);
            Ok((resolved, Some(title)))
        } else if let Some(first_url) = lines
            .iter()
            .find(|l| l.starts_with("http://") || l.starts_with("https://"))
        {
            Ok(((*first_url).to_string(), None))
        } else {
            Ok((trimmed.to_string(), None))
        }
    }

    /// Register a local video file and return its LAN HTTP URL for AirPlay `POST /play`.
    pub async fn register_file(&self, path: PathBuf) -> Result<(String, String)> {
        if !path.exists() {
            bail!("File does not exist: {}", path.display());
        }
        let token = uuid::Uuid::new_v4().simple().to_string();
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("video.mp4")
            .to_string();
        let safe_name: String = filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        self.files.write().await.insert(token.clone(), path);
        let url = format!("http://{}:{}/media/{}/{}", Self::lan_ip(), self.port, token, safe_name);
        Ok((url, filename))
    }

    /// Save uploaded bytes to a temporary cache file and register it for AirPlay playback.
    pub async fn save_uploaded_file(&self, filename: &str, bytes: &[u8]) -> Result<(String, String)> {
        let dir = std::env::temp_dir().join("nixplay-uploads");
        tokio::fs::create_dir_all(&dir).await?;
        let safe: String = filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let id = uuid::Uuid::new_v4().simple().to_string();
        let path = dir.join(format!("{id}-{safe}"));
        tokio::fs::write(&path, bytes).await?;
        self.register_file(path).await
    }

    /// Start live X11 screen capture + optional desktop audio via FFmpeg -> low-latency HLS.
    /// Returns the LAN `.m3u8` URL once the first HLS segment is ready.
    pub async fn start_screen_hls(&self, audio: ScreenAudio, fps: u32) -> Result<String> {
        if !Self::has_ffmpeg() {
            bail!(
                "ffmpeg is required for live screen casting. Install it with: sudo apt install ffmpeg"
            );
        }

        // Stop any existing screen cast first
        self.stop_screen_hls().await;

        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("nixplay-hls-{id}"));
        tokio::fs::create_dir_all(&dir).await?;

        let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0.0".to_string());
        let (width, height) = detect_screen_size().await.unwrap_or((1280, 720));
        // Cap width at 1920 and ensure even dimensions for H.264 yuv420p
        let video_size = format!("{}x{}", width & !1, height & !1);
        let playlist = dir.join("stream.m3u8");
        let seg_pattern = dir.join("seg_%04d.ts");

        // Quarter-second segments with a keyframe at every boundary: AVPlayer buffers ~3
        // segments before starting, so short segments cut glass-to-glass delay
        // (measured on tvOS 27: ~2.5s with 1s segments, ~2.0s at 0.5s, ~1.3-1.7s at 0.25s).
        const SEG_SECS: f64 = 0.25;
        let gop = ((fps as f64 * SEG_SECS).round() as u32).max(1).to_string();
        let seg_str = SEG_SECS.to_string();

        let mut cmd = Command::new("ffmpeg");
        cmd.args([
            "-y",
            "-hide_banner",
            "-loglevel",
            "warning",
            // Don't buffer/probe the live inputs before encoding starts
            "-fflags",
            "nobuffer",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-thread_queue_size",
            "64",
            "-f",
            "x11grab",
            "-framerate",
            &fps.to_string(),
            "-video_size",
            &video_size,
            "-i",
            &display,
        ]);

        // Desktop audio plays on the TV only: route it into a silent sink and capture that
        // sink's monitor (falling back to the speakers' monitor if the sink can't be made).
        // "default" is the microphone. 20ms fragments keep PulseAudio/PipeWire from
        // buffering audio, which would otherwise hold back muxing of the video too.
        let desktop_source = if audio.is_enabled() {
            match ScreenAudioRoute::activate().await {
                Ok(route) => {
                    *self.screen_audio_route.lock().await = Some(route);
                    SCREEN_SINK_MONITOR
                }
                Err(e) => {
                    warn!("Could not move desktop audio off the local speakers ({e:#})");
                    "@DEFAULT_MONITOR@"
                }
            }
        } else {
            "@DEFAULT_MONITOR@"
        };
        let pulse_sources: Vec<&str> = match audio {
            ScreenAudio::Desktop => vec![desktop_source],
            ScreenAudio::DesktopAndMic => vec![desktop_source, "default"],
            ScreenAudio::None => vec![],
        };
        for source in &pulse_sources {
            cmd.args([
                "-thread_queue_size",
                "64",
                "-f",
                "pulse",
                "-fragment_size",
                "3840",
                "-i",
                source,
            ]);
        }
        if audio == ScreenAudio::DesktopAndMic {
            cmd.args([
                "-filter_complex",
                "[1:a][2:a]amix=inputs=2:duration=longest:normalize=0[aout]",
                "-map",
                "0:v",
                "-map",
                "[aout]",
            ]);
        }

        cmd.args([
            "-vf",
            "scale=min(1920\\,iw):-2,format=yuv420p",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-profile:v",
            "main",
            "-level",
            "4.0",
            "-b:v",
            "6000k",
            "-maxrate",
            "8000k",
            "-bufsize",
            "12000k",
            "-g",
            &gop,
            "-keyint_min",
            &gop,
            "-sc_threshold",
            "0",
        ]);

        if audio.is_enabled() {
            cmd.args(["-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-ac", "2"]);
        } else {
            cmd.arg("-an");
        }

        cmd.args([
            "-f",
            "hls",
            "-muxdelay",
            "0",
            "-muxpreload",
            "0",
            "-hls_time",
            &seg_str,
            "-hls_list_size",
            "12",
            "-hls_flags",
            "delete_segments+independent_segments+omit_endlist",
            "-hls_segment_filename",
            seg_pattern.to_str().unwrap_or("seg_%04d.ts"),
            playlist.to_str().unwrap_or("stream.m3u8"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .context("failed to start ffmpeg for screen casting")?;

        // Drain ffmpeg's stderr: an unread pipe fills up and stalls the encoder mid-cast.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut lines = tokio::io::BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    warn!("ffmpeg: {line}");
                }
            });
        }

        self.hls_dirs.write().await.insert(id.clone(), dir.clone());
        *self.screen_proc.lock().await = Some((id.clone(), child, dir.clone()));

        // Wait up to 8s for ffmpeg to produce stream.m3u8 with at least 1 .ts segment
        for _ in 0..40 {
            if let Ok(content) = tokio::fs::read_to_string(&playlist).await {
                if content.contains(".ts") {
                    let url = format!(
                        "http://{}:{}/hls/{}/stream.m3u8",
                        Self::lan_ip(),
                        self.port,
                        id
                    );
                    info!("Live screen HLS ready at {url} ({video_size} @ {fps}fps)");
                    return Ok(url);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        self.stop_screen_hls().await;
        bail!("Timed out waiting for ffmpeg to initialize HLS screen stream (check DISPLAY and ffmpeg x11grab support)");
    }

    /// Stop the screen capture only if `media_url` is the stream it serves, so a finishing
    /// session can't kill a capture that was started for the next cast.
    pub async fn stop_screen_hls_for(&self, media_url: &str) {
        let mut guard = self.screen_proc.lock().await;
        if guard.as_ref().is_some_and(|(id, _, _)| media_url.contains(&format!("/hls/{id}/"))) {
            if let Some(proc) = guard.take() {
                drop(guard);
                self.finish_screen(Some(proc)).await;
            }
        }
    }

    pub async fn stop_screen_hls(&self) {
        let proc = self.screen_proc.lock().await.take();
        self.finish_screen(proc).await;
    }

    async fn finish_screen(&self, proc: Option<(String, Child, PathBuf)>) {
        if let Some((id, mut child, dir)) = proc {
            let _ = child.kill().await;
            self.hls_dirs.write().await.remove(&id);
            let _ = tokio::fs::remove_dir_all(&dir).await;
            info!("Stopped live screen HLS capture");
        }
        if let Some(route) = self.screen_audio_route.lock().await.take() {
            route.restore().await;
        }
    }
}

/// Start offset encoded in a share link: YouTube-style `?t=123`, `?t=1h2m3s`, `&start=90`,
/// or a `#t=2m` fragment (also used by Vimeo/Twitch). Returns seconds.
pub fn start_time_from_url(url: &str) -> Option<f64> {
    let (_, tail) = url.split_once(['?', '#'])?;
    tail.split(['&', '?', '#'])
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| matches!(*k, "t" | "start" | "time_continue"))
        .find_map(|(_, v)| parse_timecode(v))
        .filter(|secs| *secs > 0.0)
}

fn parse_timecode(v: &str) -> Option<f64> {
    let v = v.trim();
    if let Ok(secs) = v.trim_end_matches('s').parse::<f64>() {
        return Some(secs);
    }
    // 1h2m3s / 2m / 01h02m03s
    let (mut total, mut num) = (0.0f64, String::new());
    for c in v.chars() {
        match c {
            '0'..='9' | '.' => num.push(c),
            'h' | 'm' | 's' => {
                let n: f64 = num.parse().ok()?;
                total += n * match c { 'h' => 3600.0, 'm' => 60.0, _ => 1.0 };
                num.clear();
            }
            _ => return None,
        }
    }
    if !num.is_empty() {
        total += num.parse::<f64>().ok()?;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::start_time_from_url;

    #[test]
    fn parses_share_link_timecodes() {
        let t = |u: &str| start_time_from_url(u);
        assert_eq!(t("https://www.youtube.com/watch?v=abc&t=123"), Some(123.0));
        assert_eq!(t("https://youtu.be/abc?t=123s"), Some(123.0));
        assert_eq!(t("https://www.youtube.com/watch?v=abc&t=1h2m3s"), Some(3723.0));
        assert_eq!(t("https://vimeo.com/123#t=2m"), Some(120.0));
        assert_eq!(t("https://www.youtube.com/embed/abc?start=90"), Some(90.0));
        assert_eq!(t("https://www.youtube.com/watch?v=abc"), None);
        assert_eq!(t("https://example.com/video.mp4?token=xyz&t=0"), None);
        assert_eq!(t("https://example.com/watch?v=abc&tab=1"), None);
    }
}

async fn detect_screen_size() -> Option<(u32, u32)> {
    let out = Command::new("xrandr").arg("--current").output().await.ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains('*') {
            if let Some(res) = line.split_whitespace().next() {
                if let Some((w, h)) = res.split_once('x') {
                    if let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) {
                        return Some((w, h));
                    }
                }
            }
        }
    }
    None
}

fn mime_for_path(path: &FsPath) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .as_deref()
    {
        Some("mp4") | Some("m4v") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mkv") => "video/x-matroska",
        Some("webm") => "video/webm",
        Some("m3u8") => "application/vnd.apple.mpegurl",
        Some("ts") => "video/mp2t",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("flac") => "audio/flac",
        _ => "application/octet-stream",
    }
}

/// Serve a registered local video/audio file with full HTTP `Range` (206 Partial Content) support.
async fn serve_media_file(
    State(srv): State<Arc<MediaServer>>,
    Path((token, _filename)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let path = { srv.files.read().await.get(&token).cloned() };
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    stream_file_with_ranges(&path, &headers, false).await
}

/// Serve HLS playlists and transport stream segments (no-cache so live Apple TV playback stays fresh).
async fn serve_hls_file(
    State(srv): State<Arc<MediaServer>>,
    Path((id, filename)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    // Reject path traversal
    if filename.contains('/') || filename.contains("..") || filename.contains('\\') {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let dir = { srv.hls_dirs.read().await.get(&id).cloned() };
    let Some(dir) = dir else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tracing::debug!("HLS GET {filename}");
    let path = dir.join(&filename);
    if filename.ends_with(".m3u8") {
        // ffmpeg rounds the target duration of sub-second segments down to 0, which makes
        // the playlist invalid for AVPlayer. Serve it with the spec minimum of 1 instead.
        let Ok(text) = tokio::fs::read_to_string(&path).await else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let text = text.replace("#EXT-X-TARGETDURATION:0\n", "#EXT-X-TARGETDURATION:1\n");
        return (
            [
                (header::CONTENT_TYPE, "application/vnd.apple.mpegurl"),
                (header::CACHE_CONTROL, "no-cache, no-store"),
            ],
            text,
        )
            .into_response();
    }
    stream_file_with_ranges(&path, &headers, true).await
}

async fn stream_file_with_ranges(path: &FsPath, headers: &HeaderMap, no_cache: bool) -> Response {
    let Ok(mut file) = File::open(path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(meta) = file.metadata().await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let total_len = meta.len();
    let mime = mime_for_path(path);

    let mut start = 0u64;
    let mut end = total_len.saturating_sub(1);
    let mut is_partial = false;

    if let Some(range_val) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some(spec) = range_val.strip_prefix("bytes=") {
            if let Some((s, e)) = spec.split_once('-') {
                let s_parsed = s.trim().parse::<u64>().ok();
                let e_parsed = e.trim().parse::<u64>().ok();
                match (s_parsed, e_parsed) {
                    (Some(sv), Some(ev)) => {
                        start = sv;
                        end = ev.min(total_len.saturating_sub(1));
                        is_partial = true;
                    }
                    (Some(sv), None) => {
                        start = sv;
                        end = total_len.saturating_sub(1);
                        is_partial = true;
                    }
                    (None, Some(suffix)) => {
                        start = total_len.saturating_sub(suffix);
                        end = total_len.saturating_sub(1);
                        is_partial = true;
                    }
                    _ => {}
                }
            }
        }
    }

    if total_len == 0 {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())
            .unwrap();
    }

    if start > end || start >= total_len {
        return Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{total_len}"))
            .body(Body::empty())
            .unwrap();
    }

    // Cap single range chunk reads to 4 MiB for snappy seeking & low RAM
    let chunk_len = (end - start + 1).min(4 * 1024 * 1024);
    let actual_end = start + chunk_len - 1;

    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut buf = vec![0u8; chunk_len as usize];
    if file.read_exact(&mut buf).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let status = if is_partial || actual_end + 1 < total_len {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, chunk_len);

    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{actual_end}/{total_len}"),
        );
    }
    if no_cache {
        builder = builder.header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        );
    }

    builder.body(Body::from(buf)).unwrap()
}
