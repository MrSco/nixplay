/// AirPlay 2 Video Casting engine supporting BOTH:
/// - Modern Apple TV (tvOS 18 / 26 / 27): PTP session + Remote Control Session (type 130) +
///   `POST /command` Play Queue (`insertPlayQueueItem`, `setProperty`, `setRate`, `seek`) +
///   real-time `playbackState` events over the reverse EventChannel.
/// - Legacy AirPlay 2 receivers: fallback to `POST /play` + `GET /playback-info`.
///
/// Supports casting:
/// - YouTube / Vimeo / Twitch / 1000+ sites (auto-resolved via `yt-dlp` when installed)
/// - Direct web video & HLS (`.m3u8`) URLs
/// - Local video files served via `MediaServer` (with HTTP Range seeking)
/// - Live Linux desktop / Steam Deck screen capture via FFmpeg -> HLS

use super::airplay2::run_ntp_timing_responder;
use super::auth::{connect_and_authenticate, spawn_events_channel};
use super::rtsp::RtspClient;
use crate::config::AppConfig;
use crate::discovery::{AirPlayDevice, DiscoveryService};
use super::mirror::{run_mirror_session, MirrorOptions};
use crate::media_server::MediaServer;
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Identifies a remote control session (type 130, controlType 1) for modern tvOS video play queue.
const RCS_CLIENT_TYPE_UUID: &str = "A6B27562-B43A-4F2D-B75F-82391E250194";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoCastState {
    Idle,
    Connecting,
    Playing,
    Paused,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoCastStatus {
    pub state: VideoCastState,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub title: String,
    pub source_kind: String, // "url" | "file" | "screen" | ""
    pub url: Option<String>,
    pub duration: f64,
    pub position: f64,
    pub rate: f64,
    pub error: Option<String>,
    pub ffmpeg_available: bool,
    pub ytdlp_available: bool,
}

impl Default for VideoCastStatus {
    fn default() -> Self {
        Self {
            state: VideoCastState::Idle,
            device_id: None,
            device_name: None,
            title: String::new(),
            source_kind: String::new(),
            url: None,
            duration: 0.0,
            position: 0.0,
            rate: 0.0,
            error: None,
            ffmpeg_available: MediaServer::has_ffmpeg(),
            ytdlp_available: MediaServer::has_ytdlp(),
        }
    }
}

enum VideoCommand {
    SetRate(f64),
    Seek(f64),
    Stop,
}

pub struct VideoCastManager {
    discovery: Arc<DiscoveryService>,
    config: Arc<RwLock<AppConfig>>,
    pub media: Arc<MediaServer>,
    status: Arc<RwLock<VideoCastStatus>>,
    active_cmd: Arc<RwLock<Option<mpsc::Sender<VideoCommand>>>>,
    /// Stop signal for a running real-time mirroring session.
    mirror_stop: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    /// Bumped whenever a mirroring session starts or is stopped, so a finishing
    /// session never overwrites the status of whatever replaced it.
    mirror_gen: Arc<AtomicU64>,
    /// The running mirroring task, so `stop()` can wait for it to restore audio routing.
    mirror_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    change_tx: broadcast::Sender<()>,
}

impl VideoCastManager {
    pub fn new(
        discovery: Arc<DiscoveryService>,
        config: Arc<RwLock<AppConfig>>,
        media: Arc<MediaServer>,
        change_tx: broadcast::Sender<()>,
    ) -> Arc<Self> {
        Arc::new(Self {
            discovery,
            config,
            media,
            status: Arc::new(RwLock::new(VideoCastStatus::default())),
            active_cmd: Arc::new(RwLock::new(None)),
            mirror_stop: Arc::new(RwLock::new(None)),
            mirror_gen: Arc::new(AtomicU64::new(0)),
            mirror_task: Arc::new(RwLock::new(None)),
            change_tx,
        })
    }

    pub async fn status(&self) -> VideoCastStatus {
        self.status.read().await.clone()
    }

    fn notify(&self) {
        let _ = self.change_tx.send(());
    }

    /// Cast a direct HTTP/HTTPS/HLS URL — or a YouTube/Vimeo/Twitch page URL (auto-resolved via yt-dlp).
    pub async fn cast_url(
        self: &Arc<Self>,
        device_id: &str,
        url: String,
        title: Option<String>,
        source_kind: &str,
        start_pos: f64,
    ) -> Result<()> {
        let device = self
            .discovery
            .get(device_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("receiver '{}' not found", device_id))?;

        // Stop any previous cast — but keep the screen capture that `cast_screen` just started.
        self.stop_inner(source_kind != "screen").await;

        let (resolved_url, resolved_title) = if source_kind == "url" {
            MediaServer::resolve_streaming_url(&url).await?
        } else {
            (url.clone(), None)
        };
        // Honor share-link timecodes like YouTube's `?t=123` when no explicit start was given.
        let start_pos = match crate::media_server::start_time_from_url(&url) {
            Some(t) if source_kind == "url" && start_pos <= 0.0 => t,
            _ => start_pos,
        };

        let display_title = title
            .or(resolved_title)
            .unwrap_or_else(|| {
                url.rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&url)
                    .to_string()
            });

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        *self.active_cmd.write().await = Some(cmd_tx);

        {
            let mut st = self.status.write().await;
            st.state = VideoCastState::Connecting;
            st.device_id = Some(device.id.clone());
            st.device_name = Some(device.name.clone());
            st.title = display_title;
            st.source_kind = source_kind.to_string();
            st.url = Some(resolved_url.clone());
            st.duration = 0.0;
            st.position = start_pos;
            st.rate = 0.0;
            st.error = None;
        }
        self.notify();

        let creds = {
            let cfg = self.config.read().await;
            cfg.device_prefs(&device.id).hap_credentials
        };

        let mgr = self.clone();
        tokio::spawn(async move {
            if let Err(e) = run_video_session(
                mgr.clone(),
                device.clone(),
                creds,
                resolved_url.clone(),
                start_pos,
                cmd_rx,
            )
            .await
            {
                error!("Video cast error on '{}': {e:#}", device.name);
                {
                    let mut st = mgr.status.write().await;
                    st.state = VideoCastState::Error;
                    st.error = Some(format!("{e}"));
                }
                mgr.media.stop_screen_hls_for(&resolved_url).await;
            }
            *mgr.active_cmd.write().await = None;
            mgr.notify();
        });

        Ok(())
    }

    /// Cast a local video file (MP4, MOV, M4V, etc.) via our built-in LAN HTTP server.
    pub async fn cast_file(self: &Arc<Self>, device_id: &str, file_path: PathBuf) -> Result<()> {
        let (url, name) = self.media.register_file(file_path).await?;
        self.cast_url(device_id, url, Some(name), "file", 0.0).await
    }

    /// Cast the live Linux desktop / Steam Deck screen. Uses real AirPlay screen mirroring
    /// (~40–100ms delay) when the receiver supports it, otherwise falls back to FFmpeg -> HLS.
    pub async fn cast_screen(
        self: &Arc<Self>,
        device_id: &str,
        opts: MirrorOptions,
    ) -> Result<()> {
        self.stop().await;
        let device = self
            .discovery
            .get(device_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("receiver '{}' not found", device_id))?;
        match self.start_mirroring(&device, opts.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => warn!(
                "Real-time mirroring unavailable on '{}' ({e:#}); falling back to HLS screen cast",
                device.name
            ),
        }
        let url = self.media.start_screen_hls(opts.audio, opts.fps).await?;
        self.cast_url(
            device_id,
            url,
            Some("Linux Screen (Live HLS)".to_string()),
            "screen",
            0.0,
        )
        .await
    }

    async fn start_mirroring(
        self: &Arc<Self>,
        device: &AirPlayDevice,
        opts: MirrorOptions,
    ) -> Result<()> {
        let creds = {
            let cfg = self.config.read().await;
            cfg.device_prefs(&device.id).hap_credentials
        };
        {
            let mut st = self.status.write().await;
            st.state = VideoCastState::Connecting;
            st.device_id = Some(device.id.clone());
            st.device_name = Some(device.name.clone());
            st.title = "Linux Screen (Mirroring)".to_string();
            st.source_kind = "screen".to_string();
            st.url = None;
            st.duration = 0.0;
            st.position = 0.0;
            st.rate = 0.0;
            st.error = None;
        }
        self.notify();

        let gen = self.mirror_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        *self.mirror_stop.write().await = Some(stop_tx);

        let mgr = self.clone();
        let dev = device.clone();
        let task = tokio::spawn(async move {
            let res = run_mirror_session(dev.clone(), creds, opts, stop_rx, ready_tx).await;
            if mgr.mirror_gen.load(Ordering::SeqCst) != gen {
                return; // stopped or replaced; status already belongs to someone else
            }
            *mgr.mirror_stop.write().await = None;
            {
                let mut st = mgr.status.write().await;
                match res {
                    Err(e) => {
                        error!("Screen mirroring on '{}' failed: {e:#}", dev.name);
                        st.state = VideoCastState::Error;
                        st.error = Some(format!("{e}"));
                    }
                    Ok(()) => {
                        st.state = VideoCastState::Idle;
                        st.device_id = None;
                        st.device_name = None;
                        st.title.clear();
                        st.source_kind.clear();
                    }
                }
            }
            mgr.notify();
        });
        *self.mirror_task.write().await = Some(task);

        let outcome = match tokio::time::timeout(Duration::from_secs(30), ready_rx).await {
            Ok(Ok(Ok(_streaming))) => Ok(()),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(anyhow::anyhow!("mirroring session ended during setup")),
            Err(_) => Err(anyhow::anyhow!("timed out waiting for the first mirrored frame")),
        };
        match outcome {
            Ok(()) => {
                {
                    let mut st = self.status.write().await;
                    st.state = VideoCastState::Playing;
                    st.rate = 1.0;
                }
                self.notify();
                Ok(())
            }
            Err(e) => {
                // Invalidate the session so its exit doesn't clobber the fallback's status.
                self.mirror_gen.fetch_add(1, Ordering::SeqCst);
                if let Some(tx) = self.mirror_stop.write().await.take() {
                    let _ = tx.try_send(());
                }
                Err(e)
            }
        }
    }

    pub async fn set_rate(&self, rate: f64) {
        if let Some(ref tx) = *self.active_cmd.read().await {
            let _ = tx.send(VideoCommand::SetRate(rate)).await;
        }
    }

    pub async fn seek(&self, position: f64) {
        if let Some(ref tx) = *self.active_cmd.read().await {
            let _ = tx.send(VideoCommand::Seek(position)).await;
        }
    }

    pub async fn stop(&self) {
        self.stop_inner(true).await;
    }

    async fn stop_inner(&self, stop_screen: bool) {
        if let Some(tx) = self.active_cmd.write().await.take() {
            let _ = tx.send(VideoCommand::Stop).await;
        }
        if let Some(tx) = self.mirror_stop.write().await.take() {
            self.mirror_gen.fetch_add(1, Ordering::SeqCst);
            let _ = tx.try_send(());
        }
        // Wait briefly for the session to hand desktop audio back to the speakers.
        if let Some(task) = self.mirror_task.write().await.take() {
            let _ = tokio::time::timeout(Duration::from_secs(4), task).await;
        }
        if stop_screen {
            self.media.stop_screen_hls().await;
        }
        {
            let mut st = self.status.write().await;
            if st.state != VideoCastState::Idle {
                st.state = VideoCastState::Idle;
                st.device_id = None;
                st.device_name = None;
                st.title.clear();
                st.source_kind.clear();
                st.url = None;
                st.duration = 0.0;
                st.position = 0.0;
                st.rate = 0.0;
                st.error = None;
            }
        }
        self.notify();
    }
}

async fn send_rcs_command(
    rtsp: &mut RtspClient,
    rcs_stream_id: u64,
    command: plist::Dictionary,
) -> Result<super::rtsp::RtspResponse> {
    let mut inner_bytes = Vec::new();
    plist::to_writer_binary(&mut inner_bytes, &plist::Value::Dictionary(command))
        .context("failed to encode inner command plist")?;

    let mut params = plist::Dictionary::new();
    params.insert("data".into(), plist::Value::Data(inner_bytes));
    let mut outer = plist::Dictionary::new();
    outer.insert("params".into(), plist::Value::Dictionary(params));

    let stream_id_str = rcs_stream_id.to_string();
    let headers = [
        ("X-Apple-StreamID", stream_id_str.as_str()),
        ("User-Agent", "AirPlay/960.13.1"),
    ];
    rtsp.request_http_plist("POST", "/command", &headers, &plist::Value::Dictionary(outer))
        .await
}

async fn run_video_session(
    mgr: Arc<VideoCastManager>,
    device: AirPlayDevice,
    creds: Option<crate::config::HapCredentials>,
    media_url: String,
    start_pos: f64,
    mut cmd_rx: mpsc::Receiver<VideoCommand>,
) -> Result<()> {
    let conn = connect_and_authenticate(&device, creds.as_ref()).await?;
    let mut rtsp = conn.rtsp;
    let target_ip = conn.target_ip;
    let target_scope = conn.target_scope;
    let shared_secret = conn.shared_secret;

    let local_ip = rtsp.local_addr()?.ip();
    let session_id: u32 = rand::random();
    let client_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let item_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let session_uri = match local_ip {
        IpAddr::V4(v4) => format!("rtsp://{v4}/{session_id}"),
        IpAddr::V6(v6) => format!("rtsp://[{v6}]/{session_id}"),
    };
    let device_mac = format!(
        "AA:BB:CC:{:02X}:{:02X}:{:02X}",
        (session_id >> 16) as u8,
        (session_id >> 8) as u8,
        session_id as u8
    );

    // 1. Try modern PTP video session SETUP (required for tvOS 18/26/27 play queue & events!)
    let mut peer = plist::Dictionary::new();
    peer.insert("ID".into(), plist::Value::String(client_uuid.clone()));
    peer.insert(
        "Addresses".into(),
        plist::Value::Array(vec![plist::Value::String(local_ip.to_string())]),
    );
    peer.insert("DeviceType".into(), plist::Value::Integer(0u64.into()));
    peer.insert(
        "SupportsClockPortMatchingOverride".into(),
        plist::Value::Boolean(true),
    );
    let peer_val = plist::Value::Dictionary(peer);

    let mut ptp_setup = plist::Dictionary::new();
    ptp_setup.insert("timingProtocol".into(), plist::Value::String("PTP".into()));
    ptp_setup.insert("timingPeerInfo".into(), peer_val.clone());
    ptp_setup.insert("timingPeerList".into(), plist::Value::Array(vec![peer_val]));
    ptp_setup.insert(
        "sessionUUID".into(),
        plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
    );
    ptp_setup.insert(
        "sessionCorrelationUUID".into(),
        plist::Value::String(client_uuid.clone()),
    );
    ptp_setup.insert("updateSessionRequest".into(), plist::Value::Boolean(false));
    ptp_setup.insert("statsCollectionEnabled".into(), plist::Value::Boolean(false));
    ptp_setup.insert("isMultiSelectAirPlay".into(), plist::Value::Boolean(false));
    ptp_setup.insert("deviceID".into(), plist::Value::String(device_mac.clone()));
    ptp_setup.insert("macAddress".into(), plist::Value::String(device_mac.clone()));
    ptp_setup.insert("model".into(), plist::Value::String("iPhone14,3".into()));
    ptp_setup.insert("name".into(), plist::Value::String("NixPlay".into()));
    ptp_setup.insert("osName".into(), plist::Value::String("iPhone OS".into()));
    ptp_setup.insert("osVersion".into(), plist::Value::String("16.5".into()));
    ptp_setup.insert("osBuildVersion".into(), plist::Value::String("20F66".into()));
    ptp_setup.insert("sourceVersion".into(), plist::Value::String("690.7.1".into()));

    let mut timing_handle: Option<tokio::task::JoinHandle<()>> = None;
    let ptp_resp = rtsp
        .request_plist("SETUP", &session_uri, &[], &plist::Value::Dictionary(ptp_setup))
        .await
        .context("Video SETUP (PTP) failed")?;

    let (setup_resp, using_ptp) = if ptp_resp.status_code == 200 {
        (ptp_resp, true)
    } else {
        // Legacy fallback: NTP session SETUP for older receivers
        debug!(
            "PTP video SETUP returned {} on '{}'; falling back to NTP",
            ptp_resp.status_line, device.name
        );
        let bind_ip = match local_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        let timing_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
        let local_timing_port = timing_sock.local_addr()?.port();
        timing_handle = Some(tokio::spawn(async move {
            run_ntp_timing_responder(timing_sock).await;
        }));

        let mut ntp_setup = plist::Dictionary::new();
        ntp_setup.insert("deviceID".into(), plist::Value::String(device_mac.clone()));
        ntp_setup.insert("macAddress".into(), plist::Value::String(device_mac.clone()));
        ntp_setup.insert("name".into(), plist::Value::String("NixPlay".into()));
        ntp_setup.insert(
            "sessionUUID".into(),
            plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
        );
        ntp_setup.insert(
            "timingPort".into(),
            plist::Value::Integer((local_timing_port as u64).into()),
        );
        ntp_setup.insert("timingProtocol".into(), plist::Value::String("NTP".into()));
        let r = rtsp
            .request_plist("SETUP", &session_uri, &[], &plist::Value::Dictionary(ntp_setup))
            .await
            .context("Video SETUP (NTP fallback) failed")?;
        if r.status_code != 200 {
            if let Some(h) = timing_handle {
                h.abort();
            }
            bail!("Video SETUP rejected by '{}': {}", device.name, r.status_line);
        }
        (r, false)
    };

    let mut event_port: Option<u16> = None;
    if let Ok(pl) = setup_resp.body_plist() {
        debug!("Video SETUP reply from '{}': {:?}", device.name, pl);
        if let Some(dict) = pl.as_dictionary() {
            event_port = dict
                .get("eventPort")
                .and_then(|v| v.as_unsigned_integer())
                .map(|p| p as u16);
        }
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<plist::Value>();
    let events_handle = if let Some(ep) = event_port {
        spawn_events_channel(
            target_ip,
            ep,
            target_scope,
            shared_secret,
            device.name.clone(),
            Some(event_tx),
        )
        .await
    } else {
        None
    };

    // 2. RECORD (always sent before RCS setup)
    let _ = rtsp.request("RECORD", &session_uri, &[], None).await;

    // 3. Register Remote Control Session (type 130, controlType 1) for modern tvOS POST /command
    let mut rcs_stream_id: Option<u64> = None;
    if using_ptp {
        if let Ok(info_resp) = rtsp.request_http("GET", "/info", &[], None).await {
            if let Ok(info_pl) = info_resp.body_plist() {
                if let Some(psi) = info_pl
                    .as_dictionary()
                    .and_then(|d| d.get("psi"))
                    .and_then(|v| v.as_string())
                {
                    let mut rcs_stream = plist::Dictionary::new();
                    rcs_stream.insert("type".into(), plist::Value::Integer(130u64.into()));
                    rcs_stream.insert("controlType".into(), plist::Value::Integer(1u64.into()));
                    rcs_stream.insert(
                        "channelID".into(),
                        plist::Value::String(format!("{psi}-RCS-1")),
                    );
                    rcs_stream.insert(
                        "clientUUID".into(),
                        plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
                    );
                    rcs_stream.insert(
                        "clientTypeUUID".into(),
                        plist::Value::String(RCS_CLIENT_TYPE_UUID.into()),
                    );
                    let mut rcs_body = plist::Dictionary::new();
                    rcs_body.insert(
                        "streams".into(),
                        plist::Value::Array(vec![plist::Value::Dictionary(rcs_stream)]),
                    );
                    if let Ok(rcs_resp) = rtsp
                        .request_plist("SETUP", &session_uri, &[], &plist::Value::Dictionary(rcs_body))
                        .await
                    {
                        if rcs_resp.status_code == 200 {
                            if let Ok(pl) = rcs_resp.body_plist() {
                                debug!("RCS SETUP reply from '{}': {:?}", device.name, pl);
                                let sid = pl
                                    .as_dictionary()
                                    .and_then(|d| d.get("streams"))
                                    .and_then(|s| s.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|s| s.as_dictionary())
                                    .and_then(|d| d.get("streamID"))
                                    .and_then(|v| v.as_unsigned_integer())
                                    .unwrap_or(1);
                                rcs_stream_id = Some(sid);
                                info!("Established modern tvOS video control session (streamID={sid}) on '{}'", device.name);
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Launch playback via modern POST /command play queue OR legacy POST /play
    let session_uuid_lower = client_uuid.to_lowercase();
    let legacy_headers = [
        ("X-Apple-ProtocolVersion", "1"),
        ("X-Apple-Stream-ID", "1"),
        ("X-Apple-Session-ID", session_uuid_lower.as_str()),
    ];

    if let Some(sid) = rcs_stream_id {
        let mut start_time = plist::Dictionary::new();
        start_time.insert("flags".into(), plist::Value::Integer(1u64.into()));
        start_time.insert("value".into(), plist::Value::Integer((start_pos as i64).into()));
        start_time.insert("epoch".into(), plist::Value::Integer(0u64.into()));
        start_time.insert("timescale".into(), plist::Value::Integer(1u64.into()));

        let mut item = plist::Dictionary::new();
        item.insert("uuid".into(), plist::Value::String(item_uuid.clone()));
        item.insert("Content-Location".into(), plist::Value::String(media_url.clone()));
        item.insert("mediaType".into(), plist::Value::String("file".into()));
        item.insert(
            "IsTLSEnabled".into(),
            plist::Value::Boolean(media_url.starts_with("https://")),
        );
        item.insert("playbackRestrictions".into(), plist::Value::Integer(0u64.into()));
        item.insert("referenceRestrictions".into(), plist::Value::Integer(2u64.into()));
        item.insert("supportsIntegratedTimeline".into(), plist::Value::Boolean(false));
        item.insert("snapTimeToPausePlayback".into(), plist::Value::Boolean(false));
        item.insert("clientBundleID".into(), plist::Value::String("dev.nixplay".into()));
        item.insert("clientProcName".into(), plist::Value::String("nixplay".into()));
        // Must be <= 6 chars on tvOS 26/27!
        item.insert("playerLoggingID".into(), plist::Value::String("P/NXP".into()));
        item.insert(
            "playerItemLoggingID".into(),
            plist::Value::String("I/NIXPLAY.01".into()),
        );
        item.insert("Start-Position".into(), plist::Value::Dictionary(start_time));

        let mut insert_cmd = plist::Dictionary::new();
        insert_cmd.insert("type".into(), plist::Value::String("insertPlayQueueItem".into()));
        insert_cmd.insert("item".into(), plist::Value::Dictionary(item));

        let resp = send_rcs_command(&mut rtsp, sid, insert_cmd)
            .await
            .context("POST /command insertPlayQueueItem failed")?;
        if resp.status_code != 200 {
            if let Some(h) = timing_handle {
                h.abort();
            }
            if let Some(h) = events_handle {
                h.abort();
            }
            bail!(
                "insertPlayQueueItem rejected by '{}': {}",
                device.name,
                resp.status_line
            );
        }

        let mut item_ref = plist::Dictionary::new();
        item_ref.insert("uuid".into(), plist::Value::String(item_uuid.clone()));
        let mut prop_cmd = plist::Dictionary::new();
        prop_cmd.insert("type".into(), plist::Value::String("setProperty".into()));
        prop_cmd.insert(
            "property".into(),
            plist::Value::String("isInterestedInDateRange".into()),
        );
        prop_cmd.insert("value".into(), plist::Value::Boolean(true));
        prop_cmd.insert("item".into(), plist::Value::Dictionary(item_ref));
        let _ = send_rcs_command(&mut rtsp, sid, prop_cmd).await;

        let mut rate_cmd = plist::Dictionary::new();
        rate_cmd.insert("type".into(), plist::Value::String("setRate".into()));
        rate_cmd.insert("rate".into(), plist::Value::Real(1.0));
        let rate_resp = send_rcs_command(&mut rtsp, sid, rate_cmd).await?;
        debug!("setRate(1.0) -> {}", rate_resp.status_line);
    } else {
        // Legacy POST /play for pre-tvOS-18 receivers
        let mut play_dict = plist::Dictionary::new();
        play_dict.insert("Content-Location".into(), plist::Value::String(media_url.clone()));
        play_dict.insert("Start-Position-Seconds".into(), plist::Value::Real(start_pos));
        play_dict.insert("uuid".into(), plist::Value::String(session_uuid_lower.clone()));
        play_dict.insert("streamType".into(), plist::Value::Integer(1u64.into()));
        play_dict.insert("mediaType".into(), plist::Value::String("file".into()));
        play_dict.insert("rate".into(), plist::Value::Real(1.0));
        play_dict.insert("volume".into(), plist::Value::Real(1.0));

        let resp = rtsp
            .request_http_plist(
                "POST",
                "/play",
                &legacy_headers,
                &plist::Value::Dictionary(play_dict),
            )
            .await
            .context("legacy POST /play failed")?;
        if resp.status_code != 200 {
            if let Some(h) = timing_handle {
                h.abort();
            }
            if let Some(h) = events_handle {
                h.abort();
            }
            bail!("POST /play rejected by '{}': {}", device.name, resp.status_line);
        }
        let _ = rtsp
            .request("POST", "/rate?value=1.000000", &legacy_headers, None)
            .await;
    }

    info!("AirPlay 2 video playing on '{}': {}", device.name, media_url);
    {
        let mut st = mgr.status.write().await;
        st.state = VideoCastState::Playing;
        st.rate = 1.0;
    }
    mgr.notify();

    // 5. Event + feedback + transport control loop
    // (Feedback starts ONLY AFTER play commands are issued, matching tvOS 26/27 requirements!)
    let mut feedback_tick = tokio::time::interval(Duration::from_secs(2));
    let mut pos_tick = tokio::time::interval(Duration::from_secs(1));
    pos_tick.tick().await;
    let mut legacy_poll_tick = tokio::time::interval(Duration::from_millis(1500));
    let mut running = true;
    let mut played_seen = false;

    while running {
        tokio::select! {
            ev_opt = event_rx.recv() => {
                if let Some(ev) = ev_opt {
                    if let Some(dict) = ev.as_dictionary() {
                        let ev_type = dict.get("type").and_then(|v| v.as_string()).unwrap_or("");
                        let params = dict
                            .get("params")
                            .and_then(|v| v.as_dictionary())
                            .unwrap_or(dict);
                        match ev_type {
                            "playbackState" => {
                                let name = dict.get("name").and_then(|v| v.as_string()).unwrap_or("");
                                let duration = extract_cmtime_or_real(params.get("duration"));
                                let position = extract_cmtime_or_real(params.get("position"))
                                    .or_else(|| extract_cmtime_or_real(params.get("time")));
                                let rate = params.get("rate").and_then(|v| v.as_real());
                                info!("Apple TV playbackState: {name} (pos={position:?}, dur={duration:?}, rate={rate:?})");

                                let mut st = mgr.status.write().await;
                                if let Some(d) = duration {
                                    if d > 0.0 { st.duration = d; }
                                }
                                if let Some(p) = position {
                                    if p >= 0.0 { st.position = p; }
                                }
                                if let Some(r) = rate {
                                    st.rate = r;
                                }
                                match name {
                                    "playing" => {
                                        played_seen = true;
                                        st.state = VideoCastState::Playing;
                                        st.rate = rate.unwrap_or(1.0);
                                    }
                                    "paused" => {
                                        played_seen = true;
                                        st.state = VideoCastState::Paused;
                                        st.rate = 0.0;
                                    }
                                    "stopped" => {
                                        if played_seen {
                                            running = false;
                                        }
                                    }
                                    _ => {}
                                }
                                drop(st);
                                mgr.notify();
                            }
                            "notification" => {
                                let name = dict.get("name").and_then(|v| v.as_string()).unwrap_or("");
                                debug!("Apple TV notification: {name}");
                                if name == "itemPlayedToEnd" {
                                    info!("Video finished playing on '{}'", device.name);
                                    running = false;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ = pos_tick.tick() => {
                let mut st = mgr.status.write().await;
                if st.state == VideoCastState::Playing && st.rate > 0.01 {
                    st.position += st.rate;
                    if st.duration > 0.0 && st.position > st.duration {
                        st.position = st.duration;
                    }
                    drop(st);
                    mgr.notify();
                }
            }
            _ = feedback_tick.tick() => {
                if let Err(e) = rtsp.request("POST", "/feedback", &[], None).await {
                    debug!("Video feedback ended on '{}': {e}", device.name);
                    running = false;
                }
            }
            _ = legacy_poll_tick.tick(), if rcs_stream_id.is_none() => {
                if let Ok(resp) = rtsp.request_http("GET", "/playback-info", &legacy_headers, None).await {
                    if resp.status_code == 200 {
                        if let Ok(pl) = resp.body_plist() {
                            if let Some(dict) = pl.as_dictionary() {
                                let duration = dict.get("duration").and_then(|v| v.as_real()).unwrap_or(0.0);
                                let position = dict.get("position").and_then(|v| v.as_real()).unwrap_or(0.0);
                                let rate = dict.get("rate").and_then(|v| v.as_real()).unwrap_or(0.0);
                                if duration > 0.0 {
                                    let mut st = mgr.status.write().await;
                                    st.duration = duration;
                                    st.position = position;
                                    st.rate = rate;
                                    st.state = if rate > 0.01 { VideoCastState::Playing } else { VideoCastState::Paused };
                                    drop(st);
                                    mgr.notify();
                                }
                            }
                        }
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(VideoCommand::SetRate(rate)) => {
                        let ok = if let Some(sid) = rcs_stream_id {
                            let mut c = plist::Dictionary::new();
                            c.insert("type".into(), plist::Value::String("setRate".into()));
                            c.insert("rate".into(), plist::Value::Real(rate));
                            send_rcs_command(&mut rtsp, sid, c).await.is_ok()
                        } else {
                            let uri = format!("/rate?value={rate:.6}");
                            rtsp.request_http("POST", &uri, &legacy_headers, None).await.is_ok()
                        };
                        if ok {
                            let mut st = mgr.status.write().await;
                            st.rate = rate;
                            st.state = if rate > 0.01 { VideoCastState::Playing } else { VideoCastState::Paused };
                            drop(st);
                            mgr.notify();
                        }
                    }
                    Some(VideoCommand::Seek(pos)) => {
                        let ok = if let Some(sid) = rcs_stream_id {
                            let mut time_dict = plist::Dictionary::new();
                            time_dict.insert("flags".into(), plist::Value::Integer(1u64.into()));
                            time_dict.insert("value".into(), plist::Value::Integer(((pos * 1000.0) as i64).into()));
                            time_dict.insert("epoch".into(), plist::Value::Integer(0u64.into()));
                            time_dict.insert("timescale".into(), plist::Value::Integer(1000u64.into()));
                            let mut item_ref = plist::Dictionary::new();
                            item_ref.insert("uuid".into(), plist::Value::String(item_uuid.clone()));
                            let mut c = plist::Dictionary::new();
                            c.insert("type".into(), plist::Value::String("seek".into()));
                            c.insert("time".into(), plist::Value::Dictionary(time_dict));
                            c.insert("item".into(), plist::Value::Dictionary(item_ref));
                            send_rcs_command(&mut rtsp, sid, c).await.is_ok()
                        } else {
                            let uri = format!("/scrub?position={pos:.3}");
                            rtsp.request_http("POST", &uri, &legacy_headers, None).await.is_ok()
                        };
                        if ok {
                            let mut st = mgr.status.write().await;
                            st.position = pos;
                            drop(st);
                            mgr.notify();
                        }
                    }
                    Some(VideoCommand::Stop) | None => {
                        if let Some(sid) = rcs_stream_id {
                            let mut item_ref = plist::Dictionary::new();
                            item_ref.insert("uuid".into(), plist::Value::String(item_uuid.clone()));
                            let mut c = plist::Dictionary::new();
                            c.insert("type".into(), plist::Value::String("removePlayQueueItem".into()));
                            c.insert("item".into(), plist::Value::Dictionary(item_ref));
                            let _ = send_rcs_command(&mut rtsp, sid, c).await;
                        } else {
                            let _ = rtsp.request_http("POST", "/stop", &legacy_headers, None).await;
                        }
                        running = false;
                    }
                }
            }
        }
    }

    if let Some(h) = timing_handle {
        h.abort();
    }
    if let Some(h) = events_handle {
        h.abort();
    }
    let empty = plist::Value::Dictionary(plist::Dictionary::new());
    let _ = rtsp.request_plist("TEARDOWN", &session_uri, &[], &empty).await;
    mgr.media.stop_screen_hls_for(&media_url).await;

    {
        let mut st = mgr.status.write().await;
        if st.state != VideoCastState::Error {
            st.state = VideoCastState::Idle;
            st.device_id = None;
            st.device_name = None;
            st.title.clear();
            st.source_kind.clear();
            st.url = None;
            st.duration = 0.0;
            st.position = 0.0;
            st.rate = 0.0;
        }
    }
    mgr.notify();
    info!("AirPlay 2 video session closed for '{}'", device.name);
    Ok(())
}

/// Extract seconds from either a plist Real or an Apple CMTime dictionary `{value, timescale}`.
fn extract_cmtime_or_real(val: Option<&plist::Value>) -> Option<f64> {
    let v = val?;
    if let Some(r) = v.as_real() {
        return Some(r);
    }
    if let Some(d) = v.as_dictionary() {
        let num = d.get("value").and_then(|x| x.as_signed_integer())? as f64;
        let scale = d.get("timescale").and_then(|x| x.as_signed_integer())? as f64;
        if scale > 0.0 {
            return Some(num / scale);
        }
    }
    None
}
