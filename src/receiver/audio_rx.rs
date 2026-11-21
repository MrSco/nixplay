/// Pure-Rust in-process AirPlay 2 + AirPlay 1 (RAOP) Audio Receiver.
///
/// Zero external dependencies and zero Apple private key material:
/// - Advertises `_airplay._tcp.local.` (AirPlay 2 HAP audio receiver) and
///   `<MAC>@<Name>._raop._tcp.local.` (AirPlay 1 RAOP) via `mdns-sd`.
/// - Implements server-side HAP `pair-setup` (transient PIN "3939" or user-facing 4-digit PIN),
///   HAP `pair-verify` (remembered devices), and ChaCha20-Poly1305 encrypted RTSP.
/// - Decodes incoming ALAC (both compressed and verbatim) and L16 PCM frames in pure Rust,
///   applies volume attenuation, extracts DMAP Now Playing metadata + artwork + DACP headers,
///   and plays directly into PipeWire/PulseAudio via `pacat`.

use crate::airplay::hap::{
    tlv8_decode, tlv8_get, HapControlCipher, HapServerPairSetup, HapServerPairVerify, TLV_STATE,
};
use crate::config::ReceiverConfig;
use crate::receiver::alac_dec::{
    apply_airplay_volume_db, decode_alac_stereo_16, decode_l16_be_to_le,
};
use crate::receiver::dacp::DacpRemote;
use crate::receiver::{ReceivedTrack, ReceiverEvent};
use anyhow::{Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

const AIRPLAY_SERVICE: &str = "_airplay._tcp.local.";
const RAOP_SERVICE: &str = "_raop._tcp.local.";

/// AirPlay 2 audio-only receiver feature flags:
/// - Bit 9 (Audio)
/// - Bit 14 (MFi/FairPlay bit omitted for audio-only pure-HAP)
/// - Bit 19 (AudioMetaDataText)
/// - Bit 20 (AudioMetaDataArtwork)
/// - Bit 21 (AudioMetaDataProgress)
/// - Bit 27 (SupportsLegacyPairing / metadata)
/// - Bit 38 (SupportsUnifiedMediaControl / AirPlay2)
/// - Bit 40 (SupportsBufferedAudio)
/// - Bit 46 (HomeKitPairing)
/// - Bit 48 (SupportsTransientPairing)
/// - Bit 51 (SupportsUnifiedPairSetupAndMFi)
const FEATURES_LO: u32 = (1 << 9) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 30);
const FEATURES_HI: u32 = (1 << (38 - 32)) | (1 << (46 - 32)) | (1 << (48 - 32));

pub struct BuiltinAudioReceiver {
    port: u16,
    stop_tx: mpsc::Sender<()>,
    disconnect_tx: mpsc::Sender<()>,
    mdns: Option<ServiceDaemon>,
    task: tokio::task::JoinHandle<()>,
}

impl BuiltinAudioReceiver {
    pub async fn start(
        cfg: ReceiverConfig,
        server_sk: SigningKey,
        device_id: String,
        paired_clients: Arc<RwLock<HashMap<String, String>>>,
        event_tx: mpsc::UnboundedSender<ReceiverEvent>,
        preferred_port: Option<u16>,
        advertise_mdns: bool,
    ) -> Result<Self> {
        let listener = match preferred_port {
            Some(p) => TcpListener::bind(("0.0.0.0", p))
                .await
                .with_context(|| format!("bind AirPlay receiver on port {p}"))?,
            None => match TcpListener::bind(("0.0.0.0", 7000)).await {
                Ok(l) => l,
                Err(_) => TcpListener::bind(("0.0.0.0", 0))
                    .await
                    .context("bind AirPlay receiver on ephemeral port")?,
            },
        };
        let port = listener.local_addr()?.port();
        let pk_hex = hex::encode(server_sk.verifying_key().to_bytes());
        let pi_uuid = uuid::Uuid::new_v4().to_string();

        let mdns = if advertise_mdns {
            match register_mdns(&cfg.name, &device_id, &pk_hex, &pi_uuid, port, cfg.pin_mode) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!("Could not register AirPlay receiver mDNS advertisements: {e:#}");
                    None
                }
            }
        } else {
            None
        };

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let (disconnect_tx, mut disconnect_rx) = mpsc::channel::<()>(4);

        info!(
            "Built-in AirPlay 2 / RAOP audio receiver listening on port {port} as '{}'",
            cfg.name
        );
        let _ = event_tx.send(ReceiverEvent::Listening);

        let shared = Arc::new(ServerShared {
            cfg,
            server_sk,
            device_id,
            pi_uuid,
            paired_clients,
            event_tx: event_tx.clone(),
            active_session_cancel: Mutex::new(None),
        });

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.recv() => {
                        if let Some(cancel) = shared.active_session_cancel.lock().ok().and_then(|mut g| g.take()) {
                            let _ = cancel.try_send(());
                        }
                        break;
                    }
                    _ = disconnect_rx.recv() => {
                        if let Some(cancel) = shared.active_session_cancel.lock().ok().and_then(|mut g| g.take()) {
                            let _ = cancel.try_send(());
                        }
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                // Only one active audio client at a time: disconnect any previous session.
                                let (sess_stop_tx, sess_stop_rx) = mpsc::channel(1);
                                if let Ok(mut guard) = shared.active_session_cancel.lock() {
                                    if let Some(prev) = guard.replace(sess_stop_tx) {
                                        let _ = prev.try_send(());
                                    }
                                }
                                let s = shared.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(stream, peer, s.clone(), sess_stop_rx).await {
                                        debug!("Receiver client {peer} ended: {e:#}");
                                    }
                                    let _ = s.event_tx.send(ReceiverEvent::ClientDisconnected);
                                });
                            }
                            Err(e) => {
                                warn!("AirPlay receiver accept error: {e}");
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                        }
                    }
                }
            }
            let _ = event_tx.send(ReceiverEvent::Stopped);
        });

        Ok(Self {
            port,
            stop_tx,
            disconnect_tx,
            mdns,
            task,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn disconnect_client(&self) {
        let _ = self.disconnect_tx.send(()).await;
    }

    pub async fn stop(self) {
        let _ = self.stop_tx.send(()).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.task).await;
        if let Some(d) = self.mdns {
            let _ = d.shutdown();
        }
    }
}

struct ServerShared {
    cfg: ReceiverConfig,
    server_sk: SigningKey,
    device_id: String,
    pi_uuid: String,
    paired_clients: Arc<RwLock<HashMap<String, String>>>,
    event_tx: mpsc::UnboundedSender<ReceiverEvent>,
    active_session_cancel: Mutex<Option<mpsc::Sender<()>>>,
}

fn register_mdns(
    name: &str,
    device_id: &str,
    pk_hex: &str,
    pi_uuid: &str,
    port: u16,
    pin_mode: bool,
) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("start mDNS daemon")?;
    let lan_ip = crate::media_server::MediaServer::lan_ip();
    let host_clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let hostname = format!(
        "{}.local.",
        if host_clean.is_empty() {
            "nixplay".to_string()
        } else {
            host_clean.to_lowercase()
        }
    );

    let features_str = format!("0x{FEATURES_LO:X},0x{FEATURES_HI:X}");
    let flags = if pin_mode { "0x244" } else { "0x44" }; // 0x200 = PIN required
    let acl = if pin_mode { "2" } else { "0" };

    // 1. _airplay._tcp.local.
    let ap_props = [
        ("acl", acl),
        ("deviceid", device_id),
        ("features", features_str.as_str()),
        ("flags", flags),
        ("model", "NixPlayAudio1,1"),
        ("pi", pi_uuid),
        ("pk", pk_hex),
        ("protovers", "1.1"),
        ("srcvers", "366.0"),
        ("rsf", "0x0"),
        ("fv", "p20.78000.12"),
    ];
    let ap_info = ServiceInfo::new(
        AIRPLAY_SERVICE,
        name,
        &hostname,
        lan_ip,
        port,
        &ap_props[..],
    )
    .context("create _airplay._tcp ServiceInfo")?;
    daemon.register(ap_info).context("register _airplay._tcp")?;

    // 2. <MAC>@<Name>._raop._tcp.local.
    let mac_plain: String = device_id
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    let raop_instance = format!("{mac_plain}@{name}");
    let raop_props = [
        ("txtvers", "1"),
        ("am", "NixPlayAudio1,1"),
        ("ch", "2"),
        ("cn", "0,1"),
        ("da", "true"),
        ("et", "0,3,5"),
        ("ft", features_str.as_str()),
        ("md", "0,1,2"),
        ("pk", pk_hex),
        ("pw", "false"),
        ("sf", flags),
        ("sr", "44100"),
        ("ss", "16"),
        ("tp", "UDP"),
        ("vn", "65537"),
        ("vs", "366.0"),
    ];
    let raop_info = ServiceInfo::new(
        RAOP_SERVICE,
        &raop_instance,
        &hostname,
        lan_ip,
        port,
        &raop_props[..],
    )
    .context("create _raop._tcp ServiceInfo")?;
    daemon.register(raop_info).context("register _raop._tcp")?;

    Ok(daemon)
}

// ---------------------------------------------------------------------------
// RTSP / HTTP Server Session
// ---------------------------------------------------------------------------

struct RtspServerStream {
    stream: TcpStream,
    cipher: Option<HapControlCipher>,
    plain_buf: Vec<u8>,
}

struct RtspRequest {
    method: String,
    uri: String,
    proto: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl RtspRequest {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.get(&k.to_lowercase()).map(|s| s.as_str())
    }
}

impl RtspServerStream {
    fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            stream,
            cipher: None,
            plain_buf: Vec::new(),
        }
    }

    fn enable_encryption(&mut self, shared_secret: &[u8]) -> Result<()> {
        self.cipher = Some(HapControlCipher::from_shared_secret_server(shared_secret)?);
        Ok(())
    }

    async fn read_request(&mut self) -> Result<Option<RtspRequest>> {
        let mut tmp = [0u8; 4096];
        let (header_end, content_length) = loop {
            if let Some(pos) = self.plain_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let hdr_str = String::from_utf8_lossy(&self.plain_buf[..pos]);
                let mut cl = 0usize;
                for line in hdr_str.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            cl = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                break (pos, cl);
            }
            if !self.read_more(&mut tmp).await? {
                return Ok(None);
            }
        };

        let total = header_end + 4 + content_length;
        while self.plain_buf.len() < total {
            if !self.read_more(&mut tmp).await? {
                return Ok(None);
            }
        }

        let hdr_bytes = self.plain_buf[..header_end].to_vec();
        let body = self.plain_buf[header_end + 4..total].to_vec();
        self.plain_buf.drain(..total);

        let hdr_str = String::from_utf8_lossy(&hdr_bytes);
        let mut lines = hdr_str.lines();
        let first = lines.next().unwrap_or("").trim();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let uri = parts.next().unwrap_or("").to_string();
        let proto = parts.next().unwrap_or("RTSP/1.0").to_string();

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        Ok(Some(RtspRequest {
            method,
            uri,
            proto,
            headers,
            body,
        }))
    }

    async fn read_more(&mut self, tmp: &mut [u8]) -> Result<bool> {
        let n = self.stream.read(tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        if let Some(ref mut c) = self.cipher {
            let dec = c.feed_and_decrypt(&tmp[..n])?;
            self.plain_buf.extend_from_slice(&dec);
        } else {
            self.plain_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(true)
    }

    async fn send_response(
        &mut self,
        proto: &str,
        status: u16,
        reason: &str,
        cseq: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<()> {
        let mut out = format!("{proto} {status} {reason}\r\nServer: NixPlay/0.2\r\n");
        if let Some(cs) = cseq {
            out.push_str(&format!("CSeq: {cs}\r\n"));
        }
        for (k, v) in extra {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some((ct, data)) = body {
            out.push_str(&format!("Content-Type: {ct}\r\nContent-Length: {}\r\n", data.len()));
        } else {
            out.push_str("Content-Length: 0\r\n");
        }
        out.push_str("\r\n");
        let mut wire = out.into_bytes();
        if let Some((_, data)) = body {
            wire.extend_from_slice(data);
        }
        let to_send = if let Some(ref mut c) = self.cipher {
            c.encrypt(&wire)?
        } else {
            wire
        };
        self.stream.write_all(&to_send).await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum AudioCodec {
    Alac { spf: usize },
    L16,
}

async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<ServerShared>,
    mut stop_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let mut rtsp = RtspServerStream::new(stream);
    let mut pair_setup: Option<HapServerPairSetup> = None;
    let mut pair_verify: Option<HapServerPairVerify> = None;
    let mut active_pin: Option<String> = None;
    let mut client_name = format!("{}", peer.ip());
    let mut announced = false;
    let mut raop_codec = AudioCodec::Alac { spf: 352 };

    let volume_db = Arc::new(Mutex::new(0.0f32));
    let mut audio_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut timing_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut event_listener_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut current_track = ReceivedTrack::default();

    loop {
        let req = tokio::select! {
            _ = stop_rx.recv() => break,
            r = rtsp.read_request() => match r? {
                Some(req) => req,
                None => break,
            }
        };

        let cseq = req.header("cseq").map(|s| s.to_string());
        let cseq_ref = cseq.as_deref();
        let proto = if req.proto.starts_with("HTTP") {
            "HTTP/1.1"
        } else {
            "RTSP/1.0"
        };

        // Capture DACP remote control headers whenever present
        if let (Some(dacp_id), Some(active_remote)) =
            (req.header("dacp-id"), req.header("active-remote"))
        {
            let _ = shared.event_tx.send(ReceiverEvent::DacpReady(DacpRemote {
                dacp_id: dacp_id.to_string(),
                active_remote: active_remote.to_string(),
                cached_addr: None,
            }));
        }

        if let Some(ua) = req.header("user-agent") {
            if client_name == peer.ip().to_string() {
                if let Some(prod) = ua.split('/').next() {
                    if !prod.is_empty() {
                        client_name = format!("{prod} ({})", peer.ip());
                    }
                }
            }
        }

        debug!("RX {} {} ({} body bytes)", req.method, req.uri, req.body.len());

        match (req.method.as_str(), req.uri.as_str()) {
            ("GET", "/info") => {
                let info_plist = build_info_plist(&shared, peer);
                let mut buf = Vec::new();
                plist::to_writer_binary(&mut buf, &info_plist)?;
                rtsp.send_response(
                    proto,
                    200,
                    "OK",
                    cseq_ref,
                    &[],
                    Some(("application/x-apple-binary-plist", &buf)),
                )
                .await?;
            }
            ("POST", "/pair-pin-start") => {
                let code = format!("{:04}", rand::thread_rng().gen_range(0..10000));
                active_pin = Some(code.clone());
                let _ = shared.event_tx.send(ReceiverEvent::PinPrompt { code });
                rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await?;
            }
            ("POST", "/pair-setup") => {
                let items = tlv8_decode(&req.body)?;
                let state = tlv8_get(&items, TLV_STATE)
                    .and_then(|s| s.first().copied())
                    .unwrap_or(0);

                match state {
                    1 => {
                        let is_transient = tlv8_get(&items, crate::airplay::hap::TLV_FLAGS)
                            .and_then(|f| f.first().copied())
                            .is_some_and(|b| (b & crate::airplay::hap::PAIRING_FLAG_TRANSIENT) != 0);

                        if shared.cfg.pin_mode && is_transient {
                            // Require PIN pairing instead of transient!
                            rtsp.send_response(proto, 470, "Connection Authorization Required", cseq_ref, &[], None)
                                .await?;
                            continue;
                        }

                        let pin = if is_transient {
                            "3939".to_string()
                        } else if let Some(ref p) = active_pin {
                            p.clone()
                        } else {
                            let code = format!("{:04}", rand::thread_rng().gen_range(0..10000));
                            active_pin = Some(code.clone());
                            let _ = shared.event_tx.send(ReceiverEvent::PinPrompt { code: code.clone() });
                            code
                        };

                        let mut ps = HapServerPairSetup::new(
                            &pin,
                            shared.device_id.clone(),
                            shared.server_sk.clone(),
                        );
                        let m2 = ps.handle_m1(&req.body)?;
                        pair_setup = Some(ps);
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/octet-stream", &m2)),
                        )
                        .await?;
                    }
                    3 => {
                        let Some(ps) = pair_setup.as_mut() else {
                            rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                            continue;
                        };
                        let (m4, secret) = ps.handle_m3(&req.body)?;
                        let transient = ps.is_transient();
                        let ok = ps.session_key().is_some();
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/octet-stream", &m4)),
                        )
                        .await?;
                        if ok && transient {
                            rtsp.enable_encryption(&secret)?;
                            active_pin = None;
                        }
                    }
                    5 => {
                        let Some(ps) = pair_setup.as_ref() else {
                            rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                            continue;
                        };
                        match ps.handle_m5(&req.body) {
                            Ok((m6, cid, cpk_hex)) => {
                                if shared.cfg.remember_devices {
                                    shared.paired_clients.write().await.insert(cid.clone(), cpk_hex.clone());
                                    let _ = shared.event_tx.send(ReceiverEvent::ClientPaired {
                                        client_id: cid,
                                        client_pk_hex: cpk_hex,
                                    });
                                }
                                active_pin = None;
                                rtsp.send_response(
                                    proto,
                                    200,
                                    "OK",
                                    cseq_ref,
                                    &[],
                                    Some(("application/octet-stream", &m6)),
                                )
                                .await?;
                            }
                            Err(e) => {
                                warn!("HAP pair-setup M5 failed: {e}");
                                rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                            }
                        }
                    }
                    _ => {
                        rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                    }
                }
            }
            ("POST", "/pair-verify") => {
                let items = tlv8_decode(&req.body)?;
                let state = tlv8_get(&items, TLV_STATE)
                    .and_then(|s| s.first().copied())
                    .unwrap_or(0);
                match state {
                    1 => {
                        let mut pv = HapServerPairVerify::new(
                            shared.device_id.clone(),
                            shared.server_sk.clone(),
                        );
                        let m2 = pv.handle_m1(&req.body)?;
                        pair_verify = Some(pv);
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/octet-stream", &m2)),
                        )
                        .await?;
                    }
                    3 => {
                        let Some(pv) = pair_verify.as_ref() else {
                            rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                            continue;
                        };
                        let known = shared.paired_clients.read().await;
                        let (m4, shared_opt, _cid) =
                            pv.handle_m3(&req.body, shared.cfg.pin_mode, |id| known.get(id).cloned())?;
                        drop(known);
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/octet-stream", &m4)),
                        )
                        .await?;
                        if let Some(secret) = shared_opt {
                            rtsp.enable_encryption(&secret)?;
                        }
                    }
                    _ => {
                        rtsp.send_response(proto, 400, "Bad Request", cseq_ref, &[], None).await?;
                    }
                }
            }
            ("OPTIONS", _) => {
                rtsp.send_response(
                    proto,
                    200,
                    "OK",
                    cseq_ref,
                    &[(
                        "Public",
                        "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET",
                    )],
                    None,
                )
                .await?;
            }
            ("ANNOUNCE", _) => {
                // AirPlay 1 RAOP SDP announcement
                let sdp = String::from_utf8_lossy(&req.body);
                if sdp.contains("AppleLossless") {
                    let spf = sdp
                        .lines()
                        .find_map(|l| l.strip_prefix("a=fmtp:96 "))
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|n| n.parse::<usize>().ok())
                        .unwrap_or(352);
                    raop_codec = AudioCodec::Alac { spf };
                } else {
                    raop_codec = AudioCodec::L16;
                }
                if let Some(s) = sdp.lines().find_map(|l| l.strip_prefix("s=")) {
                    if !s.trim().is_empty() {
                        client_name = s.trim().to_string();
                    }
                }
                announced = true;
                let _ = shared.event_tx.send(ReceiverEvent::ClientConnected {
                    name: client_name.clone(),
                    kind: "AirPlay 1 Audio".into(),
                });
                rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await?;
            }
            ("SETUP", _) => {
                if req.header("content-type").is_some_and(|ct| ct.contains("plist")) {
                    // AirPlay 2 binary plist SETUP (either Stage 1 session or Stage 2 stream)
                    let pl = plist::from_bytes::<plist::Value>(&req.body)?;
                    let dict = pl.as_dictionary().context("SETUP plist not a dict")?;

                    if let Some(name) = dict.get("name").and_then(|v| v.as_string()) {
                        client_name = name.to_string();
                    }

                    if let Some(streams) = dict.get("streams").and_then(|v| v.as_array()) {
                        // Stage 2: real-time audio stream setup
                        let first = streams.first().and_then(|v| v.as_dictionary());
                        let stype = first
                            .and_then(|d| d.get("type"))
                            .and_then(|v| v.as_unsigned_integer())
                            .unwrap_or(96);
                        let ct = first
                            .and_then(|d| d.get("ct"))
                            .and_then(|v| v.as_unsigned_integer())
                            .unwrap_or(2);
                        let spf = first
                            .and_then(|d| d.get("spf"))
                            .and_then(|v| v.as_unsigned_integer())
                            .unwrap_or(352) as usize;
                        let shk: Option<[u8; 32]> = first
                            .and_then(|d| d.get("shk"))
                            .and_then(|v| v.as_data())
                            .and_then(|b| b.try_into().ok());

                        let data_sock = UdpSocket::bind("0.0.0.0:0").await?;
                        let ctrl_sock = UdpSocket::bind("0.0.0.0:0").await?;
                        let data_port = data_sock.local_addr()?.port();
                        let ctrl_port = ctrl_sock.local_addr()?.port();

                        if let Some(prev) = audio_task.take() {
                            prev.abort();
                        }
                        let codec = if ct == 1 {
                            AudioCodec::L16
                        } else {
                            AudioCodec::Alac { spf }
                        };
                        let sink = shared.cfg.output_sink.clone();
                        let vol = volume_db.clone();
                        let ev = shared.event_tx.clone();
                        audio_task = Some(tokio::spawn(async move {
                            run_udp_audio_receiver(data_sock, ctrl_sock, codec, shk, sink, vol, ev).await;
                        }));

                        let _ = shared.event_tx.send(ReceiverEvent::ClientConnected {
                            name: client_name.clone(),
                            kind: "AirPlay 2 Audio".into(),
                        });

                        let mut resp_stream = plist::Dictionary::new();
                        resp_stream.insert("type".into(), plist::Value::Integer(stype.into()));
                        resp_stream.insert("dataPort".into(), plist::Value::Integer((data_port as u64).into()));
                        resp_stream.insert("controlPort".into(), plist::Value::Integer((ctrl_port as u64).into()));
                        let mut resp_dict = plist::Dictionary::new();
                        resp_dict.insert(
                            "streams".into(),
                            plist::Value::Array(vec![plist::Value::Dictionary(resp_stream)]),
                        );
                        let mut buf = Vec::new();
                        plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(resp_dict))?;
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/x-apple-binary-plist", &buf)),
                        )
                        .await?;
                    } else {
                        // Stage 1: session + timing + event channel
                        let timing_sock = UdpSocket::bind("0.0.0.0:0").await?;
                        let timing_port = timing_sock.local_addr()?.port();
                        if let Some(prev) = timing_task.take() {
                            prev.abort();
                        }
                        timing_task = Some(tokio::spawn(async move {
                            crate::airplay::airplay2::run_ntp_timing_responder(Arc::new(timing_sock)).await;
                        }));

                        let ev_listener = TcpListener::bind("0.0.0.0:0").await?;
                        let event_port = ev_listener.local_addr()?.port();
                        if let Some(prev) = event_listener_task.take() {
                            prev.abort();
                        }
                        event_listener_task = Some(tokio::spawn(async move {
                            if let Ok((mut s, _)) = ev_listener.accept().await {
                                let mut sink = [0u8; 256];
                                while s.read(&mut sink).await.unwrap_or(0) > 0 {}
                            }
                        }));

                        let mut resp_dict = plist::Dictionary::new();
                        resp_dict.insert("eventPort".into(), plist::Value::Integer((event_port as u64).into()));
                        resp_dict.insert("timingPort".into(), plist::Value::Integer((timing_port as u64).into()));
                        let mut buf = Vec::new();
                        plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(resp_dict))?;
                        rtsp.send_response(
                            proto,
                            200,
                            "OK",
                            cseq_ref,
                            &[],
                            Some(("application/x-apple-binary-plist", &buf)),
                        )
                        .await?;
                    }
                } else {
                    // AirPlay 1 RAOP Transport header SETUP
                    let data_sock = UdpSocket::bind("0.0.0.0:0").await?;
                    let ctrl_sock = UdpSocket::bind("0.0.0.0:0").await?;
                    let timing_sock = UdpSocket::bind("0.0.0.0:0").await?;
                    let data_port = data_sock.local_addr()?.port();
                    let ctrl_port = ctrl_sock.local_addr()?.port();
                    let timing_port = timing_sock.local_addr()?.port();

                    if let Some(prev) = timing_task.take() {
                        prev.abort();
                    }
                    timing_task = Some(tokio::spawn(async move {
                        crate::airplay::airplay2::run_ntp_timing_responder(Arc::new(timing_sock)).await;
                    }));

                    if let Some(prev) = audio_task.take() {
                        prev.abort();
                    }
                    let sink = shared.cfg.output_sink.clone();
                    let vol = volume_db.clone();
                    let ev = shared.event_tx.clone();
                    let codec = raop_codec;
                    audio_task = Some(tokio::spawn(async move {
                        run_udp_audio_receiver(data_sock, ctrl_sock, codec, None, sink, vol, ev).await;
                    }));
                    if !announced {
                        let _ = shared.event_tx.send(ReceiverEvent::ClientConnected {
                            name: client_name.clone(),
                            kind: "AirPlay 1 Audio".into(),
                        });
                    }

                    let transport = format!(
                        "RTP/AVP/UDP;unicast;mode=record;server_port={data_port};control_port={ctrl_port};timing_port={timing_port}"
                    );
                    rtsp.send_response(
                        proto,
                        200,
                        "OK",
                        cseq_ref,
                        &[("Transport", &transport), ("Session", "1")],
                        None,
                    )
                    .await?;
                }
            }
            ("RECORD", _) => {
                rtsp.send_response(
                    proto,
                    200,
                    "OK",
                    cseq_ref,
                    &[("Audio-Latency", "11025")],
                    None,
                )
                .await?;
            }
            ("POST", "/feedback") | ("FLUSH", _) | ("GET_PARAMETER", _) => {
                rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await?;
            }
            ("SET_PARAMETER", _) => {
                let ct = req.header("content-type").unwrap_or("").to_lowercase();
                if ct.contains("text/parameters") {
                    let text = String::from_utf8_lossy(&req.body);
                    for line in text.lines() {
                        if let Some(val) = line.strip_prefix("volume:") {
                            if let Ok(db) = val.trim().parse::<f32>() {
                                if let Ok(mut g) = volume_db.lock() {
                                    *g = db;
                                }
                                let pct = if db <= -140.0 {
                                    0
                                } else {
                                    (((db + 30.0) / 30.0).clamp(0.0, 1.0) * 100.0).round() as u8
                                };
                                let _ = shared.event_tx.send(ReceiverEvent::Volume(pct));
                            }
                        }
                    }
                } else if ct.contains("dmap") {
                    parse_dmap_metadata(&req.body, &mut current_track);
                    let _ = shared
                        .event_tx
                        .send(ReceiverEvent::TrackUpdated(current_track.clone()));
                } else if ct.starts_with("image/") && !req.body.is_empty() && req.body.len() < 2_000_000 {
                    let mime = ct.split(';').next().unwrap_or("image/jpeg").trim();
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&req.body);
                    current_track.art_data_url = Some(format!("data:{mime};base64,{b64}"));
                    let _ = shared
                        .event_tx
                        .send(ReceiverEvent::TrackUpdated(current_track.clone()));
                }
                rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await?;
            }
            ("TEARDOWN", _) => {
                let _ = rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await;
                break;
            }
            _ => {
                rtsp.send_response(proto, 200, "OK", cseq_ref, &[], None).await?;
            }
        }
    }

    if let Some(t) = audio_task {
        t.abort();
    }
    if let Some(t) = timing_task {
        t.abort();
    }
    if let Some(t) = event_listener_task {
        t.abort();
    }
    Ok(())
}

fn build_info_plist(shared: &ServerShared, peer: SocketAddr) -> plist::Value {
    let features = ((FEATURES_HI as u64) << 32) | (FEATURES_LO as u64);
    let pk_bytes = shared.server_sk.verifying_key().to_bytes().to_vec();
    let mut dict = plist::Dictionary::new();
    dict.insert("deviceID".into(), plist::Value::String(shared.device_id.clone()));
    dict.insert("macAddress".into(), plist::Value::String(shared.device_id.clone()));
    dict.insert("name".into(), plist::Value::String(shared.cfg.name.clone()));
    dict.insert("model".into(), plist::Value::String("NixPlayAudio1,1".into()));
    dict.insert("sourceVersion".into(), plist::Value::String("366.0".into()));
    dict.insert("features".into(), plist::Value::Integer(features.into()));
    dict.insert(
        "statusFlags".into(),
        plist::Value::Integer((if shared.cfg.pin_mode { 0x244u64 } else { 0x44u64 }).into()),
    );
    dict.insert("pk".into(), plist::Value::Data(pk_bytes));
    dict.insert("pi".into(), plist::Value::String(shared.pi_uuid.clone()));
    dict.insert("senderAddress".into(), plist::Value::String(peer.to_string()));
    dict.insert("keepAliveLowPower".into(), plist::Value::Boolean(true));
    dict.insert("keepAliveSendStatsAsBody".into(), plist::Value::Boolean(true));

    let mut fmt = plist::Dictionary::new();
    fmt.insert("type".into(), plist::Value::Integer(96u64.into()));
    fmt.insert("audioInputFormats".into(), plist::Value::Integer(0x0100_0000u64.into()));
    fmt.insert("audioOutputFormats".into(), plist::Value::Integer(0x0100_0000u64.into()));
    dict.insert(
        "audioFormats".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(fmt)]),
    );

    let mut lat = plist::Dictionary::new();
    lat.insert("type".into(), plist::Value::Integer(96u64.into()));
    lat.insert("audioType".into(), plist::Value::String("default".into()));
    lat.insert("inputLatencyMicros".into(), plist::Value::Integer(0u64.into()));
    lat.insert("outputLatencyMicros".into(), plist::Value::Integer(100_000u64.into()));
    dict.insert(
        "audioLatencies".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(lat)]),
    );

    plist::Value::Dictionary(dict)
}

/// Parse DMAP tags (`mlit` -> `minm`, `asar`, `asal`) into `ReceivedTrack`.
pub fn parse_dmap_metadata(data: &[u8], track: &mut ReceivedTrack) {
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let tag = &data[i..i + 4];
        let len = u32::from_be_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
        i += 8;
        if i + len > data.len() {
            break;
        }
        let val = &data[i..i + len];
        i += len;
        match tag {
            b"mlit" => parse_dmap_metadata(val, track),
            b"minm" => track.title = String::from_utf8_lossy(val).to_string(),
            b"asar" => track.artist = String::from_utf8_lossy(val).to_string(),
            b"asal" => track.album = String::from_utf8_lossy(val).to_string(),
            _ => {}
        }
    }
}

/// Receives UDP RTP packets (AirPlay 2 ChaCha20-Poly1305 or RAOP plaintext), decodes ALAC/L16,
/// and streams PCM into PipeWire/PulseAudio via `pacat`.
async fn run_udp_audio_receiver(
    data_sock: UdpSocket,
    ctrl_sock: UdpSocket,
    codec: AudioCodec,
    shk: Option<[u8; 32]>,
    output_sink: Option<String>,
    volume_db: Arc<Mutex<f32>>,
    event_tx: mpsc::UnboundedSender<ReceiverEvent>,
) {
    let cipher = shk.map(|k| ChaCha20Poly1305::new((&k).into()));

    // Spawn pacat playback child (optional in headless test environments where pacat may not exist)
    let mut pacat_cmd = Command::new("pacat");
    pacat_cmd
        .args([
            "--playback",
            "--rate=44100",
            "--channels=2",
            "--format=s16le",
            "--latency-msec=60",
            "--client-name=NixPlay Receiver",
            "--stream-name=AirPlay Audio",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(ref sink) = output_sink {
        if !sink.trim().is_empty() {
            pacat_cmd.args(["-d", sink.trim()]);
        }
    }
    let mut pacat_child = pacat_cmd.spawn().ok();
    let mut pacat_in = pacat_child.as_mut().and_then(|c| c.stdin.take());

    let mut data_buf = [0u8; 4096];
    let mut ctrl_buf = [0u8; 512];
    let mut packets_ok = 0u64;

    loop {
        tokio::select! {
            res = data_sock.recv_from(&mut data_buf) => {
                let Ok((n, _)) = res else { break };
                if n < 12 {
                    continue;
                }
                let pt = data_buf[1] & 0x7F;
                if pt != 0x60 {
                    continue;
                }
                let payload_res: Result<Vec<u8>> = if let Some(ref c) = cipher {
                    // AirPlay 2 RTP: 12-byte header | ciphertext + 16-byte tag | 8-byte LE nonce
                    if n < 12 + 16 + 8 {
                        continue;
                    }
                    let aad = &data_buf[4..12];
                    let ct_end = n - 8;
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes[4..12].copy_from_slice(&data_buf[ct_end..n]);
                    c.decrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload { msg: &data_buf[12..ct_end], aad },
                    )
                    .map_err(|_| anyhow::anyhow!("RTP ChaCha20 decrypt failed"))
                } else {
                    Ok(data_buf[12..n].to_vec())
                };

                let Ok(raw_audio) = payload_res else {
                    continue;
                };

                let pcm_res = match codec {
                    AudioCodec::Alac { spf } => decode_alac_stereo_16(&raw_audio, spf),
                    AudioCodec::L16 => Ok(decode_l16_be_to_le(&raw_audio)),
                };
                let Ok(mut pcm) = pcm_res else {
                    continue;
                };

                let db = volume_db.lock().map(|g| *g).unwrap_or(0.0);
                apply_airplay_volume_db(&mut pcm, db);

                packets_ok += 1;
                if packets_ok == 1 {
                    let _ = event_tx.send(ReceiverEvent::AudioPacketReceived);
                }

                if let Some(ref mut stdin) = pacat_in {
                    if stdin.write_all(&pcm).await.is_err() {
                        pacat_in = None;
                    }
                }
            }
            res = ctrl_sock.recv_from(&mut ctrl_buf) => {
                if res.is_err() {
                    break;
                }
                // NTP/PTP sync ticks from sender — drained cleanly.
            }
        }
    }
    if let Some(mut c) = pacat_child {
        let _ = c.kill().await;
    }
}

/// Ensure the config has persistent server Ed25519 key & MAC device ID.
pub fn load_or_create_server_identity(cfg: &mut ReceiverConfig) -> (SigningKey, String) {
    let sk = cfg
        .server_sk_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(|seed| SigningKey::from_bytes(&seed))
        .unwrap_or_else(|| {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
            cfg.server_sk_hex = Some(hex::encode(seed));
            SigningKey::from_bytes(&seed)
        });

    let device_id = cfg.device_id.clone().unwrap_or_else(|| {
        let b: [u8; 6] = rand::random();
        let mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (b[0] & 0xFE) | 0x02,
            b[1],
            b[2],
            b[3],
            b[4],
            b[5]
        );
        cfg.device_id = Some(mac.clone());
        mac
    });

    (sk, device_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airplay::{
        airplay2::run_airplay2_session, build_dmap_metadata, raop::run_raop_session, SpeakerCommand,
        SpeakerState,
    };
    use crate::audio::AudioEngine;
    use crate::discovery::{AirPlayDevice, AirPlayProtocol, DeviceKind};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_nested_dmap_metadata() {
        let raw = build_dmap_metadata("Bohemian Rhapsody", "Queen", "A Night at the Opera");
        let mut tr = ReceivedTrack::default();
        parse_dmap_metadata(&raw, &mut tr);
        assert_eq!(tr.title, "Bohemian Rhapsody");
        assert_eq!(tr.artist, "Queen");
        assert_eq!(tr.album, "A Night at the Opera");
    }

    #[tokio::test]
    async fn loopback_airplay2_sender_to_builtin_receiver() {
        let mut cfg = ReceiverConfig::default();
        cfg.name = "Test Receiver".into();
        cfg.pin_mode = false;
        let (sk, dev_id) = load_or_create_server_identity(&mut cfg);
        let paired = Arc::new(RwLock::new(HashMap::new()));
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();

        let rx = BuiltinAudioReceiver::start(cfg, sk, dev_id, paired, ev_tx, Some(0), false)
            .await
            .unwrap();
        let port = rx.port();

        let dev = AirPlayDevice {
            id: "LOOPBACK".into(),
            name: "Test Receiver".into(),
            host: "127.0.0.1".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            scope_id: 0,
            airplay_port: Some(port),
            raop_port: Some(port),
            model: "NixPlayAudio1,1".into(),
            os_version: None,
            kind: DeviceKind::Speaker,
            protocol: AirPlayProtocol::AirPlay2,
            supports_airplay2: true,
            supports_raop: true,
            requires_password: false,
            acl: Some(0),
            group_id: None,
            is_stereo_pair: false,
            features: 0,
            flags: 0,
            last_seen_ms: 0,
        };

        let engine = AudioEngine::new();
        engine.ensure_started(false);

        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (state_tx, mut state_rx) = tokio::sync::watch::channel(SpeakerState::Connecting);
        let sender_task = tokio::spawn(run_airplay2_session(
            dev,
            None,
            75,
            0,
            engine.clone(),
            cmd_rx,
            state_tx,
        ));

        // Wait for sender to reach Streaming
        let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state_rx.changed().await.is_ok() {
                let s = *state_rx.borrow();
                if s == SpeakerState::Streaming || s == SpeakerState::Error {
                    return s;
                }
            }
            *state_rx.borrow()
        })
        .await
        .unwrap();
        assert_eq!(reached, SpeakerState::Streaming);

        // Wait for receiver to decode at least one real ChaCha20-encrypted ALAC audio packet!
        let mut got_audio = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(std::time::Duration::from_millis(500), ev_rx.recv()).await {
                if matches!(ev, ReceiverEvent::AudioPacketReceived) {
                    got_audio = true;
                    break;
                }
            }
        }
        assert!(got_audio, "builtin receiver should decrypt & decode incoming ALAC packet");

        let _ = cmd_tx.send(SpeakerCommand::Disconnect).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), sender_task).await;
        engine.stop().await;
        rx.stop().await;
    }

    #[tokio::test]
    async fn loopback_raop_sender_to_builtin_receiver() {
        let mut cfg = ReceiverConfig::default();
        cfg.name = "Test RAOP".into();
        let (sk, dev_id) = load_or_create_server_identity(&mut cfg);
        let paired = Arc::new(RwLock::new(HashMap::new()));
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();

        let rx = BuiltinAudioReceiver::start(cfg, sk, dev_id, paired, ev_tx, Some(0), false)
            .await
            .unwrap();
        let port = rx.port();

        let dev = AirPlayDevice {
            id: "LOOPBACK-RAOP".into(),
            name: "Test RAOP".into(),
            host: "127.0.0.1".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            scope_id: 0,
            airplay_port: Some(port),
            raop_port: Some(port),
            model: "NixPlayAudio1,1".into(),
            os_version: None,
            kind: DeviceKind::Speaker,
            protocol: AirPlayProtocol::Raop,
            supports_airplay2: false,
            supports_raop: true,
            requires_password: false,
            acl: Some(0),
            group_id: None,
            is_stereo_pair: false,
            features: 0,
            flags: 0,
            last_seen_ms: 0,
        };

        let engine = AudioEngine::new();
        engine.ensure_started(false);

        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (state_tx, mut state_rx) = tokio::sync::watch::channel(SpeakerState::Connecting);
        let sender_task = tokio::spawn(run_raop_session(
            dev,
            60,
            0,
            engine.clone(),
            cmd_rx,
            state_tx,
        ));

        let reached = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state_rx.changed().await.is_ok() {
                let s = *state_rx.borrow();
                if s == SpeakerState::Streaming || s == SpeakerState::Error {
                    return s;
                }
            }
            *state_rx.borrow()
        })
        .await
        .unwrap();
        assert_eq!(reached, SpeakerState::Streaming);

        let mut got_audio = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(std::time::Duration::from_millis(500), ev_rx.recv()).await {
                if matches!(ev, ReceiverEvent::AudioPacketReceived) {
                    got_audio = true;
                    break;
                }
            }
        }
        assert!(got_audio, "builtin receiver should decode incoming RAOP ALAC packet");

        let _ = cmd_tx.send(SpeakerCommand::Disconnect).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), sender_task).await;
        engine.stop().await;
        rx.stop().await;
    }
}
