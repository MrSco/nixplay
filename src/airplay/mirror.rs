// SPDX-License-Identifier: GPL-3.0-or-later
// Protocol flow follows doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! Real AirPlay screen mirroring (stream type 110) to Apple TV.
//!
//! Unlike the HLS fallback, frames are pushed over a dedicated TCP data channel and
//! timestamped on the receiver's own PTP timeline, so the Apple TV presents each frame
//! a fixed ~75ms after capture instead of buffering seconds of playlist segments.
//!
//! Session flow (HomeKit-paired receiver):
//! 1. pair-verify -> encrypted RTSP control channel
//! 2. FairPlay SAP (`POST /fp-setup` x2) -> stream master key (mixed with the pair secret)
//! 3. control SETUP (PTP timing peer) -> receiver clock anchor + event channel
//! 4. screen-audio SETUP (type 96; required even for video-only sessions)
//! 5. video SETUP (type 110) -> TCP data port
//! 6. RECORD, then stream H.264 access units encrypted with ChaCha20-Poly1305
//!    (key = HKDF-SHA512 of the pair-verify secret and the stream connection ID).

use super::auth::{connect_and_authenticate, make_sockaddr, spawn_events_channel};
use super::fairplay::{self, FpSapSession, FAIRPLAY_ENCRYPTION_TYPE};
use super::rtsp::{RtspClient, RtspResponse};
use crate::config::HapCredentials;
use crate::discovery::AirPlayDevice;
use crate::audio::pulse::{ScreenAudioRoute, SCREEN_SINK_MONITOR};
pub use crate::media_server::ScreenAudio;
use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

const SOURCE_VERSION: &str = "980.71.1";
/// Playout lead: how far after capture the receiver presents each frame.
/// Matches doubletake's "normal" (Wi-Fi) profile; wired links could go to ~40ms.
const VIDEO_LATENCY: Duration = Duration::from_millis(75);
const AUDIO_LATENCY_SAMPLES: u64 = 3748; // 85ms @ 44.1kHz
const FEATURE_FAIRPLAY_SAP: u32 = 14;
const FEATURE_STREAM_CONNECTIONS: u32 = 59;

#[derive(Debug, Clone)]
pub struct MirrorOptions {
    pub fps: u32,
    pub audio: ScreenAudio,
}

/// Events reported back to the cast manager.
#[derive(Debug)]
#[allow(dead_code)] // dimensions are informational for callers/logging
pub enum MirrorEvent {
    /// Session negotiated and the first frame reached the receiver.
    Streaming { width: u32, height: u32 },
}

// ---------------------------------------------------------------------------
// Receiver clock: maps local Instants onto the receiver's PTP timeline.
// ---------------------------------------------------------------------------

/// 32.32 fixed-point seconds, the timestamp format used in mirroring headers.
fn compact(d: Duration) -> u64 {
    let secs = d.as_secs();
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

#[derive(Debug, Clone, Copy)]
struct ReceiverClock {
    anchor_local: Instant,
    anchor_ts: u64,
    timeline_id: u64,
}

impl ReceiverClock {
    /// The receiver stamps `X-Apple-RequestReceivedTimestamp` (ms) in the same boot-relative
    /// domain as its PTP clock, so no local PTP stack is needed.
    fn anchor_from(resp: &RtspResponse) -> Option<u64> {
        let received: u64 = resp.header("X-Apple-RequestReceivedTimestamp")?.trim().parse().ok()?;
        let processing: u64 = resp
            .header("X-Apple-ProcessingTime")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        Some(compact(Duration::from_millis(received + processing)))
    }

    fn at(&self, local: Instant, bias: Duration) -> u64 {
        let delta = local.saturating_duration_since(self.anchor_local) + bias;
        self.anchor_ts.wrapping_add(compact(delta))
    }

    /// Re-anchor from a later response, never moving the timeline backwards.
    fn reanchor(&mut self, ts: u64, received_at: Instant) {
        if received_at < self.anchor_local {
            return;
        }
        let projected = self.at(received_at, Duration::ZERO);
        self.anchor_ts = ts.max(projected);
        self.anchor_local = received_at;
    }
}

// ---------------------------------------------------------------------------
// H.264 capture: ffmpeg x11grab -> libx264 (zero latency) -> FLV on stdout.
// FLV gives us whole access units, the keyframe flag, and the avcC record for free.
// ---------------------------------------------------------------------------

enum CapturedVideo {
    Config { sps: Vec<u8>, pps: Vec<u8> },
    Frame { avcc: Vec<u8>, keyframe: bool, received_at: Instant },
}

struct FlvReader {
    r: BufReader<ChildStdout>,
    started: bool,
    nal_len_size: usize,
}

impl FlvReader {
    fn new(stdout: ChildStdout) -> Self {
        Self {
            r: BufReader::with_capacity(1 << 20, stdout),
            started: false,
            nal_len_size: 4,
        }
    }

    async fn next(&mut self) -> Result<Option<CapturedVideo>> {
        if !self.started {
            let mut hdr = [0u8; 9];
            self.r.read_exact(&mut hdr).await.context("read FLV header")?;
            if &hdr[..3] != b"FLV" {
                bail!("ffmpeg did not produce an FLV stream");
            }
            let offset = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
            if offset > 9 {
                let mut skip = vec![0u8; offset - 9];
                self.r.read_exact(&mut skip).await?;
            }
            let mut prev = [0u8; 4];
            self.r.read_exact(&mut prev).await?;
            self.started = true;
        }
        loop {
            let mut tag = [0u8; 11];
            match self.r.read_exact(&mut tag).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e.into()),
            }
            let tag_type = tag[0] & 0x1f;
            let size = u32::from_be_bytes([0, tag[1], tag[2], tag[3]]) as usize;
            let mut data = vec![0u8; size];
            self.r.read_exact(&mut data).await?;
            let received_at = Instant::now();
            let mut prev = [0u8; 4];
            self.r.read_exact(&mut prev).await?;

            if tag_type != 9 || data.len() < 5 || data[0] & 0x0f != 7 {
                continue; // not AVC video
            }
            let keyframe_flag = data[0] >> 4 == 1;
            match data[1] {
                0 => {
                    let (sps, pps, len_size) = parse_avcc_record(&data[5..])
                        .context("malformed AVCDecoderConfigurationRecord from ffmpeg")?;
                    self.nal_len_size = len_size;
                    return Ok(Some(CapturedVideo::Config { sps, pps }));
                }
                1 => {
                    let (avcc, has_idr) = repack_nals(&data[5..], self.nal_len_size);
                    if avcc.is_empty() {
                        continue;
                    }
                    return Ok(Some(CapturedVideo::Frame {
                        avcc,
                        keyframe: keyframe_flag || has_idr,
                        received_at,
                    }));
                }
                _ => continue,
            }
        }
    }
}

fn parse_avcc_record(rec: &[u8]) -> Option<(Vec<u8>, Vec<u8>, usize)> {
    if rec.len() < 7 {
        return None;
    }
    let len_size = (rec[4] & 0x03) as usize + 1;
    let mut i = 5;
    let n_sps = rec[i] & 0x1f;
    i += 1;
    let mut sps = Vec::new();
    for k in 0..n_sps {
        let l = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
        i += 2;
        if k == 0 {
            sps = rec.get(i..i + l)?.to_vec();
        }
        i += l;
    }
    let n_pps = *rec.get(i)?;
    i += 1;
    let mut pps = Vec::new();
    for k in 0..n_pps {
        let l = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
        i += 2;
        if k == 0 {
            pps = rec.get(i..i + l)?.to_vec();
        }
        i += l;
    }
    (!sps.is_empty() && !pps.is_empty()).then_some((sps, pps, len_size))
}

/// Re-pack length-prefixed NALs with 4-byte lengths, dropping parameter sets and AUDs
/// (those travel in the separate codec packet). Returns (payload, contains IDR slice).
fn repack_nals(data: &[u8], len_size: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut has_idr = false;
    let mut i = 0;
    while i + len_size <= data.len() {
        let mut l = 0usize;
        for b in &data[i..i + len_size] {
            l = (l << 8) | *b as usize;
        }
        i += len_size;
        if l == 0 || i + l > data.len() {
            break;
        }
        let nal = &data[i..i + l];
        i += l;
        match nal[0] & 0x1f {
            7 | 8 | 9 => continue,
            5 => has_idr = true,
            _ => {}
        }
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(nal);
    }
    (out, has_idr)
}

/// avcC as the receiver expects it (doubletake's buildAVCCConfig, incl. its 4-byte trailer).
fn build_avcc_config(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(11 + sps.len() + pps.len() + 4);
    p.extend_from_slice(&[0x01, sps[1], sps[2], sps[3], 0xff, 0xe1]);
    p.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    p.extend_from_slice(sps);
    p.push(0x01);
    p.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    p.extend_from_slice(pps);
    p.extend_from_slice(&[0x02, 0, 0, 0]);
    p
}

async fn detect_screen_size() -> Option<(u32, u32)> {
    let out = Command::new("xrandr").arg("--current").output().await.ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains('*'))?;
    let (w, h) = line.split_whitespace().next()?.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

/// Encoded size: native resolution, capped to 1920 wide (even dimensions).
fn encode_size(w: u32, h: u32) -> (u32, u32) {
    let (w, h) = if w > 1920 { (1920, h * 1920 / w) } else { (w, h) };
    (w & !1, h & !1)
}

fn spawn_video_capture(fps: u32, src: (u32, u32), out: (u32, u32)) -> Result<Child> {
    let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0.0".into());
    let gop = (fps * 2).to_string();
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-hide_banner", "-loglevel", "warning", "-nostdin"])
        .args(["-fflags", "nobuffer", "-probesize", "32", "-analyzeduration", "0"])
        .args(["-f", "x11grab", "-framerate", &fps.to_string()])
        .args(["-video_size", &format!("{}x{}", src.0 & !1, src.1 & !1)])
        .args(["-i", &display])
        .args(["-vf", &format!("scale={}:{}:flags=bicubic,format=yuv420p", out.0, out.1)])
        .args(["-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency"])
        .args(["-profile:v", "high", "-level:v", "4.2", "-bf", "0"])
        .args(["-g", &gop, "-keyint_min", &gop, "-sc_threshold", "0"])
        .args(["-b:v", "10M", "-maxrate", "12M", "-bufsize", "3M"])
        .args(["-an", "-flush_packets", "1"])
        .args(["-f", "flv", "-flvflags", "no_duration_filesize", "pipe:1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("failed to start ffmpeg for screen mirroring")?;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("ffmpeg (mirror): {line}");
            }
        });
    }
    Ok(child)
}

// ---------------------------------------------------------------------------
// Data channel framing (128-byte APScreenProtocolHeader + payload)
// ---------------------------------------------------------------------------

struct DataChannel {
    sock: TcpStream,
    cipher: ChaCha20Poly1305,
    nonce: u64,
    width: u32,
    height: u32,
}

fn put_f32(h: &mut [u8], at: usize, v: f32) {
    h[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

impl DataChannel {
    async fn send_codec(&mut self, avcc_config: &[u8], ts: u64) -> Result<()> {
        let mut h = [0u8; 128];
        h[0..4].copy_from_slice(&(avcc_config.len() as u32).to_le_bytes());
        h[4] = 0x01; // codec configuration (sent in the clear)
        h[6] = 0x16; // H.264 format description
        h[7] = 0x01;
        h[8..16].copy_from_slice(&ts.to_le_bytes());
        let (w, hh) = (self.width as f32, self.height as f32);
        for at in [16, 40, 56] {
            put_f32(&mut h, at, w);
            put_f32(&mut h, at + 4, hh);
        }
        let mut buf = Vec::with_capacity(128 + avcc_config.len());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(avcc_config);
        self.sock.write_all(&buf).await.context("write codec packet")
    }

    async fn send_frame(&mut self, avcc: &[u8], keyframe: bool, ts: u64, timeline: u64) -> Result<()> {
        let mut h = [0u8; 128];
        h[0..4].copy_from_slice(&((avcc.len() + 16) as u32).to_le_bytes());
        h[4] = 0x00; // encrypted video
        h[5] = if keyframe { 0x10 } else { 0x00 };
        h[8..16].copy_from_slice(&ts.to_le_bytes());
        h[40..48].copy_from_slice(&timeline.to_le_bytes());
        // Receiver uses a 64-bit nonce: IETF nonce = 4 zero bytes + LE64(counter).
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: avcc, aad: &h })
            .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 frame encryption failed"))?;
        let mut buf = Vec::with_capacity(128 + sealed.len());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(&sealed);
        self.sock.write_all(&buf).await.context("write video frame")
    }

    async fn send_heartbeat(&mut self) -> Result<()> {
        let mut h = [0u8; 128];
        h[4] = 0x02;
        h[6] = 0x1e;
        self.sock.write_all(&h).await.context("write heartbeat")
    }
}

// ---------------------------------------------------------------------------
// Screen audio (stream type 96): ALAC frames over RTP/UDP, ChaCha20-Poly1305 sealed,
// with a once-a-second PTP sync packet ("TimeAnnounce") on the control port.
// ---------------------------------------------------------------------------

const AUDIO_SPF: usize = 352;
const AUDIO_RATE: u64 = 44100;

fn spawn_audio_capture(audio: ScreenAudio, desktop_source: &str) -> Result<Child> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-hide_banner", "-loglevel", "warning", "-nostdin", "-fflags", "nobuffer"]);
    // 10ms PulseAudio fragments keep capture latency well inside the 85ms playout lead.
    let sources: Vec<&str> = match audio {
        ScreenAudio::DesktopAndMic => vec![desktop_source, "default"],
        _ => vec![desktop_source],
    };
    for src in &sources {
        cmd.args(["-f", "pulse", "-fragment_size", "1764", "-i", src]);
    }
    if sources.len() > 1 {
        cmd.args(["-filter_complex", "[0:a][1:a]amix=inputs=2:duration=longest:normalize=0[a]", "-map", "[a]"]);
    }
    cmd.args(["-ac", "2", "-ar", "44100", "-f", "s16le", "-flush_packets", "1", "pipe:1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("failed to start ffmpeg audio capture")?;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("ffmpeg (mirror audio): {line}");
            }
        });
    }
    Ok(child)
}

struct AudioSender {
    data: UdpSocket,
    ctrl: Arc<UdpSocket>,
    ctrl_addr: std::net::SocketAddr,
    cipher: ChaCha20Poly1305,
    nonce: u64,
    seq: u16,
}

impl AudioSender {
    fn packet(&mut self, payload: &[u8], rtp: u32) -> Result<Vec<u8>> {
        let mut pkt = Vec::with_capacity(12 + payload.len() + 16 + 8);
        pkt.extend_from_slice(&[0x80, 0x60]);
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        pkt.extend_from_slice(&rtp.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // SSRC
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        let sealed = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &pkt[4..12] })
            .map_err(|_| anyhow::anyhow!("audio encryption failed"))?;
        pkt.extend_from_slice(&sealed);
        pkt.extend_from_slice(&nonce[4..]);
        self.nonce += 1;
        self.seq = self.seq.wrapping_add(1);
        Ok(pkt)
    }

    /// PTP TimeAnnounce: "at receiver time `ptp_ts`, the sender's RTP clock reads `rtp_now`".
    async fn sync(&self, rtp_now: u32, ptp_ts: u64, timeline: u64, first: bool) -> Result<()> {
        let playhead = rtp_now.wrapping_sub(AUDIO_LATENCY_SAMPLES as u32);
        let ns = (ptp_ts >> 32) * 1_000_000_000 + (((ptp_ts & 0xffff_ffff) * 1_000_000_000) >> 32);
        let mut p = [0u8; 28];
        p[0] = if first { 0x90 } else { 0x80 };
        p[1] = 0xd7;
        p[2..4].copy_from_slice(&4u16.to_be_bytes());
        p[4..8].copy_from_slice(&playhead.to_be_bytes());
        p[8..16].copy_from_slice(&ns.to_be_bytes());
        p[16..20].copy_from_slice(&playhead.to_be_bytes());
        p[20..28].copy_from_slice(&timeline.to_be_bytes());
        self.ctrl.send_to(&p, self.ctrl_addr).await?;
        Ok(())
    }
}

async fn pump_audio(
    mut capture: Child,
    mut sender: AudioSender,
    clock: Arc<Mutex<ReceiverClock>>,
) -> Result<()> {
    let mut stdout = capture.stdout.take().context("audio ffmpeg stdout")?;
    let mut pcm = vec![0u8; AUDIO_SPF * 4];
    stdout.read_exact(&mut pcm).await.context("read first audio frame")?;
    // The RTP clock starts at the first captured frame and advances in real time.
    let start = Instant::now();
    let rtp0: u32 = rand::random::<u32>() & 0x7fff_ffff;
    let rtp_at = |at: Instant| -> u32 {
        let el = at.saturating_duration_since(start);
        rtp0.wrapping_add((el.as_secs() * AUDIO_RATE + el.subsec_nanos() as u64 * AUDIO_RATE / 1_000_000_000) as u32)
    };
    let clock_at = |at: Instant| -> Result<(u64, u64)> {
        let c = clock.lock().map_err(|_| anyhow::anyhow!("clock poisoned"))?;
        Ok((c.at(at, Duration::ZERO), c.timeline_id))
    };
    let (ts, timeline) = clock_at(start)?;
    sender.sync(rtp0, ts, timeline, true).await?;

    let mut sync_tick = tokio::time::interval(Duration::from_secs(1));
    sync_tick.tick().await;
    let mut frame: u64 = 0;
    loop {
        let rtp = rtp0.wrapping_add((frame * AUDIO_SPF as u64) as u32);
        let alac = crate::audio::alac::encode_alac_verbatim_stereo_16(&pcm);
        let pkt = sender.packet(&alac, rtp)?;
        sender.data.send(&pkt).await.context("send audio packet")?;
        frame += 1;
        tokio::select! {
            r = stdout.read_exact(&mut pcm) => { r.context("audio capture ended")?; }
            _ = sync_tick.tick() => {
                let now = Instant::now();
                let (ts, timeline) = clock_at(now)?;
                sender.sync(rtp_at(now), ts, timeline, false).await?;
                stdout.read_exact(&mut pcm).await.context("audio capture ended")?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

fn pl_dict(pairs: Vec<(&str, plist::Value)>) -> plist::Value {
    let mut d = plist::Dictionary::new();
    for (k, v) in pairs {
        d.insert(k.to_string(), v);
    }
    plist::Value::Dictionary(d)
}

fn pl_int(v: i64) -> plist::Value {
    plist::Value::Integer(v.into())
}

fn pl_str(v: &str) -> plist::Value {
    plist::Value::String(v.to_string())
}

fn pl_get_u64(v: Option<&plist::Value>) -> Option<u64> {
    let v = v?;
    v.as_unsigned_integer()
        .or_else(|| v.as_signed_integer().map(|i| i as u64))
        .or_else(|| v.as_real().map(|r| r as u64))
}

fn random_conn_id() -> i64 {
    (rand::random::<u64>() & 0x7FFF_FFFF_FFFF_FFFF) as i64
}

fn host_for_uri(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

async fn setup(rtsp: &mut RtspClient, uri: &str, phase: &str, body: plist::Value) -> Result<(plist::Dictionary, RtspResponse, Instant)> {
    debug!("mirror {phase} SETUP -> {body:?}");
    let resp = rtsp.request_plist("SETUP", uri, &[], &body).await.with_context(|| format!("{phase} SETUP"))?;
    let received_at = Instant::now();
    if resp.status_code != 200 {
        bail!("{phase} SETUP rejected: {}", resp.status_line);
    }
    let dict = resp
        .body_plist()
        .ok()
        .and_then(|v| v.into_dictionary())
        .unwrap_or_default();
    debug!("mirror {phase} SETUP <- {dict:?}");
    Ok((dict, resp, received_at))
}

async fn fairplay_setup(rtsp: &mut RtspClient, shared_secret: &[u8]) -> Result<([u8; 16], [u8; 16])> {
    let mut fp = FpSapSession::new()?;
    let headers = [("X-Apple-ET", FAIRPLAY_ENCRYPTION_TYPE)];
    let m1 = fp.message1();
    let r2 = rtsp
        .request("POST", "/fp-setup", &headers, Some(("application/octet-stream", &m1)))
        .await
        .context("fp-setup m1")?;
    if r2.status_code != 200 {
        bail!("FairPlay fp-setup (m1) rejected: {}", r2.status_line);
    }
    let m3 = fp.exchange_m3(&r2.body).context("FairPlay m3")?;
    let r4 = rtsp
        .request("POST", "/fp-setup", &headers, Some(("application/octet-stream", &m3)))
        .await
        .context("fp-setup m3")?;
    if r4.status_code != 200 {
        bail!("FairPlay fp-setup (m3) rejected: {}", r4.status_line);
    }
    fp.confirm_m4(&r4.body).context("FairPlay m4")?;

    let raw_key: [u8; 16] = rand::random();
    let iv: [u8; 16] = rand::random();
    // ekey is only sent on legacy (unencrypted) sessions; wrapping still binds the key
    // to this SAP exchange, and the receiver derives the same mixed master key.
    let _ekey = fp.wrap_key(raw_key)?;
    let master = fairplay::derive_stream_master_key(&raw_key, shared_secret, true);
    let mut key = [0u8; 16];
    key.copy_from_slice(&master[..16]);
    Ok((key, iv))
}

/// Run a mirroring session until `stop_rx` fires or the stream fails.
/// `ready_tx` receives Ok once the first frame is on the wire, or the setup error.
pub async fn run_mirror_session(
    device: AirPlayDevice,
    creds: Option<HapCredentials>,
    opts: MirrorOptions,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: oneshot::Sender<Result<MirrorEvent>>,
) -> Result<()> {
    let mut ready_tx = Some(ready_tx);
    let result = run_inner(&device, creds, &opts, &mut stop_rx, &mut ready_tx).await;
    if let Some(tx) = ready_tx.take() {
        let _ = tx.send(match &result {
            Ok(()) => Err(anyhow::anyhow!("mirroring stopped before the first frame")),
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        });
    }
    result
}

async fn run_inner(
    device: &AirPlayDevice,
    creds: Option<HapCredentials>,
    opts: &MirrorOptions,
    stop_rx: &mut mpsc::Receiver<()>,
    ready_tx: &mut Option<oneshot::Sender<Result<MirrorEvent>>>,
) -> Result<()> {
    if device.features & (1u64 << FEATURE_FAIRPLAY_SAP) == 0 {
        bail!("'{}' does not support FairPlay screen mirroring", device.name);
    }

    // Start capture first so the encoder warms up while we negotiate.
    let (src_w, src_h) = detect_screen_size().await.unwrap_or((1280, 720));
    let (enc_w, enc_h) = encode_size(src_w, src_h);
    let mut capture = spawn_video_capture(opts.fps, (src_w, src_h), (enc_w, enc_h))?;
    let mut flv = FlvReader::new(capture.stdout.take().context("ffmpeg stdout")?);

    let conn = connect_and_authenticate(device, creds.as_ref()).await?;
    let mut rtsp = conn.rtsp;
    let shared_secret = conn.shared_secret;
    let (target_ip, target_scope) = (conn.target_ip, conn.target_scope);
    let port = device.airplay_port.or(device.raop_port).unwrap_or(7000);
    let local_ip = rtsp.local_addr()?.ip();
    let host = host_for_uri(target_ip);

    let (fp_key, fp_iv) = fairplay_setup(&mut rtsp, &shared_secret).await?;
    info!("FairPlay SAP handshake complete with '{}'", device.name);

    let session_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let sid: u64 = rand::random();
    let mac = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        0x02 | (sid as u8 & 0xfc), (sid >> 8) as u8, (sid >> 16) as u8,
        (sid >> 24) as u8, (sid >> 32) as u8, (sid >> 40) as u8
    );
    let audio_id = random_conn_id();
    let audio_uri = format!("rtsp://{host}:{port}/{audio_id}");

    // 3. Control SETUP
    let peer = pl_dict(vec![
        ("ID", pl_str(&uuid::Uuid::new_v4().to_string().to_uppercase())),
        ("SupportsClockPortMatchingOverride", plist::Value::Boolean(true)),
        ("DeviceType", pl_int(0)),
        ("Addresses", plist::Value::Array(vec![pl_str(&local_ip.to_string())])),
    ]);
    let control = pl_dict(vec![
        ("deviceID", pl_str(&mac)),
        ("macAddress", pl_str(&mac)),
        ("sessionUUID", pl_str(&session_uuid)),
        ("sourceVersion", pl_str(SOURCE_VERSION)),
        ("isScreenMirroringSession", plist::Value::Boolean(true)),
        ("timingProtocol", pl_str("PTP")),
        ("osBuildVersion", pl_str("13F69")),
        ("model", pl_str("Linux")),
        ("name", pl_str("NixPlay")),
        ("timingPeerInfo", peer.clone()),
        ("timingPeerList", plist::Value::Array(vec![peer])),
        ("updateSessionRequest", plist::Value::Boolean(false)),
        ("combinedGetInfoWithControlSetup", plist::Value::Boolean(true)),
    ]);
    let (ctrl, ctrl_resp, ctrl_at) = setup(&mut rtsp, &audio_uri, "control", control).await?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<plist::Value>();
    let events_handle = match pl_get_u64(ctrl.get("eventPort")) {
        Some(ep) if ep > 0 => {
            spawn_events_channel(target_ip, ep as u16, target_scope, shared_secret.clone(), device.name.clone(), Some(event_tx)).await
        }
        _ => None,
    };

    let mut timeline_id = ctrl
        .get("timingPeerInfo")
        .and_then(|p| p.as_dictionary())
        .and_then(|p| pl_get_u64(p.get("ClockID")))
        .unwrap_or(0);
    if timeline_id == 0 {
        // Receiver may push its clock asynchronously on the event channel.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while timeline_id == 0 {
            let ev = tokio::time::timeout_at(deadline, event_rx.recv()).await;
            let Ok(Some(ev)) = ev else { break };
            debug!("mirror event while waiting for PTP clock: {ev:?}");
            timeline_id = find_clock_id(&ev).unwrap_or(0);
        }
    }
    if timeline_id == 0 {
        bail!("receiver did not provide a PTP clock for mirroring");
    }
    let anchor_ts = ReceiverClock::anchor_from(&ctrl_resp)
        .context("receiver omitted X-Apple-RequestReceivedTimestamp")?;
    let clock = Arc::new(Mutex::new(ReceiverClock {
        anchor_local: ctrl_at,
        anchor_ts,
        timeline_id,
    }));
    info!("Mirroring PTP clock {timeline_id:#x} anchored on '{}'", device.name);

    // 4. Screen-audio stream descriptor (required even when no audio is sent).
    // Apple's real-time audio only starts processing after RECORD, so with audio
    // enabled RECORD comes before the stream SETUPs (doubletake's control-first order).
    // Receivers that answer `skipRecord` start the session without RECORD at all.
    let mut recorded = ctrl.get("skipRecord").and_then(|v| v.as_boolean()).unwrap_or(false);
    if opts.audio.is_enabled() && !recorded {
        record(&mut rtsp, &audio_uri, &session_uuid, &device.name).await?;
        recorded = true;
    }

    let bind_any = if local_ip.is_ipv4() { "0.0.0.0" } else { "::" };
    let audio_ctrl_sock = Arc::new(UdpSocket::bind((bind_any, 0)).await?);
    let audio_ctrl_port = audio_ctrl_sock.local_addr()?.port() as i64;
    let audio_key: [u8; 32] = rand::random();
    let mut audio_stream = vec![
        ("type", pl_int(96)),
        ("streamConnectionID", pl_int(audio_id)),
        ("ct", pl_int(2)),
        ("spf", pl_int(352)),
        ("sr", pl_int(44100)),
        ("audioFormat", pl_int(0x40000)),
        ("audioMode", pl_str("default")),
        ("usingScreen", plist::Value::Boolean(true)),
        ("latencyMin", pl_int(0)),
        ("latencyMax", pl_int(AUDIO_LATENCY_SAMPLES as i64)),
        ("shk", plist::Value::Data(audio_key.to_vec())),
    ];
    if device.features & (1u64 << FEATURE_STREAM_CONNECTIONS) != 0 {
        audio_stream.extend([
            ("isMedia", plist::Value::Boolean(false)),
            ("supportsDynamicStreamID", plist::Value::Boolean(true)),
            (
                "streamConnections",
                pl_dict(vec![
                    (
                        "streamConnectionTypeRTP",
                        pl_dict(vec![("streamConnectionKeyUseStreamEncryptionKey", plist::Value::Boolean(true))]),
                    ),
                    (
                        "streamConnectionTypeRTCP",
                        pl_dict(vec![("streamConnectionKeyPort", pl_int(audio_ctrl_port))]),
                    ),
                ]),
            ),
        ]);
    } else {
        audio_stream.push(("controlPort", pl_int(audio_ctrl_port)));
    }
    let audio_body = pl_dict(vec![("streams", plist::Value::Array(vec![pl_dict(audio_stream)]))]);
    let (audio_resp, _, _) = setup(&mut rtsp, &audio_uri, "screen-audio", audio_body).await?;
    let audio_ports = audio_resp
        .get("streams")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_dictionary())
        .find(|s| pl_get_u64(s.get("type")) == Some(96))
        .map(stream_ports);

    // 5. Video stream SETUP
    let video_id = random_conn_id();
    let video_uri = format!("rtsp://{host}:{port}/{video_id}");
    let timestamp_info = ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"]
        .iter()
        .map(|n| pl_dict(vec![("name", pl_str(n))]))
        .collect();
    let video_body = pl_dict(vec![(
        "streams",
        plist::Value::Array(vec![pl_dict(vec![
            ("type", pl_int(110)),
            ("streamConnectionID", pl_int(video_id)),
            ("latencyMs", pl_int(VIDEO_LATENCY.as_millis() as i64)),
            ("timestampInfo", plist::Value::Array(timestamp_info)),
            ("shk", plist::Value::Data(fp_key.to_vec())),
            ("shiv", plist::Value::Data(fp_iv.to_vec())),
        ])]),
    )]);
    let (video_resp, _, _) = setup(&mut rtsp, &video_uri, "video", video_body).await?;
    let data_port = video_resp
        .get("streams")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_dictionary())
        .find(|s| pl_get_u64(s.get("type")) == Some(110))
        .and_then(|s| pl_get_u64(s.get("dataPort")))
        .context("video SETUP returned no data port")?;

    let data_addr = make_sockaddr(target_ip, data_port as u16, target_scope);
    let sock = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(data_addr))
        .await
        .context("data channel connect timeout")?
        .with_context(|| format!("connect mirroring data channel {data_addr}"))?;
    sock.set_nodelay(true)?;

    // 6. RECORD (video-only sessions)
    if !recorded {
        record(&mut rtsp, &audio_uri, &session_uuid, &device.name).await?;
    }

    let chacha_key = fairplay::derive_chacha_key(&shared_secret, video_id)?;
    let mut data = DataChannel {
        sock,
        cipher: ChaCha20Poly1305::new(Key::from_slice(&chacha_key)),
        nonce: 0,
        width: enc_w,
        height: enc_h,
    };

    // Frame pump runs on its own task so control-channel round trips never delay frames.
    let (pump_done_tx, mut pump_done_rx) = oneshot::channel::<Result<()>>();
    let (first_frame_tx, mut first_frame_rx) = oneshot::channel::<()>();
    let pump_clock = clock.clone();
    let pump = tokio::spawn(async move {
        let res = pump_frames(&mut flv, &mut data, pump_clock, first_frame_tx).await;
        let _ = pump_done_tx.send(res);
    });

    let mut audio_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut audio_route: Option<ScreenAudioRoute> = None;
    let mut feedback = tokio::time::interval(Duration::from_secs(2));
    let mut first_frame_seen = false;
    let result: Result<()> = loop {
        tokio::select! {
            _ = stop_rx.recv() => break Ok(()),
            res = &mut pump_done_rx => {
                break match res {
                    Ok(Ok(())) => Err(anyhow::anyhow!("screen capture ended unexpectedly")),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(anyhow::anyhow!("frame pump stopped")),
                };
            }
            r = &mut first_frame_rx, if !first_frame_seen => {
                first_frame_seen = true;
                if r.is_ok() {
                    info!("Screen mirroring live on '{}' ({enc_w}x{enc_h} @ {}fps)", device.name, opts.fps);
                    if opts.audio.is_enabled() {
                        match start_audio(opts.audio, audio_ports, &audio_key, &audio_ctrl_sock, target_ip, target_scope, clock.clone()).await {
                            Ok((task, route)) => {
                                audio_task = Some(task);
                                audio_route = route;
                            }
                            Err(e) => warn!("Mirroring audio unavailable on '{}': {e:#}", device.name),
                        }
                    }
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Ok(MirrorEvent::Streaming { width: enc_w, height: enc_h }));
                    }
                }
            }
            _ = feedback.tick() => {
                match rtsp.request("POST", "/feedback", &[], None).await {
                    Ok(resp) => {
                        let at = Instant::now();
                        if let Some(ts) = ReceiverClock::anchor_from(&resp) {
                            if let Ok(mut c) = clock.lock() { c.reanchor(ts, at); }
                        }
                    }
                    Err(e) => break Err(e.context("control channel lost")),
                }
            }
            ev = event_rx.recv() => {
                if let Some(ev) = ev {
                    debug!("mirror event from '{}': {ev:?}", device.name);
                    if let Some(id) = find_clock_id(&ev) {
                        if let Ok(mut c) = clock.lock() { c.timeline_id = id; }
                    }
                }
            }
        }
    };

    pump.abort();
    if let Some(t) = audio_task {
        t.abort();
    }
    // Give the user their speakers back before anything that might be slow (TEARDOWN).
    if let Some(route) = audio_route {
        route.restore().await;
    }
    let _ = capture.kill().await;
    let empty = pl_dict(vec![]);
    let _ = tokio::time::timeout(Duration::from_secs(2), rtsp.request_plist("TEARDOWN", &audio_uri, &[], &empty)).await;
    if let Some(h) = events_handle {
        h.abort();
    }
    info!("Screen mirroring on '{}' stopped", device.name);
    result
}

async fn record(rtsp: &mut RtspClient, uri: &str, session_uuid: &str, name: &str) -> Result<()> {
    let rec = rtsp
        .request(
            "RECORD",
            uri,
            &[("Session", session_uuid), ("Range", "npt=0-"), ("RTP-Info", "seq=0;rtptime=0")],
            None,
        )
        .await
        .context("RECORD")?;
    if rec.status_code != 200 {
        warn!("RECORD on '{name}' returned {}", rec.status_line);
    }
    Ok(())
}

/// (dataPort, controlPort) from a stream descriptor, legacy or streamConnections form.
fn stream_ports(stream: &plist::Dictionary) -> (u16, u16) {
    let mut data = pl_get_u64(stream.get("dataPort")).unwrap_or(0) as u16;
    let mut ctrl = pl_get_u64(stream.get("controlPort")).unwrap_or(0) as u16;
    if let Some(conns) = stream.get("streamConnections").and_then(|c| c.as_dictionary()) {
        let port = |k: &str| {
            conns
                .get(k)
                .and_then(|c| c.as_dictionary())
                .and_then(|c| pl_get_u64(c.get("streamConnectionKeyPort")))
                .filter(|p| *p > 0)
                .map(|p| p as u16)
        };
        data = port("streamConnectionTypeRTP").unwrap_or(data);
        ctrl = port("streamConnectionTypeRTCP").unwrap_or(ctrl);
    }
    (data, ctrl)
}

#[allow(clippy::too_many_arguments)]
async fn start_audio(
    audio: ScreenAudio,
    ports: Option<(u16, u16)>,
    key: &[u8; 32],
    ctrl_sock: &Arc<UdpSocket>,
    target_ip: IpAddr,
    scope: u32,
    clock: Arc<Mutex<ReceiverClock>>,
) -> Result<(tokio::task::JoinHandle<()>, Option<ScreenAudioRoute>)> {
    let (data_port, ctrl_port) = ports.context("receiver returned no screen-audio stream")?;
    if data_port == 0 || ctrl_port == 0 {
        bail!("receiver returned no audio ports ({data_port}/{ctrl_port})");
    }
    let bind_any = if target_ip.is_ipv4() { "0.0.0.0" } else { "::" };
    let data = UdpSocket::bind((bind_any, 0)).await?;
    data.connect(make_sockaddr(target_ip, data_port, scope)).await?;
    let sender = AudioSender {
        data,
        ctrl: ctrl_sock.clone(),
        ctrl_addr: make_sockaddr(target_ip, ctrl_port, scope),
        cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        nonce: 0,
        seq: 1,
    };
    // Send desktop sound to the TV only, like Apple's own mirroring. If the silent
    // screen sink can't be created, fall back to capturing the speakers' monitor.
    let route = match ScreenAudioRoute::activate().await {
        Ok(r) => Some(r),
        Err(e) => {
            warn!("Could not move desktop audio off the local speakers ({e:#}); it will play in both places");
            None
        }
    };
    let source = if route.is_some() { SCREEN_SINK_MONITOR } else { "@DEFAULT_MONITOR@" };
    let capture = match spawn_audio_capture(audio, source) {
        Ok(c) => c,
        Err(e) => {
            if let Some(r) = route {
                r.restore().await;
            }
            return Err(e);
        }
    };
    info!("Mirroring audio ({audio:?}) -> UDP {data_port}, sync -> {ctrl_port}");
    let task = tokio::spawn(async move {
        if let Err(e) = pump_audio(capture, sender, clock).await {
            warn!("Mirroring audio stopped: {e:#}");
        }
    });
    Ok((task, route))
}

fn find_clock_id(ev: &plist::Value) -> Option<u64> {
    let d = ev.as_dictionary()?;
    let peer = d
        .get("timingPeerInfo")
        .or_else(|| d.get("params").and_then(|p| p.as_dictionary()).and_then(|p| p.get("timingPeerInfo")))?;
    pl_get_u64(peer.as_dictionary()?.get("ClockID")).filter(|id| *id != 0)
}

async fn pump_frames(
    flv: &mut FlvReader,
    data: &mut DataChannel,
    clock: Arc<Mutex<ReceiverClock>>,
    first_frame_tx: oneshot::Sender<()>,
) -> Result<()> {
    let mut first_frame_tx = Some(first_frame_tx);
    let mut config: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut sent_config: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut last_ts = 0u64;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    heartbeat.tick().await;
    let mut frames = 0u64;
    loop {
        let item = tokio::select! {
            item = flv.next() => item?,
            _ = heartbeat.tick(), if first_frame_tx.is_none() => {
                data.send_heartbeat().await?;
                continue;
            }
        };
        let Some(item) = item else { return Ok(()) };
        match item {
            CapturedVideo::Config { sps, pps } => config = Some((sps, pps)),
            CapturedVideo::Frame { avcc, keyframe, received_at } => {
                let Some(cfg) = config.as_ref() else { continue };
                if sent_config.is_none() && !keyframe {
                    continue; // decoder must start on an IDR
                }
                let (ts, timeline) = {
                    let c = clock.lock().map_err(|_| anyhow::anyhow!("clock poisoned"))?;
                    (c.at(received_at, VIDEO_LATENCY), c.timeline_id)
                };
                let ts = if ts <= last_ts { last_ts + 1 } else { ts };
                last_ts = ts;
                if keyframe && sent_config.as_ref() != Some(cfg) {
                    data.send_codec(&build_avcc_config(&cfg.0, &cfg.1), ts).await?;
                    sent_config = Some(cfg.clone());
                }
                data.send_frame(&avcc, keyframe, ts, timeline).await?;
                frames += 1;
                if frames <= 3 || frames % 900 == 0 {
                    debug!("mirror frame #{frames} ({} bytes, key={keyframe})", avcc.len());
                }
                if let Some(tx) = first_frame_tx.take() {
                    let _ = tx.send(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_timestamp_is_32_32_fixed_point() {
        assert_eq!(compact(Duration::from_secs(3)), 3u64 << 32);
        assert_eq!(compact(Duration::from_millis(500)), 1u64 << 31);
    }

    #[test]
    fn repack_drops_parameter_sets_and_flags_idr() {
        let mut d = Vec::new();
        for nal in [&[0x67u8, 1, 2][..], &[0x68, 3], &[0x09, 0xf0], &[0x65, 0x88, 0x84]] {
            d.extend_from_slice(&(nal.len() as u32).to_be_bytes());
            d.extend_from_slice(nal);
        }
        let (out, idr) = repack_nals(&d, 4);
        assert!(idr);
        assert_eq!(out, vec![0, 0, 0, 3, 0x65, 0x88, 0x84]);
    }

    #[test]
    fn avcc_record_round_trip() {
        let sps = vec![0x67, 0x64, 0x00, 0x2a, 0xac];
        let pps = vec![0x68, 0xee, 0x3c];
        let mut rec = vec![1, 0x64, 0x00, 0x2a, 0xff, 0xe1];
        rec.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        rec.extend_from_slice(&sps);
        rec.push(1);
        rec.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        rec.extend_from_slice(&pps);
        let (s, p, l) = parse_avcc_record(&rec).unwrap();
        assert_eq!((s.as_slice(), p.as_slice(), l), (sps.as_slice(), pps.as_slice(), 4));
        let cfg = build_avcc_config(&sps, &pps);
        assert_eq!(&cfg[..rec.len()], rec.as_slice());
        assert_eq!(&cfg[rec.len()..], &[2, 0, 0, 0]);
    }
}
