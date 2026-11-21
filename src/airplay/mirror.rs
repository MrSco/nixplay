// SPDX-License-Identifier: GPL-3.0-or-later
// Protocol flow follows doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! Real AirPlay screen mirroring (stream type 110) to Apple TV.
//!
//! Unlike the HLS fallback, frames are pushed over a dedicated TCP data channel and
//! timestamped on the receiver's own PTP timeline, so the Apple TV presents each frame
//! a fixed ~40–100ms after capture instead of buffering seconds of playlist segments.
//!
//! Supports:
//! - Multi-monitor selection (via `xrandr` on X11, or XDG Desktop Portal + PipeWire on Wayland)
//! - Hardware video encoding (NVENC / VAAPI) with automatic CPU fallback
//! - H.264 and HEVC (H.265, AirPlay feature bit 42, up to 4K)
//! - Adaptive wired vs. Wi-Fi latency profiles (Low 40ms / Normal 75ms / High 100ms)
//! - Configurable FPS, bitrate, and mouse cursor visibility

use super::auth::{connect_and_authenticate, make_sockaddr, spawn_events_channel};
use super::fairplay::{self, FpSapSession, FAIRPLAY_ENCRYPTION_TYPE};
use super::rtsp::{RtspClient, RtspResponse};
use crate::audio::pulse::{ScreenAudioRoute, SCREEN_SINK_MONITOR};
use crate::config::{HapCredentials, MirrorCodec, MirrorEncoder, MirrorLatencyProfile, MirrorPrefs};
use crate::discovery::AirPlayDevice;
pub use crate::media_server::ScreenAudio;
use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

const SOURCE_VERSION: &str = "980.71.1";
const FEATURE_FAIRPLAY_SAP: u32 = 14;
const FEATURE_SCREEN_MULTI_CODEC: u32 = 42;
const FEATURE_STREAM_CONNECTIONS: u32 = 59;

/// Active desktop monitor detected from X11 (`xrandr`) or fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayInfo {
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub primary: bool,
}

/// Hardware video encoders detected on this Linux system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwEncoderCaps {
    pub vaapi_h264: bool,
    pub vaapi_hevc: bool,
    pub nvenc_h264: bool,
    pub nvenc_hevc: bool,
    pub libx265: bool,
}

impl HwEncoderCaps {
    pub fn hevc_available(&self) -> bool {
        self.nvenc_hevc || self.vaapi_hevc || self.libx265
    }
}

static HW_CAPS: OnceLock<HwEncoderCaps> = OnceLock::new();

pub fn probe_hw_encoders() -> HwEncoderCaps {
    *HW_CAPS.get_or_init(|| {
        let out = std::process::Command::new("ffmpeg")
            .args(["-hide_banner", "-encoders"])
            .output();
        let Ok(out) = out else {
            return HwEncoderCaps::default();
        };
        if !out.status.success() {
            return HwEncoderCaps::default();
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let has_dri = Path::new("/dev/dri/renderD128").exists();
        let has_nv = Path::new("/dev/nvidia0").exists() || Path::new("/dev/nvidiactl").exists();
        HwEncoderCaps {
            vaapi_h264: has_dri && text.contains("h264_vaapi"),
            vaapi_hevc: has_dri && text.contains("hevc_vaapi"),
            nvenc_h264: has_nv && text.contains("h264_nvenc"),
            nvenc_hevc: has_nv && text.contains("hevc_nvenc"),
            libx265: text.contains("libx265"),
        }
    })
}

/// Parse `xrandr --query` output into connected monitors with active geometries.
pub fn parse_xrandr_displays(text: &str) -> Vec<DisplayInfo> {
    let mut displays = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 || parts[1] != "connected" {
            continue;
        }
        let name = parts[0].to_string();
        let primary = parts.get(2).is_some_and(|p| *p == "primary");
        // Find geometry token like "1920x1080+0+0" or "2560x1440+1920+0"
        let geom = parts.iter().skip(2).find(|tok| {
            tok.contains('x') && tok.contains('+') && tok.chars().next().is_some_and(|c| c.is_ascii_digit())
        });
        let Some(geom) = geom else { continue };
        let Some((wh, rest)) = geom.split_once('+') else { continue };
        let Some((w_s, h_s)) = wh.split_once('x') else { continue };
        let Some((x_s, y_s)) = rest.split_once('+') else { continue };
        let (Ok(width), Ok(height), Ok(x), Ok(y)) = (
            w_s.parse::<u32>(),
            h_s.parse::<u32>(),
            x_s.parse::<i32>(),
            y_s.parse::<i32>(),
        ) else {
            continue;
        };
        if width > 0 && height > 0 {
            displays.push(DisplayInfo {
                name,
                width,
                height,
                x,
                y,
                primary,
            });
        }
    }
    displays
}

pub fn list_displays_sync() -> Vec<DisplayInfo> {
    let Ok(out) = std::process::Command::new("xrandr").arg("--query").output() else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    parse_xrandr_displays(&String::from_utf8_lossy(&out.stdout))
}

pub async fn list_displays() -> Vec<DisplayInfo> {
    tokio::task::spawn_blocking(list_displays_sync)
        .await
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct MirrorOptions {
    pub fps: u32,
    pub audio: ScreenAudio,
    pub display: Option<String>,
    pub bitrate_kbps: u32,
    pub encoder: MirrorEncoder,
    pub codec: MirrorCodec,
    pub latency: MirrorLatencyProfile,
    pub show_cursor: bool,
}

impl Default for MirrorOptions {
    fn default() -> Self {
        Self {
            fps: 30,
            audio: ScreenAudio::Desktop,
            display: None,
            bitrate_kbps: 0,
            encoder: MirrorEncoder::Auto,
            codec: MirrorCodec::Auto,
            latency: MirrorLatencyProfile::Auto,
            show_cursor: true,
        }
    }
}

impl MirrorOptions {
    pub fn from_prefs(prefs: &MirrorPrefs, audio: ScreenAudio) -> Self {
        Self {
            fps: prefs.fps.clamp(15, 60),
            audio,
            display: prefs.display.clone(),
            bitrate_kbps: prefs.bitrate_kbps,
            encoder: prefs.encoder,
            codec: prefs.codec,
            latency: prefs.latency,
            show_cursor: prefs.show_cursor,
        }
    }
}

/// Events reported back to the cast manager.
#[derive(Debug)]
#[allow(dead_code)]
pub enum MirrorEvent {
    Streaming { width: u32, height: u32 },
}

/// Resolve video/audio playout leads based on profile and wired vs. wireless route.
fn resolve_latency_targets(profile: MirrorLatencyProfile, local_ip: IpAddr) -> (Duration, u64) {
    let effective = match profile {
        MirrorLatencyProfile::Auto => {
            if is_wireless_ip(local_ip) {
                MirrorLatencyProfile::Normal
            } else {
                MirrorLatencyProfile::Low
            }
        }
        other => other,
    };
    match effective {
        MirrorLatencyProfile::Low => (Duration::from_millis(40), 2205),     // 50ms @ 44.1kHz
        MirrorLatencyProfile::Normal | MirrorLatencyProfile::Auto => {
            (Duration::from_millis(75), 3748)                               // 85ms @ 44.1kHz
        }
        MirrorLatencyProfile::High => (Duration::from_millis(100), 7497),   // 170ms @ 44.1kHz
    }
}

/// Returns true if the network interface owning `local_ip` is wireless (`/sys/class/net/<if>/wireless`).
fn is_wireless_ip(local_ip: IpAddr) -> bool {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return true; // conservative default
    };
    for iface in ifaces {
        if iface.ip() == local_ip {
            let wireless_path = format!("/sys/class/net/{}/wireless", iface.name);
            return Path::new(&wireless_path).exists();
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveCodec {
    H264,
    Hevc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveEncoder {
    Nvenc,
    Vaapi,
    Cpu,
}

fn choose_codec_and_encoder(
    req_codec: MirrorCodec,
    req_encoder: MirrorEncoder,
    device_features: u64,
    caps: HwEncoderCaps,
) -> (ActiveCodec, ActiveEncoder) {
    let receiver_hevc = (device_features & (1u64 << FEATURE_SCREEN_MULTI_CODEC)) != 0;

    let codec = match req_codec {
        MirrorCodec::H264 => ActiveCodec::H264,
        MirrorCodec::Hevc => {
            if receiver_hevc && caps.hevc_available() {
                ActiveCodec::Hevc
            } else {
                ActiveCodec::H264
            }
        }
        MirrorCodec::Auto => {
            // Prefer HEVC automatically only when hardware HEVC is available & receiver supports it
            if receiver_hevc && (caps.nvenc_hevc || caps.vaapi_hevc) {
                ActiveCodec::Hevc
            } else {
                ActiveCodec::H264
            }
        }
    };

    let encoder = match (req_encoder, codec) {
        (MirrorEncoder::Nvenc, ActiveCodec::Hevc) if caps.nvenc_hevc => ActiveEncoder::Nvenc,
        (MirrorEncoder::Nvenc, ActiveCodec::H264) if caps.nvenc_h264 => ActiveEncoder::Nvenc,
        (MirrorEncoder::Vaapi, ActiveCodec::Hevc) if caps.vaapi_hevc => ActiveEncoder::Vaapi,
        (MirrorEncoder::Vaapi, ActiveCodec::H264) if caps.vaapi_h264 => ActiveEncoder::Vaapi,
        (MirrorEncoder::Cpu, _) => ActiveEncoder::Cpu,
        (_, ActiveCodec::Hevc) => {
            if caps.nvenc_hevc {
                ActiveEncoder::Nvenc
            } else if caps.vaapi_hevc {
                ActiveEncoder::Vaapi
            } else {
                ActiveEncoder::Cpu
            }
        }
        (_, ActiveCodec::H264) => {
            if caps.nvenc_h264 {
                ActiveEncoder::Nvenc
            } else if caps.vaapi_h264 {
                ActiveEncoder::Vaapi
            } else {
                ActiveEncoder::Cpu
            }
        }
    };

    (codec, encoder)
}

// ---------------------------------------------------------------------------
// Receiver clock: maps local Instants onto the receiver's PTP timeline.
// ---------------------------------------------------------------------------

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
// H.264 capture reader (FLV on stdout) & HEVC capture reader (Annex-B on stdout)
// ---------------------------------------------------------------------------

enum CapturedVideo {
    Config { payload: Vec<u8> },
    Frame { avcc: Vec<u8>, keyframe: bool, received_at: Instant },
}

enum VideoStreamReader {
    Flv(FlvReader),
    Hevc(HevcAnnexBReader),
}

impl VideoStreamReader {
    async fn next(&mut self) -> Result<Option<CapturedVideo>> {
        match self {
            Self::Flv(r) => r.next().await,
            Self::Hevc(r) => r.next().await,
        }
    }
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
                bail!("encoder did not produce an FLV stream");
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
                continue;
            }
            let keyframe_flag = data[0] >> 4 == 1;
            match data[1] {
                0 => {
                    let (sps, pps, len_size) = parse_avcc_record(&data[5..])
                        .context("malformed AVCDecoderConfigurationRecord from ffmpeg")?;
                    self.nal_len_size = len_size;
                    return Ok(Some(CapturedVideo::Config {
                        payload: build_avcc_config(&sps, &pps),
                    }));
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

struct HevcAnnexBReader {
    r: BufReader<ChildStdout>,
    buf: Vec<u8>,
    vps: Vec<u8>,
    sps: Vec<u8>,
    pps: Vec<u8>,
    sent_cfg: bool,
    width: u32,
    height: u32,
    pending_frame: Option<CapturedVideo>,
}

impl HevcAnnexBReader {
    fn new(stdout: ChildStdout, width: u32, height: u32) -> Self {
        Self {
            r: BufReader::with_capacity(1 << 20, stdout),
            buf: Vec::with_capacity(256 * 1024),
            vps: Vec::new(),
            sps: Vec::new(),
            pps: Vec::new(),
            sent_cfg: false,
            width,
            height,
            pending_frame: None,
        }
    }

    async fn next(&mut self) -> Result<Option<CapturedVideo>> {
        if let Some(f) = self.pending_frame.take() {
            return Ok(Some(f));
        }
        let mut chunk = [0u8; 65536];
        loop {
            if let Some(ev) = self.try_extract_au() {
                return Ok(Some(ev));
            }
            let n = self.r.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn try_extract_au(&mut self) -> Option<CapturedVideo> {
        let starts = find_annexb_starts(&self.buf);
        if starts.len() < 2 {
            return None;
        }
        // Group consecutive NALs up to the next access unit boundary (a new VCL slice after we already saw VCL)
        let mut frame_nals: Vec<u8> = Vec::new();
        let mut keyframe = false;
        let mut has_vcl = false;
        let mut consume_up_to = 0usize;
        let mut cfg_updated = false;

        for w in starts.windows(2) {
            let (sc_start, sc_len) = w[0];
            let next_start = w[1].0;
            let nal = &self.buf[sc_start + sc_len..next_start];
            if nal.len() < 2 {
                consume_up_to = next_start;
                continue;
            }
            let ntype = (nal[0] >> 1) & 0x3f;
            // If we already accumulated VCL slices and hit a parameter set, AUD, or new first slice -> flush AU
            let is_new_au = has_vcl && (matches!(ntype, 32..=35) || (ntype <= 31 && (nal.get(2).copied().unwrap_or(0) & 0x80) != 0));
            if is_new_au {
                break;
            }
            consume_up_to = next_start;
            match ntype {
                32 => {
                    if self.vps != nal {
                        self.vps = nal.to_vec();
                        cfg_updated = true;
                    }
                }
                33 => {
                    if self.sps != nal {
                        self.sps = nal.to_vec();
                        cfg_updated = true;
                    }
                }
                34 => {
                    if self.pps != nal {
                        self.pps = nal.to_vec();
                        cfg_updated = true;
                    }
                }
                35 => {} // AUD
                _ => {
                    frame_nals.extend_from_slice(&(nal.len() as u32).to_be_bytes());
                    frame_nals.extend_from_slice(nal);
                    if ntype <= 31 {
                        has_vcl = true;
                        if (16..=21).contains(&ntype) {
                            keyframe = true;
                        }
                    }
                }
            }
        }

        if consume_up_to == 0 {
            return None;
        }
        self.buf.drain(..consume_up_to);

        if has_vcl && !self.vps.is_empty() && !self.sps.is_empty() && !self.pps.is_empty() {
            let frame = CapturedVideo::Frame {
                avcc: frame_nals,
                keyframe,
                received_at: Instant::now(),
            };
            if (!self.sent_cfg || cfg_updated) && keyframe {
                if let Some(cfg_payload) =
                    build_hevc_sample_description(&self.vps, &self.sps, &self.pps, self.width, self.height)
                {
                    self.sent_cfg = true;
                    self.pending_frame = Some(frame);
                    return Some(CapturedVideo::Config { payload: cfg_payload });
                }
            }
            return Some(frame);
        }
        None
    }
}

fn find_annexb_starts(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 {
            if i + 4 <= buf.len() && buf[i + 2] == 0 && buf[i + 3] == 1 {
                out.push((i, 4));
                i += 4;
                continue;
            } else if buf[i + 2] == 1 {
                out.push((i, 3));
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Build an ISO BMFF `hvc1` VisualSampleEntry + `hvcC` configuration payload from VPS/SPS/PPS.
pub fn build_hevc_sample_description(
    vps: &[u8],
    sps: &[u8],
    pps: &[u8],
    width: u32,
    height: u32,
) -> Option<Vec<u8>> {
    if vps.len() < 2 || sps.len() < 15 || pps.len() < 2 {
        return None;
    }
    // Strip emulation prevention bytes from SPS body to read profile_tier_level cleanly
    let mut rbsp = Vec::with_capacity(sps.len());
    let mut zeros = 0u8;
    for &b in &sps[2..] {
        if zeros == 2 && b == 0x03 {
            zeros = 0;
            continue;
        }
        rbsp.push(b);
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
    }
    if rbsp.len() < 13 {
        return None;
    }
    let max_sub_layers_m1 = (rbsp[0] >> 1) & 7;
    let temporal_nested = rbsp[0] & 1;
    let profile_byte = rbsp[1];
    let compat = &rbsp[2..6];
    let constraints = &rbsp[6..12];
    let level_idc = rbsp[12];

    let mut hvcc = vec![0u8; 23];
    hvcc[0] = 1;
    hvcc[1] = profile_byte;
    hvcc[2..6].copy_from_slice(compat);
    hvcc[6..12].copy_from_slice(constraints);
    hvcc[12] = level_idc;
    hvcc[13..15].copy_from_slice(&0xf000u16.to_be_bytes());
    hvcc[15] = 0xfc;
    hvcc[16] = 0xfc | 1; // 4:2:0
    hvcc[17] = 0xf8;     // 8-bit luma
    hvcc[18] = 0xf8;     // 8-bit chroma
    hvcc[21] = ((max_sub_layers_m1 + 1) << 3) | (temporal_nested << 2) | 3; // 4-byte NAL lengths
    hvcc[22] = 3; // 3 parameter set arrays

    for (nal_type, nal) in [(32u8, vps), (33u8, sps), (34u8, pps)] {
        if nal.len() > 0xffff {
            return None;
        }
        hvcc.push(0x80 | nal_type);
        hvcc.extend_from_slice(&1u16.to_be_bytes());
        hvcc.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        hvcc.extend_from_slice(nal);
    }

    const VSE_SIZE: usize = 86;
    let total = VSE_SIZE + 8 + hvcc.len();
    let mut payload = vec![0u8; total];
    payload[0..4].copy_from_slice(&(total as u32).to_be_bytes());
    payload[4..8].copy_from_slice(b"hvc1");
    payload[14..16].copy_from_slice(&1u16.to_be_bytes());
    payload[32..34].copy_from_slice(&(width as u16).to_be_bytes());
    payload[34..36].copy_from_slice(&(height as u16).to_be_bytes());
    payload[36..40].copy_from_slice(&0x0048_0000u32.to_be_bytes());
    payload[40..44].copy_from_slice(&0x0048_0000u32.to_be_bytes());
    payload[48..50].copy_from_slice(&1u16.to_be_bytes());
    payload[82..84].copy_from_slice(&0x0018u16.to_be_bytes());
    payload[84..86].copy_from_slice(&0xffffu16.to_be_bytes());
    payload[86..90].copy_from_slice(&((8 + hvcc.len()) as u32).to_be_bytes());
    payload[90..94].copy_from_slice(b"hvcC");
    payload[94..].copy_from_slice(&hvcc);
    Some(payload)
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

async fn resolve_target_display(requested: Option<&str>) -> DisplayInfo {
    let displays = list_displays().await;
    if let Some(req) = requested.filter(|s| !s.is_empty() && *s != "auto") {
        if let Some(found) = displays.iter().find(|d| d.name == req) {
            return found.clone();
        }
    }
    if let Some(primary) = displays.iter().find(|d| d.primary) {
        return primary.clone();
    }
    if let Some(first) = displays.into_iter().next() {
        return first;
    }
    // Fallback to xrandr --current active mode
    let (w, h) = detect_screen_size().await.unwrap_or((1280, 720));
    DisplayInfo {
        name: "default".into(),
        width: w,
        height: h,
        x: 0,
        y: 0,
        primary: true,
    }
}

async fn detect_screen_size() -> Option<(u32, u32)> {
    let out = Command::new("xrandr").arg("--current").output().await.ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains('*'))?;
    let (w, h) = line.split_whitespace().next()?.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

fn encode_size(w: u32, h: u32, codec: ActiveCodec) -> (u32, u32) {
    let max_w = match codec {
        ActiveCodec::Hevc => 3840,
        ActiveCodec::H264 => 1920,
    };
    let (w, h) = if w > max_w {
        (max_w, h * max_w / w)
    } else {
        (w, h)
    };
    (w & !1, h & !1)
}

/// Try Wayland XDG Desktop Portal ScreenCast via zbus -> PipeWire node ID -> GStreamer FLV pipe.
async fn try_spawn_wayland_capture(fps: u32, out: (u32, u32), show_cursor: bool) -> Result<Child> {
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    let has_gst = std::process::Command::new("gst-launch-1.0")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !has_gst {
        bail!("gst-launch-1.0 not installed for Wayland PipeWire screen capture");
    }

    let conn = zbus::Connection::session().await.context("D-Bus session connect")?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await?;

    let token = format!("nixplay_{}", rand::random::<u32>());
    let mut opts: HashMap<&str, Value<'_>> = HashMap::new();
    opts.insert("handle_token", Value::from(format!("h_{token}")));
    opts.insert("session_handle_token", Value::from(token.as_str()));

    let req_path: OwnedObjectPath = proxy.call("CreateSession", &(opts,)).await?;
    let sess_path = wait_portal_session_handle(&conn, &req_path).await?;

    let mut sel: HashMap<&str, Value<'_>> = HashMap::new();
    sel.insert("handle_token", Value::from(format!("sel_{}", rand::random::<u32>())));
    sel.insert("types", Value::from(1u32)); // MONITOR
    sel.insert("multiple", Value::from(false));
    sel.insert("cursor_mode", Value::from(if show_cursor { 2u32 } else { 1u32 }));
    let sel_req: OwnedObjectPath = proxy.call("SelectSources", &(&sess_path, sel)).await?;
    let _ = wait_portal_response(&conn, &sel_req).await?;

    let mut start_opts: HashMap<&str, Value<'_>> = HashMap::new();
    start_opts.insert("handle_token", Value::from(format!("st_{}", rand::random::<u32>())));
    let start_req: OwnedObjectPath = proxy.call("Start", &(&sess_path, "", start_opts)).await?;
    let results = wait_portal_response(&conn, &start_req).await?;

    // Extract first stream's PipeWire node_id from results["streams"] -> a(ua{sv})
    let node_id = results
        .get("streams")
        .and_then(|v: &OwnedValue| {
            let arr = zbus::zvariant::Array::try_from(v.clone()).ok()?;
            let first = arr.first()?;
            let st = zbus::zvariant::Structure::try_from(first.clone()).ok()?;
            u32::try_from(st.fields().first()?.clone()).ok()
        })
        .context("XDG Desktop Portal returned no PipeWire screen stream (cancelled?)")?;

    let gop = fps * 2;
    let pipeline = format!(
        "pipewiresrc path={node_id} do-timestamp=true ! videoconvert ! videoscale ! video/x-raw,format=I420,width={},height={},framerate={fps}/1 ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=8000 key-int-max={gop} bframes=0 ! h264parse ! flvmux streamable=true ! fdsink fd=1",
        out.0, out.1
    );
    let mut cmd = Command::new("gst-launch-1.0");
    cmd.arg("-q")
        .args(pipeline.split_whitespace())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn().context("spawn gst-launch-1.0 for Wayland capture")?;
    Ok(child)
}

async fn wait_portal_response(
    conn: &zbus::Connection,
    req_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
    use futures_util::StreamExt;
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        req_path.as_str(),
        "org.freedesktop.portal.Request",
    )
    .await?;
    let mut stream = proxy.receive_signal("Response").await?;
    let msg = tokio::time::timeout(Duration::from_secs(60), stream.next())
        .await
        .context("timed out waiting for Wayland screen share dialog")?
        .context("portal request signal closed")?;
    let (code, results): (u32, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) =
        msg.body().deserialize()?;
    if code != 0 {
        bail!("Wayland screen share cancelled or denied (code {code})");
    }
    Ok(results)
}

async fn wait_portal_session_handle(
    conn: &zbus::Connection,
    req_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<zbus::zvariant::OwnedObjectPath> {
    let results = wait_portal_response(conn, req_path).await?;
    let s = results
        .get("session_handle")
        .and_then(|v| <&str>::try_from(v).ok())
        .context("portal response missing session_handle")?;
    Ok(zbus::zvariant::OwnedObjectPath::try_from(s.to_string())?)
}

fn spawn_video_capture(
    opts: &MirrorOptions,
    disp: &DisplayInfo,
    out: (u32, u32),
    codec: ActiveCodec,
    encoder: ActiveEncoder,
) -> Result<Child> {
    let display_env = std::env::var("DISPLAY").unwrap_or_else(|_| ":0.0".into());
    let input_spec = format!("{display_env}+{},{}", disp.x, disp.y);
    let gop = (opts.fps * 2).to_string();
    let bitrate_k = if opts.bitrate_kbps > 0 {
        opts.bitrate_kbps.clamp(1500, 25000)
    } else if out.0 > 1920 {
        14000
    } else if opts.fps >= 50 {
        12000
    } else {
        8000
    };
    let bitrate = format!("{bitrate_k}k");
    let maxrate = format!("{}k", (bitrate_k as f32 * 1.25) as u32);
    let bufsize = format!("{}k", (bitrate_k / 2).max(1500));

    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-hide_banner", "-loglevel", "warning", "-nostdin"])
        .args(["-fflags", "nobuffer", "-probesize", "32", "-analyzeduration", "0"]);

    if encoder == ActiveEncoder::Vaapi {
        cmd.args(["-vaapi_device", "/dev/dri/renderD128"]);
    }

    cmd.args([
        "-f",
        "x11grab",
        "-draw_mouse",
        if opts.show_cursor { "1" } else { "0" },
        "-framerate",
        &opts.fps.to_string(),
        "-video_size",
        &format!("{}x{}", disp.width & !1, disp.height & !1),
        "-i",
        &input_spec,
    ]);

    match (encoder, codec) {
        (ActiveEncoder::Vaapi, ActiveCodec::H264) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=nv12,hwupload", out.0, out.1),
                "-c:v",
                "h264_vaapi",
                "-bf",
                "0",
                "-g",
                &gop,
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
        (ActiveEncoder::Vaapi, ActiveCodec::Hevc) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=nv12,hwupload", out.0, out.1),
                "-c:v",
                "hevc_vaapi",
                "-bf",
                "0",
                "-g",
                &gop,
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
        (ActiveEncoder::Nvenc, ActiveCodec::H264) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=yuv420p", out.0, out.1),
                "-c:v",
                "h264_nvenc",
                "-preset",
                "p1",
                "-tune",
                "ull",
                "-rc",
                "cbr",
                "-bf",
                "0",
                "-g",
                &gop,
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
        (ActiveEncoder::Nvenc, ActiveCodec::Hevc) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=yuv420p", out.0, out.1),
                "-c:v",
                "hevc_nvenc",
                "-preset",
                "p1",
                "-tune",
                "ull",
                "-rc",
                "cbr",
                "-bf",
                "0",
                "-g",
                &gop,
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
        (ActiveEncoder::Cpu, ActiveCodec::H264) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=yuv420p", out.0, out.1),
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-profile:v",
                "high",
                "-level:v",
                "4.2",
                "-bf",
                "0",
                "-g",
                &gop,
                "-keyint_min",
                &gop,
                "-sc_threshold",
                "0",
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
        (ActiveEncoder::Cpu, ActiveCodec::Hevc) => {
            cmd.args([
                "-vf",
                &format!("scale={}:{}:flags=bicubic,format=yuv420p", out.0, out.1),
                "-c:v",
                "libx265",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-x265-params",
                &format!("keyint={gop}:min-keyint={gop}:bframes=0:repeat-headers=1"),
                "-b:v",
                &bitrate,
                "-maxrate",
                &maxrate,
                "-bufsize",
                &bufsize,
            ]);
        }
    }

    cmd.args(["-an", "-flush_packets", "1"]);
    match codec {
        ActiveCodec::H264 => {
            cmd.args(["-f", "flv", "-flvflags", "no_duration_filesize", "pipe:1"]);
        }
        ActiveCodec::Hevc => {
            cmd.args(["-f", "hevc", "pipe:1"]);
        }
    }

    cmd.stdin(std::process::Stdio::null())
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
    codec: ActiveCodec,
}

fn put_f32(h: &mut [u8], at: usize, v: f32) {
    h[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

impl DataChannel {
    async fn send_codec(&mut self, config: &[u8], ts: u64) -> Result<()> {
        let mut h = [0u8; 128];
        h[0..4].copy_from_slice(&(config.len() as u32).to_le_bytes());
        h[4] = 0x01; // codec configuration (sent in the clear)
        h[6] = match self.codec {
            ActiveCodec::H264 => 0x16,
            ActiveCodec::Hevc => 0x1e,
        };
        h[7] = 0x01;
        h[8..16].copy_from_slice(&ts.to_le_bytes());
        let (w, hh) = (self.width as f32, self.height as f32);
        for at in [16, 40, 56] {
            put_f32(&mut h, at, w);
            put_f32(&mut h, at + 4, hh);
        }
        let mut buf = Vec::with_capacity(128 + config.len());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(config);
        self.sock.write_all(&buf).await.context("write codec packet")
    }

    async fn send_frame(&mut self, avcc: &[u8], keyframe: bool, ts: u64, timeline: u64) -> Result<()> {
        let mut h = [0u8; 128];
        h[0..4].copy_from_slice(&((avcc.len() + 16) as u32).to_le_bytes());
        h[4] = 0x00; // encrypted video
        h[5] = if keyframe { 0x10 } else { 0x00 };
        h[8..16].copy_from_slice(&ts.to_le_bytes());
        h[40..48].copy_from_slice(&timeline.to_le_bytes());
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
// Screen audio (stream type 96): ALAC frames over RTP/UDP, ChaCha20-Poly1305 sealed
// ---------------------------------------------------------------------------

const AUDIO_SPF: usize = 352;
const AUDIO_RATE: u64 = 44100;

fn spawn_audio_capture(audio: ScreenAudio, desktop_source: &str) -> Result<Child> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-hide_banner", "-loglevel", "warning", "-nostdin", "-fflags", "nobuffer"]);
    let sources: Vec<&str> = match audio {
        ScreenAudio::DesktopAndMic => vec![desktop_source, "default"],
        _ => vec![desktop_source],
    };
    for src in &sources {
        cmd.args(["-f", "pulse", "-fragment_size", "1764", "-i", src]);
    }
    if sources.len() > 1 {
        cmd.args([
            "-filter_complex",
            "[0:a][1:a]amix=inputs=2:duration=longest:normalize=0[a]",
            "-map",
            "[a]",
        ]);
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
    latency_samples: u64,
}

impl AudioSender {
    fn packet(&mut self, payload: &[u8], rtp: u32) -> Result<Vec<u8>> {
        let mut pkt = Vec::with_capacity(12 + payload.len() + 16 + 8);
        pkt.extend_from_slice(&[0x80, 0x60]);
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        pkt.extend_from_slice(&rtp.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
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

    async fn sync(&self, rtp_now: u32, ptp_ts: u64, timeline: u64, first: bool) -> Result<()> {
        let playhead = rtp_now.wrapping_sub(self.latency_samples as u32);
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
    let start = Instant::now();
    let rtp0: u32 = rand::random::<u32>() & 0x7fff_ffff;
    let rtp_at = |at: Instant| -> u32 {
        let el = at.saturating_duration_since(start);
        rtp0.wrapping_add(
            (el.as_secs() * AUDIO_RATE + el.subsec_nanos() as u64 * AUDIO_RATE / 1_000_000_000) as u32,
        )
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

async fn setup(
    rtsp: &mut RtspClient,
    uri: &str,
    phase: &str,
    body: plist::Value,
) -> Result<(plist::Dictionary, RtspResponse, Instant)> {
    debug!("mirror {phase} SETUP -> {body:?}");
    let resp = rtsp
        .request_plist("SETUP", uri, &[], &body)
        .await
        .with_context(|| format!("{phase} SETUP"))?;
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
    let _ekey = fp.wrap_key(raw_key)?;
    let master = fairplay::derive_stream_master_key(&raw_key, shared_secret, true);
    let mut key = [0u8; 16];
    key.copy_from_slice(&master[..16]);
    Ok((key, iv))
}

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

    let caps = probe_hw_encoders();
    let (mut active_codec, active_encoder) =
        choose_codec_and_encoder(opts.codec, opts.encoder, device.features, caps);
    let disp = resolve_target_display(opts.display.as_deref()).await;
    let (enc_w, enc_h) = encode_size(disp.width, disp.height, active_codec);

    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|v| v.eq_ignore_ascii_case("wayland"));

    let (mut capture, mut reader) = if is_wayland && std::env::var("DISPLAY").is_err() {
        active_codec = ActiveCodec::H264;
        let mut child = try_spawn_wayland_capture(opts.fps, (enc_w, enc_h), opts.show_cursor).await?;
        let stdout = child.stdout.take().context("wayland capture stdout")?;
        (child, VideoStreamReader::Flv(FlvReader::new(stdout)))
    } else {
        let mut child = spawn_video_capture(opts, &disp, (enc_w, enc_h), active_codec, active_encoder)?;
        let stdout = child.stdout.take().context("ffmpeg stdout")?;
        let reader = match active_codec {
            ActiveCodec::H264 => VideoStreamReader::Flv(FlvReader::new(stdout)),
            ActiveCodec::Hevc => VideoStreamReader::Hevc(HevcAnnexBReader::new(stdout, enc_w, enc_h)),
        };
        (child, reader)
    };

    info!(
        "Mirror capture started: monitor={} ({}x{} -> {}x{} @ {}fps, codec={:?}, encoder={:?}, cursor={})",
        disp.name, disp.width, disp.height, enc_w, enc_h, opts.fps, active_codec, active_encoder, opts.show_cursor
    );

    let conn = connect_and_authenticate(device, creds.as_ref()).await?;
    let mut rtsp = conn.rtsp;
    let shared_secret = conn.shared_secret;
    let (target_ip, target_scope) = (conn.target_ip, conn.target_scope);
    let port = device.airplay_port.or(device.raop_port).unwrap_or(7000);
    let local_ip = rtsp.local_addr()?.ip();
    let host = host_for_uri(target_ip);
    let (video_latency, audio_latency_samples) = resolve_latency_targets(opts.latency, local_ip);

    let (fp_key, fp_iv) = fairplay_setup(&mut rtsp, &shared_secret).await?;
    info!(
        "FairPlay SAP handshake complete with '{}' (video lead={}ms)",
        device.name,
        video_latency.as_millis()
    );

    let session_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let sid: u64 = rand::random();
    let mac = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        0x02 | (sid as u8 & 0xfc),
        (sid >> 8) as u8,
        (sid >> 16) as u8,
        (sid >> 24) as u8,
        (sid >> 32) as u8,
        (sid >> 40) as u8
    );
    let audio_id = random_conn_id();
    let audio_uri = format!("rtsp://{host}:{port}/{audio_id}");

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
            spawn_events_channel(
                target_ip,
                ep as u16,
                target_scope,
                shared_secret.clone(),
                device.name.clone(),
                Some(event_tx),
            )
            .await
        }
        _ => None,
    };

    let mut timeline_id = ctrl
        .get("timingPeerInfo")
        .and_then(|p| p.as_dictionary())
        .and_then(|p| pl_get_u64(p.get("ClockID")))
        .unwrap_or(0);
    if timeline_id == 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while timeline_id == 0 {
            let ev = tokio::time::timeout_at(deadline, event_rx.recv()).await;
            let Ok(Some(ev)) = ev else { break };
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
        ("latencyMax", pl_int(audio_latency_samples as i64)),
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
                        pl_dict(vec![(
                            "streamConnectionKeyUseStreamEncryptionKey",
                            plist::Value::Boolean(true),
                        )]),
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
            ("latencyMs", pl_int(video_latency.as_millis() as i64)),
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
        codec: active_codec,
    };

    let (pump_done_tx, mut pump_done_rx) = oneshot::channel::<Result<()>>();
    let (first_frame_tx, mut first_frame_rx) = oneshot::channel::<()>();
    let pump_clock = clock.clone();
    let pump = tokio::spawn(async move {
        let res = pump_frames(&mut reader, &mut data, pump_clock, video_latency, first_frame_tx).await;
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
                    info!("Screen mirroring live on '{}' ({enc_w}x{enc_h} @ {}fps, {:?})", device.name, opts.fps, active_codec);
                    if opts.audio.is_enabled() {
                        match start_audio(opts.audio, audio_ports, &audio_key, &audio_ctrl_sock, target_ip, target_scope, clock.clone(), audio_latency_samples).await {
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
    if let Some(route) = audio_route {
        route.restore().await;
    }
    let _ = capture.kill().await;
    let empty = pl_dict(vec![]);
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        rtsp.request_plist("TEARDOWN", &audio_uri, &[], &empty),
    )
    .await;
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
    latency_samples: u64,
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
        latency_samples,
    };
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
    let peer = d.get("timingPeerInfo").or_else(|| {
        d.get("params")
            .and_then(|p| p.as_dictionary())
            .and_then(|p| p.get("timingPeerInfo"))
    })?;
    pl_get_u64(peer.as_dictionary()?.get("ClockID")).filter(|id| *id != 0)
}

async fn pump_frames(
    reader: &mut VideoStreamReader,
    data: &mut DataChannel,
    clock: Arc<Mutex<ReceiverClock>>,
    video_latency: Duration,
    first_frame_tx: oneshot::Sender<()>,
) -> Result<()> {
    let mut first_frame_tx = Some(first_frame_tx);
    let mut config: Option<Vec<u8>> = None;
    let mut sent_config: Option<Vec<u8>> = None;
    let mut last_ts = 0u64;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    heartbeat.tick().await;
    let mut frames = 0u64;
    loop {
        let item = tokio::select! {
            item = reader.next() => item?,
            _ = heartbeat.tick(), if first_frame_tx.is_none() => {
                data.send_heartbeat().await?;
                continue;
            }
        };
        let Some(item) = item else { return Ok(()) };
        match item {
            CapturedVideo::Config { payload } => config = Some(payload),
            CapturedVideo::Frame { avcc, keyframe, received_at } => {
                let Some(cfg) = config.as_ref() else { continue };
                if sent_config.is_none() && !keyframe {
                    continue;
                }
                let (ts, timeline) = {
                    let c = clock.lock().map_err(|_| anyhow::anyhow!("clock poisoned"))?;
                    (c.at(received_at, video_latency), c.timeline_id)
                };
                let ts = if ts <= last_ts { last_ts + 1 } else { ts };
                last_ts = ts;
                if keyframe && sent_config.as_ref() != Some(cfg) {
                    data.send_codec(cfg, ts).await?;
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

    #[test]
    fn parses_xrandr_multi_monitor_query() {
        let sample = "\
Screen 0: minimum 320 x 200, current 4480 x 1440, maximum 16384 x 16384
DP-1 connected primary 2560x1440+0+0 (normal left inverted right) 597mm x 336mm
   2560x1440    144.00*+
HDMI-1 connected 1920x1080+2560+180 (normal left inverted right) 527mm x 296mm
   1920x1080     60.00*+
DP-2 disconnected (normal left inverted right)
";
        let list = parse_xrandr_displays(sample);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], DisplayInfo { name: "DP-1".into(), width: 2560, height: 1440, x: 0, y: 0, primary: true });
        assert_eq!(list[1], DisplayInfo { name: "HDMI-1".into(), width: 1920, height: 1080, x: 2560, y: 180, primary: false });
    }

    #[test]
    fn codec_and_encoder_selection_respects_capabilities() {
        let caps = HwEncoderCaps {
            vaapi_h264: true,
            vaapi_hevc: true,
            nvenc_h264: false,
            nvenc_hevc: false,
            libx265: true,
        };
        // Receiver supports bit 42 + Auto -> picks HEVC + VAAPI
        assert_eq!(
            choose_codec_and_encoder(MirrorCodec::Auto, MirrorEncoder::Auto, 1u64 << 42, caps),
            (ActiveCodec::Hevc, ActiveEncoder::Vaapi)
        );
        // Receiver without bit 42 -> falls back to H.264 + VAAPI
        assert_eq!(
            choose_codec_and_encoder(MirrorCodec::Hevc, MirrorEncoder::Auto, 0, caps),
            (ActiveCodec::H264, ActiveEncoder::Vaapi)
        );
    }
}
