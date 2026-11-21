use super::auth::{connect_and_authenticate, make_sockaddr, spawn_events_channel};
use super::rtsp::RtspClient;
use super::{build_dmap_metadata, volume_pct_to_airplay_db, MetadataInfo, SpeakerCommand, SpeakerState};
use crate::audio::alac::{SAMPLES_PER_FRAME, SAMPLE_RATE};
use crate::audio::{now_ntp, AudioEngine, AudioPacket};
use crate::config::HapCredentials;
use crate::discovery::AirPlayDevice;
use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

const RTP_PAYLOAD_TYPE_REALTIME: u8 = 0x60; // 96
const RTP_MARKER_BIT: u8 = 0x80;
const BASE_LATENCY_SAMPLES: i64 = 11025; // 250ms @ 44100 Hz

pub async fn run_airplay2_session(
    device: AirPlayDevice,
    creds: Option<HapCredentials>,
    initial_volume: u8,
    initial_latency_offset_ms: i32,
    audio_engine: Arc<AudioEngine>,
    mut cmd_rx: mpsc::Receiver<SpeakerCommand>,
    state_tx: watch::Sender<SpeakerState>,
) -> Result<()> {
    let _ = state_tx.send(SpeakerState::Connecting);

    // 1. Connect (auto VPN/Tailscale direct-LAN bypass) + HAP authenticate (pair-verify or transient)
    let conn = connect_and_authenticate(&device, creds.as_ref()).await?;
    let mut rtsp = conn.rtsp;
    let target_ip = conn.target_ip;
    let target_scope = conn.target_scope;
    let shared_secret = conn.shared_secret;

    // 2. Bind local UDP sockets for audio data, RTCP control, and NTP timing
    let local_ip = rtsp.local_addr()?.ip();
    let bind_ip = match local_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    let data_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    let ctrl_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    let timing_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);

    let local_ctrl_port = ctrl_sock.local_addr()?.port();
    let local_timing_port = timing_sock.local_addr()?.port();

    let session_id: u32 = rand::random();
    let session_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
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

    // Spawn NTP timing responder immediately so receiver can sync during SETUP
    let timing_handle = {
        let timing_sock = timing_sock.clone();
        tokio::spawn(async move {
            run_ntp_timing_responder(timing_sock).await;
        })
    };

    // 3. Stage 1 SETUP (session + NTP timing)
    let mut setup1_dict = plist::Dictionary::new();
    setup1_dict.insert("deviceID".into(), plist::Value::String(device_mac));
    setup1_dict.insert("name".into(), plist::Value::String("NixPlay".into()));
    setup1_dict.insert("sessionUUID".into(), plist::Value::String(session_uuid));
    setup1_dict.insert(
        "timingPort".into(),
        plist::Value::Integer((local_timing_port as u64).into()),
    );
    setup1_dict.insert("timingProtocol".into(), plist::Value::String("NTP".into()));

    let setup1_resp = rtsp
        .request_plist("SETUP", &session_uri, &[], &plist::Value::Dictionary(setup1_dict))
        .await
        .context("AirPlay 2 SETUP (session) failed")?;
    if setup1_resp.status_code != 200 {
        timing_handle.abort();
        bail!(
            "AirPlay 2 SETUP (session) rejected by '{}': {}",
            device.name,
            setup1_resp.status_line
        );
    }

    let mut event_port: Option<u16> = None;
    let mut skip_record = false;
    if let Ok(pl) = setup1_resp.body_plist() {
        debug!("SETUP (session) reply from '{}': {:?}", device.name, pl);
        if let Some(dict) = pl.as_dictionary() {
            event_port = dict
                .get("eventPort")
                .and_then(|v| v.as_unsigned_integer())
                .map(|p| p as u16);
            skip_record = dict
                .get("skipRecord")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);
        }
    }

    let events_handle = if let Some(ep) = event_port {
        spawn_events_channel(
            target_ip,
            ep,
            target_scope,
            shared_secret.clone(),
            device.name.clone(),
            None,
        )
        .await
    } else {
        None
    };

    // 4. RECORD
    if !skip_record {
        let record_resp = rtsp
            .request("RECORD", &session_uri, &[], None)
            .await
            .context("AirPlay 2 RECORD failed")?;
        if record_resp.status_code != 200 {
            timing_handle.abort();
            if let Some(h) = events_handle {
                h.abort();
            }
            bail!(
                "AirPlay 2 RECORD rejected by '{}': {}",
                device.name,
                record_resp.status_line
            );
        }
    }

    // 5. Stage 2 SETUP (real-time ALAC stream with 32-byte shk from shared_secret[0..32])
    let audio_key: [u8; 32] = shared_secret[..32]
        .try_into()
        .context("shared secret shorter than 32 bytes")?;
    let mut stream_dict = plist::Dictionary::new();
    stream_dict.insert(
        "audioFormat".into(),
        plist::Value::Integer(262144u64.into()), // 0x40000 = ALAC/44100/16/2
    );
    stream_dict.insert("audioMode".into(), plist::Value::String("default".into()));
    stream_dict.insert(
        "controlPort".into(),
        plist::Value::Integer((local_ctrl_port as u64).into()),
    );
    stream_dict.insert("ct".into(), plist::Value::Integer(2u64.into())); // 2 = ALAC
    stream_dict.insert("isMedia".into(), plist::Value::Boolean(true));
    stream_dict.insert("latencyMax".into(), plist::Value::Integer(88200u64.into()));
    stream_dict.insert(
        "latencyMin".into(),
        plist::Value::Integer((BASE_LATENCY_SAMPLES as u64).into()),
    );
    stream_dict.insert("shk".into(), plist::Value::Data(audio_key.to_vec()));
    stream_dict.insert(
        "spf".into(),
        plist::Value::Integer((SAMPLES_PER_FRAME as u64).into()),
    );
    stream_dict.insert("sr".into(), plist::Value::Integer((SAMPLE_RATE as u64).into()));
    stream_dict.insert(
        "type".into(),
        plist::Value::Integer((RTP_PAYLOAD_TYPE_REALTIME as u64).into()),
    );
    stream_dict.insert("supportsDynamicStreamID".into(), plist::Value::Boolean(false));
    stream_dict.insert(
        "streamConnectionID".into(),
        plist::Value::Integer((session_id as u64).into()),
    );

    let mut setup2_dict = plist::Dictionary::new();
    setup2_dict.insert(
        "streams".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_dict)]),
    );

    let setup2_resp = rtsp
        .request_plist("SETUP", &session_uri, &[], &plist::Value::Dictionary(setup2_dict))
        .await
        .context("AirPlay 2 SETUP (stream) failed")?;
    if setup2_resp.status_code != 200 {
        debug!(
            "SETUP (stream) failure headers={:?}, body={:?}",
            setup2_resp.headers,
            String::from_utf8_lossy(&setup2_resp.body)
        );
        timing_handle.abort();
        if let Some(h) = events_handle {
            h.abort();
        }
        bail!(
            "AirPlay 2 SETUP (stream) rejected by '{}': {}",
            device.name,
            setup2_resp.status_line
        );
    }

    let setup2_plist = setup2_resp.body_plist()?;
    let (remote_data_port, remote_ctrl_port) = parse_stream_ports(&setup2_plist)?;
    let remote_data_addr = make_sockaddr(target_ip, remote_data_port, target_scope);
    let remote_ctrl_addr = make_sockaddr(target_ip, remote_ctrl_port, target_scope);
    info!(
        "AirPlay 2 stream active for '{}': data={}, control={}",
        device.name, remote_data_addr, remote_ctrl_addr
    );

    // 6. Set initial volume
    send_volume(&mut rtsp, &session_uri, initial_volume).await.ok();

    let _ = state_tx.send(SpeakerState::Streaming);

    let pkt_cipher = Arc::new(ChaCha20Poly1305::new((&audio_key).into()));
    let ssrc: u32 = rand::random();

    let retransmit_handle = {
        let ctrl_sock = ctrl_sock.clone();
        let engine = audio_engine.clone();
        let cipher = pkt_cipher.clone();
        tokio::spawn(async move {
            run_retransmit_responder(ctrl_sock, remote_ctrl_addr, engine, Some(cipher), ssrc).await;
        })
    };

    let mut pkt_rx = audio_engine.subscribe();
    let mut feedback_interval = tokio::time::interval(Duration::from_secs(20));
    feedback_interval.tick().await;

    let mut latency_offset_ms = initial_latency_offset_ms;
    let mut first_packet = true;
    let mut running = true;

    while running {
        tokio::select! {
            pkt_res = pkt_rx.recv() => {
                match pkt_res {
                    Ok(pkt) => {
                        let offset_samples = (latency_offset_ms as i64 * SAMPLE_RATE as i64) / 1000;
                        let effective_latency = (BASE_LATENCY_SAMPLES + offset_samples).clamp(2205, 88200) as u32;

                        if first_packet || pkt.is_sync_tick {
                            let sync_pkt = build_ntp_sync_packet(
                                pkt.rtp_time.wrapping_sub(effective_latency),
                                pkt.ntp_sec,
                                pkt.ntp_frac,
                                pkt.rtp_time,
                                first_packet,
                            );
                            let _ = ctrl_sock.send_to(&sync_pkt, remote_ctrl_addr).await;
                        }

                        let wire = encrypt_airplay2_rtp(&pkt, ssrc, first_packet, &pkt_cipher);
                        if let Err(e) = data_sock.send_to(&wire, remote_data_addr).await {
                            warn!("UDP send error to '{}': {e}", device.name);
                        }
                        first_packet = false;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!("Speaker '{}' lagged {n} audio frames", device.name);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        running = false;
                    }
                }
            }
            _ = feedback_interval.tick() => {
                if let Err(e) = rtsp.request("POST", "/feedback", &[], None).await {
                    warn!("Feedback keepalive failed for '{}': {e}", device.name);
                    running = false;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SpeakerCommand::SetVolume(vol)) => {
                        if let Err(e) = send_volume(&mut rtsp, &session_uri, vol).await {
                            warn!("SetVolume failed for '{}': {e}", device.name);
                        }
                    }
                    Some(SpeakerCommand::SetLatencyOffset(ms)) => {
                        latency_offset_ms = ms;
                        first_packet = true;
                    }
                    Some(SpeakerCommand::UpdateMetadata(meta)) => {
                        let _ = send_metadata(&mut rtsp, &session_uri, audio_engine.current_rtp_time(), &meta).await;
                    }
                    Some(SpeakerCommand::Disconnect) | None => {
                        running = false;
                    }
                }
            }
        }
    }

    // Clean teardown
    timing_handle.abort();
    retransmit_handle.abort();
    if let Some(h) = events_handle {
        h.abort();
    }

    let flush_hdr = format!(
        "seq={};rtptime={}",
        audio_engine.current_seq(),
        audio_engine.current_rtp_time()
    );
    let _ = rtsp
        .request("FLUSH", &session_uri, &[("RTP-Info", &flush_hdr)], None)
        .await;
    let empty_dict = plist::Value::Dictionary(plist::Dictionary::new());
    let _ = rtsp
        .request_plist("TEARDOWN", &session_uri, &[], &empty_dict)
        .await;

    let _ = state_tx.send(SpeakerState::Disconnected);
    info!("AirPlay 2 session closed cleanly for '{}'", device.name);
    Ok(())
}

fn parse_stream_ports(val: &plist::Value) -> Result<(u16, u16)> {
    let dict = val.as_dictionary().context("SETUP response not a dict")?;
    let streams = dict
        .get("streams")
        .and_then(|v| v.as_array())
        .context("SETUP response missing 'streams' array")?;
    let first = streams
        .first()
        .and_then(|v| v.as_dictionary())
        .context("SETUP 'streams' array empty")?;
    let data_port = first
        .get("dataPort")
        .and_then(|v| v.as_unsigned_integer())
        .context("SETUP response missing 'dataPort'")? as u16;
    let ctrl_port = first
        .get("controlPort")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(data_port as u64) as u16;
    Ok((data_port, ctrl_port))
}

async fn send_volume(rtsp: &mut RtspClient, uri: &str, vol: u8) -> Result<()> {
    let db = volume_pct_to_airplay_db(vol);
    let body = format!("volume: {db:.6}\r\n");
    rtsp.request(
        "SET_PARAMETER",
        uri,
        &[],
        Some(("text/parameters", body.as_bytes())),
    )
    .await?;
    Ok(())
}

async fn send_metadata(
    rtsp: &mut RtspClient,
    uri: &str,
    rtp_time: u32,
    meta: &MetadataInfo,
) -> Result<()> {
    let dmap = build_dmap_metadata(&meta.title, &meta.artist, &meta.album);
    let rtp_info = format!("rtptime={rtp_time}");
    rtsp.request(
        "SET_PARAMETER",
        uri,
        &[("RTP-Info", &rtp_info)],
        Some(("application/x-dmap-tagged", &dmap)),
    )
    .await?;
    Ok(())
}

/// Build an AirPlay 2 ChaCha20-Poly1305 encrypted RTP audio packet:
/// `[12-byte RTP header][encrypted ALAC][16-byte Poly1305 tag][8-byte truncated nonce]`
pub fn encrypt_airplay2_rtp(
    pkt: &AudioPacket,
    ssrc: u32,
    marker: bool,
    cipher: &ChaCha20Poly1305,
) -> Vec<u8> {
    let mut header = [0u8; 12];
    header[0] = 0x80;
    header[1] = if marker {
        RTP_PAYLOAD_TYPE_REALTIME | RTP_MARKER_BIT
    } else {
        RTP_PAYLOAD_TYPE_REALTIME
    };
    header[2..4].copy_from_slice(&pkt.seq.to_be_bytes());
    header[4..8].copy_from_slice(&pkt.rtp_time.to_be_bytes());
    header[8..12].copy_from_slice(&ssrc.to_be_bytes());

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..6].copy_from_slice(&pkt.seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = &header[4..12];
    let ct_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &pkt.alac_payload,
                aad,
            },
        )
        .expect("ChaCha20Poly1305 RTP encrypt");

    let mut out = Vec::with_capacity(12 + ct_with_tag.len() + 8);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct_with_tag);
    out.extend_from_slice(&nonce_bytes[4..12]);
    out
}

/// Build a 20-byte AirPlay NTP RTCP sync packet (`PT = 0xd4`).
pub fn build_ntp_sync_packet(
    cur_pos: u32,
    ntp_sec: u32,
    ntp_frac: u32,
    next_rtp_time: u32,
    first: bool,
) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0] = if first { 0x90 } else { 0x80 };
    buf[1] = 0xd4;
    buf[2] = 0x00;
    buf[3] = 0x07;
    buf[4..8].copy_from_slice(&cur_pos.to_be_bytes());
    buf[8..12].copy_from_slice(&ntp_sec.to_be_bytes());
    buf[12..16].copy_from_slice(&ntp_frac.to_be_bytes());
    buf[16..20].copy_from_slice(&next_rtp_time.to_be_bytes());
    buf
}

/// Respond to receiver AirPlay NTP timing queries (`0x80 0xd2` -> `0x80 0xd3`).
pub async fn run_ntp_timing_responder(sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 64];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            break;
        };
        debug!(
            "NTP timing packet ({n} bytes, pt=0x{:02x}) from {from}",
            buf.get(1).copied().unwrap_or(0)
        );
        if n < 32 || (buf[1] & 0x7F) != 0x52 {
            continue;
        }
        let (rx_sec, rx_frac) = now_ntp();
        let mut reply = [0u8; 32];
        reply[0] = 0x80;
        reply[1] = 0xd3;
        reply[2] = 0x00;
        reply[3] = 0x07;
        reply[8..16].copy_from_slice(&buf[24..32]);
        reply[16..20].copy_from_slice(&rx_sec.to_be_bytes());
        reply[20..24].copy_from_slice(&rx_frac.to_be_bytes());
        let (tx_sec, tx_frac) = now_ntp();
        reply[24..28].copy_from_slice(&tx_sec.to_be_bytes());
        reply[28..32].copy_from_slice(&tx_frac.to_be_bytes());
        let _ = sock.send_to(&reply, from).await;
    }
}

/// Respond to receiver RTCP resend requests (`0x80 0xd5`) by resending buffered RTP packets.
pub async fn run_retransmit_responder(
    ctrl_sock: Arc<UdpSocket>,
    remote_ctrl_addr: SocketAddr,
    engine: Arc<AudioEngine>,
    cipher: Option<Arc<ChaCha20Poly1305>>,
    ssrc: u32,
) {
    let mut buf = [0u8; 64];
    loop {
        let Ok((n, _from)) = ctrl_sock.recv_from(&mut buf).await else {
            break;
        };
        if n < 8 || (buf[1] & 0x7F) != 0x55 {
            continue;
        }
        let first_seq = u16::from_be_bytes([buf[4], buf[5]]);
        let count = u16::from_be_bytes([buf[6], buf[7]]).min(32);

        for i in 0..count {
            let seq = first_seq.wrapping_add(i);
            if let Some(pkt) = engine.get_retransmit_packet(seq).await {
                let inner = if let Some(ref c) = cipher {
                    encrypt_airplay2_rtp(&pkt, ssrc, false, c)
                } else {
                    super::raop::build_raop_rtp(&pkt, ssrc, false)
                };
                let mut resend = Vec::with_capacity(4 + inner.len());
                resend.push(0x80);
                resend.push(0xd6);
                resend.extend_from_slice(&seq.to_be_bytes());
                resend.extend_from_slice(&inner);
                let _ = ctrl_sock.send_to(&resend, remote_ctrl_addr).await;
            }
        }
    }
}
