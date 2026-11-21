use super::airplay2::{build_ntp_sync_packet, run_ntp_timing_responder, run_retransmit_responder};
use super::rtsp::RtspClient;
use super::{build_dmap_metadata, volume_pct_to_airplay_db, SpeakerCommand, SpeakerState};
use crate::audio::alac::{SAMPLES_PER_FRAME, SAMPLE_RATE};
use crate::audio::{AudioEngine, AudioPacket};
use crate::discovery::AirPlayDevice;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

const RAOP_LATENCY_SAMPLES: i64 = 88200; // Standard 2.0s RAOP / Shairport Sync buffer

pub async fn run_raop_session(
    device: AirPlayDevice,
    initial_volume: u8,
    initial_latency_offset_ms: i32,
    audio_engine: Arc<AudioEngine>,
    mut cmd_rx: mpsc::Receiver<SpeakerCommand>,
    state_tx: watch::Sender<SpeakerState>,
) -> Result<()> {
    let _ = state_tx.send(SpeakerState::Connecting);
    let port = device.raop_port.or(device.airplay_port).unwrap_or(5000);
    let peer_addr = SocketAddr::new(device.ip, port);

    info!("Connecting AirPlay 1 (RAOP) session to '{}' ({})", device.name, peer_addr);
    let mut rtsp = RtspClient::connect(peer_addr).await?;
    let local_ip = rtsp.local_addr()?.ip();

    let session_id: u32 = rand::random();
    let session_uri = match local_ip {
        IpAddr::V4(v4) => format!("rtsp://{v4}/{session_id}"),
        IpAddr::V6(v6) => format!("rtsp://[{v6}]/{session_id}"),
    };

    // 1. OPTIONS *
    let _ = rtsp.request("OPTIONS", "*", &[], None).await;

    // 2. ANNOUNCE (unencrypted Apple Lossless 44100/16/2, spf=352)
    let addr_type = if device.ip.is_ipv4() { "IP4" } else { "IP6" };
    let sdp = format!(
        "v=0\r\n\
         o=iTunes {session_id} 0 IN {addr_type} {local_ip}\r\n\
         s=NixPlay\r\n\
         c=IN {addr_type} {}\r\n\
         t=0 0\r\n\
         m=audio 0 RTP/AVP 96\r\n\
         a=rtpmap:96 AppleLossless\r\n\
         a=fmtp:96 {SAMPLES_PER_FRAME} 0 16 40 10 14 2 255 0 0 {SAMPLE_RATE}\r\n",
        device.ip
    );
    let ann_resp = rtsp
        .request(
            "ANNOUNCE",
            &session_uri,
            &[],
            Some(("application/sdp", sdp.as_bytes())),
        )
        .await
        .context("RAOP ANNOUNCE failed")?;
    if ann_resp.status_code != 200 {
        bail!(
            "RAOP ANNOUNCE rejected by '{}': {}",
            device.name,
            ann_resp.status_line
        );
    }

    // 3. Bind local UDP sockets
    let bind_ip = match local_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    let data_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    let ctrl_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    let timing_sock = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);

    let local_ctrl_port = ctrl_sock.local_addr()?.port();
    let local_timing_port = timing_sock.local_addr()?.port();

    let timing_handle = {
        let timing_sock = timing_sock.clone();
        tokio::spawn(async move {
            run_ntp_timing_responder(timing_sock).await;
        })
    };

    // 4. SETUP
    let transport_hdr = format!(
        "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={local_ctrl_port};timing_port={local_timing_port}"
    );
    let setup_resp = rtsp
        .request(
            "SETUP",
            &session_uri,
            &[("Transport", &transport_hdr)],
            None,
        )
        .await
        .context("RAOP SETUP failed")?;
    if setup_resp.status_code != 200 {
        timing_handle.abort();
        bail!(
            "RAOP SETUP rejected by '{}': {}",
            device.name,
            setup_resp.status_line
        );
    }

    let rtsp_session = setup_resp
        .header("session")
        .unwrap_or("1")
        .split(';')
        .next()
        .unwrap_or("1")
        .trim()
        .to_string();
    let resp_transport = setup_resp
        .header("transport")
        .context("RAOP SETUP response missing Transport header")?;

    let remote_data_port = parse_transport_port(resp_transport, "server_port")
        .context("RAOP SETUP missing server_port")?;
    let remote_ctrl_port =
        parse_transport_port(resp_transport, "control_port").unwrap_or(remote_data_port);

    let remote_data_addr = SocketAddr::new(device.ip, remote_data_port);
    let remote_ctrl_addr = SocketAddr::new(device.ip, remote_ctrl_port);
    info!(
        "RAOP stream active for '{}': data={}, control={}",
        device.name, remote_data_addr, remote_ctrl_addr
    );

    // 5. RECORD
    let rtp_info = format!(
        "seq={};rtptime={}",
        audio_engine.current_seq(),
        audio_engine.current_rtp_time()
    );
    let rec_resp = rtsp
        .request(
            "RECORD",
            &session_uri,
            &[
                ("Session", &rtsp_session),
                ("Range", "npt=0-"),
                ("RTP-Info", &rtp_info),
            ],
            None,
        )
        .await
        .context("RAOP RECORD failed")?;
    if rec_resp.status_code != 200 {
        timing_handle.abort();
        bail!(
            "RAOP RECORD rejected by '{}': {}",
            device.name,
            rec_resp.status_line
        );
    }

    // 6. Initial Volume
    let _ = send_raop_volume(&mut rtsp, &session_uri, &rtsp_session, initial_volume).await;

    let _ = state_tx.send(SpeakerState::Streaming);

    let ssrc: u32 = rand::random();
    let retransmit_handle = {
        let ctrl_sock = ctrl_sock.clone();
        let engine = audio_engine.clone();
        tokio::spawn(async move {
            run_retransmit_responder(ctrl_sock, remote_ctrl_addr, engine, None, ssrc).await;
        })
    };

    let mut pkt_rx = audio_engine.subscribe();
    let mut latency_offset_ms = initial_latency_offset_ms;
    let mut first_packet = true;
    let mut running = true;

    while running {
        tokio::select! {
            pkt_res = pkt_rx.recv() => {
                match pkt_res {
                    Ok(pkt) => {
                        let offset_samples = (latency_offset_ms as i64 * SAMPLE_RATE as i64) / 1000;
                        let effective_latency = (RAOP_LATENCY_SAMPLES + offset_samples).clamp(11025, 176400) as u32;

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

                        let wire = build_raop_rtp(&pkt, ssrc, first_packet);
                        if let Err(e) = data_sock.send_to(&wire, remote_data_addr).await {
                            warn!("RAOP UDP send error to '{}': {e}", device.name);
                        }
                        first_packet = false;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!("RAOP speaker '{}' lagged {n} frames", device.name);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        running = false;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SpeakerCommand::SetVolume(vol)) => {
                        let _ = send_raop_volume(&mut rtsp, &session_uri, &rtsp_session, vol).await;
                    }
                    Some(SpeakerCommand::SetLatencyOffset(ms)) => {
                        latency_offset_ms = ms;
                        first_packet = true;
                    }
                    Some(SpeakerCommand::UpdateMetadata(meta)) => {
                        let dmap = build_dmap_metadata(&meta.title, &meta.artist, &meta.album);
                        let rtp_info = format!("rtptime={}", audio_engine.current_rtp_time());
                        let _ = rtsp
                            .request(
                                "SET_PARAMETER",
                                &session_uri,
                                &[("Session", &rtsp_session), ("RTP-Info", &rtp_info)],
                                Some(("application/x-dmap-tagged", &dmap)),
                            )
                            .await;
                    }
                    Some(SpeakerCommand::Disconnect) | None => {
                        running = false;
                    }
                }
            }
        }
    }

    timing_handle.abort();
    retransmit_handle.abort();

    let flush_hdr = format!(
        "seq={};rtptime={}",
        audio_engine.current_seq(),
        audio_engine.current_rtp_time()
    );
    let _ = rtsp
        .request(
            "FLUSH",
            &session_uri,
            &[("Session", &rtsp_session), ("RTP-Info", &flush_hdr)],
            None,
        )
        .await;
    let _ = rtsp
        .request("TEARDOWN", &session_uri, &[("Session", &rtsp_session)], None)
        .await;

    let _ = state_tx.send(SpeakerState::Disconnected);
    info!("RAOP session closed cleanly for '{}'", device.name);
    Ok(())
}

pub fn build_raop_rtp(pkt: &AudioPacket, ssrc: u32, marker: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + pkt.alac_payload.len());
    out.push(0x80);
    out.push(if marker { 0x60 | 0x80 } else { 0x60 });
    out.extend_from_slice(&pkt.seq.to_be_bytes());
    out.extend_from_slice(&pkt.rtp_time.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(&pkt.alac_payload);
    out
}

async fn send_raop_volume(
    rtsp: &mut RtspClient,
    uri: &str,
    session: &str,
    vol: u8,
) -> Result<()> {
    let db = volume_pct_to_airplay_db(vol);
    let body = format!("volume: {db:.6}\r\n");
    rtsp.request(
        "SET_PARAMETER",
        uri,
        &[("Session", session)],
        Some(("text/parameters", body.as_bytes())),
    )
    .await?;
    Ok(())
}

fn parse_transport_port(header: &str, key: &str) -> Option<u16> {
    for part in header.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                return v.trim().parse().ok();
            }
        }
    }
    None
}
