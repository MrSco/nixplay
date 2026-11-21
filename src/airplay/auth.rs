use super::hap::{HapControlCipher, HapPairVerifier, HapTransientPairer};
use super::rtsp::RtspClient;
use crate::config::HapCredentials;
use crate::discovery::AirPlayDevice;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub fn make_sockaddr(ip: IpAddr, port: u16, scope_id: u32) -> SocketAddr {
    match ip {
        IpAddr::V4(v4) => SocketAddr::V4(std::net::SocketAddrV4::new(v4, port)),
        IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope_id)),
    }
}

pub fn is_cgnat_or_vpn(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xC0) == 64
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// Resolve a direct link-local IPv6 `(fe80::..., scope_id)` for a device's MAC address
/// from the local Linux neighbor table (`ip -6 neigh show`), bypassing VPN/Tailscale NAT.
pub async fn find_direct_link_local_by_mac(mac: &str) -> Option<(IpAddr, u32)> {
    let target_mac = mac.trim().to_lowercase();
    let out = tokio::process::Command::new("ip")
        .args(["-6", "neigh", "show"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].starts_with("fe80:") {
            continue;
        }
        let dev_idx = parts
            .iter()
            .position(|&p| p == "dev")
            .and_then(|i| parts.get(i + 1));
        let ll_idx = parts
            .iter()
            .position(|&p| p == "lladdr")
            .and_then(|i| parts.get(i + 1));
        if let (Some(&dev), Some(&ll)) = (dev_idx, ll_idx) {
            if ll.eq_ignore_ascii_case(&target_mac) {
                if let Ok(ip6) = parts[0].parse::<std::net::Ipv6Addr>() {
                    if let Ok(ifindex_str) =
                        std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
                    {
                        if let Ok(scope_id) = ifindex_str.trim().parse::<u32>() {
                            return Some((IpAddr::V6(ip6), scope_id));
                        }
                    }
                }
            }
        }
    }
    None
}

pub struct AuthenticatedAirPlayConn {
    pub rtsp: RtspClient,
    pub target_ip: IpAddr,
    pub target_scope: u32,
    pub shared_secret: Vec<u8>,
}

/// Connect to an AirPlay 2 receiver (with automatic VPN/Tailscale direct-LAN bypass)
/// and authenticate via saved `HapCredentials` (`pair-verify`) or transient pairing (`pair-setup`).
pub async fn connect_and_authenticate(
    device: &AirPlayDevice,
    creds: Option<&HapCredentials>,
) -> Result<AuthenticatedAirPlayConn> {
    let port = device.airplay_port.or(device.raop_port).unwrap_or(7000);
    let mut target_ip = device.ip;
    let mut target_scope = device.scope_id;
    let peer_addr = make_sockaddr(target_ip, port, target_scope);

    info!("Connecting AirPlay 2 session to '{}' ({})", device.name, peer_addr);
    let mut rtsp = RtspClient::connect(peer_addr).await?;

    // 1. GET /info + automatic VPN/Tailscale NAT detection & direct-LAN fallback
    let info_resp = rtsp.request("GET", "/info", &[], None).await?;
    if info_resp.status_code != 200 {
        debug!(
            "GET /info on '{}' returned {} (continuing)",
            device.name, info_resp.status_line
        );
    } else if let Ok(local) = rtsp.local_addr() {
        let local_ip = local.ip();
        if let Ok(info_pl) = info_resp.body_plist() {
            if let Some(dict) = info_pl.as_dictionary() {
                let sender_ip = dict
                    .get("senderAddress")
                    .and_then(|v| v.as_string())
                    .and_then(|s| s.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])))
                    .and_then(|h| h.parse::<IpAddr>().ok());
                let nat_detected =
                    is_cgnat_or_vpn(local_ip) || sender_ip.is_some_and(|s| s != local_ip);
                if nat_detected {
                    if let Some(mac) = dict.get("macAddress").and_then(|v| v.as_string()) {
                        if let Some((direct_ip, direct_scope)) =
                            find_direct_link_local_by_mac(mac).await
                        {
                            let direct_addr = make_sockaddr(direct_ip, port, direct_scope);
                            info!(
                                "Detected VPN/NAT route ({} -> {:?}); switching '{}' to direct LAN link {}",
                                local_ip, sender_ip, device.name, direct_addr
                            );
                            if let Ok(direct_rtsp) = RtspClient::connect(direct_addr).await {
                                rtsp = direct_rtsp;
                                target_ip = direct_ip;
                                target_scope = direct_scope;
                                let _ = rtsp.request("GET", "/info", &[], None).await;
                            }
                        } else {
                            warn!(
                                "Connection to '{}' is routed via VPN/NAT ({} -> {:?}); direct LAN link unavailable",
                                device.name, local_ip, sender_ip
                            );
                        }
                    }
                }
            }
        }
    }

    // 2. Authenticate: pair-verify (if previously PIN-paired) OR transient pair-setup
    let shared_secret: Vec<u8> = if let Some(c) = creds {
        let mut verifier = HapPairVerifier::from_credentials(c)?;
        let m1 = verifier.build_m1();
        let r1 = rtsp
            .request(
                "POST",
                "/pair-verify",
                &[("X-Apple-HKP", "3")],
                Some(("application/octet-stream", &m1)),
            )
            .await
            .context("POST /pair-verify M1 failed")?;
        if r1.status_code != 200 {
            bail!(
                "PAIRING_REQUIRED: Stored pairing rejected by '{}' ({}). Please pair again with the on-screen PIN.",
                device.name,
                r1.status_line
            );
        }
        let m3 = verifier.process_m2_and_build_m3(&r1.body)?;
        let r2 = rtsp
            .request(
                "POST",
                "/pair-verify",
                &[("X-Apple-HKP", "3")],
                Some(("application/octet-stream", &m3)),
            )
            .await
            .context("POST /pair-verify M3 failed")?;
        if r2.status_code != 200 {
            bail!(
                "PAIRING_REQUIRED: pair-verify M3 rejected by '{}' ({}). Please re-pair.",
                device.name,
                r2.status_line
            );
        }
        let secret = verifier.process_m4(&r2.body)?;
        info!("HAP pair-verify succeeded with '{}'", device.name);
        secret.to_vec()
    } else {
        let mut pairer = HapTransientPairer::new(None);
        let m1 = pairer.build_m1();
        let resp1 = rtsp
            .request(
                "POST",
                "/pair-setup",
                &[("X-Apple-HKP", "4")],
                Some(("application/octet-stream", &m1)),
            )
            .await
            .context("POST /pair-setup M1 failed")?;

        if resp1.status_code == 470 || resp1.status_code == 403 {
            bail!(
                "PAIRING_REQUIRED: '{}' requires 4-digit on-screen PIN pairing ({}). Click Pair to display the PIN on your TV.",
                device.name,
                resp1.status_line
            );
        }
        if resp1.status_code != 200 {
            bail!(
                "HAP transient pair-setup M1 rejected by '{}' ({}).",
                device.name,
                resp1.status_line
            );
        }

        let m3 = pairer
            .process_m2_and_build_m3(&resp1.body)
            .context("failed processing M2 from receiver")?;
        let resp2 = rtsp
            .request(
                "POST",
                "/pair-setup",
                &[("X-Apple-HKP", "4")],
                Some(("application/octet-stream", &m3)),
            )
            .await
            .context("POST /pair-setup M3 failed")?;

        if resp2.status_code != 200 {
            bail!(
                "HAP transient pair-setup M3 rejected by '{}' ({})",
                device.name,
                resp2.status_line
            );
        }
        let secret = pairer
            .process_m4(&resp2.body)
            .context("failed verifying M4 server proof")?;
        info!("HAP transient pairing succeeded with '{}'", device.name);
        secret.to_vec()
    };

    rtsp.enable_encryption(&shared_secret)?;

    Ok(AuthenticatedAirPlayConn {
        rtsp,
        target_ip,
        target_scope,
        shared_secret,
    })
}

/// Interactive 4-digit on-screen PIN pairing session for Apple TV & Mac receivers.
pub struct PinPairingSession {
    rtsp: RtspClient,
    device_name: String,
}

impl PinPairingSession {
    /// Connect to the receiver and trigger the 4-digit PIN popup on screen (`POST /pair-pin-start`).
    pub async fn start(device: &AirPlayDevice) -> Result<Self> {
        let port = device.airplay_port.or(device.raop_port).unwrap_or(7000);
        let mut target_ip = device.ip;
        let mut target_scope = device.scope_id;
        let mut rtsp = RtspClient::connect(make_sockaddr(target_ip, port, target_scope)).await?;

        // Check if we can bypass VPN/NAT for direct LAN pairing
        if let Ok(info_resp) = rtsp.request("GET", "/info", &[], None).await {
            if let Ok(local) = rtsp.local_addr() {
                if let Ok(pl) = info_resp.body_plist() {
                    if let Some(dict) = pl.as_dictionary() {
                        if is_cgnat_or_vpn(local.ip()) {
                            if let Some(mac) = dict.get("macAddress").and_then(|v| v.as_string()) {
                                if let Some((dip, dsc)) = find_direct_link_local_by_mac(mac).await {
                                    if let Ok(direct) =
                                        RtspClient::connect(make_sockaddr(dip, port, dsc)).await
                                    {
                                        rtsp = direct;
                                        target_ip = dip;
                                        target_scope = dsc;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = (target_ip, target_scope);

        let resp = rtsp
            .request("POST", "/pair-pin-start", &[("X-Apple-HKP", "3")], None)
            .await
            .context("POST /pair-pin-start failed")?;
        if resp.status_code != 200 {
            bail!(
                "'{}' rejected /pair-pin-start ({}). Make sure AirPlay is enabled and Allow Access is set to Anyone on the Same Network.",
                device.name,
                resp.status_line
            );
        }
        info!("PIN prompt displayed on '{}'", device.name);

        Ok(Self {
            rtsp,
            device_name: device.name.clone(),
        })
    }

    /// Complete HAP normal pairing (M1..M6) using the 4-digit PIN shown on screen.
    pub async fn finish(mut self, pin: &str) -> Result<HapCredentials> {
        let pin = pin.trim();
        let mut pairer = HapTransientPairer::new(Some(pin));

        // M1 -> M2
        let m1 = pairer.build_m1();
        let r1 = self
            .rtsp
            .request(
                "POST",
                "/pair-setup",
                &[("X-Apple-HKP", "3")],
                Some(("application/octet-stream", &m1)),
            )
            .await
            .context("pair-setup M1 failed")?;
        if r1.status_code != 200 {
            bail!("pair-setup M1 failed on '{}': {}", self.device_name, r1.status_line);
        }

        // M3 -> M4
        let m3 = pairer.process_m2_and_build_m3(&r1.body)?;
        let r2 = self
            .rtsp
            .request(
                "POST",
                "/pair-setup",
                &[("X-Apple-HKP", "3")],
                Some(("application/octet-stream", &m3)),
            )
            .await
            .context("pair-setup M3 failed")?;
        if r2.status_code != 200 {
            bail!(
                "pair-setup M3 rejected on '{}' ({}) — double-check the 4-digit PIN",
                self.device_name,
                r2.status_line
            );
        }
        let _ = pairer.process_m4(&r2.body)?;

        // M5 -> M6 (exchange persistent Ed25519 keys)
        let m5 = pairer.build_m5()?;
        let r3 = self
            .rtsp
            .request(
                "POST",
                "/pair-setup",
                &[("X-Apple-HKP", "3")],
                Some(("application/octet-stream", &m5)),
            )
            .await
            .context("pair-setup M5 failed")?;
        if r3.status_code != 200 {
            bail!("pair-setup M5 failed on '{}': {}", self.device_name, r3.status_line);
        }
        let creds = pairer.process_m6(&r3.body)?;
        info!(
            "Successfully paired with '{}' (saved persistent Ed25519 credentials)",
            self.device_name
        );
        Ok(creds)
    }
}

/// Spawn a reverse HAP-encrypted event channel listener to keep AirPlay 2 devices happy
/// and optionally forward decoded nested plist events (e.g. tvOS 26/27 `playbackState`).
pub async fn spawn_events_channel(
    ip: IpAddr,
    event_port: u16,
    scope_id: u32,
    shared_secret: Vec<u8>,
    dev_name: String,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<plist::Value>>,
) -> Option<tokio::task::JoinHandle<()>> {
    let ev_addr = make_sockaddr(ip, event_port, scope_id);
    for attempt in 0..3 {
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(ev_addr)).await {
            Ok(Ok(stream)) => {
                debug!("Connected reverse event channel to '{}' ({})", dev_name, ev_addr);
                return Some(tokio::spawn(async move {
                    run_events_loop(stream, &shared_secret, dev_name, event_tx).await;
                }));
            }
            _ => {
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
    debug!("Could not connect to eventPort {} on '{}'", event_port, dev_name);
    None
}

async fn run_events_loop(
    mut stream: TcpStream,
    shared_secret: &[u8],
    dev_name: String,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<plist::Value>>,
) {
    let Ok(mut cipher) = HapControlCipher::from_events_secret(shared_secret) else {
        return;
    };
    let mut tmp = [0u8; 4096];
    let mut plain_buf = Vec::new();
    loop {
        let Ok(n) = stream.read(&mut tmp).await else {
            break;
        };
        if n == 0 {
            break;
        }
        let Ok(dec) = cipher.feed_and_decrypt(&tmp[..n]) else {
            debug!("Events decrypt error from '{dev_name}'");
            break;
        };
        plain_buf.extend_from_slice(&dec);
        while let Some(pos) = plain_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let hdr = String::from_utf8_lossy(&plain_buf[..pos]).to_string();
            let cl: usize = hdr
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            let total = pos + 4 + cl;
            if plain_buf.len() < total {
                break;
            }
            let first_line = hdr.lines().next().unwrap_or("");
            let proto = first_line
                .split_whitespace()
                .nth(2)
                .unwrap_or("RTSP/1.0");
            let cseq = hdr.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("cseq")
                    .then(|| v.trim().to_string())
            });
            let body_bytes = plain_buf[pos + 4..total].to_vec();
            plain_buf.drain(..total);

            if let Ok(outer) = plist::from_bytes::<plist::Value>(&body_bytes) {
                // Unwrap nested bplist inside params.data (used by tvOS 26/27 playbackState events)
                let decoded = outer
                    .as_dictionary()
                    .and_then(|d| d.get("params"))
                    .and_then(|p| p.as_dictionary())
                    .and_then(|p| p.get("data"))
                    .and_then(|data| data.as_data())
                    .and_then(|bytes| plist::from_bytes::<plist::Value>(bytes).ok())
                    .unwrap_or(outer);

                debug!("Event from '{dev_name}': {:?}", decoded);
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(decoded);
                }
            } else {
                debug!("Event from '{dev_name}' ({first_line}, {cl} bytes)");
            }

            let mut reply = format!("{proto} 200 OK\r\nContent-Length: 0\r\nAudio-Latency: 0\r\n");
            if let Some(cs) = cseq {
                reply.push_str(&format!("CSeq: {cs}\r\n"));
            }
            reply.push_str("\r\n");
            if let Ok(enc) = cipher.encrypt(reply.as_bytes()) {
                let _ = stream.write_all(&enc).await;
            }
        }
    }
}
