/// DACP (Digital Audio Control Protocol) remote client.
///
/// When an iPhone, iPad, or Mac streams AirPlay audio to NixPlay, it sends `DACP-ID` and
/// `Active-Remote` headers and advertises `iTunes_Ctrl_<DACP-ID>._dacp._tcp.local.` over mDNS.
/// Sending simple HTTP requests to that endpoint lets NixPlay trigger Play/Pause, Next, and
/// Previous directly on the sending Apple device.

use anyhow::{bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DACP_SERVICE: &str = "_dacp._tcp.local.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DacpRemote {
    pub dacp_id: String,
    pub active_remote: String,
    pub cached_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DacpCommand {
    PlayPause,
    Next,
    Previous,
    VolumeUp,
    VolumeDown,
}

impl DacpCommand {
    pub fn from_str_action(s: &str) -> Option<Self> {
        match s {
            "play-pause" | "play_pause" | "playpause" => Some(Self::PlayPause),
            "next" | "nextitem" => Some(Self::Next),
            "previous" | "prev" | "previtem" => Some(Self::Previous),
            "volume-up" | "volume_up" => Some(Self::VolumeUp),
            "volume-down" | "volume_down" => Some(Self::VolumeDown),
            _ => None,
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::PlayPause => "/ctrl-int/1/playpause",
            Self::Next => "/ctrl-int/1/nextitem",
            Self::Previous => "/ctrl-int/1/previtem",
            Self::VolumeUp => "/ctrl-int/1/volumeup",
            Self::VolumeDown => "/ctrl-int/1/volumedown",
        }
    }
}

/// Resolve the sender's DACP service via mDNS and send the remote command.
pub async fn send_command(remote: &mut DacpRemote, cmd: DacpCommand) -> Result<()> {
    if let Some(addr) = remote.cached_addr {
        if send_http(addr, remote, cmd).await.is_ok() {
            return Ok(());
        }
        remote.cached_addr = None;
    }

    let id = remote.dacp_id.clone();
    let addr = tokio::task::spawn_blocking(move || find_dacp_addr(&id, Duration::from_secs(3)))
        .await
        .context("DACP lookup task failed")??;

    remote.cached_addr = Some(addr);
    send_http(addr, remote, cmd).await
}

fn find_dacp_addr(dacp_id: &str, timeout: Duration) -> Result<SocketAddr> {
    let daemon = ServiceDaemon::new().context("start mDNS daemon for DACP")?;
    let rx = daemon.browse(DACP_SERVICE).context("browse _dacp._tcp")?;
    let target_prefix = format!("itunes_ctrl_{}", dacp_id.to_lowercase());
    let deadline = std::time::Instant::now() + timeout;

    let mut found = None;
    while std::time::Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(rem.min(Duration::from_millis(200))) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let full = info.get_fullname().to_lowercase();
                if full.starts_with(&target_prefix) {
                    let ip = info
                        .get_addresses()
                        .iter()
                        .find(|a| matches!(a, IpAddr::V4(v4) if !v4.is_loopback()))
                        .or_else(|| info.get_addresses().iter().next())
                        .copied();
                    if let Some(ip) = ip {
                        found = Some(SocketAddr::new(ip, info.get_port()));
                        break;
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let _ = daemon.shutdown();

    found.ok_or_else(|| {
        anyhow::anyhow!(
            "Could not reach remote controls on the sending device. Use the controls on your phone or Mac."
        )
    })
}

async fn send_http(addr: SocketAddr, remote: &DacpRemote, cmd: DacpCommand) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("DACP connect timed out")?
        .context("DACP connect failed")?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nActive-Remote: {}\r\nConnection: close\r\n\r\n",
        cmd.path(),
        addr,
        remote.active_remote
    );
    tokio::time::timeout(Duration::from_secs(3), stream.write_all(req.as_bytes()))
        .await
        .context("DACP write timed out")??;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    if n > 0 {
        let head = String::from_utf8_lossy(&buf[..n]);
        if !head.contains("200") && !head.contains("204") {
            bail!("DACP command rejected: {}", head.lines().next().unwrap_or(""));
        }
    }
    Ok(())
}
