/// Optional supervised `uxplay` backend for receiving full AirPlay Screen Mirroring + Audio
/// from iPhones, iPads, and Macs on Linux.
///
/// Only required when the user wants to receive *video screen mirroring*; audio receiving
/// works out of the box via NixPlay's built-in pure-Rust AirPlay 2 + RAOP receiver.

use crate::config::ReceiverConfig;
use crate::receiver::ReceiverEvent;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub fn uxplay_bin() -> Option<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        let local = home.join(".local/bin/uxplay");
        if local.is_file() {
            return Some(local);
        }
    }
    let found = std::process::Command::new("uxplay")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if found {
        Some(PathBuf::from("uxplay"))
    } else {
        None
    }
}

pub fn has_uxplay() -> bool {
    uxplay_bin().is_some()
}

pub fn build_uxplay_args(cfg: &ReceiverConfig) -> Vec<String> {
    let mut args = vec!["-n".to_string(), cfg.name.clone(), "-nh".to_string()];
    if cfg.pin_mode {
        args.push("-pin".to_string());
        if cfg.remember_devices {
            if let Some(dir) = dirs::config_dir() {
                let p = dir.join("nixplay/uxplay-paired.txt");
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                args.push("-reg".to_string());
                args.push(p.to_string_lossy().to_string());
            }
        }
    }
    if cfg.h265 {
        args.push("-h265".to_string());
    }
    if let Some(ref sink) = cfg.output_sink {
        if !sink.trim().is_empty() && sink.chars().all(|c| !c.is_whitespace() && c != ';') {
            args.push("-as".to_string());
            args.push(format!("pulsesink device={sink}"));
        }
    }
    args
}

pub struct UxPlayProcess {
    child: Child,
}

impl UxPlayProcess {
    pub fn spawn(cfg: &ReceiverConfig, event_tx: mpsc::UnboundedSender<ReceiverEvent>) -> Result<Self> {
        let bin = uxplay_bin().ok_or_else(|| {
            anyhow::anyhow!(
                "uxplay is not installed. Install it (e.g. sudo apt install uxplay) or switch Receive mode to Built-in Audio."
            )
        })?;
        let args = build_uxplay_args(cfg);
        info!("Starting uxplay receiver: {} {:?}", bin.display(), args);

        let mut cmd = Command::new(&bin);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().context("failed to spawn uxplay")?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        if let Some(out) = stdout {
            let tx = event_tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    debug!("uxplay: {line}");
                    if let Some(ev) = parse_uxplay_line(&line) {
                        let _ = tx.send(ev);
                    }
                }
                let _ = tx.send(ReceiverEvent::Stopped);
            });
        }
        if let Some(err) = stderr {
            let tx = event_tx;
            tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    debug!("uxplay stderr: {line}");
                    if let Some(ev) = parse_uxplay_line(&line) {
                        let _ = tx.send(ev);
                    } else if line.to_lowercase().contains("error") || line.contains("failed") {
                        warn!("uxplay: {line}");
                    }
                }
            });
        }

        Ok(Self { child })
    }

    pub async fn stop(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

/// Parse stdout/stderr lines emitted by upstream UxPlay into structured receiver events.
pub fn parse_uxplay_line(line: &str) -> Option<ReceiverEvent> {
    let l = line.trim();
    if l.is_empty() {
        return None;
    }
    // Advertising / ready
    if l.contains("Initialized server socket") || l.contains("registered service") {
        return Some(ReceiverEvent::Listening);
    }
    // PIN prompt: "*** Use PIN 1234 ***" or "PIN: 1234"
    if let Some(pos) = l.find("PIN") {
        let after = &l[pos + 3..];
        let digits: String = after
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.len() == 4 {
            return Some(ReceiverEvent::PinPrompt { code: digits });
        }
    }
    // Client connected: "Connection request from iPhone (iPhone15,2) ..."
    if let Some(rest) = l.strip_prefix("Connection request from ") {
        let name = rest
            .split(" (")
            .next()
            .unwrap_or(rest)
            .trim()
            .to_string();
        if !name.is_empty() {
            return Some(ReceiverEvent::ClientConnected {
                name,
                kind: "Mirroring / AirPlay".into(),
            });
        }
    }
    if l.contains("raop_rtp_mirror starting") {
        return Some(ReceiverEvent::StreamKind("Screen Mirroring".into()));
    }
    if l.contains("Open connections: 0") || l.contains("Connection closed") || l.contains("client disconnected") {
        return Some(ReceiverEvent::ClientDisconnected);
    }
    if l.contains("Audio format") {
        return Some(ReceiverEvent::StreamKind("AirPlay Audio".into()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uxplay_pin_and_connection_lines() {
        assert_eq!(
            parse_uxplay_line("*** Use PIN 4821 for pairing ***"),
            Some(ReceiverEvent::PinPrompt { code: "4821".into() })
        );
        assert_eq!(
            parse_uxplay_line("Connection request from Rocco's iPhone (iPhone16,2)"),
            Some(ReceiverEvent::ClientConnected {
                name: "Rocco's iPhone".into(),
                kind: "Mirroring / AirPlay".into(),
            })
        );
        assert_eq!(
            parse_uxplay_line("Open connections: 0"),
            Some(ReceiverEvent::ClientDisconnected)
        );
    }
}
