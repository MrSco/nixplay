/// Read-only Linux Network & System Doctor for NixPlay.
///
/// Inspects common reasons AirPlay discovery, streaming, mirroring, or receiving fail
/// (Avahi, ufw/firewalld, Tailscale subnet routing, competing AirPlay receivers, PipeWire,
/// ffmpeg/hardware encoders, uxplay, Wayland/X11) and reports plain-English guidance.
/// Never modifies any system, network, or firewall configuration.

use crate::media_server::MediaServer;
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorFinding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub fix_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub warnings: usize,
    pub errors: usize,
    pub summary: String,
    pub findings: Vec<DoctorFinding>,
}

/// Run all read-only diagnostic checks on a blocking thread.
pub async fn run_doctor(media_port: u16) -> DoctorReport {
    tokio::task::spawn_blocking(move || collect_report(media_port))
        .await
        .unwrap_or_else(|_| DoctorReport {
            healthy: false,
            warnings: 0,
            errors: 1,
            summary: "Diagnostics failed to run".to_string(),
            findings: vec![],
        })
}

fn collect_report(media_port: u16) -> DoctorReport {
    let mut findings = Vec::new();

    // 1. Avahi / mDNS
    findings.push(check_avahi());

    // 2. Firewall (ufw / firewalld) — read-only
    if let Some(fw) = check_firewall(media_port) {
        findings.push(fw);
    }

    // 3. Tailscale / VPN subnet routing conflict
    if let Some(vpn) = check_tailscale_routes() {
        findings.push(vpn);
    }

    // 4. Other AirPlay receivers currently running
    let others = find_other_receivers();
    if !others.is_empty() {
        findings.push(DoctorFinding {
            id: "other_receivers".into(),
            severity: Severity::Warning,
            title: format!("Another AirPlay receiver is running ({})", others.join(", ")),
            detail: "Competing AirPlay receivers can claim port 7000/5000 or confuse Apple devices when NixPlay Receive mode is active.".into(),
            fix_hint: Some(format!("Stop {} if iPhones fail to connect to NixPlay.", others.join(", "))),
        });
    }

    // 5. PipeWire / PulseAudio
    findings.push(check_audio_backend());

    // 6. Video & Mirroring helpers (ffmpeg, hw encoders, yt-dlp, uxplay)
    findings.push(check_video_helpers());

    // 7. Display session (X11 vs Wayland)
    findings.push(check_display_session());

    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let healthy = errors == 0 && warnings == 0;
    let summary = if healthy {
        "Everything looks ready for two-way AirPlay.".into()
    } else if errors > 0 {
        format!("{errors} issue(s) and {warnings} warning(s) found.")
    } else {
        format!("{warnings} thing(s) to check for smoother AirPlay.")
    };

    DoctorReport {
        healthy,
        warnings,
        errors,
        summary,
        findings,
    }
}

fn check_avahi() -> DoctorFinding {
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", "avahi-daemon"])
        .status()
        .is_ok_and(|s| s.success());
    if active {
        DoctorFinding {
            id: "avahi".into(),
            severity: Severity::Ok,
            title: "mDNS / Avahi discovery active".into(),
            detail: "avahi-daemon is running for local AirPlay device discovery.".into(),
            fix_hint: None,
        }
    } else {
        DoctorFinding {
            id: "avahi".into(),
            severity: Severity::Info,
            title: "Avahi daemon not detected (using built-in mDNS)".into(),
            detail: "NixPlay uses its built-in Rust mDNS responder when avahi-daemon isn't active. If devices don't appear, enabling Avahi often helps on Linux desktops.".into(),
            fix_hint: Some("sudo systemctl enable --now avahi-daemon".into()),
        }
    }
}

fn check_firewall(media_port: u16) -> Option<DoctorFinding> {
    // Check firewalld first (non-root friendly)
    if let Ok(out) = Command::new("firewall-cmd").arg("--state").output() {
        if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "running" {
            let ports = Command::new("firewall-cmd")
                .arg("--list-ports")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            let has_7000 = ports.contains("7000/tcp");
            let has_media = ports.contains(&format!("{media_port}/tcp"));
            if has_7000 && has_media {
                return Some(DoctorFinding {
                    id: "firewall".into(),
                    severity: Severity::Ok,
                    title: "firewalld allows AirPlay ports".into(),
                    detail: format!("Ports 7000/tcp and {media_port}/tcp are open."),
                    fix_hint: None,
                });
            }
            return Some(DoctorFinding {
                id: "firewall".into(),
                severity: Severity::Warning,
                title: "firewalld is active — inbound AirPlay ports may be blocked".into(),
                detail: "Receiving from iPhone/Mac and casting local files to Apple TV require inbound LAN access.".into(),
                fix_hint: Some(format!(
                    "sudo firewall-cmd --add-service=mdns --add-port=7000/tcp --add-port=7001/tcp --add-port=7100/tcp --add-port={media_port}/tcp --add-port=6000-6010/udp --permanent && sudo firewall-cmd --reload"
                )),
            });
        }
    }

    // Check UFW (reading /etc/ufw/ufw.conf works without sudo!)
    if let Ok(conf) = std::fs::read_to_string("/etc/ufw/ufw.conf") {
        let enabled = conf
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes"));
        if enabled {
            return Some(DoctorFinding {
                id: "firewall".into(),
                severity: Severity::Warning,
                title: "UFW firewall is enabled".into(),
                detail: "If your iPhone can't connect to NixPlay Receive or Apple TV can't fetch local videos, make sure LAN AirPlay ports are allowed in UFW.".into(),
                fix_hint: Some(format!(
                    "sudo ufw allow 5353/udp && sudo ufw allow 7000,7001,7100,{media_port}/tcp"
                )),
            });
        } else {
            return Some(DoctorFinding {
                id: "firewall".into(),
                severity: Severity::Ok,
                title: "UFW firewall is inactive".into(),
                detail: "Local LAN AirPlay traffic is not blocked by UFW.".into(),
                fix_hint: None,
            });
        }
    }

    None
}

fn check_tailscale_routes() -> Option<DoctorFinding> {
    let out = Command::new("ip").args(["route", "show"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let routes = String::from_utf8_lossy(&out.stdout);
    // Detect if a private RFC1918 LAN subnet is routed through tailscale0
    let ts_lan = routes.lines().any(|line| {
        line.contains("dev tailscale0")
            && (line.starts_with("192.168.") || line.starts_with("10.") || line.starts_with("172."))
    });
    if ts_lan {
        return Some(DoctorFinding {
            id: "tailscale_routes".into(),
            severity: Severity::Warning,
            title: "Tailscale is routing a local LAN subnet".into(),
            detail: "Your Linux routing table sends local LAN traffic through tailscale0 (likely --accept-routes). Apple TVs often cannot fetch local video casts or mirror streams back across NAT.".into(),
            fix_hint: Some("At home, run: sudo tailscale set --accept-routes=false".into()),
        });
    }
    None
}

fn find_other_receivers() -> Vec<String> {
    let candidates = ["shairport-sync", "rpiplay", "airconnect"];
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            let comm = comm.trim();
            if candidates.contains(&comm) && !found.iter().any(|x| x == comm) {
                found.push(comm.to_string());
            }
        }
    }
    found
}

fn check_audio_backend() -> DoctorFinding {
    let ok = Command::new("pactl")
        .arg("info")
        .output()
        .is_ok_and(|o| o.status.success());
    if ok {
        DoctorFinding {
            id: "audio".into(),
            severity: Severity::Ok,
            title: "PipeWire / PulseAudio ready".into(),
            detail: "Virtual AirPlay sinks, per-app routing, and audio receiving playback are available.".into(),
            fix_hint: None,
        }
    } else {
        DoctorFinding {
            id: "audio".into(),
            severity: Severity::Error,
            title: "PipeWire / PulseAudio (pactl) unavailable".into(),
            detail: "NixPlay needs pactl/parec/pacat for desktop audio streaming and receiving playback.".into(),
            fix_hint: Some("Install pipewire-pulse or pulseaudio-utils and ensure your user audio session is running.".into()),
        }
    }
}

fn check_video_helpers() -> DoctorFinding {
    let has_ff = MediaServer::has_ffmpeg();
    let has_yt = MediaServer::has_ytdlp();
    let has_ux = crate::receiver::uxplay::has_uxplay();
    let caps = crate::airplay::mirror::probe_hw_encoders();

    let mut parts = Vec::new();
    parts.push(if has_ff {
        let mut hw = Vec::new();
        if caps.vaapi_h264 { hw.push("VAAPI"); }
        if caps.nvenc_h264 { hw.push("NVENC"); }
        if caps.hevc_available() { hw.push("HEVC"); }
        if hw.is_empty() {
            "ffmpeg (CPU)".to_string()
        } else {
            format!("ffmpeg ({})", hw.join("/"))
        }
    } else {
        "ffmpeg missing".to_string()
    });
    parts.push(if has_yt { "yt-dlp ready".into() } else { "yt-dlp missing".into() });
    parts.push(if has_ux {
        "uxplay ready (video receive)".into()
    } else {
        "uxplay not installed (audio receive still works built-in)".into()
    });

    let severity = if !has_ff { Severity::Warning } else { Severity::Ok };
    DoctorFinding {
        id: "helpers".into(),
        severity,
        title: "Media & Receiver Helpers".into(),
        detail: parts.join(" · "),
        fix_hint: if !has_ff {
            Some("sudo apt install ffmpeg".into())
        } else if !has_ux {
            Some("Optional for iPhone screen mirroring receive: sudo apt install uxplay (or build from github.com/FDH2/UxPlay)".into())
        } else {
            None
        },
    }
}

fn check_display_session() -> DoctorFinding {
    let wayland = std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|v| v.eq_ignore_ascii_case("wayland"));
    let x11 = std::env::var("DISPLAY").is_ok();
    let displays = crate::airplay::mirror::list_displays_sync();

    if wayland {
        let has_gst = Command::new("gst-launch-1.0")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        DoctorFinding {
            id: "display".into(),
            severity: if has_gst { Severity::Ok } else { Severity::Info },
            title: "Wayland display session detected".into(),
            detail: if has_gst {
                "Screen mirroring will use the XDG Desktop Portal + PipeWire/GStreamer backend.".into()
            } else {
                "Install gstreamer1.0-tools + gstreamer1.0-pipewire for native Wayland screen mirroring (XWayland fallback has limited desktop capture).".into()
            },
            fix_hint: if has_gst {
                None
            } else {
                Some("sudo apt install gstreamer1.0-tools gstreamer1.0-pipewire gstreamer1.0-plugins-ugly".into())
            },
        }
    } else if x11 {
        DoctorFinding {
            id: "display".into(),
            severity: Severity::Ok,
            title: format!("X11 display ready ({} monitor{})", displays.len().max(1), if displays.len() == 1 { "" } else { "s" }),
            detail: displays
                .iter()
                .map(|d| format!("{} ({}x{}{})", d.name, d.width, d.height, if d.primary { ", primary" } else { "" }))
                .collect::<Vec<_>>()
                .join(" · "),
            fix_hint: None,
        }
    } else {
        DoctorFinding {
            id: "display".into(),
            severity: Severity::Info,
            title: "Headless session (no DISPLAY)".into(),
            detail: "Audio streaming, file/URL casting, and AirPlay audio receiving work normally; live desktop screen mirroring requires an active desktop session.".into(),
            fix_hint: None,
        }
    }
}
