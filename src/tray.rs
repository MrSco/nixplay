use crate::airplay::{SessionManager, SpeakerSnapshot, SpeakerState};
use crate::receiver::ReceiverManager;
use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
use ksni::{Icon, ToolTip, Tray, TrayMethods};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub struct NixPlayTray {
    manager: Arc<SessionManager>,
    receiver: Arc<ReceiverManager>,
    ui_url: String,
    speakers: Vec<SpeakerSnapshot>,
    active_count: usize,
    receiving_enabled: bool,
    receiving_client: Option<String>,
    shutdown_tx: broadcast::Sender<()>,
}

/// NixPlay penguin logo, pre-rendered at the sizes panels typically request.
const TRAY_ICON_PNGS: &[&[u8]] = &[
    include_bytes!("../assets/icons/nixplay-22.png"),
    include_bytes!("../assets/icons/nixplay-32.png"),
    include_bytes!("../assets/icons/nixplay-48.png"),
    include_bytes!("../assets/icons/nixplay-64.png"),
];

/// Decode an RGBA PNG into ksni's ARGB32 (network byte order) pixmap.
/// While streaming, a small sky-blue "live" dot is drawn in the bottom-right corner.
fn decode_tray_icon(png_bytes: &[u8], streaming: bool) -> Option<Icon> {
    let mut decoder = png::Decoder::new(png_bytes);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buf).ok()?;
    if frame.color_type != png::ColorType::Rgba {
        return None;
    }
    let (w, h) = (frame.width as i32, frame.height as i32);
    let mut data = Vec::with_capacity((w * h * 4) as usize);
    for px in buf[..frame.buffer_size()].chunks_exact(4) {
        data.extend_from_slice(&[px[3], px[0], px[1], px[2]]);
    }

    if streaming {
        let r = w as f32 * 0.2;
        let (cx, cy) = (w as f32 - r - 0.5, h as f32 - r - 0.5);
        for y in 0..h {
            for x in 0..w {
                let d = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt();
                let (ring, fill) = (r + 1.2, r);
                if d > ring {
                    continue;
                }
                let idx = ((y * w + x) * 4) as usize;
                let rgb = if d <= fill { [56u8, 189, 248] } else { [255u8, 255, 255] };
                data[idx..idx + 4].copy_from_slice(&[255, rgb[0], rgb[1], rgb[2]]);
            }
        }
    }

    Some(Icon {
        width: w,
        height: h,
        data,
    })
}

fn tray_icons(streaming: bool) -> Vec<Icon> {
    TRAY_ICON_PNGS
        .iter()
        .filter_map(|bytes| decode_tray_icon(bytes, streaming))
        .collect()
}

/// Open (or bring forward) the Control Center window. The window script is a
/// single-instance GTK application, so repeated calls never stack windows.
pub fn open_ui_window(url: &str) {
    open_ui_window_for(url, std::process::id());
}

/// Like [`open_ui_window`], but ties the window's lifetime to `daemon_pid`
/// (used when a second launch hands off to the already-running daemon).
pub fn open_ui_window_for(url: &str, daemon_pid: u32) {
    spawn_ui_window(url, daemon_pid);
}

fn spawn_ui_window(url: &str, daemon_pid: u32) {
    // Try our lightweight native GTK3 + WebKit2GTK popover first if present alongside repo/install,
    // otherwise fall back gracefully to xdg-open!
    let script_candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("nixplay-ui.py"))),
        dirs::data_local_dir().map(|d| d.join("nixplay/nixplay-ui.py")),
        Some(std::path::PathBuf::from("desktop/nixplay-ui.py")),
    ];

    let parent_pid = daemon_pid.to_string();
    for cand in script_candidates.into_iter().flatten() {
        if cand.exists() {
            if std::process::Command::new("python3")
                .arg(&cand)
                .arg(url)
                .arg(&parent_pid)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .is_ok()
            {
                return;
            }
        }
    }

    // Browser fallback when GTK/WebKit2GTK isn't available.
    let _ = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

impl Tray for NixPlayTray {
    fn id(&self) -> String {
        "nixplay".into()
    }

    fn title(&self) -> String {
        "NixPlay AirPlay".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        tray_icons(self.active_count > 0 || self.receiving_client.is_some())
    }

    fn tool_tip(&self) -> ToolTip {
        let description = if let Some(ref client) = self.receiving_client {
            format!("Receiving AirPlay from {client}")
        } else if self.active_count > 0 {
            let names: Vec<&str> = self
                .speakers
                .iter()
                .filter(|s| matches!(s.state, SpeakerState::Streaming | SpeakerState::Connecting))
                .map(|s| s.device.name.as_str())
                .collect();
            format!("Streaming to {}", names.join(", "))
        } else if self.receiving_enabled {
            format!(
                "Ready to receive · {} speakers available",
                self.speakers.len()
            )
        } else {
            format!("{} speakers available — Click to open", self.speakers.len())
        };
        ToolTip {
            title: "NixPlay AirPlay".into(),
            description,
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        open_ui_window(&self.ui_url);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();

        items.push(MenuItem::Standard(StandardItem {
            label: "Open NixPlay Control Center".into(),
            activate: Box::new(|this: &mut Self| {
                open_ui_window(&this.ui_url);
            }),
            ..Default::default()
        }));

        let rx_checked = self.receiving_enabled;
        let rx_label = match &self.receiving_client {
            Some(c) => format!("Receive AirPlay (Connected: {c})"),
            None if rx_checked => "Receive AirPlay (Listening)".into(),
            None => "Receive AirPlay on this PC".into(),
        };
        items.push(MenuItem::Checkmark(CheckmarkItem {
            label: rx_label,
            checked: rx_checked,
            activate: Box::new(move |this: &mut Self| {
                let rx = this.receiver.clone();
                tokio::spawn(async move {
                    if rx_checked {
                        rx.stop().await;
                    } else {
                        let _ = rx.start().await;
                    }
                });
            }),
            ..Default::default()
        }));

        items.push(MenuItem::Separator);

        if self.speakers.is_empty() {
            items.push(MenuItem::Standard(StandardItem {
                label: "Scanning for AirPlay speakers...".into(),
                enabled: false,
                ..Default::default()
            }));
        } else {
            for snap in &self.speakers {
                let id = snap.device.id.clone();
                let checked = matches!(
                    snap.state,
                    SpeakerState::Streaming | SpeakerState::Connecting
                );
                let label = format!("{}  ({}%)", snap.device.name, snap.volume);
                items.push(MenuItem::Checkmark(CheckmarkItem {
                    label,
                    checked,
                    activate: Box::new(move |this: &mut Self| {
                        let mgr = this.manager.clone();
                        let id = id.clone();
                        tokio::spawn(async move {
                            if checked {
                                let _ = mgr.disconnect(&id).await;
                            } else {
                                let _ = mgr.connect(&id).await;
                            }
                        });
                    }),
                    ..Default::default()
                }));
            }
        }

        if self.active_count > 0 {
            items.push(MenuItem::Separator);
            items.push(MenuItem::Standard(StandardItem {
                label: "Disconnect All Speakers".into(),
                activate: Box::new(|this: &mut Self| {
                    let mgr = this.manager.clone();
                    tokio::spawn(async move {
                        mgr.disconnect_all().await;
                    });
                }),
                ..Default::default()
            }));
        }

        items.push(MenuItem::Separator);
        items.push(MenuItem::Standard(StandardItem {
            label: "Rescan Network".into(),
            activate: Box::new(|this: &mut Self| {
                let mgr = this.manager.clone();
                tokio::spawn(async move {
                    mgr.discovery.refresh().await;
                });
            }),
            ..Default::default()
        }));

        items.push(MenuItem::Standard(StandardItem {
            label: "Quit NixPlay".into(),
            activate: Box::new(|this: &mut Self| {
                let _ = this.shutdown_tx.send(());
            }),
            ..Default::default()
        }));

        items
    }
}

pub async fn start_tray(
    manager: Arc<SessionManager>,
    receiver: Arc<ReceiverManager>,
    ui_url: String,
    shutdown_tx: broadcast::Sender<()>,
) {
    let initial_speakers = manager.speakers_snapshot().await;
    let active_count = initial_speakers
        .iter()
        .filter(|s| matches!(s.state, SpeakerState::Streaming | SpeakerState::Connecting))
        .count();
    let rx_snap = receiver.snapshot().await;

    let tray = NixPlayTray {
        manager: manager.clone(),
        receiver: receiver.clone(),
        ui_url,
        speakers: initial_speakers,
        active_count,
        receiving_enabled: rx_snap.enabled,
        receiving_client: rx_snap.client_name,
        shutdown_tx,
    };

    match tray.spawn().await {
        Ok(handle) => {
            info!("System tray icon active (StatusNotifierItem)");
            let mut change_rx = manager.subscribe_changes();
            let mut disc_rx = manager.discovery.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = change_rx.recv() => {}
                        _ = disc_rx.recv() => {}
                    }
                    let snaps = manager.speakers_snapshot().await;
                    let active = snaps
                        .iter()
                        .filter(|s| {
                            matches!(s.state, SpeakerState::Streaming | SpeakerState::Connecting)
                        })
                        .count();
                    let rx_snap = receiver.snapshot().await;
                    let _ = handle
                        .update(move |t| {
                            t.speakers = snaps;
                            t.active_count = active;
                            t.receiving_enabled = rx_snap.enabled;
                            t.receiving_client = rx_snap.client_name;
                        })
                        .await;
                }
            });
        }
        Err(e) => {
            debug!("System tray unavailable ({e}); continuing in headless/Web UI mode");
            warn!("System tray icon not registered (normal on headless Linux / Raspberry Pi)");
        }
    }
}
