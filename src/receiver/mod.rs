pub mod alac_dec;
pub mod audio_rx;
pub mod dacp;
pub mod uxplay;

use crate::config::{AppConfig, ReceiverConfig, ReceiverMode};
use audio_rx::{load_or_create_server_identity, BuiltinAudioReceiver};
use dacp::{DacpCommand, DacpRemote};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tracing::{info, warn};
use uxplay::UxPlayProcess;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverState {
    Stopped,
    Listening,
    PinRequired,
    Connected,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedTrack {
    pub title: String,
    pub artist: String,
    pub album: String,
    pub art_data_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSinkInfo {
    pub name: String,
    pub description: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiverSnapshot {
    pub state: ReceiverState,
    pub enabled: bool,
    pub mode: ReceiverMode,
    pub name: String,
    pub pin_mode: bool,
    pub remember_devices: bool,
    pub h265: bool,
    pub output_sink: Option<String>,
    pub paired_count: usize,
    pub client_name: Option<String>,
    pub stream_kind: Option<String>,
    pub pin_code: Option<String>,
    pub volume: u8,
    pub track: ReceivedTrack,
    pub has_dacp: bool,
    pub uxplay_available: bool,
    pub listening_port: Option<u16>,
    pub error: Option<String>,
    pub output_sinks: Vec<OutputSinkInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverEvent {
    Listening,
    PinPrompt { code: String },
    ClientConnected { name: String, kind: String },
    ClientPaired { client_id: String, client_pk_hex: String },
    StreamKind(String),
    TrackUpdated(ReceivedTrack),
    Volume(u8),
    DacpReady(DacpRemote),
    AudioPacketReceived,
    ClientDisconnected,
    Stopped,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReceiverSettingsPatch {
    pub mode: Option<ReceiverMode>,
    pub name: Option<String>,
    pub pin_mode: Option<bool>,
    pub remember_devices: Option<bool>,
    pub h265: Option<bool>,
    /// Empty string clears to System Default
    pub output_sink: Option<String>,
}

enum ActiveBackend {
    Builtin(BuiltinAudioReceiver),
    UxPlay(UxPlayProcess),
}

struct ReceiverRuntime {
    state: ReceiverState,
    client_name: Option<String>,
    stream_kind: Option<String>,
    pin_code: Option<String>,
    volume: u8,
    track: ReceivedTrack,
    dacp: Option<DacpRemote>,
    listening_port: Option<u16>,
    error: Option<String>,
}

impl Default for ReceiverRuntime {
    fn default() -> Self {
        Self {
            state: ReceiverState::Stopped,
            client_name: None,
            stream_kind: None,
            pin_code: None,
            volume: 100,
            track: ReceivedTrack::default(),
            dacp: None,
            listening_port: None,
            error: None,
        }
    }
}

pub struct ReceiverManager {
    config: Arc<RwLock<AppConfig>>,
    backend: Mutex<Option<ActiveBackend>>,
    runtime: Arc<RwLock<ReceiverRuntime>>,
    paired_clients: Arc<RwLock<HashMap<String, String>>>,
    change_tx: broadcast::Sender<()>,
}

impl ReceiverManager {
    pub fn new(config: Arc<RwLock<AppConfig>>, change_tx: broadcast::Sender<()>) -> Arc<Self> {
        let initial_paired = config
            .try_read()
            .map(|c| c.receiver.paired_clients.clone())
            .unwrap_or_default();
        Arc::new(Self {
            config,
            backend: Mutex::new(None),
            runtime: Arc::new(RwLock::new(ReceiverRuntime::default())),
            paired_clients: Arc::new(RwLock::new(initial_paired)),
            change_tx,
        })
    }

    fn notify(&self) {
        let _ = self.change_tx.send(());
    }

    /// Start receiver if enabled in saved config.
    pub async fn start_if_enabled(self: &Arc<Self>) {
        let enabled = self.config.read().await.receiver.enabled;
        if enabled {
            if let Err(e) = self.start().await {
                warn!("Auto-start AirPlay receiver failed: {e:#}");
            }
        }
    }

    pub async fn is_running(&self) -> bool {
        self.backend.lock().await.is_some()
    }

    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        self.stop_inner(false).await;

        let (rcfg, sk, dev_id) = {
            let mut cfg = self.config.write().await;
            cfg.receiver.enabled = true;
            let (sk, dev_id) = load_or_create_server_identity(&mut cfg.receiver);
            let _ = cfg.save();
            (cfg.receiver.clone(), sk, dev_id)
        };

        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let backend_res = match rcfg.mode {
            ReceiverMode::BuiltinAudio => BuiltinAudioReceiver::start(
                rcfg.clone(),
                sk,
                dev_id,
                self.paired_clients.clone(),
                ev_tx,
                None,
                true,
            )
            .await
            .map(ActiveBackend::Builtin),
            ReceiverMode::Uxplay => UxPlayProcess::spawn(&rcfg, ev_tx).map(ActiveBackend::UxPlay),
        };

        match backend_res {
            Ok(backend) => {
                let port = match &backend {
                    ActiveBackend::Builtin(b) => Some(b.port()),
                    ActiveBackend::UxPlay(_) => None,
                };
                *self.backend.lock().await = Some(backend);
                {
                    let mut rt = self.runtime.write().await;
                    *rt = ReceiverRuntime {
                        state: ReceiverState::Listening,
                        listening_port: port,
                        ..Default::default()
                    };
                }
                self.notify();

                let mgr = self.clone();
                tokio::spawn(async move {
                    while let Some(ev) = ev_rx.recv().await {
                        mgr.handle_event(ev).await;
                    }
                });
                Ok(())
            }
            Err(e) => {
                {
                    let mut cfg = self.config.write().await;
                    cfg.receiver.enabled = false;
                    let _ = cfg.save();
                }
                {
                    let mut rt = self.runtime.write().await;
                    rt.state = ReceiverState::Error;
                    rt.error = Some(e.to_string());
                }
                self.notify();
                Err(e)
            }
        }
    }

    pub async fn stop(&self) {
        self.stop_inner(true).await;
    }

    async fn stop_inner(&self, persist_disabled: bool) {
        if persist_disabled {
            let mut cfg = self.config.write().await;
            cfg.receiver.enabled = false;
            let _ = cfg.save();
        }
        let existing = self.backend.lock().await.take();
        if let Some(backend) = existing {
            match backend {
                ActiveBackend::Builtin(b) => b.stop().await,
                ActiveBackend::UxPlay(mut u) => u.stop().await,
            }
        }
        {
            let mut rt = self.runtime.write().await;
            *rt = ReceiverRuntime::default();
        }
        self.notify();
    }

    /// Refresh/restart the receiver after sleep/resume or network IP change.
    pub async fn refresh_network(self: &Arc<Self>) {
        if self.is_running().await {
            info!("Refreshing AirPlay receiver after network/sleep event");
            let _ = self.start().await;
        }
    }

    pub async fn disconnect_client(self: &Arc<Self>) {
        let needs_restart = {
            let guard = self.backend.lock().await;
            match guard.as_ref() {
                Some(ActiveBackend::Builtin(b)) => {
                    b.disconnect_client().await;
                    false
                }
                Some(ActiveBackend::UxPlay(_)) => true,
                None => false,
            }
        };
        if needs_restart {
            let _ = self.start().await;
        }
    }

    pub async fn update_settings(
        self: &Arc<Self>,
        patch: ReceiverSettingsPatch,
    ) -> anyhow::Result<()> {
        let was_running = self.is_running().await;
        {
            let mut cfg = self.config.write().await;
            if let Some(m) = patch.mode {
                cfg.receiver.mode = m;
            }
            if let Some(name) = patch.name {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    cfg.receiver.name = trimmed.chars().take(63).collect();
                }
            }
            if let Some(pin) = patch.pin_mode {
                cfg.receiver.pin_mode = pin;
            }
            if let Some(rem) = patch.remember_devices {
                cfg.receiver.remember_devices = rem;
            }
            if let Some(h265) = patch.h265 {
                cfg.receiver.h265 = h265;
            }
            if let Some(sink) = patch.output_sink {
                let s = sink.trim().to_string();
                cfg.receiver.output_sink = if s.is_empty() { None } else { Some(s) };
            }
            let _ = cfg.save();
        }
        if was_running {
            self.start().await?;
        } else {
            self.notify();
        }
        Ok(())
    }

    pub async fn forget_paired(&self) {
        self.paired_clients.write().await.clear();
        {
            let mut cfg = self.config.write().await;
            cfg.receiver.paired_clients.clear();
            let _ = cfg.save();
        }
        if let Some(dir) = dirs::config_dir() {
            let _ = std::fs::remove_file(dir.join("nixplay/uxplay-paired.txt"));
        }
        self.notify();
    }

    pub async fn send_dacp(&self, cmd: DacpCommand) -> anyhow::Result<()> {
        let mut remote = {
            let rt = self.runtime.read().await;
            rt.dacp
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No remote-controllable device is connected."))?
        };
        let res = dacp::send_command(&mut remote, cmd).await;
        if res.is_ok() {
            self.runtime.write().await.dacp = Some(remote);
        }
        res
    }

    async fn handle_event(&self, ev: ReceiverEvent) {
        match ev {
            ReceiverEvent::Listening => {
                let mut rt = self.runtime.write().await;
                if rt.state != ReceiverState::Connected {
                    rt.state = ReceiverState::Listening;
                    rt.error = None;
                }
            }
            ReceiverEvent::PinPrompt { code } => {
                let mut rt = self.runtime.write().await;
                rt.state = ReceiverState::PinRequired;
                rt.pin_code = Some(code);
            }
            ReceiverEvent::ClientConnected { name, kind } => {
                let mut rt = self.runtime.write().await;
                rt.state = ReceiverState::Connected;
                rt.client_name = Some(name);
                rt.stream_kind = Some(kind);
                rt.pin_code = None;
                rt.error = None;
            }
            ReceiverEvent::ClientPaired {
                client_id,
                client_pk_hex,
            } => {
                let mut cfg = self.config.write().await;
                cfg.receiver.paired_clients.insert(client_id, client_pk_hex);
                let _ = cfg.save();
            }
            ReceiverEvent::StreamKind(kind) => {
                self.runtime.write().await.stream_kind = Some(kind);
            }
            ReceiverEvent::TrackUpdated(track) => {
                self.runtime.write().await.track = track;
            }
            ReceiverEvent::Volume(v) => {
                self.runtime.write().await.volume = v;
            }
            ReceiverEvent::DacpReady(remote) => {
                self.runtime.write().await.dacp = Some(remote);
            }
            ReceiverEvent::AudioPacketReceived => {
                let mut rt = self.runtime.write().await;
                if rt.state != ReceiverState::Connected {
                    rt.state = ReceiverState::Connected;
                }
            }
            ReceiverEvent::ClientDisconnected => {
                let running = self.is_running().await;
                let mut rt = self.runtime.write().await;
                rt.client_name = None;
                rt.stream_kind = None;
                rt.pin_code = None;
                rt.track = ReceivedTrack::default();
                rt.dacp = None;
                rt.state = if running {
                    ReceiverState::Listening
                } else {
                    ReceiverState::Stopped
                };
            }
            ReceiverEvent::Stopped => {
                let running = self.is_running().await;
                if !running {
                    let mut rt = self.runtime.write().await;
                    rt.state = ReceiverState::Stopped;
                }
            }
        }
        self.notify();
    }

    pub async fn snapshot(&self) -> ReceiverSnapshot {
        let cfg: ReceiverConfig = self.config.read().await.receiver.clone();
        let rt = self.runtime.read().await.clone_summary();
        let output_sinks = list_output_sinks().await;
        ReceiverSnapshot {
            state: rt.state,
            enabled: self.is_running().await,
            mode: cfg.mode,
            name: cfg.name,
            pin_mode: cfg.pin_mode,
            remember_devices: cfg.remember_devices,
            h265: cfg.h265,
            output_sink: cfg.output_sink,
            paired_count: cfg.paired_clients.len(),
            client_name: rt.client_name,
            stream_kind: rt.stream_kind,
            pin_code: rt.pin_code,
            volume: rt.volume,
            track: rt.track,
            has_dacp: rt.has_dacp,
            uxplay_available: uxplay::has_uxplay(),
            listening_port: rt.listening_port,
            error: rt.error,
            output_sinks,
        }
    }
}

struct RuntimeSummary {
    state: ReceiverState,
    client_name: Option<String>,
    stream_kind: Option<String>,
    pin_code: Option<String>,
    volume: u8,
    track: ReceivedTrack,
    has_dacp: bool,
    listening_port: Option<u16>,
    error: Option<String>,
}

impl ReceiverRuntime {
    fn clone_summary(&self) -> RuntimeSummary {
        RuntimeSummary {
            state: self.state,
            client_name: self.client_name.clone(),
            stream_kind: self.stream_kind.clone(),
            pin_code: self.pin_code.clone(),
            volume: self.volume,
            track: self.track.clone(),
            has_dacp: self.dacp.is_some(),
            listening_port: self.listening_port,
            error: self.error.clone(),
        }
    }
}

/// List physical/real PipeWire/PulseAudio output sinks (skipping NixPlay's own virtual sinks).
pub async fn list_output_sinks() -> Vec<OutputSinkInfo> {
    let default_sink = tokio::process::Command::new("pactl")
        .args(["get-default-sink"])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let Ok(out) = tokio::process::Command::new("pactl")
        .args(["list", "sinks"])
        .output()
        .await
    else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut sinks = Vec::new();
    let mut cur_name = String::new();
    let mut cur_desc = String::new();

    let flush = |sinks: &mut Vec<OutputSinkInfo>, name: &mut String, desc: &mut String| {
        if !name.is_empty()
            && *name != crate::audio::pulse::SINK_NAME
            && *name != crate::audio::pulse::SCREEN_SINK_NAME
        {
            sinks.push(OutputSinkInfo {
                is_default: *name == default_sink,
                description: if desc.is_empty() {
                    name.clone()
                } else {
                    desc.clone()
                },
                name: name.clone(),
            });
        }
        name.clear();
        desc.clear();
    };

    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("Sink #") {
            flush(&mut sinks, &mut cur_name, &mut cur_desc);
        } else if let Some(v) = t.strip_prefix("Name:") {
            cur_name = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("Description:") {
            cur_desc = v.trim().to_string();
        }
    }
    flush(&mut sinks, &mut cur_name, &mut cur_desc);
    sinks
}
