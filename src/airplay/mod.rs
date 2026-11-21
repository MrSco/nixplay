pub mod airplay2;
pub mod auth;
pub mod fairplay;
pub mod hap;
pub mod raop;
pub mod rtsp;
pub mod mirror;
pub mod video;

use crate::audio::AudioEngine;
use crate::config::AppConfig;
use crate::discovery::{AirPlayDevice, AirPlayProtocol, DeviceKind, DiscoveryService};
use anyhow::Result;
use auth::PinPairingSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerState {
    Disconnected,
    Connecting,
    Streaming,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetadataInfo {
    pub title: String,
    pub artist: String,
    pub album: String,
    pub player: String,
    pub status: String,
    pub art_url: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SpeakerCommand {
    SetVolume(u8),
    SetLatencyOffset(i32),
    UpdateMetadata(MetadataInfo),
    Disconnect,
}

struct ActiveSpeaker {
    cmd_tx: mpsc::Sender<SpeakerCommand>,
    state_rx: watch::Receiver<SpeakerState>,
    volume: u8,
    latency_offset_ms: i32,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeakerSnapshot {
    pub device: AirPlayDevice,
    pub state: SpeakerState,
    pub volume: u8,
    pub latency_offset_ms: i32,
    pub favorite: bool,
    pub paired: bool,
    pub supports_video: bool,
    pub last_error: Option<String>,
}

/// Convert UI volume percentage (0..=100) to AirPlay dB scale (-144.0 mute, -30.0..=0.0).
pub fn volume_pct_to_airplay_db(pct: u8) -> f32 {
    if pct == 0 {
        -144.0
    } else {
        let norm = (pct.min(100) as f32) / 100.0;
        -30.0 * (1.0 - norm)
    }
}

/// Encode DMAP/DAAP metadata (`mlit` containing `minm`, `asar`, `asal`) for AirPlay displays & Home app.
pub fn build_dmap_metadata(title: &str, artist: &str, album: &str) -> Vec<u8> {
    fn tag(code: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + data.len());
        out.extend_from_slice(code);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    let mut inner = Vec::new();
    if !title.is_empty() {
        inner.extend_from_slice(&tag(b"minm", title.as_bytes()));
    }
    if !artist.is_empty() {
        inner.extend_from_slice(&tag(b"asar", artist.as_bytes()));
    }
    if !album.is_empty() {
        inner.extend_from_slice(&tag(b"asal", album.as_bytes()));
    }
    tag(b"mlit", &inner)
}

pub struct SessionManager {
    pub discovery: Arc<DiscoveryService>,
    pub audio: Arc<AudioEngine>,
    pub config: Arc<RwLock<AppConfig>>,
    sessions: Arc<RwLock<HashMap<String, ActiveSpeaker>>>,
    errors: Arc<RwLock<HashMap<String, String>>>,
    metadata: Arc<RwLock<MetadataInfo>>,
    pending_pairings: Arc<Mutex<HashMap<String, PinPairingSession>>>,
    state_changed_tx: broadcast::Sender<()>,
}

impl SessionManager {
    pub fn new(
        discovery: Arc<DiscoveryService>,
        audio: Arc<AudioEngine>,
        config: AppConfig,
    ) -> Arc<Self> {
        let (state_changed_tx, _) = broadcast::channel(64);
        Arc::new(Self {
            discovery,
            audio,
            config: Arc::new(RwLock::new(config)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            errors: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(MetadataInfo::default())),
            pending_pairings: Arc::new(Mutex::new(HashMap::new())),
            state_changed_tx,
        })
    }

    pub fn change_sender(&self) -> broadcast::Sender<()> {
        self.state_changed_tx.clone()
    }

    pub fn subscribe_changes(&self) -> broadcast::Receiver<()> {
        self.state_changed_tx.subscribe()
    }

    pub fn notify_change(&self) {
        let _ = self.state_changed_tx.send(());
    }

    pub async fn active_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn speakers_snapshot(&self) -> Vec<SpeakerSnapshot> {
        let devices = self.discovery.list().await;
        let sessions = self.sessions.read().await;
        let errors = self.errors.read().await;
        let cfg = self.config.read().await;

        let mut snaps: Vec<SpeakerSnapshot> = devices
            .into_iter()
            .map(|dev| {
                let prefs = cfg.device_prefs(&dev.id);
                let paired = prefs.hap_credentials.is_some();
                // Bit 0 (VideoV1) or Bit 49 (VideoV2) or AppleTV/Mac
                let supports_video = (dev.features & ((1u64 << 0) | (1u64 << 49))) != 0
                    || matches!(dev.kind, DeviceKind::AppleTv | DeviceKind::Mac);

                if let Some(active) = sessions.get(&dev.id) {
                    SpeakerSnapshot {
                        device: dev,
                        state: *active.state_rx.borrow(),
                        volume: active.volume,
                        latency_offset_ms: active.latency_offset_ms,
                        favorite: prefs.favorite,
                        paired,
                        supports_video,
                        last_error: active.last_error.clone(),
                    }
                } else {
                    let err = errors.get(&dev.id).cloned();
                    SpeakerSnapshot {
                        device: dev,
                        state: if err.is_some() {
                            SpeakerState::Error
                        } else {
                            SpeakerState::Disconnected
                        },
                        volume: prefs.volume,
                        latency_offset_ms: prefs.latency_offset_ms,
                        favorite: prefs.favorite,
                        paired,
                        supports_video,
                        last_error: err,
                    }
                }
            })
            .collect();

        snaps.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| {
                    let rank = |s: SpeakerState| match s {
                        SpeakerState::Streaming => 0,
                        SpeakerState::Connecting => 1,
                        _ => 2,
                    };
                    rank(a.state).cmp(&rank(b.state))
                })
                .then_with(|| a.device.name.to_lowercase().cmp(&b.device.name.to_lowercase()))
        });
        snaps
    }

    fn effective_volume(device_vol: u8, master_vol: u8) -> u8 {
        ((device_vol as u16 * master_vol as u16) / 100) as u8
    }

    /// Start 4-digit on-screen PIN pairing on an Apple TV / Mac AirPlay 2 receiver.
    pub async fn start_pin_pairing(&self, device_id: &str) -> Result<String> {
        let device = self
            .discovery
            .get(device_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("device '{}' not found", device_id))?;
        let session = PinPairingSession::start(&device).await?;
        let id = device.id.clone();
        self.pending_pairings.lock().await.insert(id.clone(), session);
        Ok(device.name)
    }

    /// Complete 4-digit PIN pairing and save persistent Ed25519 credentials to config.
    pub async fn finish_pin_pairing(&self, device_id: &str, pin: &str) -> Result<()> {
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };
        let session = self
            .pending_pairings
            .lock()
            .await
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("No active PIN pairing session for '{}'. Click Pair first.", device_id))?;

        let creds = session.finish(pin).await?;
        {
            let mut cfg = self.config.write().await;
            cfg.devices.entry(id.clone()).or_default().hap_credentials = Some(creds);
            let _ = cfg.save();
        }
        self.errors.write().await.remove(&id);
        self.notify_change();
        Ok(())
    }

    pub async fn unpair(&self, device_id: &str) -> Result<()> {
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };
        {
            let mut cfg = self.config.write().await;
            if let Some(p) = cfg.devices.get_mut(&id) {
                p.hap_credentials = None;
            }
            let _ = cfg.save();
        }
        self.notify_change();
        Ok(())
    }

    /// Connect to a discovered AirPlay speaker (supports multi-room).
    pub async fn connect(self: &Arc<Self>, device_id: &str) -> Result<()> {
        let device = self
            .discovery
            .get(device_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("speaker '{}' not found", device_id))?;
        let id = device.id.clone();

        if self.sessions.read().await.contains_key(&id) {
            return Ok(());
        }

        self.errors.write().await.remove(&id);

        let (dev_vol, latency_offset, master_vol, auto_route, hap_creds) = {
            let cfg = self.config.read().await;
            let p = cfg.device_prefs(&id);
            (
                p.volume,
                p.latency_offset_ms,
                cfg.master_volume,
                cfg.auto_route_audio,
                p.hap_credentials,
            )
        };
        let eff_vol = Self::effective_volume(dev_vol, master_vol);

        self.audio.ensure_started(true);
        if auto_route {
            if let Err(e) = self.audio.pulse.activate_as_default().await {
                warn!("Could not auto-route default audio sink: {e}");
            }
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (state_tx, state_rx) = watch::channel(SpeakerState::Connecting);

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(
                id.clone(),
                ActiveSpeaker {
                    cmd_tx: cmd_tx.clone(),
                    state_rx: state_rx.clone(),
                    volume: dev_vol,
                    latency_offset_ms: latency_offset,
                    last_error: None,
                },
            );
        }
        self.notify_change();

        {
            let mgr = self.clone();
            let mut rx = state_rx;
            tokio::spawn(async move {
                while rx.changed().await.is_ok() {
                    mgr.notify_change();
                }
            });
        }

        let mgr = self.clone();
        let dev_clone = device.clone();
        let audio = self.audio.clone();
        tokio::spawn(async move {
            let res = match dev_clone.protocol {
                AirPlayProtocol::AirPlay2 => {
                    airplay2::run_airplay2_session(
                        dev_clone.clone(),
                        hap_creds,
                        eff_vol,
                        latency_offset,
                        audio.clone(),
                        cmd_rx,
                        state_tx.clone(),
                    )
                    .await
                }
                AirPlayProtocol::Raop => {
                    raop::run_raop_session(
                        dev_clone.clone(),
                        eff_vol,
                        latency_offset,
                        audio.clone(),
                        cmd_rx,
                        state_tx.clone(),
                    )
                    .await
                }
            };

            if let Err(e) = res {
                error!("Session error for '{}': {e:#}", dev_clone.name);
                let _ = state_tx.send(SpeakerState::Error);
                mgr.errors
                    .write()
                    .await
                    .insert(dev_clone.id.clone(), format!("{e}"));
            }

            mgr.sessions.write().await.remove(&dev_clone.id);

            if mgr.sessions.read().await.is_empty() {
                info!("All AirPlay speakers disconnected; restoring system audio output");
                mgr.audio.stop().await;
                let auto_route = mgr.config.read().await.auto_route_audio;
                if auto_route {
                    let _ = mgr.audio.pulse.restore_default_sink().await;
                }
            }
            mgr.notify_change();
        });

        Ok(())
    }

    pub async fn disconnect(&self, device_id: &str) -> Result<()> {
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };
        if let Some(active) = self.sessions.read().await.get(&id) {
            let _ = active.cmd_tx.send(SpeakerCommand::Disconnect).await;
        }
        self.errors.write().await.remove(&id);
        self.notify_change();
        Ok(())
    }

    pub async fn disconnect_all(&self) {
        let txs: Vec<mpsc::Sender<SpeakerCommand>> = self
            .sessions
            .read()
            .await
            .values()
            .map(|s| s.cmd_tx.clone())
            .collect();
        for tx in txs {
            let _ = tx.send(SpeakerCommand::Disconnect).await;
        }
        self.notify_change();
    }

    pub async fn set_volume(&self, device_id: &str, volume: u8) -> Result<()> {
        let vol = volume.min(100);
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };

        let master_vol = {
            let mut cfg = self.config.write().await;
            cfg.devices.entry(id.clone()).or_default().volume = vol;
            let _ = cfg.save();
            cfg.master_volume
        };

        let eff = Self::effective_volume(vol, master_vol);
        if let Some(active) = self.sessions.write().await.get_mut(&id) {
            active.volume = vol;
            let _ = active.cmd_tx.send(SpeakerCommand::SetVolume(eff)).await;
        }
        self.notify_change();
        Ok(())
    }

    pub async fn set_master_volume(&self, master: u8) -> Result<()> {
        let m = master.min(100);
        {
            let mut cfg = self.config.write().await;
            cfg.master_volume = m;
            let _ = cfg.save();
        }
        let sessions = self.sessions.read().await;
        for active in sessions.values() {
            let eff = Self::effective_volume(active.volume, m);
            let _ = active.cmd_tx.send(SpeakerCommand::SetVolume(eff)).await;
        }
        self.notify_change();
        Ok(())
    }

    pub async fn set_latency_offset(&self, device_id: &str, offset_ms: i32) -> Result<()> {
        let clamped = offset_ms.clamp(-500, 500);
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };
        {
            let mut cfg = self.config.write().await;
            cfg.devices.entry(id.clone()).or_default().latency_offset_ms = clamped;
            let _ = cfg.save();
        }
        if let Some(active) = self.sessions.write().await.get_mut(&id) {
            active.latency_offset_ms = clamped;
            let _ = active
                .cmd_tx
                .send(SpeakerCommand::SetLatencyOffset(clamped))
                .await;
        }
        self.notify_change();
        Ok(())
    }

    pub async fn toggle_favorite(&self, device_id: &str) -> Result<bool> {
        let id = if let Some(dev) = self.discovery.get(device_id).await {
            dev.id
        } else {
            device_id.to_string()
        };
        let fav = {
            let mut cfg = self.config.write().await;
            let entry = cfg.devices.entry(id).or_default();
            entry.favorite = !entry.favorite;
            let val = entry.favorite;
            let _ = cfg.save();
            val
        };
        self.notify_change();
        Ok(fav)
    }

    pub async fn set_auto_route(&self, enabled: bool) -> Result<()> {
        {
            let mut cfg = self.config.write().await;
            cfg.auto_route_audio = enabled;
            let _ = cfg.save();
        }
        if enabled && self.active_count().await > 0 {
            let _ = self.audio.pulse.activate_as_default().await;
        } else if !enabled {
            let _ = self.audio.pulse.restore_default_sink().await;
        }
        self.notify_change();
        Ok(())
    }

    pub async fn update_metadata(&self, meta: MetadataInfo) {
        let changed = {
            let mut cur = self.metadata.write().await;
            if cur.title == meta.title
                && cur.artist == meta.artist
                && cur.album == meta.album
                && cur.status == meta.status
            {
                false
            } else {
                *cur = meta.clone();
                true
            }
        };

        if !changed {
            return;
        }

        let forward = self.config.read().await.forward_mpris;
        if forward && !meta.title.is_empty() {
            let sessions = self.sessions.read().await;
            for active in sessions.values() {
                let _ = active
                    .cmd_tx
                    .send(SpeakerCommand::UpdateMetadata(meta.clone()))
                    .await;
            }
        }
        self.notify_change();
    }

    pub async fn current_metadata(&self) -> MetadataInfo {
        self.metadata.read().await.clone()
    }
}
