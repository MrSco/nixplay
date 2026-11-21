use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{debug, info};

pub const SINK_NAME: &str = "nixplay_airplay";
pub const SINK_DESCRIPTION: &str = "NixPlay AirPlay";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioAppStream {
    pub id: u32,
    pub app_name: String,
    pub media_name: String,
    pub sink_index: u32,
    pub routed_to_nixplay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioBackendStatus {
    pub server_name: String,
    pub sink_active: bool,
    pub is_default_sink: bool,
    pub previous_default_sink: Option<String>,
    pub apps: Vec<AudioAppStream>,
}

pub struct PulseAudioManager {
    module_id: Mutex<Option<u32>>,
    previous_default_sink: Mutex<Option<String>>,
    capture_child: Mutex<Option<Child>>,
}

impl PulseAudioManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            module_id: Mutex::new(None),
            previous_default_sink: Mutex::new(None),
            capture_child: Mutex::new(None),
        })
    }

    async fn run_pactl(args: &[&str]) -> Result<String> {
        let out = Command::new("pactl")
            .args(args)
            .output()
            .await
            .with_context(|| format!("failed to run pactl {:?}", args))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("pactl {:?} failed: {}", args, err.trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub async fn server_name(&self) -> String {
        match Self::run_pactl(&["info"]).await {
            Ok(out) => out
                .lines()
                .find_map(|l| l.strip_prefix("Server Name:"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "PulseAudio/PipeWire".to_string()),
            Err(_) => "Unavailable (Headless)".to_string(),
        }
    }

    pub async fn get_default_sink(&self) -> Option<String> {
        Self::run_pactl(&["get-default-sink"])
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub async fn sink_exists(&self) -> bool {
        match Self::run_pactl(&["list", "short", "sinks"]).await {
            Ok(out) => out.lines().any(|l| l.split('\t').nth(1) == Some(SINK_NAME)),
            Err(_) => false,
        }
    }

    pub async fn sink_index(&self) -> Option<u32> {
        let out = Self::run_pactl(&["list", "short", "sinks"]).await.ok()?;
        for line in out.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.get(1) == Some(&SINK_NAME) {
                return cols[0].parse().ok();
            }
        }
        None
    }

    /// Ensure the virtual `nixplay_airplay` sink exists in PipeWire / PulseAudio.
    pub async fn ensure_virtual_sink(&self) -> Result<()> {
        if self.sink_exists().await {
            debug!("Virtual sink {} already exists", SINK_NAME);
            return Ok(());
        }

        let sink_props = format!(
            "sink_properties=device.description=\"{}\" device.icon_name=audio-speakers",
            SINK_DESCRIPTION
        );
        let out = Self::run_pactl(&[
            "load-module",
            "module-null-sink",
            &format!("sink_name={}", SINK_NAME),
            "rate=44100",
            "channels=2",
            "format=s16le",
            &sink_props,
        ])
        .await?;

        if let Ok(id) = out.trim().parse::<u32>() {
            *self.module_id.lock().await = Some(id);
            info!("Created virtual audio sink '{}' (module {})", SINK_NAME, id);
        }
        Ok(())
    }

    /// Switch the system default sink to `nixplay_airplay` (remembering the prior sink so we can restore it).
    pub async fn activate_as_default(&self) -> Result<()> {
        self.ensure_virtual_sink().await?;
        if let Some(cur) = self.get_default_sink().await {
            if cur != SINK_NAME {
                *self.previous_default_sink.lock().await = Some(cur.clone());
                info!("Saved previous default sink: {}", cur);
            }
        }
        Self::run_pactl(&["set-default-sink", SINK_NAME]).await?;
        // Also move currently playing sink-inputs over to NixPlay so music seamlessly transfers!
        if let Ok(inputs) = Self::run_pactl(&["list", "short", "sink-inputs"]).await {
            for line in inputs.lines() {
                if let Some(id) = line.split('\t').next() {
                    let _ = Self::run_pactl(&["move-sink-input", id.trim(), SINK_NAME]).await;
                }
            }
        }
        info!("Routed default audio output to {}", SINK_NAME);
        Ok(())
    }

    /// Restore the user's previous default sink and move playing streams back.
    pub async fn restore_default_sink(&self) -> Result<()> {
        let prev = self.previous_default_sink.lock().await.clone();
        if let Some(prev_sink) = prev {
            if prev_sink != SINK_NAME {
                let _ = Self::run_pactl(&["set-default-sink", &prev_sink]).await;
                if let Ok(inputs) = Self::run_pactl(&["list", "short", "sink-inputs"]).await {
                    for line in inputs.lines() {
                        if let Some(id) = line.split('\t').next() {
                            let _ =
                                Self::run_pactl(&["move-sink-input", id.trim(), &prev_sink]).await;
                        }
                    }
                }
                info!("Restored default audio output to {}", prev_sink);
            }
        }
        Ok(())
    }

    /// Route a specific application stream (by sink-input ID) to NixPlay or back to the default sink.
    pub async fn route_app(&self, sink_input_id: u32, to_nixplay: bool) -> Result<()> {
        let target = if to_nixplay {
            self.ensure_virtual_sink().await?;
            SINK_NAME.to_string()
        } else {
            self.previous_default_sink
                .lock()
                .await
                .clone()
                .unwrap_or_else(|| "@DEFAULT_SINK@".to_string())
        };
        Self::run_pactl(&["move-sink-input", &sink_input_id.to_string(), &target]).await?;
        Ok(())
    }

    /// Unload the virtual sink module cleanly on shutdown.
    pub async fn cleanup(&self) {
        let _ = self.restore_default_sink().await;
        if let Some(mut child) = self.capture_child.lock().await.take() {
            let _ = child.kill().await;
        }
        if let Some(id) = self.module_id.lock().await.take() {
            let _ = Self::run_pactl(&["unload-module", &id.to_string()]).await;
            info!("Unloaded virtual audio sink module {}", id);
        }
    }

    /// List active audio-producing applications (Firefox, Spotify, VLC, Steam, etc.).
    pub async fn list_apps(&self) -> Vec<AudioAppStream> {
        let nix_idx = self.sink_index().await;
        let Ok(out) = Self::run_pactl(&["list", "sink-inputs"]).await else {
            return vec![];
        };

        let mut apps = Vec::new();
        let mut cur_id: Option<u32> = None;
        let mut cur_sink: u32 = 0;
        let mut app_name = String::new();
        let mut media_name = String::new();

        let flush = |apps: &mut Vec<AudioAppStream>,
                     id: Option<u32>,
                     sink: u32,
                     app: &mut String,
                     media: &mut String| {
            if let Some(id) = id {
                if !app.is_empty() || !media.is_empty() {
                    apps.push(AudioAppStream {
                        id,
                        app_name: if app.is_empty() {
                            "Application".to_string()
                        } else {
                            app.clone()
                        },
                        media_name: media.clone(),
                        sink_index: sink,
                        routed_to_nixplay: nix_idx.is_some_and(|n| n == sink),
                    });
                }
            }
            app.clear();
            media.clear();
        };

        for line in out.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Sink Input #") {
                flush(&mut apps, cur_id, cur_sink, &mut app_name, &mut media_name);
                cur_id = rest.trim().parse().ok();
                cur_sink = 0;
            } else if let Some(rest) = trimmed.strip_prefix("Sink:") {
                cur_sink = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = trimmed.strip_prefix("application.name = ") {
                app_name = rest.trim().trim_matches('"').to_string();
            } else if let Some(rest) = trimmed.strip_prefix("media.name = ") {
                media_name = rest.trim().trim_matches('"').to_string();
            }
        }
        flush(&mut apps, cur_id, cur_sink, &mut app_name, &mut media_name);
        apps
    }

    pub async fn status(&self) -> AudioBackendStatus {
        let server_name = self.server_name().await;
        let sink_active = self.sink_exists().await;
        let default_sink = self.get_default_sink().await;
        let is_default_sink = default_sink.as_deref() == Some(SINK_NAME);
        let previous_default_sink = self.previous_default_sink.lock().await.clone();
        let apps = self.list_apps().await;
        AudioBackendStatus {
            server_name,
            sink_active,
            is_default_sink,
            previous_default_sink,
            apps,
        }
    }

    /// Spawn a `parec` capture stream from `nixplay_airplay.monitor` producing 44100 Hz 16-bit LE stereo PCM.
    pub async fn start_capture_reader(&self) -> Result<tokio::process::ChildStdout> {
        self.ensure_virtual_sink().await?;
        let monitor = format!("{}.monitor", SINK_NAME);
        let mut child = Command::new("parec")
            .args([
                "-d",
                &monitor,
                "--format=s16le",
                "--rate=44100",
                "--channels=2",
                "--latency-msec=30",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn parec for audio capture")?;

        let stdout = child
            .stdout
            .take()
            .context("failed to take parec stdout")?;
        *self.capture_child.lock().await = Some(child);
        info!("Started audio capture from {}", monitor);
        Ok(stdout)
    }

    pub async fn stop_capture(&self) {
        if let Some(mut child) = self.capture_child.lock().await.take() {
            let _ = child.kill().await;
        }
    }
}

/// Read an exact frame of PCM bytes from an async reader, returning false on EOF/error.
pub async fn read_pcm_frame<R: AsyncReadExt + Unpin>(reader: &mut R, buf: &mut [u8]) -> bool {
    reader.read_exact(buf).await.is_ok()
}

/// Silent output used while sharing the screen: desktop audio is routed here and its
/// monitor is sent to the TV, so sound plays on the TV only (like Apple's own mirroring).
pub const SCREEN_SINK_NAME: &str = "nixplay_screen";
pub const SCREEN_SINK_MONITOR: &str = "nixplay_screen.monitor";

/// Active screen-audio redirection; call [`ScreenAudioRoute::restore`] to undo it.
pub struct ScreenAudioRoute {
    module_id: Option<u32>,
    previous_default: Option<String>,
}

async fn pactl(args: &[&str]) -> Result<String> {
    PulseAudioManager::run_pactl(args).await
}

async fn move_all_sink_inputs(to: &str) {
    if let Ok(inputs) = pactl(&["list", "short", "sink-inputs"]).await {
        for id in inputs.lines().filter_map(|l| l.split('\t').next()) {
            let _ = pactl(&["move-sink-input", id.trim(), to]).await;
        }
    }
}

/// Unload screen sinks left behind by a session that was killed before it could clean up.
/// PulseAudio/PipeWire move their streams back to a real output automatically.
pub async fn remove_stale_screen_sinks() {
    let Ok(modules) = pactl(&["list", "short", "modules"]).await else {
        return;
    };
    for line in modules.lines() {
        if line.contains(&format!("sink_name={SCREEN_SINK_NAME}")) {
            if let Some(id) = line.split('\t').next() {
                let _ = pactl(&["unload-module", id.trim()]).await;
                info!("Removed stale screen-audio sink (module {})", id.trim());
            }
        }
    }
}

impl ScreenAudioRoute {
    /// Create the silent screen sink, make it the default output, and move every
    /// playing stream onto it.
    pub async fn activate() -> Result<Self> {
        remove_stale_screen_sinks().await;
        let previous_default = pactl(&["get-default-sink"])
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != SCREEN_SINK_NAME);
        let out = pactl(&[
            "load-module",
            "module-null-sink",
            &format!("sink_name={SCREEN_SINK_NAME}"),
            "rate=44100",
            "channels=2",
            "sink_properties=device.description=\"NixPlay Screen Mirroring\"",
        ])
        .await
        .context("could not create the screen-audio sink")?;
        let route = Self {
            module_id: out.trim().parse().ok(),
            previous_default,
        };
        if let Err(e) = pactl(&["set-default-sink", SCREEN_SINK_NAME]).await {
            route.restore().await;
            return Err(e);
        }
        move_all_sink_inputs(SCREEN_SINK_NAME).await;
        info!(
            "Desktop audio routed to the TV only (was playing on {})",
            route.previous_default.as_deref().unwrap_or("default output")
        );
        Ok(route)
    }

    /// Put the user's output back and remove the screen sink.
    pub async fn restore(self) {
        if let Some(prev) = &self.previous_default {
            let _ = pactl(&["set-default-sink", prev]).await;
            move_all_sink_inputs(prev).await;
        }
        if let Some(id) = self.module_id {
            let _ = pactl(&["unload-module", &id.to_string()]).await;
        }
        info!(
            "Desktop audio restored to {}",
            self.previous_default.as_deref().unwrap_or("default output")
        );
    }
}
