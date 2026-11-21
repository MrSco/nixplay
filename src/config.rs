use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Persistent HAP long-term pairing credentials (for Apple TV / Mac PIN-paired receivers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HapCredentials {
    /// Hex-encoded 16-char client identifier (e.g. "A1B2C3D4E5F60708")
    pub client_id: String,
    /// Hex-encoded 32-byte Ed25519 client secret seed
    pub client_sk_hex: String,
    /// Hex-encoded 32-byte Ed25519 server long-term public key
    pub server_pk_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePrefs {
    /// Volume 0..=100
    #[serde(default = "default_volume")]
    pub volume: u8,
    /// Per-speaker latency offset in milliseconds (-500..=+500) for tight multi-room / HDMI sync
    #[serde(default)]
    pub latency_offset_ms: i32,
    /// Pin to top of list
    #[serde(default)]
    pub favorite: bool,
    /// Optional password for legacy RAOP / AirPlay speakers
    #[serde(default)]
    pub password: Option<String>,
    /// Persistent HAP credentials obtained via Apple TV / AirPlay 2 4-digit PIN pairing
    #[serde(default)]
    pub hap_credentials: Option<HapCredentials>,
}

fn default_volume() -> u8 {
    60
}

impl Default for DevicePrefs {
    fn default() -> Self {
        Self {
            volume: default_volume(),
            latency_offset_ms: 0,
            favorite: false,
            password: None,
            hap_credentials: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Local HTTP/Web UI bind host (127.0.0.1 for desktop, 0.0.0.0 for headless Pi / LAN control)
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Local HTTP/Web UI port
    #[serde(default = "default_port")]
    pub port: u16,
    /// LAN HTTP media server port for AirPlay video casting & live screen HLS
    #[serde(default = "default_media_port")]
    pub media_port: u16,
    /// Automatically route default system audio to NixPlay virtual sink when speakers connect
    #[serde(default = "default_true")]
    pub auto_route_audio: bool,
    /// Forward MPRIS2 Now Playing metadata & cover art
    #[serde(default = "default_true")]
    pub forward_mpris: bool,
    /// Enable system tray icon (StatusNotifierItem)
    #[serde(default = "default_true")]
    pub enable_tray: bool,
    /// Master volume (0..=100)
    #[serde(default = "default_master_volume")]
    pub master_volume: u8,
    /// Per-device preferences keyed by normalized device id
    #[serde(default)]
    pub devices: HashMap<String, DevicePrefs>,
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    17420
}

fn default_media_port() -> u16 {
    17421
}

fn default_true() -> bool {
    true
}

fn default_master_volume() -> u8 {
    100
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            media_port: default_media_port(),
            auto_route_audio: true,
            forward_mpris: true,
            enable_tray: true,
            master_volume: default_master_volume(),
            devices: HashMap::new(),
        }
    }
}

impl AppConfig {
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nixplay")
            .join("config.toml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<AppConfig>(&content) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = toml::to_string_pretty(self)?;
        std::fs::write(path, serialized)?;
        Ok(())
    }

    pub fn device_prefs(&self, id: &str) -> DevicePrefs {
        self.devices.get(id).cloned().unwrap_or_default()
    }
}
