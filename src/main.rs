mod airplay;
mod audio;
mod config;
mod discovery;
mod instance;
mod media_server;
mod mpris;
mod tray;
mod web;

use crate::airplay::video::VideoCastManager;
use crate::airplay::{SessionManager, SpeakerState};
use crate::audio::AudioEngine;
use crate::config::AppConfig;
use crate::discovery::{AirPlayProtocol, DiscoveryService};
use crate::media_server::{MediaServer, ScreenAudio};
use crate::mpris::MprisController;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "nixplay",
    version,
    about = "Friendly, polished AirPlay 2 & AirPlay 1 (RAOP) audio & video sender for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the NixPlay AirPlay daemon, system tray icon, and Web Control Center (default)
    Serve {
        /// Bind address for the Web UI (use 0.0.0.0 for headless Raspberry Pi / LAN access)
        #[arg(long)]
        bind: Option<String>,
        /// Port for the Web UI
        #[arg(long)]
        port: Option<u16>,
        /// Disable system tray icon (headless mode)
        #[arg(long)]
        no_tray: bool,
        /// Open the Control Center window automatically on startup
        #[arg(long)]
        open: bool,
    },
    /// Scan the local network and list discovered AirPlay 2 & RAOP receivers
    Scan {
        /// Seconds to listen for mDNS advertisements
        #[arg(short, long, default_value_t = 3)]
        timeout: u64,
    },
    /// Pair with an Apple TV or Mac using its 4-digit on-screen AirPlay PIN (saved permanently)
    Pair {
        /// Receiver name, ID, or IP address (e.g. "Living Room")
        device: String,
    },
    /// Stream audio directly to one or more speakers from the CLI
    Stream {
        /// Speaker name(s), ID(s), or IP address(es)
        #[arg(required = true)]
        speakers: Vec<String>,
        /// Volume percentage (0..=100)
        #[arg(short, long)]
        volume: Option<u8>,
        /// Do not auto-switch default PipeWire/PulseAudio output
        #[arg(long)]
        no_auto_route: bool,
    },
    /// Cast a local video file (MP4/MOV/M4V) or web/HLS URL to an Apple TV or AirPlay 2 display
    Cast {
        /// Receiver name, ID, or IP address (e.g. "Living Room")
        device: String,
        /// Local video file path or http(s):// video/HLS URL
        source: String,
    },
    /// Mirror your Linux desktop / Steam Deck screen to an Apple TV (real-time AirPlay
    /// mirroring, with an FFmpeg -> HLS fallback for receivers that don't support it)
    CastScreen {
        /// Receiver name, ID, or IP address (e.g. "Living Room")
        device: String,
        /// Frames per second (default: 30)
        #[arg(long, default_value_t = 30)]
        fps: u32,
        /// Cast video only without system audio
        #[arg(long, conflicts_with = "mic")]
        no_audio: bool,
        /// Also mix in the default microphone
        #[arg(long)]
        mic: bool,
    },
    /// Verify pairing & audio streaming against a speaker (sends silence by default, or --chime)
    Test {
        /// Speaker name, ID, or IP address
        speaker: String,
        /// Duration in seconds
        #[arg(short, long, default_value_t = 3)]
        seconds: u64,
        /// Play a gentle two-note test chime instead of silence
        #[arg(long)]
        chime: bool,
        /// Force protocol (airplay2 or raop)
        #[arg(long)]
        protocol: Option<String>,
    },
    /// Open the NixPlay Control Center window
    Ui {
        #[arg(long)]
        port: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("nixplay=info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = AppConfig::load();

    match cli.command {
        None => run_serve(cfg, None, None, false, false).await,
        Some(Commands::Serve {
            bind,
            port,
            no_tray,
            open,
        }) => run_serve(cfg, bind, port, no_tray, open).await,
        Some(Commands::Scan { timeout }) => run_scan(timeout).await,
        Some(Commands::Pair { device }) => run_pair(cfg, device).await,
        Some(Commands::Stream {
            speakers,
            volume,
            no_auto_route,
        }) => run_stream(cfg, speakers, volume, no_auto_route).await,
        Some(Commands::Cast { device, source }) => run_cast(cfg, device, source).await,
        Some(Commands::CastScreen {
            device,
            fps,
            no_audio,
            mic,
        }) => {
            let audio = match (no_audio, mic) {
                (true, _) => ScreenAudio::None,
                (_, true) => ScreenAudio::DesktopAndMic,
                _ => ScreenAudio::Desktop,
            };
            run_cast_screen(cfg, device, fps, audio).await
        }
        Some(Commands::Test {
            speaker,
            seconds,
            chime,
            protocol,
        }) => run_test(cfg, speaker, seconds, chime, protocol).await,
        Some(Commands::Ui { port }) => {
            let url = format!("http://127.0.0.1:{}", port.unwrap_or(cfg.port));
            match instance::running_daemon() {
                Some(pid) => tray::open_ui_window_for(&url, pid),
                None => println!("NixPlay isn't running. Start it with: nixplay serve --open"),
            }
            Ok(())
        }
    }
}

async fn run_serve(
    cfg: AppConfig,
    bind_override: Option<String>,
    port_override: Option<u16>,
    no_tray: bool,
    open_ui: bool,
) -> Result<()> {
    let bind = bind_override.unwrap_or_else(|| cfg.bind.clone());
    let port = port_override.unwrap_or(cfg.port);
    let media_port = cfg.media_port;
    let enable_tray = !no_tray && cfg.enable_tray;

    // Single instance: if NixPlay is already running, just show its window.
    if let Some(pid) = instance::running_daemon() {
        info!("NixPlay is already running (pid {pid}); opening its window instead of starting another copy");
        tray::open_ui_window_for(&format!("http://127.0.0.1:{port}"), pid);
        return Ok(());
    }
    let _instance = instance::claim();

    let discovery = DiscoveryService::start()?;
    let audio = AudioEngine::new();
    let manager = SessionManager::new(discovery.clone(), audio.clone(), cfg);
    // Recover desktop audio if a previous screen share was killed mid-session.
    crate::audio::pulse::remove_stale_screen_sinks().await;
    let media = MediaServer::start(media_port);
    let video = VideoCastManager::new(
        discovery,
        manager.config.clone(),
        media.clone(),
        manager.change_sender(),
    );
    let mpris = MprisController::start(manager.clone()).await;

    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(4);

    let ui_url = format!(
        "http://{}:{port}",
        if bind == "0.0.0.0" { "127.0.0.1" } else { &bind }
    );

    if enable_tray {
        tray::start_tray(manager.clone(), ui_url.clone(), shutdown_tx.clone()).await;
    }

    let web_state = web::WebState {
        manager: manager.clone(),
        video: video.clone(),
        mpris,
    };

    let web_bind = bind.clone();
    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::serve_web(&web_bind, port, web_state).await {
            warn!("Web server stopped: {e}");
        }
    });

    if open_ui {
        tokio::time::sleep(Duration::from_millis(250)).await;
        tray::open_ui_window(&ui_url);
    }

    info!("NixPlay is ready! Open {ui_url} or click the AirPlay icon in your system tray.");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down cleanly...");
        }
        _ = shutdown_rx.recv() => {
            info!("Quit requested from tray, shutting down cleanly...");
        }
    }

    video.stop().await;
    crate::audio::pulse::remove_stale_screen_sinks().await;
    manager.disconnect_all().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    audio.stop().await;
    audio.pulse.cleanup().await;
    web_handle.abort();
    Ok(())
}

async fn run_scan(timeout_secs: u64) -> Result<()> {
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
    let devices = discovery.list().await;
    let cfg = AppConfig::load();

    if devices.is_empty() {
        println!("No AirPlay receivers found on the local network.");
        return Ok(());
    }

    println!(
        "{:<22} {:<16} {:<6} {:<10} {:<14} {:<8} {}",
        "NAME", "IP", "PORT", "PROTOCOL", "TYPE", "PAIRED", "MODEL"
    );
    println!("{}", "-".repeat(98));
    for d in devices {
        let proto = match d.protocol {
            AirPlayProtocol::AirPlay2 => "AirPlay 2",
            AirPlayProtocol::Raop => "AirPlay 1",
        };
        let paired = if cfg.device_prefs(&d.id).hap_credentials.is_some() {
            "Yes"
        } else {
            "-"
        };
        println!(
            "{:<22} {:<16} {:<6} {:<10} {:<14} {:<8} {}",
            d.name,
            d.ip,
            d.primary_port(),
            proto,
            format!("{:?}", d.kind),
            paired,
            d.model
        );
    }
    Ok(())
}

async fn run_pair(cfg: AppConfig, device_query: String) -> Result<()> {
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let audio = AudioEngine::new();
    let manager = SessionManager::new(discovery, audio, cfg);

    let name = manager.start_pin_pairing(&device_query).await?;
    println!("A 4-digit AirPlay PIN should now be displayed on '{name}'.");
    print!("Enter the 4-digit PIN: ");
    std::io::stdout().flush()?;

    let mut pin = String::new();
    std::io::stdin().read_line(&mut pin)?;
    manager.finish_pin_pairing(&device_query, pin.trim()).await?;
    println!("Paired with '{name}'! Credentials saved to {}", AppConfig::path().display());
    Ok(())
}

async fn run_stream(
    mut cfg: AppConfig,
    speakers: Vec<String>,
    volume: Option<u8>,
    no_auto_route: bool,
) -> Result<()> {
    if no_auto_route {
        cfg.auto_route_audio = false;
    }
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let audio = AudioEngine::new();
    let manager = SessionManager::new(discovery, audio.clone(), cfg);

    for target in &speakers {
        if let Some(v) = volume {
            let _ = manager.set_volume(target, v).await;
        }
        manager.connect(target).await?;
        println!("Connecting to '{target}'...");
    }

    println!("Streaming! Press Ctrl+C to stop and restore your previous audio output.");
    tokio::signal::ctrl_c().await?;

    manager.disconnect_all().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    audio.stop().await;
    audio.pulse.cleanup().await;
    Ok(())
}

async fn run_cast(cfg: AppConfig, device: String, source: String) -> Result<()> {
    let media_port = cfg.media_port;
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let audio = AudioEngine::new();
    let manager = SessionManager::new(discovery.clone(), audio, cfg);
    let media = MediaServer::start(media_port);
    let video = VideoCastManager::new(
        discovery,
        manager.config.clone(),
        media,
        manager.change_sender(),
    );

    if source.starts_with("http://") || source.starts_with("https://") {
        println!("Casting URL to '{device}': {source}");
        video.cast_url(&device, source, None, "url", 0.0).await?;
    } else {
        let path = PathBuf::from(&source);
        println!("Casting local file to '{device}': {}", path.display());
        video.cast_file(&device, path).await?;
    }

    println!("Press Ctrl+C to stop casting.");
    tokio::signal::ctrl_c().await?;
    video.stop().await;
    crate::audio::pulse::remove_stale_screen_sinks().await;
    Ok(())
}

async fn run_cast_screen(cfg: AppConfig, device: String, fps: u32, screen_audio: ScreenAudio) -> Result<()> {
    let media_port = cfg.media_port;
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let audio = AudioEngine::new();
    let manager = SessionManager::new(discovery.clone(), audio, cfg);
    // Recover desktop audio if a previous screen share was killed mid-session.
    crate::audio::pulse::remove_stale_screen_sinks().await;
    let media = MediaServer::start(media_port);
    let video = VideoCastManager::new(
        discovery,
        manager.config.clone(),
        media,
        manager.change_sender(),
    );

    println!("Starting live screen capture ({fps}fps, audio={screen_audio:?}) -> '{device}'...");
    video.cast_screen(&device, screen_audio, fps).await?;

    println!("Live screen casting active! Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    video.stop().await;
    crate::audio::pulse::remove_stale_screen_sinks().await;
    Ok(())
}

async fn run_test(
    cfg: AppConfig,
    speaker: String,
    seconds: u64,
    chime: bool,
    protocol_override: Option<String>,
) -> Result<()> {
    let discovery = DiscoveryService::start()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut device = match discovery.get(&speaker).await {
        Some(d) => d,
        None => {
            let (ip_str, scope_id) = match speaker.split_once('%') {
                Some((addr, sc)) => (addr, sc.parse::<u32>().unwrap_or(0)),
                None => (speaker.as_str(), 0),
            };
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                discovery::AirPlayDevice {
                    id: format!("DIRECT-{ip}"),
                    name: speaker.clone(),
                    host: speaker.clone(),
                    ip,
                    scope_id,
                    airplay_port: Some(7000),
                    raop_port: Some(5000),
                    model: "Direct".into(),
                    os_version: None,
                    kind: discovery::DeviceKind::Speaker,
                    protocol: AirPlayProtocol::AirPlay2,
                    supports_airplay2: true,
                    supports_raop: true,
                    requires_password: false,
                    acl: Some(0),
                    group_id: None,
                    is_stereo_pair: false,
                    features: 0,
                    flags: 0,
                    last_seen_ms: 0,
                }
            } else {
                anyhow::bail!("Speaker '{}' not found on network", speaker);
            }
        }
    };

    if let Some(p) = protocol_override {
        device.protocol = match p.to_lowercase().as_str() {
            "airplay2" | "ap2" => AirPlayProtocol::AirPlay2,
            "raop" | "airplay1" | "ap1" => AirPlayProtocol::Raop,
            other => anyhow::bail!("Unknown protocol '{other}' (expected airplay2 or raop)"),
        };
    }

    let creds = cfg.device_prefs(&device.id).hap_credentials;

    println!(
        "Testing '{}' ({}:{}, {:?}, {}) for {}s ({})...",
        device.name,
        device.ip,
        device.primary_port(),
        device.protocol,
        device.model,
        seconds,
        if chime { "gentle chime" } else { "silent stream" }
    );

    let audio = AudioEngine::new();
    audio.ensure_started(false);

    if chime {
        audio.play_test_chime().await;
    }

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(8);
    let (state_tx, mut state_rx) = tokio::sync::watch::channel(SpeakerState::Connecting);

    let dev_clone = device.clone();
    let audio_clone = audio.clone();
    let session_task = tokio::spawn(async move {
        match dev_clone.protocol {
            AirPlayProtocol::AirPlay2 => {
                airplay::airplay2::run_airplay2_session(
                    dev_clone,
                    creds,
                    40,
                    0,
                    audio_clone,
                    cmd_rx,
                    state_tx,
                )
                .await
            }
            AirPlayProtocol::Raop => {
                airplay::raop::run_raop_session(dev_clone, 40, 0, audio_clone, cmd_rx, state_tx)
                    .await
            }
        }
    });

    let wait_res = tokio::time::timeout(Duration::from_secs(10), async {
        while state_rx.changed().await.is_ok() {
            let st = *state_rx.borrow();
            println!("  State -> {:?}", st);
            if st == SpeakerState::Streaming || st == SpeakerState::Error {
                return st;
            }
        }
        *state_rx.borrow()
    })
    .await;

    match wait_res {
        Ok(SpeakerState::Streaming) => {
            println!("  Handshake + stream setup SUCCEEDED! Streaming for {seconds}s...");
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            let _ = cmd_tx.send(airplay::SpeakerCommand::Disconnect).await;
            session_task.await??;
            audio.stop().await;
            println!("  Clean teardown SUCCEEDED!");
            Ok(())
        }
        _ => {
            let _ = cmd_tx.send(airplay::SpeakerCommand::Disconnect).await;
            audio.stop().await;
            session_task.await??;
            anyhow::bail!("Speaker did not reach Streaming state");
        }
    }
}
