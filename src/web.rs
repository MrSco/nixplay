use crate::airplay::video::{VideoCastManager, VideoCastStatus};
use crate::airplay::{MetadataInfo, SessionManager, SpeakerSnapshot};
use crate::audio::pulse::AudioBackendStatus;
use crate::discovery::AirPlayProtocol;
use crate::media_server::ScreenAudio;
use crate::mpris::MprisController;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

const INDEX_HTML: &str = include_str!("../web/index.html");
const ICON_PNG: &[u8] = include_bytes!("../assets/icons/nixplay-128.png");
const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");

#[derive(Clone)]
pub struct WebState {
    pub manager: Arc<SessionManager>,
    pub video: Arc<VideoCastManager>,
    pub mpris: Arc<MprisController>,
}

#[derive(Debug, Serialize)]
pub struct FullStatePayload {
    pub speakers: Vec<SpeakerSnapshot>,
    pub master_volume: u8,
    pub auto_route_audio: bool,
    pub audio_level: f32,
    pub streaming: bool,
    pub metadata: MetadataInfo,
    pub audio_backend: AudioBackendStatus,
    pub video: VideoCastStatus,
    pub version: &'static str,
}

async fn build_full_state(state: &WebState) -> FullStatePayload {
    let speakers = state.manager.speakers_snapshot().await;
    let cfg = state.manager.config.read().await.clone();
    let metadata = state.manager.current_metadata().await;
    let audio_backend = state.manager.audio.pulse.status().await;
    let streaming = state.manager.active_count().await > 0;
    let video = state.video.status().await;
    FullStatePayload {
        speakers,
        master_volume: cfg.master_volume,
        auto_route_audio: cfg.auto_route_audio,
        audio_level: state.manager.audio.level(),
        streaming,
        metadata,
        audio_backend,
        video,
        version: env!("CARGO_PKG_VERSION"),
    }
}

pub fn build_router(state: WebState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/assets/icon.png", get(|| async { png_response(ICON_PNG) }))
        .route("/assets/logo.png", get(|| async { png_response(LOGO_PNG) }))
        .route("/ws", get(ws_handler))
        .route("/api/state", get(get_state))
        .route("/api/scan", post(post_scan))
        .route("/api/speakers/{id}/connect", post(post_connect))
        .route("/api/speakers/{id}/disconnect", post(post_disconnect))
        .route("/api/speakers/{id}/volume", post(post_volume))
        .route("/api/speakers/{id}/latency", post(post_latency))
        .route("/api/speakers/{id}/favorite", post(post_favorite))
        .route("/api/speakers/{id}/pair/start", post(post_pair_start))
        .route("/api/speakers/{id}/pair/finish", post(post_pair_finish))
        .route("/api/speakers/{id}/unpair", post(post_unpair))
        .route("/api/speakers/disconnect-all", post(post_disconnect_all))
        .route("/api/speakers/manual", post(post_manual_speaker))
        .route("/api/master-volume", post(post_master_volume))
        .route("/api/auto-route", post(post_auto_route))
        .route("/api/test-chime", post(post_test_chime))
        .route("/api/apps/{id}/route", post(post_route_app))
        .route("/api/media/{action}", post(post_media_action))
        // AirPlay 2 Video Casting endpoints
        .route("/api/video/cast-url", post(post_video_cast_url))
        .route("/api/video/cast-file", post(post_video_cast_file))
        .route(
            "/api/video/upload-and-cast/{id}",
            post(post_video_upload_and_cast).layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024)),
        )
        .route("/api/video/cast-screen", post(post_video_cast_screen))
        .route("/api/video/rate", post(post_video_rate))
        .route("/api/video/seek", post(post_video_seek))
        .route("/api/video/stop", post(post_video_stop))
        .with_state(state)
}

pub async fn serve_web(bind: &str, port: u16, state: WebState) -> anyhow::Result<()> {
    let app = build_router(state);
    let addr = format!("{bind}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("NixPlay Web UI & API listening at http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn png_response(bytes: &'static [u8]) -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn get_state(State(state): State<WebState>) -> Json<FullStatePayload> {
    Json(build_full_state(&state).await)
}

async fn post_scan(State(state): State<WebState>) -> impl IntoResponse {
    state.manager.discovery.refresh().await;
    state.manager.notify_change();
    StatusCode::OK
}

async fn post_connect(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.manager.connect(&id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => {
            error!("Connect error for {id}: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": e.to_string()})),
            )
        }
    }
}

async fn post_disconnect(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = state.manager.disconnect(&id).await;
    Json(serde_json::json!({"ok": true}))
}

async fn post_disconnect_all(State(state): State<WebState>) -> impl IntoResponse {
    state.manager.disconnect_all().await;
    Json(serde_json::json!({"ok": true}))
}

async fn post_pair_start(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.manager.start_pin_pairing(&id).await {
        Ok(name) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "name": name})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct PinBody {
    pin: String,
}

async fn post_pair_finish(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<PinBody>,
) -> impl IntoResponse {
    match state.manager.finish_pin_pairing(&id, &body.pin).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

async fn post_unpair(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = state.manager.unpair(&id).await;
    Json(serde_json::json!({"ok": true}))
}

#[derive(Deserialize)]
struct VolumeBody {
    volume: u8,
}

async fn post_volume(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<VolumeBody>,
) -> impl IntoResponse {
    let _ = state.manager.set_volume(&id, body.volume).await;
    Json(serde_json::json!({"ok": true}))
}

#[derive(Deserialize)]
struct LatencyBody {
    offset_ms: i32,
}

async fn post_latency(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<LatencyBody>,
) -> impl IntoResponse {
    let _ = state.manager.set_latency_offset(&id, body.offset_ms).await;
    Json(serde_json::json!({"ok": true}))
}

async fn post_favorite(
    State(state): State<WebState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let fav = state.manager.toggle_favorite(&id).await.unwrap_or(false);
    Json(serde_json::json!({"ok": true, "favorite": fav}))
}

async fn post_master_volume(
    State(state): State<WebState>,
    Json(body): Json<VolumeBody>,
) -> impl IntoResponse {
    let _ = state.manager.set_master_volume(body.volume).await;
    Json(serde_json::json!({"ok": true}))
}

#[derive(Deserialize)]
struct AutoRouteBody {
    enabled: bool,
}

async fn post_auto_route(
    State(state): State<WebState>,
    Json(body): Json<AutoRouteBody>,
) -> impl IntoResponse {
    let _ = state.manager.set_auto_route(body.enabled).await;
    Json(serde_json::json!({"ok": true}))
}

async fn post_test_chime(State(state): State<WebState>) -> impl IntoResponse {
    state.manager.audio.play_test_chime().await;
    Json(serde_json::json!({"ok": true}))
}

#[derive(Deserialize)]
struct ManualSpeakerBody {
    name: String,
    ip: String,
    port: Option<u16>,
    protocol: Option<AirPlayProtocol>,
}

async fn post_manual_speaker(
    State(state): State<WebState>,
    Json(body): Json<ManualSpeakerBody>,
) -> impl IntoResponse {
    let Ok(ip) = body.ip.trim().parse::<Ipv4Addr>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "Invalid IPv4 address"})),
        );
    };
    let protocol = body.protocol.unwrap_or(AirPlayProtocol::AirPlay2);
    let port = body.port.unwrap_or(match protocol {
        AirPlayProtocol::AirPlay2 => 7000,
        AirPlayProtocol::Raop => 5000,
    });
    let dev = state
        .manager
        .discovery
        .add_manual(body.name.trim().to_string(), ip, port, protocol)
        .await;
    state.manager.notify_change();
    (StatusCode::OK, Json(serde_json::json!({"ok": true, "device": dev})))
}

#[derive(Deserialize)]
struct RouteAppBody {
    to_nixplay: bool,
}

async fn post_route_app(
    State(state): State<WebState>,
    Path(id): Path<u32>,
    Json(body): Json<RouteAppBody>,
) -> impl IntoResponse {
    match state.manager.audio.pulse.route_app(id, body.to_nixplay).await {
        Ok(()) => {
            state.manager.notify_change();
            (StatusCode::OK, Json(serde_json::json!({"ok": true})))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

async fn post_media_action(
    State(state): State<WebState>,
    Path(action): Path<String>,
) -> impl IntoResponse {
    let method = match action.as_str() {
        "play-pause" | "PlayPause" => "PlayPause",
        "next" | "Next" => "Next",
        "previous" | "Previous" => "Previous",
        _ => return StatusCode::BAD_REQUEST,
    };
    let _ = state.mpris.send_command(method).await;
    StatusCode::OK
}

// ---------- AirPlay 2 Video Casting Handlers ----------

#[derive(Deserialize)]
struct CastUrlBody {
    device_id: String,
    url: String,
    title: Option<String>,
}

async fn post_video_cast_url(
    State(state): State<WebState>,
    Json(body): Json<CastUrlBody>,
) -> impl IntoResponse {
    match state
        .video
        .cast_url(&body.device_id, body.url, body.title, "url", 0.0)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct CastFileBody {
    device_id: String,
    path: String,
}

async fn post_video_cast_file(
    State(state): State<WebState>,
    Json(body): Json<CastFileBody>,
) -> impl IntoResponse {
    let expanded = if let Some(rest) = body.path.trim().strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest)
    } else {
        PathBuf::from(body.path.trim())
    };
    match state.video.cast_file(&body.device_id, expanded).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

async fn post_video_upload_and_cast(
    State(state): State<WebState>,
    Path(device_id): Path<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        let filename = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "video.mp4".to_string());
        match field.bytes().await {
            Ok(bytes) => {
                match state.video.media.save_uploaded_file(&filename, &bytes).await {
                    Ok((url, display)) => {
                        match state
                            .video
                            .cast_url(&device_id, url, Some(display), "file", 0.0)
                            .await
                        {
                            Ok(()) => {
                                return (StatusCode::OK, Json(serde_json::json!({"ok": true})))
                            }
                            Err(e) => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(serde_json::json!({"ok": false, "error": e.to_string()})),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
                        )
                    }
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"ok": false, "error": e.to_string()})),
                )
            }
        }
    }
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"ok": false, "error": "No video file uploaded"})),
    )
}

#[derive(Deserialize)]
struct CastScreenBody {
    device_id: String,
    /// "desktop" | "desktop_and_mic" | "none"
    #[serde(default)]
    audio: Option<ScreenAudio>,
    /// Legacy toggle; `false` means no audio when `audio` is absent.
    #[serde(default = "default_true")]
    with_audio: bool,
    #[serde(default = "default_fps")]
    fps: u32,
}

fn default_true() -> bool {
    true
}
fn default_fps() -> u32 {
    30
}

async fn post_video_cast_screen(
    State(state): State<WebState>,
    Json(body): Json<CastScreenBody>,
) -> impl IntoResponse {
    match state
        .video
        .cast_screen(
            &body.device_id,
            body.audio.unwrap_or(if body.with_audio {
                ScreenAudio::Desktop
            } else {
                ScreenAudio::None
            }),
            body.fps.clamp(10, 60),
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct RateBody {
    rate: f64,
}

async fn post_video_rate(
    State(state): State<WebState>,
    Json(body): Json<RateBody>,
) -> impl IntoResponse {
    state.video.set_rate(body.rate).await;
    Json(serde_json::json!({"ok": true}))
}

#[derive(Deserialize)]
struct SeekBody {
    position: f64,
}

async fn post_video_seek(
    State(state): State<WebState>,
    Json(body): Json<SeekBody>,
) -> impl IntoResponse {
    state.video.seek(body.position).await;
    Json(serde_json::json!({"ok": true}))
}

async fn post_video_stop(State(state): State<WebState>) -> impl IntoResponse {
    state.video.stop().await;
    Json(serde_json::json!({"ok": true}))
}

// ---------- Live WebSocket ----------

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<WebState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: WebState) {
    let (mut sender, mut receiver) = socket.split();
    let mut change_rx = state.manager.subscribe_changes();
    let mut disc_rx = state.manager.discovery.subscribe();

    if let Ok(json) = serde_json::to_string(&build_full_state(&state).await) {
        if sender.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    let mut level_tick = tokio::time::interval(Duration::from_millis(120));
    let mut full_tick = tokio::time::interval(Duration::from_secs(4));

    loop {
        tokio::select! {
            _ = change_rx.recv() => {
                if let Ok(json) = serde_json::to_string(&build_full_state(&state).await) {
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
            _ = disc_rx.recv() => {
                if let Ok(json) = serde_json::to_string(&build_full_state(&state).await) {
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
            _ = full_tick.tick() => {
                if let Ok(json) = serde_json::to_string(&build_full_state(&state).await) {
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
            _ = level_tick.tick() => {
                if state.manager.active_count().await > 0 {
                    let lvl = serde_json::json!({
                        "type": "level",
                        "audio_level": state.manager.audio.level(),
                    });
                    if sender.send(Message::Text(lvl.to_string().into())).await.is_err() {
                        break;
                    }
                }
            }
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}
