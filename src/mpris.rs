use crate::airplay::{MetadataInfo, SessionManager};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};
use zbus::zvariant::OwnedValue;
use zbus::{Connection, Proxy};

/// Pure-Rust MPRIS2 watcher over D-Bus (`org.mpris.MediaPlayer2.*`).
/// Automatically picks up Now Playing track info from Spotify, Firefox, Chrome, VLC,
/// Rhythmbox, Strawberry, MPV, etc., and exposes media playback controls.
pub struct MprisController {
    conn: Option<Connection>,
}

impl MprisController {
    pub async fn start(manager: Arc<SessionManager>) -> Arc<Self> {
        let conn = match Connection::session().await {
            Ok(c) => {
                info!("Connected to session D-Bus for MPRIS2 media tracking");
                Some(c)
            }
            Err(e) => {
                debug!("Session D-Bus unavailable ({e}); MPRIS2 disabled (normal on headless)");
                None
            }
        };

        let ctrl = Arc::new(Self { conn: conn.clone() });

        if let Some(c) = conn {
            tokio::spawn(async move {
                loop {
                    if let Ok(meta) = poll_active_player(&c).await {
                        manager.update_metadata(meta).await;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
        }

        ctrl
    }

    pub async fn send_command(&self, method: &str) -> Result<()> {
        let Some(ref conn) = self.conn else {
            return Ok(());
        };
        let Some(bus_name) = find_best_player(conn).await? else {
            return Ok(());
        };
        let proxy = Proxy::new(
            conn,
            bus_name.as_str(),
            "/org/mpris/MediaPlayer2",
            "org.mpris.MediaPlayer2.Player",
        )
        .await?;
        let _: () = proxy.call(method, &()).await?;
        Ok(())
    }
}

async fn list_mpris_players(conn: &Connection) -> Result<Vec<String>> {
    let proxy = Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let names: Vec<String> = proxy.call("ListNames", &()).await?;
    Ok(names
        .into_iter()
        .filter(|n| n.starts_with("org.mpris.MediaPlayer2."))
        .collect())
}

async fn find_best_player(conn: &Connection) -> Result<Option<String>> {
    let players = list_mpris_players(conn).await?;
    let mut fallback = None;
    for name in players {
        let Ok(proxy) = Proxy::new(
            conn,
            name.as_str(),
            "/org/mpris/MediaPlayer2",
            "org.mpris.MediaPlayer2.Player",
        )
        .await
        else {
            continue;
        };
        let status: String = proxy
            .get_property("PlaybackStatus")
            .await
            .unwrap_or_default();
        if status == "Playing" {
            return Ok(Some(name));
        }
        if fallback.is_none() {
            fallback = Some(name);
        }
    }
    Ok(fallback)
}

async fn poll_active_player(conn: &Connection) -> Result<MetadataInfo> {
    let Some(name) = find_best_player(conn).await? else {
        return Ok(MetadataInfo::default());
    };

    let player_proxy = Proxy::new(
        conn,
        name.as_str(),
        "/org/mpris/MediaPlayer2",
        "org.mpris.MediaPlayer2.Player",
    )
    .await?;

    let root_proxy = Proxy::new(
        conn,
        name.as_str(),
        "/org/mpris/MediaPlayer2",
        "org.mpris.MediaPlayer2",
    )
    .await?;

    let status: String = player_proxy
        .get_property("PlaybackStatus")
        .await
        .unwrap_or_default();
    let player_name: String = root_proxy
        .get_property("Identity")
        .await
        .unwrap_or_else(|_| {
            name.strip_prefix("org.mpris.MediaPlayer2.")
                .unwrap_or(&name)
                .to_string()
        });

    let meta_map: HashMap<String, OwnedValue> = player_proxy
        .get_property("Metadata")
        .await
        .unwrap_or_default();

    let title = meta_map
        .get("xesam:title")
        .and_then(|v| String::try_from(v.clone()).ok())
        .unwrap_or_default();

    let album = meta_map
        .get("xesam:album")
        .and_then(|v| String::try_from(v.clone()).ok())
        .unwrap_or_default();

    let artist = meta_map
        .get("xesam:artist")
        .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
        .map(|v| v.join(", "))
        .unwrap_or_default();

    let art_url = meta_map
        .get("mpris:artUrl")
        .and_then(|v| String::try_from(v.clone()).ok())
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"));

    Ok(MetadataInfo {
        title,
        artist,
        album,
        player: player_name,
        status,
        art_url,
    })
}
