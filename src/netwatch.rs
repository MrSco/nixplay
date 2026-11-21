/// Watches for system sleep/resume and primary LAN IP changes (Wi-Fi switch / reconnect)
/// so AirPlay discovery and receiving mDNS advertisements refresh automatically.

use std::net::{IpAddr, UdpSocket};
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;
use tracing::info;

/// A wall-clock jump at least this large between 5s ticks means the machine slept.
pub const SLEEP_GAP: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
    ResumedFromSleep,
    PrimaryIpChanged {
        from: Option<IpAddr>,
        to: Option<IpAddr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub wall_gap: Duration,
    pub primary_ip: Option<IpAddr>,
}

pub fn decide(previous_ip: Option<IpAddr>, now: Sample) -> Option<NetworkEvent> {
    if now.wall_gap >= SLEEP_GAP {
        return Some(NetworkEvent::ResumedFromSleep);
    }
    match (previous_ip, now.primary_ip) {
        (_, None) => None, // offline — wait until an address comes back
        (from, to) if from != to => Some(NetworkEvent::PrimaryIpChanged { from, to }),
        _ => None,
    }
}

/// Ask the OS routing table which local IP would be used for outbound LAN/WAN traffic
/// (UDP connect sends zero packets).
pub fn primary_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:9").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

/// Spawn the background watcher and return a broadcast receiver for network/resume events.
pub fn spawn_network_watcher() -> broadcast::Receiver<NetworkEvent> {
    let (tx, rx) = broadcast::channel(16);
    tokio::spawn(async move {
        let mut last_wall = SystemTime::now();
        let mut last_ip = primary_ip();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now_wall = SystemTime::now();
            let wall_gap = now_wall
                .duration_since(last_wall)
                .unwrap_or(Duration::ZERO);
            last_wall = now_wall;

            let cur_ip = primary_ip();
            if let Some(ev) = decide(
                last_ip,
                Sample {
                    wall_gap,
                    primary_ip: cur_ip,
                },
            ) {
                info!("Network watcher triggered refresh: {ev:?}");
                let _ = tx.send(ev);
            }
            if cur_ip.is_some() {
                last_ip = cur_ip;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const HOME: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
    const OTHER: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 15)));

    #[test]
    fn normal_tick_is_quiet() {
        assert_eq!(
            decide(
                HOME,
                Sample {
                    wall_gap: Duration::from_secs(5),
                    primary_ip: HOME
                }
            ),
            None
        );
    }

    #[test]
    fn sleep_gap_triggers_resume() {
        assert_eq!(
            decide(
                HOME,
                Sample {
                    wall_gap: Duration::from_secs(60),
                    primary_ip: HOME
                }
            ),
            Some(NetworkEvent::ResumedFromSleep)
        );
    }

    #[test]
    fn ip_change_triggers_network_event() {
        assert_eq!(
            decide(
                HOME,
                Sample {
                    wall_gap: Duration::from_secs(5),
                    primary_ip: OTHER
                }
            ),
            Some(NetworkEvent::PrimaryIpChanged {
                from: HOME,
                to: OTHER
            })
        );
    }

    #[test]
    fn going_offline_does_not_spam() {
        assert_eq!(
            decide(
                HOME,
                Sample {
                    wall_gap: Duration::from_secs(5),
                    primary_ip: None
                }
            ),
            None
        );
    }
}
