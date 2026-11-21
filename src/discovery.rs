use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

const AIRPLAY_SERVICE: &str = "_airplay._tcp.local.";
const RAOP_SERVICE: &str = "_raop._tcp.local.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    HomePodMini,
    HomePod,
    AppleTv,
    Mac,
    ShairportSync,
    Sonos,
    Speaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AirPlayProtocol {
    #[serde(rename = "airplay2")]
    AirPlay2,
    Raop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirPlayDevice {
    /// Stable normalized identifier (MAC / deviceid without colons, uppercased)
    pub id: String,
    pub name: String,
    pub host: String,
    pub ip: IpAddr,
    #[serde(default)]
    pub scope_id: u32,
    pub airplay_port: Option<u16>,
    pub raop_port: Option<u16>,
    pub model: String,
    pub os_version: Option<String>,
    pub kind: DeviceKind,
    pub protocol: AirPlayProtocol,
    pub supports_airplay2: bool,
    pub supports_raop: bool,
    pub requires_password: bool,
    /// Access control level (0 = Anyone on network, 1 = Same Home, 2 = Password/PIN)
    pub acl: Option<u8>,
    pub group_id: Option<String>,
    pub is_stereo_pair: bool,
    pub features: u64,
    pub flags: u64,
    pub last_seen_ms: u64,
}

impl AirPlayDevice {
    pub fn primary_port(&self) -> u16 {
        match self.protocol {
            AirPlayProtocol::AirPlay2 => self.airplay_port.or(self.raop_port).unwrap_or(7000),
            AirPlayProtocol::Raop => self.raop_port.or(self.airplay_port).unwrap_or(5000),
        }
    }
}

pub fn classify_device(model: &str) -> DeviceKind {
    let m = model.to_lowercase();
    if m.starts_with("audioaccessory5") {
        DeviceKind::HomePodMini
    } else if m.starts_with("audioaccessory") {
        DeviceKind::HomePod
    } else if m.starts_with("appletv") {
        DeviceKind::AppleTv
    } else if m.starts_with("mac") || m.starts_with("imac") {
        DeviceKind::Mac
    } else if m.contains("shairport") {
        DeviceKind::ShairportSync
    } else if m.contains("sonos") || m.contains("symfonisk") {
        DeviceKind::Sonos
    } else {
        DeviceKind::Speaker
    }
}

fn parse_features(val: &str) -> u64 {
    let parts: Vec<&str> = val.split(',').collect();
    let parse_hex = |s: &str| -> u64 {
        let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(trimmed, 16).unwrap_or(0)
    };
    match parts.len() {
        1 => parse_hex(parts[0]),
        2 => {
            let lo = parse_hex(parts[0]) & 0xFFFF_FFFF;
            let hi = parse_hex(parts[1]) & 0xFFFF_FFFF;
            (hi << 32) | lo
        }
        _ => 0,
    }
}

fn parse_flags(val: &str) -> u64 {
    let trimmed = val.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        trimmed.parse::<u64>().unwrap_or(0)
    }
}

fn normalize_id(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

fn pick_best_ip(info: &ServiceInfo) -> Option<IpAddr> {
    // Strongly prefer IPv4 (more reliable across Linux LANs & HomePods), fall back to non-link-local IPv6
    let addrs = info.get_addresses();
    for addr in addrs {
        if let IpAddr::V4(v4) = addr {
            if !v4.is_loopback() && !v4.is_link_local() {
                return Some(IpAddr::V4(*v4));
            }
        }
    }
    for addr in addrs {
        if let IpAddr::V6(v6) = addr {
            if !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 {
                return Some(IpAddr::V6(*v6));
            }
        }
    }
    addrs.iter().next().copied()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct DiscoveryService {
    devices: Arc<RwLock<HashMap<String, AirPlayDevice>>>,
    events_tx: broadcast::Sender<Vec<AirPlayDevice>>,
    daemon: Option<ServiceDaemon>,
}

impl DiscoveryService {
    pub fn start() -> Result<Arc<Self>> {
        let devices = Arc::new(RwLock::new(HashMap::new()));
        let (events_tx, _) = broadcast::channel(64);

        let daemon = match ServiceDaemon::new() {
            Ok(d) => Some(d),
            Err(e) => {
                warn!("Failed to start mDNS daemon: {e}. Will rely on fallback discovery.");
                None
            }
        };

        let svc = Arc::new(Self {
            devices: devices.clone(),
            events_tx: events_tx.clone(),
            daemon,
        });

        if let Some(ref daemon) = svc.daemon {
            if let Ok(rx) = daemon.browse(AIRPLAY_SERVICE) {
                let svc_clone = svc.clone();
                tokio::spawn(async move {
                    loop {
                        match rx.recv_async().await {
                            Ok(ServiceEvent::ServiceResolved(info)) => {
                                svc_clone.handle_resolved(info, false).await;
                            }
                            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                                debug!("AirPlay service removed: {fullname}");
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
            }

            if let Ok(rx) = daemon.browse(RAOP_SERVICE) {
                let svc_clone = svc.clone();
                tokio::spawn(async move {
                    loop {
                        match rx.recv_async().await {
                            Ok(ServiceEvent::ServiceResolved(info)) => {
                                svc_clone.handle_resolved(info, true).await;
                            }
                            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                                debug!("RAOP service removed: {fullname}");
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
            }
        }

        // Also trigger an initial avahi-browse fallback sweep if avahi-daemon owns port 5353
        // (very helpful on some Linux desktops where Avahi caches records already!)
        {
            let svc_clone = svc.clone();
            tokio::spawn(async move {
                let _ = svc_clone.avahi_sweep().await;
            });
        }

        Ok(svc)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<AirPlayDevice>> {
        self.events_tx.subscribe()
    }

    pub async fn list(&self) -> Vec<AirPlayDevice> {
        let map = self.devices.read().await;
        let mut list: Vec<AirPlayDevice> = map.values().cloned().collect();
        list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        list
    }

    pub async fn get(&self, id: &str) -> Option<AirPlayDevice> {
        let map = self.devices.read().await;
        if let Some(d) = map.get(id) {
            return Some(d.clone());
        }
        // Also allow matching by name (case-insensitive) or IP for CLI ergonomics
        let q = id.to_lowercase();
        map.values()
            .find(|d| d.name.to_lowercase() == q || d.ip.to_string() == q)
            .cloned()
    }

    pub async fn refresh(&self) {
        let _ = self.avahi_sweep().await;
    }

    pub async fn add_manual(
        &self,
        name: String,
        ip: IpAddr,
        port: u16,
        protocol: AirPlayProtocol,
    ) -> AirPlayDevice {
        let id = format!(
            "MANUAL-{}",
            ip.to_string()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_uppercase()
        );
        let dev = AirPlayDevice {
            id: id.clone(),
            name,
            host: ip.to_string(),
            ip,
            scope_id: 0,
            airplay_port: if protocol == AirPlayProtocol::AirPlay2 {
                Some(port)
            } else {
                None
            },
            raop_port: if protocol == AirPlayProtocol::Raop {
                Some(port)
            } else {
                None
            },
            model: "Manual".to_string(),
            os_version: None,
            kind: DeviceKind::Speaker,
            protocol,
            supports_airplay2: protocol == AirPlayProtocol::AirPlay2,
            supports_raop: protocol == AirPlayProtocol::Raop,
            requires_password: false,
            acl: Some(0),
            group_id: None,
            is_stereo_pair: false,
            features: 0,
            flags: 0,
            last_seen_ms: now_ms(),
        };
        {
            let mut map = self.devices.write().await;
            map.insert(id, dev.clone());
        }
        self.emit_update().await;
        dev
    }

    async fn emit_update(&self) {
        let list = self.list().await;
        let _ = self.events_tx.send(list);
    }

    async fn handle_resolved(&self, info: ServiceInfo, is_raop: bool) {
        let Some(ip) = pick_best_ip(&info) else {
            return;
        };
        let fullname = info.get_fullname();
        let instance = fullname
            .strip_suffix(if is_raop {
                "._raop._tcp.local."
            } else {
                "._airplay._tcp.local."
            })
            .unwrap_or(fullname);

        let mut txt = HashMap::new();
        for prop in info.get_properties().iter() {
            txt.insert(prop.key().to_string(), prop.val_str().to_string());
        }

        self.merge_record(
            instance,
            info.get_hostname().trim_end_matches('.'),
            ip,
            info.get_port(),
            &txt,
            is_raop,
        )
        .await;
    }

    async fn merge_record(
        &self,
        instance: &str,
        hostname: &str,
        ip: IpAddr,
        port: u16,
        txt: &HashMap<String, String>,
        is_raop: bool,
    ) {
        // Determine display name and stable ID
        let (raw_id, display_name) = if is_raop {
            if let Some((prefix, rest)) = instance.split_once('@') {
                (prefix.to_string(), rest.to_string())
            } else {
                (hostname.to_string(), instance.to_string())
            }
        } else {
            let id = txt
                .get("deviceid")
                .cloned()
                .unwrap_or_else(|| hostname.to_string());
            (id, instance.to_string())
        };

        let id = normalize_id(&raw_id);
        let model = txt
            .get("model")
            .or_else(|| txt.get("am"))
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());
        let os_version = txt.get("osvers").or_else(|| txt.get("ov")).cloned();
        let features = txt
            .get("features")
            .or_else(|| txt.get("ft"))
            .map(|s| parse_features(s))
            .unwrap_or(0);
        let flags = txt
            .get("flags")
            .or_else(|| txt.get("sf"))
            .map(|s| parse_flags(s))
            .unwrap_or(0);
        let acl = txt.get("acl").and_then(|s| s.parse::<u8>().ok());
        let gid = txt.get("gid").cloned();
        let is_stereo_pair = gid.as_ref().is_some_and(|g| g.contains('+'));
        let requires_password = txt
            .get("pw")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            || (flags & 0x80) != 0;

        // Bit 48 (SupportsUnifiedMediaControl / AirPlay 2) or Bit 46 (HomeKit) or _airplay._tcp with features
        let is_ap2_capable = (!is_raop && (features != 0 || txt.contains_key("pk")))
            || ((features & (1u64 << 48)) != 0)
            || ((features & (1u64 << 46)) != 0);

        let mut map = self.devices.write().await;
        let is_new = !map.contains_key(&id);
        let entry = map.entry(id.clone()).or_insert_with(|| AirPlayDevice {
            id: id.clone(),
            name: display_name.clone(),
            host: hostname.to_string(),
            ip,
            scope_id: 0,
            airplay_port: None,
            raop_port: None,
            model: model.clone(),
            os_version: os_version.clone(),
            kind: classify_device(&model),
            protocol: if is_ap2_capable {
                AirPlayProtocol::AirPlay2
            } else {
                AirPlayProtocol::Raop
            },
            supports_airplay2: false,
            supports_raop: false,
            requires_password,
            acl,
            group_id: gid.clone(),
            is_stereo_pair,
            features,
            flags,
            last_seen_ms: now_ms(),
        });

        // Prefer IPv4 over IPv6 if we already had IPv6 and now see IPv4
        if entry.ip.is_ipv6() && ip.is_ipv4() {
            entry.ip = ip;
        }
        entry.last_seen_ms = now_ms();
        if !display_name.is_empty() {
            entry.name = display_name;
        }
        if !hostname.is_empty() {
            entry.host = hostname.to_string();
        }
        if model != "Unknown" {
            entry.model = model.clone();
            entry.kind = classify_device(&model);
        }
        if os_version.is_some() {
            entry.os_version = os_version;
        }
        if features != 0 {
            entry.features = features;
        }
        if flags != 0 {
            entry.flags = flags;
        }
        if acl.is_some() {
            entry.acl = acl;
        }
        if gid.is_some() {
            entry.group_id = gid;
            entry.is_stereo_pair = is_stereo_pair;
        }
        if requires_password {
            entry.requires_password = true;
        }

        if is_raop {
            entry.raop_port = Some(port);
            entry.supports_raop = true;
            if is_ap2_capable {
                entry.supports_airplay2 = true;
                entry.protocol = AirPlayProtocol::AirPlay2;
            }
        } else {
            entry.airplay_port = Some(port);
            entry.supports_airplay2 = true;
            entry.protocol = AirPlayProtocol::AirPlay2;
        }

        // Shairport Sync without AP2 features -> Raop
        if entry.kind == DeviceKind::ShairportSync && (entry.features & (1u64 << 48)) == 0 {
            entry.protocol = AirPlayProtocol::Raop;
            entry.supports_airplay2 = false;
        }

        if is_new {
            info!(
                "Discovered {} ({:?}, {:?}) at {}:{}",
                entry.name,
                entry.kind,
                entry.protocol,
                entry.ip,
                entry.primary_port()
            );
        } else {
            debug!(
                "Updated {} ({:?}, {:?}) at {}:{}",
                entry.name,
                entry.kind,
                entry.protocol,
                entry.ip,
                entry.primary_port()
            );
        }
        drop(map);
        self.emit_update().await;
    }

    /// Parse `avahi-browse -r -t -p` as a fast supplementary sweep (helps when Avahi already cached records).
    async fn avahi_sweep(&self) -> Result<()> {
        for (svc, is_raop) in [("_airplay._tcp", false), ("_raop._tcp", true)] {
            let output = tokio::process::Command::new("avahi-browse")
                .args(["-r", "-t", "-p", svc])
                .output()
                .await;
            let Ok(out) = output else { continue };
            if !out.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                // Format: =;iface;proto;name;type;domain;hostname;address;port;txt
                if !line.starts_with("=;") {
                    continue;
                }
                let cols: Vec<&str> = line.splitn(10, ';').collect();
                if cols.len() < 10 {
                    continue;
                }
                let instance = unescape_avahi(cols[3]);
                let hostname = cols[6];
                let Ok(ip) = cols[7].parse::<IpAddr>() else {
                    continue;
                };
                let Ok(port) = cols[8].parse::<u16>() else {
                    continue;
                };
                let txt = parse_avahi_txt(cols[9]);
                self.merge_record(&instance, hostname, ip, port, &txt, is_raop)
                    .await;
            }
        }
        Ok(())
    }
}

fn unescape_avahi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Ok(digits) = std::str::from_utf8(&bytes[i + 1..i + 4]) {
                if let Ok(code) = digits.parse::<u8>() {
                    out.push(code as char);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn parse_avahi_txt(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_quotes = false;
    let mut cur = String::new();
    for ch in raw.chars() {
        if ch == '"' {
            if in_quotes {
                if let Some((k, v)) = cur.split_once('=') {
                    map.insert(k.to_string(), v.to_string());
                }
                cur.clear();
            }
            in_quotes = !in_quotes;
        } else if in_quotes {
            cur.push(ch);
        }
    }
    map
}

/// Parsed user-entered manual AirPlay receiver address:
/// supports IPv4 (`192.168.1.50`, `192.168.1.50:7000`), IPv6 (`fe80::1`, `[fe80::1]:7000`),
/// and hostnames (`appletv.local`, `living-room.lan:7000`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    pub host: String,
    pub port: Option<u16>,
}

pub fn parse_manual_address(input: &str) -> Result<ParsedAddress, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Enter an IP address or hostname (e.g. 192.168.1.50 or tv.local).".into());
    }
    if s.contains("://") || s.contains('/') {
        return Err("Enter just the address or hostname, without http:// or paths.".into());
    }
    if s.chars().any(char::is_whitespace) {
        return Err("An address or hostname cannot contain spaces.".into());
    }

    // Bracketed IPv6: [fe80::1] or [fe80::1]:7000
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_str, after) = rest
            .split_once(']')
            .ok_or_else(|| "Missing closing ']' for IPv6 address.".to_string())?;
        let ip: std::net::Ipv6Addr = ip_str
            .parse()
            .map_err(|_| format!("'{ip_str}' is not a valid IPv6 address."))?;
        let port = if after.is_empty() {
            None
        } else if let Some(p_str) = after.strip_prefix(':') {
            let p: u16 = p_str
                .parse()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| "Port must be between 1 and 65535.".to_string())?;
            Some(p)
        } else {
            return Err("Unexpected characters after ']'.".into());
        };
        return Ok(ParsedAddress {
            host: ip.to_string(),
            port,
        });
    }

    // Bare IPv6 (contains at least two colons)
    if s.matches(':').count() >= 2 {
        let ip: std::net::Ipv6Addr = s
            .parse()
            .map_err(|_| format!("'{s}' is not a valid IPv6 address."))?;
        return Ok(ParsedAddress {
            host: ip.to_string(),
            port: None,
        });
    }

    // IPv4 or hostname with optional :port
    let (host, port) = if let Some((h, p_str)) = s.rsplit_once(':') {
        let p: u16 = p_str
            .parse()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| "Port must be between 1 and 65535.".to_string())?;
        (h, Some(p))
    } else {
        (s, None)
    };

    if host.is_empty() {
        return Err("Enter an IP address or hostname before ':port'.".into());
    }

    // Accept IPv4 directly
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(ParsedAddress {
            host: v4.to_string(),
            port,
        });
    }

    // Validate hostname characters
    let valid_host = host
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !valid_host {
        return Err(format!("'{host}' is not a valid IP address or hostname."));
    }

    Ok(ParsedAddress {
        host: host.to_lowercase(),
        port,
    })
}

/// Resolve a parsed manual address (IP or hostname) into an `IpAddr` + port.
pub async fn resolve_manual_address(
    input: &str,
    default_port: u16,
) -> Result<(IpAddr, u16, String), String> {
    let parsed = parse_manual_address(input)?;
    let port = parsed.port.unwrap_or(default_port);
    if let Ok(ip) = parsed.host.parse::<IpAddr>() {
        return Ok((ip, port, parsed.host));
    }
    let addrs = tokio::net::lookup_host((parsed.host.as_str(), port))
        .await
        .map_err(|_| format!("Could not resolve hostname '{}'. Check spelling or enter its IP address.", parsed.host))?;
    let mut picked: Option<IpAddr> = None;
    for sa in addrs {
        if sa.is_ipv4() {
            picked = Some(sa.ip());
            break;
        }
        if picked.is_none() {
            picked = Some(sa.ip());
        }
    }
    let ip = picked.ok_or_else(|| format!("Hostname '{}' returned no IP addresses.", parsed.host))?;
    Ok((ip, port, parsed.host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_ipv6_and_hostnames() {
        assert_eq!(
            parse_manual_address("192.168.1.50").unwrap(),
            ParsedAddress { host: "192.168.1.50".into(), port: None }
        );
        assert_eq!(
            parse_manual_address("192.168.1.50:7100").unwrap(),
            ParsedAddress { host: "192.168.1.50".into(), port: Some(7100) }
        );
        assert_eq!(
            parse_manual_address("[fe80::1]:7000").unwrap(),
            ParsedAddress { host: "fe80::1".into(), port: Some(7000) }
        );
        assert_eq!(
            parse_manual_address("LivingRoom.local:7000").unwrap(),
            ParsedAddress { host: "livingroom.local".into(), port: Some(7000) }
        );
        assert!(parse_manual_address("http://192.168.1.50").is_err());
        assert!(parse_manual_address("192.168.1.50:0").is_err());
    }
}
