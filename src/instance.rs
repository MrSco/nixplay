//! Single-instance guard for the NixPlay daemon (`nixplay serve`).
//!
//! The running daemon records its PID in the user's runtime directory. A second launch
//! (app menu, autostart, terminal) finds it and opens the existing Control Center window
//! instead of starting another daemon with a second tray icon.

use std::path::PathBuf;

fn pid_file() -> PathBuf {
    dirs::runtime_dir()
        .or_else(dirs::cache_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("nixplay.pid")
}

/// PID of another live `nixplay` daemon, if one is running.
pub fn running_daemon() -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(pid_file()).ok()?.trim().parse().ok()?;
    if pid == std::process::id() {
        return None;
    }
    // A stale file after a crash may point at a recycled PID: require it to be nixplay.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    (comm.trim() == "nixplay").then_some(pid)
}

/// Marks this process as the running daemon until dropped.
pub struct InstanceGuard(PathBuf);

pub fn claim() -> InstanceGuard {
    let path = pid_file();
    let _ = std::fs::write(&path, std::process::id().to_string());
    InstanceGuard(path)
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let ours = std::fs::read_to_string(&self.0)
            .map(|s| s.trim() == std::process::id().to_string())
            .unwrap_or(false);
        if ours {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
