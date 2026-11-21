# Changelog

## 0.1.0 — 2026-11-20

First release.

### Audio
- Lossless ALAC streaming to HomePod, HomePod mini, Apple TV, Mac and other AirPlay 2 / AirPlay 1 (RAOP) receivers, with multi-room sync, per-speaker volume and sync offset.
- Per-app routing through a `NixPlay AirPlay` PipeWire/PulseAudio output; MPRIS now-playing and media keys.
- One-time on-screen PIN pairing for Apple TV (HomeKit pair-setup / pair-verify).

### Video
- **Real-time AirPlay screen mirroring** to Apple TV (~0.1s delay), with desktop audio, desktop + microphone, or no audio. Desktop sound plays on the TV only while mirroring and returns to your speakers afterwards. Receivers without mirroring support fall back to a low-latency HLS stream (~1.5s).
- Cast local video files (MP4/MOV/M4V) with seeking, and web/HLS URLs.
- YouTube, Vimeo, Twitch and other sites via yt-dlp, including `?t=` start times.
- Works on tvOS 26/27 (play-queue protocol), with a fallback for older Apple TVs.

### App
- Control Center (GTK window or any browser) with a two-column layout, light/dark themes, and a system tray icon.
- Single instance: launching NixPlay again brings up the existing window.
- `install.sh` builds from source and installs ffmpeg plus an up-to-date yt-dlp.

### License
- GPL-3.0-or-later. Screen mirroring (FairPlay handshake and stream protocol) is ported from [doubletake](https://github.com/omarroth/doubletake) (LGPL-3.0-or-later); see `THIRD_PARTY_NOTICES.md`.
