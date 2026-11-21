#!/usr/bin/env bash
set -euo pipefail

# NixPlay One-Line Installer
# Works on Linux Mint, Ubuntu, Debian, Fedora, Arch, Steam Deck (SteamOS), and Raspberry Pi (ARM64)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mrsco/nixplay/main/install.sh | bash
#   (or locally inside a cloned repo: ./install.sh)

REPO_URL="${NIXPLAY_REPO_URL:-https://github.com/mrsco/nixplay.git}"
INSTALL_BIN_DIR="${HOME}/.local/bin"
INSTALL_DATA_DIR="${HOME}/.local/share/nixplay"
INSTALL_APP_DIR="${HOME}/.local/share/applications"
INSTALL_ICON_ROOT="${HOME}/.local/share/icons/hicolor"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
info() { printf "\033[1;36m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✔\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m!\033[0m %s\n" "$*"; }

bold ""
bold "  NixPlay — Friendly AirPlay 2 Audio & Video for Linux"
bold "  ─────────────────────────────────────────────────────"
echo ""

# 1. Locate source directory (use local repo if running from checkout, else clone to temp dir)
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

CLEANUP_DIR=""
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Cargo.toml" ]]; then
  SRC_DIR="$SCRIPT_DIR"
  info "Using local NixPlay checkout at $SRC_DIR"
elif [[ -f "./Cargo.toml" ]] && grep -q 'name = "nixplay"' ./Cargo.toml 2>/dev/null; then
  SRC_DIR="$(pwd)"
  info "Using local NixPlay checkout at $SRC_DIR"
else
  if ! command -v git >/dev/null 2>&1; then
    echo "Error: git is required to clone NixPlay. Install it (e.g. sudo apt install git) and re-run." >&2
    exit 1
  fi
  CLEANUP_DIR="$(mktemp -d -t nixplay-install-XXXXXX)"
  trap 'rm -rf "$CLEANUP_DIR"' EXIT
  info "Cloning NixPlay from $REPO_URL..."
  git clone --depth 1 "$REPO_URL" "$CLEANUP_DIR/nixplay"
  SRC_DIR="$CLEANUP_DIR/nixplay"
fi

# 2. Ensure Rust toolchain is installed (user-space only — no sudo needed, safe for SteamOS!)
export PATH="${HOME}/.cargo/bin:${PATH}"
if ! command -v cargo >/dev/null 2>&1; then
  info "Rust toolchain not found — installing rustup (user-space, no sudo required)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
ok "Using $(rustc --version)"

# 3. Build optimized native release binary
info "Building NixPlay (release)..."
(cd "$SRC_DIR" && cargo build --release)
ok "Build complete"

# 4. Install binary, native popover launcher, icon, and desktop entry
mkdir -p "$INSTALL_BIN_DIR" "$INSTALL_DATA_DIR" "$INSTALL_APP_DIR"

install -m 755 "$SRC_DIR/target/release/nixplay" "$INSTALL_BIN_DIR/nixplay"
install -m 755 "$SRC_DIR/desktop/nixplay-ui.py" "$INSTALL_DATA_DIR/nixplay-ui.py"
for size in 16 22 24 32 48 64 128 256 512; do
  install -D -m 644 "$SRC_DIR/assets/icons/nixplay-${size}.png" \
    "$INSTALL_ICON_ROOT/${size}x${size}/apps/nixplay.png"
done
rm -f "$INSTALL_ICON_ROOT/scalable/apps/nixplay.svg"  # old placeholder icon
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$INSTALL_ICON_ROOT" >/dev/null 2>&1 || true
fi
sed "s|Exec=nixplay|Exec=${INSTALL_BIN_DIR}/nixplay|g" "$SRC_DIR/desktop/nixplay.desktop" \
  > "$INSTALL_APP_DIR/nixplay.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$INSTALL_APP_DIR" >/dev/null 2>&1 || true
fi

# 5. Video-casting helpers: ffmpeg (live screen casting) + an up-to-date yt-dlp (YouTube etc.)
SUDO=""
if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

if ! command -v ffmpeg >/dev/null 2>&1; then
  info "Installing ffmpeg (needed for live screen casting)..."
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get install -y ffmpeg || warn "Could not install ffmpeg via apt"
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y ffmpeg || warn "Could not install ffmpeg via dnf (enable RPM Fusion for full ffmpeg)"
  elif command -v pacman >/dev/null 2>&1 && ! grep -qi steamos /etc/os-release 2>/dev/null; then
    $SUDO pacman -S --needed --noconfirm ffmpeg || warn "Could not install ffmpeg via pacman"
  else
    warn "Install ffmpeg manually to enable live screen casting (e.g. flatpak or your package manager)."
  fi
fi
command -v ffmpeg >/dev/null 2>&1 && ok "ffmpeg: $(ffmpeg -version 2>/dev/null | head -n1 | cut -d' ' -f3)"

# Distro yt-dlp packages are usually months/years old and YouTube breaks them, so NixPlay
# keeps its own copy of the official standalone release in ~/.local/bin (self-updating).
case "$(uname -m)" in
  x86_64|amd64)  YTDLP_ASSET="yt-dlp_linux" ;;
  aarch64|arm64) YTDLP_ASSET="yt-dlp_linux_aarch64" ;;
  armv7l)        YTDLP_ASSET="yt-dlp_linux_armv7l" ;;
  *)             YTDLP_ASSET="" ;;
esac
YTDLP_BIN="${INSTALL_BIN_DIR}/yt-dlp"
mkdir -p "$INSTALL_BIN_DIR"
if [[ -x "$YTDLP_BIN" ]]; then
  info "Updating yt-dlp..."
  "$YTDLP_BIN" -U >/dev/null 2>&1 || warn "yt-dlp self-update failed (keeping existing version)"
elif [[ -n "$YTDLP_ASSET" ]]; then
  info "Installing latest yt-dlp (YouTube / Vimeo / Twitch casting)..."
  YTDLP_TMP="$(mktemp -d -t nixplay-ytdlp-XXXXXX)"
  YTDLP_BASE="https://github.com/yt-dlp/yt-dlp/releases/latest/download"
  if curl -fsSL -o "$YTDLP_TMP/$YTDLP_ASSET" "$YTDLP_BASE/$YTDLP_ASSET" \
     && curl -fsSL -o "$YTDLP_TMP/SHA2-256SUMS" "$YTDLP_BASE/SHA2-256SUMS" \
     && (cd "$YTDLP_TMP" && grep " ${YTDLP_ASSET}\$" SHA2-256SUMS | sha256sum -c --status); then
    install -m 755 "$YTDLP_TMP/$YTDLP_ASSET" "$YTDLP_BIN"
  else
    warn "Could not download/verify yt-dlp; streaming-site casting will use the system yt-dlp if present."
  fi
  rm -rf "$YTDLP_TMP"
else
  warn "No prebuilt yt-dlp for $(uname -m); install it with your package manager or pipx."
fi
[[ -x "$YTDLP_BIN" ]] && ok "yt-dlp: $("$YTDLP_BIN" --version 2>/dev/null)"

# 6. Ensure ~/.local/bin is on PATH in ~/.bashrc / ~/.profile
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
ADDED_PATH=0
if [[ ":$PATH:" != *":${INSTALL_BIN_DIR}:"* ]]; then
  for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
    if [[ -f "$rc" ]] && ! grep -qF '.local/bin' "$rc" 2>/dev/null; then
      printf '\n# Added by NixPlay installer\n%s\n' "$PATH_LINE" >> "$rc"
      ADDED_PATH=1
    fi
  done
fi

echo ""
ok "NixPlay installed successfully!"
echo "   Binary:   ${INSTALL_BIN_DIR}/nixplay"
echo "   Launcher: ${INSTALL_APP_DIR}/nixplay.desktop"
echo ""

if ! command -v ffmpeg >/dev/null 2>&1; then
  warn "ffmpeg is still missing — live screen casting won't work until it's installed."
  echo "   (Audio streaming, multi-room, and MP4/MOV/URL video casting work without it.)"
  echo ""
fi

bold "Quick Start:"
if [[ "$ADDED_PATH" -eq 1 ]]; then
  echo "   source ~/.bashrc   # or open a new terminal"
fi
echo "   nixplay serve --open          # Launch system tray + Control Center UI"
echo "   nixplay scan                  # List HomePods, Apple TVs & AirPlay speakers"
echo "   nixplay test \"Kitchen\" --chime  # Play a gentle test chime"
echo "   nixplay pair \"Living Room\"    # Pair with Apple TV (4-digit on-screen PIN)"
echo ""
echo "   Headless Raspberry Pi / Steam Deck LAN remote mode:"
echo "   nixplay serve --bind 0.0.0.0 --no-tray"
echo ""
