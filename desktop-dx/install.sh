#!/usr/bin/env sh
# Kintsugi Control Room — cross-platform desktop installer.
#
# Builds the release binary, generates the platform-correct icon, and installs
# the app so it appears in your launcher / dock / start menu:
#   - macOS  : ~/Applications/Kintsugi.app  (Info.plist + .icns)
#   - Linux  : ~/.local/bin/kintsugi-control-room + ~/.local/share/applications + ~/.local/share/icons
#   - Windows: prints instructions (use the .exe + LNK shortcut)
#
# Usage:  ./install.sh           build + install
#         ./install.sh --uninstall   remove the installed files
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
bin_name="kintsugi-control-room"
app_display="Kintsugi"
release_bin="$here/target/release/$bin_name"

# Locate the per-size PNGs the build.rs rasterized into OUT_DIR.
locate_icons() {
  # OUT_DIR for the bin's build script — find the most recent one.
  find "$here/target/release/build" -path "*-build_script_build*" -prune -o \
    -name 'logo-256.png' -print 2>/dev/null | head -1 \
    | xargs -I{} dirname {} 2>/dev/null
}

say()  { printf '\033[1;32mkintsugi\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mkintsugi\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mkintsugi: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- macOS -----------------------------------------------------------------

install_macos() {
  ico_dir="$1"
  app="${HOME}/Applications/${app_display}.app"
  contents="$app/Contents"
  macos_dir="$contents/MacOS"
  res_dir="$contents/Resources"
  rm -rf "$app"
  mkdir -p "$macos_dir" "$res_dir"

  # Build the .icns from the per-size PNGs via the system `iconutil`.
  set_dir="$(mktemp -d)/${app_display}.iconset"
  mkdir -p "$set_dir"
  for size in 16 32 64 128 256 512; do
    cp "$ico_dir/logo-$size.png" "$set_dir/icon_${size}x${size}.png"
  done
  # Retina @2x variants (use the next-larger PNG).
  cp "$ico_dir/logo-32.png"  "$set_dir/icon_16x16@2x.png"  2>/dev/null || true
  cp "$ico_dir/logo-64.png"  "$set_dir/icon_32x32@2x.png"  2>/dev/null || true
  cp "$ico_dir/logo-256.png" "$set_dir/icon_128x128@2x.png" 2>/dev/null || true
  cp "$ico_dir/logo-512.png" "$set_dir/icon_256x256@2x.png" 2>/dev/null || true
  iconutil -c icns "$set_dir" -o "$res_dir/Kintsugi.icns" || die "iconutil failed"

  cp "$release_bin" "$macos_dir/$app_display"
  chmod +x "$macos_dir/$app_display"
  cat > "$contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$app_display</string>
  <key>CFBundleDisplayName</key><string>$app_display</string>
  <key>CFBundleExecutable</key><string>$app_display</string>
  <key>CFBundleIdentifier</key><string>tools.kintsugi.control-room</string>
  <key>CFBundleVersion</key><string>0.2.1</string>
  <key>CFBundleShortVersionString</key><string>0.2.1</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>Kintsugi</string>
  <key>LSMinimumSystemVersion</key><string>10.13</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
  say "Installed: $app"
  say "Open from Launchpad/Spotlight, or:  open '$app'"
}

uninstall_macos() {
  rm -rf "${HOME}/Applications/${app_display}.app"
  say "Removed ${HOME}/Applications/${app_display}.app"
}

# ---- Linux -----------------------------------------------------------------

install_linux() {
  ico_dir="$1"
  bin_dest="${HOME}/.local/bin/$bin_name"
  apps_dir="${HOME}/.local/share/applications"
  icon_root="${HOME}/.local/share/icons/hicolor"
  mkdir -p "$(dirname "$bin_dest")" "$apps_dir"
  cp "$release_bin" "$bin_dest"; chmod +x "$bin_dest"
  for size in 16 32 64 128 256 512; do
    dest="$icon_root/${size}x${size}/apps"
    mkdir -p "$dest"
    cp "$ico_dir/logo-$size.png" "$dest/kintsugi-control-room.png"
  done
  cat > "$apps_dir/kintsugi-control-room.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$app_display
Comment=Local-first command governance for AI coding agents
Exec=$bin_dest
Icon=kintsugi-control-room
Terminal=false
Categories=Utility;Security;
StartupWMClass=$bin_name
EOF
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps_dir" || true
  command -v gtk-update-icon-cache    >/dev/null 2>&1 && gtk-update-icon-cache "${HOME}/.local/share/icons/hicolor" || true
  say "Installed: $bin_dest"
  say "Should appear in your launcher; or run:  $bin_dest"
}

uninstall_linux() {
  rm -f "${HOME}/.local/bin/$bin_name"
  rm -f "${HOME}/.local/share/applications/kintsugi-control-room.desktop"
  for size in 16 32 64 128 256 512; do
    rm -f "${HOME}/.local/share/icons/hicolor/${size}x${size}/apps/kintsugi-control-room.png"
  done
  say "Removed Linux install."
}

# ---- driver ----------------------------------------------------------------

mode="${1:-install}"
os="$(uname -s 2>/dev/null || echo unknown)"

if [ "$mode" = "--uninstall" ] || [ "$mode" = "uninstall" ]; then
  case "$os" in
    Darwin) uninstall_macos ;;
    Linux)  uninstall_linux ;;
    *) warn "manual: delete the installed .exe + Start-menu shortcut." ;;
  esac
  exit 0
fi

[ -f "$release_bin" ] || {
  say "Building release binary…"
  (cd "$here" && cargo build --release) || die "release build failed"
}
[ -f "$release_bin" ] || die "release binary not found at $release_bin"

ico_dir="$(locate_icons || true)"
[ -n "$ico_dir" ] && [ -d "$ico_dir" ] || die "couldn't find rasterized icons (try a clean build)"

case "$os" in
  Darwin) install_macos "$ico_dir" ;;
  Linux)  install_linux "$ico_dir" ;;
  MINGW*|MSYS*|CYGWIN*)
    say "Windows: copy $release_bin somewhere on your PATH (e.g. C:\\Users\\<you>\\AppData\\Local\\Programs\\Kintsugi\\Kintsugi.exe),"
    say "then right-click → 'Pin to Start' to get a launcher shortcut."
    ;;
  *) warn "Unrecognized OS ($os) — run the release binary directly: $release_bin" ;;
esac
