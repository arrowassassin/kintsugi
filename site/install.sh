#!/bin/sh
# Aegis remote installer — no repo clone required.
#
#   curl -fsSL https://arrowassassin.github.io/aegis/install.sh | sh
#
# Downloads the prebuilt release binaries for your OS/arch (verified against
# SHA256SUMS) and installs them to a bin dir. If no prebuilt build matches (or
# you pass --from-source), it builds from source with `cargo install --git`.
#
# Options (after `| sh -s --`):
#   --from-source       build with cargo instead of downloading
#   --bin-dir <DIR>     install location (default: $HOME/.local/bin)
#   --version <TAG>     install a specific release tag (default: latest)
#   --with-model        after install, run the model picker (optional GGUF)
set -eu

REPO="arrowassassin/aegis"
BINS="aegis aegis-daemon aegis-shim aegis-hook aegis-mcp"
BIN_DIR="${AEGIS_BIN_DIR:-$HOME/.local/bin}"
VERSION=""
FROM_SOURCE=0
WITH_MODEL=0
PICKER_URL="https://arrowassassin.github.io/aegis/pick-model.sh"

say()  { printf '\033[1;32maegis\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33maegis\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31maegis: %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --from-source) FROM_SOURCE=1 ;;
    --with-model) WITH_MODEL=1 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a path}"; shift ;;
    --version) VERSION="${2:?--version needs a tag}"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

# Map uname → the release target triple built by .github/workflows/release.yml.
detect_target() {
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os-$arch" in
    Linux-x86_64|Linux-amd64)   echo "x86_64-unknown-linux-gnu" ;;
    Darwin-arm64|Darwin-aarch64) echo "aarch64-apple-darwin" ;;
    *) echo "" ;;  # unsupported prebuilt combo → source build
  esac
}

fetch() { # fetch URL → stdout
  if have curl; then curl -fsSL "$1"
  elif have wget; then wget -qO- "$1"
  else die "need curl or wget"; fi
}
fetch_to() { # fetch URL FILE
  if have curl; then curl -fsSL "$1" -o "$2"
  elif have wget; then wget -qO "$2" "$1"
  else die "need curl or wget"; fi
}
sha256() { # sha256 of FILE → hex
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else echo ""; fi
}

install_from_source() {
  have cargo || die "no prebuilt build for your platform and cargo is not installed.\n  Install Rust (https://rustup.rs) then re-run, or: cargo install --git https://github.com/$REPO aegis-cli aegis-daemon aegis-intercept"
  say "building from source with cargo (this can take a few minutes)…"
  cargo install --git "https://github.com/$REPO" aegis-cli aegis-daemon aegis-intercept ${VERSION:+--tag "$VERSION"}
  say "installed to $(dirname "$(command -v aegis || echo "$HOME/.cargo/bin/aegis")")"
  post_install_notes "$HOME/.cargo/bin"
}

post_install_notes() {
  dir="$1"
  echo
  say "done. next steps:"
  case ":$PATH:" in
    *":$dir:"*) : ;;
    *) printf '  add to your shell profile:  export PATH="%s:$PATH"\n' "$dir" ;;
  esac
  echo "  aegis init      # detect agents, wire interception, start the daemon"
  echo "  aegis status    # confirm it's running"
  echo
  echo "  optional — explain/score with a local model (Aegis works without one):"
  echo "    curl -fsSL $PICKER_URL | sh"
  maybe_pick_model
}

# Run the model picker now if --with-model was passed.
maybe_pick_model() {
  [ "$WITH_MODEL" -eq 1 ] || return 0
  echo
  say "running the model picker (--with-model)…"
  if have curl; then curl -fsSL "$PICKER_URL" | sh
  elif have wget; then wget -qO- "$PICKER_URL" | sh
  else warn "need curl or wget for --with-model; skipping."; fi
}

main() {
  if [ "$FROM_SOURCE" -eq 1 ]; then install_from_source; return; fi

  target="$(detect_target)"
  if [ -z "$target" ]; then
    warn "no prebuilt binaries for $(uname -s)/$(uname -m); building from source."
    install_from_source; return
  fi

  tag="$VERSION"
  if [ -z "$tag" ]; then
    tag="$(fetch "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
  fi
  if [ -z "$tag" ]; then
    warn "no published release found; building from source."
    install_from_source; return
  fi

  base="https://github.com/$REPO/releases/download/$tag"
  tarball="aegis-$target.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "downloading $tag for $target…"
  if ! fetch_to "$base/$tarball" "$tmp/$tarball"; then
    warn "release asset $tarball not found; building from source."
    install_from_source; return
  fi

  # Verify against the release SHA256SUMS when both the file and a hasher exist.
  if fetch_to "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null && [ -n "$(sha256 "$tmp/$tarball")" ]; then
    want="$(grep "$tarball" "$tmp/SHA256SUMS" | cut -d' ' -f1 | head -n1)"
    got="$(sha256 "$tmp/$tarball")"
    if [ -n "$want" ] && [ "$want" != "$got" ]; then
      die "checksum mismatch for $tarball (want $want, got $got) — refusing to install"
    fi
    [ -n "$want" ] && say "checksum verified"
  else
    warn "could not verify checksum (no SHA256SUMS or hasher); proceeding"
  fi

  tar -xzf "$tmp/$tarball" -C "$tmp"
  mkdir -p "$BIN_DIR"
  for b in $BINS; do
    src="$(find "$tmp" -type f -name "$b" 2>/dev/null | head -n1)"
    [ -n "$src" ] || { warn "binary $b missing from archive"; continue; }
    install -m 0755 "$src" "$BIN_DIR/$b" 2>/dev/null || { cp "$src" "$BIN_DIR/$b"; chmod 0755 "$BIN_DIR/$b"; }
  done
  say "installed ${BINS} to $BIN_DIR"
  post_install_notes "$BIN_DIR"
}

main
