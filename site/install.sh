#!/bin/sh
# Aegis remote installer — no repo clone required.
#
#   curl -fsSL https://github.com/arrowassassin/aegis/releases/latest/download/install.sh | sh
#
# Downloads the prebuilt release binaries for your OS/arch (verified against
# SHA256SUMS) and installs them to a bin dir. If no prebuilt build matches (or
# you pass --from-source), it builds from source with `cargo install --git`.
#
# After installing, it runs a short interactive setup (a "stepper") that offers
# to wire your agents and, optionally, set up a local model. Everything optional
# can be skipped; the default install needs no model and no toolchain.
#
# Options (after `| sh -s --`):
#   --from-source       build with cargo instead of downloading
#   --bin-dir <DIR>     install location (default: $HOME/.local/bin)
#   --version <TAG>     install a specific release tag (default: latest)
#   --with-model        non-interactively set up a local model (toolchain + GGUF)
#   --init / --no-init  wire agents + start the daemon (default: ask)
#   --yes               assume "yes" to prompts (non-interactive)
set -eu

REPO="arrowassassin/aegis"
BINS="aegis aegis-daemon aegis-shim aegis-hook aegis-mcp"
BIN_DIR="${AEGIS_BIN_DIR:-$HOME/.local/bin}"
VERSION=""
FROM_SOURCE=0
WITH_MODEL=0
DO_INIT="ask"          # ask | yes | no
ASSUME_YES=0
PICKER_URL="https://github.com/arrowassassin/aegis/releases/latest/download/pick-model.sh"
# Use sudo for system package installs when not already root.
SUDO=""
if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

say()  { printf '\033[1;32maegis\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33maegis\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31maegis: %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --from-source) FROM_SOURCE=1 ;;
    --with-model) WITH_MODEL=1 ;;
    --init) DO_INIT="yes" ;;
    --no-init) DO_INIT="no" ;;
    --yes|-y) ASSUME_YES=1 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a path}"; shift ;;
    --version) VERSION="${2:?--version needs a tag}"; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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

# Run a long command with a live spinner + elapsed time; on failure, print the
# full (verbose) output so nothing is hidden. Quiet while it works, loud if it breaks.
run_with_progress() {
  label="$1"; shift
  log="$(mktemp 2>/dev/null || echo /tmp/aegis-build.log)"
  "$@" >"$log" 2>&1 &
  pid=$!
  start="$(date +%s 2>/dev/null || echo 0)"
  if [ -w /dev/tty ]; then
    spin='|/-\'
    n=0
    while kill -0 "$pid" 2>/dev/null; do
      n=$(( (n + 1) % 4 ))
      c="$(printf '%s' "$spin" | cut -c$((n + 1)))"
      el=$(( $(date +%s 2>/dev/null || echo "$start") - start ))
      last="$(tail -n1 "$log" 2>/dev/null | tr -d '\r' | cut -c1-52)"
      printf '\r\033[K  \033[1;32m%s\033[0m %s  %ss  \033[2m%s\033[0m' "$c" "$label" "$el" "$last" > /dev/tty 2>/dev/null || true
      sleep 0.5
    done
    printf '\r\033[K' > /dev/tty 2>/dev/null || true
  fi
  rc=0; wait "$pid" || rc=$?
  el=$(( $(date +%s 2>/dev/null || echo "$start") - start ))
  if [ "$rc" -eq 0 ]; then
    say "$label — done (${el}s)"
  else
    warn "$label — FAILED after ${el}s. Full build output follows:"
    cat "$log" >&2
  fi
  rm -f "$log" 2>/dev/null || true
  return "$rc"
}

install_from_source() {
  have cargo || die "no prebuilt build for your platform and cargo is not installed.\n  Install Rust (https://rustup.rs) then re-run, or: cargo install --git https://github.com/$REPO aegis-cli aegis-daemon aegis-intercept"
  if [ -n "$VERSION" ]; then
    run_with_progress "building Aegis from source (a few minutes)" \
      cargo install --git "https://github.com/$REPO" aegis-cli aegis-daemon aegis-intercept --tag "$VERSION" || die "source build failed (see output above)"
  else
    run_with_progress "building Aegis from source (a few minutes)" \
      cargo install --git "https://github.com/$REPO" aegis-cli aegis-daemon aegis-intercept || die "source build failed (see output above)"
  fi
  say "installed to $HOME/.cargo/bin"
  stepper "$HOME/.cargo/bin"
}

# Yes/no prompt. Reads /dev/tty so it works under `curl | sh` (piped stdin).
# Non-interactive (no tty): falls back to the default, or "yes" with --yes.
ask() {
  prompt="$1"; default="${2:-N}"
  [ "$ASSUME_YES" -eq 1 ] && return 0
  if [ -r /dev/tty ]; then
    case "$default" in [Yy]*) hint="[Y/n]" ;; *) hint="[y/N]" ;; esac
    printf '%s %s ' "$prompt" "$hint" > /dev/tty
    read -r ans < /dev/tty || ans=""
    [ -z "$ans" ] && ans="$default"
    case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
  fi
  case "$default" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# Install OS packages via whatever package manager is present.
pkg_install() {
  if have brew;     then brew install "$@"
  elif have apt-get;then $SUDO apt-get update -y && $SUDO apt-get install -y "$@"
  elif have dnf;    then $SUDO dnf install -y "$@"
  elif have pacman; then $SUDO pacman -Sy --noconfirm "$@"
  elif have zypper; then $SUDO zypper install -y "$@"
  elif have apk;    then $SUDO apk add "$@"
  else return 1; fi
}

# Ensure a C/C++ toolchain + cmake (and libomp on macOS) for building llama.cpp.
ensure_build_tools() {
  # Already have cmake and a C compiler? Nothing to do.
  if have cmake && { have cc || have gcc || have clang; }; then return 0; fi
  if have brew; then
    xcode-select -p >/dev/null 2>&1 || { say "installing Xcode command-line tools…"; xcode-select --install || true; }
    have cmake || brew install cmake
    brew list libomp >/dev/null 2>&1 || brew install libomp || true
  elif have apt-get; then $SUDO apt-get update -y && $SUDO apt-get install -y cmake build-essential
  elif have dnf;    then $SUDO dnf install -y cmake gcc-c++ make
  elif have pacman; then $SUDO pacman -Sy --noconfirm cmake base-devel
  elif have zypper; then $SUDO zypper install -y cmake gcc-c++ make
  elif have apk;    then $SUDO apk add cmake build-base
  else
    warn "no known package manager — install cmake + a C/C++ compiler yourself, then re-run with --with-model."
    return 1
  fi
}

# Ensure cargo is available (offer rustup if not).
ensure_cargo() {
  have cargo && return 0
  warn "Rust (cargo) is needed to build the model engine."
  if ask "Install Rust now via rustup?" "Y"; then
    if have curl; then curl -fsSL https://sh.rustup.rs | sh -s -- -y
    elif have wget; then wget -qO- https://sh.rustup.rs | sh -s -- -y; fi
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
  fi
  have cargo
}

# Append `export NAME="VALUE"` to the user's shell profile (once), best-effort.
persist_env() {
  name="$1"; val="$2"; line="export $name=\"$val\""
  case "${SHELL:-}" in
    */zsh)  prof="$HOME/.zshrc" ;;
    */bash) prof="$HOME/.bashrc" ;;
    *)      prof="$HOME/.profile" ;;
  esac
  if grep -qs "$name=" "$prof" 2>/dev/null; then
    say "already in $prof: $line"
  elif printf '\n# added by the aegis installer\n%s\n' "$line" >> "$prof" 2>/dev/null; then
    say "added to $prof: $line"
  else
    warn "add this to your shell profile:  $line"
  fi
}

# Optional step: build the llama.cpp engine and download a model from Hugging Face.
setup_model() {
  dir="$1"
  echo
  say "setting up a local model — the in-process llama.cpp engine + a Hugging Face GGUF."
  say "this compiles llama.cpp once (a few minutes) and needs a C/C++ toolchain."
  ensure_build_tools || { warn "toolchain not ready; skipping the model (Aegis still works heuristically)."; return 0; }
  ensure_cargo       || { warn "cargo unavailable; skipping the model build."; return 0; }

  ok=1
  if [ -n "$VERSION" ]; then
    run_with_progress "compiling the llama.cpp engine (a few minutes)" \
      cargo install --git "https://github.com/$REPO" aegis-daemon \
        --features "aegis-model/llama" --root "$(dirname "$dir")" --force --tag "$VERSION" || ok=0
  else
    run_with_progress "compiling the llama.cpp engine (a few minutes)" \
      cargo install --git "https://github.com/$REPO" aegis-daemon \
        --features "aegis-model/llama" --root "$(dirname "$dir")" --force || ok=0
  fi
  [ "$ok" -eq 1 ] || { warn "model engine build failed; Aegis keeps working on the heuristic scorer."; return 0; }

  say "choosing a model from Hugging Face…"
  pickargs=""; [ "$ASSUME_YES" -eq 1 ] && pickargs="--auto"
  if have curl; then curl -fsSL "$PICKER_URL" | sh -s -- $pickargs
  elif have wget; then wget -qO- "$PICKER_URL" | sh -s -- $pickargs; fi

  mdir="${AEGIS_MODEL_DIR:-${AEGIS_DATA_DIR:-$HOME/.local/share/aegis}/models}"
  model="$(ls -t "$mdir"/*.gguf 2>/dev/null | head -n1 || true)"
  if [ -n "$model" ]; then
    persist_env "AEGIS_MODEL_FILE" "$model"
    say "model ready. Restart the daemon to load it:  aegis stop && aegis init"
  else
    warn "no model file found; run the picker again later, then set AEGIS_MODEL_FILE."
  fi
}

# The post-install stepper: PATH note, then optional wiring + optional model.
stepper() {
  dir="$1"
  echo
  case ":$PATH:" in
    *":$dir:"*) : ;;
    *) say "add to your shell profile:  export PATH=\"$dir:\$PATH\"" ;;
  esac

  # Step 1 — wire agents and start the daemon.
  if [ "$DO_INIT" = "yes" ] || { [ "$DO_INIT" = "ask" ] && ask "Wire your agents and start the daemon now? (aegis init)" "Y"; }; then
    "$dir/aegis" init || warn "aegis init failed; run it manually later."
  else
    echo "  later:  aegis init      # detect agents, wire interception, start the daemon"
  fi

  # Step 2 — optional local model.
  if [ "$WITH_MODEL" -eq 1 ] || ask "Set up a local model now? (optional; builds an engine + downloads a Qwen GGUF)" "N"; then
    setup_model "$dir"
  else
    echo "  later (optional):  curl -fsSL $PICKER_URL | sh   # download a model, then set AEGIS_MODEL_FILE"
  fi

  echo
  say "done. Aegis is guarding your machine. Try:  aegis status   ·   aegis tui"
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
  stepper "$BIN_DIR"
}

main
