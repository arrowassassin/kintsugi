#!/bin/sh
# Kintsugi remote installer — no repo clone required.
#
#   curl -fsSL https://kintsugi.tools/install.sh | sh
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
#   --bin-only          just install/replace the binaries; skip the setup stepper
#                       (used by `kintsugi update`)
set -eu

REPO="arrowassassin/kintsugi"
BINS="kintsugi kintsugi-daemon kintsugi-shim kintsugi-hook kintsugi-mcp"
BIN_DIR="${KINTSUGI_BIN_DIR:-$HOME/.local/bin}"
VERSION=""
FROM_SOURCE=0
WITH_MODEL=0
DO_INIT="ask"          # ask | yes | no
ASSUME_YES=0
BIN_ONLY=0             # 1 = install binaries only, skip the setup stepper
PICKER_URL="https://kintsugi.tools/pick-model.sh"
# Use sudo for system package installs when not already root.
SUDO=""
if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

say()  { printf '\033[1;32mkintsugi\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mkintsugi\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mkintsugi: %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --from-source) FROM_SOURCE=1 ;;
    --with-model) WITH_MODEL=1 ;;
    --init) DO_INIT="yes" ;;
    --no-init) DO_INIT="no" ;;
    --yes|-y) ASSUME_YES=1 ;;
    --bin-only) BIN_ONLY=1 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a path}"; shift ;;
    --version) VERSION="${2:?--version needs a tag}"; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
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
  log="$(mktemp 2>/dev/null || echo /tmp/kintsugi-build.log)"
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
  have cargo || die "no prebuilt build for your platform and cargo is not installed.\n  Install Rust (https://rustup.rs) then re-run, or: cargo install --git https://github.com/$REPO kintsugi"
  # The single `kintsugi` crate builds all binaries (kintsugi, kintsugi-daemon,
  # kintsugi-hook, kintsugi-shim, kintsugi-mcp).
  if [ -n "$VERSION" ]; then
    run_with_progress "building Kintsugi from source (a few minutes)" \
      cargo install --git "https://github.com/$REPO" kintsugi --tag "$VERSION" || die "source build failed (see output above)"
  else
    run_with_progress "building Kintsugi from source (a few minutes)" \
      cargo install --git "https://github.com/$REPO" kintsugi || die "source build failed (see output above)"
  fi
  say "installed to $HOME/.cargo/bin"
  [ "$BIN_ONLY" -eq 1 ] && { say "binaries updated. Restart the daemon to run the new build:  kintsugi stop && kintsugi init"; return; }
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
# Wrapped in run_with_progress so the user sees a spinner — not pages of
# Homebrew chatter ("==> Pouring …", "Caveats:", "Disable this behaviour by
# setting HOMEBREW_NO_INSTALL_CLEANUP=1", etc). On failure, the full log is
# replayed so nothing is hidden.
ensure_build_tools() {
  # Already have cmake and a C compiler? Nothing to do.
  if have cmake && { have cc || have gcc || have clang; }; then return 0; fi
  # Quiet the noisy package managers. These are all advisory: they suppress
  # hint/cleanup output but don't change what's installed.
  export HOMEBREW_NO_ENV_HINTS=1
  export HOMEBREW_NO_INSTALL_CLEANUP=1
  export HOMEBREW_NO_AUTO_UPDATE=1
  export DEBIAN_FRONTEND=noninteractive
  if have brew; then
    xcode-select -p >/dev/null 2>&1 || { say "installing Xcode command-line tools…"; xcode-select --install || true; }
    have cmake || run_with_progress "installing cmake (homebrew)" brew install cmake || return 1
    brew list libomp >/dev/null 2>&1 || run_with_progress "installing libomp (homebrew)" brew install libomp || true
  elif have apt-get; then
    run_with_progress "updating apt index" $SUDO apt-get update -y || return 1
    run_with_progress "installing cmake + build-essential (apt)" $SUDO apt-get install -y cmake build-essential || return 1
  elif have dnf;    then run_with_progress "installing cmake + gcc-c++ (dnf)"    $SUDO dnf install -y cmake gcc-c++ make || return 1
  elif have pacman; then run_with_progress "installing cmake + base-devel (pacman)" $SUDO pacman -Sy --noconfirm cmake base-devel || return 1
  elif have zypper; then run_with_progress "installing cmake + gcc-c++ (zypper)" $SUDO zypper install -y cmake gcc-c++ make || return 1
  elif have apk;    then run_with_progress "installing cmake + build-base (apk)" $SUDO apk add cmake build-base || return 1
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
  elif printf '\n# added by the kintsugi installer\n%s\n' "$line" >> "$prof" 2>/dev/null; then
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

  # Skip the (multi-minute) engine compile only if the installed daemon already
  # has llama built in AT THE SAME VERSION as the freshly-installed `kintsugi`. An app
  # upgrade changes the version, so the engine is rebuilt rather than left stale;
  # a same-version re-run skips it.
  llama_ver="$([ -x "$dir/kintsugi-daemon" ] && "$dir/kintsugi-daemon" --has-llama 2>/dev/null || true)"
  want_ver="$("$dir/kintsugi" --version 2>/dev/null | awk '{print $NF}')"
  if [ -n "$llama_ver" ] && [ "$llama_ver" = "$want_ver" ]; then
    say "llama.cpp engine already built for v$llama_ver — skipping the compile."
  else
    say "this compiles llama.cpp once (a few minutes) and needs a C/C++ toolchain."
    ensure_build_tools || { warn "toolchain not ready; skipping the model (Kintsugi still works heuristically)."; return 0; }
    ensure_cargo       || { warn "cargo unavailable; skipping the model build."; return 0; }

    ok=1
    # The daemon binary lives in the `kintsugi` crate now; build just that bin
    # with the llama engine and install it over the prebuilt heuristic daemon.
    if [ -n "$VERSION" ]; then
      run_with_progress "compiling the llama.cpp engine (a few minutes)" \
        cargo install --git "https://github.com/$REPO" kintsugi --bin kintsugi-daemon \
          --features llama --root "$(dirname "$dir")" --force --tag "$VERSION" || ok=0
    else
      run_with_progress "compiling the llama.cpp engine (a few minutes)" \
        cargo install --git "https://github.com/$REPO" kintsugi --bin kintsugi-daemon \
          --features llama --root "$(dirname "$dir")" --force || ok=0
    fi
    [ "$ok" -eq 1 ] || { warn "model engine build failed; Kintsugi keeps working on the heuristic scorer."; return 0; }
  fi

  # If a model is already configured and present, keep it — don't re-pick or
  # re-download. This is what makes `kintsugi update` rebuild the engine for the new
  # version while preserving the user's chosen model.
  if [ -n "${KINTSUGI_MODEL_FILE:-}" ] && [ -f "${KINTSUGI_MODEL_FILE:-}" ]; then
    say "keeping the configured model: $(basename "$KINTSUGI_MODEL_FILE")"
    model="$KINTSUGI_MODEL_FILE"
  else
    say "choosing a model from Hugging Face…"
    # Show the picker's menu and let the user choose — including the ★ recommended
    # models alongside the popularity-ranked ones. The picker reads /dev/tty for the
    # choice, so the menu works even under `curl | sh` (piped stdin). We only force
    # --auto for a fully non-interactive install (--yes), where there's no human to
    # answer; otherwise the picker itself falls back to the top recommendation when
    # no terminal is available.
    pickargs=""
    [ "$ASSUME_YES" -eq 1 ] && pickargs="--auto"
    if have curl; then curl -fsSL "$PICKER_URL" | sh -s -- $pickargs
    elif have wget; then wget -qO- "$PICKER_URL" | sh -s -- $pickargs; fi

    mdir="${KINTSUGI_MODEL_DIR:-${KINTSUGI_DATA_DIR:-$HOME/.local/share/kintsugi}/models}"
    model="$(ls -t "$mdir"/*.gguf 2>/dev/null | head -n1 || true)"
  fi
  if [ -n "$model" ]; then
    persist_env "KINTSUGI_MODEL_FILE" "$model"
    # Export into this process so the `kintsugi init` that runs after this (in the
    # stepper) spawns the daemon already pointed at the model — no second start,
    # no transient "heuristic fallback" message.
    export KINTSUGI_MODEL_FILE="$model"
    say "model ready: $(basename "$model")."
  else
    warn "no model file found; run the picker again later, then set KINTSUGI_MODEL_FILE."
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

  # Decide on wiring up front, but DEFER running `kintsugi init` until after the
  # model is in place. Otherwise init starts the daemon on the heuristic scorer,
  # the model step rebuilds + restarts it, and the user sees a misleading "scoring
  # with: heuristic fallback" line for a daemon that's about to be replaced.
  do_init=0
  if [ "$DO_INIT" = "yes" ] || { [ "$DO_INIT" = "ask" ] && ask "Wire your agents and start the daemon now? (kintsugi init)" "Y"; }; then
    do_init=1
  fi

  # Step 1 — optional local model: build the engine, download a GGUF, and set
  # KINTSUGI_MODEL_FILE (exported into this process so the init below inherits it).
  if [ "$WITH_MODEL" -eq 1 ] || ask "Set up a local model now? (optional; builds an engine + downloads a Qwen GGUF)" "N"; then
    setup_model "$dir"
  else
    echo "  later (optional):  curl -fsSL $PICKER_URL | sh   # download a model, then set KINTSUGI_MODEL_FILE"
  fi

  # Step 2 — wire agents and start the daemon, now that the model (if any) is set.
  # `stop` first is idempotent and ensures a daemon left over from a prior install
  # is replaced by one that inherits the freshly-set KINTSUGI_MODEL_FILE.
  if [ "$do_init" -eq 1 ]; then
    "$dir/kintsugi" stop >/dev/null 2>&1 || true
    "$dir/kintsugi" init || warn "kintsugi init failed; run it manually later."
  else
    echo "  later:  kintsugi init      # detect agents, wire interception, start the daemon"
  fi

  echo
  say "done. Kintsugi is guarding your machine. Try:  kintsugi status   ·   kintsugi tui"
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

  # Idempotent re-run: if the target version is already installed in BIN_DIR,
  # skip the download. This also preserves a locally-built llama daemon (the
  # prebuilt tarball would otherwise overwrite it with a heuristic-only build).
  installed="$("$BIN_DIR/kintsugi" --version 2>/dev/null | awk '{print $NF}')"
  if [ -n "$installed" ] && [ "$installed" = "${tag#v}" ]; then
    say "kintsugi ${tag#v} already installed in $BIN_DIR — skipping binary download."
    [ "$BIN_ONLY" -eq 1 ] && return
    stepper "$BIN_DIR"; return
  fi

  base="https://github.com/$REPO/releases/download/$tag"
  tarball="kintsugi-$target.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "downloading $tag for ${target}…"
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
  [ "$BIN_ONLY" -eq 1 ] && { say "binaries updated. Restart the daemon to run the new build:  kintsugi stop && kintsugi init"; return; }
  stepper "$BIN_DIR"
}

main
