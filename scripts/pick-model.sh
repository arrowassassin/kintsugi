#!/bin/sh
# Aegis model picker — fetch *compatible* GGUF options and install one.
#
#   curl -fsSL https://github.com/arrowassassin/aegis/releases/latest/download/pick-model.sh | sh
#
# Aegis runs fine with no model (the default heuristic scorer is offline and
# always available). This optional helper fetches a short, RAM-appropriate list
# of small instruct GGUF models from the Hugging Face API, lets you pick one,
# downloads it, prints its SHA-256, and tells you the one env var that points
# Aegis at it. Nothing here runs automatically and the daemon never calls it.
#
# Security note: a model you pick here is *your* choice — like AEGIS_MODEL_FILE,
# it is trusted because you selected it, and it bypasses the built-in checksum
# pin (which only guards the daemon's own `download` path). The SHA-256 is shown
# so you can record/pin it yourself.
#
# Options (after `| sh -s --`):
#   --auto              pick the top match for your RAM, no prompt
#   --query "<text>"    override the search (default: RAM-based, instruct GGUF)
#   --limit <N>         how many options to list (default: 12)
#   --dir <DIR>         where to save weights (default: $AEGIS_MODEL_DIR or data dir)
set -eu

HF="https://huggingface.co"
API="$HF/api"
LIMIT=12
AUTO=0
QUERY=""
DIR="${AEGIS_MODEL_DIR:-${AEGIS_DATA_DIR:-$HOME/.local/share/aegis}/models}"

# Curated "known good" GGUF repos — small, instruct-tuned, well-quantised, from
# publishers we've actually used. Listed in preference order; we pin Aegis's
# recommended model first and surface these at the top of the picker. When the
# Hugging Face search returns one of these IDs, it gets a ★ marker and (with
# --auto / no TTY) is selected ahead of the popularity ranking.
RECOMMENDED_4B="\
bartowski/Qwen3-4B-Instruct-2507-GGUF
lmstudio-community/Qwen3-4B-Instruct-2507-GGUF
MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF
Qwen/Qwen2.5-Coder-3B-Instruct-GGUF
bartowski/Qwen2.5-Coder-3B-Instruct-GGUF"

RECOMMENDED_SMALL="\
bartowski/Qwen2.5-1.5B-Instruct-GGUF
Qwen/Qwen2.5-1.5B-Instruct-GGUF
bartowski/Llama-3.2-1B-Instruct-GGUF"

say()  { printf '\033[1;32maegis\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33maegis\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31maegis: %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --auto)  AUTO=1 ;;
    --query) QUERY="${2:?--query needs text}"; shift ;;
    --limit) LIMIT="${2:?--limit needs a number}"; shift ;;
    --dir)   DIR="${2:?--dir needs a path}"; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

have curl || have wget || die "need curl or wget"
fetch() { if have curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }
fetch_to() { if have curl; then curl -fL --progress-bar "$1" -o "$2"; else wget -O "$2" "$1"; fi; }
enc() { printf '%s' "$1" | sed 's/ /%20/g'; }
sha256() {
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else echo ""; fi
}

# --- RAM → size budget. Mirrors select_spec() in crates/aegis-model. ----------
detect_ram_mb() {
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ {print int($2/1024); exit}' /proc/meminfo
  elif have sysctl; then
    b="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"; echo $(( b / 1048576 ))
  else echo 4096; fi
}

RAM="$(detect_ram_mb)"
if [ -z "$QUERY" ]; then
  # Set the search so only viable options come back: small, instruct, GGUF, and
  # sized to the machine (≥6 GB RAM → a 4B; otherwise a ~1.7B).
  if [ "$RAM" -ge 6000 ]; then QUERY="4B Instruct GGUF"; else QUERY="1.7B Instruct GGUF"; fi
fi
say "detected ~${RAM} MB RAM → searching: \"$QUERY\""

# --- Fetch candidates. Parameters constrain the result set to compatible models:
#     filter=gguf (only GGUF repos), pipeline_tag=text-generation, top by downloads.
URL="$API/models?search=$(enc "$QUERY")&filter=gguf&pipeline_tag=text-generation&sort=downloads&direction=-1&limit=$LIMIT"
RAW="$(fetch "$URL")" || die "could not reach the Hugging Face API"

# Parse ids (jq if present, else a tolerant grep) and keep instruct-style repos.
if have jq; then
  IDS="$(printf '%s' "$RAW" | jq -r '.[].id')"
else
  IDS="$(printf '%s' "$RAW" | grep -oE '"id":"[^"]+"' | sed 's/"id":"//;s/"$//')"
fi
IDS="$(printf '%s\n' "$IDS" | grep -iE 'instruct|chat|it' | head -n "$LIMIT" || true)"
[ -n "$IDS" ] || die "no compatible GGUF models came back — try --query \"<terms>\""

# Promote recommended publishers/repos to the front of the list. Anything that
# matches RECOMMENDED_* is moved to the top and marked with a ★, then the rest
# of the HF popularity ranking fills in.
if [ "$RAM" -ge 6000 ]; then RECOMMENDED="$RECOMMENDED_4B"; else RECOMMENDED="$RECOMMENDED_SMALL"; fi
PROMOTED=""; REMAINDER="$IDS"
for rec in $RECOMMENDED; do
  match="$(printf '%s\n' "$REMAINDER" | grep -Fx "$rec" || true)"
  if [ -n "$match" ]; then
    PROMOTED="${PROMOTED}${match}
"
    REMAINDER="$(printf '%s\n' "$REMAINDER" | grep -Fxv "$match" || true)"
  fi
done
IDS="$(printf '%s%s\n' "$PROMOTED" "$REMAINDER" | sed '/^$/d' | head -n "$LIMIT")"
RECOMMENDED_SET="$(printf '%s' "$PROMOTED" | sed '/^$/d')"

is_recommended() {
  printf '%s\n' "$RECOMMENDED_SET" | grep -Fxq "$1"
}

# --- Present the menu. -------------------------------------------------------
i=0
echo
printf '  %s\n' "compatible small instruct GGUF models (★ = recommended):"
echo "$IDS" | while IFS= read -r id; do
  i=$((i+1))
  if is_recommended "$id"; then
    printf '   \033[1;33m%2d ★\033[0m %s\n' "$i" "$id"
  else
    printf '   \033[1;36m%2d  \033[0m %s\n' "$i" "$id"
  fi
done
echo

N="$(printf '%s\n' "$IDS" | grep -c .)"
# Decide interactivity. We can prompt as long as the controlling terminal is
# readable — even when stdin is a pipe (the `curl | sh` install path), /dev/tty
# is still open. If even /dev/tty isn't available and the caller didn't pass
# --auto, we fall back to the top recommendation silently rather than dying:
# the user already asked for "set up a model" in install.sh, dying mid-flow on
# the second step is the user-hostile behaviour we're trying to remove.
if [ "$AUTO" -eq 1 ] || [ ! -r /dev/tty ]; then
  CHOICE=1
  [ "$AUTO" -eq 1 ] || say "non-interactive shell — auto-selecting the top recommendation."
else
  printf 'pick a number [1-%s] (default 1, q to quit): ' "$N"
  read -r CHOICE </dev/tty || CHOICE=""
  [ -z "$CHOICE" ] && CHOICE=1
  case "$CHOICE" in q|Q) say "no model installed (Aegis still runs on the heuristic scorer)."; exit 0 ;; esac
  case "$CHOICE" in *[!0-9]*) die "not a number: $CHOICE" ;; esac
  { [ "$CHOICE" -ge 1 ] && [ "$CHOICE" -le "$N" ]; } || die "out of range: $CHOICE"
fi
REPO="$(printf '%s\n' "$IDS" | sed -n "${CHOICE}p")"
[ -n "$REPO" ] || die "could not resolve choice $CHOICE"
say "selected: $REPO"

# --- Find the right single-file GGUF (prefer Q4_K_M) in the repo. ------------
DET="$(fetch "$API/models/$REPO")" || die "could not read repo metadata for $REPO"
if have jq; then
  FILES="$(printf '%s' "$DET" | jq -r '.siblings[].rfilename')"
else
  FILES="$(printf '%s' "$DET" | grep -oE '"rfilename":"[^"]+"' | sed 's/"rfilename":"//;s/"$//')"
fi
GGUF="$(printf '%s\n' "$FILES" | grep -iE '\.gguf$' | grep -ivE 'mmproj|split|-of-' || true)"
FILE="$(printf '%s\n' "$GGUF" | grep -iE 'q4_k_m' | head -n1)"
[ -n "$FILE" ] || FILE="$(printf '%s\n' "$GGUF" | grep -iE 'q4|q5' | head -n1)"
[ -n "$FILE" ] || FILE="$(printf '%s\n' "$GGUF" | head -n1)"
[ -n "$FILE" ] || die "no single-file GGUF found in $REPO (it may be split into shards)"

# --- Download + checksum. ----------------------------------------------------
mkdir -p "$DIR"
DEST="$DIR/$(basename "$FILE")"
say "downloading $FILE → $DEST"
fetch_to "$HF/$REPO/resolve/main/$FILE?download=true" "$DEST" || die "download failed"
SUM="$(sha256 "$DEST")"
[ -n "$SUM" ] && say "sha256  $SUM"

echo
say "done. point Aegis at it (add to your shell profile):"
printf '   export AEGIS_MODEL_FILE="%s"\n' "$DEST"
echo "  then rebuild/run the daemon with --features llama, or restart it if already built."
