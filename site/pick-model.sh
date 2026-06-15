#!/bin/sh
# Aegis model picker — fetch *compatible* GGUF options and install one.
#
#   curl -fsSL https://arrowassassin.github.io/aegis/pick-model.sh | sh
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

# --- Present the menu. -------------------------------------------------------
i=0
echo
printf '  %s\n' "compatible small instruct GGUF models (top by downloads):"
echo "$IDS" | while IFS= read -r id; do
  i=$((i+1)); printf '   \033[1;36m%2d\033[0m  %s\n' "$i" "$id"
done
echo

N="$(printf '%s\n' "$IDS" | grep -c .)"
if [ "$AUTO" -eq 1 ]; then
  CHOICE=1
else
  [ -t 0 ] || die "no TTY for the menu — re-run with --auto, or pass --query and pipe to 'sh -s -- --auto'"
  printf 'pick a number [1-%s] (or q to quit): ' "$N"
  read -r CHOICE </dev/tty || CHOICE=q
  case "$CHOICE" in q|Q|"") say "no model installed (Aegis still runs on the heuristic scorer)."; exit 0 ;; esac
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
