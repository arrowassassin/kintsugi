#!/usr/bin/env bash
# Kintsugi 30-second demo: an agent proposes `rm -rf`, Kintsugi holds it, you decide.
#
# Runs fully self-contained in a temp dir (its own socket, log, and shim dir) so
# it never touches your real config. Pass a key non-interactively with:
#     DEMO_KEY=d scripts/demo.sh      # deny (default)
#     DEMO_KEY=a scripts/demo.sh      # allow once
# Omit DEMO_KEY to type the answer yourself (best for recording a GIF).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

echo "▸ building kintsugi…"
cargo build --quiet

BIN="$ROOT/target/debug"
REALRM="$(command -v rm)"   # capture the real rm before we shim it
WORK="$(mktemp -d)"

export KINTSUGI_SOCKET="$WORK/run/kintsugi.sock"
export KINTSUGI_DB="$WORK/data/events.db"
export KINTSUGI_CONFIG="$WORK/config.toml"   # empty → defaults
mkdir -p "$WORK/run" "$WORK/data"

# Start the daemon.
"$BIN/kintsugi-daemon" >/dev/null 2>&1 &
DAEMON_PID=$!
# Use the real rm in cleanup (PATH gets a shimmed rm below).
trap 'kill $DAEMON_PID 2>/dev/null || true; "$REALRM" -rf "$WORK"' EXIT
for _ in $(seq 1 50); do "$BIN/kintsugi" status >/dev/null 2>&1 && break; sleep 0.05; done

# Wire a $PATH shim for rm (what a raw shell-out would hit).
SHIMS="$WORK/shims"
mkdir -p "$SHIMS"
ln -sf "$BIN/kintsugi-shim" "$SHIMS/rm"
export PATH="$SHIMS:$PATH"

# A precious directory an agent is about to wipe.
PROJECT="$WORK/project"
mkdir -p "$PROJECT/src"
echo "the only copy" > "$PROJECT/src/important.txt"

echo
echo "▸ a safe command passes straight through:"
( cd "$PROJECT" && ls src ) || true

echo
echo "▸ the agent now runs:  rm -rf $PROJECT/src"
echo "  Kintsugi intercepts it BEFORE it executes and holds it."
echo

KEY="${DEMO_KEY-}"
if [ -n "$KEY" ]; then
  printf '%s\n' "$KEY" | ( cd "$PROJECT" && rm -rf src ) || true
else
  ( cd "$PROJECT" && rm -rf src ) || true   # type a/d/r at the prompt
fi

echo
if [ -e "$PROJECT/src/important.txt" ]; then
  echo "✓ the file still exists — the deletion was held/denied:"
else
  echo "• the file was deleted — you allowed it:"
fi
ls "$PROJECT/src" 2>/dev/null || echo "  (src is gone)"

echo
echo "▸ everything is on the tamper-evident timeline:"
"$BIN/kintsugi" log

echo
echo "▸ and the audit chain verifies:"
"$BIN/kintsugi" status | sed -n 's/^/  /p'
