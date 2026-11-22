#!/bin/sh
# Paper installer entry point — short URL:
#   curl -fsSL https://kintsugi.tools/paper.sh | sh
#
# Fetches the official cargo-dist installer from the latest GitHub release and
# runs it. The installer verifies the downloaded binary against SHA-256 sums
# shipped in the release manifest.
set -eu

RELEASE_BASE="https://github.com/arrowassassin/paperscope/releases/latest/download"
INSTALLER="paperscope-installer.sh"

tmp="$(mktemp "${TMPDIR:-/tmp}/paper-installer.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$RELEASE_BASE/$INSTALLER" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp" "$RELEASE_BASE/$INSTALLER"
else
    echo "paper: need curl or wget to install" >&2
    exit 1
fi

sh "$tmp" "$@"
