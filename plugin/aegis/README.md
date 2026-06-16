# Kintsugi — Claude Code plugin

This plugin wires Claude Code to Kintsugi. It is a thin **wiring layer**: it does not
ship the Kintsugi binaries. Install those first (they're native Rust + a resident
daemon, so they belong on a real package manager — signable and checksummed):

```sh
cargo install kintsugi           # or: brew install kintsugi   (when published)
kintsugi init                    # starts the daemon and is otherwise idempotent
```

Then enable the plugin:

```
/plugin marketplace add arrowassassin/kintsugi
/plugin install kintsugi@kintsugi
```

## What it wires

- **PreToolUse hook → `kintsugi-hook`**: every `Bash` tool call is classified before
  it runs; catastrophic/ambiguous commands are held (mapped to Claude Code's
  `ask`), and everything is recorded.
- **MCP server `kintsugi-exec` → `kintsugi-mcp`**: agents can run shell commands
  *through* Kintsugi (guarded + recorded + reversible) instead of shelling out raw.

Both fail **open** if the daemon isn't running (a command runs unguarded with a
warning) — set `KINTSUGI_FAIL_CLOSED=1` to block instead. Start/keep the daemon with
`kintsugi init`.

## Why binaries aren't bundled

`/plugin install` fetches a directory of config; it doesn't compile native code or
keep a daemon alive. Keeping the binaries on `cargo`/Homebrew means they're
versioned, signed, and updated through the normal channel, while this plugin
stays a tiny, auditable manifest. (A future self-contained variant could bundle
per-OS prebuilt binaries under `bin/` and point the hook/MCP at
`${CLAUDE_PLUGIN_ROOT}`.)

## Commands you'll still use from the terminal

`kintsugi status` · `kintsugi log` · `kintsugi tui` · `kintsugi queue` / `approve <id>` ·
`kintsugi undo` · `kintsugi panic` / `resume`.
