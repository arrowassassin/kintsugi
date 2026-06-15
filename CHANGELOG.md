# Changelog

All notable changes to Aegis are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **P0.1** — Cargo workspace scaffold with six crates (`aegis-core`,
  `aegis-daemon`, `aegis-intercept`, `aegis-cli`, `aegis-model`, `aegis-tui`).
  `aegis --version` runs.
- **P0.2** — `aegis-core` shared types (`ProposedCommand`, `Class`, `Decision`,
  `Verdict`) and an append-only, hash-chained SQLite event log (`EventLog` with
  `log_event`, `tail`, `count`, `verify_chain`). SHA-256 chain binds every field
  plus the predecessor hash; tampering and row deletion are detected.

- **P0.3** — `aegis-daemon`: a local-socket IPC server (`interprocess`,
  newline-delimited JSON) and a `Daemon` that records every proposal to the
  event log and returns a verdict. Phase 0 is a pure recorder (allow-all);
  Tier-1 rules plug into `Daemon::decide` in Phase 1. Integration tests cover a
  client round-trip and multi-command log chaining.

- **P0.4** — `aegis-shim`: the `$PATH` interception shim. Symlinked as `rm`,
  `git`, etc., it captures argv+cwd, consults the daemon, and on allow execs the
  real binary (Unix `exec`, so exit code, stdio, and signals are forwarded with
  perfect fidelity). Fail-open by default; `AEGIS_FAIL_CLOSED=1` to block when
  the daemon is down. Tests: real `rm` deletes + logs + exit 0, non-zero exit
  propagation, stdout forwarding, plus unit tests for name/path resolution.

- **P0.5** — `aegis-hook`: Claude Code `PreToolUse` hook bridge. Parses the hook
  JSON, records shell commands tagged `agent = "claude-code"`, and maps the
  verdict to Claude Code's permission protocol (allow→silent, deny→`deny`,
  hold→`ask`). Fail-open on malformed payloads, non-shell tools, or a down
  daemon. Adds `aegis_core::shell::split`, a quote-aware tokenizer.

- **P0.6** — `aegis-mcp`: the `aegis-exec` MCP server (hand-rolled JSON-RPC 2.0
  over stdio, no framework dependency). Exposes one tool that runs a shell
  command guarded + recorded by Aegis, tagged with the calling agent. Handles
  `initialize`, `tools/list`, `tools/call`, `ping`. Wiring documented in
  `docs/mcp.md`.

- **P0.7** — `aegis-cli`: `aegis init` (detect agents via config dirs, create
  `$PATH` shims, wire the Claude Code hook idempotently with a backup, start the
  daemon), `aegis status` (daemon/socket/log/chain health), and `aegis log` (a
  calm timeline — outcome words not just color, one reserved accent, `NO_COLOR`
  respected, designed empty state). Completes **Phase 0 — Recorder**.

- **P1.1** — `aegis-core::rules`: the Tier-1 deterministic rule engine.
  Classifies a command into Safe / Catastrophic / Ambiguous with no I/O and no
  model. Segments chained command lines (`;`, `&&`, `||`, `|`) honoring quotes
  and takes the worst class; catastrophic checks run first and broadly (rm -rf,
  force-push/history-rewrite, destructive SQL, infra teardown, disk writes,
  secret reads, curl|sh, fork bombs); strips `sudo`/`doas`/env prefixes so they
  cannot downgrade. Covered by unit tests, a ~70-command golden corpus with a
  zero-catastrophic-as-safe gate, and `proptest` invariants.

- **P1.2** — Decision mapping wired into the daemon. `Daemon::decide` now runs
  the Tier-1 rule engine for the configured `Mode` (default Attended:
  Safe→Allow, Catastrophic→Hold, Ambiguous→Hold; Unattended:
  Catastrophic/Ambiguous→Deny; Notify→Allow). Held commands pause and do not run
  across the shim, hook (→`ask`), and MCP adapters.

- **P1.3** — The hold card and one-key approval. On a Hold the shim prints a
  calm card (plain-English risk line, the raw command verbatim, `[a]llow /
  [d]eny / [r] always-allow-here`), reads one key from `/dev/tty` (falling back
  to stdin), and records the human's resolution. No answer ⇒ stays held (safe).
  IPC gains a `Resolve` request; the event log gains a persisted `reason` column.
- **P1.4** — Decision memory. `[r]` stores a per-repo always-allow keyed by the
  exact command hash; the daemon consults memory before the rules, so a
  remembered command auto-allows next time and is logged as `memory:allow`. The
  repo key is the nearest ancestor `.git` directory.

- **P1.5** — Policy files. `aegis-core::policy` parses `.aegis.toml` (mode +
  allow/deny rules with glob/prefix matching), merges global ← repo, and applies
  it to a verdict: `deny` escalates (Attended→Hold, Unattended→Deny), `allow`
  tames the ambiguous band but never downgrades a catastrophic block. The daemon
  loads the nearest `.aegis.toml` and global config (`AEGIS_CONFIG` override) per
  command. Documented in `docs/policy.md`.

- **P1.6** — Latency guard. Benchmark tests assert the deterministic rules path
  is microsecond-scale (~3µs/call) and a Safe-command round-trip through the
  daemon (classify + log + IPC) is sub-millisecond on a warm daemon (~350µs).
  The event log now runs SQLite with `synchronous=NORMAL` under WAL.

- **P1.7** — The 30-second demo. `scripts/demo.sh` runs the full flow
  self-contained (its own socket/log/shim): a safe command passes, `rm -rf` is
  held *before* it runs, you press `a`/`d`/`r`, and the tamper-evident timeline
  shows the result with an intact chain. Non-interactive via `DEMO_KEY`. A VHS
  tape (`scripts/demo.tape`) and capture instructions live in `docs/demo.md`.
  Completes **Phase 1 — Gate**.

- **Phase 2** — `aegis-model` real implementation. A warm Tier-2 `Scorer` kept in
  the daemon fills `summary` + `risk` for the ambiguous band and drives graduated
  unattended mode (`risk` vs per-repo `threshold`). `HeuristicScorer` is the
  default, dependency-free, always-available backend (and graceful-degradation
  path); `LlamaScorer` (feature `llama`) does real CPU GGUF inference via
  `llama.cpp`. Pinned+checksummed weight management with RAM-based 3B/1.5B
  auto-selection (feature `download` for the fetch — the only network egress).
  The hold card now shows the model summary and a risk meter. Catastrophic stays
  a hard floor regardless of score; Safe stays on the model-free fast path.
  Documented in `docs/model.md`.

- **Phase 3** — snapshots + `aegis undo`. Before an allowed destructive command,
  the daemon captures the paths it will touch (`snapshot::predict_paths`) into a
  content-addressed store using reflink CoW (`reflink-copy`) with a plain-copy
  fallback, and records a manifest in a new `snapshots` table. `aegis undo`
  restores the last action; `aegis undo --session` restores every not-yet-reverted
  snapshot. Scope is stated plainly: files only — not network calls or pushed
  commits. Safe commands are never snapshotted.

- **Phase 4** — FS-watcher backstop + `ratatui` timeline.
  - Backstop: `aegis watch <path>` watches recursively (`notify`) and records FS
    changes as `fs-watch` events **through the daemon's single writer** (new
    `Observe` IPC), so the hash chain is never raced. Keeps the timeline and undo
    complete for actions that bypassed interception.
  - TUI: `aegis tui` is a real, interactive `ratatui` app over the live event log
    — keyboard navigation (`j/k`, `g/G`), `/` filter, `enter` detail, `u` undo,
    `q` quit; live polling refresh; a designed empty state; a "terminal too
    small" notice; one reserved danger accent with words-not-color and `NO_COLOR`
    support; panic-safe teardown via `ratatui::init`/`restore`. Covered by
    state-transition tests and `TestBackend` render tests at several sizes.

### Changed
- Pinned all dependencies to latest stable. `rusqlite` held at 0.39 because 0.40
  pulls `libsqlite3-sys` 0.38 which needs the unstable `cfg_select!` feature.
