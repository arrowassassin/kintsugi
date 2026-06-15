# Changelog

All notable changes to Aegis are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### CLI & install
- **`aegis stop`** — stop the background daemon (the inverse of `aegis init`). The
  daemon writes its own PID file on startup; `stop` reads it and terminates it
  cleanly, idempotent when nothing's running.
- **Guided installer** — `install.sh` runs a short cross-OS stepper after
  installing: it wires your agents (`aegis init`) and *optionally* sets up a local
  model (installs `cmake` + a C/C++ toolchain for the detected OS, builds the
  llama engine, and downloads a Qwen GGUF from Hugging Face). Everything optional
  is skippable; the default install needs no model and no toolchain. Flags:
  `--with-model`, `--init`/`--no-init`, `--yes`.
- Trimmed README/site clutter (one looping demo instead of five stacked images;
  fewer duplicate install one-liners) so the surface reads simply.

### Security (multi-model review fixes)
- **Monotonic model influence restored (spine #2):** the Tier-2 model no longer
  downgrades a rules Deny→Allow for the unattended ambiguous band. Unattended
  ambiguous now denies/queues; auto-proceed is only via human allowlist
  (`.aegis.toml`/memory). The `risk < threshold → allow` graduated path is gone.
- **Shell-wrapper evasion closed:** `bash -c "rm -rf /"`, `find -exec`, `xargs`,
  and prefix launchers (`sudo`/`env`/`timeout`/`nohup`/`setsid`/`stdbuf`) are now
  recursively/transparently classified, so wrapped destructive payloads are
  Catastrophic instead of Ambiguous. `bash/sh/zsh/find/xargs` added to the shim.
- **Kill-switch bypass closed:** `resolve()` (shim hold card / raw `Resolve` IPC)
  now refuses Allow while the kill-switch is engaged, matching `resolve_pending()`.
- **Fail-closed for catastrophic:** when the daemon is unreachable, the shim/hook/
  MCP locally classify and block catastrophic commands even without
  `AEGIS_FAIL_CLOSED` (non-catastrophic still fails open).
- **Private IPC + data-at-rest:** the socket is `0600` in a `0700` dir (off the
  world-writable temp dir); the data dir is `0700` and `events.db` (+WAL/SHM)
  `0600`, protecting verbatim-logged commands that may contain secrets.

### Log: sessions, search/filter, redaction & purge
- **Per-CLI / per-session grouping**: events now carry an originating session id
  (Claude Code hook `session_id`; one session per MCP server process, overridable
  via a `session` tool arg; `$AEGIS_SESSION` for the shim). Stored as view
  metadata (not hashed), with a migration for older DBs.
- **Search & filter** on `aegis log`: `--agent`, `--session`, `--class`, `--grep`
  (literal substring), `--since`/`--before` (RFC3339 or `day|week|month|<N>d|<N>h`).
- **Delete, two ways** (the chain stays the source of truth):
  - `aegis redact <id|filters>` — append-only hide; the row and hash chain stay
    intact and verifiable. Redacted rows show as dim `⟨redacted⟩` placeholders
    (or hidden); refuses to redact everything without an id/filter.
  - `aegis purge --yes <filters>` — explicit hard erasure: delete rows, rebuild
    the chain over survivors, record an `audit:purge` marker. Never automatic;
    refuses without a filter or `--yes`.
- **TUI**: the risk gauge is now an auto-width, single-row meter (no full-width
  white block); the detail pane shows `session` and a `redacted` headline;
  redacted events drop out of the live timeline automatically.
- **TUI filtering & session column**: the `/` filter now understands structured
  tokens — `agent:<name>`, `session:<id>`, `since:<age>`, `before:<age>` (age =
  `30m`/`2h`/`3d`/`day`/`week`/`month`) — combinable with free text (AND). A
  short `session` column appears on wide terminals (full id stays in the detail
  pane), so no horizontal scroll is needed.

### Docs/site
- **Autoplaying cast** (`docs/img/cast.svg`, mirrored to `site/cast.svg`): one
  looping animation composed from the real captured frames (hold card → denied
  timeline → live TUI) via SMIL, so it animates as a plain `<img>` on the site
  and the README with no JS or external tooling. Built by `scripts/gen_cast_svg.py`.
  (A live Claude-driven GIF is a deliberate human capture — this sandbox blocks
  the destructive step of a nested agent and ships no video encoder.)
- **Fix clipped SVG frames**: the doc/site terminal "screenshots" sized their
  frame at 8.6 px/glyph, but the fallback monospace fonts advance wider, so the
  hold card's reason line and the TUI risk gauge overflowed the right border.
  Bumped `gen_svg.py` `CHARW` to a safe 9.3 and widened the committed SVGs to fit
  their real content (`scripts/fix_svg_width.py`, content-preserving).

### Agent coverage
- **Cursor CLI detection**: `aegis init` now recognizes `~/.cursor` and reports
  it as intercepted via the `aegis-exec` MCP server (verified: Cursor CLI runs in
  the terminal and speaks stdio MCP via `~/.cursor/mcp.json`). Joins the existing
  Claude Code / Codex CLI / Qwen Code / Gemini CLI detection.
- Docs/site now lead with the agent-agnostic story: the `$PATH` shim covers *any*
  tool or raw shell-out; MCP covers any MCP client; the Claude Code hook is one
  (best-UX) option, not a requirement. Added a per-agent MCP-config table to
  `docs/mcp.md` (Codex TOML vs. Cursor/Qwen/Gemini `mcpServers` JSON).

### Model
- **Bring-your-own model (`AEGIS_MODEL_FILE`)**: point the daemon at any local
  GGUF and it loads that one — no recompile, no pinned spec. The durable answer
  to "models keep releasing"; the pinned default is now just a sensible default.
- **Interactive model picker** (`scripts/pick-model.sh`, served at
  `…/pick-model.sh`): fetches a short, RAM-appropriate list of small instruct
  GGUF models from the Hugging Face API (query constrained to `filter=gguf`,
  text-generation, sized to detected RAM), downloads your choice, prints its
  SHA-256, and tells you the one env var to set. `install.sh --with-model` runs
  it after install. Aegis still ships model-free (heuristic scorer) by default.

### Security & hardening
- Review hardening (panel: 2 principal eng, 4 testers, 2 dev-users):
  - **Catastrophic hard floor** is now consistent: neither decision memory nor
    `.aegis.toml` policy can auto-downgrade a catastrophic command, and `[r]`
    never *remembers* a catastrophic (acts as allow-once). Only an in-the-moment
    human decision runs it.
  - **Hook**: a catastrophic hold maps to `deny` (not `ask`) so a one-click
    allow in Claude's UI can't bypass the Aegis snapshot; ambiguous still `ask`.
  - **`tee` removed from the safe-list** (it clobbers files); coreutils
    `truncate -s` is now catastrophic.
  - **Hash chain**: the read-modify-append runs inside a `BEGIN IMMEDIATE`
    transaction with a busy-timeout, so concurrent writers (CLI undo/panic while
    the daemon runs) serialize instead of forking the chain.
  - **IPC** frames are bounded (16 MiB) to stop an OOM/stall of the
    single-threaded daemon.
  - **Kill-switch** also blocks queue approvals.
  - **Shim** preserves argv[0] so multi-call binaries (busybox, gunzip) behave.
  - **MCP** in-band wait fails fast when the daemon is gone instead of polling a
    dead socket for the whole timeout.
  - Size/speed: release profile now `opt-level=s`, `lto=fat`, `strip`,
    `panic=abort` (panic hooks still run, TUI teardown safe) — ~30-50% smaller
    binaries. Hot-path cleanups in the classifier.


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

- **Phase 5** — launch hardening.
  - **Panic kill-switch:** `aegis panic` engages a flag the daemon checks *first*,
    instantly denying every command (even Safe); `aegis resume` clears it. Surfaced
    in `aegis status` and recorded in the log.
  - **`aegis init` polish:** `--print-path` (for `eval "$(aegis init --print-path)"`)
    and `AEGIS_DATA_DIR` support; scorer/kill-switch shown in status.
  - **Release workflow:** tag-triggered cross-platform builds (Linux/macOS/Windows)
    that publish `SHA256SUMS`; artifact signing is left as a documented human
    checkpoint (never touches secrets autonomously).

- **Approval queue** — held commands are now resolvable so an agent can proceed.
  The daemon enqueues every Hold; `aegis queue` lists them; `aegis approve <id>` /
  `aegis deny <id>` (and the TUI's `a`/`d` on a held row) resolve them, recording
  the human decision (and snapshotting on approve). The `aegis-exec` MCP tool can
  **wait in-band** for approval (`AEGIS_APPROVAL_TIMEOUT=<secs>`) and then run the
  command and return its output, so a queued command "goes through" once a human
  approves. A human may approve any class (deliberate override); the model never
  approves catastrophic; the kill-switch overrides the whole queue. Documented in
  `docs/queue.md`.

### Fixed
- IPC enum variants that wrapped a `String`/`Vec` failed over the wire (serde
  internally-tagged enums can't represent tagged newtypes around primitives or
  sequences). Converted them to struct variants; added over-the-socket tests.

### Changed
- Pinned all dependencies to latest stable. `rusqlite` held at 0.39 because 0.40
  pulls `libsqlite3-sys` 0.38 which needs the unstable `cfg_select!` feature.
