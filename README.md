# Aegis

### Let AI coding agents move fast — without letting them wreck your machine.

AI agents now run real shell commands on your computer: `rm -rf`, `git push
--force`, `DROP TABLE`, writes straight to disk. Almost always that's fine. The one
time it isn't — a hallucinated path, a prompt-injected instruction, a confident
wrong guess — there's no undo, and you find out after.

**Aegis is the seatbelt.** It sits between the agent and your system, catches the
dangerous command **before** it runs, explains it in one plain sentence, makes
destructive actions **reversible**, and keeps a tamper-evident record of everything
every agent did. Local-first: no cloud, no account, nothing leaves your machine.

**Website:** https://arrowassassin.github.io/aegis/ · **Docs:** [`docs/`](docs/)

![Aegis: a destructive command is held before it runs, denied, and lands on the tamper-evident timeline; then the live TUI](docs/img/cast.svg)

*Real Aegis output, looping: hold card → denied timeline → live TUI. (Static
frames in [`docs/img/`](docs/img/) if the animation doesn't play.)*

> **Security spine:** the decision to hold/deny a catastrophic command is made by
> deterministic **rules, never an LLM**. The raw command is always shown verbatim;
> the model only explains. The event log is append-only and hash-chained, and
> nothing leaves your machine. See [`CLAUDE.md`](CLAUDE.md) for the full rules.

## Why Aegis

- **It stops the mistake before it happens** — not a post-mortem. A deterministic
  rule engine (not an LLM rolling the dice) decides what's catastrophic, so the
  block is predictable and can't be "talked out of" by a clever prompt.
- **Works with every agent — and your shell.** Claude Code, Cursor, Codex, Qwen,
  Gemini, or a raw `bash` script: one safety layer at the process level, not a
  fragile per-tool plugin. `aegis init` wires them all in one command.
- **Reversible by default.** Aegis snapshots files before a destructive op, so
  `aegis undo` brings them back. The honest promise is *nothing unrecoverable* —
  a filesystem backstop catches even changes that slipped past interception.
- **Private and auditable.** No cloud, no telemetry, no account. Every command
  every agent ran lands on an append-only, **hash-chained** log you own — tamper
  with a past entry and verification breaks.
- **Calm until it must shout.** Safe commands fly through in well under a
  millisecond; Aegis only interrupts for the ones that can actually hurt you.

Runs on macOS, Linux, and Windows. Install is one command; it works immediately
with no model and no setup beyond `aegis init`.

## Status

All build phases are implemented (see
[`aegis-phase0-1-tasklist.md`](aegis-phase0-1-tasklist.md) and
[`aegis-phase2-5-designdoc.md`](aegis-phase2-5-designdoc.md)):

- **Phase 0 — Recorder:** agent-agnostic interception (`$PATH` shim + Claude Code
  hook + `aegis-exec` MCP server) recording every command to a tamper-evident,
  hash-chained SQLite log.
- **Phase 1 — Gate:** a deterministic rule engine that holds dangerous commands
  for one-key approval, with per-repo decision memory and `.aegis.toml` policy.
- **Phase 2 — Explain + score:** a warm Tier-2 scorer fills a plain-English
  summary and a risk score for the ambiguous band (heuristic by default; real CPU
  GGUF inference behind `--features llama`). Escalation-only — it never downgrades
  a rules decision.
- **Phase 3 — Undo:** snapshots before destructive ops (reflink CoW + copy
  fallback) and `aegis undo` / `aegis undo --session`.
- **Phase 4 — Recorder UI:** an FS-watcher backstop and a live `ratatui` timeline
  (`aegis tui`).
- **Phase 5 — Launch:** the panic kill-switch (`aegis panic` / `aegis resume`),
  `aegis init` polish, and a cross-platform release workflow.

## Crates

| crate | role |
|-------|------|
| `aegis-core` | shared types, rule engine, policy, decision memory, hash-chained event log |
| `aegis-daemon` | resident process: local IPC server + decision loop |
| `aegis-intercept` | the `$PATH` shim, Claude Code hook bridge, and `aegis-exec` MCP server |
| `aegis-cli` | the `aegis` binary: `init`, `status`, `stop`, `log`, `tui`, … |
| `aegis-model` | Tier-2 scorer: heuristic by default, real GGUF behind `--features llama` |
| `aegis-tui` | live `ratatui` timeline |

## Install

One line. It downloads the checksum-verified binaries (or builds from source if
your platform has none), then walks you through wiring your agents and an
**optional** local model — everything optional can be skipped:

```sh
curl -fsSL https://github.com/arrowassassin/aegis/releases/latest/download/install.sh | sh
```

Prefer Cargo? `cargo install --git https://github.com/arrowassassin/aegis aegis-cli aegis-daemon aegis-intercept`

That's it — Aegis works immediately with **no model** (an offline heuristic
scorer). The optional model just sharpens the plain-English summary and risk
score for ambiguous commands; the installer can set it up, or do it later (see
[`docs/model.md`](docs/model.md)).

Day-to-day: `aegis status`, `aegis tui` (live timeline), `aegis stop` (stop the
daemon — the inverse of `init`). Also: `aegis log`, `aegis undo [--session]`,
`aegis queue` / `approve <id>` / `deny <id>`, `aegis watch <path>`,
`aegis panic` / `resume`.
The Tier-2 model, snapshots/undo, the TUI, the FS backstop, and the kill-switch
are documented in [`docs/`](docs/) (`model.md`, `policy.md`, `mcp.md`, `queue.md`,
`demo.md`).

## Works with any agent (and any shell)

Aegis is agent-agnostic. Protection lives at the process/PATH layer, not inside
any one tool, so anything that runs commands on your machine is covered:

| agent | how Aegis intercepts it |
|-------|--------------------------|
| **Claude Code** | native `PreToolUse` hook (tightest UX) + `aegis-exec` MCP |
| **Cursor CLI**, **Codex CLI**, **Qwen Code**, **Gemini CLI** | the `aegis-exec` MCP server (stdio) — add it to the agent's MCP config |
| any other MCP client | the same `aegis-exec` MCP server |
| **any tool or raw shell** (Aider, Continue, a `bash` script, a Makefile, you) | the `$PATH` shim — `aegis init` prints the `PATH` line to prepend |

`aegis init` detects installed agents (`~/.claude`, `~/.codex`, `~/.cursor`,
`~/.qwen`, `~/.gemini`), wires the Claude Code hook, prints the MCP server command
for the rest, and prints the shim `PATH` line that guards every other shell-out.
The only caveat (consistent with the security spine): the shim is a `$PATH`
mechanism, not a kernel hook — a process that calls a binary by absolute path
bypasses it, which is exactly why the FS-watcher backstop exists so "nothing is
unrecoverable." See [`docs/mcp.md`](docs/mcp.md) and
[`docs/policy.md`](docs/policy.md).

### Claude Code plugin

This repo doubles as a Claude Code plugin marketplace. Install the binaries (see
above), then enable the plugin (which wires the hook + MCP server):

```sh
/plugin marketplace add arrowassassin/aegis
/plugin install aegis@aegis
```

The plugin is a thin wiring layer (`plugin/aegis/`); install the native binaries
with the one-liner above (they're not bundled). See
[`plugin/aegis/README.md`](plugin/aegis/README.md).

## Demo

See [`docs/demo.md`](docs/demo.md). The 30-second flow — an agent's `rm -rf` is
held *before* it runs, you deny it, and it lands on the tamper-evident timeline:

```sh
bash scripts/demo.sh            # interactive (press a/d/r at the hold card)
DEMO_KEY=d bash scripts/demo.sh # non-interactive
```

## Building & testing

```sh
cargo test            # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

MIT — see [`LICENSE`](LICENSE).
