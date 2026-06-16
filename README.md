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

> **Assurance:** an adversarial stress + vulnerability assessment
> ([`docs/security-assessment.md`](docs/security-assessment.md)) measures it —
> **0 / 176** dangerous commands leak to Safe across a MITRE ATT&CK + GTFOBins
> corpus, **1.4M** fuzz inputs with no crash (a real heap-DoS was found and fixed),
> **0** known CVEs, **0** `unsafe`. Every figure is reproduced by a committed test.

## Why Aegis

- **It stops the mistake before it happens** — not a post-mortem. A deterministic
  rule engine (not an LLM rolling the dice) decides what's catastrophic, so the
  block is predictable and can't be "talked out of" by a clever prompt.
- **Works with every agent — and your shell.** Native pre-tool hooks for Claude
  Code, Cursor, Codex, Qwen, Gemini, Copilot, and OpenCode — or a raw `bash`
  script via the `$PATH` shim: one safety layer at the process level, not a
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

## How Aegis decides what's dangerous

The block decision is **deterministic and LLM-free** — fixed rules a human wrote,
never a model guessing (the model only ever *explains* and can only *add*
caution). What makes it trustworthy is *how* it reads a command:

- **It parses real shell structure, not text.** Aegis runs two passes and takes
  the **more cautious** verdict: a fast tokenizer, and a true **bash AST** parser
  ([`brush-parser`](https://crates.io/crates/brush-parser), pure-Rust). The AST
  pass sees what substring matching can't — commands hidden inside command
  substitution `$(…)`/backticks, here-documents fed to a shell, subshells, and
  `if`/`for`/`while` blocks. So `echo "$(rm -rf /)"` and `bash <<<'rm -rf /'` are
  caught, not waved through. This is the industry-standard approach: real
  AST analysis is what static analyzers (ShellCheck) and shell tooling use, and
  it avoids the documented failure mode of regex/substring scanners.
- **It fails toward caution.** A line the parser can't fully understand is **held**
  (AMBIGUOUS), never assumed safe. A parse failure can only *add* caution — it
  can never downgrade a catastrophic verdict. The hard rule, enforced by a golden
  test corpus, is **zero catastrophic-classified-as-safe**.
- **Catastrophic categories** map to the kinds of damage that matter — data
  destruction (`rm -rf`, `DROP TABLE`, `git push --force`, `terraform destroy`),
  disk/device writes (`dd`, `mkfs`), and secret reads (`.env`, `~/.ssh/…`) — in
  the spirit of the MITRE ATT&CK taxonomy and GTFOBins "this benign binary can do
  harm" catalog.

**Try it yourself — it runs nothing:**

```sh
aegis test "cd build && rm -rf ../dist"      # ⛔ CATASTROPHIC (rule: rm:recursive)
aegis test "git status"                      # ✓ SAFE
aegis test 'echo "$(git push --force)"'      # ⛔ — caught inside the substitution
```

`aegis test` shows the class, the rule that fired, what would happen, and the
exact commands Aegis sees inside your line — without executing, logging, or
contacting anything.

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
`aegis panic` / `resume`, `aegis update` (manual check + self-install from the
latest GitHub release; `--check` to only report).
The Tier-2 model, snapshots/undo, the TUI, the FS backstop, and the kill-switch
are documented in [`docs/`](docs/) (`model.md`, `policy.md`, `mcp.md`, `queue.md`,
`demo.md`).

## Works with any agent (and any shell)

Aegis is agent-agnostic. Protection lives at the process/PATH layer, not inside
any one tool, so anything that runs commands on your machine is covered:

Every major agent CLI now exposes a *pre-tool hook*: it runs a command before
executing a shell tool, hands it the proposed command, and reads back an
allow / deny / ask decision. Aegis wires that hook on each — the tightest,
in-band UX — so a held command pauses the agent itself, not just a `$PATH` shim:

| agent | how Aegis intercepts it |
|-------|--------------------------|
| **Claude Code** | native `PreToolUse` hook (`~/.claude/settings.json`) |
| **Qwen Code** | native `PreToolUse` hook (`~/.qwen/settings.json`) |
| **Gemini CLI** | native `BeforeTool` hook (`~/.gemini/settings.json`) |
| **GitHub Copilot CLI** | native `preToolUse` hook (`~/.copilot/hooks/aegis.json`, fail-closed) |
| **Cursor CLI** | native `beforeShellExecution` hook (`~/.cursor/hooks.json`) |
| **Codex CLI** | native `PreToolUse` hook (`~/.codex/config.toml`) |
| **OpenCode** | a bundled `tool.execute.before` plugin (`~/.config/opencode/plugin/aegis.js`) that bridges to the hook |
| any other MCP client | the `aegis-exec` MCP server (stdio) |
| **any tool or raw shell** (Aider, Continue, a `bash` script, a Makefile, you) | the `$PATH` shim — `aegis init` prints the `PATH` line to prepend |

One binary, `aegis-hook --agent <id>`, speaks each CLI's dialect; `aegis init`
detects installed agents (`~/.claude`, `~/.qwen`, `~/.gemini`, `~/.copilot`,
`~/.cursor`, `~/.codex`, `~/.config/opencode`), writes each one's hook config
idempotently (backing up anything it touches), and prints the shim `PATH` line
that guards every other shell-out. The caveat that keeps the guarantee honest:
hooks are an interception layer, not a kernel firewall — an agent in a
"yolo"/auto-approve mode, or a process that calls a binary by absolute path,
can bypass them, which is exactly why the FS-watcher backstop exists so
"nothing is unrecoverable." See [`docs/mcp.md`](docs/mcp.md) and
[`docs/policy.md`](docs/policy.md).

## When Aegis blocks something

A **catastrophic** command (an `rm -rf`, a `git push --force`, a `DROP TABLE`)
is denied to the agent — never silently allowed through the agent's own UI,
because that would run it with no snapshot. So the agent stops and you see why:

```
✗ rm:recursive — recursively deletes files and directories. Aegis blocked it;
  the agent will not run it. To run it yourself: `aegis run 50d56fd9` — it
  snapshots the affected files first (so `aegis undo` can roll them back) and
  confirms with a code typed at your terminal.
```

You then have three moves:

| you want to… | do this |
|--------------|---------|
| **run it yourself, reversibly** | `aegis run <id>` — snapshots the files, runs the exact command in its directory, undoable with `aegis undo`. Confirms with a code typed at your terminal, so the agent can't self-approve. (No id needed if only one is held.) |
| **let a waiting agent proceed** (shim / MCP) | `aegis approve <id>` — the waiting call runs it. (For a hook-blocked command, `aegis approve` only records the decision; use `aegis run` to actually run it.) |
| **drop it** | `aegis deny <id>` |
| **see what's held** | `aegis queue`, or `aegis tui` (press `a`) |

**Honest about reversibility:** `aegis run` snapshots the files a command is
predicted to touch. For *bounded* targets (a directory, named files) `aegis undo`
fully restores them. For *unbounded* ones — globs, `$VARS`, the filesystem root,
device nodes — a snapshot can't cover everything, and `aegis run` says so before
you confirm; the filesystem-watcher backstop is the net there. And the terminal
confirmation is a strong speed bump, not a sandbox: Aegis guards against agent
*mistakes*, not a malicious same-user process (see the honest guarantee above).

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
