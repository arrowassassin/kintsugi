<p align="center">
  <img src="https://kintsugi.tools/logo.svg" alt="Kintsugi" width="420" />
</p>

# Kintsugi

### Let AI agents — and your team — move fast, without wrecking the machine.

*A safety net for every command on your box: AI agents are caught before they do
damage; the humans (DBAs, operators) get a tamper-evident audit trail with
one-command undo.*

AI agents now run real shell commands on your computer: `rm -rf`, `git push
--force`, `DROP TABLE`, writes straight to disk. Almost always that's fine. The one
time it isn't — a hallucinated path, a prompt-injected instruction, a confident
wrong guess — there's no undo, and you find out after.

**Kintsugi is the seatbelt.** It sits between the agent and your system, catches the
dangerous command **before** it runs, explains it in one plain sentence, makes
destructive actions **reversible**, and keeps a tamper-evident record of everything
every agent did. Local-first: no cloud, no account, nothing leaves your machine.

**Website:** https://kintsugi.tools/ · **Docs:** [`docs/`](docs/)

![Kintsugi: a destructive command is held before it runs, denied, and lands on the tamper-evident timeline; then the live TUI](https://kintsugi.tools/cast.svg)

*Real Kintsugi output, looping: hold card → denied timeline → live TUI. (Static
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

## Why Kintsugi

- **It stops the mistake before it happens** — not a post-mortem. A deterministic
  rule engine (not an LLM rolling the dice) decides what's catastrophic, so the
  block is predictable and can't be "talked out of" by a clever prompt.
- **Works with every agent — and your shell.** Native pre-tool hooks for Claude
  Code, Cursor, Codex, Qwen, Gemini, Copilot, OpenCode, and Google Antigravity —
  or a raw `bash` script via the `$PATH` shim: one safety layer at the process
  level, not a fragile per-tool plugin. `kintsugi init` wires them all in one command.
- **Reversible by default.** Kintsugi snapshots files before a destructive op, so
  `kintsugi undo` brings them back. The honest promise is *nothing unrecoverable* —
  a filesystem backstop catches even changes that slipped past interception.
- **Private and auditable.** No cloud, no telemetry, no account. Every command
  every agent ran lands on an append-only, **hash-chained** log you own — tamper
  with a past entry and verification breaks.
- **Calm until it must shout.** Safe commands fly through in well under a
  millisecond; Kintsugi only interrupts for the ones that can actually hurt you.

Runs on macOS, Linux, and Windows. Install is one command; it works immediately
with no model and no setup beyond `kintsugi init`.

## How Kintsugi decides what's dangerous

The block decision is **deterministic and LLM-free** — fixed rules a human wrote,
never a model guessing (the model only ever *explains* and can only *add*
caution). What makes it trustworthy is *how* it reads a command:

- **It parses real shell structure, not text.** Kintsugi runs two passes and takes
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
kintsugi test "cd build && rm -rf ../dist"      # ⛔ CATASTROPHIC (rule: rm:recursive)
kintsugi test "git status"                      # ✓ SAFE
kintsugi test 'echo "$(git push --force)"'      # ⛔ — caught inside the substitution
```

`kintsugi test` shows the class, the rule that fired, what would happen, and the
exact commands Kintsugi sees inside your line — without executing, logging, or
contacting anything.

**See what it would have caught in your own work** — `kintsugi dry-run` classifies
your recent shell history (or `--file` / piped stdin), running nothing:

```sh
kintsugi dry-run                  # scan recent shell history
history | kintsugi dry-run        # or pipe commands in
```

**Guard an agent even in auto-approve mode** — `kintsugi guard` forces the shim
onto the agent's PATH so its shell-outs hit the gate even if it skips its hook:

```sh
kintsugi guard claude             # launch an agent, guarded
kintsugi guard -- npm run dev      # or guard any command
```

And `kintsugi limits` prints the honest threat scope — what Kintsugi can and
can't protect — because a safety tool that names its blind spots is one you can
trust.

## Status

All build phases are implemented (see
[`kintsugi-phase0-1-tasklist.md`](kintsugi-phase0-1-tasklist.md) and
[`kintsugi-phase2-5-designdoc.md`](kintsugi-phase2-5-designdoc.md)):

- **Phase 0 — Recorder:** agent-agnostic interception (`$PATH` shim + Claude Code
  hook + `kintsugi-exec` MCP server) recording every command to a tamper-evident,
  hash-chained SQLite log.
- **Phase 1 — Gate:** a deterministic rule engine that holds dangerous commands
  for one-key approval, with per-repo decision memory and `.kintsugi.toml` policy.
- **Phase 2 — Explain + score:** a warm Tier-2 scorer fills a plain-English
  summary and a risk score for the ambiguous band (heuristic by default; real CPU
  GGUF inference behind `--features llama`). Escalation-only — it never downgrades
  a rules decision.
- **Phase 3 — Undo:** snapshots before destructive ops (reflink CoW + copy
  fallback) and `kintsugi undo` / `kintsugi undo --session`.
- **Phase 4 — Recorder UI:** an FS-watcher backstop and a live `ratatui` timeline
  (`kintsugi tui`).
- **Phase 5 — Launch:** the panic kill-switch (`kintsugi panic` / `kintsugi resume`),
  `kintsugi init` polish, and a cross-platform release workflow.

## Enterprise: admin lock, passive recorder, and the control-room TUI

`kintsugi init` sets up the **personal posture** by default — just the gate plus
reversible undo, nothing to administer. On a shared or production host, run
`kintsugi init --enterprise` for the **managed posture**, which adds the controls
below:

- **Password-locked settings + "password to stop."** `kintsugi admin provision`
  seals the settings behind an admin password (argon2id verifier +
  XChaCha20-Poly1305, with a one-time recovery key). Once locked, **stopping,
  unhooking, or disabling Kintsugi requires the password**, enforced *daemon-side*
  via a challenge-response (the password never crosses the socket) with
  **brute-force lockout** — an AI agent or a normal user can't quietly turn it off,
  and a hammering script gets locked out. The settings (`recording`, `autostart`,
  `enforcement`, `fail-closed`, `require-password-to-stop`) are tightening-only
  controls — none can loosen the catastrophic floor — and are managed from the TUI
  settings panel when unlocked. Honest scope: this defeats an agent/non-root user
  and turns a forced shutdown into a logged, recoverable event — it does **not**
  stop root (see the threat matrix in
  [`kintsugi-admin-recorder-design.md`](kintsugi-admin-recorder-design.md)).
- **Auto-restart watchdog + fail-closed.** `kintsugi service install` runs the
  daemon under systemd / launchd with restart-always, so a `kill`/`pkill` relaunches
  it within seconds; disabling the watchdog is itself password-gated. With
  fail-closed set, an unreachable daemon **blocks** rather than runs unguarded — so
  killing the daemon can't be used to open the gate.
- **Passive session recording + recoverer (no AI agent).** `kintsugi record install`
  prints a bash/zsh preexec hook (or `--write ~/.bashrc` installs it as an
  idempotent, managed block) so **every command a human runs** lands on the same
  tamper-evident, classified audit log — for DBA/operator compliance. It blocks
  nothing, spools across daemon restarts, and redacts command-line secrets before
  hashing. Because the hook fires *before* the command, Kintsugi **snapshots
  destructive human commands just-in-time**, so `kintsugi undo` can roll back a
  person's destructive *filesystem* command — `rm -rf`, a clobbering overwrite, a
  bad `mv` — the same way it rolls back an agent's. (It's a filesystem recoverer:
  in-database `DROP`/`TRUNCATE`/DML aren't files, so use your database's PITR /
  backups for those; and only interactive bash/zsh sessions are captured.)
  `kintsugi report` lists the destructive commands for review.
- **A real control-room TUI.** `kintsugi tui` opens an animated, branded terminal
  app: tabbed **Timeline / Audit / Recorder** views over the live log, a vitals
  strip, one-key approve/deny/undo, a password login when locked, and an in-app
  settings panel — everything managed from one screen.
- **A desktop Control Room.** For a point-and-click surface, the **Kintsugi
  Control Room** is a native desktop app (macOS / Windows / Linux) that runs
  in-process with the engine — same live log, no extra daemon. It adds a
  first-launch **setup wizard** (password → optional model download → initialize),
  live **Timeline / Held / Audit / Recorder** screens with a details drawer and
  toast notifications, a **hook panel** that shows exactly which agent CLIs are
  wired (with per-agent enable/disable and a refresh), live **Hugging Face model
  search + download**, real settings toggles, password-gated uninstall, and a
  **system-tray status** indicator (click to open). See
  [`installing the desktop app`](#install) below.

## Crates

| crate | role |
|-------|------|
| `kintsugi-core` | shared types, rule engine, policy, decision memory, hash-chained event log |
| `kintsugi-daemon` | resident process: local IPC server + decision loop |
| `kintsugi-intercept` | the `$PATH` shim, Claude Code hook bridge, and `kintsugi-exec` MCP server |
| `kintsugi` | the `kintsugi` binary: `init`, `status`, `stop`, `log`, `tui`, … |
| `kintsugi-model` | Tier-2 scorer: heuristic by default, real GGUF behind `--features llama` |
| `kintsugi-tui` | live `ratatui` timeline |
| `kintsugi-app` | data-binding layer behind the desktop Control Room (shared with the GUI) |
| `desktop-dx/` | the Dioxus desktop **Control Room** app (separate workspace; ships `.dmg`/`.msi`/`.deb`) |

## Install

One line. It downloads the checksum-verified binaries (or builds from source if
your platform has none), then walks you through wiring your agents and an
**optional** local model — everything optional can be skipped:

```sh
curl -fsSL https://kintsugi.tools/install.sh | sh
```

Prefer Cargo? `cargo install kintsugi` installs all five CLI binaries; then
`kintsugi init` finishes the job — alongside wiring your agents, it **registers
the desktop Control Room app, offering to build it if it isn't installed yet**
(skipped on headless hosts or with `--no-desktop`). So `cargo install kintsugi &&
kintsugi init` gets you everything, GUI included.

**Prefer a packaged installer?** Grab one for your platform from the
[latest release](https://github.com/arrowassassin/kintsugi/releases/latest):
**`.dmg`** (macOS), **`.msi`** (Windows), **`.deb` / `.AppImage`** (Linux) — it
registers like any other app and first launch runs the setup wizard (password →
optional model → initialize). To (re)register a desktop build by hand,
`kintsugi install-desktop` writes the macOS `.app` bundle, the Linux `.desktop`
entry + icons, or the Windows Start-menu shortcut; `kintsugi uninstall`
(password-gated) removes everything. Keep it current from the app itself —
**Settings → Check for updates** runs the same flow as `kintsugi update`.

That's it — Kintsugi works immediately with **no model** (an offline heuristic
scorer). The optional model just sharpens the plain-English summary and risk
score for ambiguous commands; the curl installer can set it up, or do it later
with `kintsugi model install` (builds the engine + downloads a model — the path
`cargo install` users take). Swap to any local GGUF anytime with
`kintsugi model use <path>` — no Kintsugi update needed. See
[`docs/model.md`](docs/model.md).

Day-to-day: `kintsugi status`, `kintsugi tui` (live timeline), `kintsugi stop` (stop the
daemon — the inverse of `init`). Also: `kintsugi log`, `kintsugi undo [--session]`,
`kintsugi queue` / `approve <id>` / `deny <id>`, `kintsugi watch <path>`,
`kintsugi hook` (list / enable / disable the per-agent CLI hooks),
`kintsugi panic` / `resume`, `kintsugi update` (manual check + self-install from the
latest GitHub release; `--check` to only report), and `kintsugi install-desktop` /
`kintsugi uninstall` (password-gated) for the desktop app.
Manage the optional model with `kintsugi model`: `status` (what's loaded and
why), `use <path>` (point at any GGUF), `pick` (download one), `install` (build
the engine + download — for `cargo install` users), `remove` (back to heuristic).
The Tier-2 model, snapshots/undo, the TUI, the FS backstop, and the kill-switch
are documented in [`docs/`](docs/) (`model.md`, `policy.md`, `mcp.md`, `queue.md`,
`demo.md`).

## Works with any agent (and any shell)

Kintsugi is agent-agnostic. Protection lives at the process/PATH layer, not inside
any one tool, so anything that runs commands on your machine is covered:

Every major agent CLI now exposes a *pre-tool hook*: it runs a command before
executing a shell tool, hands it the proposed command, and reads back an
allow / deny / ask decision. Kintsugi wires that hook on each — the tightest,
in-band UX — so a held command pauses the agent itself, not just a `$PATH` shim:

| agent | how Kintsugi intercepts it |
|-------|--------------------------|
| **Claude Code** | native `PreToolUse` hook (`~/.claude/settings.json`) |
| **Qwen Code** | native `PreToolUse` hook (`~/.qwen/settings.json`) |
| **Gemini CLI** | native `BeforeTool` hook (`~/.gemini/settings.json`) |
| **GitHub Copilot CLI** | native `preToolUse` hook (`~/.copilot/hooks/kintsugi.json`, fail-closed) |
| **Cursor CLI** | native `beforeShellExecution` hook (`~/.cursor/hooks.json`) |
| **Codex CLI** | native `PreToolUse` hook (`~/.codex/config.toml`) |
| **OpenCode** | a bundled `tool.execute.before` plugin (`~/.config/opencode/plugin/kintsugi.js`) that bridges to the hook |
| **Google Antigravity** | native `PreToolUse` plugin hook (`~/.gemini/antigravity-cli/plugins/kintsugi/hooks.json`), or the MCP server in `~/.gemini/config/mcp_config.json` |
| any other MCP client | the `kintsugi-exec` MCP server (stdio) |
| **any tool or raw shell** (Aider, Continue, a `bash` script, a Makefile, you) | the `$PATH` shim — `kintsugi init` prints the `PATH` line to prepend |

One binary, `kintsugi-hook --agent <id>`, speaks each CLI's dialect; `kintsugi init`
detects installed agents (`~/.claude`, `~/.qwen`, `~/.gemini`, `~/.copilot`,
`~/.cursor`, `~/.codex`, `~/.config/opencode`), writes each one's hook config
idempotently (backing up anything it touches), and prints the shim `PATH` line
that guards every other shell-out. The caveat that keeps the guarantee honest:
hooks are an interception layer, not a kernel firewall — an agent in a
"yolo"/auto-approve mode, or a process that calls a binary by absolute path,
can bypass them, which is exactly why the FS-watcher backstop exists so
"nothing is unrecoverable." See [`docs/mcp.md`](docs/mcp.md) and
[`docs/policy.md`](docs/policy.md).

## When Kintsugi blocks something

A **catastrophic** command (an `rm -rf`, a `git push --force`, a `DROP TABLE`)
is denied to the agent — never silently allowed through the agent's own UI,
because that would run it with no snapshot. So the agent stops and you see why:

```
✗ rm:recursive — recursively deletes files and directories. Kintsugi blocked it;
  the agent will not run it. To run it yourself: `kintsugi run 50d56fd9` — it
  snapshots the affected files first (so `kintsugi undo` can roll them back) and
  confirms with a code typed at your terminal.
```

You then have three moves:

| you want to… | do this |
|--------------|---------|
| **run it yourself, reversibly** | `kintsugi run <id>` — snapshots the files, runs the exact command in its directory, undoable with `kintsugi undo`. Confirms with a code typed at your terminal, so the agent can't self-approve. (No id needed if only one is held.) |
| **let a waiting agent proceed** (shim / MCP) | `kintsugi approve <id>` — the waiting call runs it. (For a hook-blocked command, `kintsugi approve` only records the decision; use `kintsugi run` to actually run it.) |
| **drop it** | `kintsugi deny <id>` |
| **see what's held** | `kintsugi queue`, or `kintsugi tui` (press `a`) |

**Honest about reversibility:** `kintsugi run` snapshots the files a command is
predicted to touch. For *bounded* targets (a directory, named files) `kintsugi undo`
fully restores them. For *unbounded* ones — globs, `$VARS`, the filesystem root,
device nodes — a snapshot can't cover everything, and `kintsugi run` says so before
you confirm; the filesystem-watcher backstop is the net there. And the terminal
confirmation is a strong speed bump, not a sandbox: Kintsugi guards against agent
*mistakes*, not a malicious same-user process (see the honest guarantee above).

### Claude Code plugin

This repo doubles as a Claude Code plugin marketplace. Install the binaries (see
above), then enable the plugin (which wires the hook + MCP server):

```sh
/plugin marketplace add arrowassassin/kintsugi
/plugin install kintsugi@kintsugi
```

The plugin is a thin wiring layer (`plugin/kintsugi/`); install the native binaries
with the one-liner above (they're not bundled). See
[`plugin/kintsugi/README.md`](plugin/kintsugi/README.md).

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
