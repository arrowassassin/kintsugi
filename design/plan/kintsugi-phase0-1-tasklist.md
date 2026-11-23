# Kintsugi — Phase 0 & 1 build task list (hand this to Claude Code)

Goal of these two phases: a working, agent-agnostic recorder that logs every command from
Claude Code / Qwen / Codex CLIs, then a deterministic gate that holds dangerous commands for
one-key approval. After Phase 1 you have a real, demoable product.

Build with Claude Code. Keep a `CLAUDE.md` at the repo root with the invariants below so the
agent doesn't drift.

---

## Invariants (put these in CLAUDE.md)

- Rust workspace, edition 2021+. Single shipped binary `kintsugi` plus a resident daemon.
- The **block decision is deterministic rules only**. The LLM never decides allow/deny for
  catastrophic ops; it only summarizes and scores the ambiguous band. Model influence is
  escalation-only.
- Local-first: no network calls except optional model download (pinned + checksummed) and
  optional user-configured LLM endpoint. Never phone home.
- The raw command is always preserved and shown verbatim.
- Cross-platform: macOS, Linux, Windows. Prefer portable crates; isolate OS-specific code.
- Every command event is appended to a hash-chained log; never mutate past events.

## Workspace layout

```
kintsugi/
  Cargo.toml                 # [workspace]
  CLAUDE.md
  crates/
    kintsugi-core/              # types, rule engine, policy, event log (no I/O side effects)
    kintsugi-daemon/            # resident process, IPC server, decision loop
    kintsugi-intercept/         # hook adapter, MCP server, $PATH shim
    kintsugi-cli/               # `kintsugi` binary: init, status, log, approve, undo (stub)
    kintsugi-model/             # Tier-2 model wrapper (stub in P0/P1; real in P2)
    kintsugi-tui/               # ratatui UI (P4; create empty now)
```

## Shared types (kintsugi-core) — define first

```rust
pub struct ProposedCommand {
    pub id: Uuid,
    pub ts: OffsetDateTime,
    pub agent: String,        // "claude-code" | "qwen" | "codex" | "shim" | ...
    pub cwd: PathBuf,
    pub argv: Vec<String>,    // never lose the raw command
    pub raw: String,
}

pub enum Class { Safe, Catastrophic, Ambiguous }

pub enum Decision { Allow, Deny, Hold }   // Hold = wait for human

pub struct Verdict {
    pub class: Class,
    pub decision: Decision,
    pub tier: u8,             // 1 = rules, 2 = model
    pub reason: String,       // rule name or model reason
    pub summary: Option<String>,  // filled by model in P2
    pub risk: Option<u8>,         // 0..=100, model in P2
}
```

## IPC contract (daemon <-> interception)

- Transport: Unix domain socket (`$XDG_RUNTIME_DIR/kintsugi.sock`) / Windows named pipe.
- Request: JSON `ProposedCommand`. Response: JSON `Verdict`.
- Interception **blocks** on the response, then allows/denies execution accordingly.

## Interception adapter contract (kintsugi-intercept)

One trait, three impls. Each turns an agent's proposed command into a `ProposedCommand`,
sends it to the daemon, and enforces the `Verdict`.

```rust
pub trait Adapter {
    fn name(&self) -> &'static str;
    fn run(&self) -> anyhow::Result<()>;   // long-running for hook/MCP; one-shot for shim
}
```

---

## PHASE 0 — Recorder

P0.1  Scaffold the workspace and the six crates; `kintsugi --version` runs.
  - Accept: `cargo build` succeeds; `kintsugi` prints version.

P0.2  `kintsugi-core`: define the shared types above + an append-only SQLite event log
      (`rusqlite`) with `prev_hash`/`hash` chaining. `log_event()` + `tail(n)`.
  - Accept: unit test writes 3 events, verifies hash chain links and tamper detection.

P0.3  `kintsugi-daemon`: start a socket server that accepts `ProposedCommand`, logs it, and
      returns `Verdict{ class: Safe, decision: Allow, tier: 1 }` for everything (no rules yet).
  - Accept: a test client sends a command, gets Allow, event appears in the log.

P0.4  `kintsugi-intercept` shim: a binary that, when symlinked as `rm`/`git`/etc. on a temp
      `$PATH`, captures argv+cwd, sends to daemon, then (on Allow) execs the *real* binary
      transparently (correct exit code, stdout/stderr, signals).
  - Accept: `PATH=shimdir:$PATH rm tmpfile` deletes the file AND logs the event; exit code preserved.

P0.5  `kintsugi-intercept` Claude Code hook adapter: register an Kintsugi hook so Claude Code sends
      proposed shell commands to the daemon before running them. (Use Claude Code's current
      hook mechanism; the adapter just bridges hook payload → `ProposedCommand` → daemon.)
  - Accept: running a command via Claude Code produces a logged event tagged `agent="claude-code"`.

P0.6  `kintsugi-intercept` MCP server `kintsugi-exec`: expose a tool agents (Qwen/Codex/custom) can
      call to run a command; it bridges to the daemon. Document how to point an agent at it.
  - Accept: an MCP call to `kintsugi-exec` runs the command and logs it tagged with the agent.

P0.7  `kintsugi-cli`: `kintsugi init` (auto-detect installed agents, wire hook/MCP/shim, start daemon),
      `kintsugi status`, `kintsugi log` (pretty timeline of recent events).
  - Accept: fresh machine → `kintsugi init` → run a command in any wired agent → `kintsugi log` shows it.

Phase 0 done = every command from at least Claude Code + one MCP agent + raw shim is recorded
to a tamper-evident local log, cross-agent, with the real command preserved.

---

## PHASE 1 — Gate

P1.1  `kintsugi-core` rule engine: classify a `ProposedCommand` into Safe / Catastrophic / Ambiguous.
      - Catastrophic patterns (start here, expand): `rm -rf`/recursive force deletes, `git push
        --force`/`reset --hard`/history rewrite, `drop`/`truncate`/`delete from` SQL, `terraform
        destroy`/`kubectl delete`, redirects clobbering existing files, reads of `.env`/`~/.ssh`/
        keychains, `curl`/`wget` POSTing to non-allowlisted domains.
      - Safe auto-allow list: `ls cat pwd grep find git status/diff/log npm test cargo build` etc.
      - Everything else → Ambiguous.
  - Accept: table-driven tests; a corpus of ~50 real commands classifies correctly; zero
    catastrophic-as-safe misses.

P1.2  Decision mapping (attended): Safe → Allow; Catastrophic → Hold; Ambiguous → Hold.
      Daemon returns `Hold`; interception pauses execution and asks the CLI/TUI for a decision.
  - Accept: a catastrophic command pauses and does not run until approved.

P1.3  `kintsugi-cli` approval prompt: on Hold, print the "hold card" — risk class, the raw command
      in mono, and `[a]llow / [d]eny / [r] always-allow-here`. One keypress resolves it.
  - Accept: `[a]` runs it, `[d]` blocks it, `[r]` stores a memory entry and never asks again
    for that exact command in that repo.

P1.4  Decision memory (`kintsugi-core`): per-repo always-allow / always-deny by command hash;
      consulted before rules.
  - Accept: an `[r]`'d command auto-allows on next run; recorded in the log as memory-allow.

P1.5  Policy file: read `.kintsugi.toml` from the repo root (allow/deny additions, mode) and
      `~/.config/kintsugi/` defaults; repo overrides global.
  - Accept: adding a deny rule in `.kintsugi.toml` causes that command to Hold/Deny.

P1.6  Latency guard: ensure the Safe fast-path adds negligible overhead (no model in P1).
      Benchmark the rules path.
  - Accept: Safe-command round-trip through the daemon is sub-millisecond in a benchmark.

P1.7  Demo: script the 30-second flow — agent proposes `rm -rf` → Kintsugi holds it → you press
      `d` → it's blocked and logged. Capture a GIF.
  - Accept: the GIF clearly shows interception-before-execution across a real agent.

Phase 1 done = dangerous commands from any wired agent are held for one-key approval, with
per-repo memory and policy, deterministic and fast. This is the first shippable release.

---

## Then (brief)

- Phase 2: `kintsugi-model` real impl — bundle/download 3B Q4_K_M GGUF (1.5B low-RAM fallback,
  auto-selected), keep warm in the daemon, fill `summary`+`risk`, wire graduated unattended mode.
- Phase 3: snapshots + `kintsugi undo` (predict touched paths; reflink CoW + copy fallback).
- Phase 4: FS-watcher backstop + `ratatui` timeline reading the event log.
- Phase 5: kill-switch, signed binaries, `kintsugi init` polish, open-source launch.
