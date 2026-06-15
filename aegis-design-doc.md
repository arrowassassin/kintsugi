# Aegis — Design Doc (solo edition, v1.1 — decisions locked)

A local-first safety layer for AI coding agents. Aegis intercepts the commands an agent
is about to run, warns you in plain English *before* they execute, makes destructive
actions reversible, and keeps a tamper-evident record of everything every agent did on
your machine. No kernel code, no OS-vendor approvals, no code leaves your machine.

Status: planning, decisions locked. Author: you (solo, building with Claude Code).

---

## 1. Problem

AI coding agents now run real commands on real machines — `rm -rf`, `git push --force`,
`terraform destroy`, `drop table`, mass file rewrites — faster than a human can read a
confirmation. 2026 produced a string of public incidents (production data deleted, home
directories wiped, ~15k personal files destroyed). The damage all flows through one
chokepoint: a process spawn with a command line.

Existing safeguards are per-vendor and per-session (e.g. Claude Code's own prompts), heavy
cloud control planes, or Linux-only kernel tooling. Nothing is a lightweight, local-first,
**agent-agnostic** layer that warns before execution, undoes mistakes, and keeps one audit
trail across *every* agent you run.

## 2. Goals / Non-goals

Goals
- Warn automatically and *before execution* when an agent proposes a dangerous command.
- Make the **block decision deterministic** (rules), so it can't be argued past by the agent.
- Use a small **local model to explain**, and to score the **ambiguous band** only.
- Guarantee **nothing is unrecoverable**: snapshot before destructive ops, one-command undo.
- Work across all terminal coding agents, persistently, with one audit log.
- Stay local-first and private. Single binary. Sub-second warnings. Near-zero setup.
- Buildable solo with Claude Code; no entitlement / driver-signing dependencies.

Non-goals (v1)
- Kernel-level enforcement, sandboxing, or micro-VM isolation.
- Intercepting a *human's* keystrokes before they press Enter (v2 shell plugin).
- Protecting against agents that never touch the shell or filesystem.
- A required cloud/team product or a paywall.

## 3. Users & scope (LOCKED: agent-agnostic from v1)

- v1 targets all terminal coding agents from day one: Claude Code CLI, Qwen CLI, Codex CLI,
  Gemini CLI, and any custom/MCP agent. No single-agent wedge.
- Coverage uses the cheapest available interception point per agent: native hooks where they
  exist (e.g. Claude Code), the MCP `aegis-exec` tool for agents that call tools, and a
  `$PATH` shim for agents that shell out raw. An adapter layer normalizes them to one event.
- Adjacent (later): non-developers running computer-use agents that touch files.

## 4. Core principle (the security spine)

> Rules block. The model explains and scores the ambiguous band. A filesystem watcher is the backstop.

- The decision to **hold/deny** a catastrophic command is made by deterministic rules — never
  by the LLM. This prevents prompt-injection / "trust me, it's safe" bypasses.
- The local model's jobs: (a) write a one-sentence summary for the warning; (b) score severity
  for the **ambiguous middle band** only.
- **Monotonic model influence:** where policy lets the model affect a decision, it may only
  *add* caution (escalate an ambiguous command to deny + queue), never *remove* a rule-based
  block. An agent cannot talk the model into unlocking a blocked action.
- The raw command is **always shown verbatim**, so a wrong summary can't mislead a careful user.
- Honestly scoped guarantee: Aegis cannot promise *nothing runs un-warned* (an agent can decline
  to call the hook). It promises **nothing is unrecoverable** — the filesystem watcher records
  and enables undo even for actions that dodged interception.

## 5. Architecture

```
            ┌──────────────────────────────────────────────┐
            │                  AI agent                     │
            │   (Claude Code / Qwen / Codex / Gemini / …)   │
            └───────────────┬──────────────────────────────┘
                            │ proposes a command
        ┌───────────────────┼───────────────────────────────┐
        │ INTERCEPTION (adapter layer → one normalized event)│
        │  • native hook (primary where available)           │
        │  • MCP server `aegis-exec` (tool-calling agents)   │
        │  • $PATH shim (agents that shell out raw)          │
        └───────────────────┬───────────────────────────────┘
                            │ local socket (IPC)
            ┌───────────────▼──────────────────────────────┐
            │           Aegis resident daemon               │
            │   (model kept warm in memory, low latency)    │
            │                                               │
            │   Tier 1: deterministic rules  ──► SAFE → auto-allow
            │      │ CATASTROPHIC → block/queue (hard floor)│
            │      │ AMBIGUOUS                              │
            │      ▼                                        │
            │   Tier 2: local model (summary + severity)    │
            │      ▼                                        │
            │   Decision: you approve/deny  OR              │
            │             unattended policy (graduated)     │
            │      ▼ (if allowed & destructive)             │
            │   Snapshot (predicted paths) ──► execute      │
            │      ▼                                        │
            │   Append-only hash-chained event log          │
            └───────────────┬──────────────────────────────┘
                            │
   ┌────────────────────────┼───────────────────────────────┐
   │ BACKSTOP: filesystem watcher (notify) records all FS    │
   │ changes even from actions that bypassed interception →  │
   │ keeps undo complete. "Nothing unrecoverable."           │
   └─────────────────────────────────────────────────────────┘

   UI: TUI (ratatui) first; Tauri DVR timeline later  ◄── reads log, drives undo & policy
```

## 6. Components

1. Interception (adapter layer)
   - Hook adapter (e.g. Claude Code hooks; configured automatically on install).
   - MCP server (`aegis-exec` tool agents call instead of raw bash).
   - `$PATH` shim for `rm`, `git`, `terraform`, `psql`, etc. (catches raw shell-outs).
   - All three normalize to one `ProposedCommand` event sent to the daemon.
2. Resident daemon
   - Long-lived; holds the model in memory; IPC over Unix socket / named pipe.
   - Pure-rules fast path returns in microseconds for the common case.
3. Rule engine (Tier 1, deterministic) → classifies SAFE | CATASTROPHIC | AMBIGUOUS
   - CATASTROPHIC: destructive file ops, force push, history rewrite, DB drop/truncate, infra
     teardown, recursive/forced flags, file-clobbering redirects, secret access (`.env`,
     `~/.ssh`, keychains), network egress to new domains.
   - SAFE auto-allow: `ls`, `cat`, builds, tests, formatters, read-only git, etc.
   - Decision memory: "always allow this exact command in this repo."
4. Local model (Tier 2, explain + score the ambiguous band) — LOCKED
   - Shipped/managed with the build; runs CPU-only on any laptop that runs a coding-agent CLI.
   - Default: Qwen2.5-3B-Instruct or Llama-3.2-3B-Instruct, Q4_K_M GGUF (~2 GB); the 3B size is
     chosen because the unattended ambiguous-band judgment needs real reasoning.
   - Low-RAM fallback: Qwen2.5-1.5B-Instruct, auto-selected at install from detected memory.
   - Runtime: `llama.cpp` bindings (`llama-cpp-2`) or Candle; no GPU required.
   - Fetched + checksummed on first run (not embedded in the binary). If a local Ollama exists,
     may use it in local/free mode — but Aegis never *requires* Ollama.
   - Output forced-short JSON: `{ summary, risk, reason }`. Sub-second on a warm daemon.
   - Graceful degradation: no model / weak hardware → rules-only (blocks intact, no prose,
     ambiguous band defaults to the safe side).
5. Snapshot + undo
   - Predict touched paths from the command; snapshot only those into a content-addressed store.
   - Copy-on-write where available (APFS / btrfs / ReFS reflinks), plain copy fallback.
   - `aegis undo` (last action), `aegis undo --session` (whole agent session).
6. Flight recorder
   - Append-only, hash-chained event log in SQLite (command, decision, tier, summary, snapshot ref).
   - `aegis log` query + signed export for audit/compliance.
7. Policy
   - Per-project `.aegis.toml` committed to the repo: allow/deny rules, risk threshold, mode.
   - Global user defaults in `~/.config/aegis/`.
8. Modes (graduated, LLM-assisted balance) — LOCKED
   - Attended: hold dangerous/ambiguous ops, wait for one-key approve/deny.
   - Unattended/autonomous (no human present), three-way by rule class:
       • SAFE → allow + record.
       • CATASTROPHIC → auto-deny + queue, regardless of model (hard floor).
       • AMBIGUOUS → model severity vs. policy threshold: below → allow + record; at/above →
         deny + queue. This is where the local model strikes the "how bad is it" balance
         instead of freezing the agent.
   - Notify-only: record + warn, never block (visibility-first).
9. Controls
   - Panic kill-switch: instantly halt current + queued agent actions.
   - Tamper-evidence: detect/record attempts to disable Aegis or rewrite the log.
10. UI — LOCKED priority
   - v1: `ratatui` TUI timeline (scrub, filter, undo, approve). Backend ships fully first.
   - P2: Tauri 2 (Rust backend + web frontend) "DVR" timeline, after backend is complete.

## 7. Data model (sketch)

```
events(id, ts, agent, cwd, command, class, decision, tier, risk, summary, snapshot_id, prev_hash, hash)
snapshots(id, ts, paths_json, store_ref, reverted_bool)
policies(scope, rules_json, mode, threshold, updated_at)   # scope = global | <repo path>
memory(repo, command_hash, action)                          # always-allow / always-deny
```

## 8. UX & design direction

Calm authority — silent until the one moment it must be unmissable. The "hold card": one
plain-English sentence, the raw command in mono beneath it, a risk bar, two keys. A single
reserved accent color appears *only* on a pending dangerous action; everything else is quiet.
Copy names what the user controls; errors don't apologize. Setup is one command that
auto-detects the agent and wires interception. "Undo the last thing" is one obvious command.

## 9. Tech stack

- Language: Rust (privileged-ish hot path; memory safety; single binary; low latency).
- PTY/process: `portable-pty` + `nix` (Unix), ConPTY (Windows).
- FS watch: `notify` (inotify / FSEvents / ReadDirectoryChangesW).
- Snapshots: content-addressed store; `reflink-copy` with copy fallback.
- Storage: SQLite via `rusqlite`.
- Model runtime: `llama-cpp-2` (or Candle); GGUF weights, CPU inference.
- LLM transport (optional remote/Ollama): `reqwest`.
- UI: `ratatui` (v1), Tauri 2 + React/Svelte (P2).
- Dist: GitHub Actions → macOS .dmg, Windows .msi, Linux .AppImage; `cargo install` + Homebrew.

## 10. Build roadmap (solo + Claude Code, backend-complete first)

- Phase 0 — Recorder (1–2 wks): adapter intercept (hook + MCP + `$PATH` shim) that *logs* every
  agent command across Claude Code / Qwen / Codex. Proves agent-agnostic interception.
- Phase 1 — Gate (2–4 wks): Tier-1 rule engine classifies and holds CATASTROPHIC/AMBIGUOUS for
  one-key approval. Real product after this phase; build the 30s "rm -rf caught" demo here.
- Phase 2 — Explain + score (1–2 wks): resident daemon + bundled local model writing summary and
  severity; graduated unattended logic; rules-only fallback.
- Phase 3 — Undo (2–3 wks): predicted-path snapshots + `aegis undo` / `--session`.
- Phase 4 — Recorder + backstop (2–3 wks): hash-chained log, FS-watcher backstop, `ratatui` timeline.
- Phase 5 — Polish & launch (1–2 wks): `.aegis.toml`, unattended mode, kill-switch, signed
  binaries, open-source release, HN / r/rust / r/devtools, demo GIF.
- Later (P2+): Tauri DVR UI; deeper per-agent adapters; optional team policy sync + audit vault
  (kept open; no paywall planned).

## 11. Risks & mitigations

- Prompt fatigue (existential): tight rules, generous auto-allow, decision memory; false-positive
  rate is the north-star metric.
- Interception bypass: layered defense (hook → MCP → shim → watcher backstop); honest guarantee is
  "nothing unrecoverable," not "nothing un-warned."
- Model latency/quality: warm resident daemon; narrow forced-JSON task; rules-only fallback; raw
  command always shown.
- Model jailbreak: monotonic influence — model can only escalate caution, never unlock a block.
- Self-protection limits: detect/record tamper attempts; be explicit that userspace can't fully
  prevent a determined agent from disabling the guard.
- Undo scope: covers files; NOT network calls, external APIs, or already-pushed commits — stated plainly.
- Windows hardest surface (ConPTY, shells, reflink availability): later hardening pass.
- Differentiation vs per-vendor prompts: stay sharply agent-agnostic + persistent + undo + one
  cross-agent audit + local explanations.

## 12. Success metrics

- False-positive rate (lower is everything).
- Time-to-warning (sub-second incl. model on warm daemon).
- % commands resolved by Tier-1 rules without touching the model (target high).
- Destructive ops held or undone (the "saves" count).
- Adoption: installs, stars, agents covered.

## 13. Decisions (LOCKED)

1. Agent coverage: system-agnostic from v1 — Claude Code CLI, Qwen CLI, Codex CLI, Gemini CLI,
   custom/MCP — via the hook/MCP/PATH adapter layer.
2. Model: ship a small, capable instruct model with the build (managed download, CPU-only, runs
   on any laptop that runs a coding-agent CLI). Default 3B Q4_K_M, 1.5B low-RAM fallback. Ollama
   only if present, local/free mode, never required.
3. Scope/priority: ship the backend fully. UI starts as a `ratatui` TUI; Tauri DVR UI is P2.
4. Unattended decisions: graduated — hard rule floor auto-denies catastrophic ops; the local model
   scores the ambiguous band against a policy threshold to balance safety vs. freezing the agent
   (escalation-only; never unlocks a rule block).
5. Licensing: fully open source, free, no reserved paid tier for now.

---

## 14. Autonomous build guardrails (Claude Code cloud / auto mode)

These govern an agent building Aegis unattended. They are intentionally strict — a tool whose
job is to guard agents must itself be built under guard.

A. Branch & merge discipline
- The agent works only on feature branches, **one task-list segment per branch/PR**. Never
  commits to `main`. Diffs stay small and reviewable.
- Every PR must meet the segment's acceptance criterion (link the passing test) and update
  tests, docs, CHANGELOG, and a one-line decision-log entry.

B. Mandatory multi-role review per segment (simulated sub-agent panel) — no merge without ALL sign-offs
- 2 developer reviewers: correctness, architecture adherence, idiomatic Rust, no security-spine
  violation, dependency hygiene.
- 3 testers: author/extend tests; adversarial + cross-platform; specifically red-team the gate —
  try to bypass interception, jailbreak the rules, tamper the hash-chained log, and break
  exit-code/signal fidelity in the shim.
- 1 PM: scope adherence (block scope creep), acceptance criteria met, UX/copy sanity, decision
  log updated.

C. Test coverage gate
- >= 90% line AND branch coverage per crate, enforced in CI (`cargo-llvm-cov`). Build fails below.
- Required suites: unit, integration, OS matrix (macOS/Linux/Windows), property tests for the
  classifier, a golden command corpus, and security/adversarial tests.
- Zero-tolerance: any command classified "catastrophic-as-safe" is a hard CI failure.

D. Hard invariants — CI blocks merge if any is violated
- Rules block; the model never decides allow/deny for catastrophic ops; model influence is
  escalation-only.
- The raw command is always preserved and shown.
- Event log is append-only and hash-chained; past events are immutable.
- No network egress except the pinned+checksummed model download and a user-configured endpoint.
- No secret/credential value is ever read into logs in plaintext.
- `clippy -D warnings`, `rustfmt --check`, and the full OS build matrix are green.

E. Actions the agent may NOT take autonomously (require a human checkpoint)
- Force-push, history rewrite, branch/file deletion outside the worktree, touching `main`.
- Adding a third-party dependency outside an allowlist/threshold without flagging (supply chain).
- Publishing, releasing, pushing to registries, or modifying CI secrets.
- Any change to Section 4 (security spine), Section 6.3 (rule classes), or this Section 14.

F. Mandatory human checkpoints (stop and confirm)
- End of every phase (0-5) before starting the next.
- Before the first public release.
- Whenever 90% coverage cannot be met — must explain; never silently lower the bar.

G. Rollback
- Every merged segment must be revertible. Tag last-known-good after each phase.

H. Dogfooding (self-consistency)
- Once Phase 1's gate works, run the autonomous build agent itself THROUGH Aegis, so any
  destructive build action is guarded by the tool being built.
