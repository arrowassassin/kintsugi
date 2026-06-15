# Decision log

One line per notable build decision, newest last. See `aegis-design-doc.md` for
the locked product decisions this build implements.

- P0.1: Rust workspace with six crates (`aegis-core`, `aegis-daemon`,
  `aegis-intercept`, `aegis-cli`, `aegis-model`, `aegis-tui`). Edition 2021,
  resolver 2. `aegis` binary prints its version. IPC will use the `interprocess`
  crate for portable local sockets / named pipes.
- P0.2: Event-log hash chain is `SHA-256(prev_hash || US-separated canonical
  fields)`. The log is append-only by construction — no update/delete API — and
  `verify_chain` recomputes every row to detect edits, reorders, and deletions.
- Deps: pinned to latest stable per user request. `rusqlite` pinned to 0.39 (not
  0.40) because `libsqlite3-sys` 0.38 uses the unstable `cfg_select!` macro and
  fails to build on stable Rust 1.94. Revisit when that stabilizes.
- P0.3: IPC is newline-delimited JSON over an `interprocess` local socket
  (Unix path / Windows namespaced pipe). The daemon serves connections
  sequentially because the SQLite event-log connection is single-threaded and
  each request is sub-millisecond; the client blocks on the response.
- P0.4: The shim execs the real binary via Unix `exec()` (process image
  replacement) for exact exit-code/stdio/signal fidelity; Windows spawns and
  propagates the code. Fail-open by default (record-but-run when the daemon is
  down) to match the honest guarantee; `AEGIS_FAIL_CLOSED=1` opts into blocking.
  Real-binary resolution walks `$PATH`, skipping the shim dir and any entry that
  canonicalizes back to the shim.
- P0.5: Claude Code hook maps Verdict to the PreToolUse protocol: Allow is
  silent (Claude proceeds, event still logged), Deny -> permissionDecision
  "deny", Hold -> "ask" (a hook cannot block interactively, so defer to the
  user). Fail-open on parse errors / non-shell tools / daemon down. Added
  `aegis_core::shell::split` (single/double quote + backslash aware).
- P0.6: MCP `aegis-exec` server is a hand-rolled JSON-RPC 2.0 stdio loop (no
  MCP framework dep, keeping the dependency surface small). The tool executes
  allowed commands itself via `sh -c` / `cmd /C` and returns exit code + stdout
  + stderr; Deny/Hold are returned as tool errors without running.
- P0.7: `aegis init` detects agents by config-dir presence (most reliable
  cross-platform signal), wires Claude Code via a hook merged idempotently into
  ~/.claude/settings.json (backed up first), and links a default risky-command
  set into a shim dir the user prepends to PATH. `aegis log` is calm by design:
  outcome words (allowed/denied/held) not color alone, one reserved accent for
  danger, NO_COLOR respected. Phase 0 (Recorder) complete.
- P1.1: The classifier is intentionally conservative — catastrophic checks run
  first and broadly, only confidently read-only/build/test commands are Safe,
  everything else is Ambiguous. Chained lines are segmented (quote-aware) and
  the worst class wins; `sudo`/`doas`/env-assignment prefixes are stripped so
  they cannot mask a catastrophic program. No I/O, so it stays deterministic.
  Zero-catastrophic-as-safe is enforced as a hard test gate.
- P1.2: Class->Decision mapping lives in `aegis_core::rules::decide(class,
  mode)` so it is one source of truth across daemon and adapters. Attended holds
  catastrophic+ambiguous; unattended hard-denies catastrophic and (rules-only,
  pre-model) denies ambiguous on the safe side; notify always allows+records.
- P1.3/P1.4: Interactive approval lives in the shim (it owns the TTY): it reads
  one key from /dev/tty, falling back to stdin, defaulting to deny when there is
  no answer. Resolutions are a second IPC message (Resolve) so the daemon stays
  the single logger. Added a persisted `reason` column to the event log (also
  folded into the hash chain) so provenance — rule name, human:allow,
  memory:allow — is auditable. Decision memory is mutable state in the same DB,
  keyed by (repo-root, exact-command-hash); consulted before rules, allow-only
  in spirit but supports always-deny too. Memory never erases the rule class.
- P1.5: Decision precedence is rules -> policy -> memory, with policy able to
  set the effective mode per repo. Policy `allow` is deliberately NOT allowed to
  downgrade a catastrophic rule classification (static config must not unlock the
  hard floor); only an in-the-moment human `[r]` / explicit memory can. Policy
  files are discovered by walking up from cwd for `.aegis.toml`; global config
  path is overridable via AEGIS_CONFIG for hermetic tests.
- P1.6: SQLite runs WAL + synchronous=NORMAL so per-event logging does not
  fsync on every commit (keeps the round-trip sub-ms); a crash can only lose the
  last few transactions and the surviving hash chain stays verifiable. Measured:
  rules classify ~3.5us, safe daemon round-trip ~345us.
- P1.7: Demo is a self-contained shell script (temp socket/log/shim, real rm
  captured before shimming so cleanup is not itself intercepted). GIF capture is
  scripted via a VHS tape; this headless build environment cannot record, so the
  GIF is produced on a workstation with `vhs scripts/demo.tape`. Phase 1 (Gate)
  complete: dangerous commands from any wired agent are held for one-key
  approval, with per-repo memory and policy, deterministic and sub-ms.
- Coverage: pushed workspace line coverage to ~90% with targeted tests
  (rule branches, enum surfaces, daemon resolve/memory/policy-merge, IPC error
  mapping, adapter fail-open/closed, run-loop refactors to run_io for testability).
  Sub-90% remainder is concentrated in process-replacement (`exec`) and the
  detached-daemon spawn paths, which are exercised by the demo + integration
  tests rather than unit-covered; the thin bin wrappers just call lib functions.
- Phase 2: model is explain+score only. HeuristicScorer is the default and the
  degradation path; real GGUF inference (LlamaScorer) is behind feature `llama`
  and weight download behind `download`, so the default build stays offline and
  toolchain-free and CI stays green. Weights are SHA-256-pinned (unpinned specs
  refused). Graduated unattended uses policy.threshold (default 50). Catastrophic
  is never scored into an allow; Safe is never scored at all (fast path). The
  llama backend targets llama-cpp-2 0.1.x and is the one path not CI-compiled.
- Phase 3: snapshots capture only paths that currently exist (predicted from
  argv + redirect targets, resolved vs cwd); restore overwrites/recreates them.
  Undo deliberately does NOT delete newly-created files (avoids acting on bogus
  predicted tokens) — documented as files-only scope. reflink CoW via
  reflink-copy with copy fallback. Daemon snapshots synchronously before
  returning Allow, so files are intact at capture time and the shim execs after.
  snapshots table lives in the same DB; undo is append-only (logs an undo event).
- Phase 4: FS-watcher writes through the daemon (Observe IPC), never a second
  concurrent SQLite writer — that would race prev_hash and fork the chain. TUI
  state (app.rs) is terminal-free and unit-tested; rendering (ui.rs) is tested
  with ratatui TestBackend at multiple sizes; teardown uses ratatui::init/restore
  (panic-safe). frontend-design skill was unavailable in the build env, so its
  principles were applied directly from the CLAUDE.md TUI requirements.
- Phase 5: kill-switch is a flag file (panic.flag) beside the event DB, checked
  first in decide() so it halts even Safe commands instantly across processes;
  panic/resume are logged. Release workflow publishes SHA256SUMS; code signing is
  left as a documented human step (needs secrets) per the autonomy guardrails.
  init --print-path enables shell-rc wiring via eval.
- Queue: held commands are enqueued by the daemon and resolved via CLI
  (queue/approve/deny), TUI (a/d), or the agents bounded in-band wait
  (AEGIS_APPROVAL_TIMEOUT). The originating caller executes on approval (shim/MCP),
  so the daemon never runs commands itself; approve still logs human:allow and
  snapshots first. Two serde traps fixed: internally-tagged enums cannot wrap a
  bare String or Vec, so PendingStatus/Approve/Deny and PendingList became struct
  variants (caught by an over-the-socket integration test). A human may approve
  any class (override); the model never approves catastrophic; panic overrides all.
