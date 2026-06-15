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
- Distribution: published as a Claude Code plugin + marketplace. The plugin
  (plugin/aegis) is a thin wiring layer — PreToolUse hook -> aegis-hook and MCP
  aegis-exec -> aegis-mcp — because /plugin install ships config, not native
  binaries or a daemon. Binaries go via cargo/Homebrew (signable/checksummed);
  the repo root .claude-plugin/marketplace.json references the plugin by relative
  path so the one repo is both marketplace and plugin host. defaultEnabled=false
  (a safety tool must be trusted before it runs).
- Site: 8-bit themed static product site in `site/`, deployed to GitHub Pages
  via `.github/workflows/pages.yml` (source must be set to "GitHub Actions" once
  in repo settings). Every terminal "screenshot" is REAL output captured from the
  release binaries (TUI rendered through ratatui TestBackend; hold card, log,
  queue, init, status from live runs) — no mockups. Press Start 2P + VT323, one
  danger accent, CRT scanlines, copy-to-clipboard on commands.
- Images: docs/site frames are rendered to SVG via scripts/gen_svg.py from real
  captured output (deterministic, version-controlled images that render on GitHub
  + web). Animated flow.svg (pure CSS keyframes, no JS) is used only on the live
  site (its frames start hidden, so GitHub markdown — which may not animate — gets
  static SVGs instead). OG card og.svg + favicon added; dark/light theme toggle
  (persisted) flips chrome only, terminals stay dark. Homebrew: a build-from-
  source formula (packaging/homebrew/aegis.rb) + docs/homebrew.md (tap first,
  core later).
- Review pass: catastrophic hard floor made consistent across memory/policy/
  hook (no static or replayed allow downgrades it; hook denies catastrophic
  rather than delegating to Claude's ask which would skip the snapshot). Hash
  chain read-modify-append wrapped in BEGIN IMMEDIATE + busy_timeout so multi-
  process writers (CLI vs daemon) cannot fork it. IPC frame size bounded.
  Kill-switch blocks approvals. Shim preserves argv0. Release profile tuned for
  size (opt=s, lto=fat, strip, panic=abort).
- Remote install: scripts/install.sh (curl|sh) downloads checksum-verified
  prebuilt release binaries for the detected target, falling back to `cargo
  install --git` from source when no prebuilt build matches or no release exists
  yet — so the one-liner works today (source) and gets fast binaries post-release.
  No repo clone required. Homebrew deferred per request (formula stays in repo).
- Model upgraded to Qwen3 (4B primary / 1.7B low-RAM fallback) — newer, stronger
  per byte, same footprint; consts renamed MODEL_PRIMARY/MODEL_FALLBACK. The
  installer never fetches a model (default heuristic build stays small/offline);
  the GGUF is opt-in via --features llama,download. Installer is now served from
  GitHub Pages (site/install.sh) so the one-liner is the short
  arrowassassin.github.io/aegis/install.sh instead of the raw.githubusercontent
  path. Homebrew de-emphasized in README/site per request.
- Future-proof model selection: added AEGIS_MODEL_FILE runtime override (load any
  local GGUF, bypassing the pinned spec/checksum — a user-chosen, bring-your-own
  trust path; the daemon's own download path stays pinned-only). The pinned const
  is now documented as just a sensible default. Added scripts/pick-model.sh
  (served from Pages) that queries the Hugging Face API with constrained params
  (filter=gguf, pipeline_tag=text-generation, RAM-sized search, top by downloads),
  lists only viable small instruct GGUF options, downloads the single-file Q4_K_M
  build, and prints its SHA-256 for the user to record/pin. install.sh gained
  --with-model. Rationale (researched 2026-06): the field moves fast, so the
  mechanism (override + picker) is the future-proof choice; Qwen3 stays the
  Apache-2.0 default. Installer itself still never auto-downloads a model.
- Agent coverage: added Cursor CLI to init's detection (~/.cursor → MCP), joining
  Claude Code (hook) and Codex/Qwen/Gemini (MCP). Verified each CLI's execution
  model before claiming support: all run shell commands (covered by the $PATH
  shim) and all speak stdio MCP (covered by aegis-exec) — Codex via
  ~/.codex/config.toml [mcp_servers], Cursor via ~/.cursor/mcp.json mcpServers,
  Qwen via ~/.qwen/settings.json mcpServers, Gemini via ~/.gemini/settings.json.
  Reframed README/site/docs to lead with "works with any agent and any shell"
  (protection is at the process/PATH layer; the Claude hook is best-UX, not
  required), with the honest $PATH-vs-absolute-path caveat and the FS-watcher
  backstop as the safety net. Added a per-agent MCP-config table to docs/mcp.md.
- Sessions + log slicing + deletion: added an originating session id (Claude hook
  session_id; one-per-process for MCP, overridable; $AEGIS_SESSION for the shim),
  stored as non-hashed view metadata so old hashes/chains stay valid (migration
  adds the column). Single hash chain kept — we deliberately did NOT partition
  storage per session/CLI (that would weaken tamper-evidence and the one
  cross-agent timeline); per-CLI/per-session is a *view* via the new Filter
  (agent/session/class/grep/since/until). Deletion: redaction is the spine-safe
  default (append-only redactions table; hides from views, chain intact),
  hard purge is the explicit escape hatch (delete + rechain + audit:purge marker,
  requires a filter and --yes). TUI: free-text `/` filter now also matches
  session; risk gauge bounded to an auto-width single-row meter; detail shows
  session + a redacted headline; redacted rows drop from the live timeline.
- Multi-model security review (Grok Composer + 2 Auto reviewers) — fixes:
  (1) Monotonic model influence restored: removed the unattended graduated
  auto-allow so the Tier-2 model can never downgrade a rules Deny->Allow for the
  ambiguous band (spine rule #2); unattended ambiguous denies/queues, and only a
  human allowlist (.aegis.toml/memory) auto-proceeds. (2) Shell-wrapper evasion:
  rules now recursively classify -c payloads (bash/sh/zsh/dash/ash/ksh), find
  -exec/-execdir, and xargs, and effective_argv peels transparent prefixes
  (sudo/env/nohup/setsid/stdbuf/timeout); bash/sh/zsh/find/xargs added to
  SHIM_COMMANDS. (3) Kill-switch: resolve() now guards Allow like
  resolve_pending(). (4) Fail-closed for catastrophic when the daemon is down
  (shim/hook/mcp classify locally). (5) IPC/data hardening: socket 0600 in a 0700
  dir (off world-writable temp), data dir 0700, events.db+WAL/SHM 0600. We did
  NOT scrub secrets from the verbatim command (spine #3 mandates verbatim) —
  protected at rest instead. AEGIS_SOCKET kept as a documented trusted override
  (single-user threat model). Notify mode left as documented design debt.
- aegis stop + guided installer + docs declutter: daemon writes its own PID file
  (pid_file_path, next to the log) on startup; `aegis stop` reads it and
  kill/taskkills the process (idempotent). install.sh became a cross-OS stepper:
  default install = prebuilt binaries (no model/toolchain, works everywhere),
  then /dev/tty prompts (so it works under curl|sh) to wire agents and optionally
  set up a local model (detect OS pkg mgr → install cmake + toolchain + libomp,
  cargo install aegis-daemon --features aegis-model/llama, pick-model.sh from
  Hugging Face, persist AEGIS_MODEL_FILE). Reduced README/site image+text
  redundancy for a simpler, more trustworthy first impression.
