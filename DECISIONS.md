# Decision log

One line per notable build decision, newest last. See `kintsugi-design-doc.md` for
the locked product decisions this build implements.

- P0.1: Rust workspace with six crates (`kintsugi-core`, `kintsugi-daemon`,
  `kintsugi-intercept`, `kintsugi-cli`, `kintsugi-model`, `kintsugi-tui`). Edition 2021,
  resolver 2. `kintsugi` binary prints its version. IPC will use the `interprocess`
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
  down) to match the honest guarantee; `KINTSUGI_FAIL_CLOSED=1` opts into blocking.
  Real-binary resolution walks `$PATH`, skipping the shim dir and any entry that
  canonicalizes back to the shim.
- P0.5: Claude Code hook maps Verdict to the PreToolUse protocol: Allow is
  silent (Claude proceeds, event still logged), Deny -> permissionDecision
  "deny", Hold -> "ask" (a hook cannot block interactively, so defer to the
  user). Fail-open on parse errors / non-shell tools / daemon down. Added
  `kintsugi_core::shell::split` (single/double quote + backslash aware).
- P0.6: MCP `kintsugi-exec` server is a hand-rolled JSON-RPC 2.0 stdio loop (no
  MCP framework dep, keeping the dependency surface small). The tool executes
  allowed commands itself via `sh -c` / `cmd /C` and returns exit code + stdout
  + stderr; Deny/Hold are returned as tool errors without running.
- P0.7: `kintsugi init` detects agents by config-dir presence (most reliable
  cross-platform signal), wires Claude Code via a hook merged idempotently into
  ~/.claude/settings.json (backed up first), and links a default risky-command
  set into a shim dir the user prepends to PATH. `kintsugi log` is calm by design:
  outcome words (allowed/denied/held) not color alone, one reserved accent for
  danger, NO_COLOR respected. Phase 0 (Recorder) complete.
- P1.1: The classifier is intentionally conservative — catastrophic checks run
  first and broadly, only confidently read-only/build/test commands are Safe,
  everything else is Ambiguous. Chained lines are segmented (quote-aware) and
  the worst class wins; `sudo`/`doas`/env-assignment prefixes are stripped so
  they cannot mask a catastrophic program. No I/O, so it stays deterministic.
  Zero-catastrophic-as-safe is enforced as a hard test gate.
- P1.2: Class->Decision mapping lives in `kintsugi_core::rules::decide(class,
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
  files are discovered by walking up from cwd for `.kintsugi.toml`; global config
  path is overridable via KINTSUGI_CONFIG for hermetic tests.
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
  (KINTSUGI_APPROVAL_TIMEOUT). The originating caller executes on approval (shim/MCP),
  so the daemon never runs commands itself; approve still logs human:allow and
  snapshots first. Two serde traps fixed: internally-tagged enums cannot wrap a
  bare String or Vec, so PendingStatus/Approve/Deny and PendingList became struct
  variants (caught by an over-the-socket integration test). A human may approve
  any class (override); the model never approves catastrophic; panic overrides all.
- Distribution: published as a Claude Code plugin + marketplace. The plugin
  (plugin/kintsugi) is a thin wiring layer — PreToolUse hook -> kintsugi-hook and MCP
  kintsugi-exec -> kintsugi-mcp — because /plugin install ships config, not native
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
  source formula (packaging/homebrew/kintsugi.rb) + docs/homebrew.md (tap first,
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
  arrowassassin.github.io/kintsugi/install.sh instead of the raw.githubusercontent
  path. Homebrew de-emphasized in README/site per request.
- Future-proof model selection: added KINTSUGI_MODEL_FILE runtime override (load any
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
  shim) and all speak stdio MCP (covered by kintsugi-exec) — Codex via
  ~/.codex/config.toml [mcp_servers], Cursor via ~/.cursor/mcp.json mcpServers,
  Qwen via ~/.qwen/settings.json mcpServers, Gemini via ~/.gemini/settings.json.
  Reframed README/site/docs to lead with "works with any agent and any shell"
  (protection is at the process/PATH layer; the Claude hook is best-UX, not
  required), with the honest $PATH-vs-absolute-path caveat and the FS-watcher
  backstop as the safety net. Added a per-agent MCP-config table to docs/mcp.md.
- Sessions + log slicing + deletion: added an originating session id (Claude hook
  session_id; one-per-process for MCP, overridable; $KINTSUGI_SESSION for the shim),
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
  human allowlist (.kintsugi.toml/memory) auto-proceeds. (2) Shell-wrapper evasion:
  rules now recursively classify -c payloads (bash/sh/zsh/dash/ash/ksh), find
  -exec/-execdir, and xargs, and effective_argv peels transparent prefixes
  (sudo/env/nohup/setsid/stdbuf/timeout); bash/sh/zsh/find/xargs added to
  SHIM_COMMANDS. (3) Kill-switch: resolve() now guards Allow like
  resolve_pending(). (4) Fail-closed for catastrophic when the daemon is down
  (shim/hook/mcp classify locally). (5) IPC/data hardening: socket 0600 in a 0700
  dir (off world-writable temp), data dir 0700, events.db+WAL/SHM 0600. We did
  NOT scrub secrets from the verbatim command (spine #3 mandates verbatim) —
  protected at rest instead. KINTSUGI_SOCKET kept as a documented trusted override
  (single-user threat model). Notify mode left as documented design debt.
- kintsugi stop + guided installer + docs declutter: daemon writes its own PID file
  (pid_file_path, next to the log) on startup; `kintsugi stop` reads it and
  kill/taskkills the process (idempotent). install.sh became a cross-OS stepper:
  default install = prebuilt binaries (no model/toolchain, works everywhere),
  then /dev/tty prompts (so it works under curl|sh) to wire agents and optionally
  set up a local model (detect OS pkg mgr → install cmake + toolchain + libomp,
  cargo install kintsugi-daemon --features kintsugi-model/llama, pick-model.sh from
  Hugging Face, persist KINTSUGI_MODEL_FILE). Reduced README/site image+text
  redundancy for a simpler, more trustworthy first impression.
- Multi-CLI hooks: every supported agent now gets a *native* pre-tool hook, not
  just Claude Code. Research (per-CLI docs) found each exposes a blocking
  pre-exec hook: Claude/Qwen/Codex use Claude-style `hookSpecificOutput.
  permissionDecision` (Qwen identical; Codex via TOML `[[hooks.PreToolUse]]`);
  Gemini uses `BeforeTool` + `{decision:allow|deny}` (no ask → ambiguous holds
  map to deny under monotonic-caution); Copilot uses a fail-closed `preToolUse`
  command hook; Cursor uses `beforeShellExecution` + `{permission}`; OpenCode has
  no external-command hook, only a JS `tool.execute.before` plugin (throw to
  block), so `kintsugi init` writes a bundled bridge plugin. One `kintsugi-hook
  --agent <id>` binary owns all dialects (parse + serialize in
  `kintsugi-intercept/src/dialect.rs`); the daemon round-trip and
  fail-closed-catastrophic policy stay shared in `hook.rs`. Codex TOML is wired by
  text-append (not parse→serialize) to preserve user comments and dodge toml-rs's
  table-ordering rules. MCP stays as the documented manual fallback.
- Log UX: timeline is newest-first in both `kintsugi log` and the TUI (reversed at
  the display layer; `query()`/`tail()` keep their oldest-first contract so other
  callers and the hash-chain logic are untouched). `kintsugi log` gained real
  pagination via a new `Filter.offset` (`LIMIT ? OFFSET ?` on the newest-by-seq
  window) + `-p/--page`, with a range/total footer from `count_matching`. The
  Tier-2 llama prompt now requests a beginner-friendly explanation with 2-3 "• "
  pointers folded into the existing `summary` string (no schema change; MAX_TOKENS
  160→256); the TUI detail splits the summary on newlines so pointers render as
  their own lines. Heuristic summaries stay one line.
- Scorer observability + installer model load: the daemon's active scorer is now
  reportable over IPC (new Status request → Status{scorer}) and surfaced in `kintsugi
  status`, `kintsugi init`, and the bare `kintsugi` banner — heuristic fallback vs the
  loaded `<model> (local model)`. Motivated by a real diagnosis miss: a daemon
  spawned before KINTSUGI_MODEL_FILE existed degraded to heuristic silently (the
  "falling back…" stderr line is sent to /dev/null by `kintsugi init`), visible only
  as thin templated hold summaries. install.sh now restarts the daemon after
  setting up a model (so it inherits KINTSUGI_MODEL_FILE at spawn) but only when this
  run started it (DAEMON_STARTED gate — respects --no-init), and the model picker
  no longer auto-selects: it shows the full ★-recommended + ranked menu over
  /dev/tty and lets the user choose (--yes still auto-picks the top match).
- kintsugi update: added a manual, user-invoked self-update (`kintsugi update`, with
  `--check`/`--yes`). It GETs the GitHub releases API for the latest tag and, on
  consent, downloads + runs install.sh in a new `--bin-only` mode (binaries only,
  no stepper) targeting current_exe()'s dir. Deliberately the SINGLE explicit
  exception to spine #5 "never phone home": egress only on the explicit command,
  no automatic/background checks, no body/headers beyond curl/wget defaults, no
  user code/commands/telemetry sent. We reuse install.sh (one source of truth for
  download/checksum/source-fallback) and shell out to curl/wget rather than add an
  HTTP crate to kintsugi-cli (dependency hygiene). Version compare is a tolerant
  vMAJOR.MINOR.PATCH parse; unparseable tags fall back to "differs" so a real
  release is never hidden. Confirmed with the human before building (guardrail
  touch): scope = check + self-install, egress = manual-only.
- Installer ordering + idempotency: the stepper now sets up the model BEFORE
  running `kintsugi init`, so the daemon starts once already pointed at the model
  (was: init started a heuristic daemon, then the model step rebuilt + restarted
  it — a double start and a misleading transient "heuristic fallback" line). Made
  re-runs idempotent: install.sh skips the binary download when `kintsugi --version`
  in BIN_DIR already equals the target tag (this also stops the prebuilt tarball
  from clobbering a locally-built llama daemon); skips the llama.cpp compile when
  `kintsugi-daemon --has-llama` prints a version equal to the target (version-aware,
  so an app upgrade rebuilds the engine rather than keeping a stale one); and
  pick-model.sh skips the GGUF download when the file already exists (delete to
  re-fetch). Added a dependency-free `kintsugi-daemon --has-llama` probe that prints
  the build version + exits 0 when the engine is compiled in, else exits 1.
- kintsugi update preserves llama: `kintsugi update` probes `kintsugi-daemon --has-llama`
  and, when the engine is present, runs install.sh with `--version <tag> --no-init
  --with-model` (rebuilds the engine for the new version, keeps the configured
  model) instead of `--bin-only` (which would install the prebuilt heuristic-only
  daemon). The tag is pinned so binaries and engine match. setup_model now keeps an
  already-configured KINTSUGI_MODEL_FILE (skips the picker/download) so the rebuild
  doesn't re-pick a model. Closes the earlier gap where updating dropped llama.
- TUI paging: Space/b page the timeline by one screenful (the last-rendered
  data-row count, plumbed from the event loop via App.page_rows); f and
  PageUp/PageDown are aliases. Space/b are primary because Mac keyboards lack
  dedicated PageUp/PageDown. Footer gained a right-aligned "row N/M" indicator,
  shown only when it fits so the help text never clips on an 80-col terminal.
- Shell analysis went AST-based (industry standard). We adopted a real bash AST
  parser (`brush-parser`, pure-Rust/MIT) over the prior regex/substring approach,
  which is the documented failure mode for shell scanners (quoting/expansion slip
  through). Chose pure-Rust to keep the default build toolchain-free; rejected
  `yash-syntax` (GPL-3.0, incompatible with a distributed MIT binary).
- Keep BOTH parsers, worst-wins. The new AST pass composes with the old tokenizer
  pass and takes the most-severe class. Defense-in-depth for the security spine:
  the AST can only ADD caution, and if either pass (or the parser) fails, the
  other still stands. Never downgrades a verdict.
- AST fast-path is an allowlist, not a denylist. After the roundtable found a bare
  `&` slipping past a denylist of "interesting" characters, the skip-the-AST gate
  became an allowlist of provably-inert lines (plain word/flag/path chars only).
  A denylist is one missing operator away from a catastrophic-as-Safe miss.
- Parser DoS is prevented, not caught. brush-parser stack-overflows (uncatchable
  abort, not a panic) on deeply nested `$(…)`. We refuse input past a generous
  nesting/size/operator cap *before* parsing and classify it Ambiguous (never
  Safe); the AST-walk depth guard likewise sets a `truncated` flag that fails
  toward caution rather than dropping a buried command.
- False-positive suppression is program-aware and one-sided (human-signed-off, as
  it relaxes a guardrail). The whole-line SQL / curl-pipe / fork-bomb text scans
  are suppressed only when *every* program the line runs is a known inert text
  handler (grep/rg/echo/printf/cat/git/diff/…); any unknown or executing program
  keeps the catastrophic verdict. So `grep 'DROP TABLE'` / `git commit -m '…'` /
  `echo 'curl … | sh'` no longer hard-block, while `psql -c 'DROP TABLE'` and
  `curl … | sh` still do. Block-device writes are NOT subject to this (an inert
  program can still clobber a device via `>`), so they're detected structurally:
  a redirect *target* that is a block device, or `dd of=…` — which also fixes the
  `cat of=/dev/sda.txt` / commit-message false positives without allowlisting.
- Secret handling went deny-by-default. A command pointed at a secret path is
  never auto-`Safe`; the content-reader set is broadened (sort/diff/wc/tar/base64/…
  → `secret:read`), a truncating redirect onto a secret is `secret:clobber`, and
  `git config` that *sets* an execution primitive (core.pager / core.sshCommand /
  alias.* / *.command …) is `git:config-exec`. Reads of those keys stay safe.
- Decoder-to-shell joins download-to-shell: `… | base64 -d | sh` (and base32 /
  xxd / uudecode / openssl) is `net:pipe-to-shell`, not just `curl|sh`.
- kintsugi run / approval flow (6-reviewer roundtable: 2 principal sys-design, 2
  junior daily users, 1 PM, 1 infosec). A catastrophic command via a native hook
  is one-shot deny (an in-agent allow would skip the snapshot), so the human path
  to run it is `kintsugi run <id>`: snapshot predicted paths → execute the raw
  command in its original cwd → record. Confirmation is a random code typed at
  /dev/tty (not stdin) so an agent with piped stdio can't self-approve by
  pre-stuffing a key. Decisions taken from the panel: (1) origin-aware verbs —
  in-band (shim/MCP) keep approve (the waiting caller runs it); hook origins use
  run; approve on a hook origin no longer claims "agent may proceed" — fixes the
  approve-vs-run footgun both principals + juniors + PM flagged. (2) exactly-once
  CAS on the queue status (cas_pending_status) — kills the double-run/phantom
  Principal A found. (3) Honest reversibility (infosec V3 + both principals):
  predict_paths is now segment+cd aware, and is_fully_reversible flags unbounded
  targets (glob/$/root/device) so kintsugi run states plainly when undo can't cover
  it instead of over-promising — keeps spine #7 honest. (4) The /dev/tty gate is
  documented as a strong speed bump, NOT a sandbox: infosec correctly noted a
  same-user agent can self-approve over the unauthenticated local socket or echo
  the code from a PTY it owns. That is OUT of Kintsugi's stated threat model (spine
  #7: guards mistakes, "not an unbypassable firewall"); we raise the bar (typed
  random code, drain, tty-only) and are honest rather than claim a guarantee we
  can't keep. Deferred, deliberately, with this design as the extension point: a
  daemon-owned lease/redeem capability that unifies all paths, an explicit
  armed-vs-consumed state for a future "agent re-runs after human arm" feature,
  and nonce-bound socket auth for catastrophic — each is a protocol change that
  warrants its own review rather than riding this PR.
- Enterprise security assessment is reproducible-by-construction. Every figure in
  docs/security-assessment.md comes from a committed test (security_stress,
  robustness_fuzz, perf_report) + cargo audit/llvm-cov — no hand-written numbers.
  The heavy fuzz/perf are `#[ignore]` (campaign-only) so CI/coverage stay fast;
  the fast `dos_pathological` test (incl. the heredoc-DoS reproducer) runs always.
- Parser DoS mitigation is input-neutralization, not best-effort catching. The
  fuzzer found brush-parser heap-exhausting (~1.75GB) on malformed here-operators;
  an allocation abort is uncatchable, so we *prevent* it by rewriting here-operator
  runs (`<<`/`<<<`/…) to spaces before parsing. This keeps substitution/structure
  detection (no catastrophic-as-Safe leak) and moves here-string detection to the
  tokenizer pass. Chosen over refusing such lines (which risked a substitution-
  hidden leak) and over a bounded allocator (heavy, still aborts on the limit).
- Admin-locked settings + audit recorder is a phased, design-first feature (see
  kintsugi-admin-recorder-design.md). The daemon becomes the sole authority for privileged
  ops (stop/change-password/unhook/disable-recording behind an IPC challenge-response;
  argon2id verifier + AEAD-sealed settings with a root-owned sealed-file fallback for
  headless hosts; watchdog so `kill` isn't permanent). Honest framing is a hard gate:
  defeats an AI agent / normal user and makes a forced stop tamper-evident, never claims
  to stop root. Phase 1 here ships only the design doc + command-line secret redaction.
- Secret redaction runs at capture time, before hashing (the chain is immutable, so a
  leaked value can't be scrubbed later). It redacts the value span and keeps the command
  verbatim with a `[redacted]` marker — resolving spine #3 (verbatim) vs #6 (no secret
  values). Conservative by design (over-redact rather than leak); program-gated `-p`/`-u`
  to avoid mauling `mkdir -p`/`ps -p`; no regex dep (manual scan, hot-path safe).
- Passive recording stays userspace (rc preexec hook + the $PATH shim) per "no kernel
  code"; auditd `-e 2`/eBPF is the root-backed floor we integrate with, not reimplement.
  Recorder is fail-open for availability (never halt a DB host like auditd's disk-full
  default) and records a signed gap-marker rather than silently dropping events.
