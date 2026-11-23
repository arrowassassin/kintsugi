# Changelog

All notable changes to Kintsugi are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- **`kintsugi stop` fails loudly instead of silently succeeding.** With no
  daemon running (and nothing else to stop) it printed "the daemon is not
  running." and exited 0, so a scripted `kintsugi stop` reported success while
  stopping nothing — and with a locked vault but no terminal it exited 0 over a
  refused password gate. Every refused or nothing-to-stop path now explains on
  stderr and exits non-zero: `no daemon is running — nothing to stop`,
  `stop refused — nothing was stopped`, and the daemon-side wrong-password
  refusal too. The paths that do real work keep their exit-0 success: a
  running daemon → authenticated shutdown, and the backstop-watcher /
  stale-PID cleanup. The stop tests are now hermetic against the host's real
  vault (`KINTSUGI_VAULT` → absent), so a provisioned dogfooding machine no
  longer fails the suite.

## [0.3.0] — 2026-06-22

Phase 6: **provenance** — a pure taint model with the "lethal trifecta"
(untrusted content → sensitive read → egress sink) wired into the decision loop
as an escalation-only class floor — the **desktop Control Room** app, and a
hardening pass from the review panels. Bundles everything since 0.2.1.

### Security fixes
- **Here-doc bodies are redacted before they can reach the log.** A secret
  pasted through `bash <<EOF … AWS_SECRET_ACCESS_KEY=… EOF` used to land
  verbatim in the append-only (unscrubbable) event log — the gap the 0.2.1
  hardening consciously deferred. `redact_command` now segments here-docs
  (`<<DELIM`, `<<-DELIM`, `<<'DELIM'`, `<<"DELIM"`, here-strings `<<<word`)
  before tokenization and runs the same token passes inside bodies, one body
  line at a time (a here-doc fed to a shell is a script, so the
  program-gated passes fire with each line's own program, and a stray quote
  can only swallow its own line). The operator + delimiter stay verbatim,
  text outside bodies is byte-identical to the prior redactor
  (regression-locked and property-tested), and an unterminated body is
  redacted to end-of-input. The user still sees the raw command at warn time;
  only the stored log row is redacted — the existing model, unchanged. Still
  out of scope, honestly: sub-prompt secrets (`psql` → `\password`) and novel
  flags.
- **Taint `source_id` is redacted before it can reach a log row or the model.**
  A provenance source identifier is meant to be an identifier only, but a URL is
  an identifier that can carry a credential (`https://u:tok@host/p`, a colonless
  PAT-as-username, `?api_key=…`). Untrusted content observed from such a URL
  would have written that secret into the taint label — and, with durable taint
  (below), into the append-only (unscrubbable) event log and the agent-facing
  provenance trail. The daemon now normalizes every taint event at the single
  ingest boundary (`apply_taint`) — *before* it is persisted or applied — running
  the `source_id` through the command redactor (`redact::redact_source_id`) so
  only the secret-free form is ever stored, logged, replayed, or surfaced. Plain
  paths and tool names pass through verbatim; the pass is idempotent (safe across
  log replay).

### Provenance (Phase 6)
- **A pure taint/provenance model with the trifecta truth table (P6.1).** New
  `kintsugi-core::taint`: `SourceKind`, `TaintLabel`, `TaintSet`, `TaintStore` —
  an event-sourced model of what a session has ingested (web fetches, downloads,
  MCP output, out-of-workspace reads, the clipboard, search results) and a truth
  table for the lethal trifecta: a tainted session + a sensitive read + an
  egress sink. Pure, no I/O, unit-tested.
- **The trifecta is a class floor in the decision loop (P6.3).** Taint state
  composes with the leg predicates under `decide()`: a command from a tainted
  session that reads something sensitive and reaches an egress sink escalates —
  it can raise a class, never lower one. The same escalation-only rule as every
  other overlay.
- **Durable taint (item D).** Information-flow taint now survives a daemon restart.
  Each taint transition is persisted to an append-only `taint_events` stream and
  replayed on `Daemon::open` to reconstruct `TaintState`, closing the
  fail-open-on-restart gap that the trifecta guard documented (a `kintsugi stop` /
  watchdog relaunch no longer silently clears taint). `apply_taint` is now
  persist-then-apply (best-effort persist; never panics, never drops live-session
  protection). New `EventLog::record_taint_event` / `load_taint_events`.
- **Content-tool observation (P6.2).** The hook layer now sees the moment an agent
  ingests untrusted content — a web fetch, a search, an MCP tool result, a read of
  a file outside the workspace, a `curl`/`wget`/`git clone` — not just shell
  commands. These previously "passed through silently"; now they are normalized to
  an `ObservedIngest` and reported to the daemon, which taints the session. So a
  later command that reads a secret and reaches an egress sink is caught by the
  trifecta even when the untrusted content arrived through a non-shell tool.
  Observation **never blocks** (it only labels) and is best-effort (a parse miss,
  an untracked session, or a down daemon never affects the agent). The trust
  boundary is the workspace: an in-repo read is trusted (no false-positive taint),
  an out-of-workspace read is not. Works across the tool-style dialects
  (Claude/Qwen/Gemini/Codex/Copilot/Antigravity) and MCP calls.
- **Agent-facing deny reasons + negotiation circuit breaker.** When the gate
  blocks a command, the agent now gets a crisp, state-grounded reason plus the
  instruction to *retreat to a materially safer alternative or stop and ask the
  user* — so most prompt-injection attempts self-correct inside the agent loop and
  the human is never interrupted. A circuit breaker trips after
  3 consecutive blocks in a session and tells the agent to stop retrying and
  escalate to the human. This is a UX layer, not the security mechanism: it is
  decision-preserving (it only reframes a block, never turns one into an allow) and
  the gate holds regardless. Safety invariants enforced: a re-proposed command is
  re-classified from scratch and the reason text is never an input to the allow
  path; the reason is redacted (no credential can leak into the negotiation
  channel); and the audit log keeps the clean rule reason, not the model-facing
  instruction.
- **Provenance trail over IPC (P6.4).** The daemon can now produce the
  human-readable provenance chain for a command — the session's untrusted reads →
  this command's sensitive read → egress sink → the trifecta rule that fired — and
  exposes it over IPC (`Client::provenance`) for the CLI/TUI to render on a held
  trifecta and for forensic replay ("everything descended from source X"). A clean
  session has an empty trail; identifiers only, never secret contents.
- **`kintsugi provenance` (P6.5, CLI).** A new command renders a session's taint
  provenance — and, given a command, the full trifecta chain — as calm, labelled
  lines (every step paired with a word, one accent reserved for the rule that
  fired; `NO_COLOR` respected; a designed empty state). Docs: new
  [`docs/provenance.md`](docs/provenance.md) and a `[provenance]` block in
  [`docs/policy.md`](docs/policy.md).
- **TUI: trifecta tag.** The detail pane names a taint-driven block ("lethal-trifecta
  block — untrusted content reached a sink"), so a provenance hold reads as such.
- **The engine catalogs its own watch-lists.** The Rules view shows exactly which
  ingest channels taint a session and which egress programs are watched, sourced
  from the engine itself (`egress_channels()` / `untrusted_sources()`, locked by
  tests) so the displayed lists can never drift from what fires. The provenance
  rail lists only sessions where a trifecta rule actually fired — a clean session
  shows the calm empty state instead of one falsely labeled "carries a label".

- **TUI: provenance trail on Detail (Phase 6 V1.1).** Opening a held trifecta's
  detail view now fetches the live trail from the daemon and renders it below the
  event's own facts — the same grammar as `kintsugi provenance`: glyph + word per
  step (`↓ untrusted read`, `• sensitive read`, `→ egress sink`, `⛔ rule fired`),
  the tainted/clean state as words, the one danger accent reserved for the rule
  that fired, `NO_COLOR` honored, and a designed empty state ("nothing to trace
  for this session") for clean sessions. A down daemon degrades honestly: a
  one-line notice, with the event itself still rendered from the log.

### Desktop Control Room (new app)
- **A native desktop app, all Rust, engine in-process (Dioxus-desktop).** The
  Control Room runs the engine in-process — same live log, no extra daemon. It
  began this release as a Tauri host with a Dioxus/WASM frontend and was rebuilt
  mid-release as a pure Dioxus-desktop app (`desktop-dx/`, its own workspace:
  no web bundler, no npm, no Trunk step). Screens: **Dashboard** (metric cards +
  held alert + recent activity), **Live feed** (filter + select → details
  drawer), **Held queue** (one-key allow/deny; held catastrophic commands are
  runnable from the app), **Audit log** (search + hash-chain verify badge),
  **Settings** (real toggles), plus toast notifications and a system-tray
  status indicator. A first-run **setup wizard** (password → optional model →
  initialize) with an always-available help cheatsheet.
- **`kintsugi-app` + `kintsugi-app-types`** — the data-binding engine that
  shapes the daemon's IPC replies and the read-only event log into small,
  `serde`-serializable view-models (timeline, audit search, metrics, hash-chain
  verify, queue, the P6.4 provenance trail, status), and the wasm-safe,
  compiler-checked data contract shared by the engine and the frontend. It
  performs no decisions and adds no egress; identifiers only, never secret
  contents.
- **Live model management in the app:** Hugging Face model search + in-app
  download, real local-model selection with an honest scorer state, and picking
  a model auto-restarts the daemon to load it. `kintsugi model rm <name>`
  deletes a downloaded GGUF from disk.
- **A hook panel** showing exactly which agent CLIs are wired (per-agent
  enable/disable + refresh), a recorder summary in the UI, and a gated shell
  hook.
- **Self-install + `kintsugi install-desktop`.** The app registers itself at the
  OS level (macOS `.app` bundle with Info.plist + `.icns`, Linux `.desktop`
  entry + hicolor icons, Windows Start-menu shortcut); `kintsugi
  install-desktop` drives it from the CLI; and `cargo install kintsugi` +
  `kintsugi init` completes the desktop app too (offered, built if absent,
  skipped on headless hosts or with `--no-desktop`). A tag-triggered desktop
  release workflow (`release-desktop.yml`) packages `.dmg` / `.deb` / `.msi`
  beside SHA256SUMS.
- **New `kintsugi uninstall`** — cleanly remove Kintsugi: stop the daemon,
  strip the agent hooks (Antigravity's whole plugins subtree included), remove
  the shim dir. Password-gated when provisioned; the audit log is kept.

### CLI & daemon hardening (review-panel fixes)
- **CodeQL critical resolved: no hard-coded nonce sentinel.** The desktop's
  no-vault shutdown call passed `""` as nonce/proof; absence is now modeled as
  `Option` (never an empty string), so no placeholder ever reaches the crypto
  path. The release workflows were hardened for the audit.
- **Ambiguous holds are never orphaned.** Holds enqueue only when the surface
  genuinely needs a human: catastrophic always, ambiguous only for agents with
  **no** native ask — the predicate was inverted so an unknown agent defaults
  to enqueued rather than silently dropped. A new `PrunePending` IPC clears the
  acknowledged-orphan backlog in one step. The audit log keeps the full record
  either way.
- **`kintsugi ingest --gate`** — a pre-exec gate for the recorder: classifies
  the command synchronously, describes it (with the local model's summary), and
  for the ambiguous band asks y/N via `/dev/tty` before it runs (exit 0 =
  allow, 1 = deny; catastrophic always declined — re-run via `kintsugi run`).
  On a daemon outage or with no TTY it falls back to passive recording, so the
  gate never breaks a normal shell.
- **Self-protection floor:** `cargo`/`brew`/`npm`/`pip` `uninstall kintsugi`
  (and friends) are classified as dangerous — an agent can't talk the rules
  into uninstalling the safety layer.
- **The admin vault is read fresh per privileged op** — no more stale-cache
  lockout after `admin change-password`.
- **Recorder scoring is DoS-bounded.** Model-scoring of risky recorder events
  runs under a token bucket (burst 8, steady 4/s); under a flooded socket the
  row is recorded without its prose instead of starving the serve loop — the
  audit record and the danger class always land, and the hold/approve path is
  untouched.
- **Zero-byte liveness probes are no longer logged as connection errors.**
- Fixes: the model no longer "vanishes" after a restart (the installed daemon
  is preferred over a repo build), wrong/stale metrics, a stuck chain-verify
  state, and the Antigravity uninstall path (the live hook was left behind).

### CI
- Coverage excludes CI-unexercisable desktop/teardown paths from the line floor
  (documented in the job, not silent), and a Unix-absolute-path observe test is
  gated `cfg(unix)` so Windows stays green.

## [0.3.1] — 2026-11-22

The org move reaches every public surface — this project now lives at
`kintsugi-tools/kintsugi` — plus the desktop/release fixes that accumulated
since 0.3.0. No feature changes.

### Changed
- **Repository, homepage, and package metadata moved to the `kintsugi-tools`
  org.** Repository and homepage URLs (now https://kintsugi.tools), the CLI's
  `UPDATE_REPO` constant and its printed release/issues URLs, crate README
  links, tap references, and the plugin manifests' contact email; the version
  bump to 0.3.1 is what publishes the new metadata to the package index.
- **The website moved out of this repo** (it now lives in
  `kintsugi-tools/website`); the tree here is code + docs again.

### Fixed
- **The desktop release workflow was fixed for real runs:** the publish job no
  longer trips `sha256sum` on per-target directories; Windows builds stop
  dying on Defender locking a just-linked `.exe` (workspace excluded from
  real-time scanning); Linux desktop builds install `libxdo-dev`; macOS-Intel
  `.dmg`s are cross-built on the arm64 runner; the `.app` bundle is ad-hoc
  signed, so a quarantined download prompts "unidentified developer" instead of
  reading as "damaged"; and a duplicate `kintsugi-daemon` bin that broke Windows
  release links (LNK1104) was dropped.
- **Installer coherence:** `cargo install` and `install.sh` now target the
  same bin dir — an existing install is updated in place, and a second copy in
  another standard dir is flagged, so the two install methods never leave
  shadowing suites on `PATH`.
- **Desktop fixes:** the setup wizard's final step enables Kintsugi on all
  detected agent CLIs; the unlock screen is skipped when no vault is
  provisioned; `kintsugi uninstall` removes the desktop app too and resets the
  admin password + settings (audit data kept).

### Security fixes (release hygiene)
- **The audit log's storage engine no longer carries a known CVE.**
  `rusqlite` 0.40.1 → 0.41.1 pulls `libsqlite3-sys` 0.38.1 → 0.39.1, whose
  bundled SQLite 3.54.1 clears **RUSTSEC-2026-0459** (opening a database
  beside a crafted sibling WAL file of differing page size could return
  uninitialized page-cache memory; CVSS 4.0 Medium 6.8). The hash chain is
  app-level SHA-256 and unaffected — verified by re-running the full chain,
  corpus, daemon, and latency suites, which recompute every row hash under
  the new engine.

### Build & CI hygiene
- **CI runs the declared MSRV, not a floating stable.** All three CI jobs are
  pinned to the workspace `rust-version` (1.96.0) so CI, local dev, and the
  declared minimum all run the same compiler. The pin that previously failed
  purely on toolchain drift (CI run #205: a `duplicated_attributes` lint newer
  clippy emits and 1.96 does not) reproduces green, and the drift findings were
  root-caused in code, not suppressed: one duplicated `#[allow]` and two dead
  manifest entries (unused workspace dep `kintsugi-app`; unused direct dep
  `anyhow` in `kintsugi-core`) were removed.
- **CI now gates on `cargo audit`.** A failing RustSec advisory step reads
  `Cargo.lock` on every run. Advisories confined to the opt-in
  `llama`/`download` backends — compiled neither by CI nor by the release
  binaries — are individually recorded in `.cargo/audit.toml` with that
  scoping rationale; any NEW advisory anywhere fails the build until a
  human decides. Unsound advisories (upstream code properties) print but
  do not fail.

### Anchored trust (Phase 7)
- **Public chain-head export (T1.1).** `EventLog::chain_head()` exposes the
  logical head — `(latest_seq, head_hash)` — as a single atomic read through the
  SQLite connection; `(0, GENESIS_HASH)` when the log is empty. This is the
  primitive the upcoming `kintsugi anchor export` will checkpoint. The read is
  deliberately never a hash of the database file: under WAL a recently committed
  row can live only in the `-wal` sidecar, so the file bytes can lag (or entirely
  miss) the logical head. Taint events remain deliberately outside the hash chain
  and never move the head.
- **Anchors table + no-fork guard (T1.2).** A new append-only `anchors` table
  records exported chain-head checkpoints (`EventLog::record_anchor` /
  `latest_anchor`, new `Anchor` type; the `sig` column exists but stays NULL until
  checkpoint signing lands, so the schema does not churn twice). The C2SP
  transparency-log invariant — never record a checkpoint inconsistent with one
  previously recorded — is enforced with no exceptions: a lower seq or a
  same-seq-different-head is refused with `LogError::Fork`; an identical
  `(seq, head)` is idempotent. Purges rebuild the events chain, but the
  `audit:purge` marker is appended above every seq ever used (AUTOINCREMENT never
  renumbers or reuses), so an honest post-purge re-anchor always passes the guard
  — continuity is never faked, and a lower seq can only mean a restored or
  rewritten log, which is refused loudly. Existing databases migrate in place
  (`CREATE TABLE IF NOT EXISTS`, the session-column-migration style), and anchor
  code never touches the events table.
- **Checkpoint signing (T1.3).** `kintsugi_core::anchor` signs the exported
  checkpoint without adding any new secret at rest: the signing key is
  derived per operation from the admin vault's (password, `auth_salt`, KDF
  params) — the exact derivation the admin proof uses — and only the
  verifying public key travels, as the checkpoint's `key_id` (hex), making
  checkpoints self-certifying: anyone holding the vault file, or the
  checkpoint itself, can verify. Signatures cover a new protocol-separation
  label (`kintsugi.log.anchor.v1`, distinct from the admin proof's context),
  so an anchor signature can never be replayed as a "password to stop" proof
  and vice versa. The signed bytes are a tiny canonical JSON body
  (RFC 8785-ordered keys, no whitespace, `seq` as a decimal string so no
  IEEE-754 precision loss is possible), byte-for-byte pinned by test and
  cross-checked against `serde_json` on hostile input. A changed `key_id`
  means the vault was re-keyed; older checkpoints keep verifying under their
  recorded `key_id` (the rotation story: a new anchor series, never a
  break). A wrong password derives a different key, so a mistyped export can
  never attribute an anchor to the real key — and the export path verifies
  the password against the vault before recording (T1.4).
- **Anchor export/verify/status (T1.4).** Users get the other half of the
  guarantee: `kintsugi anchor export [--out FILE] [--origin ID] [--no-sign]
  [--password-file FILE]` writes a signed checkpoint of the current chain head
  and records it, and `kintsugi anchor verify [--checkpoint FILE]` checks the log
  against it with five distinct verdicts and exit codes — `0` INTACT, `1` STALE,
  `2` TAMPERED, `3` does-not-verify, `4` UNVERIFIABLE — so a script can tell a
  normal append from a rewrite without parsing prose. Verification reads only the
  log file (never the daemon) and makes no network call: the export holds the
  receipt, the user decides where it lives. An export is refused outright (nothing
  written, nothing exported) when its head falls behind the last recorded anchor;
  an unprovisioned or unreadable vault yields an honestly UNSIGNED checkpoint
  rather than a silently weaker one. A purge rechains, so the next anchor records
  the new head with the `audit:purge` row preserving the why — `verify` reports
  that honestly as TAMPERED (the anchored head is no longer at its seq) rather
  than as a pass. `kintsugi status` grows `anchored: <ts> (N events ago)` once any
  anchor exists. The signed-bytes fixed point is a whole-second RFC3339 timestamp,
  so a recorded anchor row rebuilds exactly the bytes that were signed instead of
  storing a second copy of the file. What this buys and what it does not is
  documented in [`docs/anchoring.md`](docs/anchoring.md): evident tampering to
  whoever holds a copy, never tamper-proofness, and no claim about a machine you
  never verify on.

## [0.2.1] — 2026-06-17

Pre-rollout security & robustness hardening from an audit. No new features —
this release closes a catastrophic-classification bypass, strengthens the admin
auth proof, and makes several failure modes fail closed or fail loud instead of
silent.

> **Upgrade note:** the admin vault scheme is bumped to v2 (asymmetric auth
> proof). A pre-v2 vault has no stored public key, so password-to-stop/unlock
> proofs fail closed until you **re-run `kintsugi admin provision`** after
> upgrading. Existing settings are unaffected; only the stop/unlock proof needs
> the new key material.

### Security fixes
- **Closed a catastrophic-as-SAFE `git -c` bypass.** An inline
  `git -c core.pager='rm -rf /' log` (and `git --config-env=…`) was read as a
  plain `git log` — the `-c <key=value>` pair was skipped by subcommand
  detection — so the injected pager/ssh/alias/hook ran arbitrary code on the
  SAFE fast path. Inline exec-config injection is now hard-blocked before the
  subcommand is dispatched, and is never classified safe (defense in depth). The
  exec-key set also gained `core.hooksPath` and `*.insteadOf`.
- **Catastrophic flags now match GNU `--flag=value` form**, so
  `rm --recursive=true /etc` and `git push --force=please` are no longer a
  bypass.
- **Asymmetric (ed25519) admin auth proof.** The v1 "password to stop/unlock"
  proof was a symmetric tag keyed by the verifier — which is *stored in the
  vault* — so anyone who could read the vault file (a same-user agent) could
  forge a proof without knowing the password. v2 derives an ed25519 key from the
  password and stores only the public key; the private seed is never persisted.

### Robustness fixes
- **Audit log failure fails closed.** If a command can't be written to the
  append-only log, the daemon now downgrades an Allow to Deny rather than letting
  it run unrecorded (spine #4).
- **`kintsugi resume` (kill-switch clear) is now password-gated** like `stop`
  when a vault is provisioned; engaging the kill-switch stays ungated.
- **Atomic undo restore.** `restore` stages each path to a temp sibling and
  rename-swaps it into place (rolling back on failure), so an interrupted undo
  can't leave a path half-written.
- **Honest reversibility warning.** An allowed destructive command whose target
  couldn't be snapshotted (or can't be fully captured) now carries a `⚠` note in
  its verdict instead of implying a clean undo.
- **Backstop degradation is surfaced, not silent.** A failed per-root watch, an
  OS event-queue overflow, or a watch-stream error now records a
  `backstop-degraded` marker on the timeline.
- **Split-brain guard.** A second daemon refuses to start if one is already
  reachable, so two writers can't race on the hash chain.
- **Windows confirm reads the real console.** The interactive run-confirmation
  prompt reads from `CONIN$`/`CONOUT$` (the physical console), not stdin (which
  the agent controls), failing closed when no console is attached.
- **Quiet session recorder.** The shell recorder hook now runs its
  fire-and-forget `kintsugi ingest` inside a detached subshell, so interactive
  shells no longer print job-control notices (`[1] 12345` / `[1]  + done …`)
  after every command. Re-run `kintsugi record install` to refresh the snippet
  in your rc file.

### CI / tests
- The latency gate now asserts the **median (p50) < 10ms** instead of a brittle
  mean < 1ms that a single CI scheduler hiccup could trip.
- The coverage job is renamed and documented honestly: **line coverage is gated**
  (floor = below-target regression guard), **branch coverage is tracked, not
  gated** (it needs a nightly toolchain).

## [0.2.0] — 2026-06-17

First minor release: the protection is now visible and trustworthy, the backstop
is on by default (and quiet), enterprise hosts can lock the wiring out of a user's
reach, and Google Antigravity joins the supported agents. Bundles everything that
accumulated since 0.1.x (the `kintsugi model` command, dry-run, limits, guard,
enforce-shell, the TUI overhaul, and the real-world update/backstop fixes).

### Google Antigravity support
- **`kintsugi init` now detects and wires Google Antigravity** like the other
  agents. It installs a native `PreToolUse` plugin hook at
  `~/.gemini/antigravity-cli/plugins/kintsugi/hooks.json` (matcher `run_command`),
  so destructive commands are classified before they run, and prints the
  `mcpServers` entry to add to `~/.gemini/config/mcp_config.json` as the MCP
  fallback. A new `antigravity` hook dialect parses Antigravity's
  `toolCall.arguments.CommandLine` payload and answers `{decision: allow|deny}`
  (no native "ask" — an ambiguous hold maps to deny, per the monotonic-caution
  rule). Detection uses Antigravity's own `~/.gemini/antigravity-cli` subtree, so
  it's distinguished from a plain Gemini CLI install that shares `~/.gemini`.

### Fixes from real-world use
- **Version reporting fixed.** The crate version is bumped to `0.2.0`; an earlier
  tag (`v0.1.4`) was cut without bumping it, so the binary self-reported a stale
  version and `kintsugi update` would offer the "new" release forever. `kintsugi
  update` now
  **verifies** the result: it warns if the freshly-installed binary reports the
  wrong version (a release built without a bump) or if another `kintsugi` shadows
  it earlier on your `PATH` — instead of silently looking like a no-op.
- **The backstop watcher is far quieter.** It now records only the *destructive*
  filesystem signals it exists to catch — **deletions and renames** — and skips
  file creates and content saves (the bulk of a working tree's churn, already
  covered by interception + snapshots for agent writes). It also ignores
  build/VCS/cache trees (`.git`, `node_modules`, `target`, `dist`, …) and editor
  scratch files. This keeps the append-only log to signal, not noise.
- **The TUI separates the backstop from the timeline.** `fs-watch` observations
  now live in their own **Backstop** tab (press `4`) instead of flooding the
  Timeline, which is now agent + human command activity. ("fs-watch" is the
  filesystem backstop `kintsugi init` starts — see `kintsugi limits`.)

### Make the protection visible and trustworthy
- **`kintsugi dry-run`** — point Kintsugi at commands you've already run (your
  shell history by default, or `--file <path>` / piped stdin) and see which would
  have been held or blocked. It runs nothing, logs nothing, and sends nothing;
  flagged commands are secret-redacted before display. The proof-before-trust
  command — see Kintsugi's value against your own work before wiring it in.
- **`kintsugi limits`** — the honest threat scope in plain English (seatbelt, not
  a kernel firewall): what it protects well, what can step around the warning,
  what undo can't bring back, and what the admin-lock does and doesn't stop.
- **`kintsugi status` saves counter** — surfaces what Kintsugi has done for you
  (catastrophic flagged · ambiguous held · reversible snapshots).

### Default-on reversibility backstop + honest drift detection
- **The filesystem-watcher backstop is now on by default.** `kintsugi init` starts
  it for your work tree, so changes that bypass interception — an agent in an
  auto-approve mode, or a tool called by absolute path like `/bin/rm` — are
  recorded for the audit trail. Opt out with `--no-watch` (or `KINTSUGI_NO_WATCH`);
  set the scope with `KINTSUGI_WATCH_DIR`. `kintsugi stop` tears it down.
- **`kintsugi status` states the backstop plainly** (watching `<root>` / off) and
  **warns loudly when the shim dir isn't on `PATH`** — a hand-edited or reverted
  shell profile no longer silently leaves raw shell-outs unguarded.

### Enterprise: shell wiring a normal user can't remove
- **New** `kintsugi admin enforce-shell` — install the shim PATH wiring in
  **root-owned system files** (Unix: `/etc/zshenv` and `/etc/profile.d/kintsugi.sh`
  or `/etc/profile`; Windows: the machine-level PATH) so a normal user cannot
  disable Kintsugi by editing their own `~/.bashrc`. Install needs sudo /
  Administrator; `--remove` needs root AND the admin password. `--status` shows
  where the wiring lives and whether the files are actually root-owned.
- `kintsugi status` now reports `shell: enforced system-wide` when the wiring is
  locked in, and the enterprise-init guidance points to the new command.
- Honest scope (also in `kintsugi limits`): this stops a normal user (or an agent
  running as them); it does NOT bind root, who can edit those system files directly.

### `kintsugi guard` — launch an agent with interception forced on
- **New command** `kintsugi guard <command…>` (e.g. `kintsugi guard claude`).
  Forces the shim dir to the front of the launched child's `PATH`, so even an
  agent in an auto-approve / "yolo" mode has the commands it runs by name hit the
  gate; ensures the daemon is up; and forwards the child's exit code (and
  terminating signal, on Unix) faithfully. Honest scope: a tool invoked by
  absolute path still bypasses the shim — the default-on backstop is the net there.

### TUI — an enterprise-grade timeline
- **Local time + dates.** Timestamps render in your local timezone (events are
  stored in UTC), with a day-grouped date column so a run of same-day rows reads
  as one block, and a full, offset-qualified datetime in the detail pane.
- **Visible scrolling & paging.** A scrollbar appears on the right border when the
  list overflows, and the footer shows both row and page position (`row 42/830 ·
  pg 3/40`).
- **Tab count badges** (`Timeline 83 · Audit 12 · Recorder 40`) and clean command
  ellipsis instead of hard-clipping. Still NO_COLOR-safe, single-accent, and
  reflowing at any size.

### `kintsugi model` — manage the local model from the CLI
- **New command** `kintsugi model status | use <path> | pick | install | remove`.
  `use` points the daemon at any local GGUF (swap models anytime, no Kintsugi
  update); `install` builds the inference engine **and** downloads a model in one
  step — the path `cargo install` users take; `status` diagnoses the common
  "model set but still heuristic" mismatch (a daemon built without the engine).
- **Persisted selection.** The chosen model path is written to `model.path` in the
  data dir, and the daemon's `LlamaScorer::autoload` reads it after the
  `KINTSUGI_MODEL_FILE` env override — so a downloaded model now takes effect
  across restarts **without** depending on a shell env var (the bug where a model
  set up by the installer didn't load on `kintsugi init`). `model use`/`pick`/
  `remove` restart a running daemon so the change applies immediately.
- **Fix: MCP binary name.** The consolidated `kintsugi` crate's MCP server binary
  is `kintsugi-mcp` (was briefly `kintsugi-exec`), matching the release archive,
  the installer, `kintsugi init` wiring, and the plugin config — fixes
  "binary kintsugi-mcp missing from archive" on install.
- **Fix: a corrupt/half-downloaded model silently fell back to heuristic.** The
  picker treated any non-empty file as "already downloaded" and wrote directly
  to the final path, so an interrupted download left a truncated GGUF that was
  never re-fetched and that `llama.cpp` then failed to load. `pick-model.sh` now
  downloads to a temp file, verifies the GGUF magic + expected size, only moves
  it into place on success, and cleans + re-fetches a corrupt existing file.
  `kintsugi model status` / `use` flag a configured file that isn't a valid GGUF
  so the failure is visible instead of a silent heuristic fallback.
- **Fix: installer built the wrong crate for the model.** After the binary
  consolidation, `install.sh` still rebuilt `kintsugi-daemon` (now a library-only
  crate) for the llama engine and built `kintsugi-cli`/`kintsugi-intercept` from
  source — so the model engine was never produced and the daemon stayed
  heuristic. The installer now builds the `kintsugi` crate (`--bin kintsugi-daemon
  --features llama` for the engine; the whole crate for a source install). The
  `kintsugi` crate gained `llama`/`download` features that forward to
  `kintsugi-model`.

### Enterprise TUI overhaul + brand (phase A4)
- **Tabbed views** — `Timeline` (everything), `Audit` (destructive-only lens), and
  `Recorder` (passively-recorded human shell sessions), switched with `Tab`/`1`/`2`/`3`;
  each is the same live log sliced a different way. A header **vitals strip** shows
  global counts (events / held / catastrophic) and daemon+scorer health, all worded so
  nothing depends on color.
- **Animated launch splash** — the `KINTSUGI` wordmark fills left-to-right with kintsugi
  gold (a `░`→`█` glyph sweep without color, so the motion never depends on the palette),
  under a Unicode rendition of the brand mark. Any key skips it.
- **Password login gate** — when the settings vault is locked, the TUI requires the admin
  password (masked, constant-time verified) before showing the app; the password is held
  zeroized for the session.
- **In-app settings panel** — `s` opens a control panel that lists the locked settings and
  toggles them (re-sealing the vault under the held password, persisted atomically). Every
  row is a *tightening* control — none can loosen the catastrophic floor.
- **Brand mark** — a dark tile rejoined by a golden kintsugi seam (`site/logo.svg`,
  `site/logo-mark.svg`), the repair-as-beauty metaphor, used on the web, the README, and
  (as Unicode) the TUI splash.

### Passive session recorder (phase A3)
- **`kintsugi record install`** prints a bash/zsh preexec hook; **`kintsugi ingest`** records
  each command a human runs (no AI-agent hook) onto the same tamper-evident chain — classified
  so a destructive command is flagged, but always `Allow` (it already ran; the recorder never
  holds/denies/snapshots). For DBA/operator audit + compliance.
- Ingest is **fire-and-forget** (never fails the shell) and **spools** to disk when the daemon
  is down, draining on the next ingest so a brief outage doesn't punch a hole in the trail.
- **`kintsugi report`** surfaces the destructive commands (catastrophic + ambiguous) for review.
- Recorded commands pass through **redact-before-hash**, so a `mysql -p…` a DBA types never
  enters the audit log in the clear.

### Admin settings management (phase A4, CLI)
- **`kintsugi admin settings`** / **`kintsugi admin set <key> <value>`** view and change the
  sealed settings (password-gated; `--password-file` for config management). Toggling
  `autostart` installs/removes the OS supervisor, so the flag drives a real action.

### Admin settings + audit recorder (phase A2)
- **`kintsugi admin`** provisions a password-locked, sealed settings vault;
  **`kintsugi stop` now requires the admin password** when locked (Unprovisioned
  proceeds, Degraded refuses - fail-closed). Defeats an agent/casual user; a root
  `kill` still wins.
- **`kintsugi service install`** runs the daemon under systemd (Linux) / launchd
  (macOS) with **auto-restart**, so a `kill`/`pkill` relaunches it within seconds;
  `service uninstall` is password-gated. This + a dedicated system account is what
  makes the lock real against `pkill`.

### Admin settings + audit recorder (phase A1)
- **Locked-settings crypto core** (`kintsugi_core::admin`): argon2id password
  verifier + XChaCha20-Poly1305 sealed settings with a one-time recovery key, the
  foundation for password-locked admin config and "password to stop". Verifier and
  sealing key are domain-separated; KDF params are pinned + versioned; AEAD uses a
  random 192-bit nonce per seal with context-bound AAD; derived keys are zeroized.
  `change_password` rotates everything (an exposed old recovery key dies). 8 tests.

### Admin settings + audit recorder (design + phase 1)
- **Design doc** ([`kintsugi-admin-recorder-design.md`](kintsugi-admin-recorder-design.md)) for two
  upcoming capabilities — password-locked encrypted settings (admin-provisioned; stopping/
  unhooking Kintsugi requires the password when locked) and passive human-shell session recording
  for enterprise/DBA audit. Folds in a 6-engineer design roundtable and a ~13-stream market /
  filesystem-technology research sweep (cited). Headline finding: *record + per-command
  filesystem revert + tamper-evident audit* is unbuilt as a shipping product (closest: a Dec-2025
  AI-agent sandbox paper and a 2003 "Undo for Operators" paper); flags a same-named academic
  "KINTSUGI" project to deconflict from, and the honest "never reversible" list.
- **Command-line secret redaction** (`kintsugi_core::redact`) — the launch-blocker for any audit
  recorder. Redacts the *value span* of credentials on a command line (DB connection strings,
  `mysql -pSECRET`, `PGPASSWORD=…`, `--token=`/`--api-key=`, `Authorization: Bearer …`,
  `curl -u user:pass`) before a command is hashed into the append-only log, keeping the rest
  verbatim and leaving a `[redacted]` marker. Conservative, no I/O, hot-path safe — so the audit
  log can't itself become a credential leak (the documented failure of auditd/tlog).

### Security assessment + hardening
- **Enterprise stress & vulnerability assessment** ([`docs/security-assessment.md`](docs/security-assessment.md),
  published at the site's *Security* page). Measured, reproducible: 0 / 176
  dangerous commands leak to Safe across a MITRE ATT&CK + GTFOBins corpus, 1.4M
  fuzz inputs with no panic/abort, 0 known CVEs (`cargo audit`, 436 deps), 0
  `unsafe` in first-party crates, 88.6% line coverage. New campaign suites:
  `security_stress`, `robustness_fuzz`, `perf_report`.
- **Fixed a heap-exhaustion DoS** the fuzzer found: a 23-byte malformed
  here-operator line (`)x<< .env$( (.envfiEOF`) made `brush-parser` attempt a
  ~1.75 GB allocation and abort the process — a daemon-crashing denial of service.
  Here-operators (`<<`, `<<<`, …) are now neutralized before parsing so the parser
  never enters the vulnerable reader; substitution detection is preserved (a
  `$(…)`-hidden catastrophe is still caught), and here-strings are caught by the
  tokenizer pass. Ten pathological inputs are regression-locked and bounded.
- **Broader secret-directory coverage:** reads/copies/archives of the secret
  *directories* themselves (`tar czf x ~/.ssh`, `sort ~/.aws/credentials`) are now
  caught, not just files within them.

### Classifier — AST-backed danger detection
- **Real bash AST analysis, not substring matching.** The Tier-1 classifier now
  runs two passes worst-wins: the existing hand-rolled tokenizer **and** a true
  bash AST parse ([`brush-parser`](https://crates.io/crates/brush-parser),
  pure-Rust, MIT). The AST pass flattens the line to the simple commands it would
  run — descending into command substitutions `$(…)`/backticks, here-docs fed to
  a shell, subshells, brace/process substitutions, `if`/`for`/`while`/`case`
  blocks, and function bodies — so danger hidden in shell structure is caught.
  The AST can only ever *add* caution; it never downgrades a tokenizer verdict.
- **`kintsugi test "<command>"`** — a dry-run classifier. Prints the class, the rule
  that fired, what would happen, and the exact commands Kintsugi parses out of the
  line, without executing, logging, or contacting anything.
- **Adversarial-review hardening** (5-reviewer roundtable on the new logic).
  Fixes for confirmed catastrophic-classified-as-SAFE holes and a parser DoS:
  - **Background operator `&`** is now a command separator (`true & rm -rf /` was
    classified Safe). Redirect forms `&>`/`>&`/`2>&1` are not mis-split.
  - **Process substitution** `<(…)` / `>(…)` is walked (`grep x <(rm -rf /)` was
    Safe); so are **function bodies** invoked on the same line (`f(){ rm -rf /; }; f`).
  - **`command`/`exec` prefixes** are peeled like `sudo`/`env` (`command rm -rf /`).
  - **`git -C <dir>` / `git -c k=v` global flags** no longer hide the subcommand,
    so `git -C /repo push --force` is Catastrophic, not Ambiguous.
  - **Deeply nested `$(…)` no longer aborts the daemon.** brush-parser can stack-
    overflow (an uncatchable abort) on hundreds of nested substitutions; input
    past a generous nesting/size/operator cap is now refused and classified
    Ambiguous (never Safe). The AST-walk depth guard sets a `truncated` flag that
    also fails toward caution rather than silently dropping a buried command.
  - The fast path that skips the AST parse is now an **allowlist** of provably
    inert lines (plain word/flag/path characters), not a denylist of "interesting"
    characters — closing the class of "one missing operator → Safe miss" bugs.
- **Fewer false positives, broader real coverage** (same roundtable):
  - **Dangerous-looking *text* no longer hard-blocks.** The whole-line SQL /
    curl-pipe / fork-bomb scans are suppressed when every program the line runs is
    an inert text handler (grep/rg/echo/printf/cat/git/diff/…), so
    `grep -rn 'DROP TABLE' src/`, `git commit -m '… TRUNCATE TABLE …'`, and
    `echo 'curl … | sh'` are no longer Catastrophic — while `psql -c 'DROP TABLE'`
    and `curl … | sh` still are (suppression is one-sided: any unknown/executing
    program keeps the verdict).
  - **Block-device writes are detected structurally** — a redirect *target* that
    is a block device (`echo x > /dev/sda`) or `dd of=…` — fixing the
    `cat of=/dev/sda.txt` / commit-message false positives.
  - **Broader secret handling:** a command aimed at a secret path is never
    auto-Safe; more content readers (`sort`/`diff`/`wc`/`tar`/`base64`/…) are
    `secret:read`; a truncating redirect onto a secret is `secret:clobber`; and
    `git config` that *sets* an execution primitive (`core.pager`,
    `core.sshCommand`, `alias.*`, …) is `git:config-exec`.
  - **Decoder-to-shell** joins download-to-shell: `… | base64 -d | sh` (base32 /
    xxd / uudecode / openssl too), not just `curl|sh`.

### Interception
- **Native hooks for every major agent CLI**, not just Claude Code. `kintsugi init`
  now detects and wires Qwen Code (`~/.qwen/settings.json`, `PreToolUse`), Gemini
  CLI (`~/.gemini/settings.json`, `BeforeTool`), GitHub Copilot CLI
  (`~/.copilot/hooks/kintsugi.json`, fail-closed `preToolUse`), Cursor CLI
  (`~/.cursor/hooks.json`, `beforeShellExecution`), Codex CLI
  (`~/.codex/config.toml`, `[[hooks.PreToolUse]]`), and OpenCode (a bundled
  `tool.execute.before` plugin at `~/.config/opencode/plugin/kintsugi.js` that
  bridges to the hook). One binary, `kintsugi-hook --agent <id>`, speaks each CLI's
  dialect; the daemon round-trip and fail-closed-catastrophic policy are shared.
  Each wire-up is idempotent and backs up any file it touches. See
  [`docs/hooks.md`](docs/hooks.md).
- **Fix duplicate log rows.** `kintsugi init` deduped a hook by its *exact* command
  string, so when the command changed (a new binary path, or adding `--agent
  <id>`) a re-run appended a second entry instead of replacing the old one. Two
  registered hooks made the CLI run Kintsugi twice per command and log every command
  2–3×. Registration now matches on the `kintsugi-hook` binary name and collapses
  any stale/duplicate entries to exactly one (settings.json, Cursor hooks.json,
  Codex config.toml). Re-run `kintsugi init` once to clean an already-duplicated
  config.

### Run a blocked command (`kintsugi run`)
- **`kintsugi run <id>`** — run a command an agent hook blocked, yourself and
  reversibly. Kintsugi snapshots the predicted paths, runs the exact command in its
  original directory, records it, and `kintsugi undo` rolls it back. Confirmed by a
  random code typed at the real terminal (`/dev/tty`, not stdin), so an agent
  shelling out to it can't self-approve by pre-stuffing a keypress. Omit the id
  when a single command is held. The catastrophic deny message now names it.
- **Origin-aware approve vs run.** A hook-blocked command is one-shot (no waiter),
  so `kintsugi approve` only records the decision and points you at `kintsugi run`;
  in-band origins (shim / MCP) keep `kintsugi approve` (their waiting caller runs it),
  and `kintsugi run` redirects there to avoid a double-run. `kintsugi queue` shows both.
- **Exactly-once resolution.** Approving/running a held command is an atomic
  compare-and-swap on its queue status, so a racing double `approve`/`run` can't
  double-execute or log a phantom approval.
- **Honest reversibility.** Snapshot prediction is now shell-segment and `cd`
  aware (`cd build; rm -rf ../dist` resolves correctly), and `kintsugi run` tells you
  up front when a target is *unbounded* (glob, `$VAR`, root, device) and a
  snapshot can't fully cover it — leaning on the filesystem-watcher backstop
  rather than over-promising `kintsugi undo`.

### Log & timeline UX
- **Newest-first** everywhere: `kintsugi log` and the live TUI timeline now show the
  most recent command at the top instead of the bottom.
- **Pagination for `kintsugi log`**: `-n/--number` is the page size and `-p/--page`
  picks the page (1 = newest; older events on higher pages). A footer shows the
  range and total (`21–40 of 137`) with `older →`/`newer →` page hints, and
  paging past the end says so instead of printing the empty state. Backed by a
  new `offset` on the core `Filter`/`query`.
- **Richer model summaries**: the Tier-2 model prompt now asks for a plain-English
  explanation plus 2–3 short "• " pointers describing what the command does and
  why it matters — for people who can't read the shell. The TUI detail pane
  renders the pointers on their own lines. (Heuristic, model-free summaries stay
  a single clear sentence.)

### CLI & install
- **`kintsugi update`** — check GitHub for a newer release and install it in place.
  Compares the running version to the latest release tag and, with your consent,
  re-runs the checksum-verifying installer (pinned to that tag) targeting the
  binary's own directory. If your daemon has the local model engine, the update
  **rebuilds the engine for the new version and keeps your configured model**
  instead of dropping back to the prebuilt heuristic-only build; otherwise it just
  swaps the binaries. `--check` reports only; `--yes` skips the prompt. Manual and
  explicit: no automatic or background checks, and no command/code/telemetry is
  ever sent — the one deliberate exception to "never phone home", per DECISIONS.md.
- **Active scorer is now visible.** `kintsugi status`, `kintsugi init`, and the bare
  `kintsugi` banner report which scorer the daemon is using — the loaded local model
  (`<model> (local model)`) or the offline `heuristic fallback (… set
  KINTSUGI_MODEL_FILE)`. Previously a model-less daemon degraded silently, so a
  mis-set `KINTSUGI_MODEL_FILE` only showed up as thin, templated hold summaries.
  Backed by a new `Status` IPC request/response.
- **Installer loads the model immediately, and sets up once.** The guided
  installer now sets up the model *before* running `kintsugi init`, so the daemon
  starts a single time already pointed at `KINTSUGI_MODEL_FILE` (no double-start, no
  transient "heuristic fallback" message). It also no longer auto-downloads: the
  model picker shows its full menu — ★ recommended models alongside the
  popularity-ranked ones — and lets you choose (only `--yes` installs auto-pick).
- **Idempotent re-runs.** Re-running `install.sh` (or `kintsugi update`) no longer
  redoes work that's already done: it skips the binary download when the target
  version is already installed (which also preserves a locally-built llama daemon
  the prebuilt tarball would otherwise overwrite), skips the multi-minute
  llama.cpp compile when the installed daemon already has the engine *at the same
  version* (probed via `kintsugi-daemon --has-llama`, so an app upgrade still
  rebuilds), and the model picker skips the GGUF download when the file already
  exists.
- **`kintsugi stop`** — stop the background daemon (the inverse of `kintsugi init`). The
  daemon writes its own PID file on startup; `stop` reads it and terminates it
  cleanly, idempotent when nothing's running.
- **Guided installer** — `install.sh` runs a short cross-OS stepper after
  installing: it wires your agents (`kintsugi init`) and *optionally* sets up a local
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
  (`.kintsugi.toml`/memory). The `risk < threshold → allow` graduated path is gone.
- **Shell-wrapper evasion closed:** `bash -c "rm -rf /"`, `find -exec`, `xargs`,
  and prefix launchers (`sudo`/`env`/`timeout`/`nohup`/`setsid`/`stdbuf`) are now
  recursively/transparently classified, so wrapped destructive payloads are
  Catastrophic instead of Ambiguous. `bash/sh/zsh/find/xargs` added to the shim.
- **Kill-switch bypass closed:** `resolve()` (shim hold card / raw `Resolve` IPC)
  now refuses Allow while the kill-switch is engaged, matching `resolve_pending()`.
- **Fail-closed for catastrophic:** when the daemon is unreachable, the shim/hook/
  MCP locally classify and block catastrophic commands even without
  `KINTSUGI_FAIL_CLOSED` (non-catastrophic still fails open).
- **Private IPC + data-at-rest:** the socket is `0600` in a `0700` dir (off the
  world-writable temp dir); the data dir is `0700` and `events.db` (+WAL/SHM)
  `0600`, protecting verbatim-logged commands that may contain secrets.

### Log: sessions, search/filter, redaction & purge
- **Per-CLI / per-session grouping**: events now carry an originating session id
  (Claude Code hook `session_id`; one session per MCP server process, overridable
  via a `session` tool arg; `$KINTSUGI_SESSION` for the shim). Stored as view
  metadata (not hashed), with a migration for older DBs.
- **Search & filter** on `kintsugi log`: `--agent`, `--session`, `--class`, `--grep`
  (literal substring), `--since`/`--before` (RFC3339 or `day|week|month|<N>d|<N>h`).
- **Delete, two ways** (the chain stays the source of truth):
  - `kintsugi redact <id|filters>` — append-only hide; the row and hash chain stay
    intact and verifiable. Redacted rows show as dim `⟨redacted⟩` placeholders
    (or hidden); refuses to redact everything without an id/filter.
  - `kintsugi purge --yes <filters>` — explicit hard erasure: delete rows, rebuild
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
- **TUI paging**: jump a screenful with `Space`/`b` (Mac-friendly pager keys, no
  PageUp/PageDown needed; `f` and the PgUp/PgDn keys also work). A right-aligned
  `row N/M` indicator shows your position when the terminal is wide enough.

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
- **Cursor CLI detection**: `kintsugi init` now recognizes `~/.cursor` and reports
  it as intercepted via the `kintsugi-exec` MCP server (verified: Cursor CLI runs in
  the terminal and speaks stdio MCP via `~/.cursor/mcp.json`). Joins the existing
  Claude Code / Codex CLI / Qwen Code / Gemini CLI detection.
- Docs/site now lead with the agent-agnostic story: the `$PATH` shim covers *any*
  tool or raw shell-out; MCP covers any MCP client; the Claude Code hook is one
  (best-UX) option, not a requirement. Added a per-agent MCP-config table to
  `docs/mcp.md` (Codex TOML vs. Cursor/Qwen/Gemini `mcpServers` JSON).

### Model
- **Bring-your-own model (`KINTSUGI_MODEL_FILE`)**: point the daemon at any local
  GGUF and it loads that one — no recompile, no pinned spec. The durable answer
  to "models keep releasing"; the pinned default is now just a sensible default.
- **Interactive model picker** (`scripts/pick-model.sh`, served at
  `…/pick-model.sh`): fetches a short, RAM-appropriate list of small instruct
  GGUF models from the Hugging Face API (query constrained to `filter=gguf`,
  text-generation, sized to detected RAM), downloads your choice, prints its
  SHA-256, and tells you the one env var to set. `install.sh --with-model` runs
  it after install. Kintsugi still ships model-free (heuristic scorer) by default.

### Security & hardening
- Review hardening (panel: 2 principal eng, 4 testers, 2 dev-users):
  - **Catastrophic hard floor** is now consistent: neither decision memory nor
    `.kintsugi.toml` policy can auto-downgrade a catastrophic command, and `[r]`
    never *remembers* a catastrophic (acts as allow-once). Only an in-the-moment
    human decision runs it.
  - **Hook**: a catastrophic hold maps to `deny` (not `ask`) so a one-click
    allow in Claude's UI can't bypass the Kintsugi snapshot; ambiguous still `ask`.
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
- **P0.1** — Cargo workspace scaffold with six crates (`kintsugi-core`,
  `kintsugi-daemon`, `kintsugi-intercept`, `kintsugi-cli`, `kintsugi-model`, `kintsugi-tui`).
  `kintsugi --version` runs.
- **P0.2** — `kintsugi-core` shared types (`ProposedCommand`, `Class`, `Decision`,
  `Verdict`) and an append-only, hash-chained SQLite event log (`EventLog` with
  `log_event`, `tail`, `count`, `verify_chain`). SHA-256 chain binds every field
  plus the predecessor hash; tampering and row deletion are detected.

- **P0.3** — `kintsugi-daemon`: a local-socket IPC server (`interprocess`,
  newline-delimited JSON) and a `Daemon` that records every proposal to the
  event log and returns a verdict. Phase 0 is a pure recorder (allow-all);
  Tier-1 rules plug into `Daemon::decide` in Phase 1. Integration tests cover a
  client round-trip and multi-command log chaining.

- **P0.4** — `kintsugi-shim`: the `$PATH` interception shim. Symlinked as `rm`,
  `git`, etc., it captures argv+cwd, consults the daemon, and on allow execs the
  real binary (Unix `exec`, so exit code, stdio, and signals are forwarded with
  perfect fidelity). Fail-open by default; `KINTSUGI_FAIL_CLOSED=1` to block when
  the daemon is down. Tests: real `rm` deletes + logs + exit 0, non-zero exit
  propagation, stdout forwarding, plus unit tests for name/path resolution.

- **P0.5** — `kintsugi-hook`: Claude Code `PreToolUse` hook bridge. Parses the hook
  JSON, records shell commands tagged `agent = "claude-code"`, and maps the
  verdict to Claude Code's permission protocol (allow→silent, deny→`deny`,
  hold→`ask`). Fail-open on malformed payloads, non-shell tools, or a down
  daemon. Adds `kintsugi_core::shell::split`, a quote-aware tokenizer.

- **P0.6** — `kintsugi-mcp`: the `kintsugi-exec` MCP server (hand-rolled JSON-RPC 2.0
  over stdio, no framework dependency). Exposes one tool that runs a shell
  command guarded + recorded by Kintsugi, tagged with the calling agent. Handles
  `initialize`, `tools/list`, `tools/call`, `ping`. Wiring documented in
  `docs/mcp.md`.

- **P0.7** — `kintsugi-cli`: `kintsugi init` (detect agents via config dirs, create
  `$PATH` shims, wire the Claude Code hook idempotently with a backup, start the
  daemon), `kintsugi status` (daemon/socket/log/chain health), and `kintsugi log` (a
  calm timeline — outcome words not just color, one reserved accent, `NO_COLOR`
  respected, designed empty state). Completes **Phase 0 — Recorder**.

- **P1.1** — `kintsugi-core::rules`: the Tier-1 deterministic rule engine.
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

- **P1.5** — Policy files. `kintsugi-core::policy` parses `.kintsugi.toml` (mode +
  allow/deny rules with glob/prefix matching), merges global ← repo, and applies
  it to a verdict: `deny` escalates (Attended→Hold, Unattended→Deny), `allow`
  tames the ambiguous band but never downgrades a catastrophic block. The daemon
  loads the nearest `.kintsugi.toml` and global config (`KINTSUGI_CONFIG` override) per
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

- **Phase 2** — `kintsugi-model` real implementation. A warm Tier-2 `Scorer` kept in
  the daemon fills `summary` + `risk` for the ambiguous band and drives graduated
  unattended mode (`risk` vs per-repo `threshold`). `HeuristicScorer` is the
  default, dependency-free, always-available backend (and graceful-degradation
  path); `LlamaScorer` (feature `llama`) does real CPU GGUF inference via
  `llama.cpp`. Pinned+checksummed weight management with RAM-based 3B/1.5B
  auto-selection (feature `download` for the fetch — the only network egress).
  The hold card now shows the model summary and a risk meter. Catastrophic stays
  a hard floor regardless of score; Safe stays on the model-free fast path.
  Documented in `docs/model.md`.

- **Phase 3** — snapshots + `kintsugi undo`. Before an allowed destructive command,
  the daemon captures the paths it will touch (`snapshot::predict_paths`) into a
  content-addressed store using reflink CoW (`reflink-copy`) with a plain-copy
  fallback, and records a manifest in a new `snapshots` table. `kintsugi undo`
  restores the last action; `kintsugi undo --session` restores every not-yet-reverted
  snapshot. Scope is stated plainly: files only — not network calls or pushed
  commits. Safe commands are never snapshotted.

- **Phase 4** — FS-watcher backstop + `ratatui` timeline.
  - Backstop: `kintsugi watch <path>` watches recursively (`notify`) and records FS
    changes as `fs-watch` events **through the daemon's single writer** (new
    `Observe` IPC), so the hash chain is never raced. Keeps the timeline and undo
    complete for actions that bypassed interception.
  - TUI: `kintsugi tui` is a real, interactive `ratatui` app over the live event log
    — keyboard navigation (`j/k`, `g/G`), `/` filter, `enter` detail, `u` undo,
    `q` quit; live polling refresh; a designed empty state; a "terminal too
    small" notice; one reserved danger accent with words-not-color and `NO_COLOR`
    support; panic-safe teardown via `ratatui::init`/`restore`. Covered by
    state-transition tests and `TestBackend` render tests at several sizes.

- **Phase 5** — launch hardening.
  - **Panic kill-switch:** `kintsugi panic` engages a flag the daemon checks *first*,
    instantly denying every command (even Safe); `kintsugi resume` clears it. Surfaced
    in `kintsugi status` and recorded in the log.
  - **`kintsugi init` polish:** `--print-path` (for `eval "$(kintsugi init --print-path)"`)
    and `KINTSUGI_DATA_DIR` support; scorer/kill-switch shown in status.
  - **Release workflow:** tag-triggered cross-platform builds (Linux/macOS/Windows)
    that publish `SHA256SUMS`; artifact signing is left as a documented human
    checkpoint (never touches secrets autonomously).

- **Approval queue** — held commands are now resolvable so an agent can proceed.
  The daemon enqueues every Hold; `kintsugi queue` lists them; `kintsugi approve <id>` /
  `kintsugi deny <id>` (and the TUI's `a`/`d` on a held row) resolve them, recording
  the human decision (and snapshotting on approve). The `kintsugi-exec` MCP tool can
  **wait in-band** for approval (`KINTSUGI_APPROVAL_TIMEOUT=<secs>`) and then run the
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

## [0.1.1]

- **Fix broken README images on crates.io.** The repo-root README (published as the
  `kintsugi` crate readme) referenced `docs/img/{logo,cast}.svg` by relative path, which
  cannot resolve on crates.io. Point both at the GitHub Pages host
  (`https://arrowassassin.github.io/kintsugi/…`), which serves SVG as `image/svg+xml`.
  README-only change; no code changes.
