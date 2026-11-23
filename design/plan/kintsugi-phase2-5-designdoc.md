# Kintsugi — Phases 2–5 design & build plan

Continuation of `kintsugi-design-doc.md` and `kintsugi-phase0-1-tasklist.md`. Phases 0
(Recorder) and 1 (Gate) are complete and deterministic. These four phases add the
local model, reversibility, the live UI, and launch hardening — **without ever
weakening the security spine**: rules still block; the model only explains and
scores the ambiguous band; nothing the model or UI does can unlock a rule-based
catastrophic block.

The guiding constraint for an autonomous build: every phase must **compile and
test green by default with no network and no exotic toolchain**. Heavy external
integrations (llama.cpp inference, model download, code signing) are therefore
**feature-gated or workflow-gated**, with a fully-functional default path
(heuristic scorer, copy-based snapshots, local UI) so CI and `cargo test` stay
green. Enabling a feature swaps in the real backend.

---

## Phase 2 — `kintsugi-model` (explain + score the ambiguous band)

**Goal:** a small CPU model, kept warm in the daemon, fills `summary` + `risk` for
the **ambiguous band only**, and drives graduated unattended mode.

### Architecture
- `Scorer` trait: `score(&ProposedCommand, Class) -> ModelOutput { summary, risk }`.
- **`HeuristicScorer` (default, always available):** deterministic, dependency-free.
  Produces a plain-English summary from the rule id and a risk score from class +
  signal words. This *is* the rules-only graceful-degradation path.
- **`LlamaScorer` (feature `llama`):** real GGUF inference via `llama-cpp-2`,
  forced-short JSON (`{summary, risk, reason}`), warm context reused per call.
- **Model management** (`model::manage`, pure + I/O split):
  - `ModelSpec { id, url, sha256, size, min_ram_mb }` pinned for 3B Q4_K_M and the
    1.5B low-RAM fallback.
  - `select_spec(ram_mb)` → 3B when RAM allows, else 1.5B (pure, tested).
  - `verify_sha256(path, expected)` (pure-ish, tested with a temp file).
  - `ensure_weights(spec, dir)` → returns the path; downloads (feature `download`,
    `reqwest` blocking) only when missing, then verifies the checksum. The **only**
    permitted network egress, pinned + checksummed.

### Decision wiring (security spine preserved)
- Daemon owns one warm `Box<dyn Scorer>`.
- **Catastrophic** → never touched by the model (hard floor).
- **Attended:** the model fills `summary`/`risk` for the hold card; the *decision*
  stays rules-based (Hold). The model only adds prose.
- **Unattended (graduated):** `Safe→allow`; `Catastrophic→deny+queue`;
  `Ambiguous→` model `risk` vs `policy.threshold`: below → allow + record; at/above
  → deny + queue. Model influence is escalation-only — it can move ambiguous toward
  caution, never unlock a rule block.
- `risk`/`summary` are persisted on the event (`tier = 2` when the model spoke).

### Acceptance
- `select_spec` and checksum verification unit-tested; daemon fills `summary`/`risk`
  for an ambiguous command via the heuristic scorer; unattended threshold flips
  allow/deny around the boundary; catastrophic stays denied regardless of `risk`.

---

## Phase 3 — snapshots + `kintsugi undo`

**Goal:** "nothing is unrecoverable." Before an allowed destructive op, snapshot the
paths it will touch; `kintsugi undo` restores them.

### Architecture
- `snapshot` module:
  - `predict_paths(cmd) -> Vec<PathBuf>`: derive likely-touched paths from argv
    (rm/shred targets, redirect targets, mv/cp sources, etc.), resolved against cwd.
    Conservative: over-include rather than miss.
  - Content-addressed store under the data dir: `snapshots/<snapshot_id>/…` plus a
    `snapshots(id, ts, paths_json, store_ref, reverted)` row in the existing DB.
  - Copy strategy: **reflink CoW** via `reflink-copy` where supported (APFS/btrfs/
    ReFS), **plain copy fallback** everywhere else. Records whether a path existed
    (so undo of a *creation* means delete-on-undo).
- Daemon: when a destructive command is **allowed** (rule allow, memory/policy
  allow, or human allow), snapshot predicted paths first and store `snapshot_id`
  on the event.
- CLI: `kintsugi undo` (last reversible action) and `kintsugi undo --session` (whole
  agent session), restoring files and marking snapshots reverted (append a
  `undo` event; never mutate history).

### Acceptance
- `predict_paths` unit-tested over a command corpus; snapshot→modify→`undo`
  restores byte-for-byte; snapshot→delete→`undo` recreates; undo of a created file
  removes it; reflink path falls back to copy cleanly.

### Honest scope
Covers files only — not network calls, external APIs, or already-pushed commits.
Stated plainly in `kintsugi undo` output and docs.

---

## Phase 4 — FS-watcher backstop + `ratatui` timeline

**Goal:** record FS changes even from actions that dodged interception (keeps undo
complete), and ship a real, live terminal UI over the event log.

### FS-watcher backstop
- `notify`-based watcher in the daemon over configured roots (repo roots seen in
  events). Debounced change events recorded as `agent="fs-watch"` log entries so
  the timeline and undo see changes that bypassed the hook/shim/MCP.
- Off by default; `kintsugi watch <path>` or `.kintsugi.toml` opt-in (watching is
  resource-sensitive and must be a deliberate choice).

### TUI (`kintsugi-tui`, launched by `kintsugi tui`)
Built to the hard requirements in `CLAUDE.md` (consult the `frontend-design`
skill; calm-until-it-must-shout; one accent; words not color alone; `NO_COLOR`;
theme-safe). A genuinely interactive `ratatui` app:
- Input/resize/teardown skeleton first; then render live data.
- Live timeline from the SQLite log (polled), keyboard nav (`j/k`/arrows, `enter`
  detail, `/` filter, `u` undo, `q` quit), a real empty state, a "terminal too
  small" state, correct teardown on exit/panic (raw mode off, alt-screen left).
- A hold/detail view showing the raw command verbatim + class/decision/reason.

### Acceptance
- Layout snapshot tests at several sizes; key-handling/state-transition tests;
  empty/filter state tests; teardown-on-panic test; a manual-verification note.

---

## Phase 5 — kill-switch, release, init polish, launch

- **Panic kill-switch:** `kintsugi panic` writes a kill-state flag the daemon checks
  *first*, instantly forcing every decision to Deny/Hold (halts current + queued
  agent actions); `kintsugi resume` clears it. Recorded in the log.
- **`kintsugi init` polish:** `KINTSUGI_DATA_DIR`, clearer agent detection and output,
  `--print-path` for shell-rc wiring, idempotency.
- **Release workflow:** a tag-triggered GitHub Actions job builds Linux/macOS/
  Windows artifacts and publishes `SHA256SUMS`. **Code signing requires secrets
  and is a human checkpoint** — the workflow leaves a documented signing step;
  the agent never touches CI secrets autonomously.
- **Launch:** README/docs polish, install instructions, demo GIF (`vhs`).

### Acceptance
- Kill-switch: with panic engaged, even a Safe command is denied; resume restores
  normal decisions; both transitions are logged. Release workflow builds in CI
  (dry run on PR). Init polish covered by CLI tests.

---

## Dependencies introduced (all from the spec's tech-stack section)
`llama-cpp-2` (feat `llama`), `reqwest` (feat `download`), `reflink-copy`,
`notify`, `ratatui`, `crossterm`. Feature-gated where they pull a toolchain or
network so the default build stays clean and offline.

## Invariants that do not move
Rules block; model is explain+score-only and escalation-only; raw command always
shown; append-only hash-chained log; no egress except the pinned+checksummed model
download; no secret values in logs.
