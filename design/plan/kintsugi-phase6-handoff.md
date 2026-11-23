# Phase 6 — handoff & next-step commands

State as of 2026-06-20. The deterministic Provenance core is built, verified, and in **one PR: #29** (`phase6/provenance-all` → `main`). This file is the exact path to continue (Claude Code CLI / Claude Cloud full suite).

## Resume this session
```bash
cd ~/GitHub/vena                 # session is registered under this dir
claude --resume 039ba03c-78c8-4546-8bb1-10b29da574ee
# then, in the interactive CLI:
/design-login                    # authorize DesignSync (design files are already local under design/control-room, so optional now)
cd ~/GitHub/kintsugi             # the repo (moved out of ~/Documents to avoid macOS TCC block)
```

## Build / test / lint (run from ~/GitHub/kintsugi)
```bash
cargo test -p kintsugi-core --lib          # 115 taint/rule/policy unit tests
cargo test -p kintsugi-core                # + integration (provenance_predicates, corpus, fuzz)
cargo test -p kintsugi-daemon              # taint_state + trifecta_gate + full daemon regression
cargo clippy --all-targets -- -D warnings  # zero-warning bar
cargo fmt --check
# coverage bar (CLAUDE.md): cargo llvm-cov --workspace  (>=90% line+branch)
```

## What's DONE (in PR #29)
- P6.1 pure taint model (`crates/kintsugi-core/src/taint.rs`)
- Item A event-sourced `TaintState` in the daemon
- Item B `is_sensitive_read` / `is_egress_sink` (`rules.rs`)
- P6.3 `Daemon::trifecta_floor` + `[provenance]` policy toggle
All green; review panels in the (now-closed) PRs #25–#28 and consolidated in #29.

## Per-segment loop (the ritual to keep using)
1. Branch off `main` (or stack on `phase6/provenance-all`): `git checkout -b phase6/<seg>`
2. TDD: write the test, implement, then:
   `cargo fmt && cargo test -p <crate> && cargo clippy -p <crate> --all-targets -- -D warnings`
3. Review panel: 2 principal eng · 1 tester · 1 perf · 1 infosec (record in the PR body).
4. `git add <paths> && git commit` (end message with the Co-Authored-By line) `&& git push -u origin phase6/<seg>`
5. `gh pr create --draft --base main --title ... --body ...`
> NOTE: Kintsugi guards this repo. `git push --force`, `git reset --hard`, `git branch -D`, `rm -rf` are **blocked** by the shim — use a fresh branch name instead of force/delete (or `kintsugi run <id>` to override at your terminal).

## Remaining Phase 6 segments (dependency order)
- **D — durable taint** (`log.rs` event variants + replay on `Daemon::open`). Closes the fail-open-on-restart gap that P6.3 documents. *Do this before relying on the guard in production.*
- **G — redact `source_id`** through `redact.rs` before any logging/agent-facing reason.
- **P6.2 — content-tool observation** (`kintsugi-intercept/{hook,dialect}.rs`): observe `WebFetch`/`Read`/search/MCP per agent → `ObservedIngest` → `daemon.apply_taint`. **Spike standalone first** (riskiest; per-agent hook schemas — test against the real CLIs).
- **Negotiation layer** (`dialect.rs`): emit model-facing deny reasons (two-channel where supported) + the "materially safer alternative / else ask the user" instruction + a consecutive-denial circuit breaker. **Invariant: re-proposed commands are re-classified from scratch; reason text never reaches the allow path.** See `kintsugi-interaction-design.md`.
- **P6.4 — provenance trail over IPC** (needed before the UI can bind real data).
- **P6.5/P6.6 — UI + demo/docs.**

## UI implementation (Tauri)
Design reference: `design/control-room/` (Claude Design reactive prototype + runtime). Brand: `kintsugi-app-design-brief.md`. Interaction model (antivirus-style, in-band, app = dashboard not gate): `kintsugi-interaction-design.md`.
Approach: add a Tauri app crate; port the `.dc.html` screens to a real web frontend; expose Tauri commands that read the daemon over IPC (verdicts, session taint, provenance trail, audit log). Land **P6.4** first so the screens bind real data.

## Carried review-panel constraints
fail-open-on-restart→D · `Reset` never from agent input · redact `source_id`→G · egress list add socat/cloud-CLIs/kubectl cp/PowerShell · P6.3 tokenize-once-and-share · negotiation re-evaluate-from-scratch.
