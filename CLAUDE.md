# CLAUDE.md — Aegis build rules (read this first, every session)

You are building **Aegis**, a local-first safety layer for AI coding agents. Full spec is in
`aegis-design-doc.md`; the current work is in `aegis-phase0-1-tasklist.md`. This file is the
short, non-negotiable rulebook. If anything you're about to do conflicts with this file, STOP
and ask the human.

## What Aegis is (one paragraph)
Aegis intercepts the commands an AI coding agent is about to run, warns the user in plain
English BEFORE they execute, makes destructive actions reversible via snapshots, and keeps a
tamper-evident log of everything every agent did. No kernel code, no OS-vendor approvals, no
code leaves the machine. Cross-platform: macOS, Linux, Windows.

## Security spine — NEVER violate these
1. **Rules block, the model only explains.** The decision to hold/deny a *catastrophic*
   command is made by deterministic rules, never by the LLM. The local model only (a) writes a
   one-sentence summary and (b) scores severity for the AMBIGUOUS band.
2. **Monotonic model influence.** Where the model affects a decision, it may only ADD caution
   (escalate ambiguous -> deny/queue). It may NEVER unlock or downgrade a rule-based block.
3. **Raw command always preserved and shown verbatim.** A summary never replaces the real command.
4. **Append-only, hash-chained event log.** Never mutate or delete past events.
5. **No network egress** except the pinned + checksummed model download and a user-configured
   LLM endpoint. Never phone home. Never transmit user code or commands anywhere.
6. **No secret values in logs.** Detect access to `.env`, `~/.ssh`, keychains; never read their
   contents into the log in plaintext.
7. **Honest guarantee:** "nothing is unrecoverable" (via the filesystem watcher backstop), NOT
   "nothing runs un-warned." Do not describe Aegis as an unbypassable firewall.

## Architecture (build to this)
- Rust workspace. Single `aegis` binary + a resident daemon that keeps the model warm.
- Interception adapter layer normalizes three sources to one `ProposedCommand`: native hook
  (e.g. Claude Code), MCP server `aegis-exec`, and a `$PATH` shim for raw shell-outs.
- Daemon decision loop: Tier-1 rules classify SAFE | CATASTROPHIC | AMBIGUOUS; Tier-2 model
  summarizes + scores the ambiguous band only.
- Snapshot before destructive ops (predicted paths, reflink CoW + copy fallback); one-command undo.
- Crates: `aegis-core`, `aegis-daemon`, `aegis-intercept`, `aegis-cli`, `aegis-model`, `aegis-tui`.

## How to work (process)
- One task-list segment per branch + PR. **Never commit to `main`.** Small, reviewable diffs.
- A segment is DONE only when its acceptance criterion in the task list is met by a passing test.
- Every PR updates: code, tests, docs, CHANGELOG, and a one-line entry in `DECISIONS.md`.
- Run the simulated review panel before proposing merge (see "Review gate" below).
- Keep the public surface small; do not add features not in the spec without asking.

## Review gate — required before any merge (simulate these roles, record their notes in the PR)
- **2 developer reviewers:** correctness, architecture adherence, idiomatic Rust, no security-spine
  violation, dependency hygiene.
- **3 testers:** write/extend tests; adversarial + cross-platform; specifically try to bypass
  interception, jailbreak the rules, tamper the log, and break exit-code/signal fidelity in the shim.
- **1 PM:** scope adherence (block scope creep), acceptance criteria met, UX/copy sanity, DECISIONS.md updated.
- No merge unless all six sign off in the PR description.

## Testing & CI gates (build must fail if unmet)
- >= 90% line AND branch coverage per crate (`cargo-llvm-cov`).
- Suites required: unit, integration, OS matrix (macOS/Linux/Windows), classifier property tests,
  a golden command corpus, and security/adversarial tests.
- **Zero tolerance:** any "catastrophic-classified-as-safe" case is a hard failure.
- `cargo clippy -- -D warnings`, `cargo fmt --check`, and the full OS matrix must be green.

## STOP and ask the human before (never do these autonomously)
- Force-push, history rewrite, branch/file deletion outside the worktree, or touching `main`.
- Adding a third-party dependency outside the allowlist, or any dependency you can't justify.
- Publishing/releasing, pushing to a registry, or modifying CI secrets.
- Any change to the security spine, the rule classes, or the guardrails.
- Lowering the 90% coverage bar for any reason — explain instead.

## Phase checkpoints (stop at each, wait for human go-ahead)
Phase 0 Recorder -> Phase 1 Gate -> Phase 2 Explain+score -> Phase 3 Undo -> Phase 4 Recorder UI
-> Phase 5 Launch. Tag last-known-good after each phase. Do not start the next phase unprompted.

## Dogfooding
Once Phase 1's gate works, run yourself (the build agent) THROUGH Aegis so your own destructive
actions during the build are guarded by the tool you are building.

## Start here
Read `aegis-phase0-1-tasklist.md`. Begin with task **P0.1** on a branch named `phase0/p0.1-scaffold`.
Before writing code for the `$PATH` shim (P0.4), build it as a small standalone spike first — it
is the riskiest cross-platform primitive; prove capture-then-exec with correct exit codes and
signal forwarding before integrating it.

## TUI requirements (Phase 4) — build a real, working terminal UI, not a static mockup

The `aegis-tui` crate must be a fully functional `ratatui` application driven by live data
from the daemon and event log. Do NOT hardcode the rows or screens from the design mockups —
those mockups show layout and information only. Treat them as a spec to implement, not pixels
to reproduce. A screen that merely paints the example text and ignores input is a FAIL.

Hard requirements (each needs a test or a manual-verification note in the PR):
1. **Responsive to terminal size.** Use ratatui's `Layout`/`Constraint` system so every view
   reflows on resize. Must remain usable from ~80x24 up to large terminals; never overflow,
   clip, or panic on small sizes. Define minimum-size behavior (show a "terminal too small"
   message rather than corrupting). Handle the `Resize` event explicitly.
2. **Real input loop.** Keyboard navigation must actually work: arrows/`j`/`k` to move,
   `enter` for detail, `u` to undo, `/` to filter, `a`/`d`/`r` on a held action, `q` to quit.
   Use `crossterm` events; debounce nothing the user expects to feel instant.
3. **Live data, not fixtures.** The timeline reads the real SQLite event log; the hold view
   reflects a real pending `Verdict` from the daemon over IPC. Updates appear without restart
   (poll or subscribe). Empty state is a real, designed state, not a blank screen.
4. **Non-blocking.** Rendering and the model/daemon round-trip must not freeze the UI. Long
   operations (model scoring, snapshot) show progress and keep the event loop alive.
5. **Correct teardown.** Always restore the terminal on exit, panic, or signal (raw mode off,
   alternate screen left, cursor restored). A crash must not leave the user's terminal broken.
6. **Accessible-in-terminal basics.** Don't rely on color alone — pair every state with a text
   label or glyph (the design system rule applies here too: e.g. `denied`, `allowed` as words,
   not just red/green). Respect `NO_COLOR`. Ensure contrast works on both light and dark themes.
7. **Theme-safe.** Don't hardcode a background. Use the terminal's own palette; a single accent
   for danger, everything else default foreground — matching the "calm until it must shout"
   direction in the design doc.

Process for the TUI work:
- **Consult the `frontend-design` skill** before building the TUI, and apply its principles in
  the terminal medium: deliberate type/layout hierarchy, structure that encodes meaning (the
  timeline's columns and the single danger accent are information, not decoration), restraint
  (one accent, quiet everywhere else), and real copy (errors explain and don't apologize;
  empty states invite action). Do not ship the generic default TUI; make the deliberate choices
  the skill asks for, scoped to what a terminal can do.
- Build the input/resize/teardown skeleton FIRST and verify it by hand, THEN render data into it.
- Write tests for: layout at several sizes, key handling/state transitions, empty/filter states,
  and clean teardown on panic.

Acceptance for Phase 4: a reviewer can resize the terminal, navigate with the keyboard, filter,
open a detail, trigger an undo, and quit cleanly — all against live log data — with no panic,
no clipping, and no broken terminal afterward.
