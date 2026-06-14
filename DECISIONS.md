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
