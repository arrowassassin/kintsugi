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
