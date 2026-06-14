# Changelog

All notable changes to Aegis are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **P0.1** — Cargo workspace scaffold with six crates (`aegis-core`,
  `aegis-daemon`, `aegis-intercept`, `aegis-cli`, `aegis-model`, `aegis-tui`).
  `aegis --version` runs.
- **P0.2** — `aegis-core` shared types (`ProposedCommand`, `Class`, `Decision`,
  `Verdict`) and an append-only, hash-chained SQLite event log (`EventLog` with
  `log_event`, `tail`, `count`, `verify_chain`). SHA-256 chain binds every field
  plus the predecessor hash; tampering and row deletion are detected.

- **P0.3** — `aegis-daemon`: a local-socket IPC server (`interprocess`,
  newline-delimited JSON) and a `Daemon` that records every proposal to the
  event log and returns a verdict. Phase 0 is a pure recorder (allow-all);
  Tier-1 rules plug into `Daemon::decide` in Phase 1. Integration tests cover a
  client round-trip and multi-command log chaining.

### Changed
- Pinned all dependencies to latest stable. `rusqlite` held at 0.39 because 0.40
  pulls `libsqlite3-sys` 0.38 which needs the unstable `cfg_select!` feature.
