# Aegis

A local-first safety layer for AI coding agents. Aegis intercepts the commands an
agent is about to run, warns you in plain English **before** they execute, makes
destructive actions reversible, and keeps a tamper-evident record of everything
every agent did on your machine. No kernel code, no OS-vendor approvals, no code
leaves your machine.

> **Security spine:** rules block, the model only explains. The decision to
> hold/deny a catastrophic command is made by deterministic rules, never by an
> LLM. The raw command is always shown verbatim. The event log is append-only and
> hash-chained. See [`CLAUDE.md`](CLAUDE.md) for the full, non-negotiable rules.

## Status

Building toward the Phase 0/1 milestone (see
[`aegis-phase0-1-tasklist.md`](aegis-phase0-1-tasklist.md)).

- **Phase 0 — Recorder (done):** agent-agnostic interception (`$PATH` shim +
  Claude Code hook + `aegis-exec` MCP server) that records every command to a
  tamper-evident, hash-chained SQLite log.
- **Phase 1 — Gate (in progress):** a deterministic rule engine that holds
  dangerous commands for one-key approval, with per-repo memory and policy.

## Crates

| crate | role |
|-------|------|
| `aegis-core` | shared types, rule engine, policy, decision memory, hash-chained event log |
| `aegis-daemon` | resident process: local IPC server + decision loop |
| `aegis-intercept` | the `$PATH` shim, Claude Code hook bridge, and `aegis-exec` MCP server |
| `aegis-cli` | the `aegis` binary: `init`, `status`, `log` |
| `aegis-model` | Tier-2 model wrapper (stub until Phase 2) |
| `aegis-tui` | ratatui timeline (Phase 4) |

## Quick start

```sh
cargo build
./target/debug/aegis init      # detect agents, wire interception, start the daemon
./target/debug/aegis status    # daemon / socket / log health
./target/debug/aegis log       # the recent command timeline
```

`aegis init` prints a `PATH` line to prepend so the shim can guard raw
shell-outs. Pointing tool-calling agents at the MCP server is documented in
[`docs/mcp.md`](docs/mcp.md); per-repo policy in [`docs/policy.md`](docs/policy.md).

## Demo

See [`docs/demo.md`](docs/demo.md). The 30-second flow — an agent's `rm -rf` is
held *before* it runs, you deny it, and it lands on the tamper-evident timeline:

```sh
bash scripts/demo.sh            # interactive (press a/d/r at the hold card)
DEMO_KEY=d bash scripts/demo.sh # non-interactive
```

## Building & testing

```sh
cargo test            # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

MIT — see [`LICENSE`](LICENSE).
