# Pointing an agent at `aegis-exec` (MCP)

Aegis ships an MCP server, `aegis-mcp`, exposing a single tool — `aegis-exec` —
that runs a shell command **through** Aegis: the command is classified, recorded
to the tamper-evident log, held/denied if dangerous, and (on allow) executed with
its output returned to the agent.

Transport is newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport).

## Wire it up

The daemon must be running (`aegis-daemon`, or `aegis init` which starts it).

### Codex CLI / generic MCP (`~/.codex/config.toml` style)

```toml
[mcp_servers.aegis]
command = "aegis-mcp"
args = []
```

### Qwen CLI / Claude Desktop style (`mcpServers` JSON)

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": []
    }
  }
}
```

Then instruct the agent to run shell commands via the `aegis-exec` tool rather
than its built-in shell. The tool accepts:

| field     | required | meaning                                            |
|-----------|----------|----------------------------------------------------|
| `command` | yes      | the shell command to run                           |
| `cwd`     | no       | working directory (defaults to the server's cwd)   |
| `agent`   | no       | calling agent name for the audit log (default `mcp`)|

## Behavior

- **Allow** → the command runs; the tool returns its exit code, stdout, stderr.
- **Deny** (catastrophic) → the command does not run; the tool returns an error.
- **Hold** (ambiguous, attended) → not run unattended; the tool returns an error
  explaining it is awaiting human approval.

Set `AEGIS_FAIL_CLOSED=1` to make the tool refuse to run when the daemon is
unreachable (default is fail-open: run unguarded with a warning).
