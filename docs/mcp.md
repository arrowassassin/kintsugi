# Pointing an agent at `kintsugi-exec` (MCP)

Kintsugi ships an MCP server, `kintsugi-mcp`, exposing a single tool — `kintsugi-exec` —
that runs a shell command **through** Kintsugi: the command is classified, recorded
to the tamper-evident log, held/denied if dangerous, and (on allow) executed with
its output returned to the agent.

Transport is newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport).

## Wire it up

The daemon must be running (`kintsugi-daemon`, or `kintsugi init` which starts it).

### Codex CLI — `~/.codex/config.toml` (TOML `mcp_servers`)

```toml
[mcp_servers.kintsugi]
command = "kintsugi-mcp"
args = []
```

### Cursor CLI — `~/.cursor/mcp.json` (or `.cursor/mcp.json` per project)

```json
{
  "mcpServers": {
    "kintsugi": { "command": "kintsugi-mcp", "args": [] }
  }
}
```

### Qwen Code — `~/.qwen/settings.json` · Gemini CLI — `~/.gemini/settings.json`

Both use the same `mcpServers` JSON shape (also matches Claude Desktop):

```json
{
  "mcpServers": {
    "kintsugi": {
      "command": "kintsugi-mcp",
      "args": []
    }
  }
}
```

> `kintsugi init` detects these agents and prints this command for you; the `$PATH`
> shim still covers any raw shell-out an agent makes outside the MCP tool.

Then instruct the agent to run shell commands via the `kintsugi-exec` tool rather
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

Set `KINTSUGI_FAIL_CLOSED=1` to make the tool refuse to run when the daemon is
unreachable (default is fail-open: run unguarded with a warning).
