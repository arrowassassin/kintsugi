# The approval queue — how a held command proceeds

![aegis queue](img/queue.svg)

When Aegis **holds** a command, the agent is never left without an answer. How it
proceeds depends on the path:

| path | on hold | how the agent proceeds |
|------|---------|------------------------|
| Claude Code hook (attended) | `permissionDecision: "ask"` | Claude Code's own prompt; approve → it runs → agent continues |
| `$PATH` shim (attended) | live hold card | press `a` → real binary runs → shell gets the output |
| MCP `aegis-exec` | enqueued + (optional) wait | a human approves from CLI/TUI → the same call runs the command and returns output |

The **queue** is "holds not yet resolved." It is resolvable from three places:

- the agent's own bounded wait (MCP), 
- the CLI: `aegis queue`, `aegis approve <id>`, `aegis deny <id>`,
- the TUI: `a` / `d` on a held row.

## In-band approval for autonomous agents (MCP)

By default the `aegis-exec` tool returns "held (id …)" immediately so the agent
is never wedged. Set `AEGIS_APPROVAL_TIMEOUT=<seconds>` to make the tool **wait**
for a human decision and then proceed in the same call:

```sh
AEGIS_APPROVAL_TIMEOUT=300 aegis-mcp   # wait up to 5 min for approval
```

Flow: agent calls `aegis-exec` → Aegis holds it and queues it → you run
`aegis approve <id>` (or press `a` in `aegis tui`) → the held command runs and its
output returns to the agent, which continues. On timeout the tool returns
"still pending" (re-run after approving, or pre-authorize).

## Making routine commands flow without nagging

- **`[r]` / memory:** approve once with "always allow here" → that exact command
  auto-allows forever in the repo.
- **`.aegis.toml` policy:** pre-authorize patterns (`allow = ["rm -rf target"]`).
- **Unattended + model:** the Tier-2 model auto-allows the safe-enough ambiguous
  band against `threshold`; only the genuinely dangerous queue.

## Security

A human may approve a queued command of any class — including catastrophic — as a
deliberate override (the same trust as `[r]`). The **model never** approves a
catastrophic command; the kill-switch (`aegis panic`) overrides everything and
denies the entire queue until `aegis resume`.
