# Agent hook integrations

Every supported agent CLI exposes a *pre-tool hook*: before it executes a shell
tool, it runs an external command, hands it a JSON description of the call on
stdin, and reads back an allow / deny / ask decision on stdout. Kintsugi wires that
hook on each CLI so a held command pauses the agent **in-band** — the tightest
possible UX, and stronger than the `$PATH` shim because the agent itself waits
for the verdict.

One binary speaks every dialect:

```sh
kintsugi-hook --agent <claude|qwen|gemini|copilot|cursor|codex|opencode>
```

`kintsugi init` detects which CLIs are installed (by their config dir) and writes
each one's hook config idempotently, backing up any file it modifies to
`*.kintsugi-bak`. You can re-run `kintsugi init` any time; it never duplicates a hook.

## What each CLI gets

| CLI | config Kintsugi writes | event | command run |
|-----|--------------------|-------|-------------|
| Claude Code | `~/.claude/settings.json` | `hooks.PreToolUse` (matcher `Bash`) | `kintsugi-hook --agent claude` |
| Qwen Code | `~/.qwen/settings.json` | `hooks.PreToolUse` (matcher `run_shell_command\|Bash\|Shell\|ShellTool`) | `kintsugi-hook --agent qwen` |
| Gemini CLI | `~/.gemini/settings.json` | `hooks.BeforeTool` (matcher `run_shell_command`) | `kintsugi-hook --agent gemini` |
| GitHub Copilot CLI | `~/.copilot/hooks/kintsugi.json` | `hooks.preToolUse` (`type: command`) | `kintsugi-hook --agent copilot` |
| Cursor CLI | `~/.cursor/hooks.json` | `hooks.beforeShellExecution` | `kintsugi-hook --agent cursor` |
| Codex CLI | `~/.codex/config.toml` | `[[hooks.PreToolUse]]` (matcher `^Bash$`) | `kintsugi-hook --agent codex` |
| OpenCode | `~/.config/opencode/plugin/kintsugi.js` | `tool.execute.before` plugin → bridges to `kintsugi-hook --agent opencode` | (JS plugin) |

## How the decision maps per dialect

The daemon returns one verdict; each dialect serializes it into that CLI's
protocol. The policy is identical everywhere and lives in
`kintsugi-intercept/src/hook.rs`; only the wire format differs (in
`kintsugi-intercept/src/dialect.rs`).

| verdict | Claude / Qwen / Codex | Gemini | Copilot | Cursor | OpenCode |
|---------|----------------------|--------|---------|--------|----------|
| SAFE → allow | (silent — proceed) | (silent) | (silent) | `{"permission":"allow"}` | `{"decision":"allow"}` |
| catastrophic → deny | `permissionDecision: deny` | `decision: deny` | `permissionDecision: deny` | `permission: deny` | `{"decision":"deny"}` → plugin throws |
| ambiguous → hold | `permissionDecision: ask` | `decision: deny`¹ | `permissionDecision: ask` | `permission: ask` | `{"decision":"ask"}` → plugin throws |

¹ Gemini's decision enum is `allow`/`deny`/`block` with no interactive *ask*, so
an ambiguous hold is mapped to **deny** with an explanatory reason. This is safe
under the monotonic-caution rule: the model may only ever *add* caution.

A **catastrophic hold is always mapped to deny**, never ask — letting the CLI's
own one-click "allow" run it would bypass Kintsugi's snapshot and void the
reversibility guarantee. Catastrophic commands must go through a guarded path
(the shim/CLI/TUI) that snapshots first.

A hook is **one-shot**: by the time you see the deny, the agent already has it
and has moved on. Unlike the MCP and `$PATH` shim paths — where the original
call waits in-band and *does* run the command when you `kintsugi approve` it — there
is no waiting process behind a hook, so approving a hook-originated catastrophic
would only record the decision, not execute it.

So the way to run a hook-blocked command yourself is **`kintsugi run <id>`** (the
deny reason names it). It snapshots the predicted paths, runs the exact command
in its original directory, records it, and is undoable with `kintsugi undo`. It
confirms with a code typed at your real terminal (`/dev/tty`), so an agent that
shells out to `kintsugi run` can't self-approve. See [`docs/queue.md`](queue.md) for
the full approve-vs-run model, exactly-once resolution, and the honest limits of
snapshot-based reversibility.

## Fail behavior

- **Daemon down + catastrophic command:** denied (fail-closed). The hook
  re-classifies locally so the hard floor holds even with the daemon stopped.
- **Daemon down + non-catastrophic:** allowed (fail-open) — Kintsugi never wedges
  an agent for a non-dangerous command. Set `KINTSUGI_FAIL_CLOSED=1` to deny
  everything when the daemon is unreachable.
- **Unparseable payload / non-shell tool:** passes through silently.
- **Copilot** command hooks are themselves *fail-closed* (a crash denies), which
  is why we register a `type: command` hook there rather than `type: http`.
- **OpenCode** plugin bridge fails *open* on a spawn/parse error (the agent isn't
  wedged), but `kintsugi-hook` still enforces the catastrophic floor internally.

## The honest caveat

Hooks are an interception layer, not an unbypassable firewall. An agent run in a
"yolo" / auto-approve mode (or with hooks disabled), or a process that calls a
binary by absolute path, can bypass the hook. That is exactly why Kintsugi keeps a
filesystem-watcher backstop and snapshots: the guarantee is **"nothing is
unrecoverable,"** not "nothing runs un-warned."
