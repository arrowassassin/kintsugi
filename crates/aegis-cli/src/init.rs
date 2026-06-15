//! `aegis init` — detect installed agents and wire up interception.
//!
//! Pure, testable helpers (agent detection, Claude settings merge, shim list)
//! are separated from the side-effecting steps (creating symlinks, writing
//! settings, starting the daemon).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Commands the `$PATH` shim intercepts by default — the dangerous ones worth
/// catching even when an agent shells out raw.
pub const SHIM_COMMANDS: &[&str] = &[
    "rm",
    "git",
    "terraform",
    "kubectl",
    "psql",
    "mysql",
    "dd",
    "shred",
    "mkfs",
    // Shell wrappers: catch destructive payloads passed as `-c`/`-exec`/stdin
    // even when the inner program is reached by absolute path or a builtin.
    "bash",
    "sh",
    "zsh",
    "find",
    "xargs",
];

/// A coding agent we detected on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedAgent {
    /// Stable id passed to `aegis-hook --agent <id>`, e.g. `"claude-code"`.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// How Aegis intercepts it.
    pub via: Interception,
}

/// The interception mechanism used for an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interception {
    /// Native pre-tool hook (Claude Code, Qwen, Gemini, Copilot, Cursor, Codex).
    Hook(HookKind),
    /// MCP `aegis-exec` tool. Retained as the documented manual fallback for
    /// agents without a blocking hook; every CLI we currently detect has one, so
    /// detection no longer emits this — but the path and binary still exist.
    #[allow(dead_code)]
    Mcp,
}

/// The flavor of native hook an agent uses, which decides how `aegis init`
/// writes its config. The wire protocol per dialect lives in `aegis-intercept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// `~/.claude/settings.json` — `hooks.PreToolUse[]`, matcher `Bash`.
    Claude,
    /// `~/.qwen/settings.json` — `hooks.PreToolUse[]` (Claude-compatible).
    Qwen,
    /// `~/.gemini/settings.json` — `hooks.BeforeTool[]`, matcher run_shell_command.
    Gemini,
    /// `~/.copilot/hooks/aegis.json` — `{version,hooks.preToolUse[]}`.
    Copilot,
    /// `~/.cursor/hooks.json` — `hooks.beforeShellExecution[]`.
    Cursor,
    /// `~/.codex/config.toml` — `[[hooks.PreToolUse]]` (Claude-compatible JSON).
    Codex,
    /// OpenCode JS plugin — `~/.config/opencode/plugin/aegis.js`.
    OpenCode,
}

impl Interception {
    pub fn as_str(self) -> &'static str {
        match self {
            Interception::Hook(_) => "native hook",
            Interception::Mcp => "MCP (aegis-exec)",
        }
    }
}

/// Detect agents by looking for their config directories under `home`.
///
/// Config-dir presence is the most reliable cross-platform signal (a CLI may be
/// installed in many ways, but it writes a dotdir on first run). Every agent we
/// can guard with a native blocking hook is detected as such; only agents with
/// no blocking pre-exec mechanism fall back to MCP.
pub fn detect_agents(home: &Path) -> Vec<DetectedAgent> {
    let mut found = Vec::new();
    let probe = |dir: &str| home.join(dir).is_dir();

    // (config dir, id, name, hook kind). Order is the display order.
    let hooked: &[(&str, &str, &str, HookKind)] = &[
        (".claude", "claude-code", "Claude Code", HookKind::Claude),
        (".qwen", "qwen", "Qwen Code", HookKind::Qwen),
        (".gemini", "gemini", "Gemini CLI", HookKind::Gemini),
        (
            ".copilot",
            "copilot",
            "GitHub Copilot CLI",
            HookKind::Copilot,
        ),
        (".cursor", "cursor", "Cursor CLI", HookKind::Cursor),
        (".codex", "codex", "Codex CLI", HookKind::Codex),
    ];
    for (dir, id, name, kind) in hooked {
        if probe(dir) {
            found.push(DetectedAgent {
                id,
                name,
                via: Interception::Hook(*kind),
            });
        }
    }

    // OpenCode keeps its config under ~/.config/opencode (XDG), with a project
    // .opencode/ as an alternative signal.
    if home.join(".config/opencode").is_dir() || probe(".opencode") {
        found.push(DetectedAgent {
            id: "opencode",
            name: "OpenCode",
            via: Interception::Hook(HookKind::OpenCode),
        });
    }

    found
}

/// Merge an Aegis pre-tool hook into an existing `settings.json`-style document,
/// idempotently. Claude Code, Qwen Code, and Gemini CLI all use the same shape —
/// `hooks.<event>[ { matcher, hooks:[{type:"command", command}] } ]` — differing
/// only in the event name (`PreToolUse` vs `BeforeTool`) and the matcher. Returns
/// the new settings document.
pub fn merge_settings_hook(
    existing: Option<Value>,
    event: &str,
    matcher: &str,
    hook_command: &str,
) -> Value {
    let mut root = match existing {
        Some(Value::Object(_)) => existing.unwrap(),
        _ => json!({}),
    };

    let obj = root.as_object_mut().expect("root is an object");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks = hooks.as_object_mut().unwrap();
    let evt = hooks.entry(event).or_insert_with(|| json!([]));
    if !evt.is_array() {
        *evt = json!([]);
    }
    let evt = evt.as_array_mut().unwrap();

    // Drop EVERY existing Aegis entry, then add exactly one fresh entry. We match
    // on the binary name (`aegis-hook`), not the full command string, so a re-run
    // after the command format changed (a new path, or adding `--agent <id>`)
    // collapses any stale/duplicate entries instead of appending another. Leaving
    // two entries made Claude run the hook twice and double-logged every command.
    evt.retain(|entry| !entry_mentions(entry, HOOK_BIN));
    evt.push(json!({
        "matcher": matcher,
        "hooks": [ { "type": "command", "command": hook_command } ]
    }));

    root
}

/// The binary basename every Aegis hook command contains — the stable marker we
/// dedupe on, regardless of the absolute path or `--agent` flag around it.
const HOOK_BIN: &str = "aegis-hook";

/// True if a `settings.json` hook entry (`{matcher, hooks:[{command}]}`) has any
/// inner hook command mentioning `needle`.
fn entry_mentions(entry: &Value, needle: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map(|hs| {
            hs.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .map(|c| c.contains(needle))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Cursor CLI wiring: `~/.cursor/hooks.json` —
/// `{version:1, hooks:{beforeShellExecution:[{command}]}}`. Cursor's entries are
/// a flat `{command}` (no matcher), so this needs its own merge. Idempotent.
pub fn merge_cursor_hooks(existing: Option<Value>, hook_command: &str) -> Value {
    let mut root = match existing {
        Some(Value::Object(_)) => existing.unwrap(),
        _ => json!({}),
    };
    let obj = root.as_object_mut().expect("root is an object");
    // Cursor's schema is versioned; set it if absent.
    obj.entry("version").or_insert_with(|| json!(1));
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks = hooks.as_object_mut().unwrap();
    let evt = hooks
        .entry("beforeShellExecution")
        .or_insert_with(|| json!([]));
    if !evt.is_array() {
        *evt = json!([]);
    }
    let evt = evt.as_array_mut().unwrap();

    // Drop any prior Aegis entry (match on the binary name, not the exact
    // command) so a format change can't leave two beforeShellExecution hooks,
    // then add exactly one.
    evt.retain(|e| {
        !e.get("command")
            .and_then(Value::as_str)
            .map(|c| c.contains(HOOK_BIN))
            .unwrap_or(false)
    });
    evt.push(json!({ "command": hook_command }));
    root
}

/// GitHub Copilot CLI wiring: the contents of `~/.copilot/hooks/aegis.json`.
///
/// Aegis owns this whole file (named after us), so we write it wholesale rather
/// than merging — a re-run just rewrites identical content. A `type:"command"`
/// hook is deliberately chosen over `type:"http"` because Copilot's command
/// hooks are *fail-closed* (a crash denies), matching our security spine.
pub fn copilot_hooks_config(hook_command: &str) -> Value {
    json!({
        "version": 1,
        "hooks": {
            "preToolUse": [
                {
                    "type": "command",
                    "bash": hook_command,
                    "timeoutSec": 30
                }
            ]
        }
    })
}

/// Codex CLI wiring: append a `[[hooks.PreToolUse]]` block to the existing
/// `~/.codex/config.toml`, idempotently. Codex's hook protocol is Claude-
/// compatible JSON; only the registration format (TOML) differs.
///
/// We append text rather than parse→serialize the whole document: it preserves
/// the user's comments and key ordering untouched, and avoids toml-rs's strict
/// rules about ordering primitive keys before sub-tables. Array-of-tables blocks
/// are valid at the end of a TOML file, after any top-level keys.
pub fn merge_codex_toml(existing: &str, hook_command: &str) -> Result<String> {
    // Idempotent: if ANY Aegis hook is already registered (match on the binary
    // name, not the exact command), leave the file alone. Matching the full
    // command instead would append a second block when the command format
    // changed, which double-runs the hook and double-logs every command.
    if existing.contains(HOOK_BIN) {
        return Ok(existing.to_string());
    }
    let escaped = hook_command.replace('\\', "\\\\").replace('"', "\\\"");
    let block = format!(
        "\n# added by `aegis init` — guards Codex shell commands via Aegis\n\
         [[hooks.PreToolUse]]\n\
         matcher = \"^Bash$\"\n\n\
         [[hooks.PreToolUse.hooks]]\n\
         type = \"command\"\n\
         command = \"{escaped}\"\n"
    );
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);
    Ok(out)
}

/// OpenCode wiring: the JS plugin written to
/// `~/.config/opencode/plugin/aegis.js`. OpenCode has no external-command hook —
/// only an in-process `tool.execute.before` plugin that aborts a call by
/// throwing. This plugin shells out to `aegis-hook --agent opencode`, passing
/// the command as JSON on stdin, and throws when the verdict isn't allow.
///
/// `hook_bin` is the absolute path to the `aegis-hook` binary so the plugin
/// works regardless of the user's `$PATH` inside OpenCode's runtime.
pub fn opencode_plugin_js(hook_bin: &str) -> String {
    // The plugin is ESM (OpenCode loads it under Bun). We keep it dependency-free
    // and use node:child_process, which Bun supports.
    let bin = hook_bin.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"// Generated by `aegis init`. Bridges OpenCode's tool.execute.before hook
// to the Aegis daemon. Aborts (throws) a bash tool call when Aegis denies or
// holds it. Safe to delete; re-created on the next `aegis init`.
import {{ spawnSync }} from "node:child_process";

const AEGIS_HOOK = "{bin}";

export const AegisPlugin = async () => ({{
  "tool.execute.before": async (input, output) => {{
    if (!input || input.tool !== "bash") return;
    const command = output?.args?.command;
    if (!command || !command.trim()) return;
    let verdict = {{ decision: "allow", reason: "" }};
    try {{
      const res = spawnSync(AEGIS_HOOK, ["--agent", "opencode"], {{
        input: JSON.stringify({{ command, cwd: process.cwd() }}),
        encoding: "utf8",
        timeout: 60000,
      }});
      if (res.stdout) verdict = JSON.parse(res.stdout);
    }} catch (e) {{
      // Fail open on a bridge error: Aegis's own catastrophic floor is enforced
      // inside aegis-hook (fail-closed there); a spawn/parse failure here must
      // not wedge the agent. The daemon still logs what it saw.
      return;
    }}
    if (verdict && (verdict.decision === "deny" || verdict.decision === "ask")) {{
      throw new Error(verdict.reason || "Blocked by Aegis");
    }}
  }},
}});
"#
    )
}

/// Resolve a sibling binary that ships next to the running `aegis` executable,
/// falling back to the bare name (assumed on `$PATH`).
pub fn sibling_bin(name: &str) -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(exe_name(name));
            if cand.exists() {
                return cand;
            }
        }
    }
    PathBuf::from(name)
}

fn exe_name(name: &str) -> String {
    #[cfg(windows)]
    {
        format!("{name}.exe")
    }
    #[cfg(not(windows))]
    {
        name.to_string()
    }
}

/// Create the shim directory and link each command name to `aegis-shim`.
///
/// Idempotent: an existing correct link is left alone; a wrong one is replaced.
/// Returns the list of command names linked.
pub fn create_shims(shim_dir: &Path, shim_bin: &Path, commands: &[&str]) -> Result<Vec<String>> {
    std::fs::create_dir_all(shim_dir)
        .with_context(|| format!("create shim dir {}", shim_dir.display()))?;
    let mut linked = Vec::new();
    for name in commands {
        let link = shim_dir.join(name);
        if link.exists() || link.is_symlink() {
            let _ = std::fs::remove_file(&link);
        }
        symlink_file(shim_bin, &link)
            .with_context(|| format!("link {} -> {}", link.display(), shim_bin.display()))?;
        linked.push((*name).to_string());
    }
    Ok(linked)
}

#[cfg(unix)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_claude_and_codex_both_via_hook() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        let found = detect_agents(tmp.path());
        assert_eq!(found.len(), 2);
        let claude = found.iter().find(|a| a.id == "claude-code").unwrap();
        assert_eq!(claude.via, Interception::Hook(HookKind::Claude));
        let codex = found.iter().find(|a| a.id == "codex").unwrap();
        assert_eq!(codex.via, Interception::Hook(HookKind::Codex));
    }

    #[test]
    fn detects_nothing_in_empty_home() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(detect_agents(tmp.path()).is_empty());
    }

    #[test]
    fn detects_all_hook_agents() {
        let tmp = tempfile::tempdir().unwrap();
        for dir in [".cursor", ".qwen", ".gemini", ".copilot"] {
            std::fs::create_dir_all(tmp.path().join(dir)).unwrap();
        }
        std::fs::create_dir_all(tmp.path().join(".config/opencode")).unwrap();
        let found = detect_agents(tmp.path());
        for (id, kind) in [
            ("cursor", HookKind::Cursor),
            ("qwen", HookKind::Qwen),
            ("gemini", HookKind::Gemini),
            ("copilot", HookKind::Copilot),
            ("opencode", HookKind::OpenCode),
        ] {
            let a = found
                .iter()
                .find(|a| a.id == id)
                .unwrap_or_else(|| panic!("expected to detect {id}"));
            assert_eq!(a.via, Interception::Hook(kind));
        }
    }

    #[test]
    fn detects_opencode_via_project_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".opencode")).unwrap();
        let found = detect_agents(tmp.path());
        assert!(found.iter().any(|a| a.id == "opencode"));
    }

    fn merge_claude(existing: Option<Value>, cmd: &str) -> Value {
        merge_settings_hook(existing, "PreToolUse", "Bash", cmd)
    }

    #[test]
    fn merge_into_empty_settings_adds_bash_hook() {
        let merged = merge_claude(None, "aegis-hook");
        let pre = &merged["hooks"]["PreToolUse"];
        assert_eq!(pre.as_array().unwrap().len(), 1);
        assert_eq!(pre[0]["matcher"], "Bash");
        assert_eq!(pre[0]["hooks"][0]["command"], "aegis-hook");
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge_claude(None, "aegis-hook");
        let twice = merge_claude(Some(once.clone()), "aegis-hook");
        assert_eq!(once, twice);
        assert_eq!(twice["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_preserves_existing_unrelated_settings() {
        let existing = json!({
            "model": "claude-opus",
            "hooks": { "PreToolUse": [
                { "matcher": "Edit", "hooks": [{ "type": "command", "command": "other" }] }
            ]}
        });
        let merged = merge_claude(Some(existing), "aegis-hook");
        assert_eq!(merged["model"], "claude-opus");
        let pre = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "keeps the Edit hook and adds Bash");
    }

    #[test]
    fn merge_replaces_non_object_hooks_value() {
        let existing = json!({ "hooks": "garbage" });
        let merged = merge_claude(Some(existing), "aegis-hook");
        assert!(merged["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn gemini_uses_beforetool_event() {
        let merged = merge_settings_hook(
            None,
            "BeforeTool",
            "run_shell_command",
            "aegis-hook --agent gemini",
        );
        let evt = merged["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(evt.len(), 1);
        assert_eq!(evt[0]["matcher"], "run_shell_command");
        assert_eq!(evt[0]["hooks"][0]["command"], "aegis-hook --agent gemini");
    }

    #[test]
    fn settings_hook_merge_is_idempotent() {
        let once = merge_settings_hook(None, "PreToolUse", "Bash", "aegis-hook --agent qwen");
        let twice = merge_settings_hook(
            Some(once.clone()),
            "PreToolUse",
            "Bash",
            "aegis-hook --agent qwen",
        );
        assert_eq!(once, twice);
        assert_eq!(twice["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn settings_hook_merge_collapses_stale_format_to_one() {
        // Simulate the real bug: an old-format Aegis hook (bare command, no
        // --agent and a different path) already in settings. A re-run with the
        // new command must REPLACE it, not append — exactly one Aegis hook.
        let stale = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [
                    { "type": "command", "command": "/old/path/aegis-hook" }
                ]},
                // an unrelated user hook that must survive
                { "matcher": "Edit", "hooks": [
                    { "type": "command", "command": "my-linter" }
                ]}
            ]}
        });
        let merged = merge_settings_hook(
            Some(stale),
            "PreToolUse",
            "Bash",
            "/new/path/aegis-hook --agent claude",
        );
        let pre = merged["hooks"]["PreToolUse"].as_array().unwrap();
        // The user's Edit hook + exactly one Aegis hook = 2 entries.
        assert_eq!(pre.len(), 2, "stale Aegis hook must be replaced, not added");
        let aegis_entries = pre
            .iter()
            .filter(|e| entry_mentions(e, "aegis-hook"))
            .count();
        assert_eq!(aegis_entries, 1, "exactly one Aegis hook must remain");
        // And it's the new command, not the stale one.
        assert!(pre
            .iter()
            .any(|e| entry_mentions(e, "/new/path/aegis-hook --agent claude")));
        assert!(pre.iter().any(|e| e["matcher"] == "Edit"));
    }

    #[test]
    fn cursor_hooks_merge_collapses_stale_entry() {
        let stale = json!({
            "version": 1,
            "hooks": { "beforeShellExecution": [
                { "command": "/old/aegis-hook" }
            ]}
        });
        let merged = merge_cursor_hooks(Some(stale), "/new/aegis-hook --agent cursor");
        let evt = merged["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(evt.len(), 1, "one Aegis cursor hook, not two");
        assert_eq!(evt[0]["command"], "/new/aegis-hook --agent cursor");
    }

    #[test]
    fn codex_toml_merge_does_not_duplicate_across_format_change() {
        // An old-format Aegis hook with a different command must NOT trigger a
        // second appended block.
        let old = "model = \"gpt-5\"\n\n[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n\n\
                   [[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"/old/aegis-hook\"\n";
        let merged = merge_codex_toml(old, "/new/aegis-hook --agent codex").unwrap();
        assert_eq!(merged, old, "must not append a second Aegis block");
        assert_eq!(merged.matches("aegis-hook").count(), 1);
    }

    #[test]
    fn cursor_hooks_merge_adds_before_shell_and_is_idempotent() {
        let cmd = "aegis-hook --agent cursor";
        let once = merge_cursor_hooks(None, cmd);
        assert_eq!(once["version"], 1);
        let evt = once["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(evt.len(), 1);
        assert_eq!(evt[0]["command"], cmd);
        let twice = merge_cursor_hooks(Some(once.clone()), cmd);
        assert_eq!(once, twice, "re-run must not duplicate");
    }

    #[test]
    fn cursor_hooks_merge_preserves_other_events() {
        let existing = json!({
            "version": 1,
            "hooks": { "afterFileEdit": [{ "command": "logger" }] }
        });
        let merged = merge_cursor_hooks(Some(existing), "aegis-hook --agent cursor");
        assert!(merged["hooks"]["afterFileEdit"].is_array());
        assert_eq!(
            merged["hooks"]["beforeShellExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn copilot_config_has_failclosed_command_hook() {
        let cfg = copilot_hooks_config("aegis-hook --agent copilot");
        assert_eq!(cfg["version"], 1);
        let pre = cfg["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(pre[0]["type"], "command");
        assert_eq!(pre[0]["bash"], "aegis-hook --agent copilot");
    }

    #[test]
    fn codex_toml_merge_adds_pretooluse_and_is_idempotent() {
        let cmd = "aegis-hook --agent codex";
        let first = merge_codex_toml("", cmd).unwrap();
        assert!(first.contains("[[hooks.PreToolUse]]") || first.contains("PreToolUse"));
        assert!(first.contains(cmd));
        // Re-running over our own output must not add a second block.
        let second = merge_codex_toml(&first, cmd).unwrap();
        let count = second.matches(cmd).count();
        assert_eq!(count, 1, "codex hook must not duplicate:\n{second}");
    }

    #[test]
    fn codex_toml_merge_preserves_existing_keys() {
        let existing = "model = \"gpt-5\"\napproval_policy = \"on-request\"\n";
        let merged = merge_codex_toml(existing, "aegis-hook --agent codex").unwrap();
        assert!(merged.contains("model = \"gpt-5\""));
        assert!(merged.contains("approval_policy = \"on-request\""));
        assert!(merged.contains("aegis-hook --agent codex"));
    }

    #[test]
    fn opencode_plugin_references_the_binary_and_bridges_bash() {
        let js = opencode_plugin_js("/usr/local/bin/aegis-hook");
        assert!(js.contains("/usr/local/bin/aegis-hook"));
        assert!(js.contains("tool.execute.before"));
        assert!(js.contains("--agent"));
        assert!(js.contains("opencode"));
        assert!(js.contains("throw new Error"));
    }

    #[test]
    fn create_shims_links_every_command() {
        let tmp = tempfile::tempdir().unwrap();
        let shim_dir = tmp.path().join("shims");
        let fake_bin = tmp.path().join("aegis-shim");
        std::fs::write(&fake_bin, b"#!/bin/sh\n").unwrap();

        let linked = create_shims(&shim_dir, &fake_bin, &["rm", "git"]).unwrap();
        assert_eq!(linked, vec!["rm", "git"]);
        assert!(shim_dir.join("rm").exists());
        assert!(shim_dir.join("git").exists());

        // Idempotent re-run does not error.
        let again = create_shims(&shim_dir, &fake_bin, &["rm", "git"]).unwrap();
        assert_eq!(again.len(), 2);
    }
}
