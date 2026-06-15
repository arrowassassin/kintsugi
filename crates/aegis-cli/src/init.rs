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
    /// Stable id, e.g. `"claude-code"`.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// How Aegis intercepts it.
    pub via: Interception,
}

/// The interception mechanism used for an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interception {
    /// Native hook (Claude Code).
    Hook,
    /// MCP `aegis-exec` tool.
    Mcp,
}

impl Interception {
    pub fn as_str(self) -> &'static str {
        match self {
            Interception::Hook => "hook",
            Interception::Mcp => "MCP (aegis-exec)",
        }
    }
}

/// Detect agents by looking for their config directories under `home`.
///
/// Config-dir presence is the most reliable cross-platform signal (a CLI may be
/// installed in many ways, but it writes a dotdir on first run).
pub fn detect_agents(home: &Path) -> Vec<DetectedAgent> {
    let mut found = Vec::new();
    let probe = |dir: &str| home.join(dir).is_dir();

    if probe(".claude") {
        found.push(DetectedAgent {
            id: "claude-code",
            name: "Claude Code",
            via: Interception::Hook,
        });
    }
    for (dir, id, name) in [
        (".codex", "codex", "Codex CLI"),
        (".cursor", "cursor", "Cursor CLI"),
        (".qwen", "qwen", "Qwen CLI"),
        (".gemini", "gemini", "Gemini CLI"),
    ] {
        if probe(dir) {
            found.push(DetectedAgent {
                id,
                name,
                via: Interception::Mcp,
            });
        }
    }
    found
}

/// Merge an Aegis `PreToolUse` Bash hook into existing Claude Code settings,
/// idempotently. Returns the new settings document.
pub fn merge_claude_settings(existing: Option<Value>, hook_command: &str) -> Value {
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
    let pre = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    if !pre.is_array() {
        *pre = json!([]);
    }
    let pre = pre.as_array_mut().unwrap();

    // Already wired? Look for any hook command mentioning our binary.
    let already = pre.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .map(|hs| {
                hs.iter().any(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .map(|c| c.contains(hook_command))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });

    if !already {
        pre.push(json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": hook_command } ]
        }));
    }

    root
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
    fn detects_claude_via_hook_and_codex_via_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        let found = detect_agents(tmp.path());
        assert_eq!(found.len(), 2);
        let claude = found.iter().find(|a| a.id == "claude-code").unwrap();
        assert_eq!(claude.via, Interception::Hook);
        let codex = found.iter().find(|a| a.id == "codex").unwrap();
        assert_eq!(codex.via, Interception::Mcp);
    }

    #[test]
    fn detects_nothing_in_empty_home() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(detect_agents(tmp.path()).is_empty());
    }

    #[test]
    fn detects_cursor_qwen_gemini_via_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        for dir in [".cursor", ".qwen", ".gemini"] {
            std::fs::create_dir_all(tmp.path().join(dir)).unwrap();
        }
        let found = detect_agents(tmp.path());
        for id in ["cursor", "qwen", "gemini"] {
            let a = found
                .iter()
                .find(|a| a.id == id)
                .unwrap_or_else(|| panic!("expected to detect {id}"));
            assert_eq!(a.via, Interception::Mcp);
        }
    }

    #[test]
    fn merge_into_empty_settings_adds_bash_hook() {
        let merged = merge_claude_settings(None, "aegis-hook");
        let pre = &merged["hooks"]["PreToolUse"];
        assert_eq!(pre.as_array().unwrap().len(), 1);
        assert_eq!(pre[0]["matcher"], "Bash");
        assert_eq!(pre[0]["hooks"][0]["command"], "aegis-hook");
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge_claude_settings(None, "aegis-hook");
        let twice = merge_claude_settings(Some(once.clone()), "aegis-hook");
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
        let merged = merge_claude_settings(Some(existing), "aegis-hook");
        assert_eq!(merged["model"], "claude-opus");
        let pre = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "keeps the Edit hook and adds Bash");
    }

    #[test]
    fn merge_replaces_non_object_hooks_value() {
        let existing = json!({ "hooks": "garbage" });
        let merged = merge_claude_settings(Some(existing), "aegis-hook");
        assert!(merged["hooks"]["PreToolUse"].is_array());
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
