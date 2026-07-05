//! Deterministic effect extraction: reduce (program, args) to the complete
//! set of filesystem/network/process effects, or `None`/`Unknown` when we
//! can't be sure. Spec: docs/superpowers/specs/2026-06-23-effects-engine-phase0-1-design.md §3.
//!
//! SECURITY CONTRACT (spec §3.2): callers may use a fully-benign EffectSet
//! ONLY to upgrade an `ambiguous:{prog}` fall-through to Safe. Nothing here
//! may run before the catastrophic checks or influence any other verdict.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Workspace,
    Outside,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    FsRead(String),
    FsWrite(String, Scope),
    FsDelete(String, Scope),
    NetEgress,
    ProcExec,
    PrivEsc,
    ShellEval,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct EffectSet {
    pub effects: Vec<Effect>,
}

impl EffectSet {
    /// The rescue predicate: complete, bounded, all-benign (spec §3.1 rule 4).
    /// Reads are benign only because the caller (classify_segment_depth) has
    /// already run the secret-path and catastrophic checks on this segment.
    pub fn is_benign(&self) -> bool {
        self.effects.iter().all(|e| match e {
            Effect::FsRead(_) => true,
            Effect::FsWrite(_, s) | Effect::FsDelete(_, s) => *s == Scope::Workspace,
            Effect::ProcExec => true, // child commands are themselves intercepted
            Effect::NetEgress | Effect::PrivEsc | Effect::ShellEval | Effect::Unknown => false,
        })
    }
}

/// Classify a path token's write-scope, paranoid (spec §3.4).
/// `root_known=false` means the caller has no cwd (classify_line): only
/// purely-relative, traversal-free paths count as Workspace by construction.
pub fn path_scope(token: &str, root_known: bool) -> Scope {
    let t = token.trim();
    if t.is_empty() {
        return Scope::Unknown;
    }
    // Anything the shell might rewrite or that escapes: not provably confined.
    if t.starts_with('~') || t.starts_with('$') || t.contains("$(") || t.contains('`') {
        return Scope::Unknown;
    }
    if t.starts_with('/') {
        return Scope::Outside; // absolute: judged Outside even with a root —
                               // Phase 0 rescues only relative paths (paranoid).
    }
    // Lexical traversal check: any `..` component can escape.
    if std::path::Path::new(t)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Scope::Unknown;
    }
    // Relative + traversal-free: stays under the execution cwd. When the
    // root is unknown this is still confinement *to the cwd*, which is the
    // workspace guarantee Phase 0 promises.
    let _ = root_known;
    Scope::Workspace
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default)]
    reads: Option<String>,
    #[serde(default)]
    writes: Option<String>,
    #[serde(default)]
    deletes: Option<String>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    value_flags: Vec<String>,
    #[serde(default)]
    list_flags: Vec<String>,
    #[serde(default)]
    safe_subcommands: Vec<String>,
    #[serde(default)]
    proc_exec: bool,
    #[serde(default)]
    runs_workspace_file: bool,
    #[serde(default)]
    skip_first_positional: bool,
    #[serde(default)]
    allow_zero_args: bool,
    #[serde(default)]
    handled_in_code: bool,
}

fn manifests() -> &'static HashMap<String, Profile> {
    static M: OnceLock<HashMap<String, Profile>> = OnceLock::new();
    M.get_or_init(|| {
        // A malformed manifest disables the whole engine (fail closed, I3).
        toml::from_str(include_str!("effects/manifest.toml")).unwrap_or_default()
    })
}

/// Resolve a path-role keyword (`reads`/`writes`/`deletes` in the manifest)
/// against the parsed positionals, returning the concrete target tokens.
/// `None` means the role name itself is unrecognized (poisons the profile).
fn expand_role<'a>(role: &str, positionals: &[&'a str]) -> Option<Vec<&'a str>> {
    match role {
        "all-args" | "path-args" => Some(positionals.to_vec()),
        "init-args" => Some(positionals[..positionals.len().saturating_sub(1)].to_vec()),
        "last-arg" => Some(positionals.last().map(|l| vec![*l]).unwrap_or_default()),
        "none" => Some(Vec::new()),
        _ => None,
    }
}

/// Extract the effect set for `prog args…`, or None when no manifest covers
/// the program (→ caller keeps the Ambiguous verdict).
pub fn extract(prog: &str, args: &[&str], root_known: bool) -> Option<EffectSet> {
    let p = manifests().get(prog)?;
    if p.handled_in_code {
        return None; // git etc. — covered by is_safe_git today; no rescue here.
    }
    let mut set = EffectSet::default();

    // docker/kubectl-style: judged purely on the first positional subcommand.
    if !p.safe_subcommands.is_empty() {
        match args.iter().find(|a| !a.starts_with('-')) {
            Some(sub) if p.safe_subcommands.iter().any(|s| s == sub) => return Some(set),
            _ => {
                set.effects.push(Effect::Unknown);
                return Some(set);
            }
        }
    }

    // tar-style list mode: first token must be an audited list flag.
    if !p.list_flags.is_empty() {
        match args.first() {
            Some(f) if p.list_flags.iter().any(|l| l == f) => {
                for a in &args[1..] {
                    set.effects.push(Effect::FsRead((*a).to_string()));
                }
                return Some(set);
            }
            _ => {
                set.effects.push(Effect::Unknown);
                return Some(set);
            }
        }
    }

    // Generic path-role profiles: split flags from positionals, strictly.
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a.starts_with('-') && a.len() > 1 {
            // Audited flag? (exact match, or --flag=value form of an audited flag)
            let base = a.split('=').next().unwrap_or(a);
            if !p.flags.iter().any(|f| f == base) {
                set.effects.push(Effect::Unknown); // unaudited flag poisons
                return Some(set);
            }
            if p.value_flags.iter().any(|f| f == base) && !a.contains('=') {
                i += 1; // consume the flag's value
            }
        } else {
            positionals.push(a);
        }
        i += 1;
    }

    // awk's program text is a skipped positional but may hide a `system()`
    // call or backtick — invisible to the flag audit above. Reject it (I3).
    if prog == "awk" {
        if let Some(first) = positionals.first() {
            if first.contains("system(") || first.contains('`') {
                set.effects.push(Effect::Unknown);
                return Some(set);
            }
        }
    }

    if p.skip_first_positional && !positionals.is_empty() {
        positionals.remove(0);
    }
    if positionals.is_empty() && !p.allow_zero_args {
        set.effects.push(Effect::Unknown);
        return Some(set);
    }

    if p.runs_workspace_file {
        if let Some(f) = positionals.first() {
            // Reject inline-code sentinels defensively even though the flag
            // audit should have caught them.
            match path_scope(f, root_known) {
                Scope::Workspace => {
                    set.effects.push(Effect::FsRead((*f).to_string()));
                    set.effects.push(Effect::ProcExec);
                }
                _ => set.effects.push(Effect::Unknown),
            }
        }
        return Some(set);
    }
    if p.proc_exec {
        set.effects.push(Effect::ProcExec);
    }

    if let Some(role) = p.reads.as_deref() {
        match expand_role(role, &positionals) {
            Some(targets) => {
                for t in targets {
                    set.effects.push(Effect::FsRead(t.to_string()));
                }
            }
            None => set.effects.push(Effect::Unknown),
        }
    }
    if let Some(role) = p.writes.as_deref() {
        match expand_role(role, &positionals) {
            Some(targets) => {
                for t in targets {
                    set.effects
                        .push(Effect::FsWrite(t.to_string(), path_scope(t, root_known)));
                }
            }
            None => set.effects.push(Effect::Unknown),
        }
    }
    if let Some(role) = p.deletes.as_deref() {
        match expand_role(role, &positionals) {
            Some(targets) => {
                for t in targets {
                    set.effects
                        .push(Effect::FsDelete(t.to_string(), path_scope(t, root_known)));
                }
            }
            None => set.effects.push(Effect::Unknown),
        }
    }

    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args<'a>(v: &[&'a str]) -> Vec<&'a str> {
        v.to_vec()
    }

    #[test]
    fn mkdir_relative_is_benign() {
        let e = extract("mkdir", &args(&["-p", "build/out"]), true).unwrap();
        assert!(e.is_benign(), "{e:?}");
    }

    #[test]
    fn unknown_program_has_no_manifest() {
        assert!(extract("weirdtool", &args(&["x"]), true).is_none());
    }

    #[test]
    fn cp_reads_sources_writes_dest() {
        let e = extract("cp", &args(&["a.txt", "b.txt"]), true).unwrap();
        assert!(e
            .effects
            .iter()
            .any(|x| matches!(x, Effect::FsRead(p) if p == "a.txt")));
        assert!(e
            .effects
            .iter()
            .any(|x| matches!(x, Effect::FsWrite(p, Scope::Workspace) if p == "b.txt")));
        assert!(e.is_benign());
    }

    #[test]
    fn absolute_path_is_outside() {
        let e = extract("mkdir", &args(&["/etc/foo"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn traversal_is_not_workspace() {
        let e = extract("cp", &args(&["a", "../../x"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn unlisted_flag_invalidates_profile() {
        // `cp --no-preserve=mode` fine, but a flag we haven't audited (e.g.
        // hypothetical `--hook=cmd`) must poison the profile -> Unknown.
        let e = extract("chmod", &args(&["--reference=/etc/shadow", "f"]), true).unwrap();
        assert!(!e.is_benign());
    }

    #[test]
    fn tar_list_ok_extract_unknown() {
        assert!(extract("tar", &args(&["-tzf", "a.tgz"]), true)
            .unwrap()
            .is_benign());
        assert!(!extract("tar", &args(&["-xzf", "a.tgz"]), true)
            .unwrap()
            .is_benign());
    }

    #[test]
    fn no_root_known_only_pure_relative_pass() {
        // When the workspace root is unknown (classify_line without cwd),
        // relative traversal-free paths are still Workspace by construction;
        // everything else is Unknown.
        assert!(extract("mkdir", &args(&["sub/dir"]), false)
            .unwrap()
            .is_benign());
        assert!(!extract("mkdir", &args(&["~/dir"]), false)
            .unwrap()
            .is_benign());
    }

    #[test]
    fn manifest_parses_and_is_nonempty() {
        // A malformed embedded manifest silently fails closed (empty map).
        // Assert the real manifest actually parses and covers the expected
        // floor, so a future TOML typo is caught by CI, not swallowed.
        assert!(
            manifests().contains_key("mkdir"),
            "embedded manifest failed to parse or is missing 'mkdir': {:?}",
            manifests().keys().collect::<Vec<_>>()
        );
    }
}
