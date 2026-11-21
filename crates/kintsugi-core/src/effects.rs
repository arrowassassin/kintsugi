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
    // Lexical traversal check: any `..` component can escape. Deliberately
    // ASCII-lexical only — Unicode lookalikes (e.g. U+2024 ONE DOT LEADER)
    // are not `..` to the OS either, so treating them as traversal would be
    // both wrong and no safer; the OS-level component match is the ground truth.
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
                    if crate::rules::is_secret_path(a) {
                        set.effects.push(Effect::Unknown);
                    } else {
                        set.effects.push(Effect::FsRead((*a).to_string()));
                    }
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
            // Short value_flag with the value directly attached (`-j4`, no
            // `=`, no space) — GNU-style short-option syntax. Recognized only
            // when the two-char prefix (`-j`) is itself a declared
            // value_flag AND the attached suffix is not itself flag-shaped
            // (a `-`-prefixed suffix, e.g. `-j-C`, would smuggle an unaudited
            // flag past the audit — poison instead, mirroring the guard for
            // the separate-token form below). Never widens matching for
            // plain (non-value) short flags.
            let short_value_prefix = (!base.contains('=') && base.len() > 2)
                .then(|| &base[..2])
                .filter(|prefix| p.value_flags.iter().any(|f| f == prefix));
            if let Some(prefix) = short_value_prefix {
                if base[2..].starts_with('-') {
                    set.effects.push(Effect::Unknown);
                    return Some(set);
                }
                if !p.flags.iter().any(|f| f == prefix) {
                    set.effects.push(Effect::Unknown);
                    return Some(set);
                }
                // Attached value consumed; nothing more to do for this token.
                i += 1;
                continue;
            }
            if !p.flags.iter().any(|f| f == base) {
                set.effects.push(Effect::Unknown); // unaudited flag poisons
                return Some(set);
            }
            if p.value_flags.iter().any(|f| f == base) && !a.contains('=') {
                // The consumed value token bypasses the flag audit entirely,
                // so a smuggled flag (e.g. `-m --evil-flag`) would otherwise
                // slip through unaudited. No legitimate mode/jobs/separator
                // value starts with '-', and a value_flag at end-of-args has
                // no value to consume — poison to Unknown either way (I3).
                match args.get(i + 1) {
                    Some(v) if v.starts_with('-') => {
                        set.effects.push(Effect::Unknown);
                        return Some(set);
                    }
                    Some(_) => {
                        i += 1; // consume the flag's (validated) value
                    }
                    None => {
                        set.effects.push(Effect::Unknown);
                        return Some(set);
                    }
                }
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
    // A `reads = "none"` + `proc_exec` profile (e.g. `make`) declares that
    // running it with ONLY the audited flags has no filesystem effect of its
    // own — that's true for a bare invocation (the default target), but a
    // positional here is a *target name* (`install`, `uninstall`, `clean`,
    // …) selecting an arbitrary, unaudited recipe whose effects (e.g.
    // installing to a system directory) are invisible to this profile.
    // Poison rather than silently trust the target name — `allow_zero_args`
    // exists precisely so the bare/no-target form still rescues.
    if p.reads.as_deref() == Some("none") && !positionals.is_empty() {
        set.effects.push(Effect::Unknown);
        return Some(set);
    }

    if p.runs_workspace_file {
        // Any positional beyond the script path is an argument *to that
        // script* (e.g. `manage.py migrate`, `script.py --exec-anything`) —
        // its effects are entirely opaque to us, so it must poison the
        // profile to Unknown rather than being silently dropped. Without
        // this, `python manage.py migrate` (or any script + argv) would
        // extract as merely {FsRead, ProcExec} and rescue to Safe.
        if positionals.len() > 1 {
            set.effects.push(Effect::Unknown);
            return Some(set);
        }
        if let Some(f) = positionals.first() {
            // Reject inline-code sentinels defensively even though the flag
            // audit should have caught them.
            if crate::rules::is_secret_path(f) {
                set.effects.push(Effect::Unknown);
            } else {
                match path_scope(f, root_known) {
                    Scope::Workspace => {
                        set.effects.push(Effect::FsRead((*f).to_string()));
                        set.effects.push(Effect::ProcExec);
                    }
                    _ => set.effects.push(Effect::Unknown),
                }
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
                    if crate::rules::is_secret_path(t) {
                        set.effects.push(Effect::Unknown);
                    } else {
                        set.effects.push(Effect::FsRead(t.to_string()));
                    }
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
    fn value_flag_cannot_smuggle_unaudited_flags() {
        assert!(!extract("mkdir", &["-m", "--evil-flag", "dir"], true)
            .unwrap()
            .is_benign());
        assert!(!extract("make", &["-j", "-C"], true).unwrap().is_benign()); // flag-shaped value
        assert!(!extract("mkdir", &["-m"], true).unwrap().is_benign()); // value_flag at end
        assert!(extract("mkdir", &["-m", "755", "dir"], true)
            .unwrap()
            .is_benign()); // real value still fine
    }

    #[test]
    fn secret_reads_poison_within_the_module() {
        // `is_secret_path` doesn't recognize `/etc/shadow` (no such pattern) —
        // use paths it does match: `.ssh/id_rsa` and a bare `id_rsa` basename.
        assert!(!extract("tar", &["-tzf", "id_rsa"], true)
            .unwrap()
            .is_benign());
        assert!(!extract("sort", &["../.ssh/id_rsa"], true)
            .unwrap()
            .is_benign());
        assert!(extract("sort", &["names.txt"], true).unwrap().is_benign()); // non-secret read fine
    }

    #[test]
    fn runs_workspace_file_rejects_extra_positionals() {
        // A second positional is an argument *to* the script (e.g. a Django
        // management command) whose effects we cannot see — must poison to
        // Unknown, not be silently dropped. Guards against `python manage.py
        // migrate` (or worse, argv smuggled to the script) rescuing to Safe.
        assert!(!extract("python", &["manage.py", "migrate"], true)
            .unwrap()
            .is_benign());
        assert!(!extract("python3", &["script.py", "--anything"], true)
            .unwrap()
            .is_benign());
        // Still benign with exactly one positional.
        assert!(extract("python", &["script.py"], true).unwrap().is_benign());
    }

    #[test]
    fn make_with_a_target_name_is_not_benign() {
        // A target selects an arbitrary, unaudited recipe (e.g. `install`
        // commonly writes outside the workspace to a system prefix) — the
        // `reads = "none"` profile has no way to know what a target does, so
        // it must not be silently trusted. Only the bare/no-target form (the
        // Makefile's default target) is rescued.
        assert!(!extract("make", &["install"], true).unwrap().is_benign());
        assert!(!extract("make", &["-j4", "install"], true)
            .unwrap()
            .is_benign());
        assert!(!extract("make", &["uninstall"], true).unwrap().is_benign());
        assert!(extract("make", &[], true).unwrap().is_benign());
        assert!(extract("make", &["-j4"], true).unwrap().is_benign());
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
    #[test]
    fn attached_short_value_flag_is_recognized() {
        // `make -j4` (GNU-style attached short value) must be treated the
        // same as `make -j 4` — not poisoned as an unaudited flag.
        assert!(extract("make", &["-j4"], true).unwrap().is_benign());
        assert!(extract("make", &["-j", "4"], true).unwrap().is_benign());
        // A plain short flag must NOT be widened by this: `-j` alone with no
        // attached digits is unaffected (still a value_flag needing a value).
        assert!(!extract("make", &["-j"], true).unwrap().is_benign());
        // An attached value that is itself flag-shaped must still poison —
        // mirrors the existing smuggling guard for the separate-token form.
        assert!(!extract("make", &["-j-C"], true).unwrap().is_benign());
    }
}
