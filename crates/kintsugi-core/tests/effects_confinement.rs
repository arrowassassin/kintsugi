//! Confinement is the footgun (spec §3.4): every trick that could smuggle a
//! write outside the workspace must land on Outside or Unknown — never
//! Workspace. Paranoia is correct; the worst case must be an unnecessary
//! question, never a miss.

use kintsugi_core::effects::{extract, path_scope, Scope};

#[test]
fn traversal_variants_never_confined() {
    for p in [
        "../x", "a/../../x", "./../x", "a/b/../../../etc", "..", "a/..",
    ] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn absolute_and_home_never_confined() {
    for p in ["/etc/passwd", "/tmp/x", "~/x", "~root/x", "$HOME/x", "${HOME}/x"] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn substitution_and_backticks_never_confined() {
    for p in ["$(pwd)/x", "`pwd`/x", "a$(cmd)b", "$VAR/dir"] {
        assert_ne!(path_scope(p, true), Scope::Workspace, "escaped: {p}");
    }
}

#[test]
fn plain_relative_is_confined() {
    for p in ["x", "a/b/c", "./x", "dir/", "weird name.txt", ".hidden/file"] {
        assert_eq!(path_scope(p, true), Scope::Workspace, "over-held: {p}");
    }
}

#[test]
fn empty_and_whitespace_are_unknown() {
    assert_eq!(path_scope("", true), Scope::Unknown);
    assert_eq!(path_scope("   ", true), Scope::Unknown);
}

#[test]
fn secret_relative_paths_still_blocked_upstream() {
    // .env is relative and traversal-free — path_scope alone calls it
    // Workspace. The SECRET check lives upstream (is_secret_path runs in
    // catastrophic checks / is_safe before any rescue). Prove the composed
    // classifier still holds/blocks it after the rescue lands (Task 5 test);
    // here we just document the division of labor.
    assert_eq!(path_scope(".env", true), Scope::Workspace);
}

#[test]
fn extract_never_panics_on_garbage() {
    for line in [
        vec!["--", "-", "---x"],
        vec![""],
        vec!["\u{0}"],
        vec!["-p"],
        vec!["a", "b", "c", "d", "e", "f", "g"],
    ] {
        let _ = extract("mkdir", &line, true);
        let _ = extract("cp", &line, true);
        let _ = extract("tar", &line, true);
    }
}
