//! Security regression: destructive payloads hidden inside shell wrappers
//! (`bash -c`, `find -exec`, `xargs`, prefix launchers) must still classify as
//! Catastrophic — not get downgraded to Ambiguous by the wrapper program.

use aegis_core::{classify_line, Class};

fn cat(raw: &str) {
    assert_eq!(
        classify_line(raw).class,
        Class::Catastrophic,
        "expected CATASTROPHIC for: {raw}"
    );
}

fn not_cat(raw: &str) {
    assert_ne!(
        classify_line(raw).class,
        Class::Catastrophic,
        "expected NOT catastrophic for: {raw}"
    );
}

#[test]
fn shell_dash_c_payloads_are_unwrapped() {
    cat(r#"bash -c "rm -rf /""#);
    cat(r#"sh -c "rm -rf ~""#);
    cat(r#"zsh -c "rm -rf /""#);
    cat(r#"bash -lc "rm -rf /""#);
    // chained payload inside -c
    cat(r#"bash -c "echo hi && rm -rf /""#);
    // nested wrapping still resolves
    cat(r#"bash -c "sh -c 'rm -rf /'""#);
}

#[test]
fn find_exec_and_xargs_payloads_are_unwrapped() {
    cat(r#"find . -name '*.log' -exec rm -rf {} ';'"#);
    cat(r#"find /tmp -execdir rm -rf {} '+'"#);
    cat(r#"echo / | xargs rm -rf"#);
    cat(r#"ls | xargs -I{} rm -rf {}"#);
}

#[test]
fn prefix_launchers_resolve_to_real_program() {
    cat("timeout 5 rm -rf /");
    cat("nohup rm -rf /tmp/x -r");
    cat("setsid rm -rf / -f");
    cat("sudo timeout 5 rm -rf /");
    cat("timeout -k 5 10 rm -rf /");
}

#[test]
fn benign_wrapped_commands_stay_benign() {
    not_cat(r#"bash -c "ls -la""#);
    not_cat(r#"sh -c "echo hello""#);
    not_cat(r#"bash -lc "git status""#);
    not_cat(r#"find . -name '*.rs' -exec grep TODO {} ';'"#);
    not_cat("timeout 5 cargo test");
}

#[test]
fn deeply_nested_wrappers_terminate() {
    // Build many layers of `bash -c "..."`; must not hang or overflow.
    let mut s = String::from("rm -rf /");
    for _ in 0..40 {
        s = format!("bash -c \"{}\"", s.replace('"', "'"));
    }
    // It terminates (depth-guarded). Inner is destructive but past the depth cap
    // it simply stops unwrapping — the point is no panic / no infinite loop.
    let _ = classify_line(&s);
}
