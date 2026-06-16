//! The `$PATH` shim adapter.
//!
//! When a directory of symlinks (`rm`, `git`, `terraform`, …) all pointing at the
//! `kintsugi-shim` binary is prepended to `$PATH`, every matching shell-out lands
//! here first. The shim:
//!
//! 1. recovers the command name from `argv[0]` (or `argv[1]` if invoked directly),
//! 2. captures `argv` + cwd into a [`ProposedCommand`] tagged `agent = "shim"`,
//! 3. asks the daemon for a [`Verdict`] and enforces it, then
//! 4. on allow, **execs the real binary** so exit code, stdio, and signals are
//!    forwarded with perfect fidelity (on Unix the shim *becomes* the real
//!    process).
//!
//! Fail-open by default (record-but-don't-block when the daemon is down), which
//! matches the honest guarantee — "nothing unrecoverable", not "nothing
//! un-warned". Set `KINTSUGI_FAIL_CLOSED=1` to block instead.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kintsugi_core::{Decision, ProposedCommand, Verdict};
use kintsugi_daemon::{Client, Resolution};

/// Exit code used when Kintsugi refuses to run a command (mirrors shell "cannot
/// execute": 126).
pub const EXIT_BLOCKED: u8 = 126;
/// Exit code when the real binary cannot be found (mirrors shell 127).
pub const EXIT_NOT_FOUND: u8 = 127;

/// Entry point for the `kintsugi-shim` binary.
///
/// Returns an [`ExitCode`] only on the non-exec paths (blocked / not-found /
/// daemon-down-fail-closed). On the happy path under Unix it never returns: the
/// process image is replaced by the real binary.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let invoked = program_name(args.first().map(String::as_str).unwrap_or("kintsugi-shim"));

    let (cmd_name, cmd_args) = match split_invocation(&invoked, &args) {
        Some(v) => v,
        None => {
            eprintln!("usage: kintsugi-shim <command> [args...]");
            return ExitCode::from(EXIT_BLOCKED);
        }
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let raw = render_command(&cmd_name, &cmd_args);
    let mut argv = Vec::with_capacity(cmd_args.len() + 1);
    argv.push(cmd_name.clone());
    argv.extend(cmd_args.iter().cloned());
    // Raw shell-outs have no agent session; group by KINTSUGI_SESSION if the shell
    // exports one, else leave it unset (best-effort, per CLAUDE.md honesty).
    let session = std::env::var("KINTSUGI_SESSION").ok();
    let proposed = ProposedCommand::new("shim", cwd, argv, raw).with_session(session);

    match consult_daemon(&proposed) {
        DaemonOutcome::Allow => {}
        DaemonOutcome::Refuse(code) => return ExitCode::from(code),
    }

    // Allowed: hand off to the real binary.
    match resolve_real_binary(&cmd_name) {
        Some(real) => exec_real(&real, &cmd_name, &cmd_args),
        None => {
            eprintln!("kintsugi: {cmd_name}: command not found");
            ExitCode::from(EXIT_NOT_FOUND)
        }
    }
}

enum DaemonOutcome {
    Allow,
    Refuse(u8),
}

/// Ask the daemon and translate its verdict into an allow/refuse outcome,
/// prompting the human with the hold card when the command is held.
fn consult_daemon(proposed: &ProposedCommand) -> DaemonOutcome {
    match Client::send(proposed) {
        Ok(verdict) => enforce(proposed, &verdict),
        Err(e) => {
            // Daemon down: locally run the Tier-1 classifier so the catastrophic
            // hard floor still blocks (fail-closed for catastrophic) even though we
            // can't record the event. Non-catastrophic honors the fail-open default.
            if kintsugi_core::classify(proposed).class == kintsugi_core::Class::Catastrophic {
                eprintln!(
                    "kintsugi: daemon unreachable; blocking catastrophic command (fail-closed): {e}"
                );
                DaemonOutcome::Refuse(EXIT_BLOCKED)
            } else if fail_closed() {
                eprintln!("kintsugi: daemon unreachable; blocking (fail-closed): {e}");
                DaemonOutcome::Refuse(EXIT_BLOCKED)
            } else {
                eprintln!("kintsugi: warning: daemon unreachable; running unguarded: {e}");
                DaemonOutcome::Allow
            }
        }
    }
}

/// Map a verdict to an outcome, prompting on Hold.
fn enforce(proposed: &ProposedCommand, verdict: &Verdict) -> DaemonOutcome {
    match verdict.decision {
        Decision::Allow => DaemonOutcome::Allow,
        Decision::Deny => {
            eprintln!("kintsugi: blocked [{}]: {}", verdict.class, verdict.reason);
            DaemonOutcome::Refuse(EXIT_BLOCKED)
        }
        Decision::Hold => prompt_and_resolve(proposed, verdict),
    }
}

/// Show the hold card, read one key from the terminal, and record the human's
/// resolution. With no terminal/stdin available, default to deny (safe).
fn prompt_and_resolve(proposed: &ProposedCommand, verdict: &Verdict) -> DaemonOutcome {
    let color = std::env::var_os("NO_COLOR").is_none();
    eprint!("{}", crate::holdcard::render(&proposed.raw, verdict, color));

    let (decision, remember) = match read_key() {
        Some('a') => (Decision::Allow, false),
        Some('r') => (Decision::Allow, true),
        Some('d') => (Decision::Deny, false),
        _ => {
            // No answer (no TTY, EOF, or anything else) → safe default: deny,
            // and do not record a resolution (the held event already stands).
            eprintln!("kintsugi: no decision given; leaving the command held (not run).");
            return DaemonOutcome::Refuse(EXIT_BLOCKED);
        }
    };

    // Record the human's resolution (best-effort).
    let resolution = Resolution {
        command: proposed.clone(),
        decision,
        remember,
    };
    if let Err(e) = Client::resolve(&resolution) {
        eprintln!("kintsugi: warning: could not record resolution: {e}");
    }

    match decision {
        Decision::Allow => DaemonOutcome::Allow,
        _ => DaemonOutcome::Refuse(EXIT_BLOCKED),
    }
}

/// Read a single decision key from the controlling terminal, falling back to
/// stdin. Returns the lowercased first non-whitespace character, if any.
fn read_key() -> Option<char> {
    use std::io::BufReader;

    // Prefer the real terminal so we read the human, not an agent's piped stdin.
    #[cfg(unix)]
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        if let Some(c) = first_char(BufReader::new(tty)) {
            return Some(c);
        }
    }
    // Fall back to stdin (used in tests and non-TTY pipelines).
    let stdin = std::io::stdin();
    first_char(BufReader::new(stdin.lock()))
}

fn first_char<R: std::io::BufRead>(mut reader: R) -> Option<char> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    line.trim().chars().next().map(|c| c.to_ascii_lowercase())
}

/// Whether the shim should block when the daemon is unreachable.
fn fail_closed() -> bool {
    matches!(
        std::env::var("KINTSUGI_FAIL_CLOSED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Split the program invocation into `(command, args)`.
///
/// - Invoked via a symlink (`rm foo`): command = `rm`, args = `[foo]`.
/// - Invoked directly (`kintsugi-shim rm foo`): command = `rm`, args = `[foo]`.
fn split_invocation(invoked: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    if invoked == "kintsugi-shim" || invoked == "kintsugi-shim.exe" {
        let cmd = args.get(1)?.clone();
        Some((cmd, args.get(2..).unwrap_or(&[]).to_vec()))
    } else {
        Some((invoked.to_string(), args.get(1..).unwrap_or(&[]).to_vec()))
    }
}

/// The basename of a program path, with a trailing `.exe` stripped.
fn program_name(arg0: &str) -> String {
    let base = Path::new(arg0)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(arg0);
    base.strip_suffix(".exe").unwrap_or(base).to_string()
}

/// Render a command and args back into a readable string for the log/UI.
fn render_command(cmd: &str, args: &[String]) -> String {
    let mut out = String::from(cmd);
    for a in args {
        out.push(' ');
        if a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '"') {
            out.push('"');
            out.push_str(&a.replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(a);
        }
    }
    out
}

/// The directory containing the running shim executable, canonicalized.
fn own_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    exe.parent().map(Path::to_path_buf)
}

/// The canonical path of the running shim executable.
fn own_exe() -> Option<PathBuf> {
    std::env::current_exe().ok()?.canonicalize().ok()
}

/// Resolve the *real* binary for `name` by walking `$PATH`, skipping the shim's
/// own directory and any entry that resolves back to the shim itself.
pub fn resolve_real_binary(name: &str) -> Option<PathBuf> {
    // An explicit path (contains a separator) is used as-is.
    if name.contains('/') || (cfg!(windows) && name.contains('\\')) {
        let p = PathBuf::from(name);
        return is_executable_file(&p).then_some(p);
    }

    let own_dir = own_dir();
    let own_exe = own_exe();
    let path = std::env::var_os("PATH")?;

    for dir in std::env::split_paths(&path) {
        // Skip the shim directory itself.
        if let Some(od) = &own_dir {
            if dir.canonicalize().ok().as_deref() == Some(od.as_path()) {
                continue;
            }
        }
        let candidate = dir.join(name);
        if !is_executable_file(&candidate) {
            continue;
        }
        // Skip a candidate that resolves back to the shim (e.g. another symlink).
        if let (Ok(cc), Some(oe)) = (candidate.canonicalize(), &own_exe) {
            if &cc == oe {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}

/// Whether `path` is a regular, executable file (following symlinks).
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Replace this process with the real binary (Unix) or spawn-and-wait (Windows).
#[cfg(unix)]
fn exec_real(real: &Path, argv0: &str, args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    // Preserve argv[0] (the invoked name) so multi-call binaries — busybox,
    // gunzip→gzip, etc. — pick the right applet. `exec` only returns on failure;
    // on success the kernel replaces this image, preserving exit code, stdio, and
    // signal delivery exactly.
    let err = std::process::Command::new(real)
        .arg0(argv0)
        .args(args)
        .exec();
    eprintln!("kintsugi: failed to exec {}: {err}", real.display());
    ExitCode::from(EXIT_BLOCKED)
}

/// Windows has no `exec`; spawn the child, wait, and propagate its exit code.
#[cfg(not(unix))]
fn exec_real(real: &Path, _argv0: &str, args: &[String]) -> ExitCode {
    match std::process::Command::new(real).args(args).status() {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1))
        }
        Err(e) => {
            eprintln!("kintsugi: failed to run {}: {e}", real.display());
            ExitCode::from(EXIT_BLOCKED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_name_strips_dir_and_exe() {
        assert_eq!(program_name("/usr/bin/rm"), "rm");
        assert_eq!(program_name("rm"), "rm");
        assert_eq!(program_name("git.exe"), "git");
        #[cfg(windows)]
        assert_eq!(program_name(r"C:\tools\git.exe"), "git");
    }

    #[test]
    fn split_invocation_symlink_form() {
        let args = vec!["rm".to_string(), "-rf".to_string(), "x".to_string()];
        let (cmd, rest) = split_invocation("rm", &args).unwrap();
        assert_eq!(cmd, "rm");
        assert_eq!(rest, vec!["-rf", "x"]);
    }

    #[test]
    fn split_invocation_direct_form() {
        let args = vec![
            "kintsugi-shim".to_string(),
            "git".to_string(),
            "status".to_string(),
        ];
        let (cmd, rest) = split_invocation("kintsugi-shim", &args).unwrap();
        assert_eq!(cmd, "git");
        assert_eq!(rest, vec!["status"]);
    }

    #[test]
    fn split_invocation_direct_form_requires_a_command() {
        let args = vec!["kintsugi-shim".to_string()];
        assert!(split_invocation("kintsugi-shim", &args).is_none());
    }

    #[test]
    fn render_command_quotes_whitespace() {
        assert_eq!(render_command("rm", &["a".into(), "b".into()]), "rm a b");
        assert_eq!(
            render_command("git", &["commit".into(), "-m".into(), "two words".into()]),
            r#"git commit -m "two words""#
        );
    }

    #[test]
    fn render_command_quotes_empty_and_quoted_args() {
        assert_eq!(render_command("x", &["".into()]), r#"x """#);
        assert_eq!(render_command("echo", &[r#"a"b"#.into()]), r#"echo "a\"b""#);
    }

    #[test]
    fn resolve_explicit_path_is_used_directly() {
        #[cfg(unix)]
        {
            assert_eq!(
                resolve_real_binary("/bin/sh"),
                Some(PathBuf::from("/bin/sh"))
            );
            assert!(resolve_real_binary("/definitely/not/here").is_none());
        }
    }

    #[test]
    fn first_char_reads_lowercased_first_nonspace() {
        use std::io::Cursor;
        assert_eq!(first_char(Cursor::new(b"A\n".to_vec())), Some('a'));
        assert_eq!(first_char(Cursor::new(b"  d ".to_vec())), Some('d'));
        assert_eq!(first_char(Cursor::new(b"".to_vec())), None);
        assert_eq!(first_char(Cursor::new(b"\n".to_vec())), None);
    }

    #[test]
    fn resolve_finds_a_real_binary_on_path() {
        // `sh` exists on every Unix CI image.
        #[cfg(unix)]
        {
            let found = resolve_real_binary("sh");
            assert!(found.is_some(), "expected to find sh on PATH");
            assert!(is_executable_file(&found.unwrap()));
        }
    }

    #[test]
    fn resolve_missing_binary_is_none() {
        assert!(resolve_real_binary("definitely-not-a-real-binary-xyz").is_none());
    }
}
