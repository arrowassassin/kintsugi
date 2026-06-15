//! `aegis-hook`: the Claude Code `PreToolUse` hook bridge.
//!
//! Reads a hook event JSON on stdin, records/decides via the daemon, and writes
//! a permission decision on stdout. Wire it into Claude Code settings as a
//! `PreToolUse` hook for the `Bash` tool (see `aegis init`).

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = aegis_intercept::hook::run();
    ExitCode::from(u8::try_from(code & 0xff).unwrap_or(0))
}
