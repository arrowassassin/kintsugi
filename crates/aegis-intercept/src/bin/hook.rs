//! `aegis-hook`: the pre-tool hook bridge for every supported agent CLI.
//!
//! Reads a hook event JSON on stdin, records/decides via the daemon, and writes
//! a permission decision on stdout in the calling CLI's protocol. The dialect is
//! selected with `--agent <id>` (claude, qwen, gemini, copilot, cursor, codex,
//! opencode), defaulting to Claude Code. `aegis init` wires each detected CLI to
//! call this with the right flag.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = aegis_intercept::hook::run();
    ExitCode::from(u8::try_from(code & 0xff).unwrap_or(0))
}
