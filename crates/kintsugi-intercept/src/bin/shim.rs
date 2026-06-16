//! `kintsugi-shim`: the `$PATH` interception shim.
//!
//! Symlink this binary as `rm`, `git`, `terraform`, … on a directory prepended
//! to `$PATH`. Each invocation is captured, sent to the daemon, and — on allow —
//! transparently handed off to the real binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    kintsugi_intercept::shim::run()
}
