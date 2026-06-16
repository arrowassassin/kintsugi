//! `kintsugi-daemon` binary entry point.

fn main() -> anyhow::Result<()> {
    // A dependency-free probe so the installer can tell whether this build has the
    // in-process llama.cpp engine compiled in — without starting the daemon. When
    // present, prints this build's version and exits 0; otherwise exits 1. The
    // installer compares the printed version to the target so an app upgrade still
    // rebuilds the engine (a same-version re-run skips it).
    if std::env::args().nth(1).as_deref() == Some("--has-llama") {
        if kintsugi_model::model_available() {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        std::process::exit(1);
    }
    kintsugi_daemon::run()
}
