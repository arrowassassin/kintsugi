//! `aegis-daemon` binary entry point.

fn main() -> anyhow::Result<()> {
    aegis_daemon::run()
}
