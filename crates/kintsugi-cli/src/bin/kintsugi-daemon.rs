fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--has-llama") {
        if kintsugi_model::model_available() {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        std::process::exit(1);
    }
    kintsugi_daemon::run()
}
