use std::process::ExitCode;

fn main() -> ExitCode {
    let code = kintsugi_intercept::hook::run();
    ExitCode::from(u8::try_from(code & 0xff).unwrap_or(0))
}
