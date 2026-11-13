#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(torwell_engine::cli::run(&args));
}

#[cfg(not(unix))]
fn main() {
    std::process::exit(torwell_engine::unsupported::run());
}
