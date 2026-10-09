fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && matches!(args[1].as_str(), "-h" | "--help" | "help") {
        eprintln!("{}", usage_message());
        return;
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: could not read current directory: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = cargo_connector::run_cli_in(&cwd, &args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn usage_message() -> &'static str {
    "cargo-connector — Cargo subcommand `cargo connector`\n\
     \n\
     cargo connector new <name> [--lang rust|go|python]\n\
     \n\
     Creates a minimal Rust subprocess plugin with plugin.toml (Phase 6.3).\n\
     Install: cargo install --path cargo-connector   (or add the binary to PATH)\n\
     \n\
     Go / Python scaffolds are planned; only `rust` is implemented."
}
