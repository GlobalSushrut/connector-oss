//! AIOS-B16 — `connector completions <shell>` — shell completion script generation
//!
//! Uses clap_complete to generate completion scripts for bash, zsh, fish, and powershell.
//!
//! ```text
//! connector completions bash   >> ~/.bash_completion
//! connector completions zsh    > ~/.zfunc/_connector
//! connector completions fish   > ~/.config/fish/completions/connector.fish
//! connector completions powershell >> $PROFILE
//! ```

use std::io;
use clap::CommandFactory;
use clap_complete::{generate as clap_generate, Shell};

/// Generate completion script for the given shell name and print to stdout.
pub fn generate(shell_name: &str) {
    let shell = match shell_name.to_lowercase().as_str() {
        "bash"        => Shell::Bash,
        "zsh"         => Shell::Zsh,
        "fish"        => Shell::Fish,
        "powershell"  => Shell::PowerShell,
        other => {
            eprintln!(
                "Unknown shell '{}'. Supported: bash | zsh | fish | powershell",
                other
            );
            std::process::exit(1);
        }
    };

    let mut cmd = crate::Cli::command();
    clap_generate(shell, &mut cmd, "connector", &mut io::stdout());
}
