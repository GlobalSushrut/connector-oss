use anyhow::{Context, Result};
use std::process::Command;

pub async fn edit(path: &str) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(&editor)
        .arg(path)
        .status()
        .with_context(|| format!("Failed to launch editor '{}'", editor))?;
    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }
    println!("Validating {} after edit...", path);
    crate::commands::policy::validate(path, true).await
}

pub async fn validate(path: &str, verbose: bool) -> Result<()> {
    crate::commands::policy::validate(path, verbose).await
}
