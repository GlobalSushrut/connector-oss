//! Connector starts the pinned roles. The operator does not run vendor commands.
//!
//! The boots are the existing scripts. This module does not run deploy-verify,
//! does not mint a token, and does not restart the platform.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::Json;
use serde_json::{json, Value};

struct BootState {
    running: bool,
    seven_exit: Option<i32>,
    intel_exit: Option<i32>,
    note: String,
}

static BOOT: Mutex<BootState> = Mutex::new(BootState {
    running: false,
    seven_exit: None,
    intel_exit: None,
    note: String::new(),
});

pub fn group_word(exit: Option<i32>) -> &'static str {
    match exit {
        None => "not started",
        Some(0) => "started",
        Some(_) => "down",
    }
}

fn snapshot(state: &BootState) -> Value {
    json!({
        "ok": true,
        "running": state.running,
        "sign_in_through_traffic": group_word(state.seven_exit),
        "recall_model_flow": group_word(state.intel_exit),
        "note": state.note,
        "platform_started": false,
        "deploy_verify_ran": false,
        "acceptance_passed": false,
        "seven_backend": false,
        "honesty": "Connector starts the pinned roles. A script that exits non-zero leaves that group down. This does not run deploy-verify.",
    })
}

pub fn progress() -> Value {
    let state = BOOT.lock().unwrap_or_else(|err| err.into_inner());
    snapshot(&state)
}

pub fn begin() -> Value {
    let oss = match oss_boot_dir() {
        Ok(path) => path,
        Err(reason) => {
            return json!({
                "ok": false,
                "running": false,
                "reason": reason,
                "platform_started": false,
                "deploy_verify_ran": false,
                "acceptance_passed": false,
                "seven_backend": false,
            });
        }
    };
    {
        let mut state = BOOT.lock().unwrap_or_else(|err| err.into_inner());
        if state.running {
            return snapshot(&state);
        }
        state.running = true;
        state.seven_exit = None;
        state.intel_exit = None;
        state.note.clear();
    }
    std::thread::spawn(move || {
        let seven = run_boot(&oss.join("boot-backends.sh"));
        let intel = run_boot(&oss.join("boot-intelligence.sh"));
        let mut state = BOOT.lock().unwrap_or_else(|err| err.into_inner());
        state.running = false;
        state.seven_exit = Some(seven.0);
        state.intel_exit = Some(intel.0);
        state.note = [seven.1, intel.1]
            .into_iter()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
    });
    progress()
}

pub async fn get_progress() -> Json<Value> {
    Json(progress())
}

pub async fn post_up() -> Json<Value> {
    Json(begin())
}

fn oss_boot_dir() -> Result<PathBuf, &'static str> {
    if let Ok(root) = std::env::var("CONNECTOR_REPO_ROOT") {
        let oss = PathBuf::from(root).join("oss");
        if boot_scripts_present(&oss) {
            return Ok(oss);
        }
    }
    let mut dir = std::env::current_dir().map_err(|_| "finger boot scripts are not in this tree")?;
    loop {
        let oss = dir.join("oss");
        if boot_scripts_present(&oss) {
            return Ok(oss);
        }
        if !dir.pop() {
            break;
        }
    }
    Err("finger boot scripts are not in this tree")
}

fn boot_scripts_present(oss: &Path) -> bool {
    oss.join("boot-backends.sh").is_file() && oss.join("boot-intelligence.sh").is_file()
}

fn run_boot(script: &Path) -> (i32, String) {
    match std::process::Command::new("bash")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) => (
            output.status.code().unwrap_or(1),
            safe_boot_note(&output.stdout, &output.stderr),
        ),
        Err(err) => (127, safe_boot_note(err.to_string().as_bytes(), b"")),
    }
}

pub fn safe_boot_note(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stderr).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(stdout));
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("password")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("api_key")
            || lower.contains("bearer")
            || lower.contains("docker ")
            || lower.contains("curl ")
        {
            continue;
        }
        return trimmed.chars().take(180).collect();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_group_stays_down() {
        assert_eq!(group_word(None), "not started");
        assert_eq!(group_word(Some(0)), "started");
        assert_eq!(group_word(Some(2)), "down");
    }

    #[test]
    fn boot_notes_drop_vendor_commands_and_secrets() {
        let note = safe_boot_note(
            b"docker pull example\npassword=hidden\n[not ready] sign-in\n",
            b"",
        );
        assert_eq!(note, "[not ready] sign-in");
        assert!(safe_boot_note(b"curl -s http://example\n", b"").is_empty());
    }
}
