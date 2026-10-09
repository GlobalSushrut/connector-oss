//! `devguard cage` — layered workstation controls for supported channels.
//!
//! These controls reduce accidental and agent-mediated bypasses, but they are
//! not a kernel security boundary and do not govern unrelated host processes.
//!
//! 1. **Filesystem watchdog** — inotify daemon monitors protected paths,
//!    instantly reverts unauthorized writes, alerts on forbidden reads.
//! 2. **Git hooks** — pre-commit + pre-push hooks check branch/file policy.
//! 3. **Exec wrapper** — shell wrapper intercepts commands through policy check.
//!
//! These layers improve enforcement, but guarantees depend on which layers are
//! actually active and integrated with the running toolchain.

use anyhow::{Context, Result};
use crate::adapter::windsurf::WindsurfAdapter;
use crate::config::DevGuardConfig;
use notify::Watcher;
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `devguard cage start` — activate all enforcement layers
pub async fn start(config_path: &str, hook_devguard_path: Option<String>) -> Result<()> {
    let config = DevGuardConfig::load(config_path)
        .with_context(|| format!("Cannot load {}", config_path))?;

    let workspace = std::env::current_dir()?;
    println!("DevGuard Cage — Activating OS-level enforcement");
    println!("  Workspace: {}", workspace.display());
    println!();

    // 1. Install git hooks
    let git_result = install_git_hooks(&workspace, config_path, hook_devguard_path.as_deref());
    match &git_result {
        Ok(count) => println!("  ✓ Git hooks:       {} hooks installed", count),
        Err(e) => println!("  ⚠ Git hooks:       {} (not a git repo?)", e),
    }

    // 2. Install filesystem watchdog
    let watch_result = install_fs_watchdog(&workspace, &config, config_path);
    match &watch_result {
        Ok(_) => println!("  ✓ FS watchdog:     active — forbidden writes will be reverted"),
        Err(e) => println!("  ⚠ FS watchdog:     {}", e),
    }

    // 3. Install exec wrapper
    let exec_result = install_exec_wrapper(&workspace, config_path);
    match &exec_result {
        Ok(_) => println!("  ✓ Exec wrapper:    installed — shell-session command checks (not universal tool interception)"),
        Err(e) => println!("  ⚠ Exec wrapper:    {}", e),
    }

    // 4. Set file permissions on protected paths
    let perm_result = set_file_permissions(&workspace, &config);
    match &perm_result {
        Ok(count) => println!("  ✓ File perms:      {} paths protected via chmod", count),
        Err(e) => println!("  ⚠ File perms:      {}", e),
    }

    // 5. Install Windsurf hooks.json for TRUE pre-write blocking (not just post-revert)
    let windsurf_result = install_windsurf_hooks(config_path);
    match &windsurf_result {
        Ok(_) => println!("  ✓ Windsurf hooks:  .windsurf/hooks.json installed — writes blocked BEFORE execution"),
        Err(e) => println!("  ○ Windsurf hooks:  {} (no .windsurf dir — not a Windsurf workspace)", e),
    }

    println!();

    let active_layers = [
        &git_result.is_ok(), &watch_result.is_ok(),
        &exec_result.is_ok(), &perm_result.is_ok(),
    ]
        .iter().filter(|x| ***x).count();

    if active_layers >= 3 {
        println!("  ✓ Cage ACTIVE — {}/4 workstation control layers running", active_layers);
        println!("  Supported editor, git, and shell channels are guarded; unrelated host processes are outside this boundary.");
    } else if active_layers > 0 {
        println!("  ⚠ Cage PARTIAL — {}/4 layers active. Some enforcement gaps remain.", active_layers);
    } else {
        println!("  ✗ Cage FAILED — no enforcement layers active.");
    }

    // Write cage state file
    let cage_state = serde_json::json!({
        "active": true,
        "layers": {
            "git_hooks": git_result.is_ok(),
            "fs_watchdog": watch_result.is_ok(),
            "exec_wrapper": exec_result.is_ok(),
            "file_perms": perm_result.is_ok(),
            "windsurf_hooks": windsurf_result.is_ok(),
        },
        "workspace": workspace.display().to_string(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "config": config_path,
    });
    let cage_dir = workspace.join(".devguard");
    let _ = std::fs::create_dir_all(&cage_dir);
    let _ = std::fs::write(cage_dir.join("cage.json"), serde_json::to_string_pretty(&cage_state)?);

    Ok(())
}

/// `devguard cage stop` — deactivate enforcement layers
pub async fn stop() -> Result<()> {
    let workspace = std::env::current_dir()?;
    println!("DevGuard Cage — Deactivating enforcement");

    // Stop filesystem watchdog
    stop_fs_watchdog(&workspace)?;
    println!("  ✓ FS watchdog stopped");

    // Remove exec wrapper
    remove_exec_wrapper(&workspace)?;
    println!("  ✓ Exec wrapper removed");

    // Remove Windsurf hooks
    WindsurfAdapter::remove_hooks();
    println!("  ✓ Windsurf hooks removed");

    // Remove git hooks (keep them — they're non-destructive)
    println!("  ○ Git hooks kept (safe, run `devguard cage purge` to remove)");

    // Restore file permissions
    restore_file_permissions(&workspace)?;
    println!("  ✓ File permissions restored");

    let cage_state_path = workspace.join(".devguard/cage.json");
    if cage_state_path.exists() {
        let _ = std::fs::remove_file(&cage_state_path);
    }

    println!("\n  Cage deactivated. Agents are ungoverned.");
    Ok(())
}

/// `devguard cage status` — show cage state
pub async fn status(verify: bool) -> Result<()> {
    let workspace = std::env::current_dir()?;
    let cage_path = workspace.join(".devguard/cage.json");

    if !cage_path.exists() {
        println!("Cage: NOT ACTIVE");
        println!("  Run `devguard cage start` to activate OS-level enforcement.");
        if verify {
            run_verify_probes()?;
        }
        return Ok(());
    }

    let state: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&cage_path)?)?;
    println!("DevGuard Cage Status\n");
    println!("  Active:    {}", state.get("active").and_then(|v| v.as_bool()).unwrap_or(false));
    println!("  Since:     {}", state.get("started_at").and_then(|v| v.as_str()).unwrap_or("?"));
    println!("  Workspace: {}", state.get("workspace").and_then(|v| v.as_str()).unwrap_or("?"));

    if let Some(layers) = state.get("layers").and_then(|v| v.as_object()) {
        println!("\n  Enforcement layers:");
        for (name, active) in layers {
            let ok = active.as_bool().unwrap_or(false);
            println!("    {} {}", if ok { "✓" } else { "✗" }, name);
        }
    }

    if verify {
        run_verify_probes()?;
    }

    print_hook_resolution_status(&workspace);

    // Check if watchdog PID is still alive
    let pid_file = workspace.join(".devguard/watchdog.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            let pid = pid_str.trim().parse::<i32>().unwrap_or_default();
            let alive = is_pid_alive(pid);
            println!("\n  Watchdog:  {} (PID {})", if alive { "running" } else { "DEAD" }, pid_str.trim());
            let heartbeat = workspace.join(".devguard/watchdog.heartbeat");
            if heartbeat.exists() {
                if let Ok(ts) = std::fs::read_to_string(&heartbeat) {
                    if let Ok(last) = ts.trim().parse::<i64>() {
                        let now = chrono::Utc::now().timestamp();
                        let age = now.saturating_sub(last);
                        println!("  Heartbeat: {}s ago{}", age, if age > 10 { " (STALE)" } else { "" });
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Git Hooks ────────────────────────────────────────────────────────────────

fn install_git_hooks(workspace: &Path, config_path: &str, hook_devguard_path: Option<&str>) -> Result<usize> {
    let git_dir = workspace.join(".git");
    if !git_dir.exists() {
        anyhow::bail!("Not a git repository");
    }

    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let devguard_bin = hook_devguard_path
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DEVGUARD_BIN_PATH").ok())
        .unwrap_or_else(|| "devguard".to_string());

    let mut count = 0;

    // pre-commit hook — check file policy before commit
    let pre_commit = format!(r#"#!/bin/bash
# DevGuard pre-commit hook — enforces file write policy
# Installed by `devguard cage start`. Do not remove manually.
set -e

DG="{devguard}"
CONFIG="{config}"

if [ -f .devguard/connector.json ]; then
    TOKEN="${{CONNECTOR_AGENT_TOKEN:-${{DEVGUARD_TOKEN:-}}}}"
    case "$TOKEN" in
        cg_*) ;;
        *)
            echo "[DevGuard] DENY — this repo is under Connector. No agent ID + role. Even read is denied."
            echo "  Ask the node: POST /api/v1/devguard/admit"
            echo "  Then: export CONNECTOR_AGENT_TOKEN=cg_…"
            exit 1
            ;;
    esac
fi

if ! command -v "$DG" >/dev/null 2>&1; then
    if [ -f .devguard/connector.json ]; then
        echo "[DevGuard] DENY — linked repo but devguard is not on PATH"
        exit 1
    fi
    echo "[DevGuard] WARNING: devguard not on PATH — hook disabled"
    exit 0
fi

if [ ! -f "$CONFIG" ]; then
    if [ -f .devguard/connector.json ]; then
        echo "[DevGuard] DENY — linked repo but policy file missing"
        exit 1
    fi
    echo "[DevGuard] Policy file $CONFIG not found — commit allowed (no policy)"
    exit 0
fi

# Check each staged file against write policy
BLOCKED=0
while IFS= read -r file; do
    result=$("$DG" check file write "$file" --config "$CONFIG" 2>&1)
    if echo "$result" | grep -q "DENY"; then
        echo "[DevGuard] BLOCKED: Cannot commit write to '$file'"
        echo "  $result"
        BLOCKED=1
    fi
done < <(git diff --cached --name-only --diff-filter=ACMR)

if [ "$BLOCKED" -eq 1 ]; then
    echo ""
    echo "[DevGuard] Commit DENIED — one or more files violate policy."
    echo "  Your role does not allow writing to these files."
    exit 1
fi
"#, devguard = devguard_bin, config = config_path);

    std::fs::write(hooks_dir.join("pre-commit"), &pre_commit)?;
    make_executable(&hooks_dir.join("pre-commit"))?;
    count += 1;

    // pre-push hook — check branch policy before push
    let pre_push = format!(r#"#!/bin/bash
# DevGuard pre-push hook — enforces branch policy
# Installed by `devguard cage start`. Do not remove manually.
set -e

DG="{devguard}"
CONFIG="{config}"

if [ -f .devguard/connector.json ]; then
    TOKEN="${{CONNECTOR_AGENT_TOKEN:-${{DEVGUARD_TOKEN:-}}}}"
    case "$TOKEN" in
        cg_*) ;;
        *)
            echo "[DevGuard] DENY — this repo is under Connector. No agent ID + role. Even read is denied."
            echo "  Ask the node: POST /api/v1/devguard/admit"
            echo "  Then: export CONNECTOR_AGENT_TOKEN=cg_…"
            exit 1
            ;;
    esac
fi

if ! command -v "$DG" >/dev/null 2>&1; then
    if [ -f .devguard/connector.json ]; then
        echo "[DevGuard] DENY — linked repo but devguard is not on PATH"
        exit 1
    fi
    echo "[DevGuard] WARNING: devguard not on PATH — hook disabled"
    exit 0
fi

if [ ! -f "$CONFIG" ]; then
    if [ -f .devguard/connector.json ]; then
        echo "[DevGuard] DENY — linked repo but policy file missing"
        exit 1
    fi
    exit 0
fi

# Read push info from stdin
while read local_ref local_sha remote_ref remote_sha; do
    # Extract branch name from refs/heads/branch-name
    branch=$(echo "$remote_ref" | sed 's|refs/heads/||')
    if [ -z "$branch" ]; then
        branch=$(echo "$local_ref" | sed 's|refs/heads/||')
    fi

    if [ -n "$branch" ]; then
        result=$("$DG" check git push "$branch" --config "$CONFIG" 2>&1)
        if echo "$result" | grep -q "DENY"; then
            echo "[DevGuard] PUSH BLOCKED to branch '$branch'"
            echo "  $result"
            echo ""
            echo "  Your role does not allow pushing to this branch."
            exit 1
        fi
    fi
done
"#, devguard = devguard_bin, config = config_path);

    std::fs::write(hooks_dir.join("pre-push"), &pre_push)?;
    make_executable(&hooks_dir.join("pre-push"))?;
    count += 1;

    Ok(count)
}

fn print_hook_resolution_status(workspace: &Path) {
    let hooks_dir = workspace.join(".git/hooks");
    if !hooks_dir.exists() {
        return;
    }

    let mut reported = false;
    for hook_name in ["pre-commit", "pre-push"] {
        let hook_path = hooks_dir.join(hook_name);
        if !hook_path.exists() {
            continue;
        }
        if let Some(bin) = extract_hook_binary(&hook_path) {
            let ok = resolve_hook_binary(&bin);
            if !reported {
                println!("\n  Git hook binary resolution:");
                reported = true;
            }
            println!(
                "    {} {} -> {}",
                if ok { "✓" } else { "✗" },
                hook_name,
                if ok { "resolves" } else { "NOT found (hooks disabled)" }
            );
        }
    }
}

fn extract_hook_binary(hook_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(hook_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("DG=\"") {
            return rest.strip_suffix('"').map(|s| s.to_string());
        }
    }
    None
}

fn resolve_hook_binary(bin: &str) -> bool {
    let path = Path::new(bin);
    if path.is_absolute() || bin.contains('/') {
        return path.exists();
    }
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", shell_escape(bin))])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn shell_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('\'');
    for c in input.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn run_verify_probes() -> Result<()> {
    let probe_root = build_probe_workspace()?;
    let target = probe_root.join("protected/secret.txt");
    let original = "ORIGINAL\n";
    std::fs::write(&target, original)?;

    let config_path = write_probe_config(&probe_root)?;
    let config = DevGuardConfig::load(
        config_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 probe config path"))?
    )?;

    println!("\n  Verification probes (--verify):");

    // Probe file permission layer (should block write with EACCES).
    let mut file_perm_ok = false;
    let perm_setup = set_file_permissions(&probe_root, &config);
    if perm_setup.is_ok() {
        let blocked = std::fs::write(&target, "UNAUTHORIZED\n").is_err();
        file_perm_ok = blocked;
        let _ = restore_file_permissions(&probe_root);
    }
    println!(
        "    {} file_perms write-block probe",
        if file_perm_ok { "✓" } else { "✗" }
    );

    // Probe watchdog layer (write should be reverted quickly).
    let mut watchdog_ok = false;
    let config_str = config_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 probe config path"))?;
    let watchdog_setup = install_fs_watchdog(&probe_root, &config, config_str);
    if watchdog_setup.is_ok() {
        std::thread::sleep(Duration::from_millis(150));
        let _ = std::fs::write(&target, "TAMPERED\n");
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            if std::fs::read_to_string(&target).ok().as_deref() == Some(original) {
                watchdog_ok = true;
                break;
            }
        }
        let _ = stop_fs_watchdog(&probe_root);
    }
    println!(
        "    {} fs_watchdog revert probe",
        if watchdog_ok { "✓" } else { "✗" }
    );

    let _ = std::fs::remove_dir_all(&probe_root);
    Ok(())
}

fn build_probe_workspace() -> Result<PathBuf> {
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let root = std::env::temp_dir().join(format!("devguard-cage-verify-{}", ts));
    std::fs::create_dir_all(root.join("protected"))?;
    Ok(root)
}

fn write_probe_config(workspace: &Path) -> Result<PathBuf> {
    let yaml = r#"version: "2.0"
roles:
  intern:
    clearance: 1
    files:
      hidden:
        - "protected/**"
"#;
    let path = workspace.join("devguard.yaml");
    std::fs::write(&path, yaml)?;
    Ok(path)
}

// ── Filesystem Watchdog ──────────────────────────────────────────────────────

fn install_fs_watchdog(workspace: &Path, config: &DevGuardConfig, config_path: &str) -> Result<()> {
    let cage_dir = workspace.join(".devguard");
    std::fs::create_dir_all(&cage_dir)?;

    let pid_file = cage_dir.join("watchdog.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if is_pid_alive(pid) {
                    anyhow::bail!("Watchdog already running with PID {}", pid);
                }
            }
        }
        let _ = std::fs::remove_file(&pid_file);
    }

    // Collect all protected file paths (hidden from the lowest-clearance role)
    let mut protected_files: Vec<String> = Vec::new();

    let intern_role = config.roles.values()
        .min_by_key(|r| r.clearance)
        .or_else(|| config.roles.values().next());

    if let Some(role) = intern_role {
        for pattern in &role.files.hidden {
            let clean = pattern.trim_end_matches("/**").trim_end_matches("/*").to_string();
            let path = workspace.join(&clean);
            if path.is_dir() {
                // Recursively collect all files in the directory
                if let Ok(entries) = walkdir(&path) {
                    for entry in entries {
                        if let Ok(rel) = entry.strip_prefix(workspace) {
                            protected_files.push(rel.to_string_lossy().to_string());
                        }
                    }
                }
            } else if path.is_file() {
                if let Ok(rel) = path.strip_prefix(workspace) {
                    protected_files.push(rel.to_string_lossy().to_string());
                }
            }
        }
    }

    if protected_files.is_empty() {
        anyhow::bail!("No protected files found in workspace");
    }

    // Take SHA256 snapshot of every protected file
    let mut snapshots: Vec<(String, String)> = Vec::new();
    for f in &protected_files {
        let full = workspace.join(f);
        if let Ok(content) = std::fs::read(&full) {
            use sha2::{Sha256, Digest};
            let hash = format!("{:x}", Sha256::digest(&content));
            snapshots.push((f.clone(), hash));
        }
    }

    // Write snapshot
    let snapshot_path = cage_dir.join("snapshot.json");
    std::fs::write(&snapshot_path, serde_json::to_string_pretty(&snapshots)?)?;

    // Also save a backup of every protected file for revert
    let backup_dir = cage_dir.join("backup");
    std::fs::create_dir_all(&backup_dir)?;
    for f in &protected_files {
        let src = workspace.join(f);
        let dst = backup_dir.join(f);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&src, &dst);
    }

    // Launch Rust notify-based watchdog in background.
    let current_exe = std::env::current_exe()
        .context("Cannot resolve current devguard binary path for watchdog")?;
    let child = std::process::Command::new(current_exe)
        .arg("cage")
        .arg("watchdog")
        .arg("--workspace")
        .arg(workspace)
        .arg("--config")
        .arg(config_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to start filesystem watchdog")?;

    let pid = child.id();
    std::fs::write(cage_dir.join("watchdog.pid"), pid.to_string())?;

    Ok(())
}

// ── Windsurf Hooks ───────────────────────────────────────────────────────────

/// Install .windsurf/hooks.json for TRUE pre-write blocking.
/// The watchdog only reverts after the fact; hooks.json blocks BEFORE the write.
fn install_windsurf_hooks(config_path: &str) -> Result<()> {
    // Only install if .windsurf directory exists (Windsurf workspace)
    let windsurf_dir = std::path::Path::new(".windsurf");
    if !windsurf_dir.exists() {
        anyhow::bail!(".windsurf directory not found");
    }

    let adapter = crate::adapter::windsurf::WindsurfAdapter;
    let hook_script = adapter.write_hook_script_public(config_path);
    let ok = adapter.install_hooks_public(&hook_script);

    if ok {
        Ok(())
    } else {
        anyhow::bail!("Could not write .windsurf/hooks.json")
    }
}

/// Recursively collect all files in a directory
fn walkdir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path)?);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn stop_fs_watchdog(workspace: &Path) -> Result<()> {
    let pid_file = workspace.join(".devguard/watchdog.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                let _ = std::process::Command::new("kill").arg(pid.to_string()).output();
                std::thread::sleep(Duration::from_millis(300));
                if is_pid_alive(pid) {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &pid.to_string()])
                        .output();
                    std::thread::sleep(Duration::from_millis(300));
                }
                if is_pid_alive(pid) {
                    anyhow::bail!("Failed to stop watchdog PID {} even after SIGKILL", pid);
                }
            }
        }
        std::fs::remove_file(&pid_file)?;
    }
    let _ = std::fs::remove_file(workspace.join(".devguard/watchdog.heartbeat"));
    Ok(())
}

// ── Exec Wrapper ─────────────────────────────────────────────────────────────

fn install_exec_wrapper(workspace: &Path, config_path: &str) -> Result<()> {
    let cage_dir = workspace.join(".devguard");
    std::fs::create_dir_all(&cage_dir)?;

    let devguard_bin = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("devguard"));

    // Create a shell wrapper that intercepts commands
    let wrapper = format!(r#"#!/bin/bash
# DevGuard exec wrapper — checks every command against policy before execution.
# Source this in your shell: source .devguard/exec_wrapper.sh
# Or add to .bashrc: [ -f .devguard/exec_wrapper.sh ] && source .devguard/exec_wrapper.sh

DG="{devguard}"
CONFIG="{config}"
WORKSPACE="{workspace}"

devguard_preexec() {{
    local cmd="$1"
    # Skip devguard's own commands and basic shell builtins
    case "$cmd" in
        devguard*|cd*|echo*|printf*|export*|source*|.*|alias*|type*|which*) return 0 ;;
    esac

    if [ -f "$WORKSPACE/$CONFIG" ]; then
        result=$("$DG" check exec "$cmd" --config "$WORKSPACE/$CONFIG" 2>&1)
        if echo "$result" | grep -q "DENY"; then
            echo ""
            echo "╔══════════════════════════════════════════════════════════╗"
            echo "║  [DevGuard] COMMAND BLOCKED                            ║"
            echo "║  $result"
            echo "╚══════════════════════════════════════════════════════════╝"
            echo ""
            return 1
        fi
    fi
    return 0
}}

# Hook into bash preexec via DEBUG trap
if [ -n "$BASH_VERSION" ]; then
    __devguard_trap() {{
        local cmd="$BASH_COMMAND"
        # Don't intercept the trap itself or prompts
        [[ "$cmd" == "__devguard_trap" ]] && return
        [[ "$cmd" == *"PROMPT_COMMAND"* ]] && return
        devguard_preexec "$cmd" || kill -INT $$
    }}
    trap '__devguard_trap' DEBUG
    echo "[DevGuard] Exec wrapper active — commands are governed"
fi
"#,
        devguard = devguard_bin.display(),
        config = config_path,
        workspace = workspace.display(),
    );

    std::fs::write(cage_dir.join("exec_wrapper.sh"), &wrapper)?;

    Ok(())
}

fn remove_exec_wrapper(workspace: &Path) -> Result<()> {
    let wrapper = workspace.join(".devguard/exec_wrapper.sh");
    if wrapper.exists() {
        let _ = std::fs::remove_file(&wrapper);
    }
    Ok(())
}

// ── File Permissions ─────────────────────────────────────────────────────────

fn set_file_permissions(workspace: &Path, config: &DevGuardConfig) -> Result<usize> {
    let mut count = 0;

    // Find intern (lowest clearance) role
    let intern_role = config.roles.values()
        .min_by_key(|r| r.clearance)
        .or_else(|| config.roles.values().next());

    let role = match intern_role {
        Some(r) => r,
        None => return Ok(0),
    };

    // Save current permissions so we can restore them
    let cage_dir = workspace.join(".devguard");
    std::fs::create_dir_all(&cage_dir)?;
    let mut saved_perms: Vec<(String, u32)> = Vec::new();

    for pattern in &role.files.hidden {
        let clean = pattern.trim_end_matches("/**").trim_end_matches("/*");
        let target = workspace.join(clean);

        if target.exists() {
            // Save current permissions
            if let Ok(meta) = std::fs::metadata(&target) {
                use std::os::unix::fs::PermissionsExt;
                saved_perms.push((clean.to_string(), meta.permissions().mode()));
            }

            // Make read-only (remove write permission)
            let _ = std::process::Command::new("chmod")
                .args(["-R", "a-w", &target.to_string_lossy()])
                .output();
            count += 1;
        }
    }

    // Save original permissions for restore
    let _ = std::fs::write(
        cage_dir.join("saved_perms.json"),
        serde_json::to_string_pretty(&saved_perms)?,
    );

    Ok(count)
}

fn restore_file_permissions(workspace: &Path) -> Result<()> {
    let perms_file = workspace.join(".devguard/saved_perms.json");
    if perms_file.exists() {
        let data = std::fs::read_to_string(&perms_file)?;
        let saved: Vec<(String, u32)> = serde_json::from_str(&data)?;
        for (path, mode) in &saved {
            let target = workspace.join(path);
            if target.exists() {
                let _ = std::process::Command::new("chmod")
                    .args(["-R", &format!("{:o}", mode & 0o7777), &target.to_string_lossy()])
                    .output();
            }
        }
        let _ = std::fs::remove_file(&perms_file);
    }
    Ok(())
}

pub async fn run_watchdog(workspace: &str, config_path: &str) -> Result<()> {
    let workspace = PathBuf::from(workspace);
    let config = DevGuardConfig::load(config_path)
        .with_context(|| format!("Cannot load {}", config_path))?;
    let cage_dir = workspace.join(".devguard");
    std::fs::create_dir_all(&cage_dir)?;

    let protected = collect_protected_files(&workspace, &config)?;
    let protected_set: HashSet<PathBuf> = protected.iter().map(|p| workspace.join(p)).collect();
    let heartbeat = cage_dir.join("watchdog.heartbeat");
    let log_path = cage_dir.join("watchdog.log");

    let monitor_dirs = collect_monitor_dirs(&workspace, &protected);
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;

    for dir in &monitor_dirs {
        watcher.watch(dir, notify::RecursiveMode::Recursive)?;
    }

    loop {
        let now = chrono::Utc::now().timestamp().to_string();
        let _ = std::fs::write(&heartbeat, now);
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(event)) => {
                for path in event.paths {
                    if !is_protected_path(&path, &protected_set) {
                        continue;
                    }
                    let rel = path.strip_prefix(&workspace).unwrap_or(&path).to_string_lossy().to_string();
                    if path.exists() {
                        let _ = restore_protected_file(&workspace, &rel);
                        append_log(&log_path, &format!("[DevGuard] TAMPER DETECTED+REVERTED: {}", rel));
                    } else {
                        append_log(&log_path, &format!("[DevGuard] ALERT: protected file deleted: {}", rel));
                    }
                }
            }
            Ok(Err(e)) => append_log(&log_path, &format!("[DevGuard] watcher error: {}", e)),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("watchdog channel disconnected"),
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn collect_protected_files(workspace: &Path, config: &DevGuardConfig) -> Result<Vec<String>> {
    let mut protected_files: Vec<String> = Vec::new();
    let intern_role = config.roles.values()
        .min_by_key(|r| r.clearance)
        .or_else(|| config.roles.values().next());
    if let Some(role) = intern_role {
        for pattern in &role.files.hidden {
            let clean = pattern.trim_end_matches("/**").trim_end_matches("/*").to_string();
            let path = workspace.join(&clean);
            if path.is_dir() {
                if let Ok(entries) = walkdir(&path) {
                    for entry in entries {
                        if let Ok(rel) = entry.strip_prefix(workspace) {
                            protected_files.push(rel.to_string_lossy().to_string());
                        }
                    }
                }
            } else if path.is_file() {
                if let Ok(rel) = path.strip_prefix(workspace) {
                    protected_files.push(rel.to_string_lossy().to_string());
                }
            }
        }
    }
    if protected_files.is_empty() {
        anyhow::bail!("No protected files found in workspace");
    }
    Ok(protected_files)
}

fn collect_monitor_dirs(workspace: &Path, protected_files: &[String]) -> HashSet<PathBuf> {
    let mut dirs = HashSet::new();
    for f in protected_files {
        let full = workspace.join(f);
        if let Some(parent) = full.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }
    dirs
}

fn is_protected_path(path: &Path, protected: &HashSet<PathBuf>) -> bool {
    protected.contains(path)
}

fn restore_protected_file(workspace: &Path, relative_path: &str) -> Result<()> {
    let src = workspace.join(".devguard/backup").join(relative_path);
    let dst = workspace.join(relative_path);
    if !src.exists() {
        anyhow::bail!("backup not found for {}", relative_path);
    }
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::process::Command::new("chmod").args(["u+w", &dst.to_string_lossy()]).output();
    std::fs::copy(src, dst)?;
    Ok(())
}

fn append_log(path: &Path, line: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let msg = format!("{} {}\n", ts, line);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
}

fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}
