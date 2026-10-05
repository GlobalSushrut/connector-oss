/// build.rs — Inject build-time constants into the connector-platform binary.
///
/// These constants are read at compile time and embedded as `option_env!()` macros.
/// This enables:
///   - Offline license validation without phone-home on every startup
///   - Tamper detection via baked-in binary ID
///   - Reproducible build metadata (git hash, timestamp, tier)
///
/// Production build workflow:
///   1. Operator obtains license key from license server
///   2. Creates `.license-seed` file in server/ with key_id, instance_id, tier
///   3. Runs: cargo build --release
///   4. build.rs reads .license-seed and injects values as env vars
///   5. Binary contains baked-in identity — no env vars needed at runtime
///
/// .license-seed format (one KEY=VALUE per line):
///   CONNECTOR_KEY_ID=key_abc123
///   CONNECTOR_INSTANCE_ID=inst_xyz789
///   CONNECTOR_TIER_BAKED=Enterprise
///   CONNECTOR_BINARY_ID_BAKED=bin_prod_abc123
///   CONNECTOR_LICENSE_SERVER=https://license.connector.dev

use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&from, &to)?;
        }
        // Skip symlinks (e.g. `current` release pointer) — embed uses flat files only.
    }
    Ok(())
}

fn host_arch_labels() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    (os, arch)
}

fn sha256_file(path: &Path) -> Option<String> {
    let output = Command::new("sha256sum").arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.split_whitespace().next().map(|s| s.to_string())
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn stage_microvm_assets() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");
    let firecracker_manifest = repo_root.join("vendor/firecracker/manifest.json");
    let microvm_manifest = repo_root.join("vendor/microvm/manifest.json");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("microvm_assets");
    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::create_dir_all(&out);

    println!("cargo:rerun-if-changed={}", firecracker_manifest.display());
    println!("cargo:rerun-if-changed={}", microvm_manifest.display());
    println!("cargo:rerun-if-changed={}", repo_root.join("vendor/firecracker").display());
    println!("cargo:rerun-if-changed={}", repo_root.join("vendor/microvm").display());

    let strict = env_truthy("CONNECTOR_REQUIRE_VENDORED_MICROVM");
    let (os, arch) = host_arch_labels();

    let mut firecracker_path_out = String::new();
    let mut kernel_path_out = String::new();
    let mut rootfs_path_out = String::new();

    if firecracker_manifest.is_file() {
        let manifest_raw = std::fs::read_to_string(&firecracker_manifest)
            .unwrap_or_else(|e| panic!("read {}: {}", firecracker_manifest.display(), e));
        let v: serde_json::Value = serde_json::from_str(&manifest_raw)
            .unwrap_or_else(|e| panic!("parse {}: {}", firecracker_manifest.display(), e));
        if let Some(entries) = v.get("binaries").and_then(|x| x.as_array()) {
            if let Some(entry) = entries.iter().find(|e| {
                e.get("os").and_then(|x| x.as_str()) == Some(os)
                    && e.get("arch").and_then(|x| x.as_str()) == Some(arch)
            }) {
                if let Some(rel) = entry.get("path").and_then(|x| x.as_str()) {
                    let src = repo_root.join("vendor/firecracker").join(rel);
                    if src.is_file() {
                        let expected = entry.get("sha256").and_then(|x| x.as_str()).unwrap_or("");
                        let actual = sha256_file(&src).unwrap_or_default();
                        if strict && (expected.is_empty() || expected.contains("REPLACE_")) {
                            panic!(
                                "{} has placeholder sha256 for {}",
                                firecracker_manifest.display(),
                                rel
                            );
                        }
                        if strict && !expected.is_empty() && !expected.contains("REPLACE_") && actual != expected {
                            panic!(
                                "firecracker checksum mismatch for {}: expected {}, got {}",
                                src.display(),
                                expected,
                                actual
                            );
                        }
                        let dst = out.join("firecracker");
                        std::fs::copy(&src, &dst).expect("copy firecracker to OUT_DIR");
                        firecracker_path_out = dst.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    if microvm_manifest.is_file() {
        let manifest_raw = std::fs::read_to_string(&microvm_manifest)
            .unwrap_or_else(|e| panic!("read {}: {}", microvm_manifest.display(), e));
        let v: serde_json::Value = serde_json::from_str(&manifest_raw)
            .unwrap_or_else(|e| panic!("parse {}: {}", microvm_manifest.display(), e));
        if let Some(entries) = v.get("images").and_then(|x| x.as_array()) {
            if let Some(entry) = entries.iter().find(|e| {
                e.get("os").and_then(|x| x.as_str()) == Some("linux")
                    && e.get("arch").and_then(|x| x.as_str()) == Some(arch)
            }) {
                let kernel_rel = entry.get("kernel_path").and_then(|x| x.as_str()).unwrap_or("");
                let rootfs_rel = entry.get("rootfs_path").and_then(|x| x.as_str()).unwrap_or("");
                if !kernel_rel.is_empty() && !rootfs_rel.is_empty() {
                    let kernel_src = repo_root.join("vendor/microvm").join(kernel_rel);
                    let rootfs_src = repo_root.join("vendor/microvm").join(rootfs_rel);
                    if kernel_src.is_file() && rootfs_src.is_file() {
                        let kernel_expected = entry.get("kernel_sha256").and_then(|x| x.as_str()).unwrap_or("");
                        let rootfs_expected = entry.get("rootfs_sha256").and_then(|x| x.as_str()).unwrap_or("");
                        let kernel_actual = sha256_file(&kernel_src).unwrap_or_default();
                        let rootfs_actual = sha256_file(&rootfs_src).unwrap_or_default();
                        if strict
                            && (kernel_expected.contains("REPLACE_") || rootfs_expected.contains("REPLACE_"))
                        {
                            panic!(
                                "{} has placeholder image checksums for {}",
                                microvm_manifest.display(),
                                arch
                            );
                        }
                        if strict && !kernel_expected.is_empty() && !kernel_expected.contains("REPLACE_") && kernel_actual != kernel_expected {
                            panic!(
                                "kernel checksum mismatch for {}: expected {}, got {}",
                                kernel_src.display(),
                                kernel_expected,
                                kernel_actual
                            );
                        }
                        if strict && !rootfs_expected.is_empty() && !rootfs_expected.contains("REPLACE_") && rootfs_actual != rootfs_expected {
                            panic!(
                                "rootfs checksum mismatch for {}: expected {}, got {}",
                                rootfs_src.display(),
                                rootfs_expected,
                                rootfs_actual
                            );
                        }
                        let kernel_dst = out.join("vmlinux");
                        let rootfs_dst = out.join("rootfs.ext4");
                        std::fs::copy(&kernel_src, &kernel_dst).expect("copy kernel to OUT_DIR");
                        std::fs::copy(&rootfs_src, &rootfs_dst).expect("copy rootfs to OUT_DIR");
                        kernel_path_out = kernel_dst.to_string_lossy().to_string();
                        rootfs_path_out = rootfs_dst.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    if strict && (firecracker_path_out.is_empty() || kernel_path_out.is_empty() || rootfs_path_out.is_empty()) {
        panic!(
            "CONNECTOR_REQUIRE_VENDORED_MICROVM=1 but required vendor assets are missing for host {}-{}",
            os, arch
        );
    }

    if !firecracker_path_out.is_empty() {
        println!("cargo:rustc-env=CONNECTOR_VENDORED_FIRECRACKER_PATH={}", firecracker_path_out);
    }
    if !kernel_path_out.is_empty() {
        println!("cargo:rustc-env=CONNECTOR_VENDORED_MICROVM_KERNEL_PATH={}", kernel_path_out);
    }
    if !rootfs_path_out.is_empty() {
        println!("cargo:rustc-env=CONNECTOR_VENDORED_MICROVM_ROOTFS_PATH={}", rootfs_path_out);
    }
}

/// Stage `ui-leptos/dashboard/dist` into `OUT_DIR/dashboard_embed` for `include_dir!` (Phase 1.5).
/// If the real dist is missing (e.g. clean CI checkout), copy a small tracked stub so the crate always compiles.
fn stage_dashboard_embed() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let real_dist = manifest_dir.join("../ui-leptos/dashboard/dist");
    let stub = manifest_dir.join("dashboard-embed-stub");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("dashboard_embed");
    let _ = std::fs::remove_dir_all(&out);

    if real_dist.join("index.html").is_file() {
        copy_dir_recursive(&real_dist, &out).expect("copy ui-leptos/dashboard/dist to OUT_DIR");
        eprintln!(
            "[build.rs] Staged dashboard dist → {} (from {})",
            out.display(),
            real_dist.display()
        );
    } else {
        copy_dir_recursive(&stub, &out).expect("copy dashboard-embed-stub to OUT_DIR");
        eprintln!(
            "[build.rs] WARN: {} missing — embedding dashboard-embed-stub (run Trunk build for real UI)",
            real_dist.display()
        );
    }

    println!("cargo:rerun-if-changed={}", real_dist.join("index.html").display());
    println!("cargo:rerun-if-changed={}", stub.join("index.html").display());
}

fn main() {
    stage_dashboard_embed();
    stage_microvm_assets();
    // ── 1. Build timestamp ────────────────────────────────────────────────────
    let ts = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|epoch| {
            // Convert epoch to ISO 8601
            let dt = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(epoch as u64);
            format!("{:?}", dt)
        })
        .unwrap_or_else(|| {
            // Current time — non-reproducible but fine for dev
            format!("{}", chrono_approx_now())
        });
    println!("cargo:rustc-env=CONNECTOR_BUILD_TS={}", ts);

    // ── 2. Git commit hash ────────────────────────────────────────────────────
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=10", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CONNECTOR_GIT_HASH={}", git_hash);

    // Dirty working tree?
    let git_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=CONNECTOR_GIT_DIRTY={}", if git_dirty { "true" } else { "false" });

    // Full build label
    let build_label = format!("v{}-{}{}", 
        env!("CARGO_PKG_VERSION"), 
        git_hash,
        if git_dirty { "-dirty" } else { "" }
    );
    println!("cargo:rustc-env=CONNECTOR_BUILD_LABEL={}", build_label);

    // ── 3. Read .license-seed for production build injection ──────────────────
    // File lives in server/.license-seed — gitignored, operator-managed
    let seed_path = std::path::Path::new(".license-seed");
    if seed_path.exists() {
        println!("cargo:rerun-if-changed=.license-seed");
        match std::fs::read_to_string(seed_path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim();
                        // Only forward known safe keys
                        match key {
                            "CONNECTOR_KEY_ID"
                            | "CONNECTOR_INSTANCE_ID"
                            | "CONNECTOR_TIER_BAKED"
                            | "CONNECTOR_BINARY_ID_BAKED"
                            | "CONNECTOR_LICENSE_SERVER"
                            | "CONNECTOR_BANNER"
                            | "CONNECTOR_SIGNING_PUBKEY_HEX" => {
                                println!("cargo:rustc-env={}={}", key, value);
                                eprintln!("[build.rs] Injected {} into binary", key);
                            }
                            _ => eprintln!("[build.rs] WARN: Unknown .license-seed key: {}", key),
                        }
                    }
                }
                eprintln!("[build.rs] License seed injected from .license-seed");
            }
            Err(e) => eprintln!("[build.rs] WARN: Cannot read .license-seed: {}", e),
        }
    } else {
        // Dev build — no license seed, use defaults
        println!("cargo:rustc-env=CONNECTOR_BINARY_ID_BAKED=bin_dev");
        println!("cargo:rustc-env=CONNECTOR_TIER_BAKED=Community");
        println!("cargo:rustc-env=CONNECTOR_LICENSE_SERVER=https://license.connector.dev");
        // Dev placeholder — 32 zero bytes as hex. Replace with real pubkey in production.
        println!("cargo:rustc-env=CONNECTOR_SIGNING_PUBKEY_HEX=0000000000000000000000000000000000000000000000000000000000000000");
    }

    println!("cargo:rerun-if-env-changed=CONNECTOR_SIGNING_PUBKEY_HEX");

    // Rebuild if these files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=CONNECTOR_KEY_ID");
    println!("cargo:rerun-if-env-changed=CONNECTOR_INSTANCE_ID");
}

/// Approximate current timestamp in ISO 8601 without chrono dependency in build.rs.
fn chrono_approx_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert epoch to approximate date string
    let days = secs / 86400;
    let year = 1970 + days / 365;
    format!("{}-build", year)
}
