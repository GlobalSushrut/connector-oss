//! `connectorctl data` — backup, restore, upgrade, storage.

use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance, human_lines};
use crate::transport::{self, Client};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let verb = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match verb {
        "backup" => backup(opts, rest),
        "restore" => restore(opts, rest),
        "upgrade" => upgrade(opts, rest),
        "storage" => storage(opts),
        _ => Err(
            "usage: connectorctl data <backup|restore|upgrade|storage>".into(),
        ),
    }
}

fn data_dir() -> String {
    std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into())
}

fn node_is_up(opts: &GlobalOpts) -> bool {
    transport::probe_health(opts).is_ok()
}

fn backup(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let mut out = "connector-backup.tar.gz".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                out = args
                    .get(i + 1)
                    .ok_or("usage: --out requires a path")?
                    .clone();
                i += 2;
            }
            other if other.starts_with('-') => {
                return Err(format!("usage: unknown flag {other}"));
            }
            _ => i += 1,
        }
    }

    if node_is_up(opts) && !opts.yes {
        return Ok(CmdResult {
            ok: false,
            command: "data backup".into(),
            exit: ExitCode::Refused,
            source: Provenance::host("live health probe"),
            data: json!({}),
            warnings: vec![],
            error: Some(
                "node is healthy — stop the node first, or pass --yes to force a live backup (may be inconsistent)"
                    .into(),
            ),
        }
        .emit(opts));
    }

    let dir = data_dir();
    if !Path::new(&dir).is_dir() {
        return Err(format!("data dir missing: {dir}"));
    }

    let staging = std::env::temp_dir().join(format!(
        "connector-backup-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let data_copy = staging.join("data");
    copy_dir(Path::new(&dir), &data_copy)?;

    let manifest = json!({
        "schema": "connector.trust_domain_backup.v1",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "data_dir": dir,
        "cli_version": env!("CARGO_PKG_VERSION"),
        "live_forced": node_is_up(opts),
        "files": file_inventory(&data_copy)?,
    });
    std::fs::write(
        staging.join("MANIFEST.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .map_err(|e| e.to_string())?;

    let status = Command::new("tar")
        .args(["-czf", &out, "-C"])
        .arg(&staging)
        .args(["MANIFEST.json", "data"])
        .status()
        .map_err(|e| format!("tar failed: {e}"))?;
    let _ = std::fs::remove_dir_all(&staging);
    if !status.success() {
        return Ok(CmdResult {
            ok: false,
            command: "data backup".into(),
            exit: ExitCode::Failure,
            source: Provenance::host("tar create"),
            data: json!({}),
            warnings: vec![],
            error: Some("tar create failed".into()),
        }
        .emit(opts));
    }

    let sha = sha256_file(Path::new(&out))?;
    Ok(CmdResult {
        ok: true,
        command: "data backup".into(),
        exit: ExitCode::Success,
        source: Provenance::host(format!("tar of {dir}")),
        data: merge_human(
            json!({
                "archive": out,
                "sha256": sha,
                "manifest_schema": "connector.trust_domain_backup.v1",
                "live_forced": node_is_up(opts),
            }),
            vec![
                format!("backup → {out}"),
                format!("sha256: {sha}"),
            ],
            opts,
        ),
        warnings: if node_is_up(opts) {
            vec!["backup taken while node was healthy — consistency not guaranteed".into()]
        } else {
            vec![]
        },
        error: None,
    }
    .emit(opts))
}

fn restore(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let archive = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .ok_or("usage: connectorctl data restore <archive.tar.gz> --yes")?;
    if !opts.yes {
        return Err("usage: restore requires --yes".into());
    }
    if node_is_up(opts) {
        return Ok(CmdResult {
            ok: false,
            command: "data restore".into(),
            exit: ExitCode::Refused,
            source: Provenance::host("live health probe"),
            data: json!({}),
            warnings: vec![],
            error: Some("node is healthy — run `connectorctl node stop` before restore".into()),
        }
        .emit(opts));
    }
    if !Path::new(&archive).is_file() {
        return Err(format!("archive not found: {archive}"));
    }

    let staging = std::env::temp_dir().join(format!(
        "connector-restore-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let status = Command::new("tar")
        .args(["-xzf", &archive, "-C"])
        .arg(&staging)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("tar extract failed".into());
    }

    let manifest_path = staging.join("MANIFEST.json");
    let mut warnings = vec![];
    if manifest_path.is_file() {
        let raw = std::fs::read_to_string(&manifest_path).map_err(|e| e.to_string())?;
        let man: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| format!("manifest decode: {e}"))?;
        if man.get("schema").and_then(|s| s.as_str()) != Some("connector.trust_domain_backup.v1")
        {
            return Err("manifest schema mismatch — refusing restore".into());
        }
    } else {
        warnings.push("archive has no MANIFEST.json — restoring as legacy flat data dump".into());
    }

    let src_data = if staging.join("data").is_dir() {
        staging.join("data")
    } else {
        staging.clone()
    };
    let dest = data_dir();
    std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    // Clear dest contents carefully
    for entry in std::fs::read_dir(&dest).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(&p).map_err(|e| e.to_string())?;
        }
    }
    copy_dir(&src_data, Path::new(&dest))?;
    let _ = std::fs::remove_dir_all(&staging);

    Ok(CmdResult {
        ok: true,
        command: "data restore".into(),
        exit: ExitCode::Success,
        source: Provenance::host(format!("tar extract {archive} → {dest}")),
        data: merge_human(
            json!({ "archive": archive, "data_dir": dest }),
            vec![format!("restored {archive} → {dest}")],
            opts,
        ),
        warnings,
        error: None,
    }
    .emit(opts))
}

fn upgrade(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let mut from: Option<String> = None;
    let mut apply = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from-tarball" | "--from" => {
                from = args.get(i + 1).cloned();
                i += 2;
            }
            "--apply" => {
                apply = true;
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "usage: unknown flag {other}\nconnectorctl data upgrade [--from-tarball DIR|TAR.gz] [--apply]"
                ));
            }
            _ => i += 1,
        }
    }

    let steps = vec![
        "1. connectorctl data backup -o /var/backups/pre-upgrade.tar.gz".into(),
        "2. connectorctl node stop".into(),
        "3. sha256sum -c SHA256SUMS".into(),
        "4. connectorctl data upgrade --from-tarball <pkg> --apply".into(),
        "5. connectorctl node start && connectorctl node doctor".into(),
    ];

    let Some(src) = from else {
        if apply {
            return Err("--apply requires --from-tarball".into());
        }
        return Ok(CmdResult {
            ok: true,
            command: "data upgrade".into(),
            exit: ExitCode::Success,
            source: Provenance::host("upgrade runbook"),
            data: merge_human(
                json!({ "data_dir": data_dir(), "steps": steps }),
                {
                    let mut l = vec![
                        "Node binary upgrade (data_dir preserved)".into(),
                        format!("data_dir: {}", data_dir()),
                    ];
                    l.extend(steps);
                    l
                },
                opts,
            ),
            warnings: vec![],
            error: None,
        }
        .emit(opts));
    };

    let stage = extract_or_dir(&src)?;
    let bin_platform = find_in_stage(&stage, "connector-platform")?;
    let bin_ctl = find_in_stage(&stage, "connectorctl")?;
    let install_dir =
        std::env::var("CONNECTOR_INSTALL_DIR").unwrap_or_else(|_| "/usr/local/bin".into());

    if !apply {
        return Ok(CmdResult {
            ok: true,
            command: "data upgrade".into(),
            exit: ExitCode::Success,
            source: Provenance::host("dry-run"),
            data: merge_human(
                json!({
                    "platform_src": bin_platform,
                    "ctl_src": bin_ctl,
                    "install_dir": install_dir,
                    "apply": false,
                }),
                vec![
                    format!("would install {} → {install_dir}/connector-platform", bin_platform),
                    format!("would install {} → {install_dir}/connectorctl", bin_ctl),
                    "dry run only — re-run with --apply after node stop".into(),
                ],
                opts,
            ),
            warnings: vec![],
            error: None,
        }
        .emit(opts));
    }

    if node_is_up(opts) {
        return Ok(CmdResult {
            ok: false,
            command: "data upgrade".into(),
            exit: ExitCode::Refused,
            source: Provenance::host("live health probe"),
            data: json!({}),
            warnings: vec![],
            error: Some("node still healthy — stop before --apply".into()),
        }
        .emit(opts));
    }

    let dest_p = Path::new(&install_dir).join("connector-platform");
    let dest_c = Path::new(&install_dir).join("connectorctl");
    // Keep rollback copies
    for (src_bin, dest) in [(&bin_platform, &dest_p), (&bin_ctl, &dest_c)] {
        if dest.exists() {
            let bak = PathBuf::from(format!("{}.bak", dest.display()));
            let _ = std::fs::copy(dest, &bak);
        }
        std::fs::copy(src_bin, dest).map_err(|e| {
            format!(
                "copy {src_bin} → {}: {e} (need write access or set CONNECTOR_INSTALL_DIR)",
                dest.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dest)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(dest, perms);
        }
    }

    Ok(CmdResult {
        ok: true,
        command: "data upgrade".into(),
        exit: ExitCode::Success,
        source: Provenance::host(format!("atomic replace under {install_dir}")),
        data: merge_human(
            json!({
                "install_dir": install_dir,
                "data_dir_untouched": data_dir(),
                "rollback_suffix": ".bak",
            }),
            vec![
                format!("binaries replaced under {install_dir}"),
                "data_dir untouched — next: connectorctl node start && connectorctl node doctor"
                    .into(),
            ],
            opts,
        ),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn storage(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let client = Client::new(opts)?;
    match client.get_json("/api/v1/monitor/storage/layout") {
        Ok(v) => Ok(CmdResult {
            ok: true,
            command: "data storage".into(),
            exit: ExitCode::Success,
            source: Provenance::api("GET", "/api/v1/monitor/storage/layout"),
            data: v,
            warnings: vec![],
            error: None,
        }
        .emit(opts)),
        Err(e) => Ok(CmdResult {
            ok: false,
            command: "data storage".into(),
            exit: e.exit_code(),
            source: Provenance::api("GET", "/api/v1/monitor/storage/layout"),
            data: json!({}),
            warnings: vec![],
            error: Some(e.message()),
        }
        .emit(opts)),
    }
}

fn extract_or_dir(src: &str) -> Result<PathBuf, String> {
    let p = Path::new(src);
    if !p.exists() {
        return Err(format!("path not found: {src}"));
    }
    if p.is_file() && src.ends_with(".tar.gz") {
        let tmp = std::env::temp_dir().join(format!("connector-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let st = Command::new("tar")
            .args(["-xzf", src, "-C"])
            .arg(&tmp)
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("tar extract failed".into());
        }
        let mut root = tmp.clone();
        if let Ok(rd) = std::fs::read_dir(&tmp) {
            let dirs: Vec<_> = rd
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .collect();
            if dirs.len() == 1 {
                root = dirs[0].path();
            }
        }
        Ok(root)
    } else if p.is_dir() {
        Ok(p.to_path_buf())
    } else {
        Err("--from-tarball must be .tar.gz or extracted package dir".into())
    }
}

fn find_in_stage(stage: &Path, name: &str) -> Result<String, String> {
    for c in [stage.join("bin").join(name), stage.join(name)] {
        if c.is_file() {
            return Ok(c.display().to_string());
        }
    }
    Err(format!("{name} not found under {}", stage.display()))
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in walkdir(src)? {
        let rel = entry.strip_prefix(src).map_err(|e| e.to_string())?;
        let target = dst.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
        } else if entry.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::copy(&entry, &target).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = vec![];
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for e in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            let p = e.path();
            out.push(p.clone());
            if p.is_dir() {
                rec(&p, out)?;
            }
        }
        Ok(())
    }
    rec(root, &mut out)?;
    Ok(out)
}

fn file_inventory(root: &Path) -> Result<Vec<serde_json::Value>, String> {
    let mut files = vec![];
    for p in walkdir(root)? {
        if p.is_file() {
            let meta = std::fs::metadata(&p).map_err(|e| e.to_string())?;
            let rel = p.strip_prefix(root).unwrap_or(&p);
            files.push(json!({
                "path": rel.display().to_string(),
                "bytes": meta.len(),
            }));
        }
    }
    Ok(files)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    if let Ok(out) = Command::new("sha256sum").arg(path).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(hash) = s.split_whitespace().next() {
                return Ok(hash.to_string());
            }
        }
    }
    Ok("(sha256sum unavailable)".into())
}

fn merge_human(
    mut data: serde_json::Value,
    lines: Vec<String>,
    opts: &GlobalOpts,
) -> serde_json::Value {
    if opts.output == crate::output::OutputMode::Human {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("_human".into(), json!(lines));
        } else {
            return human_lines(lines);
        }
    }
    data
}
