//! Hierarchical compliance ledger on disk (court-oriented retention model).
//!
//! Time model (aligned with operator spec):
//! - **Stamp**: 30 s wall-clock bucket (`unix_ts / STAMP_SEC`).
//! - **Frame**: `STAMPS_PER_FRAME` stamps = 5 minutes.
//! - **Rollup** (“12 hooks”): `FRAMES_PER_ROLLUP` consecutive frames = one rollup period.
//! - **Paragraph**: `ROLLUPS_PER_PARA` rollups.
//! - **Book**: `PARAS_PER_BOOK` paragraphs.
//! - **Retention**: keep at most [`MAX_BOOKS`] book directories (oldest pruned).
//!
//! Live TUI shows only the last 5 minutes of captures; full history lives under this tree — open with **z** in the WitnessCtl TUI (session quarantine moved to **Ctrl+z**).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const STAMP_SEC: i64 = 30;
pub const STAMPS_PER_FRAME: i64 = 10;
pub const FRAMES_PER_ROLLUP: i64 = 12;
pub const ROLLUPS_PER_PARA: i64 = 7;
pub const PARAS_PER_BOOK: i64 = 8;
pub const MAX_BOOKS: usize = 100;

pub fn books_root() -> PathBuf {
    if let Ok(p) = std::env::var("WITNESSCTL_COMPLIANCE_BOOKS_DIR") {
        let t = p.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local/share"))
        })
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("witnessctl").join("compliance-books")
}

fn hierarchy_for_bucket(stamp_bucket: i64) -> (i64, i64, i64, i64, i64) {
    let frame_ix = stamp_bucket / STAMPS_PER_FRAME;
    let rollup_ix = frame_ix / FRAMES_PER_ROLLUP;
    let para_ix = rollup_ix / ROLLUPS_PER_PARA;
    let book_ix = para_ix / PARAS_PER_BOOK;
    let para_ord = para_ix % PARAS_PER_BOOK;
    let rollup_ord = rollup_ix % ROLLUPS_PER_PARA;
    let frame_ord = frame_ix % FRAMES_PER_ROLLUP;
    (book_ix, para_ord, rollup_ord, frame_ord, stamp_bucket)
}

fn book_dir(root: &Path, book_ix: i64) -> PathBuf {
    root.join(format!("book_{book_ix:012}"))
}

/// Append a ledger record for an export (PDF/JSON/HTML/MD). Creates nested book/para/rollup/frame/stamp paths.
pub fn record_export_moment(
    session_id: Uuid,
    export_format: &str,
    body_sha256_hex: &str,
    body_len: usize,
) -> std::io::Result<()> {
    let root = books_root();
    fs::create_dir_all(&root)?;
    let readme = root.join("README.txt");
    if !readme.exists() {
        let mut f = fs::File::create(&readme)?;
        writeln!(
            f,
            "WitnessCtl compliance books (court-oriented ledger).\n\
             Stamp=30s bucket, frame=10 stamps (5 min), rollup=12 frames, para=7 rollups, book=8 paras; keep {MAX_BOOKS} books.\n\
             Live TUI shows last 5 minutes only — browse this directory (TUI key z).\n\
             Override path: WITNESSCTL_COMPLIANCE_BOOKS_DIR\n"
        )?;
    }

    let bucket = chrono::Utc::now().timestamp() / STAMP_SEC;
    let (book_ix, para, rollup, frame, _) = hierarchy_for_bucket(bucket);
    let bdir = book_dir(&root, book_ix);
    let stamp_path = bdir
        .join(format!("para_{para:02}"))
        .join(format!("rollup_{rollup:03}"))
        .join(format!("frame_{frame:02}"))
        .join(format!("stamp_{bucket}.json"));
    if let Some(parent) = stamp_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let line = serde_json::json!({
        "schema": "witnessctl.compliance_stamp.v1",
        "utc": chrono::Utc::now().to_rfc3339(),
        "stamp_bucket": bucket,
        "session_id": session_id,
        "export_format": export_format,
        "body_sha256": body_sha256_hex,
        "body_bytes": body_len,
        "hierarchy": {
            "book_ix": book_ix,
            "para": para,
            "rollup": rollup,
            "frame": frame,
            "stamps_per_frame": STAMPS_PER_FRAME,
            "frames_per_rollup": FRAMES_PER_ROLLUP,
            "rollups_per_para": ROLLUPS_PER_PARA,
            "paras_per_book": PARAS_PER_BOOK,
        }
    });
    fs::write(&stamp_path, format!("{}\n", line))?;

    let manifest = bdir.join("MANIFEST.jsonl");
    let mut mf = fs::OpenOptions::new().create(true).append(true).open(manifest)?;
    writeln!(
        mf,
        "{}",
        serde_json::json!({
            "t": chrono::Utc::now().to_rfc3339(),
            "session_id": session_id,
            "format": export_format,
            "sha256": body_sha256_hex,
            "stamp_path": stamp_path.strip_prefix(&root).unwrap_or(&stamp_path).display().to_string(),
        })
    )?;

    prune_old_books_under(&root)?;
    Ok(())
}

fn prune_old_books_under(root: &Path) -> std::io::Result<()> {
    let mut dirs: Vec<(i64, PathBuf)> = fs::read_dir(root)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("book_") {
                name.strip_prefix("book_")
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|ix| (ix, p))
            } else {
                None
            }
        })
        .collect();
    if dirs.len() <= MAX_BOOKS {
        return Ok(());
    }
    dirs.sort_by_key(|(ix, _)| *ix);
    while dirs.len() > MAX_BOOKS {
        if let Some((_, path)) = dirs.first() {
            let _ = fs::remove_dir_all(path);
        }
        dirs.remove(0);
    }
    Ok(())
}

/// Legal / custody front-matter prepended to exported Markdown (and thus HTML/PDF).
pub fn court_grade_front_matter(session_id: Uuid, chain_head: Option<&str>) -> String {
    let chain = chain_head.unwrap_or("(no chain head — session not sealed or chain unavailable)");
    format!(
        "---\n\
document_class: witnessctl_compliance_exhibit\n\
session_id: \"{sid}\"\n\
generator: \"WitnessCtl (connector-private)\"\n\
---\n\n\
# Court-grade exhibit header (machine + human)\n\n\
This artifact is generated **for governance and technical review**. It is **not** legal advice and **does not** by itself \
establish admissibility in any jurisdiction. Custody, discovery, and evidentiary rules remain the responsibility of the producing organization.\n\n\
## Chain-of-custody summary\n\n\
| Field | Value |\n\
|------|-------|\n\
| Session (UUID) | `{sid}` |\n\
| Wall-clock (UTC, generation) | `{gen}` |\n\
| Receipt chain head (HMAC) | `{chain}` |\n\
| Ledger root (books) | `{root}` |\n\n\
## Integrity model\n\n\
- Each export is logged under a **30 s stamp bucket** with nested **frame → rollup → paragraph → book** paths (see `README.txt` in the ledger directory).\n\
- The Markdown body below is followed by a **SHA-256** line anchoring the narrative **excluding** that final integrity section (two-pass in exporter).\n\n\
---\n\n",
        sid = session_id,
        gen = chrono::Utc::now().to_rfc3339(),
        chain = chain,
        root = books_root().display(),
    )
}

pub fn court_grade_integrity_footer(body_sha256_pre_footer: &str) -> String {
    format!(
        "\n\n---\n## Integrity anchor (SHA-256 of Markdown above this line)\n\n`sha256:{}`\n",
        body_sha256_pre_footer
    )
}

/// Open the ledger directory in the default file/browser handler (`xdg-open` / `open` / `explorer`).
pub fn open_books_root_in_browser() -> anyhow::Result<()> {
    let root = books_root();
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(&root)?;
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(&root).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer").arg(&root).spawn()?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::process::Command::new("xdg-open").arg(&root).spawn()?;
    }
    Ok(())
}
