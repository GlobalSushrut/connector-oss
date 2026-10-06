//! Offline evidence bundle verification (no database, no server).
//!
//! Usage:
//!   witnessctl-verify ./evidence.witness --hmac-secret <secret>
//!   WITNESSCTL_HMAC_SECRET=... witnessctl-verify ./evidence.witness

use std::env;
use std::path::Path;
use std::process::ExitCode;

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let path = match args.get(1) {
        Some(p) if !p.starts_with('-') => p,
        _ => {
            eprintln!("Usage: witnessctl-verify <bundle.witness|.witnessctl|.witness.json> [--hmac-secret <secret>]");
            return ExitCode::from(2);
        }
    };
    let secret = flag_value(&args, "--hmac-secret")
        .or_else(|| env::var("WITNESSCTL_HMAC_SECRET").ok())
        .unwrap_or_default();
    if secret.trim().is_empty() {
        eprintln!("error: set WITNESSCTL_HMAC_SECRET or --hmac-secret");
        return ExitCode::from(2);
    }

    let bundle = match witnessctl::bundle_file::load_bundle_json(Path::new(path)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };
    match witnessctl::receipt::verify_bundle_value(&bundle, secret.trim()) {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            if report.tamper_detected {
                eprintln!("FAILED: tamper detected");
                return ExitCode::from(1);
            }
            println!("PASSED: chain_valid captures={} receipts={}", report.capture_count, report.receipt_count);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}
