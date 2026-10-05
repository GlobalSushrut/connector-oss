//! Boot progress reporter
//!
//! Formats and displays boot progress in a professional infrastructure style.

use super::{StageResult, NodeIdentity, BootContext, BOOT_STAGE_NAMES};
use std::time::Duration;

/// ANSI color codes for terminal output
mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RED: &str = "\x1b[31m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
}

/// Check if colors should be used
fn use_colors() -> bool {
    std::env::var("NO_COLOR").is_err() 
        && std::env::var("CONNECTOR_NO_COLOR").is_err()
        && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// Boot reporter for formatted output
pub struct BootReporter {
    use_colors: bool,
    verbose: bool,
}

impl BootReporter {
    pub fn new() -> Self {
        Self {
            use_colors: use_colors(),
            verbose: std::env::var("CONNECTOR_BOOT_VERBOSE").is_ok(),
        }
    }

    /// Print the boot header
    pub fn print_header(&self, identity: &NodeIdentity) {
        let version = identity.version;
        
        if self.use_colors {
            eprintln!();
            eprintln!("{}{}Connector Node Boot v{}{}",
                colors::BOLD, colors::CYAN, version, colors::RESET);
            eprintln!("{}════════════════════════════════════════════════════════════════{}",
                colors::DIM, colors::RESET);
            eprintln!();
            eprintln!("{}[NODE]{}       ID: {}",
                colors::CYAN, colors::RESET, identity.node_id);
            eprintln!("{}[NODE]{}       Mode: {}",
                colors::CYAN, colors::RESET, identity.mode);
            eprintln!("{}[NODE]{}       Version: {}",
                colors::CYAN, colors::RESET, version);
            eprintln!("{}[NODE]{}       Data: {}",
                colors::CYAN, colors::RESET, identity.data_dir);
            eprintln!();
        } else {
            eprintln!();
            eprintln!("Connector Node Boot v{}", version);
            eprintln!("════════════════════════════════════════════════════════════════");
            eprintln!();
            eprintln!("[NODE]       ID: {}", identity.node_id);
            eprintln!("[NODE]       Mode: {}", identity.mode);
            eprintln!("[NODE]       Version: {}", version);
            eprintln!("[NODE]       Data: {}", identity.data_dir);
            eprintln!();
        }
    }

    /// Print a stage result
    pub fn print_stage(&self, result: &StageResult) {
        let duration_ms = result.duration.as_millis();
        let duration_str = if duration_ms > 0 {
            format!("{}ms", duration_ms)
        } else {
            String::new()
        };

        // Determine category for display
        let category = match result.stage {
            0..=1 => "CONFIG",
            2 => "CONFIG",
            3 => "STORAGE",
            4..=5 => "CORE",
            6 => "SCHEDULER",
            7 => "CAPS",
            8 => "RESTORE",
            9 => "SERVICES",
            10 => "ACCESS",
            11 => "READY",
            _ => "UNKNOWN",
        };

        if self.use_colors {
            let (icon, color) = if result.success {
                ("✓", colors::GREEN)
            } else {
                ("✗", colors::RED)
            };

            eprintln!(
                "{}[{:<10}]{} {} {:<40} {}{}{}",
                colors::CYAN,
                category,
                colors::RESET,
                icon,
                result.message,
                colors::DIM,
                duration_str,
                colors::RESET
            );

            // Print details if verbose
            if self.verbose && !result.details.is_empty() {
                for detail in &result.details {
                    eprintln!("{}             {}{}",
                        colors::DIM, detail, colors::RESET);
                }
            }
        } else {
            let icon = if result.success { "✓" } else { "✗" };
            eprintln!(
                "[{:<10}] {} {:<40} {}",
                category,
                icon,
                result.message,
                duration_str
            );

            if self.verbose && !result.details.is_empty() {
                for detail in &result.details {
                    eprintln!("             {}", detail);
                }
            }
        }
    }

    /// Print access endpoints (special formatting)
    pub fn print_access(&self, addr: &str) {
        if self.use_colors {
            eprintln!();
            eprintln!("{}[ACCESS]{}     {} API .......................... {}:{}/api/v1",
                colors::CYAN, colors::RESET, colors::GREEN, addr, colors::RESET);
            eprintln!("{}[ACCESS]{}     {} UI ........................... {}:{}/",
                colors::CYAN, colors::RESET, colors::GREEN, addr, colors::RESET);
            eprintln!("{}[ACCESS]{}     {} Metrics ...................... {}:{}/metrics",
                colors::CYAN, colors::RESET, colors::GREEN, addr, colors::RESET);
            eprintln!("{}[ACCESS]{}     {} Health ....................... {}:{}/health",
                colors::CYAN, colors::RESET, colors::GREEN, addr, colors::RESET);
        } else {
            eprintln!();
            eprintln!("[ACCESS]     ✓ API .......................... {}/api/v1", addr);
            eprintln!("[ACCESS]     ✓ UI ........................... {}/", addr);
            eprintln!("[ACCESS]     ✓ Metrics ...................... {}/metrics", addr);
            eprintln!("[ACCESS]     ✓ Health ....................... {}/health", addr);
        }
    }

    /// Print the boot footer (ready state)
    pub fn print_footer(&self, total_duration: Duration, success: bool) {
        eprintln!();
        
        if self.use_colors {
            eprintln!("{}════════════════════════════════════════════════════════════════{}",
                colors::DIM, colors::RESET);
            
            if success {
                eprintln!("{}{}[READY]{}      Node healthy — workloads schedulable",
                    colors::BOLD, colors::GREEN, colors::RESET);
                eprintln!("{}{}[READY]{}      Boot time: {}ms",
                    colors::BOLD, colors::GREEN, colors::RESET, total_duration.as_millis());
            } else {
                eprintln!("{}{}[FAILED]{}     Boot failed — see errors above",
                    colors::BOLD, colors::RED, colors::RESET);
            }
            
            eprintln!("{}════════════════════════════════════════════════════════════════{}",
                colors::DIM, colors::RESET);
        } else {
            eprintln!("════════════════════════════════════════════════════════════════");
            
            if success {
                eprintln!("[READY]      Node healthy — workloads schedulable");
                eprintln!("[READY]      Boot time: {}ms", total_duration.as_millis());
            } else {
                eprintln!("[FAILED]     Boot failed — see errors above");
            }
            
            eprintln!("════════════════════════════════════════════════════════════════");
        }
        
        eprintln!();
    }

    /// Print dev mode banner
    pub fn print_dev_mode(&self, addr: &str) {
        if self.use_colors {
            eprintln!();
            eprintln!("{}{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
                colors::BOLD, colors::YELLOW, colors::RESET);
            eprintln!("{}{}  DEV MODE — auth bypassed. Use any token:{}",
                colors::BOLD, colors::YELLOW, colors::RESET);
            eprintln!("{}  Authorization: Bearer dev-token{}",
                colors::WHITE, colors::RESET);
            eprintln!();
            eprintln!("{}  Quick start:{}",
                colors::WHITE, colors::RESET);
            eprintln!("{}    curl {}/health{}",
                colors::DIM, addr, colors::RESET);
            eprintln!("{}    curl {}/api/v1{}",
                colors::DIM, addr, colors::RESET);
            eprintln!("{}{}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{}",
                colors::BOLD, colors::YELLOW, colors::RESET);
        } else {
            eprintln!();
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("  DEV MODE — auth bypassed. Use any token:");
            eprintln!("  Authorization: Bearer dev-token");
            eprintln!();
            eprintln!("  Quick start:");
            eprintln!("    curl {}/health", addr);
            eprintln!("    curl {}/api/v1", addr);
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
        eprintln!();
    }

    /// Print a boot error
    pub fn print_error(&self, stage: &str, message: &str, hint: Option<&str>) {
        if self.use_colors {
            eprintln!();
            eprintln!("{}{}[BOOT ERROR]{} Stage: {}",
                colors::BOLD, colors::RED, colors::RESET, stage);
            eprintln!("{}  Error: {}{}",
                colors::RED, message, colors::RESET);
            if let Some(h) = hint {
                eprintln!("{}  Fix: {}{}",
                    colors::YELLOW, h, colors::RESET);
            }
            eprintln!();
        } else {
            eprintln!();
            eprintln!("[BOOT ERROR] Stage: {}", stage);
            eprintln!("  Error: {}", message);
            if let Some(h) = hint {
                eprintln!("  Fix: {}", h);
            }
            eprintln!();
        }
    }
}

impl Default for BootReporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a boot context as JSON (for structured logging)
pub fn boot_context_to_json(ctx: &BootContext) -> serde_json::Value {
    serde_json::json!({
        "node_id": ctx.identity.node_id,
        "version": ctx.identity.version,
        "mode": ctx.identity.mode.to_string(),
        "environment": ctx.identity.environment,
        "boot_time_ms": ctx.total_duration().as_millis(),
        "ready": ctx.is_complete(),
        "stages": ctx.stages.iter().map(|s| {
            serde_json::json!({
                "stage": s.stage,
                "name": s.name,
                "success": s.success,
                "duration_ms": s.duration.as_millis(),
                "message": s.message,
            })
        }).collect::<Vec<_>>(),
    })
}
