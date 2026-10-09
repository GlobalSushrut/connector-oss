//! CLI output formatting utilities.

/// Print a success message with checkmark.
pub fn success(msg: &str) {
    println!("  ✓ {}", msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    println!("  ⚠ {}", msg);
}

/// Print an error message.
pub fn error(msg: &str) {
    eprintln!("  ✗ {}", msg);
}

/// Print a section header.
pub fn section(title: &str) {
    println!("\n── {} ──", title);
}
