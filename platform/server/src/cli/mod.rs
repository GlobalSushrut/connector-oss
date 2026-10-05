//! CLI Module for connectorctl
//!
//! Provides:
//! - Help system with man-page style documentation
//! - Shell completion for bash, zsh, and fish

pub mod help;
pub mod completion;

pub use help::{HelpSystem, HelpPage};
pub use completion::{Shell, generate_completion, print_install_instructions};
