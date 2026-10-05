//! connectorctl — neutral operator CLI for Connector Platform.
//!
//! Machine-truth contract: every successful command cites a real host mechanism
//! or exact API route. No invented measurements, no endpoint relabeling.

mod access;
mod data;
mod govern;
mod iia;
mod node;
mod output;
mod product;
mod product_eval;
mod registry;
mod substrate;
mod transport;
mod workload;

use output::{ExitCode, GlobalOpts};
use registry::dispatch;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match run(&args[1..]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            if e.starts_with("usage:") {
                ExitCode::Usage
            } else {
                ExitCode::Failure
            }
        }
    };
    std::process::exit(code as i32);
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let (opts, rest) = GlobalOpts::parse(args)?;
    if rest.is_empty() {
        registry::print_help(&opts);
        return Ok(ExitCode::Success);
    }
    dispatch(&opts, &rest)
}
