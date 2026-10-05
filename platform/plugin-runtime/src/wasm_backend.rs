//! Phase **5.6** — Wasmtime + WASI preview1 for community / untrusted plugin binaries (`.wasm`).
//!
//! - **`SpawnRequest::program`** must point at a **WebAssembly module** (magic `\0asm` or `.wasm` suffix).
//! - **`CONNECTOR_WASM_FUEL_UNITS`** (optional): when set to a positive integer, enables **fuel** metering on the store.
//! - **Filesystem:** if **`workspace_host_mount`** or **`cwd`** is set and exists as a directory, it is preopened at **`/`**
//!   with read-only dir + file perms (guest sees the tree under `/`).
//! - **Network:** WASI TCP/UDP are disabled on the builder (`allow_tcp` / `allow_udp` **false**).

use std::fs;
use std::path::Path;

use async_trait::async_trait;
use serde_json::json;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtxBuilder};

use crate::error::PluginRuntimeError;
use crate::types::{IsolationRuntime, SpawnReceipt, SpawnRequest};
use crate::PluginIsolationBackend;

#[derive(Debug, Default, Clone)]
pub struct WasmPluginBackend;

impl WasmPluginBackend {
    pub fn new() -> Self {
        Self
    }
}

fn looks_like_wasm_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("wasm"))
        .unwrap_or(false)
        || wasm_magic_ok(path)
}

fn wasm_magic_ok(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    if let Ok(n) = fs::File::open(path).and_then(|mut f| std::io::Read::read(&mut f, &mut buf)) {
        n >= 4 && buf == *b"\0asm"
    } else {
        false
    }
}

fn wasm_fuel_units() -> Option<u64> {
    std::env::var("CONNECTOR_WASM_FUEL_UNITS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
}

fn run_wasm_sync(req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError> {
    if !looks_like_wasm_path(&req.program) {
        return Err(PluginRuntimeError::Wasm(
            "program path is not a wasm module (.wasm suffix or \\0asm magic)".into(),
        ));
    }
    let mut config = Config::new();
    config.async_support(false);
    if wasm_fuel_units().is_some() {
        config.consume_fuel(true);
    }
    let engine = Engine::new(&config).map_err(|e| PluginRuntimeError::Wasm(e.to_string()))?;

    let module = Module::from_file(&engine, &req.program)
        .map_err(|e| PluginRuntimeError::Wasm(format!("load module: {e}")))?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |cx| cx)
        .map_err(|e| PluginRuntimeError::Wasm(format!("link wasi: {e}")))?;

    let guest_argv0 = req
        .program
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("plugin.wasm")
        .to_string();
    let mut argv: Vec<String> = vec![guest_argv0];
    argv.extend(req.args.iter().cloned());

    let mut builder = WasiCtxBuilder::new();
    builder.allow_blocking_current_thread(true);
    builder.allow_tcp(false);
    builder.allow_udp(false);
    builder.args(&argv);
    for (k, v) in &req.env {
        builder.env(k, v);
    }
    let preopen = req
        .workspace_host_mount
        .clone()
        .or(req.cwd.clone())
        .filter(|p| p.is_dir());
    if let Some(ref dir) = preopen {
        builder
            .preopened_dir(dir, ".", DirPerms::READ, FilePerms::READ)
            .map_err(|e| PluginRuntimeError::Wasm(format!("preopen dir {}: {e}", dir.display())))?;
    }

    let wasi = builder.build_p1();
    let mut store = Store::new(&engine, wasi);
    let fuel_budget = wasm_fuel_units();
    if let Some(units) = fuel_budget {
        store
            .set_fuel(units)
            .map_err(|e| PluginRuntimeError::Wasm(format!("set fuel: {e}")))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| PluginRuntimeError::Wasm(format!("instantiate: {e}")))?;

    let entry = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .or_else(|_| instance.get_typed_func::<(), ()>(&mut store, "main"))
        .map_err(|_| {
            PluginRuntimeError::Wasm(
                "wasm module has no `_start` or `main` export (expected WASI command)".into(),
            )
        })?;

    let exit_code = match entry.call(&mut store, ()) {
        Ok(()) => 0i32,
        Err(e) => {
            if let Some(I32Exit(code)) = e.downcast_ref() {
                *code
            } else {
                return Err(PluginRuntimeError::Wasm(format!("wasm trap: {e:?}")));
            }
        }
    };

    let fuel_units_consumed = fuel_budget.and_then(|b| {
        store
            .get_fuel()
            .ok()
            .map(|remaining| b.saturating_sub(remaining))
    });

    Ok(SpawnReceipt {
        backend: "wasm".into(),
        plugin_id: req.plugin_id,
        detail: json!({
            "phase": "5.6_wasmtime_wasi_p1",
            "wasm_path": req.program,
            "exit_code": exit_code,
            "fuel_units_budget": fuel_budget,
            "fuel_units_consumed": fuel_units_consumed,
            "preopened_host_dir": preopen,
            "argv": argv,
        }),
    })
}

#[async_trait]
impl PluginIsolationBackend for WasmPluginBackend {
    fn kind(&self) -> IsolationRuntime {
        IsolationRuntime::Wasm
    }

    async fn spawn(&self, req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError> {
        tokio::task::spawn_blocking(move || run_wasm_sync(req))
            .await
            .map_err(|e| PluginRuntimeError::Spawn(format!("wasm join: {e}")))?
    }
}
