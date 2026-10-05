use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmtime::{Config, Engine, Instance, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxCredential {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasmSandboxRequest {
    pub vakya: serde_json::Value,
    #[serde(default)]
    pub input: serde_json::Value,
    #[serde(default)]
    pub credentials: Vec<SandboxCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WasmSandboxLimits {
    pub max_memory_bytes: usize,
    pub fuel: u64,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024,
            fuel: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasmSandboxResult {
    pub output: serde_json::Value,
    pub fuel_remaining: u64,
}

#[derive(Debug, Error)]
pub enum WasmSandboxError {
    #[error("sandbox configuration error: {0}")]
    Config(String),
    #[error("wasm runtime error: {0}")]
    Runtime(String),
    #[error("module is missing required export: {0}")]
    MissingExport(String),
    #[error("invalid ABI response from guest module")]
    InvalidResponse,
    #[error("serialization error: {0}")]
    Serialization(String),
}

struct SandboxState {
    limits: StoreLimits,
}

pub struct VakyaWasmSandbox {
    engine: Engine,
    limits: WasmSandboxLimits,
}

impl VakyaWasmSandbox {
    pub fn new(limits: WasmSandboxLimits) -> Result<Self, WasmSandboxError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|e| WasmSandboxError::Config(e.to_string()))?;
        Ok(Self { engine, limits })
    }

    pub fn execute(
        &self,
        module_bytes: &[u8],
        entrypoint: &str,
        request: &WasmSandboxRequest,
    ) -> Result<WasmSandboxResult, WasmSandboxError> {
        let module = Module::from_binary(&self.engine, module_bytes)
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;

        let state = SandboxState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;

        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmSandboxError::MissingExport("memory".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| WasmSandboxError::MissingExport("alloc".into()))?;
        let execute = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, entrypoint)
            .map_err(|_| WasmSandboxError::MissingExport(entrypoint.into()))?;

        let payload = Self::request_payload(request)?;
        let input_ptr = alloc
            .call(&mut store, payload.len() as i32)
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;
        memory
            .write(&mut store, input_ptr as usize, &payload)
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;

        let packed = execute
            .call(&mut store, (input_ptr, payload.len() as i32))
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;
        let (output_ptr, output_len) = Self::unpack_ptr_len(packed)?;
        let output = Self::read_json(&memory, &mut store, output_ptr, output_len)?;
        let fuel_remaining = store
            .get_fuel()
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;

        Ok(WasmSandboxResult {
            output,
            fuel_remaining,
        })
    }

    fn request_payload(request: &WasmSandboxRequest) -> Result<Vec<u8>, WasmSandboxError> {
        let creds: BTreeMap<String, String> = request
            .credentials
            .iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "vakya": request.vakya,
            "input": request.input,
            "credentials": creds,
        }))
        .map_err(|e| WasmSandboxError::Serialization(e.to_string()))
    }

    fn unpack_ptr_len(packed: i64) -> Result<(usize, usize), WasmSandboxError> {
        if packed < 0 {
            return Err(WasmSandboxError::InvalidResponse);
        }
        let ptr = ((packed >> 32) & 0xffff_ffff) as usize;
        let len = (packed & 0xffff_ffff) as usize;
        Ok((ptr, len))
    }

    fn read_json(
        memory: &Memory,
        store: &mut Store<SandboxState>,
        ptr: usize,
        len: usize,
    ) -> Result<serde_json::Value, WasmSandboxError> {
        let mut bytes = vec![0u8; len];
        memory
            .read(store, ptr, &mut bytes)
            .map_err(|e| WasmSandboxError::Runtime(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| WasmSandboxError::Serialization(e.to_string()))
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 4096))
                (func (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $heap))
                    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
                    (local.get $ptr)
                )
                (func (export "execute") (param $ptr i32) (param $len i32) (result i64)
                    (local $out i32)
                    (local $i i32)
                    (local.set $out (call 0 (local.get $len)))
                    (local.set $i (i32.const 0))
                    (block $done
                      (loop $copy
                        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
                        (i32.store8
                          (i32.add (local.get $out) (local.get $i))
                          (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $copy)))
                    (i64.or
                      (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
                      (i64.extend_i32_u (local.get $len)))
                )
            )"#,
        )
        .unwrap()
    }

    fn counter_module() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 4096))
                (global $count (mut i32) (i32.const 0))
                (data (i32.const 2048) "{\"count\":0}")
                (func (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $heap))
                    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
                    (local.get $ptr)
                )
                (func (export "execute") (param $ptr i32) (param $len i32) (result i64)
                    (drop (local.get $ptr))
                    (drop (local.get $len))
                    (global.set $count (i32.add (global.get $count) (i32.const 1)))
                    (i32.store8 (i32.const 2057) (i32.add (global.get $count) (i32.const 48)))
                    (i64.or
                      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
                      (i64.extend_i32_u (i32.const 11)))
                )
            )"#,
        )
        .unwrap()
    }

    #[test]
    fn test_sandbox_injects_credentials_into_request() {
        let sandbox = VakyaWasmSandbox::new(WasmSandboxLimits::default()).unwrap();
        let result = sandbox
            .execute(
                &echo_module(),
                "execute",
                &WasmSandboxRequest {
                    vakya: serde_json::json!({"action": "test.run"}),
                    input: serde_json::json!({"payload": true}),
                    credentials: vec![SandboxCredential {
                        name: "api_key".into(),
                        value: "secret-123".into(),
                    }],
                },
            )
            .unwrap();

        assert_eq!(result.output["vakya"]["action"], "test.run");
        assert_eq!(result.output["credentials"]["api_key"], "secret-123");
        assert_eq!(result.output["input"]["payload"], true);
    }

    #[test]
    fn test_sandbox_instance_is_ephemeral_per_execution() {
        let sandbox = VakyaWasmSandbox::new(WasmSandboxLimits::default()).unwrap();
        let request = WasmSandboxRequest {
            vakya: serde_json::json!({"action": "test.counter"}),
            input: serde_json::Value::Null,
            credentials: vec![],
        };

        let first = sandbox.execute(&counter_module(), "execute", &request).unwrap();
        let second = sandbox.execute(&counter_module(), "execute", &request).unwrap();

        assert_eq!(first.output["count"], 1);
        assert_eq!(second.output["count"], 1);
    }
}
