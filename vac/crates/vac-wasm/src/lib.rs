//! VAC WASM - WebAssembly bindings for VAC
//!
//! Provides JavaScript/TypeScript bindings for the VAC core functionality.

use wasm_bindgen::prelude::*;

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    // Set panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Compute SHA256 hash
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    vac_core::sha256(data).to_vec()
}

/// Encode event to DAG-CBOR and return CID string
#[wasm_bindgen]
pub fn encode_event(event_json: &str) -> Result<String, JsValue> {
    let event: vac_core::Event = serde_json::from_str(event_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
    
    let cid = vac_core::compute_cid(&event)
        .map_err(|e| JsValue::from_str(&format!("CID error: {}", e)))?;
    
    Ok(cid.to_string())
}

/// Create a sparse vector from features
#[wasm_bindgen]
pub struct JsSparseVector {
    inner: vac_red::SparseVector,
}

#[wasm_bindgen]
impl JsSparseVector {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: vac_red::SparseVector::new(),
        }
    }
    
    pub fn add(&mut self, dim: usize, value: f64) {
        self.inner.add(dim, value);
    }
    
    pub fn get(&self, dim: usize) -> f64 {
        self.inner.get(dim)
    }
    
    pub fn norm(&self) -> f64 {
        self.inner.norm()
    }
    
    pub fn normalize(&mut self) {
        self.inner.normalize();
    }
    
    pub fn cosine_similarity(&self, other: &JsSparseVector) -> f64 {
        self.inner.cosine_similarity(&other.inner)
    }
}

/// RED Engine for entropy computation
#[wasm_bindgen]
pub struct JsRedEngine {
    inner: vac_red::RedEngine,
}

#[wasm_bindgen]
impl JsRedEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: vac_red::RedEngine::new(),
        }
    }
    
    pub fn observe(&mut self, vector: &JsSparseVector) {
        self.inner.observe(&vector.inner);
    }
    
    pub fn retrieval_feedback(&mut self, vector: &JsSparseVector, was_useful: bool) {
        self.inner.retrieval_feedback(&vector.inner, was_useful);
    }
    
    pub fn compute_entropy(&self, vector: &JsSparseVector) -> f64 {
        self.inner.compute_entropy(&vector.inner)
    }
    
    pub fn reframe_network(&mut self) {
        self.inner.reframe_network();
    }
    
    pub fn total_observations(&self) -> u64 {
        self.inner.total_observations
    }
    
    pub fn total_retrievals(&self) -> u64 {
        self.inner.total_retrievals
    }
}

/// Encode features into a sparse vector
#[wasm_bindgen]
pub fn encode_features(
    entities: Vec<String>,
    predicates: Vec<String>,
    text: &str,
) -> JsSparseVector {
    let inner = vac_red::encode_event(&entities, &predicates, text, vac_red::DEFAULT_DIMS);
    JsSparseVector { inner }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_sparse_vector() {
        let mut v = JsSparseVector::new();
        v.add(0, 1.0);
        assert_eq!(v.get(0), 1.0);
    }
}
