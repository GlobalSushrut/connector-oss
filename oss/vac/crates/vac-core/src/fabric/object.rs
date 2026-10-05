//! # Memory Object Fabric
//!
//! S3-compatible durable storage for large memory payloads, artifacts, traces,
//! pages, snapshots, and archives.
//!
//! ## Namespace Layout
//!
//! ```text
//! s3://connector/
//!   tenants/{tenant_id}/
//!     containers/{container_id}/
//!       objects/{object_id}                        — raw memory objects (any modality)
//!       chunks/{chunk_id}                          — extracted chunks
//!       pages/{page_code}.json                     — range window pages
//!       traces/{trace_id}/span_{n}.json            — reasoning traces
//!       artifacts/{artifact_id}                    — uploaded documents
//!       snapshots/{snapshot_id}.bin                — replay snapshots
//!       bundles/{bundle_id}.tar.gz                 — evidence bundles
//!       archives/{year}/{month}/{archive_id}       — cold storage
//!       images/{image_id}.{ext}                    — camera, screenshot, render
//!       video/{video_id}.{ext}                     — video recordings, streams
//!       audio/{audio_id}.{ext}                     — microphone, speech, music
//!       sensors/{sensor_id}/{ts}.bin               — accelerometer, gyro, LiDAR, GPS
//!       point_clouds/{cloud_id}.{ext}              — 3D scans, depth maps
//!       models/{model_id}/v{ver}/weights.{ext}     — NN weights (safetensors, ONNX)
//!       models/{model_id}/v{ver}/config.json       — model config / hyperparams
//!       datasets/{dataset_id}/v{ver}/part_{n}.{ext}— training/eval data shards
//!       gradients/{run_id}/step_{n}.bin            — gradient snapshots
//!       features/{feature_id}.{ext}                — extracted feature maps
//!       perception/{frame_id}.{ext}                — perception pipeline output
//!       actuation/{command_id}.json                — motor/actuator commands
//!       multipart/{upload_id}/part_{n}             — chunked upload staging
//! ```
//!
//! ## Backends
//!
//! | Mode | Backend |
//! |------|---------|
//! | Developer | In-memory `HashMap` |
//! | Single-server | Local filesystem / MinIO |
//! | Production | AWS S3 / GCS / Azure Blob |
//! | Sovereign | Self-hosted MinIO / Ceph |

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::types::*;

// =============================================================================
// ObjectRef — S3-compatible object reference
// =============================================================================

/// Reference to an object stored in the Object Fabric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRef {
    pub namespace: String,
    pub key: String,
    pub version: Option<String>,
    pub size_bytes: u64,
    pub content_hash: String,
    pub content_type: String,
    pub storage_tier: StorageTier,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

/// Metadata attached to an object on write.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub content_type: String,
    pub storage_tier: StorageTier,
    pub tags: HashMap<String, String>,
}

impl Default for StorageTier {
    fn default() -> Self {
        StorageTier::Hot
    }
}

// =============================================================================
// ObjectFabricConfig
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectFabricConfig {
    /// Root prefix for all objects (e.g., "connector").
    pub root_prefix: String,
    /// Maximum object size in bytes (0 = unlimited).
    pub max_object_bytes: u64,
    /// Enable versioning.
    pub versioning_enabled: bool,
    /// Default storage tier for new objects.
    pub default_tier: StorageTier,
}

impl Default for ObjectFabricConfig {
    fn default() -> Self {
        Self {
            root_prefix: "connector".to_string(),
            max_object_bytes: 0,
            versioning_enabled: false,
            default_tier: StorageTier::Hot,
        }
    }
}

// =============================================================================
// ObjectBackend trait — pluggable storage provider
// =============================================================================

/// Backend trait for object storage.
///
/// Implement for each storage provider: in-memory, filesystem, S3, MinIO, etc.
pub trait ObjectBackend: Send + Sync {
    fn put(&mut self, namespace: &str, key: &str, data: &[u8], meta: &ObjectMeta) -> Result<ObjectRef, String>;
    fn get(&self, namespace: &str, key: &str) -> Result<(Vec<u8>, ObjectRef), String>;
    fn head(&self, namespace: &str, key: &str) -> Result<ObjectRef, String>;
    fn delete(&mut self, namespace: &str, key: &str) -> Result<(), String>;
    fn list(&self, namespace: &str, prefix: &str, limit: usize) -> Result<Vec<ObjectRef>, String>;
    fn exists(&self, namespace: &str, key: &str) -> bool;
    fn size(&self, namespace: &str, key: &str) -> Result<u64, String>;
}

// =============================================================================
// InMemoryObjectBackend — HashMap-based (developer mode)
// =============================================================================

/// In-memory object backend using HashMaps.
/// Suitable for testing and single-process agents.
#[derive(Debug, Default)]
pub struct InMemoryObjectBackend {
    objects: HashMap<(String, String), (Vec<u8>, ObjectRef)>,
    /// Version counter per (namespace, key) for versioning.
    versions: HashMap<(String, String), u64>,
}

impl InMemoryObjectBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.objects.values().map(|(data, _)| data.len() as u64).sum()
    }
}

impl ObjectBackend for InMemoryObjectBackend {
    fn put(&mut self, namespace: &str, key: &str, data: &[u8], meta: &ObjectMeta) -> Result<ObjectRef, String> {
        let version = self.versions
            .entry((namespace.to_string(), key.to_string()))
            .or_insert(0);
        *version += 1;

        let obj_ref = ObjectRef {
            namespace: namespace.to_string(),
            key: key.to_string(),
            version: Some(format!("v{}", version)),
            size_bytes: data.len() as u64,
            content_hash: sha2_hex(data),
            content_type: meta.content_type.clone(),
            storage_tier: meta.storage_tier,
            created_at: now_ms(),
            metadata: meta.tags.clone(),
        };

        self.objects.insert(
            (namespace.to_string(), key.to_string()),
            (data.to_vec(), obj_ref.clone()),
        );

        Ok(obj_ref)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<(Vec<u8>, ObjectRef), String> {
        self.objects
            .get(&(namespace.to_string(), key.to_string()))
            .cloned()
            .ok_or_else(|| format!("Object not found: {}/{}", namespace, key))
    }

    fn head(&self, namespace: &str, key: &str) -> Result<ObjectRef, String> {
        self.objects
            .get(&(namespace.to_string(), key.to_string()))
            .map(|(_, r)| r.clone())
            .ok_or_else(|| format!("Object not found: {}/{}", namespace, key))
    }

    fn delete(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        self.objects.remove(&(namespace.to_string(), key.to_string()));
        Ok(())
    }

    fn list(&self, namespace: &str, prefix: &str, limit: usize) -> Result<Vec<ObjectRef>, String> {
        let mut results: Vec<ObjectRef> = self.objects.iter()
            .filter(|((ns, k), _)| ns == namespace && k.starts_with(prefix))
            .map(|(_, (_, r))| r.clone())
            .collect();
        results.sort_by(|a, b| a.key.cmp(&b.key));
        results.truncate(limit);
        Ok(results)
    }

    fn exists(&self, namespace: &str, key: &str) -> bool {
        self.objects.contains_key(&(namespace.to_string(), key.to_string()))
    }

    fn size(&self, namespace: &str, key: &str) -> Result<u64, String> {
        self.objects
            .get(&(namespace.to_string(), key.to_string()))
            .map(|(data, _)| data.len() as u64)
            .ok_or_else(|| format!("Object not found: {}/{}", namespace, key))
    }
}

// =============================================================================
// ObjectFabric — high-level API
// =============================================================================

/// High-level object storage with namespace layout and lifecycle management.
pub struct ObjectFabric {
    pub config: ObjectFabricConfig,
    backend: Box<dyn ObjectBackend>,
}

impl ObjectFabric {
    pub fn new(config: ObjectFabricConfig, backend: Box<dyn ObjectBackend>) -> Self {
        Self { config, backend }
    }

    /// Create with in-memory backend (developer mode).
    pub fn in_memory() -> Self {
        Self::new(
            ObjectFabricConfig::default(),
            Box::new(InMemoryObjectBackend::new()),
        )
    }

    /// Build the full key for an object within a tenant/container.
    pub fn build_key(tenant_id: &str, container_id: &str, category: &str, object_id: &str) -> String {
        format!("tenants/{}/containers/{}/{}/{}", tenant_id, container_id, category, object_id)
    }

    /// Store a memory object payload.
    pub fn put_object(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        category: &str,
        object_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        if self.config.max_object_bytes > 0 && data.len() as u64 > self.config.max_object_bytes {
            return Err(format!(
                "Object too large: {} bytes > {} max",
                data.len(), self.config.max_object_bytes
            ));
        }

        let key = Self::build_key(tenant_id, container_id, category, object_id);
        let meta = ObjectMeta {
            content_type: content_type.to_string(),
            storage_tier: self.config.default_tier,
            tags: HashMap::new(),
        };

        self.backend.put(&self.config.root_prefix, &key, data, &meta)
    }

    /// Retrieve a memory object payload.
    pub fn get_object(
        &self,
        tenant_id: &str,
        container_id: &str,
        category: &str,
        object_id: &str,
    ) -> Result<(Vec<u8>, ObjectRef), String> {
        let key = Self::build_key(tenant_id, container_id, category, object_id);
        self.backend.get(&self.config.root_prefix, &key)
    }

    /// Check if an object exists.
    pub fn exists(
        &self,
        tenant_id: &str,
        container_id: &str,
        category: &str,
        object_id: &str,
    ) -> bool {
        let key = Self::build_key(tenant_id, container_id, category, object_id);
        self.backend.exists(&self.config.root_prefix, &key)
    }

    /// Delete an object.
    pub fn delete_object(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        category: &str,
        object_id: &str,
    ) -> Result<(), String> {
        let key = Self::build_key(tenant_id, container_id, category, object_id);
        self.backend.delete(&self.config.root_prefix, &key)
    }

    /// List objects under a category prefix.
    pub fn list_objects(
        &self,
        tenant_id: &str,
        container_id: &str,
        category: &str,
        limit: usize,
    ) -> Result<Vec<ObjectRef>, String> {
        let prefix = format!("tenants/{}/containers/{}/{}/", tenant_id, container_id, category);
        self.backend.list(&self.config.root_prefix, &prefix, limit)
    }

    /// Store a trace span as a JSON object.
    pub fn put_trace_span(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        trace_id: &str,
        span_index: u32,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/span_{:06}.json", trace_id, span_index);
        self.put_object(tenant_id, container_id, "traces", &object_id, data, "application/json")
    }

    /// Store a page (range window) as JSON.
    pub fn put_page(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        page_code: &str,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}.json", page_code);
        self.put_object(tenant_id, container_id, "pages", &object_id, data, "application/json")
    }

    /// Store an artifact (uploaded document, etc.).
    pub fn put_artifact(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        artifact_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "artifacts", artifact_id, data, content_type)
    }

    /// Store a snapshot.
    pub fn put_snapshot(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        snapshot_id: &str,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "snapshots", snapshot_id, data, "application/octet-stream")
    }

    // =========================================================================
    // Multimodal Storage Helpers
    // =========================================================================

    /// Store an image (camera capture, screenshot, render, satellite, medical).
    pub fn put_image(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        image_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "images", image_id, data, content_type)
    }

    /// Store a video segment or recording.
    pub fn put_video(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        video_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "video", video_id, data, content_type)
    }

    /// Store an audio segment (microphone, speech, generated audio).
    pub fn put_audio(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        audio_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "audio", audio_id, data, content_type)
    }

    /// Store sensor data (accelerometer, gyroscope, LiDAR, GPS, temperature, etc.).
    pub fn put_sensor_data(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        sensor_id: &str,
        timestamp: i64,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/{}.bin", sensor_id, timestamp);
        self.put_object(tenant_id, container_id, "sensors", &object_id, data, content_type)
    }

    /// Store a point cloud (LiDAR scan, depth map, 3D reconstruction).
    pub fn put_point_cloud(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        cloud_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "point_clouds", cloud_id, data, content_type)
    }

    /// Store neural network model weights (safetensors, ONNX, PyTorch, TF).
    pub fn put_model_weights(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        model_id: &str,
        version: u32,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/v{}/weights", model_id, version);
        self.put_object(tenant_id, container_id, "models", &object_id, data, content_type)
    }

    /// Store model configuration / hyperparameters.
    pub fn put_model_config(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        model_id: &str,
        version: u32,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/v{}/config.json", model_id, version);
        self.put_object(tenant_id, container_id, "models", &object_id, data, "application/json")
    }

    /// Store a dataset shard (training data, evaluation data).
    pub fn put_dataset_shard(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        dataset_id: &str,
        version: u32,
        shard_index: u32,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/v{}/part_{:06}", dataset_id, version, shard_index);
        self.put_object(tenant_id, container_id, "datasets", &object_id, data, content_type)
    }

    /// Store gradient snapshot from a training run.
    pub fn put_gradient(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        run_id: &str,
        step: u64,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/step_{:08}.bin", run_id, step);
        self.put_object(tenant_id, container_id, "gradients", &object_id, data, "application/octet-stream")
    }

    /// Store extracted feature map / feature vector.
    pub fn put_feature(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        feature_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "features", feature_id, data, content_type)
    }

    /// Store perception pipeline output (bounding boxes, segmentation, etc.).
    pub fn put_perception(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        frame_id: &str,
        data: &[u8],
        content_type: &str,
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "perception", frame_id, data, content_type)
    }

    /// Store actuation command log.
    pub fn put_actuation(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        command_id: &str,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        self.put_object(tenant_id, container_id, "actuation", command_id, data, "application/json")
    }

    // =========================================================================
    // Chunked Upload (multipart for large files)
    // =========================================================================

    /// Store a single part of a chunked upload.
    pub fn put_upload_part(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        upload_id: &str,
        part_index: u32,
        data: &[u8],
    ) -> Result<ObjectRef, String> {
        let object_id = format!("{}/part_{:06}", upload_id, part_index);
        self.put_object(tenant_id, container_id, "multipart", &object_id, data, "application/octet-stream")
    }

    /// Complete a chunked upload by concatenating parts into a final object.
    /// Returns the completed ObjectRef.
    pub fn complete_chunked_upload(
        &mut self,
        tenant_id: &str,
        container_id: &str,
        upload_id: &str,
        target_category: &str,
        target_id: &str,
        content_type: &str,
        part_count: u32,
    ) -> Result<ObjectRef, String> {
        let mut assembled = Vec::new();
        for i in 0..part_count {
            let part_key = format!("{}/part_{:06}", upload_id, i);
            let (data, _) = self.get_object(tenant_id, container_id, "multipart", &part_key)?;
            assembled.extend_from_slice(&data);
        }

        let result = self.put_object(tenant_id, container_id, target_category, target_id, &assembled, content_type)?;

        // Cleanup parts
        for i in 0..part_count {
            let part_key = format!("{}/part_{:06}", upload_id, i);
            let _ = self.delete_object(tenant_id, container_id, "multipart", &part_key);
        }

        Ok(result)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_put_get() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta {
            content_type: "text/plain".to_string(),
            ..Default::default()
        };

        let obj_ref = backend.put("ns", "key1", b"hello world", &meta).unwrap();
        assert_eq!(obj_ref.size_bytes, 11);
        assert_eq!(obj_ref.namespace, "ns");
        assert_eq!(obj_ref.key, "key1");
        assert!(obj_ref.version.is_some());

        let (data, ref2) = backend.get("ns", "key1").unwrap();
        assert_eq!(data, b"hello world");
        assert_eq!(ref2.content_hash, obj_ref.content_hash);
    }

    #[test]
    fn test_in_memory_head() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta::default();
        backend.put("ns", "k", b"data", &meta).unwrap();

        let head = backend.head("ns", "k").unwrap();
        assert_eq!(head.size_bytes, 4);
    }

    #[test]
    fn test_in_memory_delete() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta::default();
        backend.put("ns", "k", b"data", &meta).unwrap();
        assert!(backend.exists("ns", "k"));

        backend.delete("ns", "k").unwrap();
        assert!(!backend.exists("ns", "k"));
    }

    #[test]
    fn test_in_memory_list() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta::default();
        backend.put("ns", "dir/a.txt", b"a", &meta).unwrap();
        backend.put("ns", "dir/b.txt", b"b", &meta).unwrap();
        backend.put("ns", "other/c.txt", b"c", &meta).unwrap();

        let results = backend.list("ns", "dir/", 100).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, "dir/a.txt");
        assert_eq!(results[1].key, "dir/b.txt");
    }

    #[test]
    fn test_in_memory_versioning() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta::default();
        let v1 = backend.put("ns", "k", b"v1", &meta).unwrap();
        let v2 = backend.put("ns", "k", b"v2", &meta).unwrap();
        assert_ne!(v1.version, v2.version);

        let (data, _) = backend.get("ns", "k").unwrap();
        assert_eq!(data, b"v2"); // latest version
    }

    #[test]
    fn test_object_fabric_key_building() {
        let key = ObjectFabric::build_key("acme", "cont_A", "objects", "obj_001");
        assert_eq!(key, "tenants/acme/containers/cont_A/objects/obj_001");
    }

    #[test]
    fn test_object_fabric_roundtrip() {
        let mut fabric = ObjectFabric::in_memory();

        let obj = fabric.put_object("acme", "cont_A", "objects", "obj_001", b"payload data", "text/plain").unwrap();
        assert_eq!(obj.size_bytes, 12);

        assert!(fabric.exists("acme", "cont_A", "objects", "obj_001"));

        let (data, _) = fabric.get_object("acme", "cont_A", "objects", "obj_001").unwrap();
        assert_eq!(data, b"payload data");

        fabric.delete_object("acme", "cont_A", "objects", "obj_001").unwrap();
        assert!(!fabric.exists("acme", "cont_A", "objects", "obj_001"));
    }

    #[test]
    fn test_object_fabric_max_size() {
        let config = ObjectFabricConfig {
            max_object_bytes: 10,
            ..Default::default()
        };
        let mut fabric = ObjectFabric::new(config, Box::new(InMemoryObjectBackend::new()));
        let result = fabric.put_object("t", "c", "objects", "big", &[0u8; 100], "bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_object_fabric_traces() {
        let mut fabric = ObjectFabric::in_memory();
        fabric.put_trace_span("acme", "cont_A", "trace_001", 0, b"{\"span\":0}").unwrap();
        fabric.put_trace_span("acme", "cont_A", "trace_001", 1, b"{\"span\":1}").unwrap();

        let traces = fabric.list_objects("acme", "cont_A", "traces", 100).unwrap();
        assert_eq!(traces.len(), 2);
    }

    #[test]
    fn test_object_fabric_pages() {
        let mut fabric = ObjectFabric::in_memory();
        fabric.put_page("acme", "cont_A", "ns_test/000001", b"{\"page\":1}").unwrap();
        assert!(fabric.exists("acme", "cont_A", "pages", "ns_test/000001.json"));
    }

    #[test]
    fn test_in_memory_stats() {
        let mut backend = InMemoryObjectBackend::new();
        let meta = ObjectMeta::default();
        backend.put("ns", "a", b"hello", &meta).unwrap();
        backend.put("ns", "b", b"world!", &meta).unwrap();
        assert_eq!(backend.object_count(), 2);
        assert_eq!(backend.total_bytes(), 11);
    }

    #[test]
    fn test_not_found_errors() {
        let backend = InMemoryObjectBackend::new();
        assert!(backend.get("ns", "nope").is_err());
        assert!(backend.head("ns", "nope").is_err());
        assert!(backend.size("ns", "nope").is_err());
    }

    // ── Multimodal tests ──

    #[test]
    fn test_put_image() {
        let mut f = ObjectFabric::in_memory();
        let fake_png = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
        f.put_image("t", "c", "cam_001.png", &fake_png, "image/png").unwrap();
        assert!(f.exists("t", "c", "images", "cam_001.png"));
    }

    #[test]
    fn test_put_video() {
        let mut f = ObjectFabric::in_memory();
        f.put_video("t", "c", "recording_001.mp4", b"fake-video", "video/mp4").unwrap();
        assert!(f.exists("t", "c", "video", "recording_001.mp4"));
    }

    #[test]
    fn test_put_audio() {
        let mut f = ObjectFabric::in_memory();
        f.put_audio("t", "c", "mic_001.wav", b"fake-audio", "audio/wav").unwrap();
        assert!(f.exists("t", "c", "audio", "mic_001.wav"));
    }

    #[test]
    fn test_put_sensor_data() {
        let mut f = ObjectFabric::in_memory();
        let accel_data = vec![0u8; 600]; // 100 samples * 3 axes * 2 bytes
        f.put_sensor_data("t", "c", "imu_front", 1700000000, &accel_data, "application/x-sensor").unwrap();
        assert!(f.exists("t", "c", "sensors", "imu_front/1700000000.bin"));
    }

    #[test]
    fn test_put_point_cloud() {
        let mut f = ObjectFabric::in_memory();
        f.put_point_cloud("t", "c", "lidar_scan_001.pcd", b"pcd-data", "application/x-pcd").unwrap();
        assert!(f.exists("t", "c", "point_clouds", "lidar_scan_001.pcd"));
    }

    #[test]
    fn test_put_model_weights_and_config() {
        let mut f = ObjectFabric::in_memory();
        let weights = vec![0u8; 1024]; // fake model weights
        f.put_model_weights("t", "c", "resnet50", 3, &weights, "application/x-safetensors").unwrap();
        f.put_model_config("t", "c", "resnet50", 3, b"{\"layers\":50}").unwrap();

        assert!(f.exists("t", "c", "models", "resnet50/v3/weights"));
        assert!(f.exists("t", "c", "models", "resnet50/v3/config.json"));

        let models = f.list_objects("t", "c", "models", 100).unwrap();
        assert_eq!(models.len(), 2);
    }

    #[test]
    fn test_put_dataset_shards() {
        let mut f = ObjectFabric::in_memory();
        for i in 0..3 {
            f.put_dataset_shard("t", "c", "imagenet", 1, i, &[0u8; 100], "application/x-parquet").unwrap();
        }
        let shards = f.list_objects("t", "c", "datasets", 100).unwrap();
        assert_eq!(shards.len(), 3);
    }

    #[test]
    fn test_put_gradient() {
        let mut f = ObjectFabric::in_memory();
        f.put_gradient("t", "c", "run_001", 500, &[0u8; 256]).unwrap();
        assert!(f.exists("t", "c", "gradients", "run_001/step_00000500.bin"));
    }

    #[test]
    fn test_put_perception_and_actuation() {
        let mut f = ObjectFabric::in_memory();
        f.put_perception("t", "c", "frame_001", b"{\"boxes\":[]}", "application/json").unwrap();
        f.put_actuation("t", "c", "cmd_001", b"{\"servo\":90}").unwrap();
        assert!(f.exists("t", "c", "perception", "frame_001"));
        assert!(f.exists("t", "c", "actuation", "cmd_001"));
    }

    #[test]
    fn test_chunked_upload() {
        let mut f = ObjectFabric::in_memory();

        // Upload 3 parts
        f.put_upload_part("t", "c", "upload_001", 0, b"AAAA").unwrap();
        f.put_upload_part("t", "c", "upload_001", 1, b"BBBB").unwrap();
        f.put_upload_part("t", "c", "upload_001", 2, b"CCCC").unwrap();

        // Complete upload → assemble into target
        let result = f.complete_chunked_upload(
            "t", "c", "upload_001",
            "video", "big_recording.mp4",
            "video/mp4", 3,
        ).unwrap();

        assert_eq!(result.size_bytes, 12); // 4+4+4
        assert!(f.exists("t", "c", "video", "big_recording.mp4"));

        let (data, _) = f.get_object("t", "c", "video", "big_recording.mp4").unwrap();
        assert_eq!(&data, b"AAAABBBBCCCC");

        // Parts should be cleaned up
        assert!(!f.exists("t", "c", "multipart", "upload_001/part_000000"));
    }
}
