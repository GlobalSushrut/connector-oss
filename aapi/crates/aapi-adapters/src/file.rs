//! File system adapter

use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use aapi_core::types::EffectBucket;
use aapi_core::Vakya;

use crate::effect::{CapturedEffect, EffectBuilder, ReversalMethod, StateSnapshot};
use crate::error::{AdapterError, AdapterResult};
use crate::traits::{Adapter, ActionDescriptor, ExecutionContext, ExecutionResult, HealthStatus};

/// File system adapter for file operations
pub struct FileAdapter {
    /// Base directory for file operations (sandboxing)
    base_dir: Option<PathBuf>,
    /// Maximum file size for read operations
    max_read_size: usize,
    /// Whether to capture full content in effects
    capture_content: bool,
}

impl Default for FileAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FileAdapter {
    pub fn new() -> Self {
        Self {
            base_dir: None,
            max_read_size: 10 * 1024 * 1024, // 10MB
            capture_content: true,
        }
    }

    pub fn with_base_dir(mut self, base_dir: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(base_dir.into());
        self
    }

    pub fn with_max_read_size(mut self, size: usize) -> Self {
        self.max_read_size = size;
        self
    }

    pub fn without_content_capture(mut self) -> Self {
        self.capture_content = false;
        self
    }

    /// Resolve and validate a file path
    fn resolve_path(&self, resource_id: &str) -> AdapterResult<PathBuf> {
        // Remove file: prefix if present
        let path_str = resource_id
            .strip_prefix("file:")
            .or_else(|| resource_id.strip_prefix("file://"))
            .unwrap_or(resource_id);

        let path = PathBuf::from(path_str);

        // If base_dir is set, ensure path is within it
        if let Some(ref base) = self.base_dir {
            let canonical_base = base.canonicalize().unwrap_or_else(|_| base.clone());
            
            // For new files, check parent directory
            let check_path = if path.exists() {
                path.canonicalize().map_err(AdapterError::Io)?
            } else {
                path.parent()
                    .map(|p| p.canonicalize().unwrap_or_else(|_| p.to_path_buf()))
                    .unwrap_or_else(|| PathBuf::from("."))
            };

            if !check_path.starts_with(&canonical_base) {
                return Err(AdapterError::PermissionDenied(format!(
                    "Path {} is outside base directory",
                    path.display()
                )));
            }
        }

        Ok(path)
    }

    /// Capture state of a file
    async fn capture_state(&self, path: &PathBuf) -> StateSnapshot {
        if !path.exists() {
            return StateSnapshot::not_exists();
        }

        match fs::metadata(path).await {
            Ok(metadata) => {
                let size = metadata.len();
                
                // Read content if small enough and capture is enabled
                let content = if self.capture_content && size <= self.max_read_size as u64 {
                    match fs::read(path).await {
                        Ok(data) => {
                            // Try to parse as JSON, otherwise store as base64
                            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                                Some(json)
                            } else {
                                Some(serde_json::json!({
                                    "_type": "binary",
                                    "_encoding": "base64",
                                    "_data": base64::Engine::encode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &data
                                    )
                                }))
                            }
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                };

                let mut snapshot = if let Some(ref content) = content {
                    StateSnapshot::from_json(content)
                } else {
                    // Just compute hash from file
                    match fs::read(path).await {
                        Ok(data) => StateSnapshot::from_bytes(&data),
                        Err(_) => StateSnapshot::from_hash("ERROR", 0),
                    }
                };

                snapshot.size = Some(size);
                snapshot.properties.insert(
                    "modified".to_string(),
                    serde_json::json!(metadata.modified()
                        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
                        .unwrap_or_default()),
                );

                snapshot
            }
            Err(_) => StateSnapshot::not_exists(),
        }
    }

    /// Execute file.read action
    async fn execute_read(
        &self,
        vakya: &Vakya,
        path: &PathBuf,
        _context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let start = std::time::Instant::now();

        // Check file exists
        if !path.exists() {
            return Err(AdapterError::NotFound(format!("File not found: {}", path.display())));
        }

        // Check size
        let metadata = fs::metadata(path).await?;
        if metadata.len() > self.max_read_size as u64 {
            return Err(AdapterError::InvalidInput(format!(
                "File too large: {} bytes (max {})",
                metadata.len(),
                self.max_read_size
            )));
        }

        // Read file
        let content = fs::read(path).await?;
        
        // Capture effect (read is non-mutating)
        let state = self.capture_state(path).await;
        let effect = EffectBuilder::new(
            vakya.vakya_id.0.clone(),
            EffectBucket::Read,
            vakya.v2_karma.rid.0.clone(),
        )
        .target_type("file")
        .after(state)
        .build();

        let duration_ms = start.elapsed().as_millis() as u64;

        // Try to return as JSON if possible
        let data = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&content) {
            json
        } else {
            serde_json::json!({
                "content_type": "application/octet-stream",
                "size": content.len(),
                "content_base64": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &content
                )
            })
        };

        Ok(ExecutionResult::success(data, vec![effect], duration_ms))
    }

    /// Execute file.write action
    async fn execute_write(
        &self,
        vakya: &Vakya,
        path: &PathBuf,
        context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let start = std::time::Instant::now();

        // Capture before state
        let before = self.capture_state(path).await;

        // Get content from body
        let content = self.extract_content(&vakya.body)?;

        if context.dry_run {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ExecutionResult::success(
                serde_json::json!({"dry_run": true, "would_write": content.len()}),
                vec![],
                duration_ms,
            ));
        }

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write file
        fs::write(path, &content).await?;

        // Capture after state
        let after = self.capture_state(path).await;

        // Build effect with reversal instructions
        let effect = EffectBuilder::new(
            vakya.vakya_id.0.clone(),
            if before.hash == "NOT_EXISTS" { EffectBucket::Create } else { EffectBucket::Update },
            vakya.v2_karma.rid.0.clone(),
        )
        .target_type("file")
        .before(before.clone())
        .after(after)
        .reversible(
            ReversalMethod::RestoreState,
            serde_json::json!({
                "path": path.to_string_lossy(),
                "before_hash": before.hash,
                "before_content": before.content,
            }),
        )
        .build();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecutionResult::success(
            serde_json::json!({
                "path": path.to_string_lossy(),
                "size": content.len(),
                "created": before.hash == "NOT_EXISTS",
            }),
            vec![effect],
            duration_ms,
        ))
    }

    /// Execute file.delete action
    async fn execute_delete(
        &self,
        vakya: &Vakya,
        path: &PathBuf,
        context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let start = std::time::Instant::now();

        if !path.exists() {
            return Err(AdapterError::NotFound(format!("File not found: {}", path.display())));
        }

        // Capture before state
        let before = self.capture_state(path).await;

        if context.dry_run {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ExecutionResult::success(
                serde_json::json!({"dry_run": true, "would_delete": path.to_string_lossy()}),
                vec![],
                duration_ms,
            ));
        }

        // Delete file
        fs::remove_file(path).await?;

        // Capture after state
        let after = StateSnapshot::not_exists();

        // Build effect with reversal instructions
        let effect = EffectBuilder::new(
            vakya.vakya_id.0.clone(),
            EffectBucket::Delete,
            vakya.v2_karma.rid.0.clone(),
        )
        .target_type("file")
        .before(before.clone())
        .after(after)
        .reversible(
            ReversalMethod::Recreate,
            serde_json::json!({
                "path": path.to_string_lossy(),
                "before_content": before.content,
            }),
        )
        .build();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecutionResult::success(
            serde_json::json!({
                "path": path.to_string_lossy(),
                "deleted": true,
            }),
            vec![effect],
            duration_ms,
        ))
    }

    /// Execute file.list action
    async fn execute_list(
        &self,
        vakya: &Vakya,
        path: &PathBuf,
        _context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let start = std::time::Instant::now();

        if !path.exists() {
            return Err(AdapterError::NotFound(format!("Directory not found: {}", path.display())));
        }

        if !path.is_dir() {
            return Err(AdapterError::InvalidInput(format!("Not a directory: {}", path.display())));
        }

        let mut entries = Vec::new();
        let mut dir = fs::read_dir(path).await?;

        while let Some(entry) = dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            entries.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "path": entry.path().to_string_lossy(),
                "is_dir": metadata.is_dir(),
                "is_file": metadata.is_file(),
                "size": if metadata.is_file() { Some(metadata.len()) } else { None },
            }));
        }

        let effect = EffectBuilder::new(
            vakya.vakya_id.0.clone(),
            EffectBucket::Read,
            vakya.v2_karma.rid.0.clone(),
        )
        .target_type("directory")
        .build();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecutionResult::success(
            serde_json::json!({
                "path": path.to_string_lossy(),
                "entries": entries,
                "count": entries.len(),
            }),
            vec![effect],
            duration_ms,
        ))
    }

    /// Extract content from VĀKYA body
    fn extract_content(&self, body: &serde_json::Value) -> AdapterResult<Vec<u8>> {
        // Check for direct content
        if let Some(content) = body.get("content") {
            if let Some(s) = content.as_str() {
                return Ok(s.as_bytes().to_vec());
            }
            // If it's JSON, serialize it
            return Ok(serde_json::to_vec_pretty(content)?);
        }

        // Check for base64 content
        if let Some(b64) = body.get("content_base64").and_then(|v| v.as_str()) {
            use base64::Engine;
            return base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| AdapterError::InvalidInput(format!("Invalid base64: {}", e)));
        }

        // Use entire body as content
        Ok(serde_json::to_vec_pretty(body)?)
    }
}

#[async_trait]
impl Adapter for FileAdapter {
    fn domain(&self) -> &str {
        "file"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec![
            "file.read",
            "file.write",
            "file.delete",
            "file.list",
            "file.exists",
            "file.metadata",
        ]
    }

    async fn execute(&self, vakya: &Vakya, context: &ExecutionContext) -> AdapterResult<ExecutionResult> {
        let path = self.resolve_path(&vakya.v2_karma.rid.0)?;
        let action = &vakya.v3_kriya.action;

        debug!(action = %action, path = %path.display(), "Executing file action");

        match action.as_str() {
            "file.read" => self.execute_read(vakya, &path, context).await,
            "file.write" => self.execute_write(vakya, &path, context).await,
            "file.delete" => self.execute_delete(vakya, &path, context).await,
            "file.list" => self.execute_list(vakya, &path, context).await,
            "file.exists" => {
                let exists = path.exists();
                Ok(ExecutionResult::success(
                    serde_json::json!({"exists": exists}),
                    vec![],
                    0,
                ))
            }
            "file.metadata" => {
                if !path.exists() {
                    return Err(AdapterError::NotFound(format!("File not found: {}", path.display())));
                }
                let metadata = fs::metadata(&path).await?;
                Ok(ExecutionResult::success(
                    serde_json::json!({
                        "size": metadata.len(),
                        "is_file": metadata.is_file(),
                        "is_dir": metadata.is_dir(),
                        "readonly": metadata.permissions().readonly(),
                    }),
                    vec![],
                    0,
                ))
            }
            _ => Err(AdapterError::UnsupportedAction(action.clone())),
        }
    }

    fn can_rollback(&self, action: &str) -> bool {
        matches!(action, "file.write" | "file.delete")
    }

    async fn rollback(&self, effect: &CapturedEffect) -> AdapterResult<()> {
        let reversal = effect.reversal.as_ref()
            .ok_or_else(|| AdapterError::RollbackFailed("No reversal instructions".to_string()))?;

        let path_str = reversal.data.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdapterError::RollbackFailed("Missing path in reversal".to_string()))?;

        let path = PathBuf::from(path_str);

        match reversal.method {
            ReversalMethod::RestoreState | ReversalMethod::Recreate => {
                // Restore from before content
                if let Some(content) = reversal.data.get("before_content") {
                    if content.is_null() || content.get("_type").and_then(|v| v.as_str()) == Some("NOT_EXISTS") {
                        // File didn't exist before, delete it
                        if path.exists() {
                            fs::remove_file(&path).await?;
                        }
                    } else {
                        // Restore content
                        let bytes = if let Some(data) = content.get("_data").and_then(|v| v.as_str()) {
                            use base64::Engine;
                            base64::engine::general_purpose::STANDARD
                                .decode(data)
                                .map_err(|e| AdapterError::RollbackFailed(e.to_string()))?
                        } else {
                            serde_json::to_vec_pretty(content)?
                        };
                        fs::write(&path, bytes).await?;
                    }
                }
            }
            ReversalMethod::Delete => {
                if path.exists() {
                    fs::remove_file(&path).await?;
                }
            }
            _ => {
                return Err(AdapterError::RollbackFailed(format!(
                    "Unsupported reversal method: {:?}",
                    reversal.method
                )));
            }
        }

        info!(path = %path.display(), "Rollback completed");
        Ok(())
    }

    async fn health_check(&self) -> AdapterResult<HealthStatus> {
        let start = std::time::Instant::now();

        // Check base directory if set
        if let Some(ref base) = self.base_dir {
            if !base.exists() {
                return Ok(HealthStatus::unhealthy(format!(
                    "Base directory does not exist: {}",
                    base.display()
                )));
            }
        }

        Ok(HealthStatus::healthy().with_latency(start.elapsed().as_millis() as u64))
    }
}

/// Get action descriptors for the file adapter
pub fn file_action_descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new("file.read", "Read file contents")
            .with_effect(EffectBucket::Read)
            .idempotent(),
        ActionDescriptor::new("file.write", "Write content to file")
            .with_effect(EffectBucket::Update)
            .reversible(),
        ActionDescriptor::new("file.delete", "Delete a file")
            .with_effect(EffectBucket::Delete)
            .reversible(),
        ActionDescriptor::new("file.list", "List directory contents")
            .with_effect(EffectBucket::Read)
            .idempotent(),
        ActionDescriptor::new("file.exists", "Check if file exists")
            .with_effect(EffectBucket::None)
            .idempotent(),
        ActionDescriptor::new("file.metadata", "Get file metadata")
            .with_effect(EffectBucket::Read)
            .idempotent(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aapi_core::*;
    use tempfile::TempDir;

    fn create_test_vakya(action: &str, resource: &str, body: serde_json::Value) -> Vakya {
        Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new("user:test"),
                role: None,
                realm: None,
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new(resource),
                kind: Some("file".to_string()),
                ns: None,
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new("file", action.split('.').last().unwrap_or(action)))
            .adhikarana(Adhikarana {
                cap: CapabilityRef::Reference { cap_ref: "cap:test".to_string() },
                policy_ref: None,
                ttl: Some(TtlConstraint {
                    expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                    max_duration_ms: None,
                }),
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec![],
                context: None,
            })
            .body(body)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_file_write_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let adapter = FileAdapter::new().with_base_dir(temp_dir.path());
        let context = ExecutionContext::default();

        let file_path = temp_dir.path().join("test.txt");
        let resource = format!("file:{}", file_path.display());

        // Write
        let write_vakya = create_test_vakya(
            "file.write",
            &resource,
            serde_json::json!({"content": "Hello, World!"}),
        );
        let write_result = adapter.execute(&write_vakya, &context).await.unwrap();
        assert!(write_result.success);
        assert_eq!(write_result.effects.len(), 1);

        // Read
        let read_vakya = create_test_vakya("file.read", &resource, serde_json::json!({}));
        let read_result = adapter.execute(&read_vakya, &context).await.unwrap();
        assert!(read_result.success);
    }

    #[tokio::test]
    async fn test_file_delete() {
        let temp_dir = TempDir::new().unwrap();
        let adapter = FileAdapter::new().with_base_dir(temp_dir.path());
        let context = ExecutionContext::default();

        let file_path = temp_dir.path().join("to_delete.txt");
        std::fs::write(&file_path, "delete me").unwrap();

        let resource = format!("file:{}", file_path.display());
        let vakya = create_test_vakya("file.delete", &resource, serde_json::json!({}));
        
        let result = adapter.execute(&vakya, &context).await.unwrap();
        assert!(result.success);
        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn test_path_sandboxing() {
        let temp_dir = TempDir::new().unwrap();
        let adapter = FileAdapter::new().with_base_dir(temp_dir.path());

        // Try to access file outside base directory
        let result = adapter.resolve_path("/etc/passwd");
        assert!(result.is_err());
    }
}
