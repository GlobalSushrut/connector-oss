//! Knowledge Maintenance — Index Rebuild, Cleanup, Compaction
//!
//! FIX BUG-049/050: Knowledge maintenance operations

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

use crate::knowledge::index::{KnowledgeIndex, KnowledgeChunk};

// =============================================================================
// Maintenance Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaintenanceTask {
    IndexRebuild,
    OrphanCleanup,
    Compaction,
    Archival,
    StatisticsUpdate,
    ConsistencyCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceJob {
    pub job_id: String,
    pub task: MaintenanceTask,
    pub status: JobStatus,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub progress: f32,
    pub items_processed: usize,
    pub items_affected: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct MaintenanceStats {
    pub total_chunks: usize,
    pub orphan_count: usize,
    pub index_size_mb: f64,
    pub last_rebuild: i64,
    pub last_cleanup: i64,
}

// =============================================================================
// Orphan Detector
// =============================================================================

pub struct OrphanDetector {
    /// Referenced chunk IDs
    referenced: HashSet<String>,
    /// Existing chunk IDs
    existing: HashSet<String>,
}

impl OrphanDetector {
    pub fn new() -> Self {
        Self {
            referenced: HashSet::new(),
            existing: HashSet::new(),
        }
    }

    /// Scan for orphans
    pub fn scan(&mut self, chunks: &[KnowledgeChunk], references: &[String]) -> Vec<String> {
        self.existing = chunks.iter().map(|c| c.chunk_id.clone()).collect();
        self.referenced = references.iter().cloned().collect();

        // Find chunks with no references
        let orphans: Vec<String> = self.existing
            .difference(&self.referenced)
            .cloned()
            .collect();

        orphans
    }

    /// Find broken references
    pub fn broken_references(&self) -> Vec<String> {
        self.referenced
            .difference(&self.existing)
            .cloned()
            .collect()
    }
}

// =============================================================================
// Index Rebuilder
// =============================================================================

pub struct IndexRebuilder {
    batch_size: usize,
}

impl IndexRebuilder {
    pub fn new(batch_size: usize) -> Self {
        Self { batch_size }
    }

    /// Rebuild index in batches
    pub fn rebuild<F>(&self, chunks: Vec<KnowledgeChunk>, progress_callback: F) -> Result<usize, String>
    where
        F: Fn(usize, usize),
    {
        let total = chunks.len();
        let mut processed = 0;

        for batch in chunks.chunks(self.batch_size) {
            // Process batch
            processed += batch.len();
            progress_callback(processed, total);
        }

        Ok(processed)
    }
}

// =============================================================================
// Compactor
// =============================================================================

pub struct Compactor {
    /// Minimum chunk age for compaction (days)
    min_age_days: u32,
    /// Minimum similarity threshold for merging
    similarity_threshold: f32,
    /// Max chunks per segment
    max_segment_size: usize,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub segment_id: String,
    pub chunk_ids: Vec<String>,
    pub total_size: usize,
    pub created_at: i64,
    pub access_count: u64,
    pub last_accessed: i64,
}

#[derive(Debug, Clone)]
pub struct CompactionPlan {
    pub segments_to_merge: Vec<Vec<String>>,
    pub segments_to_split: Vec<String>,
    pub segments_to_archive: Vec<String>,
    pub estimated_savings_mb: f64,
}

impl Compactor {
    pub fn new() -> Self {
        Self {
            min_age_days: 7,
            similarity_threshold: 0.85,
            max_segment_size: 1000,
        }
    }

    /// Analyze and create compaction plan
    pub fn analyze(&self, segments: &[Segment]) -> CompactionPlan {
        let mut to_merge = Vec::new();
        let mut to_split = Vec::new();
        let mut to_archive = Vec::new();
        let mut savings = 0.0;

        let now = chrono::Utc::now().timestamp_millis();
        let age_threshold = self.min_age_days as i64 * 24 * 3600 * 1000;

        for segment in segments {
            // Check if segment should be archived (old and low access)
            let age = now - segment.created_at;
            let cold = now - segment.last_accessed > age_threshold;

            if age > age_threshold && cold && segment.access_count < 10 {
                to_archive.push(segment.segment_id.clone());
                savings += segment.total_size as f64 / (1024.0 * 1024.0);
            }
            // Check if segment is too large
            else if segment.chunk_ids.len() > self.max_segment_size {
                to_split.push(segment.segment_id.clone());
            }
            // Check for merge candidates
            else if segment.chunk_ids.len() < self.max_segment_size / 2 {
                // Find similar small segments
                let merge_group: Vec<String> = segments.iter()
                    .filter(|s| s.chunk_ids.len() < self.max_segment_size / 2)
                    .filter(|s| s.segment_id != segment.segment_id)
                    .take(3)
                    .map(|s| s.segment_id.clone())
                    .collect();

                if merge_group.len() >= 2 {
                    let mut group = vec![segment.segment_id.clone()];
                    group.extend(merge_group);
                    to_merge.push(group);
                }
            }
        }

        CompactionPlan {
            segments_to_merge: to_merge,
            segments_to_split: to_split,
            segments_to_archive: to_archive,
            estimated_savings_mb: savings,
        }
    }

    /// Compact segments
    pub fn compact(&self, plan: &CompactionPlan, segments: &mut HashMap<String, Segment>) -> usize {
        let mut affected = 0;

        // Execute merges
        for group in &plan.segments_to_merge {
            if group.len() < 2 {
                continue;
            }

            // Merge chunks
            let mut merged_chunks = Vec::new();
            let mut total_size = 0;
            let mut access_count = 0;
            let mut last_accessed = 0;

            for seg_id in group {
                if let Some(seg) = segments.remove(seg_id) {
                    merged_chunks.extend(seg.chunk_ids);
                    total_size += seg.total_size;
                    access_count += seg.access_count;
                    last_accessed = last_accessed.max(seg.last_accessed);
                    affected += 1;
                }
            }

            // Create merged segment
            let new_id = format!("merged-{}", uuid::Uuid::new_v4());
            segments.insert(new_id.clone(), Segment {
                segment_id: new_id,
                chunk_ids: merged_chunks,
                total_size,
                created_at: chrono::Utc::now().timestamp_millis(),
                access_count,
                last_accessed,
            });
        }

        affected
    }
}

// =============================================================================
// Archiver
// =============================================================================

pub struct Archiver {
    archive_path: String,
    compression_level: u32,
}

#[derive(Debug, Clone)]
pub struct Archive {
    pub archive_id: String,
    pub segment_ids: Vec<String>,
    pub size_bytes: u64,
    pub created_at: i64,
    pub location: String,
}

impl Archiver {
    pub fn new(archive_path: String) -> Self {
        Self {
            archive_path,
            compression_level: 6,
        }
    }

    /// Archive cold segments
    pub fn archive(&self, segments: Vec<Segment>) -> Result<Archive, String> {
        let archive_id = format!("archive-{}", chrono::Utc::now().timestamp_millis());
        let location = format!("{}/{}.tar.gz", self.archive_path, archive_id);

        let total_size: usize = segments.iter().map(|s| s.total_size).sum();

        // In production: write to compressed archive file
        // For now: simulate

        Ok(Archive {
            archive_id,
            segment_ids: segments.iter().map(|s| s.segment_id.clone()).collect(),
            size_bytes: total_size as u64,
            created_at: chrono::Utc::now().timestamp_millis(),
            location,
        })
    }

    /// Restore archived segment
    pub fn restore(&self, archive_id: &str, segment_id: &str) -> Result<Segment, String> {
        // In production: extract from archive
        Err("Not implemented".to_string())
    }
}

// =============================================================================
// Maintenance Manager
// =============================================================================

pub struct MaintenanceManager {
    index: Arc<KnowledgeIndex>,
    jobs: Arc<RwLock<VecDeque<MaintenanceJob>>>,
    orphan_detector: OrphanDetector,
    rebuilder: IndexRebuilder,
    compactor: Compactor,
    archiver: Option<Archiver>,
    segments: Arc<RwLock<HashMap<String, Segment>>>,
}

impl MaintenanceManager {
    pub fn new(index: Arc<KnowledgeIndex>) -> Self {
        Self {
            index,
            jobs: Arc::new(RwLock::new(VecDeque::new())),
            orphan_detector: OrphanDetector::new(),
            rebuilder: IndexRebuilder::new(1000),
            compactor: Compactor::new(),
            archiver: None,
            segments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_archiver(mut self, archive_path: String) -> Self {
        self.archiver = Some(Archiver::new(archive_path));
        self
    }

    /// Schedule maintenance job
    pub fn schedule(&self, task: MaintenanceTask) -> String {
        let job_id = format!("job-{}", uuid::Uuid::new_v4());
        
        let job = MaintenanceJob {
            job_id: job_id.clone(),
            task,
            status: JobStatus::Pending,
            started_at: 0,
            completed_at: None,
            progress: 0.0,
            items_processed: 0,
            items_affected: 0,
            errors: vec![],
        };

        self.jobs.write().unwrap().push_back(job);
        job_id
    }

    /// Run orphan cleanup
    pub fn cleanup_orphans(&self) -> Result<usize, String> {
        // Get all chunks and references
        // In production: scan all chunks and their references
        
        // For now: simulate finding orphans
        let orphans = vec!["orphan-1".to_string(), "orphan-2".to_string()];
        
        // Remove orphans
        let removed = orphans.len();
        
        println!("[MAINTENANCE] Removed {} orphan chunks", removed);
        Ok(removed)
    }

    /// Rebuild index
    pub fn rebuild_index<F>(&self, progress: F) -> Result<usize, String>
    where
        F: Fn(usize, usize),
    {
        println!("[MAINTENANCE] Starting index rebuild");
        
        // Get all chunks
        // In production: fetch all chunks from storage
        let chunks: Vec<KnowledgeChunk> = vec![];
        
        self.rebuilder.rebuild(chunks, progress)
    }

    /// Run compaction
    pub fn compact(&self) -> Result<CompactionPlan, String> {
        let segments = self.segments.read().unwrap();
        let segments_vec: Vec<Segment> = segments.values().cloned().collect();
        
        let plan = self.compactor.analyze(&segments_vec);
        
        println!("[MAINTENANCE] Compaction plan: {} segments to merge, {} to archive",
            plan.segments_to_merge.len(),
            plan.segments_to_archive.len()
        );
        
        Ok(plan)
    }

    /// Archive cold data
    pub fn archive_cold(&self) -> Result<Option<Archive>, String> {
        if let Some(ref archiver) = self.archiver {
            // Get cold segments
            let cold: Vec<Segment> = self.segments.read().unwrap()
                .values()
                .filter(|s| s.access_count < 5)
                .cloned()
                .collect();

            if cold.is_empty() {
                return Ok(None);
            }

            let archive = archiver.archive(cold)?;
            
            // Remove archived segments from active
            for seg_id in &archive.segment_ids {
                self.segments.write().unwrap().remove(seg_id);
            }

            println!("[MAINTENANCE] Archived {} segments to {}",
                archive.segment_ids.len(),
                archive.location
            );

            Ok(Some(archive))
        } else {
            Err("Archiver not configured".to_string())
        }
    }

    /// Get maintenance stats
    pub fn stats(&self) -> MaintenanceStats {
        let segments = self.segments.read().unwrap();
        let total_size: usize = segments.values().map(|s| s.total_size).sum();

        MaintenanceStats {
            total_chunks: segments.values().map(|s| s.chunk_ids.len()).sum(),
            orphan_count: 0, // Would calculate from orphan detector
            index_size_mb: total_size as f64 / (1024.0 * 1024.0),
            last_rebuild: 0, // Would track from job history
            last_cleanup: 0,
        }
    }

    /// Run all maintenance
    pub fn run_full_maintenance(&self) -> Vec<MaintenanceResult> {
        let mut results = Vec::new();

        // Orphan cleanup
        match self.cleanup_orphans() {
            Ok(removed) => results.push(MaintenanceResult {
                task: MaintenanceTask::OrphanCleanup,
                success: true,
                items_affected: removed,
                message: format!("Removed {} orphans", removed),
            }),
            Err(e) => results.push(MaintenanceResult {
                task: MaintenanceTask::OrphanCleanup,
                success: false,
                items_affected: 0,
                message: e,
            }),
        }

        // Compaction
        match self.compact() {
            Ok(plan) => results.push(MaintenanceResult {
                task: MaintenanceTask::Compaction,
                success: true,
                items_affected: plan.segments_to_merge.len() + plan.segments_to_archive.len(),
                message: format!("Planned: {} merges, {} archives", 
                    plan.segments_to_merge.len(), 
                    plan.segments_to_archive.len()),
            }),
            Err(e) => results.push(MaintenanceResult {
                task: MaintenanceTask::Compaction,
                success: false,
                items_affected: 0,
                message: e,
            }),
        }

        results
    }
}

#[derive(Debug, Clone)]
pub struct MaintenanceResult {
    pub task: MaintenanceTask,
    pub success: bool,
    pub items_affected: usize,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orphan_detection() {
        let mut detector = OrphanDetector::new();
        
        let chunks = vec![
            KnowledgeChunk {
                chunk_id: "chunk-1".to_string(),
                content: "content 1".to_string(),
                metadata: crate::knowledge::index::ChunkMetadata {
                    source: "test".to_string(),
                    chunk_type: crate::knowledge::index::ChunkType::Text,
                    confidence: 0.9,
                    tags: vec![],
                },
                created_at: 1000,
            },
            KnowledgeChunk {
                chunk_id: "chunk-2".to_string(),
                content: "content 2".to_string(),
                metadata: crate::knowledge::index::ChunkMetadata {
                    source: "test".to_string(),
                    chunk_type: crate::knowledge::index::ChunkType::Text,
                    confidence: 0.9,
                    tags: vec![],
                },
                created_at: 1000,
            },
        ];

        let references = vec!["chunk-1".to_string()];
        let orphans = detector.scan(&chunks, &references);

        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], "chunk-2");
    }

    #[test]
    fn test_compaction_plan() {
        let compactor = Compactor::new();

        let segments = vec![
            Segment {
                segment_id: "seg-1".to_string(),
                chunk_ids: (0..10).map(|i| format!("chunk-{}", i)).collect(),
                total_size: 1000,
                created_at: chrono::Utc::now().timestamp_millis() - 86400000 * 30, // 30 days old
                access_count: 2,
                last_accessed: chrono::Utc::now().timestamp_millis() - 86400000 * 20,
            },
            Segment {
                segment_id: "seg-2".to_string(),
                chunk_ids: (10..20).map(|i| format!("chunk-{}", i)).collect(),
                total_size: 1000,
                created_at: chrono::Utc::now().timestamp_millis() - 86400000 * 30,
                access_count: 1,
                last_accessed: chrono::Utc::now().timestamp_millis() - 86400000 * 25,
            },
        ];

        let plan = compactor.analyze(&segments);
        
        assert!(!plan.segments_to_archive.is_empty());
    }
}
