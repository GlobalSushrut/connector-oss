//! Knowledge Systems — Indexing, Search, and Processing

pub mod index;
pub mod pagination;
pub mod maintenance;
pub mod dehallucination;
pub mod cot_ledger;

pub use index::{KnowledgeIndex, HnswIndex, InvertedIndex, KnowledgeChunk, Embedding, IndexStats};
pub use pagination::{Paginator, PageRequest, PageResult, StreamingIterator};
pub use maintenance::{MaintenanceManager, MaintenanceTask, CompactionPlan};
pub use dehallucination::{DehallucinationChain, HallucinationReport, GroundTruthDB};
pub use cot_ledger::{CotLedger, ReasoningChain, StepType};
