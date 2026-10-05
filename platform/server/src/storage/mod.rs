//! Storage Systems — S3, Kafka, and Backend Adapters

pub mod adapter;

pub use adapter::{StorageManager, S3Adapter, KafkaAdapter, MemoryStorage};
