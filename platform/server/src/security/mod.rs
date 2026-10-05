//! Security Module — Network & Infrastructure Security
//!
//! FIX BUG-064/065: Security infrastructure

pub mod cache;

pub use cache::{SecureCacheLayer as SecurityCache, SharedSecureCache, DataClassification, CacheError};
