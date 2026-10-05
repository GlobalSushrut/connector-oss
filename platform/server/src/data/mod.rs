//! Data Module — Security, Privacy, and Consent Management
//!
//! Phase 7: Data Security Infrastructure

pub mod ledger;
pub mod sensitive_store;
pub mod policy;
pub mod subject_isolation;
pub mod consent;

pub use ledger::{
    DataControlLedger, Cid, DataSegment, DataType, SensitivityLevel,
    DataLineage, LedgerStats, LineageResult,
};

pub use sensitive_store::{
    SensitiveStore, EncryptedData, EncryptionAlgorithm,
    AccessPolicy, AccessRequest, AccessGrant, StoreStats,
};

pub use policy::{
    PolicyEngine, DataHandlingPolicy, PolicyRule, PolicyCondition, PolicyAction,
    PolicyEvaluation, EvaluationContext, ViolationSeverity, PolicyStats,
};

pub use subject_isolation::{
    SubjectIsolationManager, Subject, SubjectType, IsolationLevel,
    SubjectNamespace, ErasureReport,
};

pub use consent::{
    ConsentRegistry, ConsentRecord, ConsentMechanism, DataCategory,
    PurposeDefinition, LegalBasis, ConsentCheck, ConsentStats,
};
