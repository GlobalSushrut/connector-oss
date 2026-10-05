//! Blind Query — Query Without Seeing Sensitive Data
//!
//! Allows LLM to answer queries without accessing:
//! - Patient names
//! - Medical conditions
//! - Financial details
//! - Other PII
//!
//! Query is processed on anonymized data, answer is reconstructed
//! for authorized users only.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// =============================================================================
// Blind Query Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindQuery {
    /// Query ID
    pub query_id: String,
    /// Original query (contains PII)
    pub original_query: String,
    /// Anonymized query (for LLM)
    pub anonymized_query: String,
    /// Context hash for reconstruction
    pub context_hash: String,
    /// Query type
    pub query_type: QueryType,
    /// Authorization level required
    pub required_auth: AuthLevel,
    /// Created at
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryType {
    MedicalConsultation,
    FinancialInquiry,
    PersonalInformation,
    GeneralKnowledge,
    SensitiveResearch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    Public,           // No auth needed
    Patient,          // Data subject
    MedicalStaff,     // Doctors, nurses
    Administrator,    // System admins
    Auditor,          // Compliance auditors
    SystemOnly,       // No human access
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindResponse {
    /// Response ID
    pub response_id: String,
    /// Query ID
    pub query_id: String,
    /// Anonymized response (from LLM)
    pub anonymized_response: String,
    /// Reconstructed response (for authorized users)
    pub reconstructed_response: Option<String>,
    /// Was reconstruction successful?
    pub reconstruction_status: ReconstructionStatus,
    /// Confidence score
    pub confidence: f64,
    /// Audit trail
    pub access_log: Vec<AccessEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconstructionStatus {
    Success,
    Partial,          // Some tokens couldn't be reconstructed
    Failed,           // Reconstruction failed
    Unauthorized,     // User not authorized
    NotRequested,     // Reconstruction not requested
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntry {
    pub timestamp: i64,
    pub accessor_id: String,
    pub accessor_role: String,
    pub action: AccessAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessAction {
    QuerySubmitted,
    AnonymizedProcessed,
    ReconstructionRequested,
    ReconstructionGranted,
    ReconstructionDenied,
}

// =============================================================================
// Blind Query Engine
// =============================================================================

use super::dao_identity::{DaoIdentity, AnonymizedText};
use super::semantic_anonymizer::{SemanticAnonymizer, SemanticAnonymization};

pub struct BlindQueryEngine {
    /// DAO identity for PII management
    dao_identity: DaoIdentity,
    /// Semantic anonymizer
    semantic_anon: SemanticAnonymizer,
    /// Query history
    queries: HashMap<String, BlindQuery>,
    /// Response history
    responses: HashMap<String, BlindResponse>,
    /// User authorizations
    user_auth_levels: HashMap<String, AuthLevel>,
}

impl BlindQueryEngine {
    pub fn new() -> Self {
        Self {
            dao_identity: DaoIdentity::new(),
            semantic_anon: SemanticAnonymizer::new(),
            queries: HashMap::new(),
            responses: HashMap::new(),
            user_auth_levels: HashMap::new(),
        }
    }

    /// Submit blind query (Step 1: Anonymize)
    pub fn submit_query(
        &mut self,
        user_id: String,
        user_role: String,
        original_query: String,
        query_type: QueryType,
    ) -> Result<BlindQuery, BlindQueryError> {
        let now = chrono::Utc::now().timestamp_millis();
        let query_id = format!("bq-{}-{}", now, uuid::Uuid::new_v4());

        // Determine required auth level
        let required_auth = self.query_type_to_auth_level(&query_type);

        // Check if user can submit this query type
        let user_auth = self.user_auth_levels.get(&user_id).copied()
            .unwrap_or(AuthLevel::Public);

        if user_auth < required_auth {
            return Err(BlindQueryError::InsufficientAuthorization {
                required: required_auth,
                provided: user_auth,
            });
        }

        // Anonymize using semantic anonymizer
        let semantic_anon = self.semantic_anon.anonymize(&original_query);
        
        // Additional DAO identity anonymization
        let context = format!("query_{}", query_id);
        let dao_anon = self.dao_identity.anonymize_text(&original_query, &context);

        // Combine anonymizations (use semantic as primary)
        let anonymized_query = semantic_anon.anonymized_text.clone();

        let query = BlindQuery {
            query_id: query_id.clone(),
            original_query,
            anonymized_query,
            context_hash: dao_anon.context_hash,
            query_type,
            required_auth,
            created_at: now,
        };

        self.queries.insert(query_id.clone(), query.clone());

        // Log access
        let access_entry = AccessEntry {
            timestamp: now,
            accessor_id: user_id,
            accessor_role: user_role,
            action: AccessAction::QuerySubmitted,
        };

        Ok(query)
    }

    /// Process anonymized response from LLM (Step 2)
    pub fn process_anonymized_response(
        &mut self,
        query_id: &str,
        anonymized_response: String,
        llm_model: String,
    ) -> Result<BlindResponse, BlindQueryError> {
        let query = self.queries.get(query_id)
            .ok_or(BlindQueryError::QueryNotFound)?;

        let now = chrono::Utc::now().timestamp_millis();
        let response_id = format!("br-{}-{}", query_id, now);

        let response = BlindResponse {
            response_id: response_id.clone(),
            query_id: query_id.to_string(),
            anonymized_response: anonymized_response.clone(),
            reconstructed_response: None,
            reconstruction_status: ReconstructionStatus::NotRequested,
            confidence: 0.9, // Placeholder
            access_log: vec![AccessEntry {
                timestamp: now,
                accessor_id: llm_model,
                accessor_role: "llm".to_string(),
                action: AccessAction::AnonymizedProcessed,
            }],
        };

        self.responses.insert(response_id.clone(), response.clone());

        Ok(response)
    }

    /// Request reconstruction (Step 3: Authorized users only)
    pub fn request_reconstruction(
        &mut self,
        response_id: &str,
        user_id: String,
        user_role: String,
        reason: &str,
    ) -> Result<BlindResponse, BlindQueryError> {
        let mut response = self.responses.get_mut(response_id)
            .ok_or(BlindQueryError::ResponseNotFound)?;

        let query = self.queries.get(&response.query_id)
            .ok_or(BlindQueryError::QueryNotFound)?;

        let now = chrono::Utc::now().timestamp_millis();

        // Check authorization
        let user_auth = self.user_auth_levels.get(&user_id).copied()
            .unwrap_or(AuthLevel::Public);

        if user_auth < query.required_auth {
            // Log denial
            response.access_log.push(AccessEntry {
                timestamp: now,
                accessor_id: user_id,
                accessor_role: user_role,
                action: AccessAction::ReconstructionDenied,
            });
            response.reconstruction_status = ReconstructionStatus::Unauthorized;

            return Err(BlindQueryError::InsufficientAuthorization {
                required: query.required_auth,
                provided: user_auth,
            });
        }

        // Attempt reconstruction
        let semantic_result = self.semantic_anon.reconstruct_with_semantics(
            &response.anonymized_response,
            &super::semantic_anonymizer::SemanticAnonymization {
                anonymized_text: query.anonymized_query.clone(),
                mappings: vec![], // Would need to store original mappings
                original_text: query.original_query.clone(),
            }
        );

        // Try DAO reconstruction as fallback
        let dao_result = self.dao_identity.reconstruct_response(
            &response.anonymized_response,
            &query.context_hash,
            &user_id
        );

        // Combine reconstructions
        let reconstructed = if dao_result.is_ok() {
            dao_result.unwrap()
        } else {
            semantic_result
        };

        // Check if reconstruction is complete
        let has_anon_tokens = reconstructed.contains("PERSON_") || 
                              reconstructed.contains("MEDICAL_CONDITION_") ||
                              reconstructed.contains("[ANON");

        let status = if has_anon_tokens {
            ReconstructionStatus::Partial
        } else {
            ReconstructionStatus::Success
        };

        // Log access
        response.access_log.push(AccessEntry {
            timestamp: now,
            accessor_id: user_id,
            accessor_role: user_role,
            action: AccessAction::ReconstructionGranted,
        });

        response.reconstructed_response = Some(reconstructed);
        response.reconstruction_status = status;

        Ok(response.clone())
    }

    /// Register user authorization level
    pub fn register_user(&mut self, user_id: String, auth_level: AuthLevel) {
        self.user_auth_levels.insert(user_id, auth_level);
    }

    /// Get query type required auth level
    fn query_type_to_auth_level(&self, query_type: &QueryType) -> AuthLevel {
        match query_type {
            QueryType::MedicalConsultation => AuthLevel::MedicalStaff,
            QueryType::FinancialInquiry => AuthLevel::Administrator,
            QueryType::PersonalInformation => AuthLevel::Patient,
            QueryType::GeneralKnowledge => AuthLevel::Public,
            QueryType::SensitiveResearch => AuthLevel::Auditor,
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> BlindQueryStats {
        let total_queries = self.queries.len();
        let total_responses = self.responses.len();

        let reconstructed_count = self.responses.values()
            .filter(|r| matches!(r.reconstruction_status, ReconstructionStatus::Success | ReconstructionStatus::Partial))
            .count();

        let denied_count = self.responses.values()
            .filter(|r| matches!(r.reconstruction_status, ReconstructionStatus::Unauthorized))
            .count();

        BlindQueryStats {
            total_queries,
            total_responses,
            successful_reconstructions: reconstructed_count,
            denied_reconstructions: denied_count,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BlindQueryError {
    InsufficientAuthorization { required: AuthLevel, provided: AuthLevel },
    QueryNotFound,
    ResponseNotFound,
    ReconstructionFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindQueryStats {
    pub total_queries: usize,
    pub total_responses: usize,
    pub successful_reconstructions: usize,
    pub denied_reconstructions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_medical_query() {
        let mut engine = BlindQueryEngine::new();

        // Register doctor
        engine.register_user("dr.smith".to_string(), AuthLevel::MedicalStaff);

        // Patient query with PII
        let query = "rahul has aids, what treatment?";
        
        let blind_query = engine.submit_query(
            "dr.smith".to_string(),
            "doctor".to_string(),
            query.to_string(),
            QueryType::MedicalConsultation,
        ).unwrap();

        // Query is anonymized
        assert!(!blind_query.anonymized_query.contains("rahul"));
        assert!(!blind_query.anonymized_query.contains("aids"));

        // But context preserved for LLM
        assert!(blind_query.anonymized_query.contains("treatment"));
    }

    #[test]
    fn test_unauthorized_reconstruction_fails() {
        let mut engine = BlindQueryEngine::new();

        // Register doctor and patient
        engine.register_user("dr.smith".to_string(), AuthLevel::MedicalStaff);
        engine.register_user("rahul".to_string(), AuthLevel::Patient);
        engine.register_user("hacker".to_string(), AuthLevel::Public);

        // Doctor submits query
        let blind_query = engine.submit_query(
            "dr.smith".to_string(),
            "doctor".to_string(),
            "rahul has diabetes".to_string(),
            QueryType::MedicalConsultation,
        ).unwrap();

        // LLM responds (anonymized)
        let response = engine.process_anonymized_response(
            &blind_query.query_id,
            "[PERSON_1] with [MEDICAL_CONDITION_1] requires insulin".to_string(),
            "gpt-4".to_string(),
        ).unwrap();

        // Hacker tries to reconstruct - should fail
        let result = engine.request_reconstruction(
            &response.response_id,
            "hacker".to_string(),
            "attacker".to_string(),
            "stole credentials",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_patient_can_view_own_data() {
        let mut engine = BlindQueryEngine::new();

        engine.register_user("rahul".to_string(), AuthLevel::Patient);

        // Query about self
        let blind_query = engine.submit_query(
            "rahul".to_string(),
            "patient".to_string(),
            "what are my test results".to_string(),
            QueryType::PersonalInformation,
        ).unwrap();

        // LLM response
        let response = engine.process_anonymized_response(
            &blind_query.query_id,
            "[PERSON_1] results are normal".to_string(),
            "gpt-4".to_string(),
        ).unwrap();

        // Patient can reconstruct own data
        let reconstructed = engine.request_reconstruction(
            &response.response_id,
            "rahul".to_string(),
            "patient".to_string(),
            "view my results",
        ).unwrap();

        assert!(reconstructed.reconstructed_response.is_some());
    }
}
