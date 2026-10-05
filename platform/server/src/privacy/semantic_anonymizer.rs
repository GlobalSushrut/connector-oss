//! Semantic Anonymizer — Context-Preserving PII Removal
//!
//! Ensures LLM understands context WITHOUT seeing personal data:
//! - Medical conditions → semantic categories
//! - Names → role-based identifiers
//! - Locations → region types
//! - Financial amounts → ranges
//!
//! LLM gets: "Patient [ANON_PERSON_1] has [CONDITION_SEVERE]"
//! Not: "John has HIV" or "rahul has aids"

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// =============================================================================
// Semantic Categories (Preserve meaning without exposing specifics)
// =============================================================================

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum MedicalCategory {
    ConditionMild,
    ConditionModerate,
    ConditionSevere,
    ConditionCritical,
    ConditionChronic,
    ConditionAcute,
    TreatmentRequired,
    ObservationOnly,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum PersonRole {
    Patient,
    Doctor,
    Caregiver,
    FamilyMember,
    Administrator,
    Researcher,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum LocationType {
    Hospital,
    Clinic,
    Home,
    PublicPlace,
    Workplace,
    GeographicRegion,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinancialRange {
    Nominal,      // <$100
    Low,          // $100-$1000
    Moderate,     // $1000-$10000
    High,         // $10000-$100000
    VeryHigh,     // >$100000
}

/// Semantic anonymization token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticToken {
    /// Anonymous ID (e.g., "ANON_PERSON_1")
    pub token: String,
    /// Semantic category preserving context
    pub category: SemanticCategory,
    /// Original type (for reconstruction)
    pub original_type: PiiType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SemanticCategory {
    Medical(MedicalCategory),
    Person(PersonRole),
    Location(LocationType),
    Financial(FinancialRange),
    Temporal,     // Time/date patterns
    Generic,      // Other anonymized data
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PiiType {
    Name,
    Email,
    Phone,
    Address,
    MedicalCondition,
    MedicalRecord,
    Ssn,
    FinancialAccount,
    Amount,
    DateOfBirth,
    Biometric,
}

// =============================================================================
// Semantic Anonymizer
// =============================================================================

pub struct SemanticAnonymizer {
    /// Category counters for consistent token generation
    counters: HashMap<String, u32>,
    /// Medical condition mappings
    medical_conditions: HashMap<String, MedicalCategory>,
    /// Person name mappings
    person_map: HashMap<String, String>,
}

impl SemanticAnonymizer {
    pub fn new() -> Self {
        let mut medical_conditions = HashMap::new();
        
        // Map conditions to severity (without exposing the actual condition)
        medical_conditions.insert("hiv".to_string(), MedicalCategory::ConditionSevere);
        medical_conditions.insert("aids".to_string(), MedicalCategory::ConditionCritical);
        medical_conditions.insert("diabetes".to_string(), MedicalCategory::ConditionChronic);
        medical_conditions.insert("flu".to_string(), MedicalCategory::ConditionMild);
        medical_conditions.insert("cancer".to_string(), MedicalCategory::ConditionSevere);
        medical_conditions.insert("hypertension".to_string(), MedicalCategory::ConditionChronic);
        medical_conditions.insert("asthma".to_string(), MedicalCategory::ConditionChronic);
        medical_conditions.insert("common cold".to_string(), MedicalCategory::ConditionMild);

        Self {
            counters: HashMap::new(),
            medical_conditions,
            person_map: HashMap::new(),
        }
    }

    /// Anonymize text preserving semantic meaning for LLM
    pub fn anonymize(&mut self, text: &str) -> SemanticAnonymization {
        let mut result = text.to_lowercase();
        let mut mappings = Vec::new();

        // Step 1: Anonymize medical conditions → severity categories
        for (condition, category) in &self.medical_conditions {
            if result.contains(condition) {
                let token = self.generate_token("MEDICAL_CONDITION", SemanticCategory::Medical(*category), PiiType::MedicalCondition);
                result = result.replace(condition, &token.token);
                mappings.push((condition.clone(), token.clone()));
            }
        }

        // Step 2: Anonymize person names → role-based tokens
        let name_pattern = regex::Regex::new(r"\b([a-z]+\s+[a-z]+)\b").unwrap();
        for cap in name_pattern.captures_iter(&result.clone()) {
            let name = cap.get(1).unwrap().as_str();
            if name.len() > 3 && !self.is_common_word(name) {
                let token = self.generate_token("PERSON", SemanticCategory::Person(PersonRole::Patient), PiiType::Name);
                result = result.replace(name, &token.token);
                mappings.push((name.to_string(), token));
            }
        }

        // Step 3: Anonymize emails → person tokens
        let email_pattern = regex::Regex::new(r"\b[\w.-]+@[\w.-]+\.[a-z]{2,}\b").unwrap();
        for cap in email_pattern.captures_iter(&result.clone()) {
            let email = cap.get(0).unwrap().as_str();
            let token = self.generate_token("EMAIL", SemanticCategory::Person(PersonRole::Patient), PiiType::Email);
            result = result.replace(email, &token.token);
            mappings.push((email.to_string(), token));
        }

        // Step 4: Anonymize phone numbers
        let phone_pattern = regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
        for cap in phone_pattern.captures_iter(&result.clone()) {
            let phone = cap.get(0).unwrap().as_str();
            let token = self.generate_token("PHONE", SemanticCategory::Generic, PiiType::Phone);
            result = result.replace(phone, &token.token);
            mappings.push((phone.to_string(), token));
        }

        // Step 5: Anonymize financial amounts
        let amount_pattern = regex::Regex::new(r"\$[\d,]+(\.\d{2})?").unwrap();
        for cap in amount_pattern.captures_iter(&result.clone()) {
            let amount_str = cap.get(0).unwrap().as_str();
            let amount = amount_str.replace(",", "").replace("$", "").parse::<f64>().unwrap_or(0.0);
            let range = self.amount_to_range(amount);
            let token = self.generate_token("AMOUNT", SemanticCategory::Financial(range), PiiType::Amount);
            result = result.replace(amount_str, &token.token);
            mappings.push((amount_str.to_string(), token));
        }

        SemanticAnonymization {
            anonymized_text: result,
            mappings,
            original_text: text.to_string(),
        }
    }

    /// Generate consistent semantic token
    fn generate_token(
        &mut self,
        prefix: &str,
        category: SemanticCategory,
        original_type: PiiType,
    ) -> SemanticToken {
        let counter = self.counters.entry(prefix.to_string()).or_insert(0);
        *counter += 1;

        let token = format!("[{}_{}]", prefix, counter);

        SemanticToken {
            token,
            category,
            original_type,
        }
    }

    /// Convert amount to range category
    fn amount_to_range(&self, amount: f64) -> FinancialRange {
        match amount {
            a if a < 100.0 => FinancialRange::Nominal,
            a if a < 1000.0 => FinancialRange::Low,
            a if a < 10000.0 => FinancialRange::Moderate,
            a if a < 100000.0 => FinancialRange::High,
            _ => FinancialRange::VeryHigh,
        }
    }

    /// Check if word is common (not a name)
    fn is_common_word(&self, word: &str) -> bool {
        let common = vec!["patient", "doctor", "hospital", "clinic", "medical", "treatment", 
                         "diagnosis", "symptom", "prescription", "medication"];
        common.contains(&word)
    }

    /// Reconstruct with semantic substitutions (for authorized users)
    pub fn reconstruct_with_semantics(
        &self,
        anonymized: &str,
        original_context: &SemanticAnonymization,
    ) -> String {
        let mut result = anonymized.to_string();

        // Replace tokens with original values
        for (original, token) in &original_context.mappings {
            result = result.replace(&token.token, original);
        }

        result
    }

    /// Get semantic context for LLM
    pub fn get_semantic_context(&self, anonymization: &SemanticAnonymization) -> String {
        let mut context = String::new();

        for (_, token) in &anonymization.mappings {
            let category_desc = match &token.category {
                SemanticCategory::Medical(cat) => format!("{:?}", cat),
                SemanticCategory::Person(role) => format!("{:?}", role),
                SemanticCategory::Location(loc) => format!("{:?}", loc),
                SemanticCategory::Financial(range) => format!("{:?}", range),
                SemanticCategory::Temporal => "Time reference".to_string(),
                SemanticCategory::Generic => "Anonymized data".to_string(),
            };

            context.push_str(&format!("{} = {}\n", token.token, category_desc));
        }

        context
    }
}

#[derive(Debug, Clone)]
pub struct SemanticAnonymization {
    pub anonymized_text: String,
    pub mappings: Vec<(String, SemanticToken)>, // (original, token)
    pub original_text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_medical_condition_anonymization() {
        let mut anonymizer = SemanticAnonymizer::new();

        // Critical: "rahul has aids" scenario
        let text = "rahul has aids and needs immediate treatment";
        let result = anonymizer.anonymize(text);

        // Should NOT contain actual name or condition
        assert!(!result.anonymized_text.contains("rahul"));
        assert!(!result.anonymized_text.contains("aids"));

        // SHOULD contain semantic tokens
        assert!(result.anonymized_text.contains("PERSON_"));
        assert!(result.anonymized_text.contains("MEDICAL_CONDITION_"));

        // LLM can still understand severity from token
        let context = anonymizer.get_semantic_context(&result);
        assert!(context.contains("Critical") || context.contains("Severe"));
    }

    #[test]
    fn test_preserves_medical_context() {
        let mut anonymizer = SemanticAnonymizer::new();

        let text = "Patient john doe with diabetes requires insulin therapy";
        let result = anonymizer.anonymize(text);

        // Anonymized
        assert!(!result.anonymized_text.contains("john doe"));
        assert!(!result.anonymized_text.contains("diabetes"));

        // But medical context preserved
        assert!(result.anonymized_text.contains("insulin"));
        assert!(result.anonymized_text.contains("therapy"));
        assert!(result.anonymized_text.contains("patient"));
    }

    #[test]
    fn test_financial_anonymization() {
        let mut anonymizer = SemanticAnonymizer::new();

        let text = "Treatment costs $50000";
        let result = anonymizer.anonymize(text);

        // Amount anonymized
        assert!(!result.anonymized_text.contains("50000"));
        assert!(result.anonymized_text.contains("AMOUNT_"));

        // But range info available
        let context = anonymizer.get_semantic_context(&result);
        assert!(context.contains("High") || context.contains("VeryHigh"));
    }

    #[test]
    fn test_reconstruction() {
        let mut anonymizer = SemanticAnonymizer::new();

        let original = "rahul has aids";
        let anon = anonymizer.anonymize(original);

        // LLM response (anonymized)
        let llm_response = "[PERSON_1] with [MEDICAL_CONDITION_1] requires ART therapy";

        // Reconstruct for doctor
        let reconstructed = anonymizer.reconstruct_with_semantics(llm_response, &anon);
        assert!(reconstructed.contains("rahul") || reconstructed.contains("aids"));
    }

    #[test]
    fn test_email_anonymization() {
        let mut anonymizer = SemanticAnonymizer::new();

        let text = "Contact patient at john@example.com";
        let result = anonymizer.anonymize(text);

        assert!(!result.anonymized_text.contains("john@example.com"));
        assert!(result.anonymized_text.contains("EMAIL_"));
    }
}
