//! Grounding Table — deterministic mapping from natural language to codes.
//!
//! The LLM proposes conditions/procedures in natural language.
//! The grounding table maps them to standardized codes (ICD-10, CPT, etc.)
//! WITHOUT involving the LLM — pure deterministic lookup.
//!
//! This prevents the LLM from inventing codes (Z88.6 for codeine when
//! the patient has sulfa allergy, etc.)
//!
//! Tables are loaded from JSON and can be domain-specific:
//! - Medical: ICD-10, CPT, SNOMED
//! - Legal: statute references, regulation codes
//! - Financial: transaction codes, risk categories

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═════════════════════════════════════════════════════════════════
// CodeEntry — a single code in the grounding table
// ═════════════════════════════════════════════════════════════════

/// A standardized code entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEntry {
    /// The standardized code (e.g., "I21.11", "93000", "18 U.S.C. § 1030")
    pub code: String,
    /// Human-readable description
    pub desc: String,
    /// Code system (e.g., "icd10", "cpt", "statute")
    #[serde(default)]
    pub system: String,
}

// ═════════════════════════════════════════════════════════════════
// GroundingTable — deterministic lookup from terms to codes
// ═════════════════════════════════════════════════════════════════

/// A grounding table maps natural-language terms to standardized codes.
///
/// Categories organize entries (e.g., "conditions", "allergies", "procedures").
/// Within each category, keys are lowercase normalized terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingTable {
    /// Category → (term → CodeEntry)
    categories: HashMap<String, HashMap<String, CodeEntry>>,
}

impl GroundingTable {
    /// Create an empty grounding table.
    pub fn new() -> Self {
        Self { categories: HashMap::new() }
    }

    /// Load from JSON string.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "conditions": {
    ///     "inferior stemi": {"code": "I21.11", "desc": "STEMI involving RCA"},
    ///     "type 2 diabetes": {"code": "E11.9", "desc": "Type 2 DM"}
    ///   },
    ///   "allergies": { ... }
    /// }
    /// ```
    ///
    /// Also accepts the shorthand format used in medical_codes.json:
    /// ```json
    /// {
    ///   "conditions": {
    ///     "inferior stemi": {"icd10": "I21.11", "desc": "..."}
    ///   }
    /// }
    /// ```
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        // Try the canonical format first
        let raw: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        let obj = raw.as_object()
            .ok_or_else(|| "Expected JSON object at top level".to_string())?;

        let mut categories = HashMap::new();

        for (cat_name, cat_value) in obj {
            let cat_obj = cat_value.as_object()
                .ok_or_else(|| format!("Category '{}' must be an object", cat_name))?;

            let mut entries = HashMap::new();
            for (term, entry_value) in cat_obj {
                let entry_obj = entry_value.as_object()
                    .ok_or_else(|| format!("Entry '{}' in '{}' must be an object", term, cat_name))?;

                // Extract code: try "code", then "icd10", then "cpt"
                let code = entry_obj.get("code")
                    .or_else(|| entry_obj.get("icd10"))
                    .or_else(|| entry_obj.get("cpt"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("Entry '{}' missing code/icd10/cpt field", term))?;

                let desc = entry_obj.get("desc")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Determine system from which key was used
                let system = if entry_obj.contains_key("icd10") {
                    "icd10"
                } else if entry_obj.contains_key("cpt") {
                    "cpt"
                } else {
                    "unknown"
                };

                entries.insert(term.to_lowercase(), CodeEntry {
                    code: code.to_string(),
                    desc: desc.to_string(),
                    system: system.to_string(),
                });
            }

            categories.insert(cat_name.clone(), entries);
        }

        Ok(Self { categories })
    }

    /// Load from a JSON file path.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read file '{}': {}", path, e))?;
        Self::from_json(&content)
    }

    /// Add a single entry.
    pub fn add(&mut self, category: &str, term: &str, code: &str, desc: &str, system: &str) {
        self.categories
            .entry(category.to_string())
            .or_default()
            .insert(term.to_lowercase(), CodeEntry {
                code: code.to_string(),
                desc: desc.to_string(),
                system: system.to_string(),
            });
    }

    /// Exact lookup by category and term.
    pub fn lookup(&self, category: &str, term: &str) -> Option<&CodeEntry> {
        self.categories
            .get(category)
            .and_then(|entries| entries.get(&term.to_lowercase()))
    }

    /// Fuzzy lookup — checks if term is a substring of any key or vice versa.
    pub fn lookup_fuzzy(&self, category: &str, term: &str) -> Option<&CodeEntry> {
        // Try exact first
        if let Some(entry) = self.lookup(category, term) {
            return Some(entry);
        }

        // Fuzzy: substring match
        let term_lower = term.to_lowercase();
        self.categories.get(category).and_then(|entries| {
            for (key, entry) in entries {
                if term_lower.contains(key.as_str()) || key.contains(term_lower.as_str()) {
                    return Some(entry);
                }
            }
            None
        })
    }

    /// List all categories.
    pub fn categories(&self) -> Vec<&str> {
        self.categories.keys().map(|s| s.as_str()).collect()
    }

    /// Count entries in a category.
    pub fn category_count(&self, category: &str) -> usize {
        self.categories.get(category).map(|e| e.len()).unwrap_or(0)
    }

    /// Total entries across all categories.
    pub fn total_entries(&self) -> usize {
        self.categories.values().map(|e| e.len()).sum()
    }
}

impl Default for GroundingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ═════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "conditions": {
                "inferior stemi": {"icd10": "I21.11", "desc": "STEMI involving RCA"},
                "type 2 diabetes": {"icd10": "E11.9", "desc": "Type 2 DM"},
                "hypertension": {"icd10": "I10", "desc": "Essential hypertension"}
            },
            "allergies": {
                "sulfa": {"icd10": "Z88.2", "desc": "Allergy to sulfonamides"},
                "shellfish": {"icd10": "Z91.013", "desc": "Allergy to seafood"}
            },
            "procedures": {
                "troponin": {"cpt": "84484", "desc": "Troponin, quantitative"},
                "ecg 12 lead": {"cpt": "93000", "desc": "ECG routine"}
            }
        }"#
    }

    #[test]
    fn test_load_from_json() {
        let table = GroundingTable::from_json(sample_json()).unwrap();
        assert_eq!(table.total_entries(), 7);
        assert_eq!(table.category_count("conditions"), 3);
        assert_eq!(table.category_count("allergies"), 2);
        assert_eq!(table.category_count("procedures"), 2);
    }

    #[test]
    fn test_exact_lookup() {
        let table = GroundingTable::from_json(sample_json()).unwrap();
        let entry = table.lookup("conditions", "inferior stemi").unwrap();
        assert_eq!(entry.code, "I21.11");
        assert_eq!(entry.system, "icd10");
    }

    #[test]
    fn test_case_insensitive() {
        let table = GroundingTable::from_json(sample_json()).unwrap();
        assert!(table.lookup("conditions", "Inferior STEMI").is_some());
        assert!(table.lookup("allergies", "SULFA").is_some());
    }

    #[test]
    fn test_fuzzy_lookup() {
        let table = GroundingTable::from_json(sample_json()).unwrap();
        // "stemi" is substring of "inferior stemi"
        let entry = table.lookup_fuzzy("conditions", "stemi").unwrap();
        assert_eq!(entry.code, "I21.11");
    }

    #[test]
    fn test_no_match() {
        let table = GroundingTable::from_json(sample_json()).unwrap();
        assert!(table.lookup("conditions", "appendicitis").is_none());
        assert!(table.lookup_fuzzy("conditions", "appendicitis").is_none());
    }

    #[test]
    fn test_add_entry() {
        let mut table = GroundingTable::new();
        table.add("conditions", "appendicitis", "K35.80", "Unspecified acute appendicitis", "icd10");
        assert_eq!(table.total_entries(), 1);
        let entry = table.lookup("conditions", "appendicitis").unwrap();
        assert_eq!(entry.code, "K35.80");
    }

    #[test]
    fn test_canonical_format() {
        let json = r#"{
            "risks": {
                "high volatility": {"code": "RISK-001", "desc": "High market volatility"}
            }
        }"#;
        let table = GroundingTable::from_json(json).unwrap();
        let entry = table.lookup("risks", "high volatility").unwrap();
        assert_eq!(entry.code, "RISK-001");
        assert_eq!(entry.system, "unknown");
    }
}
