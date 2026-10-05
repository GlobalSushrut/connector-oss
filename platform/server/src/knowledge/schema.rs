//! Knowledge Schema — Validation, Ontology, Entity Extraction
//!
//! FIX BUG-042: Schema validation, ontology alignment, entity extraction

use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use regex::Regex;

// =============================================================================
// Schema Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeSchema {
    /// Schema version
    pub version: String,
    /// Entity types defined in schema
    pub entity_types: HashMap<String, EntityType>,
    /// Relationship types
    pub relationship_types: HashMap<String, RelationshipType>,
    /// Property types
    pub property_types: HashMap<String, PropertyType>,
    /// Ontology references
    pub ontologies: Vec<OntologyRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityType {
    pub name: String,
    pub description: String,
    pub properties: Vec<PropertyDef>,
    pub parent_type: Option<String>,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipType {
    pub name: String,
    pub description: String,
    pub domain: Vec<String>, // Entity types that can be subjects
    pub range: Vec<String>,  // Entity types that can be objects
    pub cardinality: Cardinality,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Cardinality {
    OneToOne,
    OneToMany,
    ManyToOne,
    ManyToMany,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyDef {
    pub name: String,
    pub property_type: String,
    pub required: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyType {
    pub name: String,
    pub data_type: DataType,
    pub validation_rules: Vec<ValidationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    String { min_len: Option<usize>, max_len: Option<usize> },
    Integer { min: Option<i64>, max: Option<i64> },
    Float { min: Option<f64>, max: Option<f64> },
    Boolean,
    DateTime,
    Enum(Vec<String>),
    List(Box<DataType>),
    Map(HashMap<String, DataType>),
    Reference(String), // Reference to entity type
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    Unique,
    Index,
    NotNull,
    Pattern(String), // Regex pattern
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    MinLength(usize),
    MaxLength(usize),
    Pattern(String),
    Range { min: f64, max: f64 },
    EnumValues(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OntologyRef {
    pub id: String,
    pub name: String,
    pub url: String,
    pub prefix: String,
}

// =============================================================================
// Schema Validator
// =============================================================================

pub struct SchemaValidator {
    schema: KnowledgeSchema,
    compiled_patterns: HashMap<String, Regex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntity {
    pub entity_id: String,
    pub entity_type: String,
    pub properties: HashMap<String, serde_json::Value>,
    pub relationships: Vec<Relationship>,
    pub source: String,
    pub confidence: f64,
    pub extracted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub relation_type: String,
    pub target_entity: String,
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub entity_id: String,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub error_type: ErrorType,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    MissingRequired,
    TypeMismatch,
    ConstraintViolation,
    PatternMismatch,
    RangeViolation,
    UnknownType,
    OntologyMismatch,
}

impl SchemaValidator {
    pub fn new(schema: KnowledgeSchema) -> Self {
        let mut patterns = HashMap::new();
        
        // Pre-compile regex patterns
        for (type_name, prop_type) in &schema.property_types {
            for rule in &prop_type.validation_rules {
                if let ValidationRule::Pattern(pat) = rule {
                    if let Ok(regex) = Regex::new(pat) {
                        patterns.insert(format!("{}:pattern", type_name), regex);
                    }
                }
            }
        }
        
        Self {
            schema,
            compiled_patterns: patterns,
        }
    }

    /// Validate entity against schema
    pub fn validate(&self, entity: &KnowledgeEntity) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check entity type exists
        let entity_type = match self.schema.entity_types.get(&entity.entity_type) {
            Some(t) => t,
            None => {
                errors.push(ValidationError {
                    field: "entity_type".to_string(),
                    error_type: ErrorType::UnknownType,
                    message: format!("Unknown entity type: {}", entity.entity_type),
                });
                return ValidationResult {
                    valid: false,
                    entity_id: entity.entity_id.clone(),
                    errors,
                    warnings,
                };
            }
        };

        // Validate properties
        for prop_def in &entity_type.properties {
            let prop_name = &prop_def.name;
            
            if prop_def.required {
                if !entity.properties.contains_key(prop_name) {
                    errors.push(ValidationError {
                        field: prop_name.clone(),
                        error_type: ErrorType::MissingRequired,
                        message: format!("Required property '{}' is missing", prop_name),
                    });
                    continue;
                }
            }

            if let Some(value) = entity.properties.get(prop_name) {
                // Get property type
                if let Some(prop_type) = self.schema.property_types.get(&prop_def.property_type) {
                    if let Err(e) = self.validate_value(value, &prop_type.data_type, prop_name) {
                        errors.push(e);
                    }
                }
            }
        }

        // Validate relationships
        for rel in &entity.relationships {
            if let Some(rel_type) = self.schema.relationship_types.get(&rel.relation_type) {
                // Check if entity type is valid domain
                if !rel_type.domain.contains(&entity.entity_type) {
                    errors.push(ValidationError {
                        field: format!("rel.{}", rel.relation_type),
                        error_type: ErrorType::ConstraintViolation,
                        message: format!(
                            "Entity type '{}' cannot be subject of '{}' relationship",
                            entity.entity_type, rel.relation_type
                        ),
                    });
                }
            } else {
                warnings.push(format!("Unknown relationship type: {}", rel.relation_type));
            }
        }

        // Check confidence threshold
        if entity.confidence < 0.0 || entity.confidence > 1.0 {
            errors.push(ValidationError {
                field: "confidence".to_string(),
                error_type: ErrorType::RangeViolation,
                message: "Confidence must be between 0.0 and 1.0".to_string(),
            });
        }

        ValidationResult {
            valid: errors.is_empty(),
            entity_id: entity.entity_id.clone(),
            errors,
            warnings,
        }
    }

    fn validate_value(
        &self,
        value: &serde_json::Value,
        data_type: &DataType,
        field: &str,
    ) -> Result<(), ValidationError> {
        match (value, data_type) {
            (serde_json::Value::String(s), DataType::String { min_len, max_len }) => {
                if let Some(min) = min_len {
                    if s.len() < *min {
                        return Err(ValidationError {
                            field: field.to_string(),
                            error_type: ErrorType::ConstraintViolation,
                            message: format!("String too short (min {} chars)", min),
                        });
                    }
                }
                if let Some(max) = max_len {
                    if s.len() > *max {
                        return Err(ValidationError {
                            field: field.to_string(),
                            error_type: ErrorType::ConstraintViolation,
                            message: format!("String too long (max {} chars)", max),
                        });
                    }
                }
                Ok(())
            }
            (serde_json::Value::Number(n), DataType::Integer { min, max }) => {
                if let Some(v) = n.as_i64() {
                    if let Some(min_v) = min {
                        if v < *min_v {
                            return Err(ValidationError {
                                field: field.to_string(),
                                error_type: ErrorType::RangeViolation,
                                message: format!("Value below minimum {}", min_v),
                            });
                        }
                    }
                    if let Some(max_v) = max {
                        if v > *max_v {
                            return Err(ValidationError {
                                field: field.to_string(),
                                error_type: ErrorType::RangeViolation,
                                message: format!("Value above maximum {}", max_v),
                            });
                        }
                    }
                }
                Ok(())
            }
            (serde_json::Value::Bool(_), DataType::Boolean) => Ok(()),
            (serde_json::Value::Array(arr), DataType::List(item_type)) => {
                for (i, item) in arr.iter().enumerate() {
                    self.validate_value(item, item_type, &format!("{}[{}]", field, i))?;
                }
                Ok(())
            }
            _ => Err(ValidationError {
                field: field.to_string(),
                error_type: ErrorType::TypeMismatch,
                message: format!("Type mismatch: expected {:?}", data_type),
            }),
        }
    }

    /// Create default schema
    pub fn default_schema() -> KnowledgeSchema {
        let mut entity_types = HashMap::new();
        let mut property_types = HashMap::new();

        // String type
        property_types.insert("Text".to_string(), PropertyType {
            name: "Text".to_string(),
            data_type: DataType::String { min_len: Some(1), max_len: Some(10000) },
            validation_rules: vec![],
        });

        // Confidence type
        property_types.insert("Confidence".to_string(), PropertyType {
            name: "Confidence".to_string(),
            data_type: DataType::Float { min: Some(0.0), max: Some(1.0) },
            validation_rules: vec![],
        });

        // Timestamp type
        property_types.insert("Timestamp".to_string(), PropertyType {
            name: "Timestamp".to_string(),
            data_type: DataType::Integer { min: Some(0), max: None },
            validation_rules: vec![],
        });

        // Entity: Document
        entity_types.insert("Document".to_string(), EntityType {
            name: "Document".to_string(),
            description: "A text document".to_string(),
            properties: vec![
                PropertyDef { name: "title".to_string(), property_type: "Text".to_string(), required: true, default_value: None },
                PropertyDef { name: "content".to_string(), property_type: "Text".to_string(), required: true, default_value: None },
                PropertyDef { name: "author".to_string(), property_type: "Text".to_string(), required: false, default_value: None },
            ],
            parent_type: None,
            constraints: vec![],
        });

        // Entity: Person
        entity_types.insert("Person".to_string(), EntityType {
            name: "Person".to_string(),
            description: "A human person".to_string(),
            properties: vec![
                PropertyDef { name: "name".to_string(), property_type: "Text".to_string(), required: true, default_value: None },
                PropertyDef { name: "email".to_string(), property_type: "Text".to_string(), required: false, default_value: None },
            ],
            parent_type: None,
            constraints: vec![Constraint::Unique],
        });

        KnowledgeSchema {
            version: "1.0".to_string(),
            entity_types,
            relationship_types: HashMap::new(),
            property_types,
            ontologies: vec![
                OntologyRef {
                    id: "schema.org".to_string(),
                    name: "Schema.org".to_string(),
                    url: "https://schema.org".to_string(),
                    prefix: "schema".to_string(),
                },
            ],
        }
    }
}

// =============================================================================
// Ontology Alignment
// =============================================================================

pub struct OntologyAligner {
    mappings: HashMap<String, String>, // local_type -> ontology_type
}

impl OntologyAligner {
    pub fn new() -> Self {
        let mut mappings = HashMap::new();
        
        // Schema.org mappings
        mappings.insert("Person".to_string(), "schema:Person".to_string());
        mappings.insert("Document".to_string(), "schema:Article".to_string());
        mappings.insert("Organization".to_string(), "schema:Organization".to_string());
        mappings.insert("Event".to_string(), "schema:Event".to_string());
        
        Self { mappings }
    }

    /// Map local entity type to ontology type
    pub fn map_to_ontology(&self, local_type: &str) -> Option<String> {
        self.mappings.get(local_type).cloned()
    }

    /// Align entity to ontology
    pub fn align_entity(&self, entity: &KnowledgeEntity) -> Option<AlignedEntity> {
        self.map_to_ontology(&entity.entity_type).map(|ontology_type| {
            AlignedEntity {
                original: entity.clone(),
                ontology_type,
                ontology_properties: self.map_properties(entity),
            }
        })
    }

    fn map_properties(&self, entity: &KnowledgeEntity) -> HashMap<String, serde_json::Value> {
        let mut mapped = HashMap::new();
        
        // Map common properties
        for (key, value) in &entity.properties {
            let mapped_key = match key.as_str() {
                "name" => "schema:name",
                "title" => "schema:headline",
                "content" => "schema:text",
                "author" => "schema:author",
                "email" => "schema:email",
                _ => key.as_str(),
            };
            mapped.insert(mapped_key.to_string(), value.clone());
        }
        
        mapped
    }
}

#[derive(Debug, Clone)]
pub struct AlignedEntity {
    pub original: KnowledgeEntity,
    pub ontology_type: String,
    pub ontology_properties: HashMap<String, serde_json::Value>,
}

// =============================================================================
// Entity Extractor
// =============================================================================

pub struct EntityExtractor {
    patterns: Vec<EntityPattern>,
}

#[derive(Debug, Clone)]
pub struct EntityPattern {
    pub entity_type: String,
    pub regex: Regex,
    pub confidence: f64,
}

impl EntityExtractor {
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // Email pattern
        if let Ok(regex) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
            patterns.push(EntityPattern {
                entity_type: "Email".to_string(),
                regex,
                confidence: 0.95,
            });
        }

        // URL pattern
        if let Ok(regex) = Regex::new(r"https?://[^\s]+") {
            patterns.push(EntityPattern {
                entity_type: "URL".to_string(),
                regex,
                confidence: 0.95,
            });
        }

        // Date pattern (YYYY-MM-DD)
        if let Ok(regex) = Regex::new(r"\d{4}-\d{2}-\d{2}") {
            patterns.push(EntityPattern {
                entity_type: "Date".to_string(),
                regex,
                confidence: 0.90,
            });
        }

        // Phone number pattern
        if let Ok(regex) = Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b") {
            patterns.push(EntityPattern {
                entity_type: "Phone".to_string(),
                regex,
                confidence: 0.85,
            });
        }

        Self { patterns }
    }

    /// Extract entities from text
    pub fn extract(&self, text: &str) -> Vec<ExtractedEntity> {
        let mut entities = Vec::new();

        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(text) {
                entities.push(ExtractedEntity {
                    entity_type: pattern.entity_type.clone(),
                    value: mat.as_str().to_string(),
                    start_pos: mat.start(),
                    end_pos: mat.end(),
                    confidence: pattern.confidence,
                    context: text.chars().skip(mat.start().saturating_sub(20)).take(40).collect(),
                });
            }
        }

        entities
    }

    /// Extract and create knowledge entities
    pub fn extract_entities(&self, text: &str, source: &str) -> Vec<KnowledgeEntity> {
        let extracted = self.extract(text);
        let mut entities = Vec::new();

        for ext in extracted {
            let entity = KnowledgeEntity {
                entity_id: format!("{}-{}", ext.entity_type.to_lowercase(), uuid::Uuid::new_v4()),
                entity_type: ext.entity_type,
                properties: {
                    let mut props = HashMap::new();
                    props.insert("value".to_string(), serde_json::Value::String(ext.value));
                    props.insert("context".to_string(), serde_json::Value::String(ext.context));
                    props
                },
                relationships: vec![],
                source: source.to_string(),
                confidence: ext.confidence,
                extracted_at: chrono::Utc::now().timestamp_millis(),
            };
            entities.push(entity);
        }

        entities
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub entity_type: String,
    pub value: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub confidence: f64,
    pub context: String,
}

// =============================================================================
// Knowledge Schema Manager
// =============================================================================

pub struct SchemaManager {
    schema: KnowledgeSchema,
    validator: SchemaValidator,
    aligner: OntologyAligner,
    extractor: EntityExtractor,
}

impl SchemaManager {
    pub fn new() -> Self {
        let schema = SchemaValidator::default_schema();
        let validator = SchemaValidator::new(schema.clone());
        
        Self {
            schema,
            validator,
            aligner: OntologyAligner::new(),
            extractor: EntityExtractor::new(),
        }
    }

    pub fn validate(&self, entity: &KnowledgeEntity) -> ValidationResult {
        self.validator.validate(entity)
    }

    pub fn align(&self, entity: &KnowledgeEntity) -> Option<AlignedEntity> {
        self.aligner.align_entity(entity)
    }

    pub fn extract(&self, text: &str, source: &str) -> Vec<KnowledgeEntity> {
        self.extractor.extract_entities(text, source)
    }

    pub fn get_schema(&self) -> &KnowledgeSchema {
        &self.schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validation() {
        let schema = SchemaValidator::default_schema();
        let validator = SchemaValidator::new(schema);

        let entity = KnowledgeEntity {
            entity_id: "doc1".to_string(),
            entity_type: "Document".to_string(),
            properties: {
                let mut props = HashMap::new();
                props.insert("title".to_string(), serde_json::Value::String("Test".to_string()));
                props.insert("content".to_string(), serde_json::Value::String("Content".to_string()));
                props
            },
            relationships: vec![],
            source: "test".to_string(),
            confidence: 0.9,
            extracted_at: 1000,
        };

        let result = validator.validate(&entity);
        assert!(result.valid);
    }

    #[test]
    fn test_entity_extraction() {
        let extractor = EntityExtractor::new();
        let text = "Contact us at test@example.com or visit https://example.com";
        
        let entities = extractor.extract(text);
        
        assert!(!entities.is_empty());
        assert!(entities.iter().any(|e| e.entity_type == "Email"));
        assert!(entities.iter().any(|e| e.entity_type == "URL"));
    }

    #[test]
    fn test_ontology_alignment() {
        let aligner = OntologyAligner::new();
        
        let entity = KnowledgeEntity {
            entity_id: "p1".to_string(),
            entity_type: "Person".to_string(),
            properties: {
                let mut props = HashMap::new();
                props.insert("name".to_string(), serde_json::Value::String("John".to_string()));
                props
            },
            relationships: vec![],
            source: "test".to_string(),
            confidence: 0.9,
            extracted_at: 1000,
        };

        let aligned = aligner.align_entity(&entity);
        assert!(aligned.is_some());
        assert_eq!(aligned.unwrap().ontology_type, "schema:Person");
    }
}
