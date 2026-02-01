//! Route definitions for the Gateway

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::handlers::*;
use crate::state::AppState;

/// Create the main router with all routes
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health and status
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        
        // VĀKYA operations
        .route("/v1/vakya", post(submit_vakya))
        .route("/v1/vakya/:vakya_id", get(get_vakya))
        .route("/v1/vakya/:vakya_id/receipt", get(get_receipt))
        .route("/v1/vakya/:vakya_id/effects", get(get_effects))
        
        // Transparency log
        .route("/v1/merkle/root", get(get_merkle_root))
        .route("/v1/merkle/proof", get(get_inclusion_proof))
        
        // Adapters
        .route("/v1/adapters", get(list_adapters))
        
        // State
        .with_state(state)
}

/// Create router with OpenAPI documentation
pub fn create_router_with_docs(state: Arc<AppState>) -> Router {
    let api_router = create_router(state);
    
    // Add OpenAPI spec endpoint
    api_router.route("/openapi.json", get(openapi_spec))
}

/// OpenAPI specification handler
async fn openapi_spec() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "AAPI Gateway",
            "description": "Agentic Action Protocol Interface Gateway API",
            "version": env!("CARGO_PKG_VERSION"),
            "license": {
                "name": "Apache-2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0"
            }
        },
        "servers": [
            {
                "url": "http://localhost:8080",
                "description": "Local development server"
            }
        ],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "operationId": "healthCheck",
                    "tags": ["System"],
                    "responses": {
                        "200": {
                            "description": "Gateway is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/HealthResponse"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/vakya": {
                "post": {
                    "summary": "Submit a VĀKYA for execution",
                    "operationId": "submitVakya",
                    "tags": ["VĀKYA"],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/SubmitVakyaRequest"
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "VĀKYA accepted",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/SubmitVakyaResponse"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Validation error"
                        },
                        "403": {
                            "description": "Authorization denied"
                        }
                    }
                }
            },
            "/v1/vakya/{vakya_id}": {
                "get": {
                    "summary": "Get a VĀKYA by ID",
                    "operationId": "getVakya",
                    "tags": ["VĀKYA"],
                    "parameters": [
                        {
                            "name": "vakya_id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "VĀKYA record"
                        },
                        "404": {
                            "description": "VĀKYA not found"
                        }
                    }
                }
            },
            "/v1/vakya/{vakya_id}/receipt": {
                "get": {
                    "summary": "Get receipt for a VĀKYA",
                    "operationId": "getReceipt",
                    "tags": ["VĀKYA"],
                    "parameters": [
                        {
                            "name": "vakya_id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Receipt record"
                        },
                        "404": {
                            "description": "Receipt not found"
                        }
                    }
                }
            },
            "/v1/vakya/{vakya_id}/effects": {
                "get": {
                    "summary": "Get effects for a VĀKYA",
                    "operationId": "getEffects",
                    "tags": ["VĀKYA"],
                    "parameters": [
                        {
                            "name": "vakya_id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of effect records"
                        }
                    }
                }
            },
            "/v1/merkle/root": {
                "get": {
                    "summary": "Get Merkle tree root",
                    "operationId": "getMerkleRoot",
                    "tags": ["Transparency"],
                    "parameters": [
                        {
                            "name": "tree_type",
                            "in": "query",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "enum": ["vakya", "effect", "receipt"]
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Merkle root"
                        }
                    }
                }
            },
            "/v1/merkle/proof": {
                "get": {
                    "summary": "Get inclusion proof",
                    "operationId": "getInclusionProof",
                    "tags": ["Transparency"],
                    "parameters": [
                        {
                            "name": "tree_type",
                            "in": "query",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "enum": ["vakya", "effect", "receipt"]
                            }
                        },
                        {
                            "name": "leaf_index",
                            "in": "query",
                            "required": true,
                            "schema": {
                                "type": "integer"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Inclusion proof"
                        },
                        "404": {
                            "description": "Proof not found"
                        }
                    }
                }
            },
            "/v1/adapters": {
                "get": {
                    "summary": "List registered adapters",
                    "operationId": "listAdapters",
                    "tags": ["Adapters"],
                    "responses": {
                        "200": {
                            "description": "List of adapters"
                        }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Get gateway metrics",
                    "operationId": "getMetrics",
                    "tags": ["System"],
                    "responses": {
                        "200": {
                            "description": "Gateway metrics"
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "HealthResponse": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string" },
                        "gateway_id": { "type": "string" },
                        "version": { "type": "string" },
                        "timestamp": { "type": "string", "format": "date-time" }
                    }
                },
                "SubmitVakyaRequest": {
                    "type": "object",
                    "required": ["vakya"],
                    "properties": {
                        "vakya": { "$ref": "#/components/schemas/Vakya" },
                        "signature": { "type": "string" },
                        "key_id": { "type": "string" }
                    }
                },
                "SubmitVakyaResponse": {
                    "type": "object",
                    "properties": {
                        "vakya_id": { "type": "string" },
                        "vakya_hash": { "type": "string" },
                        "status": { "type": "string" },
                        "receipt": { "$ref": "#/components/schemas/Receipt" },
                        "merkle_root": { "type": "string" },
                        "leaf_index": { "type": "integer" }
                    }
                },
                "Vakya": {
                    "type": "object",
                    "description": "VĀKYA - Agentic Action Request envelope"
                },
                "Receipt": {
                    "type": "object",
                    "description": "PRAMĀṆA - Execution receipt"
                }
            }
        },
        "tags": [
            { "name": "System", "description": "System operations" },
            { "name": "VĀKYA", "description": "VĀKYA submission and retrieval" },
            { "name": "Transparency", "description": "Transparency log operations" },
            { "name": "Adapters", "description": "Adapter management" }
        ]
    }))
}
