//! # Zero-Config Auto-Detection
//!
//! Detects LLM provider, model, and API key from environment variables.
//! The developer writes ZERO config — we figure it out.
//!
//! ## Priority Order
//!
//! 1. `OPENAI_API_KEY`     → openai / gpt-4o
//! 2. `ANTHROPIC_API_KEY`  → anthropic / claude-sonnet-4-20250514
//! 3. `DEEPSEEK_API_KEY`   → deepseek / deepseek-chat
//! 4. `GOOGLE_API_KEY`     → google / gemini-2.0-flash
//! 5. `GROQ_API_KEY`       → groq / llama-3.3-70b-versatile
//! 6. `MISTRAL_API_KEY`    → mistral / mistral-large-latest
//! 7. `TOGETHER_API_KEY`   → together / meta-llama/Llama-3.3-70B-Instruct-Turbo
//! 8. `FIREWORKS_API_KEY`  → fireworks / accounts/fireworks/models/llama-v3p3-70b-instruct
//! 9. `COHERE_API_KEY`     → cohere / command-r-plus
//! 10. `PERPLEXITY_API_KEY` → perplexity / llama-3.1-sonar-large-128k-online
//! 11. `XAI_API_KEY`       → xai / grok-2
//! 12. `OLLAMA_HOST`       → ollama / llama3.3 (local, no key needed)
//!
//! ## Usage
//!
//! ```rust,ignore
//! if let Some(detected) = auto_detect_llm() {
//!     println!("Provider: {}, Model: {}, Key: {}", detected.provider, detected.model, detected.api_key);
//! }
//! ```

/// Auto-detected LLM configuration from environment variables.
#[derive(Debug, Clone)]
pub struct DetectedLlm {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub endpoint: Option<String>,
}

/// A provider definition for auto-detection.
struct ProviderDef {
    env_var: &'static str,
    provider: &'static str,
    default_model: &'static str,
    endpoint: Option<&'static str>,
}

/// Priority-ordered list of providers to check.
const PROVIDERS: &[ProviderDef] = &[
    ProviderDef { env_var: "OPENAI_API_KEY",     provider: "openai",     default_model: "gpt-4o",                                                     endpoint: None },
    ProviderDef { env_var: "ANTHROPIC_API_KEY",   provider: "anthropic",  default_model: "claude-sonnet-4-20250514",                                    endpoint: None },
    ProviderDef { env_var: "DEEPSEEK_API_KEY",    provider: "deepseek",   default_model: "deepseek-chat",                                               endpoint: Some("https://api.deepseek.com/v1") },
    ProviderDef { env_var: "GOOGLE_API_KEY",      provider: "google",     default_model: "gemini-2.0-flash",                                            endpoint: None },
    ProviderDef { env_var: "GROQ_API_KEY",        provider: "groq",       default_model: "llama-3.3-70b-versatile",                                     endpoint: Some("https://api.groq.com/openai/v1") },
    ProviderDef { env_var: "MISTRAL_API_KEY",     provider: "mistral",    default_model: "mistral-large-latest",                                        endpoint: Some("https://api.mistral.ai/v1") },
    ProviderDef { env_var: "TOGETHER_API_KEY",    provider: "together",   default_model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",                     endpoint: Some("https://api.together.xyz/v1") },
    ProviderDef { env_var: "FIREWORKS_API_KEY",   provider: "fireworks",  default_model: "accounts/fireworks/models/llama-v3p3-70b-instruct",            endpoint: Some("https://api.fireworks.ai/inference/v1") },
    ProviderDef { env_var: "COHERE_API_KEY",      provider: "cohere",     default_model: "command-r-plus",                                              endpoint: None },
    ProviderDef { env_var: "PERPLEXITY_API_KEY",  provider: "perplexity", default_model: "llama-3.1-sonar-large-128k-online",                           endpoint: Some("https://api.perplexity.ai") },
    ProviderDef { env_var: "XAI_API_KEY",         provider: "xai",        default_model: "grok-2",                                                      endpoint: Some("https://api.x.ai/v1") },
];

/// Detect LLM provider, model, and API key from environment variables.
///
/// Checks env vars in priority order (OpenAI first, then Anthropic, etc.).
/// Returns `None` if no API key is found in any known env var.
///
/// For Ollama (local): checks `OLLAMA_HOST` env var. No API key needed.
pub fn auto_detect_llm() -> Option<DetectedLlm> {
    // Check each provider in priority order
    for p in PROVIDERS {
        if let Ok(key) = std::env::var(p.env_var) {
            if !key.is_empty() {
                return Some(DetectedLlm {
                    provider: p.provider.to_string(),
                    model: p.default_model.to_string(),
                    api_key: key,
                    endpoint: p.endpoint.map(|s| s.to_string()),
                });
            }
        }
    }

    // Special case: Ollama (local, no key needed)
    if let Ok(host) = std::env::var("OLLAMA_HOST") {
        if !host.is_empty() {
            return Some(DetectedLlm {
                provider: "ollama".to_string(),
                model: "llama3.3".to_string(),
                api_key: String::new(),
                endpoint: Some(host),
            });
        }
    }

    // Fallback: check if Ollama is running on default port
    // (don't block — just check env)
    None
}

/// Returns a human-readable list of which env vars to set.
pub fn detect_help() -> String {
    let mut lines = vec![
        "No LLM API key detected. Set one of these environment variables:".to_string(),
        String::new(),
    ];
    for p in PROVIDERS {
        lines.push(format!("  export {}=<your-key>    # → {} / {}", p.env_var, p.provider, p.default_model));
    }
    lines.push(String::new());
    lines.push("  export OLLAMA_HOST=http://localhost:11434    # → ollama / llama3.3 (local, free)".to_string());
    lines.push(String::new());
    lines.push("Tip: OpenAI and Anthropic are recommended for best results.".to_string());
    lines.join("\n")
}

/// Detect all available providers (for multi-provider setups).
pub fn detect_all_providers() -> Vec<DetectedLlm> {
    let mut found = Vec::new();
    for p in PROVIDERS {
        if let Ok(key) = std::env::var(p.env_var) {
            if !key.is_empty() {
                found.push(DetectedLlm {
                    provider: p.provider.to_string(),
                    model: p.default_model.to_string(),
                    api_key: key,
                    endpoint: p.endpoint.map(|s| s.to_string()),
                });
            }
        }
    }
    if let Ok(host) = std::env::var("OLLAMA_HOST") {
        if !host.is_empty() {
            found.push(DetectedLlm {
                provider: "ollama".to_string(),
                model: "llama3.3".to_string(),
                api_key: String::new(),
                endpoint: Some(host),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_help_output() {
        let help = detect_help();
        assert!(help.contains("OPENAI_API_KEY"));
        assert!(help.contains("ANTHROPIC_API_KEY"));
        assert!(help.contains("DEEPSEEK_API_KEY"));
        assert!(help.contains("OLLAMA_HOST"));
        assert!(help.contains("ollama"));
    }

    #[test]
    fn test_provider_table_has_all_entries() {
        assert!(PROVIDERS.len() >= 11);
        assert_eq!(PROVIDERS[0].provider, "openai");
        assert_eq!(PROVIDERS[1].provider, "anthropic");
        assert_eq!(PROVIDERS[2].provider, "deepseek");
        assert_eq!(PROVIDERS[0].default_model, "gpt-4o");
        assert!(PROVIDERS[1].default_model.contains("claude"));
        assert_eq!(PROVIDERS[2].default_model, "deepseek-chat");
    }

    #[test]
    fn test_provider_openai_has_no_endpoint() {
        assert!(PROVIDERS[0].endpoint.is_none());
    }

    #[test]
    fn test_provider_deepseek_has_endpoint() {
        assert!(PROVIDERS[2].endpoint.is_some());
        assert!(PROVIDERS[2].endpoint.unwrap().contains("deepseek"));
    }

    #[test]
    fn test_provider_groq_has_endpoint() {
        let groq = PROVIDERS.iter().find(|p| p.provider == "groq").unwrap();
        assert!(groq.endpoint.is_some());
        assert!(groq.endpoint.unwrap().contains("groq"));
    }

    #[test]
    fn test_all_providers_have_nonempty_fields() {
        for p in PROVIDERS {
            assert!(!p.env_var.is_empty());
            assert!(!p.provider.is_empty());
            assert!(!p.default_model.is_empty());
        }
    }

    #[test]
    fn test_detected_llm_struct() {
        let d = DetectedLlm {
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "sk-test".to_string(),
            endpoint: None,
        };
        assert_eq!(d.provider, "openai");
        assert_eq!(d.model, "gpt-4o");
        assert!(d.endpoint.is_none());
    }

    #[test]
    fn test_detect_help_contains_all_providers() {
        let help = detect_help();
        for p in PROVIDERS {
            assert!(help.contains(p.env_var), "Missing {} in help", p.env_var);
            assert!(help.contains(p.provider), "Missing {} in help", p.provider);
        }
    }
}
