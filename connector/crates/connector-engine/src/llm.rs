//! # LLM Client — Dynamic Multi-Provider
//!
//! Supports ALL major providers + custom endpoints.
//! Provider/model/key are fully dynamic at runtime.

use serde::{Deserialize, Serialize};

// ── Config ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub endpoint: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub system_prompt: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApiFormat { OpenAi, Anthropic, Gemini }

impl LlmConfig {
    pub fn new(provider: &str, model: &str, api_key: &str) -> Self {
        Self { provider: provider.into(), model: model.into(), api_key: api_key.into(),
               endpoint: None, max_tokens: 4096, temperature: 0.7, system_prompt: None }
    }
    pub fn from_llm_string(llm: &str, api_key: &str) -> Self {
        let p: Vec<&str> = llm.splitn(2, ':').collect();
        if p.len() == 2 { Self::new(p[0], p[1], api_key) } else { Self::new("openai", llm, api_key) }
    }
    pub fn custom(endpoint: &str, model: &str, token: &str) -> Self {
        let mut c = Self::new("custom", model, token);
        c.endpoint = Some(endpoint.trim_end_matches('/').into()); c
    }
    pub fn from_env() -> Self {
        Self {
            provider: std::env::var("CONNECTOR_LLM_PROVIDER").unwrap_or("openai".into()),
            model: std::env::var("CONNECTOR_LLM_MODEL").unwrap_or("gpt-4o".into()),
            api_key: std::env::var("CONNECTOR_LLM_API_KEY").unwrap_or_default(),
            endpoint: std::env::var("CONNECTOR_LLM_ENDPOINT").ok(),
            max_tokens: 4096, temperature: 0.7, system_prompt: None,
        }
    }
    pub fn with_endpoint(mut self, e: &str) -> Self { self.endpoint = Some(e.trim_end_matches('/').into()); self }
    pub fn with_max_tokens(mut self, n: u32) -> Self { self.max_tokens = n; self }
    pub fn with_temperature(mut self, t: f32) -> Self { self.temperature = t; self }
    pub fn with_system(mut self, s: &str) -> Self { self.system_prompt = Some(s.into()); self }

    pub fn base_url(&self) -> String {
        if let Some(ref ep) = self.endpoint { return ep.clone(); }
        match self.provider.as_str() {
            "openai"     => "https://api.openai.com/v1",
            "anthropic"  => "https://api.anthropic.com/v1",
            "gemini"     => "https://generativelanguage.googleapis.com/v1beta",
            "deepseek"   => "https://api.deepseek.com/v1",
            "groq"       => "https://api.groq.com/openai/v1",
            "together"   => "https://api.together.xyz/v1",
            "mistral"    => "https://api.mistral.ai/v1",
            "cohere"     => "https://api.cohere.com/v2",
            "fireworks"  => "https://api.fireworks.ai/inference/v1",
            "perplexity" => "https://api.perplexity.ai",
            "openrouter" => "https://openrouter.ai/api/v1",
            "ollama"     => "http://localhost:11434/v1",
            "lmstudio"   => "http://localhost:1234/v1",
            "vllm"       => "http://localhost:8000/v1",
            _            => "https://api.openai.com/v1",
        }.into()
    }
    pub fn api_format(&self) -> ApiFormat {
        match self.provider.as_str() {
            "anthropic" => ApiFormat::Anthropic,
            "gemini" => ApiFormat::Gemini,
            _ => ApiFormat::OpenAi,
        }
    }
}

// ── Messages ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage { pub role: String, pub content: String }

#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub text: String, pub model: String, pub provider: String,
    pub input_tokens: u32, pub output_tokens: u32, pub finish_reason: String,
}

#[derive(Debug, Clone)]
pub struct LlmError { pub message: String, pub status: Option<u16>, pub provider: String }
impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LLM[{}]: {}", self.provider, self.message)
    }
}
impl std::error::Error for LlmError {}

// ── OpenAI types ─────────────────────────────────────────────

#[derive(Serialize)] struct OaiReq { model: String, messages: Vec<ChatMessage>, max_tokens: u32, temperature: f32 }
#[derive(Deserialize)] struct OaiResp { choices: Option<Vec<OaiChoice>>, model: Option<String>, usage: Option<OaiUsage>, error: Option<ErrBody> }
#[derive(Deserialize)] struct OaiChoice { message: OaiMsg, finish_reason: Option<String> }
#[derive(Deserialize)] struct OaiMsg { content: Option<String> }
#[derive(Deserialize)] struct OaiUsage { prompt_tokens: Option<u32>, completion_tokens: Option<u32> }

// ── Anthropic types ──────────────────────────────────────────

#[derive(Serialize)] struct AntReq { model: String, messages: Vec<ChatMessage>, max_tokens: u32, #[serde(skip_serializing_if = "Option::is_none")] system: Option<String> }
#[derive(Deserialize)] struct AntResp { content: Option<Vec<AntContent>>, model: Option<String>, usage: Option<AntUsage>, stop_reason: Option<String>, error: Option<ErrBody> }
#[derive(Deserialize)] struct AntContent { text: Option<String> }
#[derive(Deserialize)] struct AntUsage { input_tokens: Option<u32>, output_tokens: Option<u32> }

// ── Gemini types ─────────────────────────────────────────────

#[derive(Serialize)] struct GemReq { contents: Vec<GemContent>, #[serde(skip_serializing_if = "Option::is_none")] system_instruction: Option<GemContent>, #[serde(rename = "generationConfig")] generation_config: GemCfg }
#[derive(Serialize, Deserialize)] struct GemContent { #[serde(skip_serializing_if = "Option::is_none")] role: Option<String>, parts: Vec<GemPart> }
#[derive(Serialize, Deserialize)] struct GemPart { text: String }
#[derive(Serialize)] struct GemCfg { #[serde(rename = "maxOutputTokens")] max_output_tokens: u32, temperature: f32 }
#[derive(Deserialize)] struct GemResp { candidates: Option<Vec<GemCand>>, #[serde(rename = "usageMetadata")] usage_metadata: Option<GemUsage>, error: Option<ErrBody> }
#[derive(Deserialize)] struct GemCand { content: Option<GemContent>, #[serde(rename = "finishReason")] finish_reason: Option<String> }
#[derive(Deserialize)] struct GemUsage { #[serde(rename = "promptTokenCount")] prompt_token_count: Option<u32>, #[serde(rename = "candidatesTokenCount")] candidates_token_count: Option<u32> }

#[derive(Deserialize)] struct ErrBody { message: Option<String> }

// ── Client ───────────────────────────────────────────────────

pub struct LlmClient { http: reqwest::Client }

impl LlmClient {
    pub fn new() -> Self { Self { http: reqwest::Client::new() } }

    pub async fn chat(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        match cfg.api_format() {
            ApiFormat::OpenAi => self.openai(cfg, msgs).await,
            ApiFormat::Anthropic => self.anthropic(cfg, msgs).await,
            ApiFormat::Gemini => self.gemini(cfg, msgs).await,
        }
    }

    pub async fn complete(&self, cfg: &LlmConfig, input: &str, sys: Option<&str>) -> Result<LlmResponse, LlmError> {
        let mut m = Vec::new();
        if let Some(s) = sys.or(cfg.system_prompt.as_deref()) { m.push(ChatMessage { role: "system".into(), content: s.into() }); }
        m.push(ChatMessage { role: "user".into(), content: input.into() });
        self.chat(cfg, m).await
    }

    pub fn complete_sync(&self, cfg: &LlmConfig, input: &str, sys: Option<&str>) -> Result<LlmResponse, LlmError> {
        tokio::runtime::Runtime::new()
            .map_err(|e| LlmError { message: e.to_string(), status: None, provider: cfg.provider.clone() })?
            .block_on(self.complete(cfg, input, sys))
    }

    fn err(&self, cfg: &LlmConfig, msg: &str, st: Option<u16>) -> LlmError {
        LlmError { message: msg.into(), status: st, provider: cfg.provider.clone() }
    }

    async fn openai(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/chat/completions", cfg.base_url());
        let body = OaiReq { model: cfg.model.clone(), messages: msgs, max_tokens: cfg.max_tokens, temperature: cfg.temperature };
        let resp = self.http.post(&url).header("Authorization", format!("Bearer {}", cfg.api_key)).json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: OaiResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let ch = d.choices.unwrap_or_default();
        let c = ch.first().ok_or_else(|| self.err(cfg, "no choices", Some(st)))?;
        let u = d.usage.as_ref();
        Ok(LlmResponse { text: c.message.content.clone().unwrap_or_default(), model: d.model.unwrap_or(cfg.model.clone()), provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.prompt_tokens).unwrap_or(0), output_tokens: u.and_then(|x| x.completion_tokens).unwrap_or(0), finish_reason: c.finish_reason.clone().unwrap_or("stop".into()) })
    }

    async fn anthropic(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/messages", cfg.base_url());
        let (mut sys, mut um) = (None, Vec::new());
        for m in msgs { if m.role == "system" { sys = Some(m.content); } else { um.push(m); } }
        let body = AntReq { model: cfg.model.clone(), messages: um, max_tokens: cfg.max_tokens, system: sys };
        let resp = self.http.post(&url).header("x-api-key", &cfg.api_key).header("anthropic-version", "2023-06-01").json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: AntResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let txt = d.content.as_ref().and_then(|c| c.first()).and_then(|c| c.text.clone()).unwrap_or_default();
        let u = d.usage.as_ref();
        Ok(LlmResponse { text: txt, model: d.model.unwrap_or(cfg.model.clone()), provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.input_tokens).unwrap_or(0), output_tokens: u.and_then(|x| x.output_tokens).unwrap_or(0), finish_reason: d.stop_reason.unwrap_or("end_turn".into()) })
    }

    async fn gemini(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/models/{}:generateContent?key={}", cfg.base_url(), cfg.model, cfg.api_key);
        let (mut si, mut contents) = (None, Vec::new());
        for m in msgs {
            if m.role == "system" { si = Some(GemContent { role: None, parts: vec![GemPart { text: m.content }] }); }
            else { contents.push(GemContent { role: Some(if m.role == "assistant" { "model" } else { "user" }.into()), parts: vec![GemPart { text: m.content }] }); }
        }
        let body = GemReq { contents, system_instruction: si, generation_config: GemCfg { max_output_tokens: cfg.max_tokens, temperature: cfg.temperature } };
        let resp = self.http.post(&url).json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: GemResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let cands = d.candidates.unwrap_or_default();
        let txt = cands.first().and_then(|c| c.content.as_ref()).and_then(|c| c.parts.first()).map(|p| p.text.clone()).unwrap_or_default();
        let fin = cands.first().and_then(|c| c.finish_reason.clone()).unwrap_or("STOP".into());
        let u = d.usage_metadata.as_ref();
        Ok(LlmResponse { text: txt, model: cfg.model.clone(), provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.prompt_token_count).unwrap_or(0), output_tokens: u.and_then(|x| x.candidates_token_count).unwrap_or(0), finish_reason: fin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_providers() {
        let cases = vec![
            ("openai", "https://api.openai.com/v1", ApiFormat::OpenAi),
            ("anthropic", "https://api.anthropic.com/v1", ApiFormat::Anthropic),
            ("gemini", "https://generativelanguage.googleapis.com/v1beta", ApiFormat::Gemini),
            ("deepseek", "https://api.deepseek.com/v1", ApiFormat::OpenAi),
            ("groq", "https://api.groq.com/openai/v1", ApiFormat::OpenAi),
            ("together", "https://api.together.xyz/v1", ApiFormat::OpenAi),
            ("mistral", "https://api.mistral.ai/v1", ApiFormat::OpenAi),
            ("ollama", "http://localhost:11434/v1", ApiFormat::OpenAi),
            ("openrouter", "https://openrouter.ai/api/v1", ApiFormat::OpenAi),
        ];
        for (prov, url, fmt) in cases {
            let c = LlmConfig::new(prov, "m", "k");
            assert_eq!(c.base_url(), url, "provider: {}", prov);
            assert_eq!(c.api_format(), fmt, "provider: {}", prov);
        }
    }

    #[test]
    fn test_custom_endpoint() {
        let c = LlmConfig::custom("https://my-cloud.com/v1/", "my-model", "tok-123");
        assert_eq!(c.base_url(), "https://my-cloud.com/v1");
        assert_eq!(c.model, "my-model");
        assert_eq!(c.api_key, "tok-123");
        assert_eq!(c.api_format(), ApiFormat::OpenAi);
    }

    #[test]
    fn test_llm_string() {
        let c = LlmConfig::from_llm_string("anthropic:claude-3.5-sonnet", "k");
        assert_eq!(c.provider, "anthropic");
        assert_eq!(c.model, "claude-3.5-sonnet");
        let c2 = LlmConfig::from_llm_string("gpt-4o", "k");
        assert_eq!(c2.provider, "openai");
        assert_eq!(c2.model, "gpt-4o");
    }

    #[test]
    fn test_builder() {
        let c = LlmConfig::new("openai", "gpt-4o", "k")
            .with_system("You help").with_temperature(0.3).with_max_tokens(2048);
        assert_eq!(c.system_prompt.as_deref(), Some("You help"));
        assert_eq!(c.temperature, 0.3);
        assert_eq!(c.max_tokens, 2048);
    }
}
