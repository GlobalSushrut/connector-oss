//! # LLM Client — Dynamic Multi-Provider
//!
//! Supports ALL major providers + custom endpoints.
//! Provider/model/key are fully dynamic at runtime.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

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
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "default_tool_type")]
    pub call_type: String,
    pub function: ToolFunction,
}

fn default_tool_type() -> String {
    "function".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// DeepSeek-R1 / reasoning models: opaque chain-of-thought to pass back on tool loops.
    /// Never treat as auditable memory — session continuity only (LTL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    /// Assistant tool_calls for multi-turn tool loops (OpenAI/DeepSeek shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Tool result message: correlates to assistant tool_call id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
            reasoning_content: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning_content = Some(reasoning.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub text: String,
    pub model: String,
    pub provider: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub finish_reason: String,
    /// Provider reasoning to pass back on subsequent turns (DeepSeek etc.).
    pub reasoning_content: Option<String>,
    /// Provider tool_calls — treated as Cognitive Proposal Objects by Connector, never authority.
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl LlmResponse {
    pub fn plain(
        text: String,
        model: String,
        provider: String,
        input_tokens: u32,
        output_tokens: u32,
        finish_reason: String,
    ) -> Self {
        Self {
            text,
            model,
            provider,
            input_tokens,
            output_tokens,
            finish_reason,
            reasoning_content: None,
            tool_calls: None,
        }
    }
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
#[derive(Deserialize)] struct OaiMsg {
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ToolCall>>,
}
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

/// Pin outbound LLM HTTP to the first resolved IP (SSRF hardening). Off when
/// `CONNECTOR_LLM_DNS_PIN=0` — recommended on shared cloud VMs (CDN rotation).
pub fn dns_pin_enabled() -> bool {
    !matches!(
        std::env::var("CONNECTOR_LLM_DNS_PIN").ok().as_deref(),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

pub fn llm_http_timeout() -> Duration {
    std::env::var("CONNECTOR_LLM_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

pub fn llm_connect_timeout() -> Duration {
    std::env::var("CONNECTOR_LLM_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
}

pub struct LlmClient { http: reqwest::Client }

impl LlmClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(llm_http_timeout())
            .connect_timeout(llm_connect_timeout())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http }
    }

    pub async fn chat(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        match cfg.api_format() {
            ApiFormat::OpenAi => self.openai(cfg, msgs).await,
            ApiFormat::Anthropic => self.anthropic(cfg, msgs).await,
            ApiFormat::Gemini => self.gemini(cfg, msgs).await,
        }
    }

    pub async fn complete(&self, cfg: &LlmConfig, input: &str, sys: Option<&str>) -> Result<LlmResponse, LlmError> {
        let mut m = Vec::new();
        if let Some(s) = sys.or(cfg.system_prompt.as_deref()) {
            m.push(ChatMessage::new("system", s));
        }
        m.push(ChatMessage::new("user", input));
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

    fn parse_url_host_port(url: &str) -> Option<(String, u16)> {
        let s = url.trim();
        let https = s.starts_with("https://");
        let rest = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://"))?;
        let default = if https { 443 } else { 80 };
        let authority = rest.split('/').next()?.split('?').next()?.split('#').next()?;
        let hostport = authority.rsplit('@').next()?.trim();
        if let Some(inner) = hostport.strip_prefix('[') {
            let (host, after) = inner.split_once(']')?;
            let port = after.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default);
            return Some((host.to_ascii_lowercase(), port));
        }
        if let Some((h, p)) = hostport.rsplit_once(':') {
            if p.chars().all(|c| c.is_ascii_digit()) {
                return Some((h.to_ascii_lowercase(), p.parse().unwrap_or(default)));
            }
        }
        Some((hostport.to_ascii_lowercase(), default))
    }

    fn pin_socket(host: &str, port: u16) -> Result<SocketAddr, String> {
        static PINS: OnceLock<Mutex<BTreeMap<String, Vec<IpAddr>>>> = OnceLock::new();
        let host = host.trim().trim_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let mut resolved: Vec<IpAddr> = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            resolved.push(ip);
        } else if let Ok(addrs) = (host.as_str(), port).to_socket_addrs() {
            for addr in addrs {
                resolved.push(addr.ip());
            }
        }
        resolved.sort();
        resolved.dedup();
        if resolved.is_empty() {
            return Err("llm_dns_unresolved".into());
        }
        let store = PINS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut g = store.lock().unwrap_or_else(|e| e.into_inner());
        let ips = match g.get(&host) {
            None => {
                g.insert(host.clone(), resolved.clone());
                resolved
            }
            Some(pin) => {
                if resolved.iter().any(|ip| !pin.contains(ip)) {
                    return Err("llm_dns_pin_mismatch".into());
                }
                pin.clone()
            }
        };
        let ip = ips.first().copied().ok_or_else(|| "llm_dns_unresolved".to_string())?;
        Ok(SocketAddr::new(ip, port))
    }

    fn http_for_url(&self, url: &str) -> Result<reqwest::Client, LlmError> {
        if !dns_pin_enabled() {
            return Ok(self.http.clone());
        }
        let Some((host, port)) = Self::parse_url_host_port(url) else {
            return Ok(self.http.clone());
        };
        let addr = Self::pin_socket(&host, port).map_err(|e| LlmError {
            message: e,
            status: None,
            provider: "dns_pin".into(),
        })?;
        reqwest::Client::builder()
            .timeout(llm_http_timeout())
            .connect_timeout(llm_connect_timeout())
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&host, addr)
            .build()
            .map_err(|e| LlmError {
                message: e.to_string(),
                status: None,
                provider: "dns_pin".into(),
            })
    }

    async fn openai(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/chat/completions", cfg.base_url());
        let body = OaiReq { model: cfg.model.clone(), messages: msgs, max_tokens: cfg.max_tokens, temperature: cfg.temperature };
        let resp = self.http_for_url(&url)?.post(&url).header("Authorization", format!("Bearer {}", cfg.api_key)).json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: OaiResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let ch = d.choices.unwrap_or_default();
        let c = ch.first().ok_or_else(|| self.err(cfg, "no choices", Some(st)))?;
        let u = d.usage.as_ref();
        Ok(LlmResponse {
            text: c.message.content.clone().unwrap_or_default(),
            model: d.model.unwrap_or(cfg.model.clone()),
            provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.prompt_tokens).unwrap_or(0),
            output_tokens: u.and_then(|x| x.completion_tokens).unwrap_or(0),
            finish_reason: c.finish_reason.clone().unwrap_or("stop".into()),
            reasoning_content: c.message.reasoning_content.clone(),
            tool_calls: c.message.tool_calls.clone(),
        })
    }

    async fn anthropic(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/messages", cfg.base_url());
        let (mut sys, mut um) = (None, Vec::new());
        for m in msgs { if m.role == "system" { sys = Some(m.content); } else { um.push(m); } }
        let body = AntReq { model: cfg.model.clone(), messages: um, max_tokens: cfg.max_tokens, system: sys };
        let resp = self.http_for_url(&url)?.post(&url).header("x-api-key", &cfg.api_key).header("anthropic-version", "2023-06-01").json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: AntResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let txt = d.content.as_ref().and_then(|c| c.first()).and_then(|c| c.text.clone()).unwrap_or_default();
        let u = d.usage.as_ref();
        Ok(LlmResponse {
            text: txt,
            model: d.model.unwrap_or(cfg.model.clone()),
            provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.input_tokens).unwrap_or(0),
            output_tokens: u.and_then(|x| x.output_tokens).unwrap_or(0),
            finish_reason: d.stop_reason.unwrap_or("end_turn".into()),
            reasoning_content: None,
            tool_calls: None, // Anthropic tool_use is handled on the platform Anthropic gateway path
        })
    }

    async fn gemini(&self, cfg: &LlmConfig, msgs: Vec<ChatMessage>) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/models/{}:generateContent?key={}", cfg.base_url(), cfg.model, cfg.api_key);
        let (mut si, mut contents) = (None, Vec::new());
        for m in msgs {
            if m.role == "system" { si = Some(GemContent { role: None, parts: vec![GemPart { text: m.content }] }); }
            else { contents.push(GemContent { role: Some(if m.role == "assistant" { "model" } else { "user" }.into()), parts: vec![GemPart { text: m.content }] }); }
        }
        let body = GemReq { contents, system_instruction: si, generation_config: GemCfg { max_output_tokens: cfg.max_tokens, temperature: cfg.temperature } };
        let resp = self.http_for_url(&url)?.post(&url).json(&body).send().await.map_err(|e| self.err(cfg, &e.to_string(), None))?;
        let st = resp.status().as_u16();
        let d: GemResp = resp.json().await.map_err(|e| self.err(cfg, &e.to_string(), Some(st)))?;
        if let Some(e) = d.error { return Err(self.err(cfg, e.message.as_deref().unwrap_or("error"), Some(st))); }
        let cands = d.candidates.unwrap_or_default();
        let txt = cands.first().and_then(|c| c.content.as_ref()).and_then(|c| c.parts.first()).map(|p| p.text.clone()).unwrap_or_default();
        let fin = cands.first().and_then(|c| c.finish_reason.clone()).unwrap_or("STOP".into());
        let u = d.usage_metadata.as_ref();
        Ok(LlmResponse {
            text: txt,
            model: cfg.model.clone(),
            provider: cfg.provider.clone(),
            input_tokens: u.and_then(|x| x.prompt_token_count).unwrap_or(0),
            output_tokens: u.and_then(|x| x.candidates_token_count).unwrap_or(0),
            finish_reason: fin,
            reasoning_content: None,
            tool_calls: None,
        })
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
