use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceUri {
    Model { provider: String, model: String },
    ModelFallback,
    Tool { name: String, version: Option<String> },
    MemoryPersistent { namespace: String },
    MemoryEphemeral,
    PolicyPreset { name: String },
    PolicyCustom { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUriError {
    pub input: String,
    pub message: String,
}

impl fmt::Display for ResourceUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ResourceUriError {}

impl ResourceUri {
    pub fn parse(input: &str) -> Result<Self, ResourceUriError> {
        input.parse()
    }

    pub fn normalized_tool_id(&self) -> Option<String> {
        match self {
            Self::Tool { name, version } => match version {
                Some(version) => Some(format!("{}@{}", name, version)),
                None => Some(name.clone()),
            },
            _ => None,
        }
    }

    pub fn resolved_model(&self) -> Option<(String, String)> {
        match self {
            Self::Model { provider, model } => Some((provider.clone(), model.clone())),
            Self::ModelFallback => Some(select_fallback_model()),
            _ => None,
        }
    }

    pub fn policy_name(&self) -> Option<String> {
        match self {
            Self::PolicyPreset { name } | Self::PolicyCustom { name } => Some(name.clone()),
            _ => None,
        }
    }

    pub fn storage_uri(&self, memory_root: &Path) -> Option<String> {
        match self {
            Self::MemoryEphemeral => Some("memory".to_string()),
            Self::MemoryPersistent { namespace } => {
                let mut path = namespace_path(memory_root, namespace);
                path.set_extension("redb");
                Some(format!("redb:{}", path.display()))
            }
            _ => None,
        }
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model { provider, model } => write!(f, "model://{}/{}", provider, model),
            Self::ModelFallback => write!(f, "model://fallback"),
            Self::Tool { name, version } => {
                if let Some(version) = version {
                    write!(f, "tool://{}@{}", name, version)
                } else {
                    write!(f, "tool://{}", name)
                }
            }
            Self::MemoryPersistent { namespace } => write!(f, "memory://persistent/{}", namespace),
            Self::MemoryEphemeral => write!(f, "memory://ephemeral"),
            Self::PolicyPreset { name } => write!(f, "policy://{}", name),
            Self::PolicyCustom { name } => write!(f, "policy://custom/{}", name),
        }
    }
}

impl FromStr for ResourceUri {
    type Err = ResourceUriError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some((scheme, rest)) = input.split_once("://") else {
            return Err(ResourceUriError {
                input: input.to_string(),
                message: format!("resource URI must contain '://': {}", input),
            });
        };

        match scheme {
            "model" => {
                if rest == "fallback" {
                    return Ok(Self::ModelFallback);
                }
                let Some((provider, model)) = rest.split_once('/') else {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("model URI must be model://<provider>/<model>: {}", input),
                    });
                };
                if provider.is_empty() || model.is_empty() {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("model URI must include provider and model: {}", input),
                    });
                }
                Ok(Self::Model {
                    provider: provider.to_string(),
                    model: model.to_string(),
                })
            }
            "tool" => {
                if rest.is_empty() {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("tool URI must be tool://<name> or tool://<name>@<version>: {}", input),
                    });
                }
                let (name, version) = match rest.split_once('@') {
                    Some((name, version)) => (name, Some(version.to_string())),
                    None => (rest, None),
                };
                if name.is_empty() {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("tool URI is missing a tool name: {}", input),
                    });
                }
                Ok(Self::Tool {
                    name: name.to_string(),
                    version,
                })
            }
            "memory" => {
                if rest == "ephemeral" {
                    return Ok(Self::MemoryEphemeral);
                }
                let Some(namespace) = rest.strip_prefix("persistent/") else {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("memory URI must be memory://persistent/<namespace> or memory://ephemeral: {}", input),
                    });
                };
                if namespace.is_empty() {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("memory URI is missing a namespace: {}", input),
                    });
                }
                Ok(Self::MemoryPersistent {
                    namespace: namespace.to_string(),
                })
            }
            "policy" => {
                if let Some(name) = rest.strip_prefix("custom/") {
                    if name.is_empty() {
                        return Err(ResourceUriError {
                            input: input.to_string(),
                            message: format!("custom policy URI is missing a policy name: {}", input),
                        });
                    }
                    return Ok(Self::PolicyCustom {
                        name: name.to_string(),
                    });
                }
                if rest.is_empty() {
                    return Err(ResourceUriError {
                        input: input.to_string(),
                        message: format!("policy URI must be policy://<name> or policy://custom/<name>: {}", input),
                    });
                }
                Ok(Self::PolicyPreset {
                    name: rest.to_string(),
                })
            }
            _ => Err(ResourceUriError {
                input: input.to_string(),
                message: format!("unsupported resource URI scheme '{}': {}", scheme, input),
            }),
        }
    }
}

pub trait Resource: fmt::Debug + Send + Sync {
    fn uri(&self) -> String;
    fn kind(&self) -> &'static str;
    fn target(&self) -> String;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedResource {
    pub uri: ResourceUri,
    pub target: String,
}

impl Resource for ResolvedResource {
    fn uri(&self) -> String {
        self.uri.to_string()
    }

    fn kind(&self) -> &'static str {
        match self.uri {
            ResourceUri::Model { .. } | ResourceUri::ModelFallback => "model",
            ResourceUri::Tool { .. } => "tool",
            ResourceUri::MemoryPersistent { .. } | ResourceUri::MemoryEphemeral => "memory",
            ResourceUri::PolicyPreset { .. } | ResourceUri::PolicyCustom { .. } => "policy",
        }
    }

    fn target(&self) -> String {
        self.target.clone()
    }
}

pub trait ResourceResolver {
    fn resolve(&self, uri: ResourceUri) -> Result<Box<dyn Resource>, String>;
}

#[derive(Debug, Clone)]
pub struct DefaultResourceResolver {
    memory_root: PathBuf,
}

impl Default for DefaultResourceResolver {
    fn default() -> Self {
        Self {
            memory_root: std::env::var("CONNECTOR_MEMORY_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(".connector/k")),
        }
    }
}

impl DefaultResourceResolver {
    pub fn new(memory_root: impl Into<PathBuf>) -> Self {
        Self {
            memory_root: memory_root.into(),
        }
    }
}

impl ResourceResolver for DefaultResourceResolver {
    fn resolve(&self, uri: ResourceUri) -> Result<Box<dyn Resource>, String> {
        let target = match &uri {
            ResourceUri::Model { provider, model } => format!("{}/{}", provider, model),
            ResourceUri::ModelFallback => {
                let (provider, model) = select_fallback_model();
                format!("{}/{}", provider, model)
            }
            ResourceUri::Tool { .. } => uri.normalized_tool_id().unwrap_or_default(),
            ResourceUri::MemoryPersistent { .. } | ResourceUri::MemoryEphemeral => uri
                .storage_uri(&self.memory_root)
                .ok_or_else(|| format!("cannot resolve storage URI for {}", uri))?,
            ResourceUri::PolicyPreset { name } | ResourceUri::PolicyCustom { name } => name.clone(),
        };

        Ok(Box::new(ResolvedResource { uri, target }))
    }
}

fn namespace_path(memory_root: &Path, namespace: &str) -> PathBuf {
    let mut path = memory_root.to_path_buf();
    for segment in namespace.split('/') {
        if segment.is_empty() {
            continue;
        }
        let sanitized: String = segment
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        path.push(sanitized);
    }
    path
}

fn select_fallback_model() -> (String, String) {
    if std::env::var("GROQ_API_KEY").is_ok() {
        return ("groq".to_string(), "llama-3.1-8b-instant".to_string());
    }
    if std::env::var("GEMINI_API_KEY").is_ok() {
        return ("gemini".to_string(), "gemini-1.5-flash".to_string());
    }
    if std::env::var("OPENAI_API_KEY").is_ok() {
        return ("openai".to_string(), "gpt-4o-mini".to_string());
    }
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return ("anthropic".to_string(), "claude-3-5-haiku-latest".to_string());
    }
    ("openai".to_string(), "gpt-4o-mini".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_model_uri() {
        let uri = ResourceUri::parse("model://openai/gpt-4o").unwrap();
        assert_eq!(
            uri,
            ResourceUri::Model {
                provider: "openai".to_string(),
                model: "gpt-4o".to_string(),
            }
        );
    }

    #[test]
    fn parse_tool_uri_with_version() {
        let uri = ResourceUri::parse("tool://ehr_lookup@v2").unwrap();
        assert_eq!(
            uri,
            ResourceUri::Tool {
                name: "ehr_lookup".to_string(),
                version: Some("v2".to_string()),
            }
        );
    }

    #[test]
    fn parse_memory_uri() {
        let uri = ResourceUri::parse("memory://persistent/org/team").unwrap();
        assert_eq!(
            uri,
            ResourceUri::MemoryPersistent {
                namespace: "org/team".to_string(),
            }
        );
    }

    #[test]
    fn resolve_memory_uri_to_redb_storage() {
        let resolver = DefaultResourceResolver::new("/tmp/connector-k");
        let resource = resolver
            .resolve(ResourceUri::parse("memory://persistent/ns:test/demo").unwrap())
            .unwrap();
        assert!(resource.target().starts_with("redb:/tmp/connector-k/"));
        assert!(resource.target().ends_with("demo.redb"));
    }
}
