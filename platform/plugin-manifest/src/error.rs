use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("semver: {0}")]
    Semver(String),
    #[error("manifest: {0}")]
    Invalid(String),
    #[error("plugin.id must be '<vendor>/<slug>' with non-empty parts (got {0:?})")]
    InvalidId(String),
    #[error("reserved id prefix 'connector/' is only for first-party plugins (author={author:?}, id={id:?})")]
    ReservedVendorNamespace { id: String, author: String },
    #[error("capabilities.required must not use wildcard network host (got {0:?})")]
    WildcardNetworkCapability(String),
}
