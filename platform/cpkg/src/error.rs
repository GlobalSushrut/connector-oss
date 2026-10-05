use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpkgError {
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("manifest: {0}")]
    Manifest(#[from] connector_plugin_manifest::ManifestError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("utf8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("missing required file `{0}` in package")]
    MissingFile(&'static str),

    #[error("duplicate path `{0}` in package")]
    DuplicatePath(String),

    #[error("forbidden archive path `{0}`")]
    ForbiddenPath(String),

    #[error("{0}")]
    Invalid(&'static str),

    #[error("cpkg signature verification failed")]
    SignatureInvalid,

    #[error("no trusted public key registered for key_id `{0}`")]
    TrustKeyNotFound(String),
}
