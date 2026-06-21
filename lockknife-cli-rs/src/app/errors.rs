use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, LockKnifeError>;

#[derive(Debug, Error)]
pub enum LockKnifeError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("feature deferred: {feature}. {reason}")]
    FeatureDeferred {
        feature: &'static str,
        reason: &'static str,
    },
    #[error("command failed: {program} {args:?}: {stderr}")]
    CommandFailed {
        program: String,
        args: Vec<String>,
        stderr: String,
    },
    #[error("device selection error: {0}")]
    DeviceSelection(String),
    #[error("missing required file: {0}")]
    MissingFile(PathBuf),
}

impl LockKnifeError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn deferred(feature: &'static str, reason: &'static str) -> Self {
        Self::FeatureDeferred { feature, reason }
    }
}
