use std::path::PathBuf;
use thiserror::Error;

/// Typed errors returned by `firmlens-core` operations.
/// Never includes secret values, credential literals, or raw source lines.
#[derive(Debug, Error)]
pub enum FirmLensError {
    #[error("input path does not exist or cannot be accessed: {path}")]
    InputNotFound { path: PathBuf },

    #[error("invalid scan configuration: {reason}")]
    InvalidConfiguration { reason: String },

    #[error("archive ingestion rejected ({code}): {message}")]
    IngestionRejected { code: String, message: String },

    #[error("ingestion deadline exceeded after {timeout_ms} ms")]
    IngestionTimeout { timeout_ms: u64 },

    #[error("temporary workspace cleanup failed at {path}: {reason}")]
    CleanupFailed { path: PathBuf, reason: String },

    #[error("I/O error on {path}: {reason}")]
    Io { path: PathBuf, reason: String },

    #[error("serialization error: {reason}")]
    Serialization { reason: String },
}
