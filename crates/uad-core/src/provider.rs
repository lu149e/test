//! Provider contract.
//!
//! A provider *discovers* what a source offers for a package and returns concrete download
//! descriptions. It never writes to storage: transfer, verification and persistence belong to
//! the engine, so every provider benefits from the same resumable downloader, hashing,
//! deduplication and provenance logging.

use crate::offer::{Discovery, DiscoveryRequest};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// First-party store or official API (Google Play, Play Developer API).
    Official,
    /// Authorised repository with its own signed index (F-Droid).
    AuthorizedRepository,
    /// Files supplied by the operator (imports, emulator pulls).
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    pub enabled: bool,
    pub requires_credentials: bool,
    /// Lower value = tried first.
    pub priority: i32,
    pub description: String,
    /// Why it is disabled or which limitations apply.
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("package not available from this provider")]
    NotFound,
    #[error("provider is not configured: {0}")]
    NotConfigured(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("access denied by the source: {0}")]
    Denied(String),
    #[error("transient error (retryable): {0}")]
    Transient(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("integrity error: {0}")]
    Integrity(String),
    #[error("{0}")]
    Other(String),
}

impl ProviderError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, ProviderError::Transient(_))
    }
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn info(&self) -> ProviderInfo;

    fn id(&self) -> String {
        self.info().id
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError>;
}
