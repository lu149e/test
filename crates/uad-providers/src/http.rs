//! Shared HTTP client construction and helpers.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use uad_core::{ProviderError, Sha256Digest};

pub const USER_AGENT: &str = concat!("uad/", env!("CARGO_PKG_VERSION"), " (+https://github.com/lu149e/test)");

/// Client honouring `HTTPS_PROXY`/`NO_PROXY` and the platform trust store
/// (`SSL_CERT_FILE` is respected by the native root loader).
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(600))
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client configuration is static and valid")
}

pub fn map_err(e: reqwest::Error) -> ProviderError {
    if e.is_timeout() || e.is_connect() || e.is_request() {
        ProviderError::Transient(e.to_string())
    } else if let Some(s) = e.status() {
        status_error(s, &e.to_string())
    } else {
        ProviderError::Other(e.to_string())
    }
}

pub fn status_error(s: reqwest::StatusCode, ctx: &str) -> ProviderError {
    match s.as_u16() {
        404 | 410 => ProviderError::NotFound,
        401 => ProviderError::Auth(ctx.to_string()),
        403 => ProviderError::Denied(ctx.to_string()),
        408 | 425 | 429 | 500..=599 => ProviderError::Transient(format!("HTTP {s}: {ctx}")),
        _ => ProviderError::Protocol(format!("HTTP {s}: {ctx}")),
    }
}

/// Downloads `url` to `dest` (via a temporary file), verifying size and SHA-256 when given.
pub async fn download_verified(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_sha256: Option<&Sha256Digest>,
    expected_size: Option<u64>,
) -> Result<Sha256Digest, ProviderError> {
    let resp = client.get(url).send().await.map_err(map_err)?;
    if !resp.status().is_success() {
        return Err(status_error(resp.status(), url));
    }
    let tmp = dest.with_extension("part");
    let mut file = tokio::fs::File::create(&tmp).await.map_err(|e| ProviderError::Other(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await.map_err(map_err)? {
        total += chunk.len() as u64;
        if let Some(max) = expected_size {
            if total > max {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(ProviderError::Integrity(format!("{url}: larger than the declared {max} bytes")));
            }
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| ProviderError::Other(e.to_string()))?;
    }
    file.flush().await.map_err(|e| ProviderError::Other(e.to_string()))?;
    drop(file);
    let digest = Sha256Digest(hasher.finalize().into());
    if let Some(sz) = expected_size {
        if sz != total {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(ProviderError::Integrity(format!("{url}: size {total} != declared {sz}")));
        }
    }
    if let Some(exp) = expected_sha256 {
        if exp != &digest {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(ProviderError::Integrity(format!("{url}: SHA-256 {digest} != declared {exp}")));
        }
    }
    tokio::fs::rename(&tmp, dest).await.map_err(|e| ProviderError::Other(e.to_string()))?;
    Ok(digest)
}
