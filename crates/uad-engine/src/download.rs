//! Resumable, verified downloads into the content-addressed store.
//!
//! * Partial data lives in `tmp/<key>.part`; retries continue with `Range` requests.
//! * SHA-256 and SHA-1 are computed while streaming; declared digests and sizes are enforced
//!   before a file is adopted into the object store.
//! * Transient failures (connect errors, 5xx, 429, truncated bodies) are retried with
//!   exponential backoff; integrity failures are not.

use crate::store::Store;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use uad_core::{ExpectedDigests, FileSource, Sha1Digest, Sha256Digest};

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("transient: {0}")]
    Transient(String),
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("rejected by server: {0}")]
    Rejected(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct Fetched {
    pub sha256: Sha256Digest,
    pub sha1: Sha1Digest,
    pub size: u64,
    pub path: PathBuf,
    /// Already present in the store before this download (deduplicated).
    pub deduplicated: bool,
    pub resumed_from: u64,
}

pub struct Downloader {
    /// One in-flight transfer per partial file (concurrent jobs may request the same URL).
    inflight: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    client: reqwest::Client,
    store: Arc<Store>,
    permits: Arc<Semaphore>,
    retries: u32,
    max_bytes: u64,
}

fn key_for(url: &str) -> String {
    hex::encode(&Sha256::digest(url.as_bytes())[..16])
}

impl Downloader {
    pub fn new(store: Arc<Store>, concurrency: usize, retries: u32, max_bytes: u64) -> Self {
        Self {
            inflight: Default::default(),
            client: uad_providers::http::client(),
            store,
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            retries,
            max_bytes,
        }
    }

    pub async fn fetch(&self, source: &FileSource, expected: &ExpectedDigests, size_hint: Option<u64>) -> Result<Fetched, DownloadError> {
        // Short-circuit: the declared SHA-256 is already stored.
        if let Some(sha) = &expected.sha256 {
            if self.store.artifact_known(sha).unwrap_or(false) {
                let path = self.store.object_path(sha);
                let (s256, s1, size) = hash_file(&path).await.map_err(|e| DownloadError::Other(e.to_string()))?;
                if &s256 == sha {
                    return Ok(Fetched {
                        sha256: s256,
                        sha1: s1,
                        size,
                        path,
                        deduplicated: true,
                        resumed_from: 0,
                    });
                }
                return Err(DownloadError::Integrity(format!("stored object {sha} is corrupt")));
            }
        }
        let _permit = self.permits.acquire().await.map_err(|e| DownloadError::Other(e.to_string()))?;
        match source {
            FileSource::Local { path } => self.import_local(path, expected).await,
            FileSource::Http { url, headers, .. } => {
                let key = key_for(url);
                let lock = self.inflight.lock().unwrap().entry(key.clone()).or_default().clone();
                let _guard = lock.lock().await;
                // Another job may have completed the same file meanwhile.
                if let Some(sha) = &expected.sha256 {
                    if self.store.artifact_known(sha).unwrap_or(false) {
                        let path = self.store.object_path(sha);
                        let (s256, s1, size) = hash_file(&path).await.map_err(|e| DownloadError::Other(e.to_string()))?;
                        return Ok(Fetched {
                            sha256: s256,
                            sha1: s1,
                            size,
                            path,
                            deduplicated: true,
                            resumed_from: 0,
                        });
                    }
                }
                let part = self.store.tmp_dir().join(format!("{key}.part"));
                let mut attempt = 0;
                loop {
                    match self.http_once(url, headers, &part, size_hint).await {
                        Ok(resumed_from) => return self.finish(&part, expected, size_hint, resumed_from).await,
                        Err(DownloadError::Transient(e)) if attempt < self.retries => {
                            attempt += 1;
                            let wait = Duration::from_millis(500 * 2u64.pow(attempt.min(6)));
                            tracing::warn!("download attempt {attempt} failed ({e}); retrying in {wait:?}");
                            tokio::time::sleep(wait).await;
                        }
                        Err(e) => {
                            if matches!(e, DownloadError::Integrity(_) | DownloadError::Rejected(_)) {
                                let _ = tokio::fs::remove_file(&part).await;
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    async fn http_once(&self, url: &str, headers: &[uad_core::Header], part: &Path, size_hint: Option<u64>) -> Result<u64, DownloadError> {
        let existing = tokio::fs::metadata(part).await.map(|m| m.len()).unwrap_or(0);
        if let Some(sz) = size_hint {
            if existing == sz && sz > 0 {
                return Ok(existing); // complete from a previous run; verified in finish()
            }
            if existing > sz {
                let _ = tokio::fs::remove_file(part).await;
            }
        }
        let existing = tokio::fs::metadata(part).await.map(|m| m.len()).unwrap_or(0);
        let mut req = self.client.get(url);
        for h in headers {
            req = req.header(&h.name, &h.value);
        }
        if existing > 0 {
            req = req.header("Range", format!("bytes={existing}-"));
        }
        let mut resp = req.send().await.map_err(|e| DownloadError::Transient(e.without_url().to_string()))?;
        let status = resp.status();
        let (mut file, resumed_from) = if status.as_u16() == 206 && existing > 0 {
            (
                tokio::fs::OpenOptions::new()
                    .append(true)
                    .open(part)
                    .await
                    .map_err(|e| DownloadError::Other(e.to_string()))?,
                existing,
            )
        } else if status.is_success() {
            (tokio::fs::File::create(part).await.map_err(|e| DownloadError::Other(e.to_string()))?, 0)
        } else if status.as_u16() == 416 && existing > 0 {
            return Ok(existing); // already complete
        } else if status.as_u16() == 429 || status.is_server_error() {
            return Err(DownloadError::Transient(format!("HTTP {status}")));
        } else {
            return Err(DownloadError::Rejected(format!("HTTP {status}")));
        };
        let mut written = resumed_from;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as u64;
                    if written > self.max_bytes || size_hint.is_some_and(|s| written > s) {
                        return Err(DownloadError::Integrity(format!("download exceeds expected size ({written} bytes)")));
                    }
                    file.write_all(&chunk).await.map_err(|e| DownloadError::Other(e.to_string()))?;
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = file.flush().await;
                    return Err(DownloadError::Transient(format!(
                        "connection interrupted after {written} bytes: {}",
                        e.without_url()
                    )));
                }
            }
        }
        file.flush().await.map_err(|e| DownloadError::Other(e.to_string()))?;
        if let Some(sz) = size_hint {
            if written < sz {
                return Err(DownloadError::Transient(format!("truncated body: {written}/{sz} bytes")));
            }
        }
        Ok(resumed_from)
    }

    async fn finish(&self, part: &Path, expected: &ExpectedDigests, size_hint: Option<u64>, resumed_from: u64) -> Result<Fetched, DownloadError> {
        let (sha256, sha1, size) = hash_file(part).await.map_err(|e| DownloadError::Other(e.to_string()))?;
        check_expected(&sha256, &sha1, size, expected, size_hint)?;
        let deduplicated = self.store.artifact_known(&sha256).unwrap_or(false);
        let path = self
            .store
            .adopt(part, &sha256, &sha1.to_hex(), size)
            .map_err(|e| DownloadError::Other(e.to_string()))?;
        Ok(Fetched {
            sha256,
            sha1,
            size,
            path,
            deduplicated,
            resumed_from,
        })
    }

    async fn import_local(&self, src: &Path, expected: &ExpectedDigests) -> Result<Fetched, DownloadError> {
        let meta = tokio::fs::metadata(src)
            .await
            .map_err(|e| DownloadError::Other(format!("{}: {e}", src.display())))?;
        if meta.len() > self.max_bytes {
            return Err(DownloadError::Integrity("file exceeds maximum size".into()));
        }
        let tmp = self.store.tmp_dir().join(format!("import-{}.part", uuid::Uuid::new_v4()));
        tokio::fs::copy(src, &tmp).await.map_err(|e| DownloadError::Other(e.to_string()))?;
        let (sha256, sha1, size) = hash_file(&tmp).await.map_err(|e| DownloadError::Other(e.to_string()))?;
        if let Err(e) = check_expected(&sha256, &sha1, size, expected, None) {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        let deduplicated = self.store.artifact_known(&sha256).unwrap_or(false);
        let path = self
            .store
            .adopt(&tmp, &sha256, &sha1.to_hex(), size)
            .map_err(|e| DownloadError::Other(e.to_string()))?;
        Ok(Fetched {
            sha256,
            sha1,
            size,
            path,
            deduplicated,
            resumed_from: 0,
        })
    }
}

fn check_expected(
    sha256: &Sha256Digest,
    sha1: &Sha1Digest,
    size: u64,
    expected: &ExpectedDigests,
    size_hint: Option<u64>,
) -> Result<(), DownloadError> {
    if let Some(e) = &expected.sha256 {
        if e != sha256 {
            return Err(DownloadError::Integrity(format!("SHA-256 mismatch: declared {e}, got {sha256}")));
        }
    }
    if let Some(e) = &expected.sha1 {
        if e != sha1 {
            return Err(DownloadError::Integrity(format!("SHA-1 mismatch: declared {e}, got {sha1}")));
        }
    }
    if let Some(s) = size_hint {
        if s != size {
            return Err(DownloadError::Integrity(format!("size mismatch: declared {s}, got {size}")));
        }
    }
    Ok(())
}

pub async fn hash_file(path: &Path) -> std::io::Result<(Sha256Digest, Sha1Digest, u64)> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut s256 = Sha256::new();
    let mut s1 = Sha1::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        s256.update(&buf[..n]);
        s1.update(&buf[..n]);
        total += n as u64;
    }
    Ok((Sha256Digest(s256.finalize().into()), Sha1Digest(s1.finalize().into()), total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Raw HTTP/1.1 test server: `/file` serves 64 KiB; the first request is cut after 10 000
    /// bytes by closing the socket, later requests honour `Range`; other paths return 404.
    async fn serve() -> (String, Arc<AtomicUsize>, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let data: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (d, h) = (data.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let d = d.clone();
                let h = h.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    if !req.starts_with("GET /file") {
                        let _ = sock
                            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    let hit = h.fetch_add(1, Ordering::SeqCst);
                    let range = req.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("range: bytes=")
                            .map(|r| r.trim_end_matches('-').trim().parse::<usize>().unwrap())
                    });
                    if hit == 0 {
                        let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", d.len());
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&d[..10_000]).await;
                        let _ = sock.flush().await;
                        return; // drop: connection cut mid-body
                    }
                    let (status, body) = match range {
                        Some(start) => ("206 Partial Content", &d[start..]),
                        None => ("200 OK", &d[..]),
                    };
                    let head = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                });
            }
        });
        (format!("http://{addr}"), hits, data)
    }

    fn store() -> (tempfile::TempDir, Arc<Store>) {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(Store::open(&d.path().join("db"), d.path().join("o"), d.path().join("t")).unwrap());
        (d, s)
    }

    #[tokio::test]
    async fn resumes_after_interruption_and_verifies() {
        let (base, hits, data) = serve().await;
        let (_d, s) = store();
        let dl = Downloader::new(s.clone(), 2, 3, u64::MAX);
        let expected = ExpectedDigests {
            sha256: Some(Sha256Digest(Sha256::digest(&data).into())),
            sha1: None,
        };
        let src = FileSource::Http {
            url: format!("{base}/file"),
            headers: vec![],
            url_is_sensitive: false,
        };
        let f = dl.fetch(&src, &expected, Some(data.len() as u64)).await.unwrap();
        assert_eq!(f.size, data.len() as u64);
        assert_eq!(f.resumed_from, 10_000, "second attempt must resume with Range");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(std::fs::read(&f.path).unwrap(), data);
        // Second fetch is served from the store without network.
        let again = dl.fetch(&src, &expected, Some(data.len() as u64)).await.unwrap();
        assert!(again.deduplicated);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejects_digest_mismatch_and_http_errors() {
        let (base, _hits, data) = serve().await;
        let (_d, s) = store();
        let dl = Downloader::new(s.clone(), 2, 3, u64::MAX);
        let wrong = ExpectedDigests {
            sha256: Some(Sha256Digest([9u8; 32])),
            sha1: None,
        };
        let src = FileSource::Http {
            url: format!("{base}/file"),
            headers: vec![],
            url_is_sensitive: false,
        };
        let e = dl.fetch(&src, &wrong, Some(data.len() as u64)).await.unwrap_err();
        assert!(matches!(e, DownloadError::Integrity(_)), "{e}");
        assert_eq!(s.stats().unwrap().1, 0, "nothing adopted");
        let src = FileSource::Http {
            url: format!("{base}/missing"),
            headers: vec![],
            url_is_sensitive: false,
        };
        assert!(matches!(
            dl.fetch(&src, &ExpectedDigests::default(), None).await.unwrap_err(),
            DownloadError::Rejected(_)
        ));
    }
}
