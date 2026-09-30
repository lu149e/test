//! Encrypted secret store (ChaCha20-Poly1305).
//!
//! * Master key: `UAD_MASTER_KEY` (32 bytes, hex or base64) if set — recommended, supplied by
//!   the service manager or a secret manager; otherwise a random key is generated in
//!   `<data_dir>/keys/master.key` (owner-only permissions), which protects against leaks of the
//!   data directory's other files/backups but not against an attacker with full disk access.
//! * Values can also be injected read-only through `UAD_SECRET_<KEY>` environment variables
//!   (`play.aas_token` → `UAD_SECRET_PLAY_AAS_TOKEN`).
//! * Secrets are never logged, never written to the database and never returned by the API.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uad_core::SecretStore;

pub struct FileSecretStore {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    cache: Mutex<BTreeMap<String, String>>,
    pub key_source: KeySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Environment,
    KeyFile,
}

pub fn env_name(key: &str) -> String {
    format!("UAD_SECRET_{}", key.to_ascii_uppercase().replace(['.', '-'], "_"))
}

/// Writes a file readable only by the owner (0600 on Unix; inherits profile ACLs on Windows).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

fn parse_key(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let bytes = hex::decode(s).ok().or_else(|| base64::engine::general_purpose::STANDARD.decode(s).ok())?;
    bytes.try_into().ok()
}

impl FileSecretStore {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let (key, key_source) = match std::env::var("UAD_MASTER_KEY") {
            Ok(v) => (
                parse_key(&v).ok_or("UAD_MASTER_KEY must be 32 bytes (hex or base64)")?,
                KeySource::Environment,
            ),
            Err(_) => {
                let kp = data_dir.join("keys").join("master.key");
                let key = match std::fs::read_to_string(&kp) {
                    Ok(s) => parse_key(&s).ok_or_else(|| format!("{} is corrupt", kp.display()))?,
                    Err(_) => {
                        let mut k = [0u8; 32];
                        rand::rngs::OsRng.fill_bytes(&mut k);
                        write_private(&kp, hex::encode(k).as_bytes()).map_err(|e| e.to_string())?;
                        k
                    }
                };
                (key, KeySource::KeyFile)
            }
        };
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let path = data_dir.join("secrets.enc");
        let cache = match std::fs::read(&path) {
            Ok(data) if data.len() > 12 => {
                let plain = cipher
                    .decrypt(&Nonce::from(<[u8; 12]>::try_from(&data[..12]).unwrap()), &data[12..])
                    .map_err(|_| "cannot decrypt secrets.enc (wrong master key?)".to_string())?;
                serde_json::from_slice(&plain).map_err(|e| e.to_string())?
            }
            _ => BTreeMap::new(),
        };
        Ok(Self {
            path,
            cipher,
            cache: Mutex::new(cache),
            key_source,
        })
    }

    fn persist(&self, map: &BTreeMap<String, String>) -> Result<(), String> {
        let plain = serde_json::to_vec(map).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(&Nonce::from(nonce), plain.as_ref())
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        write_private(&self.path, &out).map_err(|e| e.to_string())
    }

    /// Names of stored secrets (values are never exposed).
    pub fn keys(&self) -> Vec<String> {
        self.cache.lock().unwrap().keys().cloned().collect()
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(env_name(key)).ok().or_else(|| self.cache.lock().unwrap().get(key).cloned())
    }

    fn put(&self, key: &str, value: &str) -> Result<(), String> {
        let mut m = self.cache.lock().unwrap();
        m.insert(key.to_string(), value.to_string());
        self.persist(&m)
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        let mut m = self.cache.lock().unwrap();
        if m.remove(key).is_some() {
            self.persist(&m)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_encryption_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileSecretStore::open(dir.path()).unwrap();
        s.put("play.aas_token", "aas_et/SECRET-VALUE").unwrap();
        let raw = std::fs::read(dir.path().join("secrets.enc")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("SECRET-VALUE"));
        let s2 = FileSecretStore::open(dir.path()).unwrap();
        assert_eq!(s2.get("play.aas_token").as_deref(), Some("aas_et/SECRET-VALUE"));
        s2.delete("play.aas_token").unwrap();
        assert!(FileSecretStore::open(dir.path()).unwrap().get("play.aas_token").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("keys/master.key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn env_names() {
        assert_eq!(env_name("play.aas_token"), "UAD_SECRET_PLAY_AAS_TOKEN");
    }
}
