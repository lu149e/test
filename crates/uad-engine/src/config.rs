//! Engine configuration (TOML). Secrets never live here: see [`crate::secrets`].

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uad_providers::fdroid::FdroidConfig;
use uad_providers::local::LocalConfig;
use uad_providers::play::PlayConfig;
use uad_providers::play_dev::PlayDevConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_jobs")]
    pub max_concurrent_jobs: usize,
    #[serde(default = "default_downloads")]
    pub max_concurrent_downloads: usize,
    #[serde(default = "default_retries")]
    pub download_retries: u32,
    /// Seconds a single provider may take for discovery.
    #[serde(default = "default_discovery_timeout")]
    pub discovery_timeout_secs: u64,
    /// Maximum accepted size of a single downloaded or uploaded file.
    #[serde(default = "default_max_file")]
    pub max_file_bytes: u64,
    /// Treat a signer that differs from the pinned one as an error (true) or a warning.
    #[serde(default = "default_true")]
    pub strict_signer_pinning: bool,
    #[serde(default)]
    pub bundletool: BundletoolConfig,
    #[serde(default)]
    pub providers: ProvidersConfig,
    /// Optional bearer token required by the HTTP API (read from `UAD_API_TOKEN` if unset).
    #[serde(default)]
    pub api_token_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(default = "default_true")]
    pub play_web: bool,
    #[serde(default)]
    pub fdroid: FdroidConfig,
    #[serde(default)]
    pub play: PlayConfig,
    #[serde(default)]
    pub play_dev: PlayDevConfig,
    #[serde(default)]
    pub local: LocalConfig,
    #[cfg(feature = "emulator")]
    #[serde(default)]
    pub emulator: uad_providers::emulator::EmulatorConfig,
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            play_web: true,
            fdroid: FdroidConfig::default(),
            play: PlayConfig::default(),
            play_dev: PlayDevConfig::default(),
            local: LocalConfig::default(),
            #[cfg(feature = "emulator")]
            emulator: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundletoolConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to `bundletool-all-<ver>.jar`. If unset and `auto_download`, the pinned release
    /// is fetched from GitHub and verified against `jar_sha256`.
    #[serde(default)]
    pub jar: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_download: bool,
    #[serde(default = "default_bt_url")]
    pub download_url: String,
    #[serde(default = "default_bt_sha")]
    pub jar_sha256: String,
    #[serde(default = "default_java")]
    pub java: String,
    /// Keystore used to sign APKs generated from bundles. If unset, a dedicated local key is
    /// created (with `keytool`) under `<data_dir>/keys`; generated APKs are never presented as
    /// originals either way.
    #[serde(default)]
    pub keystore: Option<PathBuf>,
    #[serde(default)]
    pub key_alias: Option<String>,
    /// Name of the environment variable holding the keystore password.
    #[serde(default)]
    pub keystore_password_env: Option<String>,
    #[serde(default = "default_bt_timeout")]
    pub timeout_secs: u64,
}

impl Default for BundletoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            jar: None,
            auto_download: true,
            download_url: default_bt_url(),
            jar_sha256: default_bt_sha(),
            java: default_java(),
            keystore: None,
            key_alias: None,
            keystore_password_env: None,
            timeout_secs: default_bt_timeout(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data")
}
fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_jobs() -> usize {
    2
}
fn default_downloads() -> usize {
    4
}
fn default_retries() -> u32 {
    4
}
fn default_discovery_timeout() -> u64 {
    900
}
fn default_max_file() -> u64 {
    8 * 1024 * 1024 * 1024
}
fn default_true() -> bool {
    true
}
fn default_bt_url() -> String {
    "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar".into()
}
/// SHA-256 of bundletool-all-1.18.3.jar (official GitHub release).
fn default_bt_sha() -> String {
    "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29".into()
}
fn default_java() -> String {
    "java".into()
}
fn default_bt_timeout() -> u64 {
    600
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").expect("defaults are valid")
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                toml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))
            }
            None => Ok(Self::default()),
        }
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.data_dir.join("objects")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.data_dir.join("cache")
    }
    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }
    pub fn inbox_dir(&self) -> PathBuf {
        self.providers.local.inbox.clone().unwrap_or_else(|| self.data_dir.join("inbox"))
    }
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("uad.sqlite3")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let c = Config::default();
        assert_eq!(c.max_concurrent_jobs, 2);
        assert!(c.providers.fdroid.enabled);
        assert!(!c.providers.play.enabled);
        let c: Config = toml::from_str("data_dir = \"/srv/uad\"\n[providers.play]\nenabled = true\ndevice_profiles = [\"arm64\", \"x86_64\"]\n").unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/srv/uad"));
        assert_eq!(c.providers.play.device_profiles.len(), 2);
    }
}
