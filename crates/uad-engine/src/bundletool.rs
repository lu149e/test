//! bundletool integration: turns an Android App Bundle into a universal APK.
//!
//! bundletool must sign what it generates. Unless a keystore is configured, a dedicated local
//! key ("UAD Local Build Key") is created, so generated APKs are always distinguishable from
//! originals by their signer as well as by their recorded origin. The developer's or Google
//! Play's signing key is never available here, so a generated APK can never be byte- or
//! signature-identical to what Play distributes.

use crate::config::BundletoolConfig;
use crate::secrets::write_private;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::OnceCell;

#[derive(Debug, thiserror::Error)]
pub enum BundletoolError {
    #[error("bundletool unavailable: {0}")]
    Unavailable(String),
    #[error("bundletool failed: {0}")]
    Failed(String),
}

pub struct Bundletool {
    cfg: BundletoolConfig,
    tools_dir: PathBuf,
    keys_dir: PathBuf,
    jar: OnceCell<PathBuf>,
    version: OnceCell<String>,
}

pub struct Generated {
    pub path: PathBuf,
    pub tool: String,
}

const LOCAL_KS: &str = "generated-apks.jks";
const LOCAL_ALIAS: &str = "uad-local-build";

impl Bundletool {
    pub fn new(cfg: BundletoolConfig, data_dir: &Path) -> Self {
        Self { cfg, tools_dir: data_dir.join("tools"), keys_dir: data_dir.join("keys"), jar: OnceCell::new(), version: OnceCell::new() }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    async fn resolve_jar(&self) -> Result<PathBuf, BundletoolError> {
        if let Some(j) = &self.cfg.jar {
            if j.exists() {
                return Ok(j.clone());
            }
            return Err(BundletoolError::Unavailable(format!("{} not found", j.display())));
        }
        let name = self.cfg.download_url.rsplit('/').next().unwrap_or("bundletool-all.jar").to_string();
        let target = self.tools_dir.join(&name);
        if target.exists() {
            let data = tokio::fs::read(&target).await.map_err(|e| BundletoolError::Unavailable(e.to_string()))?;
            if hex::encode(Sha256::digest(&data)) == self.cfg.jar_sha256.to_ascii_lowercase() {
                return Ok(target);
            }
            tracing::warn!("cached {} does not match pinned SHA-256; re-downloading", target.display());
        }
        if !self.cfg.auto_download {
            return Err(BundletoolError::Unavailable("no jar configured and auto_download disabled".into()));
        }
        tokio::fs::create_dir_all(&self.tools_dir).await.map_err(|e| BundletoolError::Unavailable(e.to_string()))?;
        let expected = uad_core::Sha256Digest::parse_flexible(&self.cfg.jar_sha256).ok_or_else(|| BundletoolError::Unavailable("invalid jar_sha256".into()))?;
        tracing::info!("downloading bundletool from {}", self.cfg.download_url);
        uad_providers::http::download_verified(&uad_providers::http::client(), &self.cfg.download_url, &target, Some(&expected), None)
            .await
            .map_err(|e| BundletoolError::Unavailable(format!("download: {e}")))?;
        Ok(target)
    }

    pub async fn jar(&self) -> Result<PathBuf, BundletoolError> {
        self.jar.get_or_try_init(|| self.resolve_jar()).await.cloned()
    }

    async fn run(&self, args: &[String], timeout: Duration) -> Result<String, BundletoolError> {
        let jar = self.jar().await?;
        let mut cmd = Command::new(&self.cfg.java);
        cmd.arg("-jar").arg(&jar).args(args).stdin(Stdio::null()).kill_on_drop(true);
        let out = tokio::time::timeout(timeout, cmd.output())
            .await
            .map_err(|_| BundletoolError::Failed("timed out".into()))?
            .map_err(|e| BundletoolError::Unavailable(format!("{}: {e}", self.cfg.java)))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let msg: String = err.lines().filter(|l| !l.contains("JAVA_TOOL_OPTIONS")).collect::<Vec<_>>().join("\n");
            return Err(BundletoolError::Failed(msg.chars().take(2000).collect()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub async fn version(&self) -> Result<String, BundletoolError> {
        self.version.get_or_try_init(|| async { self.run(&["version".into()], Duration::from_secs(60)).await.map(|v| format!("bundletool {v}")) }).await.cloned()
    }

    fn keytool(&self) -> PathBuf {
        let java = Path::new(&self.cfg.java);
        if let Some(dir) = java.parent().filter(|d| !d.as_os_str().is_empty()) {
            let k = dir.join(if cfg!(windows) { "keytool.exe" } else { "keytool" });
            if k.exists() {
                return k;
            }
        }
        if let Some(home) = std::env::var_os("JAVA_HOME") {
            let k = PathBuf::from(home).join("bin").join(if cfg!(windows) { "keytool.exe" } else { "keytool" });
            if k.exists() {
                return k;
            }
        }
        PathBuf::from("keytool")
    }

    /// Returns (keystore, alias, password file) — creating the local build key if needed.
    async fn signing(&self, scratch: &Path) -> Result<(PathBuf, String, PathBuf), BundletoolError> {
        if let Some(ks) = &self.cfg.keystore {
            let alias = self.cfg.key_alias.clone().ok_or_else(|| BundletoolError::Unavailable("bundletool.key_alias required with keystore".into()))?;
            let env = self.cfg.keystore_password_env.clone().ok_or_else(|| BundletoolError::Unavailable("bundletool.keystore_password_env required".into()))?;
            let pass = std::env::var(&env).map_err(|_| BundletoolError::Unavailable(format!("{env} not set")))?;
            let pf = scratch.join("ks.pass");
            write_private(&pf, pass.as_bytes()).map_err(|e| BundletoolError::Unavailable(e.to_string()))?;
            return Ok((ks.clone(), alias, pf));
        }
        let ks = self.keys_dir.join(LOCAL_KS);
        let pf = self.keys_dir.join("generated-apks.pass");
        if !ks.exists() || !pf.exists() {
            let mut pw = [0u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut pw);
            let pass = hex::encode(pw);
            write_private(&pf, pass.as_bytes()).map_err(|e| BundletoolError::Unavailable(e.to_string()))?;
            let _ = tokio::fs::remove_file(&ks).await;
            let out = Command::new(self.keytool())
                .args(["-genkeypair", "-keystore"])
                .arg(&ks)
                .args(["-storetype", "PKCS12", "-alias", LOCAL_ALIAS, "-keyalg", "RSA", "-keysize", "3072", "-validity", "10000"])
                .args(["-dname", "CN=UAD Local Build Key (NOT an original signer), O=Universal APK Downloader"])
                .args(["-storepass", &pass, "-keypass", &pass])
                .stdin(Stdio::null())
                .output()
                .await
                .map_err(|e| BundletoolError::Unavailable(format!("keytool: {e}")))?;
            if !out.status.success() {
                return Err(BundletoolError::Unavailable(format!("keytool: {}", String::from_utf8_lossy(&out.stderr))));
            }
        }
        Ok((ks, LOCAL_ALIAS.into(), pf))
    }

    /// Builds a universal APK from `aab` into `work_dir`.
    pub async fn build_universal(&self, aab: &Path, work_dir: &Path) -> Result<Generated, BundletoolError> {
        if !self.cfg.enabled {
            return Err(BundletoolError::Unavailable("disabled in configuration".into()));
        }
        tokio::fs::create_dir_all(work_dir).await.map_err(|e| BundletoolError::Failed(e.to_string()))?;
        let (ks, alias, pass_file) = self.signing(work_dir).await?;
        let apks = work_dir.join("universal.apks");
        let _ = tokio::fs::remove_file(&apks).await;
        let pf = format!("file:{}", pass_file.display());
        let args: Vec<String> = vec![
            "build-apks".into(),
            format!("--bundle={}", aab.display()),
            format!("--output={}", apks.display()),
            "--mode=universal".into(),
            format!("--ks={}", ks.display()),
            format!("--ks-key-alias={alias}"),
            format!("--ks-pass={pf}"),
            format!("--key-pass={pf}"),
        ];
        self.run(&args, Duration::from_secs(self.cfg.timeout_secs)).await?;
        let out = work_dir.join("universal.apk");
        let apks2 = apks.clone();
        let out2 = out.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let mut z = zip::ZipArchive::new(std::fs::File::open(&apks2).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            let mut e = z.by_name("universal.apk").map_err(|e| e.to_string())?;
            let mut f = std::fs::File::create(&out2).map_err(|e| e.to_string())?;
            std::io::copy(&mut e, &mut f).map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|e| BundletoolError::Failed(e.to_string()))?
        .map_err(BundletoolError::Failed)?;
        let _ = tokio::fs::remove_file(work_dir.join("ks.pass")).await;
        Ok(Generated { path: out, tool: self.version().await.unwrap_or_else(|_| "bundletool".into()) })
    }
}
