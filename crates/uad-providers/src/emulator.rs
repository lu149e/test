//! Optional Android emulator integration (compiled with the `emulator` feature).
//!
//! Scope, stated plainly: this module manages a *local* AVD (start headless, wait for boot,
//! stop) and extracts the APKs of an app that is already installed on it (`pm path` +
//! `adb pull`). It does not automate the Play Store UI, does not sign in to accounts and
//! cannot obtain variants the emulator's configuration would not receive (an x86_64 AVD gets
//! x86_64 splits only). Use it for apps the operator installed on the AVD through legitimate
//! means (e.g. Play Store on a Google Play system image).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use uad_core::{
    Discovery, DiscoveryRequest, ExpectedDigests, FileRole, FileSource, Offer, OfferLayout, Provider, ProviderError, ProviderInfo, ProviderKind,
    RemoteFile,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Android SDK root; defaults to `ANDROID_SDK_ROOT` / `ANDROID_HOME`.
    #[serde(default)]
    pub sdk_root: Option<PathBuf>,
    /// AVD to start when no device is available.
    #[serde(default)]
    pub avd: Option<String>,
    /// Use an already running device/emulator with this serial instead of starting one.
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_boot")]
    pub boot_timeout_secs: u64,
    /// Stop the emulator after each discovery if this module started it.
    #[serde(default = "default_true")]
    pub stop_after_use: bool,
}

fn default_port() -> u16 {
    5580
}
fn default_boot() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self { enabled: false, sdk_root: None, avd: None, serial: None, port: default_port(), boot_timeout_secs: default_boot(), stop_after_use: true }
    }
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Parses `pm path` output (`package:/data/app/.../base.apk` per line).
pub fn parse_pm_path(out: &str) -> Vec<String> {
    out.lines().filter_map(|l| l.trim().strip_prefix("package:")).map(|s| s.trim().to_string()).filter(|s| s.ends_with(".apk")).collect()
}

/// Extracts `versionCode` and `versionName` from `dumpsys package <pkg>`.
pub fn parse_dumpsys_version(out: &str) -> (Option<i64>, Option<String>) {
    let mut vc = None;
    let mut vn = None;
    for tok in out.split_whitespace() {
        if vc.is_none() {
            if let Some(v) = tok.strip_prefix("versionCode=") {
                vc = v.parse().ok();
            }
        }
        if vn.is_none() {
            if let Some(v) = tok.strip_prefix("versionName=") {
                vn = Some(v.to_string());
            }
        }
    }
    (vc, vn)
}

pub struct EmulatorProvider {
    cfg: EmulatorConfig,
    work_dir: PathBuf,
    lock: tokio::sync::Mutex<()>,
}

impl EmulatorProvider {
    pub fn new(cfg: EmulatorConfig, cache_dir: &Path) -> Self {
        Self { cfg, work_dir: cache_dir.join("emulator"), lock: tokio::sync::Mutex::new(()) }
    }

    fn sdk(&self) -> Result<PathBuf, ProviderError> {
        self.cfg
            .sdk_root
            .clone()
            .or_else(|| std::env::var_os("ANDROID_SDK_ROOT").map(PathBuf::from))
            .or_else(|| std::env::var_os("ANDROID_HOME").map(PathBuf::from))
            .ok_or_else(|| ProviderError::NotConfigured("Android SDK not found (set emulator.sdk_root or ANDROID_SDK_ROOT)".into()))
    }

    fn adb(&self) -> Result<PathBuf, ProviderError> {
        Ok(self.sdk()?.join("platform-tools").join(exe("adb")))
    }

    async fn run(&self, program: &Path, args: &[&str], timeout: Duration) -> Result<String, ProviderError> {
        let fut = Command::new(program).args(args).stdin(Stdio::null()).kill_on_drop(true).output();
        let out = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ProviderError::Transient(format!("{} {:?} timed out", program.display(), args)))?
            .map_err(|e| ProviderError::NotConfigured(format!("{}: {e}", program.display())))?;
        if !out.status.success() {
            return Err(ProviderError::Other(format!("{} {:?}: {}", program.display(), args, String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    async fn adb_s(&self, serial: &str, args: &[&str]) -> Result<String, ProviderError> {
        let mut a = vec!["-s", serial];
        a.extend_from_slice(args);
        self.run(&self.adb()?, &a, Duration::from_secs(120)).await
    }

    async fn device_ready(&self, serial: &str) -> bool {
        matches!(self.adb_s(serial, &["shell", "getprop", "sys.boot_completed"]).await, Ok(s) if s.trim() == "1")
    }

    /// Returns (serial, started_by_us).
    async fn ensure_device(&self) -> Result<(String, bool), ProviderError> {
        if let Some(s) = &self.cfg.serial {
            if self.device_ready(s).await {
                return Ok((s.clone(), false));
            }
            return Err(ProviderError::Transient(format!("device {s} not ready")));
        }
        let serial = format!("emulator-{}", self.cfg.port);
        if self.device_ready(&serial).await {
            return Ok((serial, false));
        }
        let avd = self.cfg.avd.clone().ok_or_else(|| ProviderError::NotConfigured("no emulator.avd or emulator.serial configured".into()))?;
        let emulator = self.sdk()?.join("emulator").join(exe("emulator"));
        let port = self.cfg.port.to_string();
        tracing::info!("starting AVD {avd} on port {port}");
        Command::new(&emulator)
            .args(["-avd", &avd, "-port", &port, "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot-save"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ProviderError::NotConfigured(format!("{}: {e}", emulator.display())))?;
        let deadline = Instant::now() + Duration::from_secs(self.cfg.boot_timeout_secs);
        while Instant::now() < deadline {
            if self.device_ready(&serial).await {
                return Ok((serial, true));
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let _ = self.adb_s(&serial, &["emu", "kill"]).await;
        Err(ProviderError::Transient(format!("AVD {avd} did not boot within {}s", self.cfg.boot_timeout_secs)))
    }

    async fn extract(&self, serial: &str, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        let pkg = req.package.as_str(); // validated: [A-Za-z0-9_.] only, safe for the device shell
        let paths = parse_pm_path(&self.adb_s(serial, &["shell", "pm", "path", pkg]).await.unwrap_or_default());
        if paths.is_empty() {
            return Err(ProviderError::NotFound);
        }
        let (vc, vn) = parse_dumpsys_version(&self.adb_s(serial, &["shell", "dumpsys", "package", pkg]).await?);
        let vc = vc.ok_or_else(|| ProviderError::Protocol("versionCode not found in dumpsys".into()))?;
        if req.version_code.is_some_and(|r| r != vc) {
            return Err(ProviderError::NotFound);
        }
        let dir = self.work_dir.join(pkg).join(vc.to_string());
        tokio::fs::create_dir_all(&dir).await.map_err(|e| ProviderError::Other(e.to_string()))?;
        let mut files = vec![];
        for (i, remote) in paths.iter().enumerate() {
            let name = Path::new(remote).file_name().and_then(|n| n.to_str()).unwrap_or("base.apk").to_string();
            let local = dir.join(format!("{i:02}-{name}"));
            self.adb_s(serial, &["pull", remote, &local.to_string_lossy()]).await?;
            let role = if paths.len() == 1 {
                FileRole::Standalone
            } else if name == "base.apk" {
                FileRole::Base
            } else {
                FileRole::Split(name.trim_start_matches("split_").trim_end_matches(".apk").to_string())
            };
            files.push(RemoteFile { role, file_name: name, source: FileSource::Local { path: local }, size: None, expected: ExpectedDigests::default() });
        }
        let layout = if files.len() > 1 { OfferLayout::SplitSet } else { OfferLayout::UniversalApk };
        Ok(Discovery {
            offers: vec![Offer {
                provider: "emulator".into(),
                package: req.package.clone(),
                version_code: vc,
                version_name: vn,
                layout,
                files,
                abis: vec![],
                min_sdk: None,
                trust: None,
                device_profile: Some(serial.to_string()),
                channel: format!("pulled from local emulator/device {serial}"),
            }],
            notes: vec!["Only the splits installed for this emulator's configuration are available.".into()],
            ..Default::default()
        })
    }
}

#[async_trait]
impl Provider for EmulatorProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "emulator".into(),
            name: "Local Android emulator".into(),
            kind: ProviderKind::Local,
            enabled: self.cfg.enabled,
            requires_credentials: false,
            priority: 40,
            description: "Extracts APKs of apps already installed on a local AVD (optional component).".into(),
            status: "Requires Android SDK emulator + a hardware-accelerated host (KVM/WHPX). Does not automate Play Store.".into(),
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        if !self.cfg.enabled {
            return Err(ProviderError::NotConfigured("emulator provider disabled".into()));
        }
        let _g = self.lock.lock().await;
        let (serial, started) = self.ensure_device().await?;
        let res = self.extract(&serial, req).await;
        if started && self.cfg.stop_after_use {
            let _ = self.adb_s(&serial, &["emu", "kill"]).await;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_adb_output() {
        let out = "package:/data/app/~~abc==/com.x-1/base.apk\npackage:/data/app/~~abc==/com.x-1/split_config.arm64_v8a.apk\n";
        assert_eq!(parse_pm_path(out).len(), 2);
        let d = "Packages:\n  Package [com.x] (1a2b):\n    versionCode=12345 minSdk=24 targetSdk=34\n    versionName=1.2.3\n";
        assert_eq!(parse_dumpsys_version(d), (Some(12345), Some("1.2.3".into())));
    }
}
