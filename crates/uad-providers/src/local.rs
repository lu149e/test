//! Local import provider: files placed by the operator in an inbox directory (or uploaded
//! through the web UI). Accepts APKs, App Bundles (`.aab`) and ZIP containers of split APKs
//! (`.apks`, `.xapk`, `.apkm` when not encrypted).
//!
//! This is how original AABs enter the system (e.g. a developer's own bundle) so they can be
//! turned into a universal APK with bundletool.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use uad_apk::Container;
use uad_core::{
    Discovery, DiscoveryRequest, ExpectedDigests, FileRole, FileSource, Offer, OfferLayout, Provider, ProviderError, ProviderInfo, ProviderKind,
    RemoteFile,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Inbox directory; defaults to `<data_dir>/inbox`.
    #[serde(default)]
    pub inbox: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self { enabled: true, inbox: None }
    }
}

pub struct LocalProvider {
    enabled: bool,
    inbox: PathBuf,
    extract_dir: PathBuf,
}

const MAX_INNER_APK: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    container: Container,
    version_code: i64,
    version_name: Option<String>,
    split: Option<String>,
    group: String,
}

impl LocalProvider {
    pub fn new(enabled: bool, inbox: PathBuf, cache_dir: &Path) -> Self {
        Self {
            enabled,
            inbox,
            extract_dir: cache_dir.join("local-extracted"),
        }
    }

    pub fn inbox(&self) -> &Path {
        &self.inbox
    }

    fn scan(&self, pkg: &str) -> Result<Vec<Candidate>, ProviderError> {
        let mut out = vec![];
        let rd = match std::fs::read_dir(&self.inbox) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(ProviderError::Other(format!("{}: {e}", self.inbox.display()))),
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
            match ext.as_str() {
                "apk" | "aab" => {
                    if let Ok((container, m)) = uad_apk::peek_manifest(&path) {
                        if m.package == pkg {
                            out.push(Candidate {
                                group: if m.split.is_some() {
                                    format!("loose-{}", m.version_code)
                                } else {
                                    path.display().to_string()
                                },
                                path,
                                container,
                                version_code: m.version_code,
                                version_name: m.version_name,
                                split: m.split,
                            });
                        }
                    }
                }
                "apks" | "xapk" | "apkm" => match self.extract_container(&path) {
                    Ok(files) => {
                        for f in files {
                            if let Ok((container, m)) = uad_apk::peek_manifest(&f) {
                                if m.package == pkg {
                                    out.push(Candidate {
                                        path: f,
                                        container,
                                        version_code: m.version_code,
                                        version_name: m.version_name,
                                        split: m.split,
                                        group: path.display().to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!("cannot read {}: {e}", path.display()),
                },
                _ => {}
            }
        }
        Ok(out)
    }

    /// Extracts inner APKs of a split container into a content-addressed directory.
    fn extract_container(&self, path: &Path) -> Result<Vec<PathBuf>, String> {
        let (digest, _, _) = uad_apk::file_digests(path).map_err(|e| e.to_string())?;
        let dir = self.extract_dir.join(digest.to_hex());
        let done = dir.join(".complete");
        if !done.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let mut z = zip::ZipArchive::new(std::fs::File::open(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            for i in 0..z.len() {
                let mut e = z.by_index(i).map_err(|e| e.to_string())?;
                let name = e.name().to_string();
                if !name.to_ascii_lowercase().ends_with(".apk") || e.is_dir() {
                    continue;
                }
                if e.encrypted() {
                    return Err("encrypted container (unsupported)".into());
                }
                // Flatten names; never trust archive paths (zip-slip).
                let base = Path::new(&name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("inner.apk")
                    .replace("..", "_");
                let target = dir.join(format!("{i:03}-{base}"));
                let mut out = std::fs::File::create(&target).map_err(|e| e.to_string())?;
                let copied = std::io::copy(&mut (&mut e).take(MAX_INNER_APK), &mut out).map_err(|e| e.to_string())?;
                if copied >= MAX_INNER_APK {
                    return Err("inner APK exceeds size limit".into());
                }
            }
            std::fs::write(&done, b"").map_err(|e| e.to_string())?;
        }
        let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "apk"))
            .collect();
        v.sort();
        Ok(v)
    }
}

fn file_name(p: &Path) -> String {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string()
}

#[async_trait]
impl Provider for LocalProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "local".into(),
            name: "Local import".into(),
            kind: ProviderKind::Local,
            enabled: self.enabled,
            requires_credentials: false,
            priority: 30,
            description: format!("APK/AAB/APKS files placed in {} or uploaded via the web UI", self.inbox.display()),
            status: "Provenance is the operator's import; authenticity rests on signature verification and certificate pinning only.".into(),
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        let pkg = req.package.as_str().to_string();
        let this = LocalProvider {
            enabled: self.enabled,
            inbox: self.inbox.clone(),
            extract_dir: self.extract_dir.clone(),
        };
        let cands = tokio::task::spawn_blocking(move || this.scan(&pkg))
            .await
            .map_err(|e| ProviderError::Other(e.to_string()))??;
        let target_vc = match req.version_code {
            Some(v) => v,
            None => cands.iter().map(|c| c.version_code).max().ok_or(ProviderError::NotFound)?,
        };
        let mut groups: BTreeMap<String, Vec<&Candidate>> = BTreeMap::new();
        for c in cands.iter().filter(|c| c.version_code == target_vc) {
            groups.entry(c.group.clone()).or_default().push(c);
        }
        if groups.is_empty() {
            return Err(ProviderError::NotFound);
        }
        let mut d = Discovery::default();
        for (group, members) in groups {
            let layout = if members.iter().any(|m| m.container == Container::AppBundle) {
                OfferLayout::AppBundle
            } else if members.iter().any(|m| m.split.is_some()) {
                OfferLayout::SplitSet
            } else {
                OfferLayout::UniversalApk // refined by analysis (may be ABI-specific)
            };
            let files = members
                .iter()
                .map(|m| RemoteFile {
                    role: match (&m.container, &m.split) {
                        (Container::AppBundle, _) => FileRole::AppBundle,
                        (_, Some(s)) => FileRole::Split(s.clone()),
                        (_, None) if layout == OfferLayout::SplitSet => FileRole::Base,
                        _ => FileRole::Standalone,
                    },
                    file_name: file_name(&m.path),
                    source: FileSource::Local { path: m.path.clone() },
                    size: std::fs::metadata(&m.path).ok().map(|x| x.len()),
                    expected: ExpectedDigests::default(),
                })
                .collect();
            d.offers.push(Offer {
                provider: "local".into(),
                package: req.package.clone(),
                version_code: target_vc,
                version_name: members[0].version_name.clone(),
                layout,
                files,
                abis: vec![],
                min_sdk: None,
                trust: None,
                device_profile: None,
                channel: format!("local import ({group})"),
            });
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uad_core::PackageName;

    fn fixture(p: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../uad-apk/tests/fixtures").join(p)
    }

    #[tokio::test]
    async fn discovers_apk_aab_and_split_containers() {
        let inbox = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        std::fs::copy(fixture("app.aab"), inbox.path().join("my.aab")).unwrap();
        std::fs::copy(fixture("rsa_v1v2v3.apk"), inbox.path().join("app.apk")).unwrap();
        // .apks container of split APKs
        {
            let f = std::fs::File::create(inbox.path().join("set.apks")).unwrap();
            let mut z = zip::ZipWriter::new(f);
            for n in ["base-master.apk", "base-arm64_v8a.apk", "base-xxhdpi.apk"] {
                z.start_file(format!("splits/{n}"), zip::write::SimpleFileOptions::default()).unwrap();
                std::io::copy(&mut std::fs::File::open(fixture(&format!("splits/{n}"))).unwrap(), &mut z).unwrap();
            }
            z.start_file("../../evil.apk", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut z, b"not an apk").unwrap();
            z.finish().unwrap();
        }
        std::fs::write(inbox.path().join("junk.apk"), b"junk").unwrap();
        let p = LocalProvider::new(true, inbox.path().to_path_buf(), cache.path());
        let req = DiscoveryRequest {
            package: PackageName::new("com.uad.fixture").unwrap(),
            version_code: None,
            abis: vec![],
            locale: None,
        };
        let d = p.discover(&req).await.unwrap();
        let layouts: Vec<OfferLayout> = d.offers.iter().map(|o| o.layout).collect();
        assert!(layouts.contains(&OfferLayout::AppBundle), "{layouts:?}");
        assert!(layouts.contains(&OfferLayout::UniversalApk));
        let split = d.offers.iter().find(|o| o.layout == OfferLayout::SplitSet).unwrap();
        assert_eq!(split.files.len(), 3);
        assert_eq!(split.files.iter().filter(|f| f.role == FileRole::Base).count(), 1);
        // zip-slip entry stayed inside the extraction directory
        assert!(!cache.path().parent().unwrap().join("evil.apk").exists());

        let req = DiscoveryRequest {
            package: PackageName::new("com.other.app").unwrap(),
            ..req
        };
        assert!(matches!(p.discover(&req).await, Err(ProviderError::NotFound)));
    }
}
