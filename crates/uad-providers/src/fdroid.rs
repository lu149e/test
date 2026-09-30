//! F-Droid repository provider.
//!
//! Trust chain (no trust in TLS or mirrors alone):
//! 1. `entry.jar` is a JAR signed with the repository key; its signer certificate SHA-256 must
//!    equal the pinned repository fingerprint.
//! 2. `entry.json` (inside the verified JAR) declares the SHA-256 and size of `index-v2.json`.
//! 3. `index-v2.json` lists, per APK, its SHA-256 and the SHA-256 of the app signing certificate.
//! 4. The engine later checks the downloaded APK against both values.
//!
//! Anti-rollback: an `entry.json` older than the last accepted one is rejected.

use crate::http;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uad_core::{
    Abi, AppMetadata, Availability, Discovery, DiscoveryRequest, ExpectedDigests, FileRole, FileSource, KnownVariant, Offer, OfferLayout, Provider,
    ProviderError, ProviderInfo, ProviderKind, RemoteFile, Sha256Digest, TrustAnchor,
};

/// Signing-certificate fingerprint of the official https://f-droid.org/repo repository.
pub const FDROID_MAIN_FINGERPRINT: &str = "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdroidConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_repo")]
    pub repo_url: String,
    /// SHA-256 of the repository signing certificate.
    #[serde(default = "default_fp")]
    pub fingerprint: String,
    /// How often `entry.jar` is re-checked.
    #[serde(default = "default_refresh")]
    pub refresh_minutes: u64,
    /// Include versions marked with a release channel (e.g. Beta).
    #[serde(default)]
    pub include_prereleases: bool,
}

fn default_true() -> bool {
    true
}
fn default_repo() -> String {
    "https://f-droid.org/repo".into()
}
fn default_fp() -> String {
    FDROID_MAIN_FINGERPRINT.into()
}
fn default_refresh() -> u64 {
    30
}

impl Default for FdroidConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            repo_url: default_repo(),
            fingerprint: default_fp(),
            refresh_minutes: default_refresh(),
            include_prereleases: false,
        }
    }
}

// ---- index-v2 subset --------------------------------------------------------------------

#[derive(Deserialize)]
struct EntryJson {
    timestamp: i64,
    index: EntryFile,
}

#[derive(Deserialize)]
struct EntryFile {
    name: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
struct IndexV2 {
    packages: HashMap<String, IndexPackage>,
}

#[derive(Deserialize)]
struct IndexPackage {
    metadata: IndexMetadata,
    #[serde(default)]
    versions: HashMap<String, IndexVersion>,
}

#[derive(Deserialize, Default)]
struct IndexMetadata {
    #[serde(default)]
    name: BTreeMap<String, String>,
    #[serde(default)]
    summary: BTreeMap<String, String>,
    #[serde(default, rename = "authorName")]
    author_name: Option<String>,
    #[serde(default)]
    icon: BTreeMap<String, IndexFile>,
    #[serde(default, rename = "preferredSigner")]
    preferred_signer: Option<String>,
}

#[derive(Deserialize)]
struct IndexFile {
    name: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Deserialize)]
struct IndexVersion {
    #[serde(default)]
    added: i64,
    file: IndexFile,
    manifest: IndexManifest,
    #[serde(default, rename = "releaseChannels")]
    release_channels: Vec<String>,
}

#[derive(Deserialize)]
struct IndexManifest {
    #[serde(rename = "versionName", default)]
    version_name: Option<String>,
    #[serde(rename = "versionCode")]
    version_code: i64,
    #[serde(rename = "usesSdk", default)]
    uses_sdk: Option<UsesSdk>,
    #[serde(default)]
    nativecode: Vec<String>,
    #[serde(default)]
    signer: Option<Signer>,
}

#[derive(Deserialize)]
struct UsesSdk {
    #[serde(rename = "minSdkVersion", default)]
    min: Option<u32>,
}

#[derive(Deserialize)]
struct Signer {
    #[serde(default)]
    sha256: Vec<String>,
}

// ---- compact in-memory index ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactVersion {
    pub version_code: i64,
    pub version_name: Option<String>,
    pub file: String,
    pub sha256: String,
    pub size: Option<u64>,
    pub min_sdk: Option<u32>,
    pub nativecode: Vec<String>,
    pub signers: Vec<String>,
    pub channels: Vec<String>,
    pub added: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactPackage {
    pub name: Option<String>,
    pub summary: Option<String>,
    pub author: Option<String>,
    pub icon: Option<String>,
    pub preferred_signer: Option<String>,
    /// Sorted by version code, newest first.
    pub versions: Vec<CompactVersion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompactIndex {
    pub index_sha256: String,
    pub entry_timestamp: i64,
    pub packages: HashMap<String, CompactPackage>,
}

fn pick_locale(m: &BTreeMap<String, String>) -> Option<String> {
    m.get("en-US").or_else(|| m.get("en")).or_else(|| m.values().next()).cloned()
}

impl CompactIndex {
    fn from_v2(v2: IndexV2, index_sha256: String, entry_timestamp: i64) -> Self {
        let packages = v2
            .packages
            .into_iter()
            .map(|(id, p)| {
                let mut versions: Vec<CompactVersion> = p
                    .versions
                    .into_values()
                    .map(|v| CompactVersion {
                        version_code: v.manifest.version_code,
                        version_name: v.manifest.version_name,
                        file: v.file.name,
                        sha256: v.file.sha256.unwrap_or_default(),
                        size: v.file.size,
                        min_sdk: v.manifest.uses_sdk.and_then(|u| u.min),
                        nativecode: v.manifest.nativecode,
                        signers: v.manifest.signer.map(|s| s.sha256).unwrap_or_default(),
                        channels: v.release_channels,
                        added: v.added,
                    })
                    .collect();
                versions.sort_by(|a, b| b.version_code.cmp(&a.version_code));
                let icon = p
                    .metadata
                    .icon
                    .get("en-US")
                    .or_else(|| p.metadata.icon.values().next())
                    .map(|f| f.name.clone());
                (
                    id,
                    CompactPackage {
                        name: pick_locale(&p.metadata.name),
                        summary: pick_locale(&p.metadata.summary),
                        author: p.metadata.author_name,
                        icon,
                        preferred_signer: p.metadata.preferred_signer,
                        versions,
                    },
                )
            })
            .collect();
        Self {
            index_sha256,
            entry_timestamp,
            packages,
        }
    }
}

struct State {
    index: Option<Arc<CompactIndex>>,
    last_check: Option<Instant>,
}

pub struct FdroidProvider {
    cfg: FdroidConfig,
    cache_dir: PathBuf,
    client: reqwest::Client,
    state: Mutex<State>,
}

impl FdroidProvider {
    pub fn new(cfg: FdroidConfig, cache_dir: PathBuf) -> Self {
        Self {
            cfg,
            cache_dir,
            client: http::client(),
            state: Mutex::new(State {
                index: None,
                last_check: None,
            }),
        }
    }

    fn repo(&self) -> &str {
        self.cfg.repo_url.trim_end_matches('/')
    }

    fn dir(&self) -> PathBuf {
        use sha2::Digest;
        let h = hex::encode(&sha2::Sha256::digest(self.repo().as_bytes())[..8]);
        self.cache_dir.join("fdroid").join(h)
    }

    /// Returns a verified index, refreshing it when stale.
    pub async fn index(&self) -> Result<Arc<CompactIndex>, ProviderError> {
        let mut st = self.state.lock().await;
        let fresh = st
            .last_check
            .is_some_and(|t| t.elapsed() < Duration::from_secs(self.cfg.refresh_minutes * 60));
        if fresh {
            if let Some(i) = &st.index {
                return Ok(i.clone());
            }
        }
        let dir = self.dir();
        tokio::fs::create_dir_all(&dir).await.map_err(|e| ProviderError::Other(e.to_string()))?;
        let res = self.refresh(&dir, st.index.clone()).await;
        match res {
            Ok(idx) => {
                st.index = Some(idx.clone());
                st.last_check = Some(Instant::now());
                Ok(idx)
            }
            // Network down: keep serving the last verified index if we have one.
            Err(ProviderError::Transient(e)) if st.index.is_some() => {
                tracing::warn!("F-Droid refresh failed, using cached verified index: {e}");
                Ok(st.index.clone().unwrap())
            }
            Err(e) => {
                if st.index.is_none() {
                    if let Ok(idx) = self.load_cached(&dir).await {
                        tracing::warn!("F-Droid refresh failed ({e}); using cached verified index from disk");
                        let idx = Arc::new(idx);
                        st.index = Some(idx.clone());
                        return Ok(idx);
                    }
                }
                Err(e)
            }
        }
    }

    async fn load_cached(&self, dir: &std::path::Path) -> Result<CompactIndex, ProviderError> {
        let data = tokio::fs::read(dir.join("compact.json"))
            .await
            .map_err(|e| ProviderError::Other(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| ProviderError::Other(e.to_string()))
    }

    async fn refresh(&self, dir: &std::path::Path, current: Option<Arc<CompactIndex>>) -> Result<Arc<CompactIndex>, ProviderError> {
        let entry_path = dir.join("entry.jar");
        http::download_verified(&self.client, &format!("{}/entry.jar", self.repo()), &entry_path, None, None).await?;
        let fingerprint = self.cfg.fingerprint.to_ascii_lowercase();
        let entry: EntryJson = tokio::task::spawn_blocking(move || verify_entry_jar(&entry_path, &fingerprint))
            .await
            .map_err(|e| ProviderError::Other(e.to_string()))??;

        let current = match current {
            Some(c) => Some(c),
            None => self.load_cached(dir).await.ok().map(Arc::new),
        };
        if let Some(c) = &current {
            if entry.timestamp < c.entry_timestamp {
                return Err(ProviderError::Integrity(format!(
                    "F-Droid entry.json timestamp {} is older than the last accepted {} (possible rollback/freeze attack)",
                    entry.timestamp, c.entry_timestamp
                )));
            }
            if c.index_sha256 == entry.index.sha256.to_ascii_lowercase() {
                return Ok(c.clone());
            }
        }
        let expected =
            Sha256Digest::parse_flexible(&entry.index.sha256).ok_or_else(|| ProviderError::Protocol("bad index sha256 in entry.json".into()))?;
        let index_path = dir.join("index-v2.json");
        let url = format!("{}/{}", self.repo(), entry.index.name.trim_start_matches('/'));
        tracing::info!("downloading F-Droid index ({} bytes)", entry.index.size);
        http::download_verified(&self.client, &url, &index_path, Some(&expected), Some(entry.index.size)).await?;
        let ts = entry.timestamp;
        let sha = expected.to_hex();
        let compact_path = dir.join("compact.json");
        let idx = tokio::task::spawn_blocking(move || -> Result<CompactIndex, ProviderError> {
            let f = std::fs::File::open(&index_path).map_err(|e| ProviderError::Other(e.to_string()))?;
            let v2: IndexV2 =
                serde_json::from_reader(std::io::BufReader::new(f)).map_err(|e| ProviderError::Protocol(format!("index-v2.json: {e}")))?;
            let idx = CompactIndex::from_v2(v2, sha, ts);
            let tmp = compact_path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec(&idx).map_err(|e| ProviderError::Other(e.to_string()))?)
                .map_err(|e| ProviderError::Other(e.to_string()))?;
            std::fs::rename(&tmp, &compact_path).map_err(|e| ProviderError::Other(e.to_string()))?;
            let _ = std::fs::remove_file(&index_path);
            Ok(idx)
        })
        .await
        .map_err(|e| ProviderError::Other(e.to_string()))??;
        Ok(Arc::new(idx))
    }

    fn offer_for(&self, pkg: &str, p: &CompactPackage, v: &CompactVersion) -> Offer {
        let abis: Vec<Abi> = v.nativecode.iter().filter_map(|a| Abi::parse(a)).collect();
        let layout = if abis.len() == 1 {
            OfferLayout::AbiSpecificApk
        } else {
            OfferLayout::UniversalApk
        };
        let file_name = v.file.trim_start_matches('/').to_string();
        let signers: Vec<Sha256Digest> = v.signers.iter().filter_map(|s| Sha256Digest::parse_flexible(s)).collect();
        Offer {
            provider: "fdroid".into(),
            package: uad_core::PackageName::new(pkg).expect("validated by caller"),
            version_code: v.version_code,
            version_name: v.version_name.clone(),
            layout,
            files: vec![RemoteFile {
                role: FileRole::Standalone,
                file_name: file_name.clone(),
                source: FileSource::Http {
                    url: format!("{}/{}", self.repo(), file_name),
                    headers: vec![],
                    url_is_sensitive: false,
                },
                size: v.size,
                expected: ExpectedDigests {
                    sha256: Sha256Digest::parse_flexible(&v.sha256),
                    sha1: None,
                },
            }],
            abis,
            min_sdk: v.min_sdk,
            trust: Some(TrustAnchor {
                signer_cert_sha256: signers,
                asserted_by: format!(
                    "F-Droid signed index ({}/entry.jar, repo key {})",
                    self.repo(),
                    &self.cfg.fingerprint[..16]
                ),
                authenticated: true,
            }),
            device_profile: None,
            channel: format!(
                "F-Droid repository {}{}",
                self.repo(),
                if p.preferred_signer.is_some() {
                    " (preferred signer enforced)"
                } else {
                    ""
                }
            ),
        }
    }
}

/// Verifies `entry.jar` and returns the parsed `entry.json`.
fn verify_entry_jar(path: &std::path::Path, fingerprint: &str) -> Result<EntryJson, ProviderError> {
    let mut f = std::fs::File::open(path).map_err(|e| ProviderError::Other(e.to_string()))?;
    let layout = uad_apk::zipinfo::ZipLayout::read(&mut f).map_err(|e| ProviderError::Integrity(format!("entry.jar: {e}")))?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| ProviderError::Other(e.to_string()))?,
    ))
    .map_err(|e| ProviderError::Integrity(format!("entry.jar: {e}")))?;
    let rep = uad_apk::sig::v1::verify_jar(&mut zip, &layout.entry_names);
    if !rep.verified {
        return Err(ProviderError::Integrity(format!("entry.jar signature invalid: {:?}", rep.errors)));
    }
    let signer = rep
        .signers
        .first()
        .and_then(|s| s.certificate.as_ref())
        .map(|c| c.sha256.to_hex())
        .unwrap_or_default();
    if signer != fingerprint {
        return Err(ProviderError::Integrity(format!(
            "entry.jar signed by {signer}, expected pinned repository key {fingerprint}"
        )));
    }
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut zip.by_name("entry.json").map_err(|e| ProviderError::Protocol(e.to_string()))?,
        &mut data,
    )
    .map_err(|e| ProviderError::Other(e.to_string()))?;
    serde_json::from_slice(&data).map_err(|e| ProviderError::Protocol(format!("entry.json: {e}")))
}

/// Selects versions to offer. Pure function, unit-tested.
pub fn select_versions<'a>(p: &'a CompactPackage, req_version: Option<i64>, abis: &[Abi], include_prereleases: bool) -> Vec<&'a CompactVersion> {
    let signer_ok = |v: &CompactVersion| match &p.preferred_signer {
        Some(ps) => v.signers.is_empty() || v.signers.iter().any(|s| s.eq_ignore_ascii_case(ps)),
        None => true,
    };
    let candidates: Vec<&CompactVersion> = p.versions.iter().filter(|v| signer_ok(v)).collect();
    if let Some(vc) = req_version {
        return candidates.into_iter().filter(|v| v.version_code == vc).collect();
    }
    let stable: Vec<&CompactVersion> = candidates
        .iter()
        .copied()
        .filter(|v| include_prereleases || v.channels.is_empty())
        .collect();
    let pool = if stable.is_empty() { candidates } else { stable };
    let Some(latest) = pool.first() else { return vec![] };
    // ABI-split builds share a version name and have single-ABI native code.
    let mut picked: Vec<&CompactVersion> = if latest.nativecode.len() == 1 && latest.version_name.is_some() {
        pool.iter()
            .copied()
            .filter(|v| v.version_name == latest.version_name && v.nativecode.len() == 1)
            .collect()
    } else {
        vec![*latest]
    };
    if !abis.is_empty() {
        picked.retain(|v| v.nativecode.is_empty() || v.nativecode.iter().filter_map(|a| Abi::parse(a)).any(|a| abis.contains(&a)));
    }
    picked
}

#[async_trait]
impl Provider for FdroidProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "fdroid".into(),
            name: "F-Droid".into(),
            kind: ProviderKind::AuthorizedRepository,
            enabled: self.cfg.enabled,
            requires_credentials: false,
            priority: 20,
            description: format!("Signed F-Droid repository at {} (index authenticated with pinned key)", self.repo()),
            status: "Only free/open-source apps published in the repository. Builds are made by F-Droid and may be signed by F-Droid, not by the Play Store developer key.".into(),
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        let idx = self.index().await?;
        let pkg = req.package.as_str();
        let p = idx.packages.get(pkg).ok_or(ProviderError::NotFound)?;
        let selected = select_versions(p, req.version_code, &req.abis, self.cfg.include_prereleases);
        if selected.is_empty() {
            return Err(ProviderError::NotFound);
        }
        let mut d = Discovery::default();
        let latest = selected[0];
        d.metadata = Some(AppMetadata {
            title: p.name.clone(),
            developer: p.author.clone(),
            icon_url: p.icon.as_ref().map(|i| format!("{}/{}", self.repo(), i.trim_start_matches('/'))),
            summary: p.summary.clone(),
            version_name: latest.version_name.clone(),
            version_code: Some(latest.version_code),
            source: "fdroid".into(),
        });
        d.offers = selected.iter().map(|v| self.offer_for(pkg, p, v)).collect();
        let picked: Vec<i64> = selected.iter().map(|v| v.version_code).collect();
        for v in p.versions.iter().filter(|v| !picked.contains(&v.version_code)).take(20) {
            d.known.push(KnownVariant {
                provider: "fdroid".into(),
                version_code: Some(v.version_code),
                version_name: v.version_name.clone(),
                description: format!(
                    "other version in repository{}{}",
                    if v.channels.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", v.channels.join(","))
                    },
                    if v.nativecode.is_empty() {
                        String::new()
                    } else {
                        format!(", ABIs {}", v.nativecode.join("/"))
                    }
                ),
                role: Some(FileRole::Standalone),
                abis: v.nativecode.iter().filter_map(|a| Abi::parse(a)).collect(),
                availability: Availability::Identified,
            });
        }
        if p.versions.len() > 20 + picked.len() {
            d.notes
                .push(format!("{} older versions not listed", p.versions.len() - 20 - picked.len()));
        }
        d.notes.push("F-Droid builds apps from source; its APKs may be signed with F-Droid's key rather than the developer key used on Google Play (unless reproducible builds are published with the developer signature).".into());
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(vc: i64, name: &str, abis: &[&str], ch: &[&str]) -> CompactVersion {
        CompactVersion {
            version_code: vc,
            version_name: Some(name.into()),
            file: format!("/p_{vc}.apk"),
            sha256: "00".repeat(32),
            size: Some(1),
            min_sdk: Some(21),
            nativecode: abis.iter().map(|s| s.to_string()).collect(),
            signers: vec!["aa".repeat(32)],
            channels: ch.iter().map(|s| s.to_string()).collect(),
            added: 0,
        }
    }

    fn pkg(versions: Vec<CompactVersion>) -> CompactPackage {
        CompactPackage {
            name: None,
            summary: None,
            author: None,
            icon: None,
            preferred_signer: Some("aa".repeat(32)),
            versions,
        }
    }

    #[test]
    fn picks_latest_stable_universal() {
        let p = pkg(vec![
            v(30, "3.0-beta", &[], &["Beta"]),
            v(20, "2.0", &["arm64-v8a", "x86"], &[]),
            v(10, "1.0", &[], &[]),
        ]);
        let s = select_versions(&p, None, &[], false);
        assert_eq!(s.iter().map(|v| v.version_code).collect::<Vec<_>>(), vec![20]);
        let s = select_versions(&p, None, &[], true);
        assert_eq!(s[0].version_code, 30);
    }

    #[test]
    fn groups_abi_split_builds() {
        let p = pkg(vec![
            v(104, "5.4", &["arm64-v8a"], &[]),
            v(103, "5.4", &["x86_64"], &[]),
            v(102, "5.4", &["x86"], &[]),
            v(101, "5.4", &["armeabi-v7a"], &[]),
            v(94, "5.3", &["arm64-v8a"], &[]),
        ]);
        assert_eq!(select_versions(&p, None, &[], false).len(), 4);
        let only = select_versions(&p, None, &[Abi::X86_64], false);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].version_code, 103);
        assert_eq!(select_versions(&p, Some(94), &[], false).len(), 1);
    }

    #[test]
    fn filters_foreign_signers() {
        let mut other = v(50, "9.9", &[], &[]);
        other.signers = vec!["bb".repeat(32)];
        let p = pkg(vec![other, v(20, "2.0", &[], &[])]);
        assert_eq!(select_versions(&p, None, &[], false)[0].version_code, 20);
    }
}
