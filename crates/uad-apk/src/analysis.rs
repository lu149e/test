//! One-stop analysis of an APK or App Bundle file.

use crate::manifest::ApkManifest;
use crate::sig::{self, SignatureReport, VerifyPolicy};
use crate::zipinfo::ZipLayout;
use crate::{axml, proto_xml};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use uad_core::{Abi, Sha1Digest, Sha256Digest, VariantKind};

const MAX_MANIFEST: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Container {
    Apk,
    AppBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModuleInfo {
    pub name: String,
    pub native_abis: Vec<Abi>,
    pub has_dex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApkAnalysis {
    pub container: Container,
    pub file_size: u64,
    pub sha256: Sha256Digest,
    pub sha1: Sha1Digest,
    pub manifest: ApkManifest,
    /// ABIs with native libraries (`lib/<abi>/*.so`).
    pub native_abis: Vec<Abi>,
    pub has_dex: bool,
    pub entry_count: usize,
    /// App Bundle modules (only for AABs).
    pub modules: Vec<ModuleInfo>,
    pub classification: VariantKind,
    pub signature: SignatureReport,
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid ZIP/APK: {0}")]
    Zip(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error(transparent)]
    Verify(#[from] sig::VerifyError),
}

/// Streams the file once to compute SHA-256 and SHA-1.
pub fn file_digests(path: &Path) -> std::io::Result<(Sha256Digest, Sha1Digest, u64)> {
    let mut f = File::open(path)?;
    let mut s256 = Sha256::new();
    let mut s1 = Sha1::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        s256.update(&buf[..n]);
        s1.update(&buf[..n]);
        total += n as u64;
    }
    Ok((Sha256Digest(s256.finalize().into()), Sha1Digest(s1.finalize().into()), total))
}

fn read_limited<R: Read>(r: R, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.take(limit).read_to_end(&mut v)?;
    Ok(v)
}

fn abi_from_lib_path(name: &str, prefix: &str) -> Option<Result<Abi, String>> {
    let rest = name.strip_prefix(prefix)?.strip_prefix("lib/")?;
    let (dir, file) = rest.split_once('/')?;
    if !file.ends_with(".so") {
        return None;
    }
    Some(Abi::parse(dir).ok_or_else(|| dir.to_string()))
}

pub fn analyze(path: &Path) -> Result<ApkAnalysis, AnalysisError> {
    let (sha256, sha1, file_size) = file_digests(path)?;
    let mut f = File::open(path)?;
    let layout = ZipLayout::read(&mut f).map_err(|e| AnalysisError::Zip(e.to_string()))?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(File::open(path)?)).map_err(|e| AnalysisError::Zip(e.to_string()))?;
    let names = layout.entry_names.clone();
    let mut warnings = Vec::new();

    let is_bundle = names.iter().any(|n| n == "BundleConfig.pb") && names.iter().any(|n| n == "base/manifest/AndroidManifest.xml");
    let (container, manifest_el) = if is_bundle {
        let data = read_limited(
            zip.by_name("base/manifest/AndroidManifest.xml")
                .map_err(|e| AnalysisError::Zip(e.to_string()))?,
            MAX_MANIFEST,
        )?;
        (Container::AppBundle, proto_xml::parse(&data).map_err(AnalysisError::Manifest)?)
    } else {
        let data = read_limited(
            zip.by_name("AndroidManifest.xml")
                .map_err(|e| AnalysisError::Manifest(format!("AndroidManifest.xml: {e}")))?,
            MAX_MANIFEST,
        )?;
        (Container::Apk, axml::parse(&data).map_err(|e| AnalysisError::Manifest(e.to_string()))?)
    };
    let manifest = ApkManifest::from_element(&manifest_el).map_err(|e| AnalysisError::Manifest(e.to_string()))?;

    let mut modules = Vec::new();
    let mut abis = BTreeSet::new();
    let mut has_dex = false;
    if container == Container::AppBundle {
        let module_names: BTreeSet<String> = names
            .iter()
            .filter_map(|n| n.strip_suffix("/manifest/AndroidManifest.xml"))
            .filter(|m| !m.contains('/'))
            .map(String::from)
            .collect();
        for m in module_names {
            let prefix = format!("{m}/");
            let mut mabis = BTreeSet::new();
            for n in &names {
                match abi_from_lib_path(n, &prefix) {
                    Some(Ok(a)) => {
                        mabis.insert(a);
                    }
                    Some(Err(d)) => warnings.push(format!("unknown native ABI directory {d} in module {m}")),
                    None => {}
                }
            }
            let mdex = names.iter().any(|n| n.starts_with(&format!("{m}/dex/")) && n.ends_with(".dex"));
            has_dex |= mdex;
            abis.extend(mabis.iter().copied());
            modules.push(ModuleInfo {
                name: m,
                native_abis: mabis.into_iter().collect(),
                has_dex: mdex,
            });
        }
    } else {
        for n in &names {
            match abi_from_lib_path(n, "") {
                Some(Ok(a)) => {
                    abis.insert(a);
                }
                Some(Err(d)) => warnings.push(format!("unknown native ABI directory lib/{d}")),
                None => {}
            }
            if !n.contains('/') && n.starts_with("classes") && n.ends_with(".dex") {
                has_dex = true;
            }
        }
    }
    warnings.dedup();
    let native_abis: Vec<Abi> = abis.into_iter().collect();

    let classification = if container == Container::AppBundle {
        VariantKind::AppBundle
    } else if let Some(split) = &manifest.split {
        if manifest.is_feature_split {
            VariantKind::FeatureSplit { module: split.clone() }
        } else {
            VariantKind::from_split_name(split)
        }
    } else if !manifest.is_standalone() {
        VariantKind::BaseApk
    } else if native_abis.len() == 1 {
        VariantKind::StandaloneApk { abis: native_abis.clone() }
    } else {
        VariantKind::UniversalApk
    };

    let signature = sig::verify_with_layout(
        path,
        &mut f,
        &layout,
        VerifyPolicy {
            min_sdk: manifest.min_sdk,
            target_sdk: manifest.target_sdk,
        },
    )?;
    if manifest.debuggable {
        warnings.push("application is debuggable".into());
    }
    Ok(ApkAnalysis {
        container,
        file_size,
        sha256,
        sha1,
        manifest,
        native_abis,
        has_dex,
        entry_count: names.len(),
        modules,
        classification,
        signature,
        warnings,
    })
}

/// Reads only the manifest (no hashing or signature verification). For quick indexing.
pub fn peek_manifest(path: &Path) -> Result<(Container, ApkManifest), AnalysisError> {
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(File::open(path)?)).map_err(|e| AnalysisError::Zip(e.to_string()))?;
    if zip.by_name("BundleConfig.pb").is_ok() {
        let data = read_limited(
            zip.by_name("base/manifest/AndroidManifest.xml")
                .map_err(|e| AnalysisError::Zip(e.to_string()))?,
            MAX_MANIFEST,
        )?;
        let el = proto_xml::parse(&data).map_err(AnalysisError::Manifest)?;
        return Ok((
            Container::AppBundle,
            ApkManifest::from_element(&el).map_err(|e| AnalysisError::Manifest(e.to_string()))?,
        ));
    }
    let data = read_limited(
        zip.by_name("AndroidManifest.xml")
            .map_err(|e| AnalysisError::Manifest(format!("AndroidManifest.xml: {e}")))?,
        MAX_MANIFEST,
    )?;
    Ok((
        Container::Apk,
        ApkManifest::parse_binary(&data).map_err(|e| AnalysisError::Manifest(e.to_string()))?,
    ))
}
