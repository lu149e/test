//! Consistency and dependency checks for a set of split APKs meant to be installed together.

use crate::analysis::ApkAnalysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uad_core::{parse_split_name, Abi, SplitDimension};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SplitSetReport {
    pub package: Option<String>,
    pub version_code: Option<i64>,
    pub base_present: bool,
    pub splits: Vec<String>,
    pub abis: Vec<Abi>,
    pub densities: Vec<String>,
    pub languages: Vec<String>,
    pub feature_modules: Vec<String>,
    /// Required split types (Android 13+ `requiredSplitTypes`) not provided by any member.
    pub unmet_required_split_types: Vec<String>,
    /// A consistent, installable set (`adb install-multiple` would accept it).
    pub installable: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validates APKs that are meant to form one installation. `members` are (label, analysis).
pub fn validate_split_set(members: &[(String, &ApkAnalysis)]) -> SplitSetReport {
    let mut r = SplitSetReport::default();
    if members.is_empty() {
        r.errors.push("empty split set".into());
        return r;
    }
    let bases: Vec<_> = members.iter().filter(|(_, a)| a.manifest.split.is_none()).collect();
    match bases.len() {
        0 => r.errors.push("no base APK in the set".into()),
        1 => r.base_present = true,
        n => r.errors.push(format!("{n} base APKs in the set")),
    }
    let packages: BTreeSet<&str> = members.iter().map(|(_, a)| a.manifest.package.as_str()).collect();
    if packages.len() > 1 {
        r.errors.push(format!("mixed packages: {packages:?}"));
    }
    r.package = packages.iter().next().map(|s| s.to_string());
    let versions: BTreeSet<i64> = members.iter().map(|(_, a)| a.manifest.version_code).collect();
    if versions.len() > 1 {
        r.errors.push(format!("mixed version codes: {versions:?}"));
    }
    r.version_code = versions.iter().next().copied();

    // Every member must be validly signed by the same signer.
    let mut signer_sets: BTreeMap<Vec<String>, Vec<&str>> = BTreeMap::new();
    for (label, a) in members {
        if !a.signature.verified {
            r.errors.push(format!("{label}: signature not verified"));
        }
        let mut ids: Vec<String> = a.signature.signers.iter().map(|c| c.sha256.to_hex()).collect();
        ids.sort();
        signer_sets.entry(ids).or_default().push(label);
    }
    if signer_sets.len() > 1 {
        r.errors.push("members are signed by different certificates".into());
    }

    let mut names = BTreeSet::new();
    let mut provided_types: BTreeSet<String> = BTreeSet::new();
    let mut required_types: BTreeSet<String> = BTreeSet::new();
    let mut feature_names: BTreeSet<String> = BTreeSet::new();
    for (label, a) in members {
        provided_types.extend(a.manifest.split_types.iter().cloned());
        required_types.extend(a.manifest.required_split_types.iter().cloned());
        if let Some(s) = &a.manifest.split {
            if !names.insert(s.clone()) {
                r.errors.push(format!("{label}: duplicate split name {s}"));
            }
            if a.manifest.is_feature_split {
                feature_names.insert(s.clone());
            }
            let parsed = parse_split_name(s);
            match parsed.dimension {
                Some(SplitDimension::Abi(abi)) => r.abis.push(abi),
                Some(SplitDimension::Density(d)) => r.densities.push(d),
                Some(SplitDimension::Language(l)) => r.languages.push(l),
                Some(SplitDimension::Other(_)) => {}
                None => {
                    if let Some(m) = parsed.module {
                        feature_names.insert(m);
                    }
                }
            }
        } else {
            // Native code shipped in the base counts as coverage too.
            r.abis.extend(a.native_abis.iter().copied());
        }
    }
    for (label, a) in members {
        if let Some(target) = &a.manifest.config_for_split {
            if !feature_names.contains(target) {
                r.errors.push(format!("{label}: configForSplit={target} but that feature split is not in the set"));
            }
        }
        for dep in &a.manifest.uses_splits {
            if !names.contains(dep) {
                r.errors.push(format!("{label}: <uses-split {dep}> not satisfied"));
            }
        }
    }
    r.unmet_required_split_types = required_types.difference(&provided_types).cloned().collect();
    if !r.unmet_required_split_types.is_empty() {
        r.errors.push(format!("required split types not provided: {}", r.unmet_required_split_types.join(", ")));
    }
    if bases.len() == 1 && bases[0].1.manifest.is_split_required && members.len() == 1 {
        r.errors.push("base APK declares that splits are required".into());
    }
    r.abis.sort();
    r.abis.dedup();
    let abi_splits = r.abis.len();
    if abi_splits > 1 && members.iter().any(|(_, a)| a.manifest.split.as_deref().is_some_and(|s| s.starts_with("config.") && parse_split_name(s).dimension.as_ref().is_some_and(|d| matches!(d, SplitDimension::Abi(_))))) {
        r.warnings.push("set contains several ABI splits; the installer will only use the device's".into());
    }
    r.splits = names.into_iter().collect();
    r.feature_modules = feature_names.into_iter().collect();
    r.installable = r.errors.is_empty();
    r
}
