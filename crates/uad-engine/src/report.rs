//! Job report: the user-facing, persisted result of a job.

use serde::{Deserialize, Serialize};
use uad_apk::SplitSetReport;
use uad_core::{Abi, AppMetadata, Availability, FileRole, VariantKind};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobReport {
    pub package: Option<String>,
    pub play_url: Option<String>,
    pub metadata: Option<AppMetadata>,
    pub providers: Vec<ProviderOutcome>,
    /// `universal_original`, `universal_generated`, `split_set`, `variants` or `none`.
    pub outcome: String,
    pub outcome_description: String,
    pub variants: Vec<VariantEntry>,
    pub split_sets: Vec<SplitSetEntry>,
    pub notes: Vec<String>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub known: usize,
    pub identified: usize,
    pub retrieved: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderOutcome {
    pub id: String,
    pub name: String,
    /// `offers`, `metadata_only`, `not_found`, `not_configured`, `denied`, `auth_error`, `error`, `timeout`, `skipped`.
    pub status: String,
    pub message: Option<String>,
    pub offers: usize,
    pub duration_ms: u128,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

impl Check {
    pub fn new(name: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        Self { name: name.into(), status, detail: detail.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantEntry {
    pub id: usize,
    pub provider: String,
    pub channel: Option<String>,
    pub device_profile: Option<String>,
    pub version_code: Option<i64>,
    pub version_name: Option<String>,
    pub role: Option<FileRole>,
    pub file_name: Option<String>,
    pub description: Option<String>,
    pub availability: Availability,
    pub planned: bool,
    pub kind: Option<VariantKind>,
    /// `original` or `generated_from_aab`.
    pub origin: Option<String>,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub abis: Vec<Abi>,
    pub min_sdk: Option<u32>,
    pub source: Option<String>,
    pub offer_index: Option<usize>,
    pub derived_from: Option<String>,
    pub deduplicated: bool,
    pub signature_schemes: Vec<String>,
    pub signer_sha256: Vec<String>,
    pub checks: Vec<Check>,
    pub verified: Option<bool>,
    pub error: Option<String>,
    pub provenance_seq: Option<i64>,
}

impl VariantEntry {
    pub fn blank(id: usize, provider: &str) -> Self {
        Self {
            id,
            provider: provider.into(),
            channel: None,
            device_profile: None,
            version_code: None,
            version_name: None,
            role: None,
            file_name: None,
            description: None,
            availability: Availability::Known,
            planned: false,
            kind: None,
            origin: None,
            sha256: None,
            size: None,
            abis: vec![],
            min_sdk: None,
            source: None,
            offer_index: None,
            derived_from: None,
            deduplicated: false,
            signature_schemes: vec![],
            signer_sha256: vec![],
            checks: vec![],
            verified: None,
            error: None,
            provenance_seq: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitSetEntry {
    pub label: String,
    pub provider: String,
    pub device_profile: Option<String>,
    pub offer_index: usize,
    pub version_code: i64,
    /// Variant entry ids of the members.
    pub members: Vec<usize>,
    pub report: SplitSetReport,
}
