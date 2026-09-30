//! Android signature verification: v1 (JAR), v2, v3 and v3.1, plus cross-scheme consistency
//! and anti-stripping checks. A valid signature proves *integrity* and *signer identity*; it
//! says nothing about whether the code is benign or where it was distributed.

pub mod cert;
pub mod crypto;
pub mod v1;
pub mod v2v3;

use crate::zipinfo::{ZipLayout, ZipLayoutError};
use cert::CertificateInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use uad_core::Sha256Digest;
use v1::V1Report;
use v2v3::{SchemeReport, SOURCE_STAMP_V1_BLOCK_ID, SOURCE_STAMP_V2_BLOCK_ID, V2_BLOCK_ID, V31_BLOCK_ID, V3_BLOCK_ID, VERITY_PADDING_BLOCK_ID};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureReport {
    pub v1: V1Report,
    pub v2: Option<SchemeReport>,
    pub v3: Option<SchemeReport>,
    pub v31: Option<SchemeReport>,
    pub source_stamp_present: bool,
    pub other_blocks: Vec<String>,
    /// Signer certificates in effect, strongest scheme first, de-duplicated.
    pub signers: Vec<CertificateInfo>,
    /// Certificate rotation history (oldest first), when a v3 lineage is present.
    pub lineage: Vec<CertificateInfo>,
    pub schemes_verified: Vec<String>,
    /// Cryptographic integrity and signer identity verified with no errors.
    pub verified: bool,
    pub errors: Vec<String>,
    /// Platform-policy or hygiene issues (e.g. v1 missing for minSdk < 24) that do not imply
    /// tampering.
    pub warnings: Vec<String>,
}

impl SignatureReport {
    /// All certificate digests that legitimately identify this signer (current signers plus
    /// rotation history). Used to compare against store-declared signers and pinned identities.
    pub fn identity_digests(&self) -> Vec<Sha256Digest> {
        let mut v: Vec<Sha256Digest> = self.signers.iter().map(|c| c.sha256).collect();
        for c in &self.lineage {
            if !v.contains(&c.sha256) {
                v.push(c.sha256);
            }
        }
        v
    }

    /// Signer certificate Android uses on current platform versions.
    pub fn current_signer(&self) -> Option<&CertificateInfo> {
        self.signers.first()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyPolicy {
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    Layout(#[from] ZipLayoutError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(String),
}

pub fn verify_apk(path: &Path, policy: VerifyPolicy) -> Result<SignatureReport, VerifyError> {
    let mut f = File::open(path)?;
    let layout = ZipLayout::read(&mut f)?;
    verify_with_layout(path, &mut f, &layout, policy)
}

pub fn verify_with_layout(path: &Path, f: &mut File, layout: &ZipLayout, policy: VerifyPolicy) -> Result<SignatureReport, VerifyError> {
    let mut rep = SignatureReport {
        v1: V1Report::default(),
        v2: None,
        v3: None,
        v31: None,
        source_stamp_present: false,
        other_blocks: vec![],
        signers: vec![],
        lineage: vec![],
        schemes_verified: vec![],
        verified: false,
        errors: vec![],
        warnings: vec![],
    };

    let dups = layout.duplicate_entries();
    if !dups.is_empty() {
        rep.errors.push(format!("duplicate ZIP entries: {}", dups.join(", ")));
    }
    if let Some(off) = layout.first_local_header_offset {
        if off != 0 {
            rep.warnings.push(format!("{off} bytes of data precede the first ZIP entry"));
        }
    }

    let mut cache = HashMap::new();
    let mut v2_attrs = Vec::new();
    if let Some(block) = &layout.signing_block {
        for (id, value) in &block.pairs {
            match *id {
                V2_BLOCK_ID => {
                    let (r, attrs) = v2v3::verify_block(f, layout, *id, value, &mut cache);
                    v2_attrs = attrs;
                    rep.v2 = Some(r);
                }
                V3_BLOCK_ID => rep.v3 = Some(v2v3::verify_block(f, layout, *id, value, &mut cache).0),
                V31_BLOCK_ID => rep.v31 = Some(v2v3::verify_block(f, layout, *id, value, &mut cache).0),
                SOURCE_STAMP_V1_BLOCK_ID | SOURCE_STAMP_V2_BLOCK_ID => rep.source_stamp_present = true,
                VERITY_PADDING_BLOCK_ID => {}
                other => rep.other_blocks.push(format!("0x{other:08x}")),
            }
        }
    }

    let file = File::open(path)?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file)).map_err(|e| VerifyError::Zip(e.to_string()))?;
    rep.v1 = v1::verify_jar(&mut zip, &layout.entry_names);

    // Per-scheme results.
    let schemes: [(&str, Option<&SchemeReport>); 3] = [("v3.1", rep.v31.as_ref()), ("v3", rep.v3.as_ref()), ("v2", rep.v2.as_ref())];
    for (name, s) in schemes {
        if let Some(s) = s {
            if s.verified {
                rep.schemes_verified.push(name.into());
            } else {
                for e in &s.errors {
                    rep.errors.push(format!("{name}: {e}"));
                }
                for (i, signer) in s.signers.iter().enumerate() {
                    for e in &signer.errors {
                        rep.errors.push(format!("{name} signer #{}: {e}", i + 1));
                    }
                }
            }
        }
    }
    if rep.v1.present {
        if rep.v1.verified {
            rep.schemes_verified.push("v1".into());
        } else {
            for e in &rep.v1.errors {
                rep.errors.push(format!("v1: {e}"));
            }
            for s in &rep.v1.signers {
                for e in &s.errors {
                    rep.errors.push(format!("v1 {}: {e}", s.signature_file));
                }
            }
        }
        rep.warnings.extend(rep.v1.warnings.iter().map(|w| format!("v1: {w}")));
    }

    let any_present = rep.v1.present || rep.v2.is_some() || rep.v3.is_some() || rep.v31.is_some();
    if !any_present {
        rep.errors.push("APK is not signed".into());
    }

    // Anti-stripping: schemes declared by v1 / v2 must be present.
    for id in &rep.v1.declared_apk_schemes {
        let missing = match id {
            2 => rep.v2.is_none(),
            3 => rep.v3.is_none(),
            _ => false,
        };
        if missing {
            rep.errors.push(format!(
                "v1 signature declares APK Signature Scheme v{id} but that block is missing (stripped)"
            ));
        }
    }
    for attrs in &v2_attrs {
        if let Some((_, v)) = attrs.iter().find(|(id, _)| *id == v2v3::STRIPPING_PROTECTION_ATTR_ID) {
            if v.len() >= 4 && u32::from_le_bytes(v[..4].try_into().unwrap()) == 3 && rep.v3.is_none() {
                rep.errors.push("v2 signature declares a v3 signature that is missing (stripped)".into());
            }
        }
    }

    // Collect signers and check cross-scheme consistency.
    let add = |c: &CertificateInfo, list: &mut Vec<CertificateInfo>| {
        if !list.iter().any(|x| x.sha256 == c.sha256) {
            list.push(c.clone());
        }
    };
    let mut signers = Vec::new();
    let mut lineage = Vec::new();
    for s in [rep.v31.as_ref(), rep.v3.as_ref()].into_iter().flatten() {
        for signer in &s.signers {
            if let Some(c) = &signer.certificate {
                add(c, &mut signers);
            }
            for c in &signer.lineage {
                add(c, &mut lineage);
            }
        }
    }
    let v2_certs: Vec<CertificateInfo> = rep
        .v2
        .iter()
        .flat_map(|s| s.signers.iter().filter_map(|x| x.certificate.clone()))
        .collect();
    let v1_certs: Vec<CertificateInfo> = rep.v1.signers.iter().filter_map(|x| x.certificate.clone()).collect();
    for c in v2_certs.iter().chain(v1_certs.iter()) {
        add(c, &mut signers);
    }
    let known: Vec<Sha256Digest> = signers.iter().map(|c| c.sha256).chain(lineage.iter().map(|c| c.sha256)).collect();
    let v3_present = rep.v3.is_some() || rep.v31.is_some();
    if v3_present {
        // v2/v1 signers must appear in the v3 signer set or its lineage.
        let v3_ids: Vec<Sha256Digest> = [rep.v31.as_ref(), rep.v3.as_ref()]
            .into_iter()
            .flatten()
            .flat_map(|s| s.signers.iter())
            .flat_map(|s| s.certificate.iter().map(|c| c.sha256).chain(s.lineage.iter().map(|c| c.sha256)))
            .collect();
        for c in v2_certs.iter().chain(v1_certs.iter()) {
            if !v3_ids.contains(&c.sha256) {
                rep.errors.push(format!("signer {} of v1/v2 is unrelated to the v3 signer", c.sha256));
            }
        }
    } else if !v2_certs.is_empty() && !v1_certs.is_empty() {
        let mut a: Vec<_> = v2_certs.iter().map(|c| c.sha256).collect();
        let mut b: Vec<_> = v1_certs.iter().map(|c| c.sha256).collect();
        a.sort();
        a.dedup();
        b.sort();
        b.dedup();
        if a != b {
            rep.errors.push("v1 and v2 signer sets differ".into());
        }
    }
    let _ = known;
    rep.signers = signers;
    rep.lineage = lineage;

    // Platform policy (warnings).
    if let Some(min) = policy.min_sdk {
        if min < 24 && !rep.v1.present && any_present {
            rep.warnings
                .push(format!("minSdk {min} < 24 but no v1 signature: will not install on Android < 7.0"));
        }
    }
    if let Some(t) = policy.target_sdk {
        if t >= 30 && rep.v2.is_none() && !v3_present && rep.v1.present {
            rep.warnings
                .push(format!("targetSdk {t} requires APK Signature Scheme v2+ on Android 11+, only v1 present"));
        }
    }
    if rep
        .signers
        .iter()
        .any(|c| c.public_key_bits.is_some_and(|b| c.public_key_algorithm == "RSA" && b < 2048))
    {
        rep.warnings.push("signer uses an RSA key shorter than 2048 bits".into());
    }

    rep.verified = any_present && rep.errors.is_empty() && !rep.schemes_verified.is_empty();
    Ok(rep)
}
