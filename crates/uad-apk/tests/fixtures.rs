//! Cross-checks uad-apk against fixtures produced by official tooling
//! (scripts/gen-fixtures.sh) and against the verdicts of `apksigner verify`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uad_apk::{analyze, validate_split_set, ApkAnalysis, Container};
use uad_core::{Abi, SplitDimension, VariantKind};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[derive(Debug, Default)]
struct Expected {
    verifies: bool,
    error: String,
    signer_sha256: Vec<String>,
}

/// Parses the `--min-sdk-version 24` verdicts recorded by the fixture generator.
fn apksigner_expectations() -> HashMap<String, Expected> {
    let text = std::fs::read_to_string(fixtures().join("apksigner-expected.txt")).unwrap();
    let mut map = HashMap::new();
    let mut current: Option<String> = None;
    let mut in_24 = false;
    for line in text.lines() {
        if let Some(n) = line.strip_prefix("== ") {
            current = Some(n.to_string());
            in_24 = false;
            map.insert(n.to_string(), Expected::default());
        } else if line == "-- min-sdk-24" {
            in_24 = true;
        } else if in_24 {
            let e = map.get_mut(current.as_ref().unwrap()).unwrap();
            if line == "Verifies" {
                e.verifies = true;
            } else if let Some(err) = line.strip_prefix("ERROR: ") {
                e.error = err.to_string();
            } else if let Some(idx) = line.find("certificate SHA-256 digest: ") {
                e.signer_sha256.push(line[idx + 28..].trim().to_string());
            }
        }
    }
    map
}

fn all_apks() -> Vec<PathBuf> {
    let mut v = vec![];
    for dir in [fixtures(), fixtures().join("splits")] {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "apk") {
                v.push(p);
            }
        }
    }
    v.sort();
    v
}

#[test]
fn signature_verdicts_match_apksigner() {
    let expected = apksigner_expectations();
    let apks = all_apks();
    assert!(apks.len() >= 14, "fixtures missing: {apks:?}");
    for path in apks {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let exp = expected.get(&name).unwrap_or_else(|| panic!("no apksigner verdict for {name}"));
        let a = analyze(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let sig = &a.signature;
        if exp.verifies {
            assert!(sig.verified, "{name}: apksigner verifies but we do not: {:?}", sig.errors);
            let ours: Vec<String> = sig.identity_digests().iter().map(|d| d.to_hex()).collect();
            for s in &exp.signer_sha256 {
                assert!(ours.contains(s), "{name}: signer {s} not found in {ours:?}");
            }
        } else if exp.error.contains("Target SDK version") {
            // apksigner enforces platform policy as an error; we verify integrity and warn.
            assert!(sig.verified, "{name}: {:?}", sig.errors);
            assert!(sig.warnings.iter().any(|w| w.contains("targetSdk")), "{name}: {:?}", sig.warnings);
        } else {
            assert!(!sig.verified, "{name}: apksigner rejects ({}) but we accept", exp.error);
        }
    }
}

#[test]
fn tampered_apk_is_rejected_with_digest_mismatch() {
    let a = analyze(&fixtures().join("tampered_content.apk")).unwrap();
    assert!(!a.signature.verified);
    let all = a.signature.errors.join("\n");
    assert!(all.contains("digest mismatch"), "{all}");
    // The v1 per-entry digest must catch the modified library too.
    assert!(all.contains("lib/arm64-v8a/libuad.so"), "{all}");
}

#[test]
fn schemes_detected() {
    let a = analyze(&fixtures().join("rsa_v1v2v3.apk")).unwrap();
    assert_eq!(a.signature.schemes_verified, vec!["v3", "v2", "v1"]);
    assert!(a.signature.v1.declared_apk_schemes.contains(&2));
    assert!(a.signature.v1.entries_verified > 3);

    let a = analyze(&fixtures().join("ec_v2only.apk")).unwrap();
    assert_eq!(a.signature.schemes_verified, vec!["v2"]);
    assert_eq!(a.signature.signers[0].public_key_algorithm, "EC P-256");
    // minSdk 21 without v1 is a platform-compatibility warning, not a tamper error.
    assert!(a.signature.warnings.iter().any(|w| w.contains("Android < 7.0")));

    let a = analyze(&fixtures().join("rsa3072_v3only.apk")).unwrap();
    assert_eq!(a.signature.schemes_verified, vec!["v3"]);
    assert_eq!(a.signature.signers[0].public_key_bits, Some(3072));

    let a = analyze(&fixtures().join("rsa_verity.apk")).unwrap();
    let v2 = a.signature.v2.as_ref().unwrap();
    assert!(v2.signers[0].content_digests_verified.iter().any(|d| format!("{d:?}").contains("Verity")), "{v2:?}");
}

#[test]
fn key_rotation_lineage_is_verified() {
    let a = analyze(&fixtures().join("rotated_v3.apk")).unwrap();
    assert!(a.signature.verified, "{:?}", a.signature.errors);
    assert!(a.signature.v31.is_some(), "rotation targets v3.1 by default");
    assert_eq!(a.signature.lineage.len(), 2);
    let ids = a.signature.identity_digests();
    assert!(ids.contains(&a.signature.lineage[0].sha256));
    assert!(ids.contains(&a.signature.lineage[1].sha256));
    assert_ne!(a.signature.lineage[0].sha256, a.signature.lineage[1].sha256);
}

#[test]
fn manifest_and_classification() {
    let a = analyze(&fixtures().join("rsa_v1v2v3.apk")).unwrap();
    let m = &a.manifest;
    assert_eq!(m.package, "com.uad.fixture");
    assert_eq!(m.version_code, 42);
    assert_eq!(m.version_name.as_deref(), Some("1.2.3"));
    assert_eq!(m.min_sdk, Some(21));
    assert_eq!(m.target_sdk, Some(34));
    assert_eq!(m.permissions, vec!["android.permission.INTERNET"]);
    assert_eq!(m.features.len(), 1);
    assert!(!m.features[0].required);
    assert!(!m.has_code);
    assert_eq!(a.native_abis, vec![Abi::Arm64V8a, Abi::X86_64]);
    assert_eq!(a.classification, VariantKind::UniversalApk);
    assert_eq!(a.container, Container::Apk);

    let s = |f: &str| analyze(&fixtures().join("splits").join(f)).unwrap();
    assert_eq!(s("base-master.apk").classification, VariantKind::BaseApk);
    assert_eq!(s("base-master.apk").manifest.required_split_types, vec!["base__abi", "base__density"]);
    assert!(matches!(s("base-arm64_v8a.apk").classification, VariantKind::ConfigSplit { dimension: SplitDimension::Abi(Abi::Arm64V8a), .. }));
    assert!(matches!(s("base-xxhdpi.apk").classification, VariantKind::ConfigSplit { dimension: SplitDimension::Density(ref d), .. } if d == "xxhdpi"));
    assert!(matches!(s("base-es.apk").classification, VariantKind::ConfigSplit { dimension: SplitDimension::Language(ref l), .. } if l == "es"));
}

#[test]
fn app_bundle_is_analyzed() {
    let a = analyze(&fixtures().join("app.aab")).unwrap();
    assert_eq!(a.container, Container::AppBundle);
    assert_eq!(a.classification, VariantKind::AppBundle);
    assert_eq!(a.manifest.package, "com.uad.fixture");
    assert_eq!(a.manifest.version_code, 42);
    assert_eq!(a.manifest.min_sdk, Some(21));
    assert_eq!(a.modules.len(), 1);
    assert_eq!(a.modules[0].name, "base");
    assert_eq!(a.native_abis, vec![Abi::Arm64V8a, Abi::X86_64]);
    // Bundle signed with jarsigner (upload-key style): v1 verification applies.
    assert!(a.signature.v1.verified, "{:?}", a.signature.errors);
}

#[test]
fn split_set_validation() {
    let dir = fixtures().join("splits");
    let load = |f: &str| (f.to_string(), analyze(&dir.join(f)).unwrap());
    let all: Vec<(String, ApkAnalysis)> = ["base-master.apk", "base-arm64_v8a.apk", "base-x86_64.apk", "base-xxhdpi.apk", "base-mdpi.apk", "base-es.apk"]
        .iter()
        .map(|f| load(f))
        .collect();
    let refs: Vec<(String, &ApkAnalysis)> = all.iter().map(|(n, a)| (n.clone(), a)).collect();
    let r = validate_split_set(&refs);
    assert!(r.installable, "{:?}", r.errors);
    assert_eq!(r.abis, vec![Abi::Arm64V8a, Abi::X86_64]);
    assert!(r.languages.contains(&"es".to_string()));

    // A device-specific subset is still valid.
    let subset: Vec<(String, &ApkAnalysis)> = refs.iter().filter(|(n, _)| ["base-master.apk", "base-arm64_v8a.apk", "base-xxhdpi.apk"].contains(&n.as_str())).cloned().collect();
    assert!(validate_split_set(&subset).installable);

    // Without a density split the base's requiredSplitTypes are unmet.
    let no_density: Vec<(String, &ApkAnalysis)> = refs.iter().filter(|(n, _)| ["base-master.apk", "base-arm64_v8a.apk"].contains(&n.as_str())).cloned().collect();
    let r = validate_split_set(&no_density);
    assert!(!r.installable);
    assert_eq!(r.unmet_required_split_types, vec!["base__density"]);

    // Mixing in an APK from a different signer is rejected.
    let other = analyze(&fixtures().join("ec_v2only.apk")).unwrap();
    let mut mixed = subset.clone();
    mixed.push(("ec_v2only.apk".into(), &other));
    let r = validate_split_set(&mixed);
    assert!(!r.installable);
}

#[test]
fn generated_universal_from_bundletool() {
    let a = analyze(&fixtures().join("generated_universal.apk")).unwrap();
    assert!(a.signature.verified);
    assert!(a.manifest.split.is_none());
    assert_eq!(a.classification, VariantKind::UniversalApk);
    assert_eq!(a.native_abis, vec![Abi::Arm64V8a, Abi::X86_64]);
}

#[test]
fn apks_archive_roundtrip() {
    let dir = fixtures().join("splits");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("set.apks");
    let base = dir.join("base-master.apk");
    let abi = dir.join("base-arm64_v8a.apk");
    let (h1, _, s1) = uad_apk::file_digests(&base).unwrap();
    let (h2, _, s2) = uad_apk::file_digests(&abi).unwrap();
    uad_apk::apks::write_apks(
        &out,
        "com.uad.fixture",
        42,
        &[("base-master.apk".into(), base.as_path(), None, h1.to_hex(), s1), ("base-arm64_v8a.apk".into(), abi.as_path(), Some("config.arm64_v8a".into()), h2.to_hex(), s2)],
    )
    .unwrap();
    let mut z = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
    let mut inner = Vec::new();
    std::io::Read::read_to_end(&mut z.by_name("splits/base-master.apk").unwrap(), &mut inner).unwrap();
    assert_eq!(inner, std::fs::read(&base).unwrap(), "APKs must be copied byte-for-byte");
    assert!(z.by_name("uad-apks.json").is_ok());
}

#[test]
fn garbage_is_rejected_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("x.apk");
    std::fs::write(&p, b"PK\x03\x04 definitely not a zip").unwrap();
    assert!(analyze(&p).is_err());
    std::fs::write(&p, []).unwrap();
    assert!(analyze(&p).is_err());
}

#[test]
fn stripped_v2_v3_block_is_detected() {
    let src = fixtures().join("rsa_v1v2v3.apk");
    let data = std::fs::read(&src).unwrap();
    let mut f = std::fs::File::open(&src).unwrap();
    let layout = uad_apk::zipinfo::ZipLayout::read(&mut f).unwrap();
    let block = layout.signing_block.as_ref().unwrap();
    let mut out = data[..block.offset as usize].to_vec();
    out.extend_from_slice(&data[layout.cd_offset as usize..]);
    let eocd = out.len() - layout.eocd.len();
    out[eocd + 16..eocd + 20].copy_from_slice(&(block.offset as u32).to_le_bytes());
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("stripped.apk");
    std::fs::write(&p, out).unwrap();
    let a = analyze(&p).unwrap();
    assert!(a.signature.v1.verified, "v1 itself is intact");
    assert!(!a.signature.verified);
    assert!(a.signature.errors.iter().any(|e| e.contains("stripped")), "{:?}", a.signature.errors);
}
