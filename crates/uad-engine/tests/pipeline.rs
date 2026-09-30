//! End-to-end pipeline tests using local inputs only (no network).
//! The bundletool test needs `UAD_TEST_BUNDLETOOL=/path/bundletool-all.jar` and a JDK.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use uad_core::{Availability, JobOptions, JobState, VariantKind};
use uad_engine::{Config, Engine, JobReport};

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../uad-apk/tests/fixtures").join(p)
}

fn engine(dir: &Path) -> Arc<Engine> {
    let mut cfg = Config::default();
    cfg.data_dir = dir.to_path_buf();
    cfg.providers.play_web = false;
    cfg.providers.fdroid.enabled = false;
    cfg.bundletool.auto_download = false;
    if let Ok(j) = std::env::var("UAD_TEST_BUNDLETOOL") {
        cfg.bundletool.jar = Some(j.into());
    } else {
        cfg.bundletool.enabled = false;
    }
    Engine::open(cfg).unwrap()
}

async fn run(e: &Engine, input: &str, opts: JobOptions) -> (JobState, JobReport, String) {
    let id = e.create_job(input, opts).unwrap();
    e.run_job(&id).await;
    let v = e.job(&id).unwrap();
    (v.job.state, e.report(&id).unwrap().unwrap(), id)
}

fn inbox(dir: &Path) -> PathBuf {
    dir.join("inbox")
}

#[tokio::test]
async fn local_universal_apk_end_to_end() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    std::fs::copy(fixture("rsa_v1v2v3.apk"), inbox(d.path()).join("a.apk")).unwrap();
    let (state, r, id) = run(&e, "https://play.google.com/store/apps/details?id=com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Completed, "{:#?}", r);
    assert_eq!(r.outcome, "universal_original");
    let v = r.variants.iter().find(|v| v.availability == Availability::Retrieved).unwrap();
    assert_eq!(v.kind, Some(VariantKind::UniversalApk));
    assert_eq!(v.origin.as_deref(), Some("original"));
    assert!(v.provenance_seq.is_some());
    // Bytes are served unmodified and only because they are verified.
    let (path, name) = e.verified_artifact(v.sha256.as_ref().unwrap()).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), std::fs::read(fixture("rsa_v1v2v3.apk")).unwrap());
    assert_eq!(name, "a.apk");
    assert!(e.ledger.verify_chain().unwrap().valid);
    // Event log shows every state of the machine.
    let states: Vec<String> = e.job(&id).unwrap().events.iter().map(|ev| ev.to_state.clone()).collect();
    assert_eq!(states, ["queued", "resolving", "discovering", "acquiring", "processing", "verifying", "completed"]);
}

#[tokio::test]
async fn split_set_from_container_and_apks_export() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    let f = std::fs::File::create(inbox(d.path()).join("set.apks")).unwrap();
    let mut z = zip::ZipWriter::new(f);
    for n in ["base-master.apk", "base-arm64_v8a.apk", "base-x86_64.apk", "base-xxhdpi.apk", "base-mdpi.apk", "base-es.apk"] {
        z.start_file(n, zip::write::SimpleFileOptions::default()).unwrap();
        std::io::copy(&mut std::fs::File::open(fixture(&format!("splits/{n}"))).unwrap(), &mut z).unwrap();
    }
    z.finish().unwrap();
    let (state, r, id) = run(&e, "com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Completed, "{:#?}", r);
    assert_eq!(r.outcome, "split_set");
    assert_eq!(r.split_sets.len(), 1);
    assert!(r.split_sets[0].report.installable);
    assert_eq!(r.counts.retrieved, 6);
    let (apks, name) = e.export_split_set(&id, 0).await.unwrap();
    assert!(name.ends_with(".apks"));
    let z = zip::ZipArchive::new(std::fs::File::open(apks).unwrap()).unwrap();
    assert_eq!(z.len(), 7);
}

#[tokio::test]
async fn tampered_apk_fails_and_is_quarantined() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    std::fs::copy(fixture("tampered_content.apk"), inbox(d.path()).join("t.apk")).unwrap();
    let (state, r, _) = run(&e, "com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Failed);
    let v = r.variants.iter().find(|v| v.sha256.is_some()).unwrap();
    assert_eq!(v.availability, Availability::Failed);
    assert!(v.checks.iter().any(|c| c.name == "signature" && c.detail.contains("digest mismatch")));
    assert!(e.verified_artifact(v.sha256.as_ref().unwrap()).is_err(), "unverified bytes must not be served");
}

#[tokio::test]
async fn signer_change_is_detected_by_pinning() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    std::fs::copy(fixture("rsa_v1v2v3.apk"), inbox(d.path()).join("a.apk")).unwrap();
    let (state, _, _) = run(&e, "com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Completed);
    // Same package and version, different key.
    std::fs::remove_file(inbox(d.path()).join("a.apk")).unwrap();
    std::fs::copy(fixture("ec_v2only.apk"), inbox(d.path()).join("b.apk")).unwrap();
    let (state, r, _) = run(&e, "com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Failed, "{:#?}", r.variants);
    let v = r.variants.iter().find(|v| v.sha256.is_some()).unwrap();
    assert!(v.checks.iter().any(|c| c.name == "signer_pin" && c.detail.contains("SIGNER CHANGED")));
}

#[tokio::test]
async fn unknown_package_fails_with_reasons() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    let (state, r, id) = run(&e, "com.nobody.nothing", JobOptions::default()).await;
    assert_eq!(state, JobState::Failed);
    assert_eq!(r.outcome, "none");
    assert!(e.job(&id).unwrap().job.error.unwrap().contains("no downloadable offer"));
    assert!(e.create_job("not a package", JobOptions::default()).is_err());
}

#[tokio::test]
async fn interrupted_job_is_recovered_on_start() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(inbox(d.path())).unwrap();
    std::fs::copy(fixture("rsa_v1v2v3.apk"), inbox(d.path()).join("a.apk")).unwrap();
    let id = {
        let e = engine(d.path());
        let id = e.create_job("com.uad.fixture", JobOptions::default()).unwrap();
        // Simulate a crash in the middle of acquisition.
        for (a, b) in [(JobState::Queued, JobState::Resolving), (JobState::Resolving, JobState::Discovering), (JobState::Discovering, JobState::Acquiring)] {
            e.store.transition(&id, a, b, None).unwrap();
        }
        id
    };
    let e = engine(d.path());
    e.start().await.unwrap();
    for _ in 0..100 {
        if e.job(&id).unwrap().job.state.is_terminal() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let v = e.job(&id).unwrap();
    assert_eq!(v.job.state, JobState::Completed);
    assert!(v.events.iter().any(|ev| ev.message.as_deref() == Some("recovered after restart")));
}

#[tokio::test]
async fn app_bundle_to_generated_universal_apk() {
    if std::env::var("UAD_TEST_BUNDLETOOL").is_err() {
        eprintln!("skipped: UAD_TEST_BUNDLETOOL not set");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let e = engine(d.path());
    std::fs::copy(fixture("app.aab"), inbox(d.path()).join("app.aab")).unwrap();
    let (state, r, _) = run(&e, "com.uad.fixture", JobOptions::default()).await;
    assert_eq!(state, JobState::Completed, "{:#?} {:?}", r.variants, r.notes);
    assert_eq!(r.outcome, "universal_generated", "{:?}", r.notes);
    let g = r.variants.iter().find(|v| v.kind == Some(VariantKind::GeneratedUniversalApk)).unwrap();
    assert_eq!(g.origin.as_deref(), Some("generated_from_aab"));
    assert_eq!(g.availability, Availability::Retrieved);
    let bundle = r.variants.iter().find(|v| v.kind == Some(VariantKind::AppBundle)).unwrap();
    assert_eq!(g.derived_from, bundle.sha256);
    assert_ne!(g.signer_sha256, bundle.signer_sha256, "generated APK is signed by the local build key");
    let prov = e.provenance(g.sha256.as_ref().unwrap()).unwrap();
    assert_eq!(prov[0]["record"]["origin"], "generated_from_aab");
}
