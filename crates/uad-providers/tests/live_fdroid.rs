//! Live tests against https://f-droid.org (network required). Run with:
//! `cargo test -p uad-providers --test live_fdroid -- --ignored`

use uad_core::{DiscoveryRequest, OfferLayout, PackageName, Provider, ProviderError};
use uad_providers::fdroid::{FdroidConfig, FdroidProvider};

#[tokio::test]
#[ignore = "network"]
async fn verified_index_and_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let p = FdroidProvider::new(FdroidConfig::default(), dir.path().to_path_buf());
    let req = DiscoveryRequest {
        package: PackageName::new("org.fdroid.fdroid").unwrap(),
        version_code: None,
        abis: vec![],
        locale: None,
    };
    let d = p.discover(&req).await.unwrap();
    let offer = &d.offers[0];
    println!("{:#?}", offer);
    assert_eq!(offer.layout, OfferLayout::UniversalApk);
    assert!(offer.files[0].expected.sha256.is_some());
    assert!(offer.trust.as_ref().unwrap().authenticated);

    // ABI-split app.
    let req = DiscoveryRequest {
        package: PackageName::new("InfinityLoop1309.NewPipeEnhanced").unwrap(),
        ..req.clone()
    };
    let d = p.discover(&req).await.unwrap();
    println!(
        "abi offers: {:?}",
        d.offers.iter().map(|o| (o.version_code, o.abis.clone())).collect::<Vec<_>>()
    );
    assert!(d.offers.len() >= 2);

    let req = DiscoveryRequest {
        package: PackageName::new("com.whatsapp").unwrap(),
        ..req
    };
    assert!(matches!(p.discover(&req).await, Err(ProviderError::NotFound)));
}

#[tokio::test]
#[ignore = "network"]
async fn wrong_pinned_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = FdroidConfig {
        fingerprint: "00".repeat(32),
        ..Default::default()
    };
    let p = FdroidProvider::new(cfg, dir.path().to_path_buf());
    let err = p.index().await.unwrap_err();
    println!("{err}");
    assert!(matches!(err, ProviderError::Integrity(_)));
}
