//! Live checks of the Google Play device protocol that do not need an account.
//! `cargo test -p uad-providers --test live_play -- --ignored --nocapture`

use uad_providers::play::client::PlayClient;
use uad_providers::play::device::{DeviceProfile, BUILTIN_PROFILES};

#[tokio::test]
#[ignore = "network"]
async fn anonymous_checkin_accepts_builtin_profiles() {
    let c = PlayClient::new("en_US", "UTC");
    for name in BUILTIN_PROFILES {
        let p = DeviceProfile::builtin(name).unwrap();
        let r = c.checkin(&p).await.unwrap_or_else(|e| panic!("{name}: {e}"));
        println!(
            "{name}: gsf id {:x}, consistency token present: {}",
            r.android_id.unwrap(),
            r.device_checkin_consistency_token.is_some()
        );
        assert!(r.android_id.unwrap() != 0);
    }
}

#[tokio::test]
#[ignore = "network"]
async fn bad_oauth_token_is_reported_as_auth_error() {
    let c = PlayClient::new("en_US", "UTC");
    let p = DeviceProfile::builtin("arm64").unwrap();
    let e = c.exchange_oauth_token("nobody@example.com", "oauth2_4/invalid", &p).await.unwrap_err();
    println!("{e}");
    assert!(matches!(
        e,
        uad_core::ProviderError::Auth(_) | uad_core::ProviderError::Denied(_) | uad_core::ProviderError::Protocol(_)
    ));
}
