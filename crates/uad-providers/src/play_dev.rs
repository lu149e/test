//! Google Play Developer API provider (official, documented, authorised).
//!
//! For apps owned by the operator's Play Console account, `generatedApks` returns the APKs that
//! Google Play generated from the uploaded bundle, signed with the app signing key: the
//! universal APK, split APKs per variant and standalone APKs. This is the authoritative way to
//! obtain the exact files Play distributes, without any device emulation.
//!
//! API: https://developers.google.com/android-publisher/api-ref/rest/v3/generatedapks

use crate::http;
use async_trait::async_trait;
use base64::Engine;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uad_core::{
    Discovery, DiscoveryRequest, ExpectedDigests, FileRole, FileSource, Header, Offer, OfferLayout, PackageName, Provider, ProviderError,
    ProviderInfo, ProviderKind, RemoteFile, SecretStore, Sha256Digest, TrustAnchor,
};

pub const SECRET_SERVICE_ACCOUNT: &str = "play_dev.service_account_json";
const API: &str = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications";
const SCOPE: &str = "https://www.googleapis.com/auth/androidpublisher";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayDevConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Track used to find the current version when none is requested.
    #[serde(default = "default_track")]
    pub track: String,
}

fn default_track() -> String {
    "production".into()
}

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedApksListResponse {
    #[serde(default)]
    pub generated_apks: Vec<GeneratedApksPerSigningKey>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedApksPerSigningKey {
    #[serde(default)]
    pub certificate_sha256_hash: Option<String>,
    #[serde(default)]
    pub generated_split_apks: Vec<GeneratedSplitApk>,
    #[serde(default)]
    pub generated_standalone_apks: Vec<GeneratedStandaloneApk>,
    #[serde(default)]
    pub generated_universal_apk: Option<GeneratedUniversalApk>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedSplitApk {
    pub download_id: String,
    #[serde(default)]
    pub variant_id: Option<i64>,
    #[serde(default)]
    pub module_name: Option<String>,
    #[serde(default)]
    pub split_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedStandaloneApk {
    pub download_id: String,
    #[serde(default)]
    pub variant_id: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUniversalApk {
    pub download_id: String,
}

pub struct PlayDevProvider {
    cfg: PlayDevConfig,
    secrets: Arc<dyn SecretStore>,
    client: reqwest::Client,
    token: Mutex<Option<(String, i64)>>,
}

fn b64url(d: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d)
}

/// Builds an RS256-signed JWT assertion for the OAuth 2.0 JWT bearer flow.
fn jwt_assertion(sa: &ServiceAccount, now: i64) -> Result<String, ProviderError> {
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&sa.private_key).map_err(|e| ProviderError::NotConfigured(format!("service account key: {e}")))?;
    let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({"iss": sa.client_email, "scope": SCOPE, "aud": sa.token_uri, "iat": now, "exp": now + 3600});
    let payload = b64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
    let sig = signer.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&sig.to_bytes())))
}

impl PlayDevProvider {
    pub fn new(cfg: PlayDevConfig, secrets: Arc<dyn SecretStore>) -> Self {
        Self { cfg, secrets, client: http::client(), token: Mutex::new(None) }
    }

    async fn access_token(&self) -> Result<String, ProviderError> {
        let now = chrono::Utc::now().timestamp();
        let mut t = self.token.lock().await;
        if let Some((tok, exp)) = t.as_ref() {
            if *exp > now + 60 {
                return Ok(tok.clone());
            }
        }
        let json = self.secrets.get(SECRET_SERVICE_ACCOUNT).ok_or_else(|| ProviderError::NotConfigured("no service account configured".into()))?;
        let sa: ServiceAccount = serde_json::from_str(&json).map_err(|e| ProviderError::NotConfigured(format!("service account JSON: {e}")))?;
        let assertion = jwt_assertion(&sa, now)?;
        let resp = self
            .client
            .post(&sa.token_uri)
            .form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
            .send()
            .await
            .map_err(http::map_err)?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Auth(format!("token endpoint HTTP {s}: {}", body.chars().take(200).collect::<String>())));
        }
        let tr: TokenResponse = resp.json().await.map_err(http::map_err)?;
        *t = Some((tr.access_token.clone(), now + tr.expires_in.max(60)));
        Ok(tr.access_token)
    }

    async fn api<T: for<'de> Deserialize<'de>>(&self, method: reqwest::Method, url: &str) -> Result<T, ProviderError> {
        let token = self.access_token().await?;
        let resp = self.client.request(method, url).bearer_auth(token).header("Content-Length", "0").send().await.map_err(http::map_err)?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(http::status_error(s, &body.chars().take(300).collect::<String>()));
        }
        resp.json().await.map_err(http::map_err)
    }

    /// Highest version code released on the configured track (via a throw-away edit).
    async fn current_version(&self, pkg: &str) -> Result<i64, ProviderError> {
        #[derive(Deserialize)]
        struct Edit {
            id: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Track {
            #[serde(default)]
            releases: Vec<Release>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Release {
            #[serde(default)]
            version_codes: Vec<String>,
            #[serde(default)]
            status: Option<String>,
        }
        let edit: Edit = self.api(reqwest::Method::POST, &format!("{API}/{pkg}/edits")).await?;
        let track: Result<Track, _> = self.api(reqwest::Method::GET, &format!("{API}/{pkg}/edits/{}/tracks/{}", edit.id, self.cfg.track)).await;
        let _ = self.api::<serde_json::Value>(reqwest::Method::DELETE, &format!("{API}/{pkg}/edits/{}", edit.id)).await;
        let track = track?;
        track
            .releases
            .iter()
            .filter(|r| matches!(r.status.as_deref(), Some("completed") | Some("inProgress") | None))
            .flat_map(|r| r.version_codes.iter().filter_map(|v| v.parse::<i64>().ok()))
            .max()
            .ok_or_else(|| ProviderError::NotFound)
    }
}

/// Maps a generatedApks response to offers. Pure, unit-tested.
pub fn generated_to_offers(pkg: &PackageName, vc: i64, resp: &GeneratedApksListResponse, bearer: &str) -> Vec<Offer> {
    let auth = vec![Header { name: "Authorization".into(), value: format!("Bearer {bearer}"), sensitive: true }];
    let url = |id: &str| format!("{API}/{pkg}/generatedApks/{vc}/downloads/{id}:download?alt=media");
    let file = |role: FileRole, name: String, id: &str| RemoteFile {
        role,
        file_name: name,
        source: FileSource::Http { url: url(id), headers: auth.clone(), url_is_sensitive: false },
        size: None,
        expected: ExpectedDigests::default(),
    };
    let mut offers = vec![];
    for (ki, key) in resp.generated_apks.iter().enumerate() {
        let trust = key.certificate_sha256_hash.as_deref().and_then(Sha256Digest::parse_flexible).map(|d| TrustAnchor {
            signer_cert_sha256: vec![d],
            asserted_by: "Google Play Developer API (generatedApks, app signing key)".into(),
            authenticated: false,
        });
        let base_offer = |layout, files, channel: String| Offer {
            provider: "play_dev".into(),
            package: pkg.clone(),
            version_code: vc,
            version_name: None,
            layout,
            files,
            abis: vec![],
            min_sdk: None,
            trust: trust.clone(),
            device_profile: None,
            channel,
        };
        if let Some(u) = &key.generated_universal_apk {
            offers.push(base_offer(
                OfferLayout::UniversalApk,
                vec![file(FileRole::Standalone, format!("{pkg}-{vc}-universal.apk"), &u.download_id)],
                format!("Play Developer API generated universal APK (signing key #{ki})"),
            ));
        }
        let mut by_variant: BTreeMap<i64, Vec<&GeneratedSplitApk>> = BTreeMap::new();
        for s in &key.generated_split_apks {
            by_variant.entry(s.variant_id.unwrap_or(0)).or_default().push(s);
        }
        for (variant, splits) in by_variant {
            let files = splits
                .iter()
                .map(|s| {
                    let module = s.module_name.clone().unwrap_or_else(|| "base".into());
                    let split = s.split_id.clone().unwrap_or_default();
                    let is_base = module == "base" && split.is_empty();
                    let name = if is_base { format!("{pkg}-{vc}-v{variant}-base.apk") } else { format!("{pkg}-{vc}-v{variant}-{module}-{split}.apk").replace("-.apk", ".apk") };
                    let split_name = match (module.as_str(), split.as_str()) {
                        ("base", s) => s.to_string(),
                        (m, "") => m.to_string(),
                        (m, s) => format!("{m}.{s}"),
                    };
                    file(if is_base { FileRole::Base } else { FileRole::Split(split_name) }, name, &s.download_id)
                })
                .collect();
            offers.push(base_offer(OfferLayout::SplitSet, files, format!("Play Developer API split APKs, variant {variant}")));
        }
        for s in &key.generated_standalone_apks {
            let v = s.variant_id.unwrap_or(0);
            offers.push(base_offer(
                OfferLayout::AbiSpecificApk,
                vec![file(FileRole::Standalone, format!("{pkg}-{vc}-standalone-v{v}.apk"), &s.download_id)],
                format!("Play Developer API standalone APK, variant {v}"),
            ));
        }
    }
    offers
}

#[async_trait]
impl Provider for PlayDevProvider {
    fn info(&self) -> ProviderInfo {
        let configured = self.secrets.get(SECRET_SERVICE_ACCOUNT).is_some();
        ProviderInfo {
            id: "play_dev".into(),
            name: "Google Play Developer API".into(),
            kind: ProviderKind::Official,
            enabled: self.cfg.enabled,
            requires_credentials: true,
            priority: 5,
            description: "Official Android Publisher API: universal and split APKs generated and signed by Google Play, for apps in your developer account.".into(),
            status: match (self.cfg.enabled, configured) {
                (false, _) => "Disabled in configuration.".into(),
                (true, false) => "Enabled but no service account configured (uad secrets set-file play_dev.service_account_json <file>).".into(),
                (true, true) => "Configured. Only apps owned by the developer account are accessible.".into(),
            },
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        if !self.cfg.enabled {
            return Err(ProviderError::NotConfigured("play_dev provider disabled".into()));
        }
        let pkg = req.package.as_str();
        let vc = match req.version_code {
            Some(v) => v,
            None => self.current_version(pkg).await?,
        };
        let resp: GeneratedApksListResponse = self.api(reqwest::Method::GET, &format!("{API}/{pkg}/generatedApks/{vc}")).await?;
        let token = self.access_token().await?;
        let offers = generated_to_offers(&req.package, vc, &resp, &token);
        if offers.is_empty() {
            return Err(ProviderError::NotFound);
        }
        let mut d = Discovery { offers, ..Default::default() };
        d.notes.push("Access tokens embedded in download requests expire after about one hour.".into());
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_generated_apks() {
        let json = r#"{"generatedApks":[{"certificateSha256Hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "generatedUniversalApk":{"downloadId":"U1"},
          "generatedSplitApks":[{"downloadId":"B","variantId":1,"moduleName":"base","splitId":""},
                                {"downloadId":"A","variantId":1,"moduleName":"base","splitId":"config.arm64_v8a"},
                                {"downloadId":"F","variantId":1,"moduleName":"camera","splitId":""}],
          "generatedStandaloneApks":[{"downloadId":"S1","variantId":7}]}]}"#;
        let r: GeneratedApksListResponse = serde_json::from_str(json).unwrap();
        let pkg = PackageName::new("com.example.app").unwrap();
        let offers = generated_to_offers(&pkg, 12, &r, "tok");
        assert_eq!(offers.len(), 3);
        assert_eq!(offers[0].layout, OfferLayout::UniversalApk);
        assert!(offers[0].trust.is_some());
        let split = &offers[1];
        assert_eq!(split.files.iter().filter(|f| f.role == FileRole::Base).count(), 1);
        assert!(split.files.iter().any(|f| f.role == FileRole::Split("config.arm64_v8a".into())));
        assert!(split.files.iter().any(|f| f.role == FileRole::Split("camera".into())));
        assert_eq!(offers[2].layout, OfferLayout::AbiSpecificApk);
    }

    #[test]
    fn jwt_is_well_formed() {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
        let sa = ServiceAccount { client_email: "x@y.iam.gserviceaccount.com".into(), private_key: pem, token_uri: default_token_uri() };
        let jwt = jwt_assertion(&sa, 1_700_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["scope"], SCOPE);
        // Signature verifies with the public key.
        use rsa::signature::Verifier;
        let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key.to_public_key());
        let sig = rsa::pkcs1v15::Signature::try_from(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
    }
}
