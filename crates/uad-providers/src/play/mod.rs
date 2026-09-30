//! Google Play provider (device protocol).
//!
//! Requires the operator's own Google account (AAS token). For every configured device
//! profile it asks Play which files that device would receive, so ABI/density/language
//! variants are discovered by varying the declared device configuration. Only free apps are
//! acquired automatically; paid apps are delivered only if the account already owns them.

pub mod client;
pub mod device;
pub mod proto;

use async_trait::async_trait;
use client::{PlayClient, Session};
use device::{parse_properties, DeviceProfile, BUILTIN_PROFILES};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uad_core::{
    Abi, AppMetadata, Availability, Discovery, DiscoveryRequest, ExpectedDigests, FileRole, FileSource, Header, KnownVariant, Offer, OfferLayout,
    Provider, ProviderError, ProviderInfo, ProviderKind, RemoteFile, SecretStore, Sha1Digest, Sha256Digest, TrustAnchor,
};

pub const SECRET_EMAIL: &str = "play.email";
pub const SECRET_AAS: &str = "play.aas_token";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Device profiles to query (built-in: arm64, armv7, x86_64, x86; or names from `profiles_file`).
    #[serde(default = "default_profiles")]
    pub device_profiles: Vec<String>,
    /// Optional `.properties` file with additional device profiles.
    #[serde(default)]
    pub profiles_file: Option<PathBuf>,
    #[serde(default = "default_locale")]
    pub locale: String,
    #[serde(default = "default_tz")]
    pub timezone: String,
    /// Pause between consecutive Play requests (rate limiting).
    #[serde(default = "default_delay")]
    pub request_delay_ms: u64,
}

fn default_profiles() -> Vec<String> {
    vec!["arm64".into()]
}
fn default_locale() -> String {
    "en_US".into()
}
fn default_tz() -> String {
    "UTC".into()
}
fn default_delay() -> u64 {
    750
}

impl Default for PlayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            device_profiles: default_profiles(),
            profiles_file: None,
            locale: default_locale(),
            timezone: default_tz(),
            request_delay_ms: default_delay(),
        }
    }
}

pub struct PlayProvider {
    cfg: PlayConfig,
    client: PlayClient,
    secrets: Arc<dyn SecretStore>,
    lock: tokio::sync::Mutex<()>,
}

pub fn load_profiles(cfg: &PlayConfig) -> Result<Vec<DeviceProfile>, ProviderError> {
    let file_profiles = match &cfg.profiles_file {
        Some(p) => parse_properties(&std::fs::read_to_string(p).map_err(|e| ProviderError::NotConfigured(format!("{}: {e}", p.display())))?),
        None => vec![],
    };
    cfg.device_profiles
        .iter()
        .map(|n| {
            file_profiles
                .iter()
                .find(|p| &p.name == n)
                .cloned()
                .or_else(|| DeviceProfile::builtin(n))
                .ok_or_else(|| ProviderError::NotConfigured(format!("unknown device profile {n} (built-in: {BUILTIN_PROFILES:?})")))
        })
        .collect()
}

fn session_key(profile: &str) -> String {
    format!("play.session.{profile}")
}

impl PlayProvider {
    pub fn new(cfg: PlayConfig, secrets: Arc<dyn SecretStore>) -> Self {
        let client = PlayClient::new(&cfg.locale, &cfg.timezone);
        Self { cfg, client, secrets, lock: tokio::sync::Mutex::new(()) }
    }

    pub fn client(&self) -> &PlayClient {
        &self.client
    }

    /// Exchanges a one-time `oauth_token` for an AAS token and stores both email and token.
    pub async fn setup_account(&self, email: &str, oauth_token: &str) -> Result<(), ProviderError> {
        let profile = load_profiles(&self.cfg)?.into_iter().next().ok_or_else(|| ProviderError::NotConfigured("no device profile".into()))?;
        let aas = self.client.exchange_oauth_token(email, oauth_token, &profile).await?;
        self.secrets.put(SECRET_EMAIL, email).map_err(ProviderError::Other)?;
        self.secrets.put(SECRET_AAS, &aas).map_err(ProviderError::Other)?;
        for p in BUILTIN_PROFILES {
            let _ = self.secrets.delete(&session_key(p));
        }
        Ok(())
    }

    fn credentials(&self) -> Result<(String, String), ProviderError> {
        match (self.secrets.get(SECRET_EMAIL), self.secrets.get(SECRET_AAS)) {
            (Some(e), Some(t)) if !e.is_empty() && !t.is_empty() => Ok((e, t)),
            _ => Err(ProviderError::NotConfigured("Google account not configured (run `uad play-login`)".into())),
        }
    }

    async fn session(&self, profile: &DeviceProfile, force_new: bool) -> Result<Session, ProviderError> {
        if !force_new {
            if let Some(s) = self.secrets.get(&session_key(&profile.name)).and_then(|j| serde_json::from_str::<Session>(&j).ok()) {
                return Ok(s);
            }
        }
        let (email, aas) = self.credentials()?;
        let s = self.client.login(&email, &aas, profile).await?;
        let json = serde_json::to_string(&s).map_err(|e| ProviderError::Other(e.to_string()))?;
        self.secrets.put(&session_key(&profile.name), &json).map_err(ProviderError::Other)?;
        Ok(s)
    }

    async fn pause(&self) {
        tokio::time::sleep(Duration::from_millis(self.cfg.request_delay_ms)).await;
    }

    async fn discover_with_profile(&self, profile: &DeviceProfile, req: &DiscoveryRequest) -> Result<(proto::Item, Offer), ProviderError> {
        let pkg = req.package.as_str();
        let mut session = self.session(profile, false).await?;
        let item = match self.client.details(profile, &session, pkg).await {
            Err(ProviderError::Auth(_)) => {
                session = self.session(profile, true).await?;
                self.client.details(profile, &session, pkg).await?
            }
            r => r?,
        };
        self.pause().await;
        let app = item.details.as_ref().and_then(|d| d.app_details.clone()).ok_or(ProviderError::NotFound)?;
        let vc = req.version_code.or(app.version_code).ok_or_else(|| ProviderError::Protocol("details without version code".into()))?;
        let paid = item.offer.first().and_then(|o| o.micros).unwrap_or(0) > 0;
        let dtok = if paid {
            None // never purchase; delivery succeeds only if the account already owns the app
        } else {
            let t = self.client.acquire_free(profile, &session, pkg, vc).await?;
            self.pause().await;
            t
        };
        let data = self.client.delivery(profile, &session, pkg, vc, dtok.as_deref()).await.map_err(|e| match e {
            ProviderError::Denied(m) if paid => ProviderError::Denied(format!("paid app not owned by the configured account: {m}")),
            e => e,
        })?;
        self.pause().await;
        Ok((item.clone(), delivery_to_offer(pkg, vc, app.version_string.clone(), &data, profile, &app)))
    }
}

/// Converts a delivery response into an offer. Pure, unit-tested.
pub fn delivery_to_offer(
    pkg: &str,
    vc: i64,
    version_name: Option<String>,
    data: &proto::AndroidAppDeliveryData,
    profile: &DeviceProfile,
    app: &proto::AppDetails,
) -> Offer {
    let cookies: Vec<Header> = if data.download_auth_cookie.is_empty() {
        vec![]
    } else {
        let v = data
            .download_auth_cookie
            .iter()
            .filter_map(|c| Some(format!("{}={}", c.name.as_ref()?, c.value.as_ref()?)))
            .collect::<Vec<_>>()
            .join("; ");
        vec![Header { name: "Cookie".into(), value: v, sensitive: true }]
    };
    let src = |url: &str| FileSource::Http { url: url.to_string(), headers: cookies.clone(), url_is_sensitive: true };
    let digests = |sha256: Option<&String>, sha1: Option<&String>| ExpectedDigests {
        sha256: sha256.and_then(|s| Sha256Digest::parse_flexible(s)),
        sha1: sha1.and_then(|s| Sha1Digest::parse_flexible(s)),
    };
    let has_splits = !data.split_delivery_data.is_empty();
    let mut files = vec![RemoteFile {
        role: if has_splits { FileRole::Base } else { FileRole::Standalone },
        file_name: if has_splits { format!("{pkg}-{vc}-base.apk") } else { format!("{pkg}-{vc}.apk") },
        source: src(data.download_url.as_deref().unwrap_or_default()),
        size: data.download_size.map(|s| s as u64),
        expected: digests(data.sha256.as_ref(), data.sha1.as_ref()),
    }];
    for s in &data.split_delivery_data {
        let (Some(name), Some(url)) = (&s.name, &s.download_url) else { continue };
        files.push(RemoteFile {
            role: FileRole::Split(name.clone()),
            file_name: format!("{pkg}-{vc}-{name}.apk"),
            source: src(url),
            size: s.download_size.map(|x| x as u64),
            expected: digests(s.sha256.as_ref(), s.sha1.as_ref()),
        });
    }
    for f in &data.additional_file {
        let Some(url) = &f.download_url else { continue };
        let kind = if f.file_type.unwrap_or(0) == 0 { "main" } else { "patch" };
        files.push(RemoteFile {
            role: FileRole::Obb(kind.into()),
            file_name: format!("{kind}.{}.{pkg}.obb", f.version_code.unwrap_or(vc as i32)),
            source: src(url),
            size: f.size.map(|x| x as u64),
            expected: digests(None, f.sha1.as_ref()),
        });
    }
    if let Some(dm) = &data.dex_metadata {
        if let Some(url) = &dm.download_url {
            files.push(RemoteFile {
                role: FileRole::DexMetadata,
                file_name: format!("{pkg}-{vc}.dm"),
                source: src(url),
                size: dm.download_size.map(|x| x as u64),
                expected: digests(dm.sha256.as_ref(), None),
            });
        }
    }
    let signers: Vec<Sha256Digest> = app.certificate_set.iter().filter_map(|c| c.sha256.as_deref().and_then(Sha256Digest::parse_flexible)).collect();
    Offer {
        provider: "play".into(),
        package: uad_core::PackageName::new(pkg).expect("validated package"),
        version_code: vc,
        version_name,
        layout: if has_splits { OfferLayout::SplitSet } else { OfferLayout::UniversalApk },
        files,
        abis: profile.abis().iter().filter_map(|a| Abi::parse(a)).take(1).collect(),
        min_sdk: None,
        trust: (!signers.is_empty()).then(|| TrustAnchor {
            signer_cert_sha256: signers,
            asserted_by: "Google Play app details (TLS-authenticated session)".into(),
            authenticated: false,
        }),
        device_profile: Some(profile.name.clone()),
        channel: format!("Google Play delivery for device profile '{}'", profile.name),
    }
}

#[async_trait]
impl Provider for PlayProvider {
    fn info(&self) -> ProviderInfo {
        let configured = self.credentials().is_ok();
        ProviderInfo {
            id: "play".into(),
            name: "Google Play".into(),
            kind: ProviderKind::Official,
            enabled: self.cfg.enabled,
            requires_credentials: true,
            priority: 10,
            description: format!("Google Play device protocol with the operator's account; profiles {:?}", self.cfg.device_profiles),
            status: if !self.cfg.enabled {
                "Disabled in configuration.".into()
            } else if configured {
                "Account configured. Free apps only; availability depends on account, country and device profile.".into()
            } else {
                "Enabled but no Google account configured (uad play-login).".into()
            },
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        if !self.cfg.enabled {
            return Err(ProviderError::NotConfigured("play provider disabled".into()));
        }
        self.credentials()?;
        let _guard = self.lock.lock().await; // one Play conversation at a time per account
        let profiles = load_profiles(&self.cfg)?;
        let mut d = Discovery::default();
        let mut first_err = None;
        let mut delivered_splits = std::collections::BTreeSet::new();
        let mut listed_splits: Vec<String> = vec![];
        for profile in &profiles {
            match self.discover_with_profile(profile, req).await {
                Ok((item, offer)) => {
                    let app = item.details.as_ref().and_then(|x| x.app_details.as_ref());
                    if d.metadata.is_none() {
                        d.metadata = Some(AppMetadata {
                            title: item.title.clone().or_else(|| app.and_then(|a| a.title.clone())),
                            developer: item.creator.clone().or_else(|| app.and_then(|a| a.developer_name.clone())),
                            icon_url: None,
                            summary: None,
                            version_name: app.and_then(|a| a.version_string.clone()),
                            version_code: Some(offer.version_code),
                            source: "play".into(),
                        });
                    }
                    if let Some(a) = app {
                        listed_splits.extend(a.split_id.iter().cloned());
                    }
                    for f in &offer.files {
                        if let FileRole::Split(n) = &f.role {
                            delivered_splits.insert(n.clone());
                        }
                    }
                    d.offers.push(offer);
                }
                Err(e) => {
                    d.notes.push(format!("profile {}: {e}", profile.name));
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        listed_splits.sort();
        listed_splits.dedup();
        for s in listed_splits.into_iter().filter(|s| !delivered_splits.contains(s)) {
            d.known.push(KnownVariant {
                provider: "play".into(),
                version_code: d.metadata.as_ref().and_then(|m| m.version_code),
                version_name: None,
                description: "split listed by Google Play details but not delivered to any configured device profile".into(),
                role: Some(FileRole::Split(s)),
                abis: vec![],
                availability: Availability::Known,
            });
        }
        if d.offers.is_empty() {
            return Err(first_err.unwrap_or(ProviderError::NotFound));
        }
        Ok(d)
    }
}


#[cfg(test)]
mod tests {
    use super::proto::*;
    use super::*;

    #[test]
    fn delivery_mapping() {
        let data = AndroidAppDeliveryData {
            download_size: Some(100),
            sha1: Some("qZk+NkcGgWq6PiVxeFDCbJzQ2J0=".into()),
            download_url: Some("https://play.googleapis.com/download/by-token/x?token=SECRET".into()),
            additional_file: vec![],
            download_auth_cookie: vec![HttpCookie { name: Some("MarketDA".into()), value: Some("123".into()) }],
            split_delivery_data: vec![SplitDeliveryData {
                name: Some("config.arm64_v8a".into()),
                download_size: Some(5),
                sha1: None,
                download_url: Some("https://play.googleapis.com/s".into()),
                sha256: Some("n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg".into()),
            }],
            sha256: None,
            dex_metadata: None,
        };
        let app = AppDetails { certificate_set: vec![CertificateSet { certificate_hash: None, sha256: Some("aa".repeat(32)) }], ..Default::default() };
        let p = DeviceProfile::builtin("arm64").unwrap();
        let o = delivery_to_offer("com.example.app", 7, Some("1.0".into()), &data, &p, &app);
        assert_eq!(o.layout, OfferLayout::SplitSet);
        assert_eq!(o.files.len(), 2);
        assert_eq!(o.files[0].role, FileRole::Base);
        assert!(o.files[0].expected.sha1.is_some());
        assert_eq!(o.files[1].role, FileRole::Split("config.arm64_v8a".into()));
        assert!(o.files[1].expected.sha256.is_some());
        match &o.files[0].source {
            FileSource::Http { headers, url_is_sensitive, .. } => {
                assert!(url_is_sensitive);
                assert!(headers[0].sensitive);
            }
            _ => panic!(),
        }
        assert!(!o.files[0].source.redacted().contains("SECRET"));
        assert_eq!(o.trust.unwrap().signer_cert_sha256.len(), 1);
        assert_eq!(o.abis, vec![Abi::Arm64V8a]);
    }
}
