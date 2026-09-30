//! Google Play device-protocol client: checkin, authentication, details, purchase (free apps
//! only) and delivery. Uses the operator's own Google account; no access control is bypassed:
//! Play decides what the account/device profile is entitled to.

use super::device::DeviceProfile;
use super::proto::*;
use crate::http;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uad_core::ProviderError;

pub const BASE: &str = "https://android.clients.google.com";
const GMS: &str = "com.google.android.gms";
const VENDING: &str = "com.android.vending";
/// Signature digest of the Play Store / GMS apps, sent as `client_sig`/`callerSig`.
const PLAY_CLIENT_SIG: &str = "38918a453d07199354f8b19af05ec6562ced5788";
const PLAY_SCOPE: &str = "oauth2:https://www.googleapis.com/auth/googleplay";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub profile: String,
    pub gsf_id: u64,
    pub checkin_consistency_token: Option<String>,
    pub device_config_token: Option<String>,
    pub auth_token: String,
    pub dfe_cookie: Option<String>,
    pub created_at: i64,
}

pub struct PlayClient {
    http: reqwest::Client,
    base: String,
    pub locale: String,
    pub timezone: String,
}

/// Parses `key=value` lines returned by `/auth`. Keys are lower-cased.
pub fn parse_form_reply(body: &str) -> HashMap<String, String> {
    body.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

fn decode_err(e: prost::DecodeError) -> ProviderError {
    ProviderError::Protocol(format!("invalid protobuf response: {e}"))
}

impl PlayClient {
    pub fn new(locale: &str, timezone: &str) -> Self {
        Self::with_base(BASE, locale, timezone)
    }

    pub fn with_base(base: &str, locale: &str, timezone: &str) -> Self {
        Self { http: http::client(), base: base.trim_end_matches('/').to_string(), locale: locale.into(), timezone: timezone.into() }
    }

    fn lang(&self) -> String {
        self.locale.split('_').next().unwrap_or("en").to_string()
    }

    fn country(&self) -> String {
        self.locale.split('_').nth(1).unwrap_or("us").to_ascii_lowercase()
    }

    async fn auth_request(&self, form: Vec<(&str, String)>, extra_headers: &[(&str, String)]) -> Result<HashMap<String, String>, ProviderError> {
        let mut req = self.http.post(format!("{}/auth", self.base)).header("app", GMS).form(&form);
        for (k, v) in extra_headers {
            req = req.header(*k, v);
        }
        let resp = req.send().await.map_err(http::map_err)?;
        let status = resp.status();
        let body = resp.text().await.map_err(http::map_err)?;
        let reply = parse_form_reply(&body);
        if !status.is_success() {
            let err = reply.get("error").cloned().unwrap_or_else(|| format!("HTTP {status}"));
            return Err(if status.as_u16() == 403 || err.contains("BadAuthentication") || err.contains("NeedsBrowser") {
                ProviderError::Auth(format!("Google rejected the credentials: {err}"))
            } else {
                http::status_error(status, &err)
            });
        }
        Ok(reply)
    }

    /// One-time exchange of an `oauth_token` (obtained by signing in at
    /// https://accounts.google.com/EmbeddedSetup) for a long-lived AAS token.
    pub async fn exchange_oauth_token(&self, email: &str, oauth_token: &str, profile: &DeviceProfile) -> Result<String, ProviderError> {
        let form = vec![
            ("lang", self.lang()),
            ("google_play_services_version", profile.gsf_version().to_string()),
            ("sdk_version", profile.sdk().to_string()),
            ("device_country", self.country()),
            ("Email", email.to_string()),
            ("service", "ac2dm".into()),
            ("get_accountid", "1".into()),
            ("ACCESS_TOKEN", "1".into()),
            ("callerPkg", GMS.into()),
            ("add_account", "1".into()),
            ("Token", oauth_token.to_string()),
            ("callerSig", PLAY_CLIENT_SIG.into()),
            ("droidguard_results", "null".into()),
        ];
        let reply = self.auth_request(form, &[("User-Agent", profile.auth_user_agent())]).await?;
        reply.get("token").cloned().ok_or_else(|| ProviderError::Auth("no AAS token in reply".into()))
    }

    pub async fn checkin(&self, profile: &DeviceProfile) -> Result<AndroidCheckinResponse, ProviderError> {
        let now = chrono::Utc::now().timestamp();
        let req = AndroidCheckinRequest {
            id: Some(0),
            checkin: Some(profile.checkin_proto(now)),
            locale: Some(self.locale.clone()),
            time_zone: Some(self.timezone.clone()),
            version: Some(3),
            device_configuration: Some(profile.device_config()),
            fragment: Some(0),
            ..Default::default()
        };
        let resp = self
            .http
            .post(format!("{}/checkin", self.base))
            .header("Content-Type", "application/x-protobuf")
            .header("User-Agent", profile.auth_user_agent())
            .header("app", GMS)
            .body(req.encode_to_vec())
            .send()
            .await
            .map_err(http::map_err)?;
        if !resp.status().is_success() {
            return Err(http::status_error(resp.status(), "checkin"));
        }
        let bytes = resp.bytes().await.map_err(http::map_err)?;
        let r = AndroidCheckinResponse::decode(bytes).map_err(decode_err)?;
        if r.android_id.unwrap_or(0) == 0 {
            return Err(ProviderError::Protocol("checkin returned no device id".into()));
        }
        Ok(r)
    }

    async fn request_auth_token(&self, email: &str, aas_token: &str, profile: &DeviceProfile, gsf_id: u64) -> Result<String, ProviderError> {
        let form = vec![
            ("androidId", format!("{gsf_id:x}")),
            ("sdk_version", profile.sdk().to_string()),
            ("Email", email.to_string()),
            ("google_play_services_version", profile.gsf_version().to_string()),
            ("device_country", self.country()),
            ("lang", self.lang()),
            ("callerSig", PLAY_CLIENT_SIG.into()),
            ("app", VENDING.into()),
            ("client_sig", PLAY_CLIENT_SIG.into()),
            ("callerPkg", GMS.into()),
            ("Token", aas_token.to_string()),
            ("oauth2_foreground", "1".into()),
            ("token_request_options", "CAA4AVAB".into()),
            ("check_email", "1".into()),
            ("system_partition", "1".into()),
            ("service", PLAY_SCOPE.into()),
        ];
        let reply = self.auth_request(form, &[("User-Agent", profile.auth_user_agent()), ("device", format!("{gsf_id:x}"))]).await?;
        reply.get("auth").cloned().ok_or_else(|| ProviderError::Auth("no Play auth token in reply".into()))
    }

    fn fdfe_headers(&self, profile: &DeviceProfile, s: &PartialSession) -> reqwest::header::HeaderMap {
        use reqwest::header::{HeaderName, HeaderValue};
        let mut h = reqwest::header::HeaderMap::new();
        let mut put = |k: &str, v: String| {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
                h.insert(n, v);
            }
        };
        if let Some(t) = &s.auth_token {
            put("Authorization", format!("Bearer {t}"));
        }
        put("User-Agent", profile.finsky_user_agent());
        put("X-DFE-Device-Id", format!("{:x}", s.gsf_id));
        put("Accept-Language", self.locale.replace('_', "-"));
        put("X-DFE-Client-Id", "am-android-google".into());
        put("X-DFE-Network-Type", "4".into());
        put("X-DFE-Content-Filters", String::new());
        put("X-Limit-Ad-Tracking-Enabled", "false".into());
        put("X-DFE-UserLanguages", self.locale.clone());
        put("X-DFE-Request-Params", "timeoutMs=4000".into());
        if let Some(t) = &s.checkin_consistency_token {
            put("X-DFE-Device-Checkin-Consistency-Token", t.clone());
        }
        if let Some(t) = &s.device_config_token {
            put("X-DFE-Device-Config-Token", t.clone());
        }
        if let Some(c) = &s.dfe_cookie {
            put("X-DFE-Cookie", c.clone());
        }
        if let Some(m) = profile.sim_operator() {
            put("X-DFE-MCCMCN", m);
        }
        h
    }

    async fn fdfe(
        &self,
        profile: &DeviceProfile,
        s: &PartialSession,
        method: reqwest::Method,
        endpoint: &str,
        query: &[(&str, String)],
        body: Option<(Vec<u8>, &str)>,
    ) -> Result<ResponseWrapper, ProviderError> {
        let mut req = self.http.request(method, format!("{}/fdfe/{endpoint}", self.base)).headers(self.fdfe_headers(profile, s)).query(query);
        if let Some((b, ct)) = body {
            req = req.header("Content-Type", ct).body(b);
        } else if endpoint == "purchase" {
            req = req.header("Content-Length", "0");
        }
        let resp = req.send().await.map_err(http::map_err)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(http::map_err)?;
        let wrapper = ResponseWrapper::decode(bytes.clone()).ok();
        let server_msg = wrapper.as_ref().and_then(|w| w.commands.as_ref()).and_then(|c| c.display_error_message.clone());
        if !status.is_success() {
            let msg = server_msg.unwrap_or_else(|| format!("HTTP {status} on {endpoint}"));
            return Err(classify_server_error(status.as_u16(), &msg));
        }
        let w = wrapper.ok_or_else(|| ProviderError::Protocol(format!("{endpoint}: undecodable response")))?;
        if w.payload.is_none() {
            if let Some(m) = server_msg {
                return Err(classify_server_error(status.as_u16(), &m));
            }
        }
        Ok(w)
    }

    /// Full device login for one profile.
    pub async fn login(&self, email: &str, aas_token: &str, profile: &DeviceProfile) -> Result<Session, ProviderError> {
        let missing = profile.missing_keys();
        if !missing.is_empty() {
            return Err(ProviderError::NotConfigured(format!("device profile {} lacks {:?}", profile.name, missing)));
        }
        let c = self.checkin(profile).await?;
        let mut s = PartialSession {
            gsf_id: c.android_id.unwrap_or(0),
            checkin_consistency_token: c.device_checkin_consistency_token,
            device_config_token: None,
            auth_token: None,
            dfe_cookie: None,
        };
        let upload = UploadDeviceConfigRequest { device_configuration: Some(profile.device_config()), manufacturer: None };
        let w = self
            .fdfe(profile, &s, reqwest::Method::POST, "uploadDeviceConfig", &[], Some((upload.encode_to_vec(), "application/x-protobuf")))
            .await?;
        s.device_config_token = w.payload.and_then(|p| p.upload_device_config_response).and_then(|r| r.upload_device_config_token);
        s.auth_token = Some(self.request_auth_token(email, aas_token, profile, s.gsf_id).await?);
        let w = self.fdfe(profile, &s, reqwest::Method::GET, "toc", &[], None).await?;
        let toc = w.payload.and_then(|p| p.toc_response).ok_or_else(|| ProviderError::Protocol("toc: empty response".into()))?;
        if toc.tos_token.is_some() && toc.cookie.is_none() {
            return Err(ProviderError::Denied(
                "the Google account must accept the Google Play Terms of Service (sign in once on any Android device or emulator)".into(),
            ));
        }
        s.dfe_cookie = toc.cookie;
        Ok(Session {
            profile: profile.name.clone(),
            gsf_id: s.gsf_id,
            checkin_consistency_token: s.checkin_consistency_token,
            device_config_token: s.device_config_token,
            auth_token: s.auth_token.unwrap_or_default(),
            dfe_cookie: s.dfe_cookie,
            created_at: chrono::Utc::now().timestamp(),
        })
    }

    pub async fn details(&self, profile: &DeviceProfile, s: &Session, pkg: &str) -> Result<Item, ProviderError> {
        let w = self.fdfe(profile, &s.into(), reqwest::Method::GET, "details", &[("doc", pkg.to_string())], None).await?;
        w.payload.and_then(|p| p.details_response).and_then(|d| d.item).ok_or(ProviderError::NotFound)
    }

    /// "Purchase" of a free item (offer type 1, price 0) returns a delivery token. Paid items are
    /// never purchased by this client.
    pub async fn acquire_free(&self, profile: &DeviceProfile, s: &Session, pkg: &str, vc: i64) -> Result<Option<String>, ProviderError> {
        let q = [("ot", "1".to_string()), ("doc", pkg.to_string()), ("vc", vc.to_string())];
        let w = self.fdfe(profile, &s.into(), reqwest::Method::POST, "purchase", &q, None).await?;
        Ok(w.payload.and_then(|p| p.buy_response).and_then(|b| b.encoded_delivery_token))
    }

    pub async fn delivery(&self, profile: &DeviceProfile, s: &Session, pkg: &str, vc: i64, dtok: Option<&str>) -> Result<AndroidAppDeliveryData, ProviderError> {
        let mut q = vec![("ot", "1".to_string()), ("doc", pkg.to_string()), ("vc", vc.to_string())];
        if let Some(t) = dtok {
            q.push(("dtok", t.to_string()));
        }
        let w = self.fdfe(profile, &s.into(), reqwest::Method::GET, "delivery", &q, None).await?;
        let d = w.payload.and_then(|p| p.delivery_response).ok_or_else(|| ProviderError::Protocol("delivery: empty response".into()))?;
        match d.app_delivery_data {
            Some(data) if data.download_url.is_some() => Ok(data),
            _ => Err(match d.status {
                Some(2) => ProviderError::Denied("not available for this device profile/account (delivery status 2)".into()),
                Some(3) => ProviderError::Denied("app not owned by the account (paid or restricted)".into()),
                other => ProviderError::Denied(format!("no download offered (delivery status {other:?})")),
            }),
        }
    }
}

pub(crate) struct PartialSession {
    gsf_id: u64,
    checkin_consistency_token: Option<String>,
    device_config_token: Option<String>,
    auth_token: Option<String>,
    dfe_cookie: Option<String>,
}

impl From<&Session> for PartialSession {
    fn from(s: &Session) -> Self {
        Self {
            gsf_id: s.gsf_id,
            checkin_consistency_token: s.checkin_consistency_token.clone(),
            device_config_token: s.device_config_token.clone(),
            auth_token: Some(s.auth_token.clone()),
            dfe_cookie: s.dfe_cookie.clone(),
        }
    }
}

fn classify_server_error(status: u16, msg: &str) -> ProviderError {
    let l = msg.to_ascii_lowercase();
    if status == 404 || l.contains("not found") || l.contains("item not found") {
        ProviderError::NotFound
    } else if status == 401 {
        ProviderError::Auth(msg.into())
    } else if l.contains("compatible") || l.contains("not available in your country") || status == 403 {
        ProviderError::Denied(msg.into())
    } else if status == 429 || status >= 500 {
        ProviderError::Transient(msg.into())
    } else {
        ProviderError::Protocol(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_reply() {
        let r = parse_form_reply("SID=BAD\nAuth=ya29.abc=def\nError=BadAuthentication\n");
        assert_eq!(r["auth"], "ya29.abc=def");
        assert_eq!(r["error"], "BadAuthentication");
    }

    #[test]
    fn error_classification() {
        assert!(matches!(classify_server_error(200, "Item not found."), ProviderError::NotFound));
        assert!(matches!(classify_server_error(200, "Your device isn't compatible with this version."), ProviderError::Denied(_)));
        assert!(matches!(classify_server_error(503, "x"), ProviderError::Transient(_)));
    }
}
