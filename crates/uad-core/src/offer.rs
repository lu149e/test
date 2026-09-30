//! What providers return: discovered application metadata and concrete, fetchable offers.

use crate::digest::{Sha1Digest, Sha256Digest};
use crate::input::PackageName;
use crate::variant::{Abi, Availability, FileRole};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Input to [`crate::Provider::discover`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRequest {
    pub package: PackageName,
    /// Specific version requested; `None` means "latest the provider offers".
    pub version_code: Option<i64>,
    /// Restrict ABI-specific variants to these ABIs (empty = all).
    pub abis: Vec<Abi>,
    /// Locale hint (e.g. `es-ES`) for metadata.
    pub locale: Option<String>,
}

/// Human-facing metadata about an application.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AppMetadata {
    pub title: Option<String>,
    pub developer: Option<String>,
    pub icon_url: Option<String>,
    pub summary: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub source: String,
}

/// Something a provider knows exists but cannot (or did not) locate for download.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnownVariant {
    pub provider: String,
    pub version_code: Option<i64>,
    pub version_name: Option<String>,
    pub description: String,
    pub role: Option<FileRole>,
    pub abis: Vec<Abi>,
    pub availability: Availability,
}

/// Overall structure of an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferLayout {
    /// One standalone APK that the provider declares valid for every supported ABI.
    UniversalApk,
    /// One standalone APK restricted to a subset of ABIs.
    AbiSpecificApk,
    /// Base APK plus split APKs (configuration and/or feature).
    SplitSet,
    /// An Android App Bundle to be processed with bundletool.
    AppBundle,
}

/// Expected digests declared by the provider (trust material from the source).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedDigests {
    pub sha256: Option<Sha256Digest>,
    pub sha1: Option<Sha1Digest>,
}

/// An HTTP header required to fetch a file. Sensitive headers (cookies, bearer tokens) are
/// never persisted or logged.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
    pub sensitive: bool,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = if self.sensitive { "<redacted>" } else { &self.value };
        write!(f, "{}: {}", self.name, v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileSource {
    Http {
        url: String,
        #[serde(default)]
        headers: Vec<Header>,
        /// The URL embeds credentials/tokens; only scheme+host+path may be recorded.
        #[serde(default)]
        url_is_sensitive: bool,
    },
    /// A file already on the local filesystem (import, emulator pull, bundletool output).
    Local { path: PathBuf },
}

impl FileSource {
    /// Representation safe to persist in provenance records.
    pub fn redacted(&self) -> String {
        match self {
            FileSource::Http { url, url_is_sensitive, .. } => {
                if *url_is_sensitive {
                    match url::Url::parse(url) {
                        Ok(mut u) => {
                            u.set_query(None);
                            u.set_fragment(None);
                            let _ = u.set_password(None);
                            let _ = u.set_username("");
                            format!("{u} (query redacted)")
                        }
                        Err(_) => "<unparseable url redacted>".into(),
                    }
                } else {
                    url.clone()
                }
            }
            FileSource::Local { path } => format!("file://{}", path.display()),
        }
    }
}

/// A file that can be fetched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteFile {
    pub role: FileRole,
    pub file_name: String,
    pub source: FileSource,
    pub size: Option<u64>,
    #[serde(default)]
    pub expected: ExpectedDigests,
}

/// Trust material asserted by the source about who signed the APK.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustAnchor {
    /// SHA-256 digests of the expected signing certificates (DER).
    pub signer_cert_sha256: Vec<Sha256Digest>,
    /// Where the assertion comes from (e.g. "F-Droid signed index (entry.jar)").
    pub asserted_by: String,
    /// Whether the assertion itself was cryptographically authenticated.
    pub authenticated: bool,
}

/// A concrete, fetchable set of files for one version of an app.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Offer {
    pub provider: String,
    pub package: PackageName,
    pub version_code: i64,
    pub version_name: Option<String>,
    pub layout: OfferLayout,
    pub files: Vec<RemoteFile>,
    /// ABIs the offer covers according to the provider (empty = no native code / unknown).
    pub abis: Vec<Abi>,
    pub min_sdk: Option<u32>,
    pub trust: Option<TrustAnchor>,
    /// Device profile used to obtain device-specific offers (Play), if any.
    pub device_profile: Option<String>,
    /// Free-form description of the channel, recorded in provenance.
    pub channel: String,
}

/// Everything a provider reports for a package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Discovery {
    pub metadata: Option<AppMetadata>,
    pub offers: Vec<Offer>,
    pub known: Vec<KnownVariant>,
    /// Non-fatal notes (limitations hit, partial results…).
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_urls_are_redacted() {
        let s = FileSource::Http {
            url: "https://user:pw@play.googleapis.com/download/by-token/x?token=SECRET&x=1".into(),
            headers: vec![],
            url_is_sensitive: true,
        };
        let r = s.redacted();
        assert!(!r.contains("SECRET"));
        assert!(!r.contains("pw"));
        assert!(r.starts_with("https://play.googleapis.com/download/by-token/x"));
        let h = Header { name: "Cookie".into(), value: "SECRET".into(), sensitive: true };
        assert!(!format!("{h:?}").contains("SECRET"));
    }
}
