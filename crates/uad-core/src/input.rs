//! Parsing of user-supplied application references.

use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

/// A syntactically valid Android application id (e.g. `org.mozilla.firefox`).
///
/// Rules follow the Android `applicationId` constraints enforced by Google Play: at least two
/// dot-separated segments, each starting with an ASCII letter and containing only
/// `[A-Za-z0-9_]`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackageName(String);

impl PackageName {
    pub const MAX_LEN: usize = 255;

    pub fn new(s: impl Into<String>) -> Result<Self, InputError> {
        let s = s.into();
        if s.is_empty() || s.len() > Self::MAX_LEN {
            return Err(InputError::InvalidPackage(s));
        }
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() < 2 {
            return Err(InputError::InvalidPackage(s));
        }
        for seg in &segments {
            let mut chars = seg.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() => {}
                _ => return Err(InputError::InvalidPackage(s)),
            }
            if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(InputError::InvalidPackage(s));
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Canonical Google Play URL for this package.
    pub fn play_url(&self) -> String {
        format!("https://play.google.com/store/apps/details?id={}", self.0)
    }
}

impl TryFrom<String> for PackageName {
    type Error = InputError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<PackageName> for String {
    fn from(p: PackageName) -> String {
        p.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PackageName({})", self.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InputError {
    #[error("invalid Android package name: {0:?}")]
    InvalidPackage(String),
    #[error("unsupported link: {0}")]
    UnsupportedLink(String),
    #[error("the link does not contain an application id")]
    MissingId,
}

/// Normalised result of parsing user input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInput {
    pub package: PackageName,
    /// Where the reference came from, kept for provenance.
    pub source: InputSource,
    /// Optional locale hint (`hl`) and country (`gl`) extracted from a Play link.
    pub hl: Option<String>,
    pub gl: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSource {
    PlayUrl,
    MarketUri,
    FdroidUrl,
    PackageName,
}

/// Parses a Google Play link, a `market://details?id=` URI, an F-Droid package page or a bare
/// package name.
pub fn parse_input(raw: &str) -> Result<AppInput, InputError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(InputError::MissingId);
    }

    if !raw.contains("://") && !raw.contains('/') {
        return Ok(AppInput {
            package: PackageName::new(raw)?,
            source: InputSource::PackageName,
            hl: None,
            gl: None,
        });
    }

    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let url = Url::parse(&with_scheme).map_err(|_| InputError::UnsupportedLink(raw.into()))?;
    let q = |k: &str| url.query_pairs().find(|(key, _)| key == k).map(|(_, v)| v.into_owned());

    match url.scheme() {
        "market" => {
            let id = q("id").ok_or(InputError::MissingId)?;
            return Ok(AppInput {
                package: PackageName::new(id)?,
                source: InputSource::MarketUri,
                hl: None,
                gl: None,
            });
        }
        "http" | "https" => {}
        _ => return Err(InputError::UnsupportedLink(raw.into())),
    }

    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match host.as_str() {
        "play.google.com" | "market.android.com" => {
            let path = url.path().trim_end_matches('/');
            if !(path.ends_with("/store/apps/details") || path == "/details") {
                return Err(InputError::UnsupportedLink(raw.into()));
            }
            let id = q("id").ok_or(InputError::MissingId)?;
            Ok(AppInput {
                package: PackageName::new(id)?,
                source: InputSource::PlayUrl,
                hl: q("hl"),
                gl: q("gl"),
            })
        }
        "f-droid.org" | "www.f-droid.org" => {
            // https://f-droid.org/packages/<id>/ or /<lang>/packages/<id>/
            let segs: Vec<&str> = url.path_segments().map(|s| s.filter(|x| !x.is_empty()).collect()).unwrap_or_default();
            let pos = segs.iter().position(|s| *s == "packages").ok_or(InputError::MissingId)?;
            let id = segs.get(pos + 1).ok_or(InputError::MissingId)?;
            Ok(AppInput {
                package: PackageName::new(*id)?,
                source: InputSource::FdroidUrl,
                hl: None,
                gl: None,
            })
        }
        _ => Err(InputError::UnsupportedLink(raw.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_play_links() {
        let i = parse_input("https://play.google.com/store/apps/details?id=org.mozilla.firefox&hl=es&gl=MX").unwrap();
        assert_eq!(i.package.as_str(), "org.mozilla.firefox");
        assert_eq!(i.source, InputSource::PlayUrl);
        assert_eq!(i.hl.as_deref(), Some("es"));
        assert_eq!(i.gl.as_deref(), Some("MX"));
        let i = parse_input("play.google.com/store/apps/details?hl=en&id=com.whatsapp").unwrap();
        assert_eq!(i.package.as_str(), "com.whatsapp");
        let i = parse_input("  market://details?id=com.example.app  ").unwrap();
        assert_eq!(i.source, InputSource::MarketUri);
        let i = parse_input("https://f-droid.org/es/packages/org.fdroid.fdroid/").unwrap();
        assert_eq!(i.package.as_str(), "org.fdroid.fdroid");
        let i = parse_input("com.example.my_app2").unwrap();
        assert_eq!(i.source, InputSource::PackageName);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_input("").is_err());
        assert!(parse_input("singlesegment").is_err());
        assert!(parse_input("com.1bad.start").is_err());
        assert!(parse_input("com.bad-char.app").is_err());
        assert!(parse_input("https://play.google.com/store/apps/details").is_err());
        assert!(parse_input("https://play.google.com/store/apps/dev?id=123").is_err());
        assert!(parse_input("https://evil.example/store/apps/details?id=com.a.b").is_err());
        assert!(parse_input("https://play.google.com/store/apps/details?id=com.a.b%2F..%2Fx").is_err());
        assert!(parse_input("file:///etc/passwd").is_err());
    }
}
