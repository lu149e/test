//! Public Google Play store page: identification and human metadata only (no downloads).
//! Uses the schema.org JSON-LD block embedded in the page.

use crate::http;
use async_trait::async_trait;
use serde::Deserialize;
use uad_core::{AppMetadata, Discovery, DiscoveryRequest, Provider, ProviderError, ProviderInfo, ProviderKind};

pub struct PlayWebProvider {
    client: reqwest::Client,
    enabled: bool,
}

impl PlayWebProvider {
    pub fn new(enabled: bool) -> Self {
        Self {
            client: http::client(),
            enabled,
        }
    }
}

#[derive(Deserialize)]
struct LdApp {
    #[serde(rename = "@type")]
    ty: Option<String>,
    name: Option<String>,
    description: Option<String>,
    image: Option<String>,
    author: Option<LdAuthor>,
    #[serde(default)]
    offers: Vec<LdOffer>,
}

#[derive(Deserialize)]
struct LdAuthor {
    name: Option<String>,
}

#[derive(Deserialize)]
struct LdOffer {
    price: Option<String>,
    #[serde(rename = "priceCurrency")]
    currency: Option<String>,
}

/// Extracted page facts.
#[derive(Debug, Clone, PartialEq)]
pub struct PlayPage {
    pub metadata: AppMetadata,
    /// `Some(true)` when the listing has a non-zero price.
    pub paid: Option<bool>,
    pub price: Option<String>,
}

pub fn parse_page(html: &str) -> Option<PlayPage> {
    let marker = "<script type=\"application/ld+json\"";
    let mut rest = html;
    while let Some(i) = rest.find(marker) {
        let after = &rest[i..];
        let start = after.find('>')? + 1;
        let end = after[start..].find("</script>")? + start;
        let json = &after[start..end];
        if let Ok(app) = serde_json::from_str::<LdApp>(json) {
            if app.ty.as_deref() == Some("SoftwareApplication") {
                let offer = app.offers.first();
                let price = offer.and_then(|o| o.price.clone());
                let paid = price.as_deref().map(|p| p.trim() != "0" && !p.trim().is_empty());
                return Some(PlayPage {
                    metadata: AppMetadata {
                        title: app.name,
                        developer: app.author.and_then(|a| a.name),
                        icon_url: app.image,
                        summary: app.description,
                        version_name: None,
                        version_code: None,
                        source: "play_web".into(),
                    },
                    paid,
                    price: price.map(|p| {
                        format!("{p} {}", offer.and_then(|o| o.currency.clone()).unwrap_or_default())
                            .trim()
                            .to_string()
                    }),
                });
            }
        }
        rest = &after[end..];
    }
    None
}

#[async_trait]
impl Provider for PlayWebProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "play_web".into(),
            name: "Google Play (public listing)".into(),
            kind: ProviderKind::Official,
            enabled: self.enabled,
            requires_credentials: false,
            priority: 0,
            description: "Reads the public store listing to confirm the app exists and obtain its name, developer and price.".into(),
            status: "Metadata only: the public listing does not expose downloads.".into(),
        }
    }

    async fn discover(&self, req: &DiscoveryRequest) -> Result<Discovery, ProviderError> {
        let hl = req.locale.as_deref().and_then(|l| l.split(['-', '_']).next()).unwrap_or("en");
        let url = format!("https://play.google.com/store/apps/details?id={}&hl={hl}&gl=US", req.package);
        let resp = self.client.get(&url).header("Accept-Language", hl).send().await.map_err(http::map_err)?;
        if !resp.status().is_success() {
            return Err(http::status_error(resp.status(), "Google Play listing"));
        }
        let html = resp.text().await.map_err(http::map_err)?;
        let page = parse_page(&html).ok_or_else(|| ProviderError::Protocol("listing has no SoftwareApplication data".into()))?;
        let mut d = Discovery {
            metadata: Some(page.metadata),
            ..Default::default()
        };
        d.notes.push("Listed on Google Play".into());
        if page.paid == Some(true) {
            d.notes.push(format!(
                "Paid app ({}): only obtainable through an account that owns it; purchases are never automated.",
                page.price.unwrap_or_default()
            ));
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_ld() {
        let html = r#"<html><script type="application/ld+json" nonce="x">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Firefox Fast & Private Browser","image":"https://play-lh.googleusercontent.com/abc","author":{"@type":"Person","name":"Mozilla"},"offers":[{"@type":"Offer","price":"0","priceCurrency":"USD"}]}</script></html>"#;
        let p = parse_page(html).unwrap();
        assert_eq!(p.metadata.title.as_deref(), Some("Firefox Fast & Private Browser"));
        assert_eq!(p.metadata.developer.as_deref(), Some("Mozilla"));
        assert_eq!(p.paid, Some(false));
        let paid = html.replace("\"price\":\"0\"", "\"price\":\"4.99\"");
        assert_eq!(parse_page(&paid).unwrap().paid, Some(true));
        assert!(parse_page("<html></html>").is_none());
    }
}
