//! Typed view over `AndroidManifest.xml`.

use crate::axml::{self, AttrValue, Element};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ApkManifest {
    pub package: String,
    /// Full 64-bit version code (`versionCodeMajor << 32 | versionCode`).
    pub version_code: i64,
    pub version_name: Option<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    pub compile_sdk: Option<u32>,
    /// `split` attribute: present only on split APKs.
    pub split: Option<String>,
    pub config_for_split: Option<String>,
    pub is_feature_split: bool,
    /// Base declares it cannot be installed without its splits.
    pub is_split_required: bool,
    /// Android 13+ split dependency declarations (`base__abi,base__density`…).
    pub required_split_types: Vec<String>,
    pub split_types: Vec<String>,
    /// Feature splits this split depends on (`<uses-split>`).
    pub uses_splits: Vec<String>,
    pub permissions: Vec<String>,
    pub features: Vec<UsesFeature>,
    pub application_label: Option<String>,
    pub debuggable: bool,
    pub has_code: bool,
    pub extract_native_libs: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsesFeature {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error(transparent)]
    Axml(#[from] axml::AxmlError),
    #[error("root element is <{0}>, expected <manifest>")]
    NotManifest(String),
    #[error("manifest has no package attribute")]
    NoPackage,
}

fn csv(v: Option<&AttrValue>) -> Vec<String> {
    v.and_then(|v| v.as_str())
        .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

fn uint(v: Option<&AttrValue>) -> Option<u32> {
    v.and_then(|v| v.as_int()).and_then(|i| u32::try_from(i).ok())
}

impl ApkManifest {
    pub fn parse_binary(data: &[u8]) -> Result<Self, ManifestError> {
        Self::from_element(&axml::parse(data)?)
    }

    pub fn from_element(root: &Element) -> Result<Self, ManifestError> {
        if root.name != "manifest" {
            return Err(ManifestError::NotManifest(root.name.clone()));
        }
        let package = root
            .plain_attr("package")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(ManifestError::NoPackage)?
            .to_string();
        let minor = root.android_attr("versionCode").and_then(|v| v.as_int()).unwrap_or(0) as u32 as i64;
        let major = root.android_attr("versionCodeMajor").and_then(|v| v.as_int()).unwrap_or(0) as u32 as i64;
        let mut m = ApkManifest {
            package,
            version_code: (major << 32) | minor,
            version_name: root.android_attr("versionName").map(|v| v.display()),
            compile_sdk: uint(root.android_attr("compileSdkVersion")),
            split: root.plain_attr("split").and_then(|v| v.as_str()).map(String::from),
            config_for_split: root
                .plain_attr("configForSplit")
                .and_then(|v| v.as_str())
                .map(String::from)
                .filter(|s| !s.is_empty()),
            is_feature_split: root.android_attr("isFeatureSplit").and_then(|v| v.as_bool()).unwrap_or(false),
            is_split_required: root.android_attr("isSplitRequired").and_then(|v| v.as_bool()).unwrap_or(false),
            required_split_types: csv(root.android_attr("requiredSplitTypes")),
            split_types: csv(root.android_attr("splitTypes")),
            has_code: true,
            ..Default::default()
        };
        if let Some(sdk) = root.children_named("uses-sdk").next() {
            m.min_sdk = uint(sdk.android_attr("minSdkVersion"));
            m.target_sdk = uint(sdk.android_attr("targetSdkVersion"));
            m.max_sdk = uint(sdk.android_attr("maxSdkVersion"));
        }
        for p in root
            .children
            .iter()
            .filter(|c| c.name == "uses-permission" || c.name == "uses-permission-sdk-23")
        {
            if let Some(n) = p.android_attr("name").and_then(|v| v.as_str()) {
                m.permissions.push(n.to_string());
            }
        }
        for f in root.children_named("uses-feature") {
            if let Some(n) = f.android_attr("name").and_then(|v| v.as_str()) {
                let required = f.android_attr("required").and_then(|v| v.as_bool()).unwrap_or(true);
                m.features.push(UsesFeature {
                    name: n.to_string(),
                    required,
                });
            }
        }
        for u in root.children_named("uses-split") {
            if let Some(n) = u.android_attr("name").and_then(|v| v.as_str()) {
                m.uses_splits.push(n.to_string());
            }
        }
        if let Some(app) = root.children_named("application").next() {
            m.application_label = app.android_attr("label").map(|v| v.display());
            m.debuggable = app.android_attr("debuggable").and_then(|v| v.as_bool()).unwrap_or(false);
            m.has_code = app.android_attr("hasCode").and_then(|v| v.as_bool()).unwrap_or(true);
            m.extract_native_libs = app.android_attr("extractNativeLibs").and_then(|v| v.as_bool());
            if app.android_attr("isSplitRequired").and_then(|v| v.as_bool()) == Some(true) {
                m.is_split_required = true;
            }
            for md in app.children_named("meta-data") {
                let name = md.android_attr("name").and_then(|v| v.as_str());
                if name == Some("com.android.vending.splits.required") && md.android_attr("value").and_then(|v| v.as_bool()) == Some(true) {
                    m.is_split_required = true;
                }
            }
        }
        Ok(m)
    }

    pub fn is_split(&self) -> bool {
        self.split.is_some()
    }

    /// True when the APK can be installed on its own (no mandatory splits declared).
    pub fn is_standalone(&self) -> bool {
        self.split.is_none() && !self.is_split_required && self.required_split_types.is_empty()
    }
}
