//! Vocabulary for APK variants.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Android ABIs relevant for distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Abi {
    #[serde(rename = "arm64-v8a")]
    Arm64V8a,
    #[serde(rename = "armeabi-v7a")]
    ArmeabiV7a,
    #[serde(rename = "armeabi")]
    Armeabi,
    #[serde(rename = "x86")]
    X86,
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "riscv64")]
    Riscv64,
    #[serde(rename = "mips")]
    Mips,
    #[serde(rename = "mips64")]
    Mips64,
}

impl Abi {
    pub const PRIMARY: [Abi; 4] = [Abi::Arm64V8a, Abi::ArmeabiV7a, Abi::X86, Abi::X86_64];

    /// Name as used in `lib/<abi>/` directories and in `nativecode` lists.
    pub fn as_str(self) -> &'static str {
        match self {
            Abi::Arm64V8a => "arm64-v8a",
            Abi::ArmeabiV7a => "armeabi-v7a",
            Abi::Armeabi => "armeabi",
            Abi::X86 => "x86",
            Abi::X86_64 => "x86_64",
            Abi::Riscv64 => "riscv64",
            Abi::Mips => "mips",
            Abi::Mips64 => "mips64",
        }
    }

    /// Accepts both the directory form (`arm64-v8a`) and the split-name form (`arm64_v8a`).
    pub fn parse(s: &str) -> Option<Abi> {
        Some(match s.replace('_', "-").as_str() {
            "arm64-v8a" => Abi::Arm64V8a,
            "armeabi-v7a" => Abi::ArmeabiV7a,
            "armeabi" => Abi::Armeabi,
            "x86" => Abi::X86,
            "x86-64" => Abi::X86_64,
            "riscv64" => Abi::Riscv64,
            "mips" => Abi::Mips,
            "mips64" => Abi::Mips64,
            _ => return None,
        })
    }
}

impl fmt::Display for Abi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Screen density qualifiers used by configuration splits.
pub const DENSITIES: [&str; 8] = ["ldpi", "mdpi", "tvdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "nodpi"];

/// The configuration dimension a configuration split targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "dimension", content = "value", rename_all = "snake_case")]
pub enum SplitDimension {
    Abi(Abi),
    Density(String),
    Language(String),
    /// Texture compression format, device tier, country set… or unknown future dimensions.
    Other(String),
}

/// Result of interpreting a split name such as `config.arm64_v8a` or `feature.config.es`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSplitName {
    /// Feature module the config split belongs to, `None` for the base module.
    pub module: Option<String>,
    pub dimension: Option<SplitDimension>,
}

/// Interprets split names produced by bundletool / Google Play.
///
/// Conventions: base config splits are `config.<qualifier>`; config splits of a feature module
/// are `<module>.config.<qualifier>`; a bare name without `config.` is a feature split.
pub fn parse_split_name(name: &str) -> ParsedSplitName {
    let (module, qualifier) = if let Some(q) = name.strip_prefix("config.") {
        (None, Some(q))
    } else if let Some(idx) = name.find(".config.") {
        (Some(name[..idx].to_string()), Some(&name[idx + ".config.".len()..]))
    } else {
        (Some(name.to_string()), None)
    };
    let dimension = qualifier.map(classify_qualifier);
    ParsedSplitName { module, dimension }
}

fn classify_qualifier(q: &str) -> SplitDimension {
    if let Some(abi) = Abi::parse(q) {
        return SplitDimension::Abi(abi);
    }
    if DENSITIES.contains(&q) {
        return SplitDimension::Density(q.to_string());
    }
    // Language qualifiers: `es`, `pt_BR`, `b+sr+Latn` style is normalised by bundletool to
    // lowercase two/three-letter codes, optionally with a region.
    let lang = q.split('_').next().unwrap_or(q);
    if (2..=3).contains(&lang.len()) && lang.chars().all(|c| c.is_ascii_lowercase()) {
        return SplitDimension::Language(q.to_string());
    }
    SplitDimension::Other(q.to_string())
}

/// Role of a single file within an offer, as declared by the provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "role", content = "name", rename_all = "snake_case")]
pub enum FileRole {
    /// A self-contained APK (no required splits). May or may not be "universal".
    Standalone,
    /// The base APK of a split set.
    Base,
    /// A split APK (config or feature), identified by its split name.
    Split(String),
    /// Android App Bundle.
    AppBundle,
    /// Expansion file (`main`/`patch`).
    Obb(String),
    /// ART dex metadata (`.dm`) delivered by Play for cloud profiles.
    DexMetadata,
}

/// Classification of an acquired or generated artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VariantKind {
    /// Original standalone APK containing native code for every ABI the app ships (or none).
    UniversalApk,
    /// Original standalone APK restricted to specific ABIs.
    StandaloneApk {
        abis: Vec<Abi>,
    },
    BaseApk,
    ConfigSplit {
        module: Option<String>,
        dimension: SplitDimension,
        split: String,
    },
    FeatureSplit {
        module: String,
    },
    /// Universal APK generated locally from an AAB with bundletool. Never an original file:
    /// it carries a signature from the local signing key, not the developer's.
    GeneratedUniversalApk,
    AppBundle,
    Obb,
    DexMetadata,
}

impl VariantKind {
    pub fn is_original(&self) -> bool {
        !matches!(self, VariantKind::GeneratedUniversalApk)
    }

    pub fn from_split_name(split: &str) -> VariantKind {
        let parsed = parse_split_name(split);
        match (parsed.module, parsed.dimension) {
            (module, Some(dimension)) => VariantKind::ConfigSplit {
                module,
                dimension,
                split: split.to_string(),
            },
            (Some(module), None) => VariantKind::FeatureSplit { module },
            (None, None) => VariantKind::BaseApk,
        }
    }
}

/// How far we got with a given variant. The distinction is central to honest reporting:
/// * `Known`: metadata says the variant exists (e.g. listed split id), no download location.
/// * `Identified`: a provider returned a concrete, fetchable location for it.
/// * `Retrieved`: bytes were downloaded, stored and verified.
/// * `Failed`: identified but acquisition or verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Known,
    Identified,
    Retrieved,
    Failed,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Known => "known",
            Availability::Identified => "identified",
            Availability::Retrieved => "retrieved",
            Availability::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "known" => Self::Known,
            "identified" => Self::Identified,
            "retrieved" => Self::Retrieved,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_names() {
        assert_eq!(
            VariantKind::from_split_name("config.arm64_v8a"),
            VariantKind::ConfigSplit {
                module: None,
                dimension: SplitDimension::Abi(Abi::Arm64V8a),
                split: "config.arm64_v8a".into()
            }
        );
        assert_eq!(
            VariantKind::from_split_name("config.xxhdpi"),
            VariantKind::ConfigSplit {
                module: None,
                dimension: SplitDimension::Density("xxhdpi".into()),
                split: "config.xxhdpi".into()
            }
        );
        assert_eq!(
            VariantKind::from_split_name("config.es"),
            VariantKind::ConfigSplit {
                module: None,
                dimension: SplitDimension::Language("es".into()),
                split: "config.es".into()
            }
        );
        assert_eq!(
            VariantKind::from_split_name("camera.config.x86_64"),
            VariantKind::ConfigSplit {
                module: Some("camera".into()),
                dimension: SplitDimension::Abi(Abi::X86_64),
                split: "camera.config.x86_64".into()
            }
        );
        assert_eq!(
            VariantKind::from_split_name("camera"),
            VariantKind::FeatureSplit { module: "camera".into() }
        );
        assert!(matches!(
            VariantKind::from_split_name("config.astc"),
            VariantKind::ConfigSplit {
                dimension: SplitDimension::Other(_),
                ..
            }
        ));
    }

    #[test]
    fn abi_parse() {
        for abi in Abi::PRIMARY {
            assert_eq!(Abi::parse(abi.as_str()), Some(abi));
        }
        assert_eq!(Abi::parse("arm64_v8a"), Some(Abi::Arm64V8a));
        assert_eq!(Abi::parse("x86_64"), Some(Abi::X86_64));
        assert_eq!(Abi::parse("sparc"), None);
    }
}
