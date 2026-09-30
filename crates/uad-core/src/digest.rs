//! Fixed-size digest newtypes with hex (de)serialisation.

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

macro_rules! digest_type {
    ($name:ident, $len:expr, $label:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            pub fn from_slice(b: &[u8]) -> Option<Self> {
                <[u8; $len]>::try_from(b).ok().map(Self)
            }

            /// Accepts lowercase/uppercase hex, standard base64 or URL-safe base64 (with or
            /// without padding). Stores publish digests in all of these encodings.
            pub fn parse_flexible(s: &str) -> Option<Self> {
                let s = s.trim();
                if s.len() == $len * 2 {
                    if let Ok(v) = hex::decode(s) {
                        return Self::from_slice(&v);
                    }
                }
                let engines = [
                    &base64::engine::general_purpose::STANDARD,
                    &base64::engine::general_purpose::STANDARD_NO_PAD,
                    &base64::engine::general_purpose::URL_SAFE,
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                ];
                for e in engines {
                    if let Ok(v) = e.decode(s) {
                        if let Some(d) = Self::from_slice(&v) {
                            return Some(d);
                        }
                    }
                }
                None
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $label, self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let v = hex::decode(s.trim()).map_err(|e| e.to_string())?;
                Self::from_slice(&v).ok_or_else(|| format!("expected {} bytes", $len))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

digest_type!(Sha256Digest, 32, "sha256");
digest_type!(Sha1Digest, 20, "sha1");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flexible_parsing_accepts_hex_and_base64() {
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let d = Sha256Digest::parse_flexible(hex).unwrap();
        assert_eq!(d.to_hex(), hex);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d.0);
        assert_eq!(Sha256Digest::parse_flexible(&b64), Some(d));
        let b64std = base64::engine::general_purpose::STANDARD.encode(d.0);
        assert_eq!(Sha256Digest::parse_flexible(&b64std), Some(d));
        assert!(Sha256Digest::parse_flexible("nope").is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let d = Sha1Digest([7u8; 20]);
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Sha1Digest>(&j).unwrap(), d);
    }
}
