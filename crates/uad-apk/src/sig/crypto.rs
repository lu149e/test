//! Signature primitives. All algorithms are delegated to RustCrypto implementations; this module
//! only maps Android/PKCS algorithm identifiers to them.

use der::{asn1::ObjectIdentifier, Decode};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use spki::SubjectPublicKeyInfoRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum DigestAlg {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlg::Md5 => md5::Md5::digest(data).to_vec(),
            DigestAlg::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlg::Sha224 => Sha224::digest(data).to_vec(),
            DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn hasher(self) -> Hasher {
        match self {
            DigestAlg::Md5 => Hasher::Md5(md5::Md5::new()),
            DigestAlg::Sha1 => Hasher::Sha1(Sha1::new()),
            DigestAlg::Sha224 => Hasher::Sha224(Sha224::new()),
            DigestAlg::Sha256 => Hasher::Sha256(Sha256::new()),
            DigestAlg::Sha384 => Hasher::Sha384(Sha384::new()),
            DigestAlg::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    /// Names used in JAR manifests (`SHA-256-Digest`, `SHA1-Digest`…).
    pub fn from_jar_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "MD5" => DigestAlg::Md5,
            "SHA1" | "SHA-1" => DigestAlg::Sha1,
            "SHA-224" => DigestAlg::Sha224,
            "SHA-256" => DigestAlg::Sha256,
            "SHA-384" => DigestAlg::Sha384,
            "SHA-512" => DigestAlg::Sha512,
            _ => return None,
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Some(match oid.to_string().as_str() {
            "1.2.840.113549.2.5" => DigestAlg::Md5,
            "1.3.14.3.2.26" => DigestAlg::Sha1,
            "2.16.840.1.101.3.4.2.4" => DigestAlg::Sha224,
            "2.16.840.1.101.3.4.2.1" => DigestAlg::Sha256,
            "2.16.840.1.101.3.4.2.2" => DigestAlg::Sha384,
            "2.16.840.1.101.3.4.2.3" => DigestAlg::Sha512,
            _ => return None,
        })
    }

    /// Relative strength used to pick the strongest digest when several are present.
    pub fn strength(self) -> u8 {
        match self {
            DigestAlg::Md5 => 0,
            DigestAlg::Sha1 => 1,
            DigestAlg::Sha224 => 2,
            DigestAlg::Sha256 => 3,
            DigestAlg::Sha384 => 4,
            DigestAlg::Sha512 => 5,
        }
    }
}

pub enum Hasher {
    Md5(md5::Md5),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, d: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(d),
            Hasher::Sha1(h) => h.update(d),
            Hasher::Sha224(h) => h.update(d),
            Hasher::Sha256(h) => h.update(d),
            Hasher::Sha384(h) => h.update(d),
            Hasher::Sha512(h) => h.update(d),
        }
    }
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha224(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyScheme {
    RsaPkcs1v15,
    RsaPss,
    Ecdsa,
    Dsa,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("unsupported public key: {0}")]
    UnsupportedKey(String),
    #[error("public key does not match signature scheme")]
    KeyMismatch,
    #[error("malformed public key or signature: {0}")]
    Malformed(String),
    #[error("signature did not verify")]
    BadSignature,
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_DSA: &str = "1.2.840.10040.4.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

/// Key algorithm family and size, for reporting.
pub fn describe_key(spki_der: &[u8]) -> Result<(String, Option<usize>), CryptoError> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|e| CryptoError::Malformed(e.to_string()))?;
    let oid = spki.algorithm.oid.to_string();
    Ok(match oid.as_str() {
        OID_RSA => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::traits::PublicKeyParts;
            let k = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| CryptoError::Malformed(e.to_string()))?;
            ("RSA".into(), Some(k.size() * 8))
        }
        OID_EC => {
            let curve = spki
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .map(|o| o.to_string())
                .unwrap_or_default();
            match curve.as_str() {
                OID_P256 => ("EC P-256".into(), Some(256)),
                OID_P384 => ("EC P-384".into(), Some(384)),
                OID_P521 => ("EC P-521".into(), Some(521)),
                other => (format!("EC ({other})"), None),
            }
        }
        OID_DSA => ("DSA".into(), None),
        other => (format!("unknown ({other})"), None),
    })
}

/// Verifies `signature` over `message` with the key in `spki_der`, hashing with `digest`.
pub fn verify(spki_der: &[u8], scheme: KeyScheme, digest: DigestAlg, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let hashed = digest.hash(message);
    verify_prehashed(spki_der, scheme, digest, &hashed, signature)
}

pub fn verify_prehashed(spki_der: &[u8], scheme: KeyScheme, digest: DigestAlg, hashed: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|e| CryptoError::Malformed(e.to_string()))?;
    let oid = spki.algorithm.oid.to_string();
    match scheme {
        KeyScheme::RsaPkcs1v15 | KeyScheme::RsaPss => {
            if oid != OID_RSA {
                return Err(CryptoError::KeyMismatch);
            }
            use rsa::pkcs8::DecodePublicKey;
            let key = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| CryptoError::Malformed(e.to_string()))?;
            let res = if scheme == KeyScheme::RsaPkcs1v15 {
                let pad = match digest {
                    DigestAlg::Md5 => rsa::Pkcs1v15Sign::new::<md5::Md5>(),
                    DigestAlg::Sha1 => rsa::Pkcs1v15Sign::new::<Sha1>(),
                    DigestAlg::Sha224 => rsa::Pkcs1v15Sign::new::<Sha224>(),
                    DigestAlg::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
                    DigestAlg::Sha384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
                    DigestAlg::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
                };
                key.verify(pad, hashed, signature)
            } else {
                let pad = match digest {
                    DigestAlg::Sha256 => rsa::Pss::new::<Sha256>(),
                    DigestAlg::Sha512 => rsa::Pss::new::<Sha512>(),
                    _ => return Err(CryptoError::UnsupportedKey("RSA-PSS digest".into())),
                };
                key.verify(pad, hashed, signature)
            };
            res.map_err(|_| CryptoError::BadSignature)
        }
        KeyScheme::Ecdsa => {
            if oid != OID_EC {
                return Err(CryptoError::KeyMismatch);
            }
            let curve = spki
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .map(|o| o.to_string())
                .unwrap_or_default();
            let point = spki.subject_public_key.raw_bytes();
            match curve.as_str() {
                OID_P256 => {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    let sig = p256::ecdsa::Signature::from_der(signature).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    vk.verify_prehash(hashed, &sig).map_err(|_| CryptoError::BadSignature)
                }
                OID_P384 => {
                    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    let sig = p384::ecdsa::Signature::from_der(signature).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    vk.verify_prehash(hashed, &sig).map_err(|_| CryptoError::BadSignature)
                }
                OID_P521 => {
                    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    let sig = p521::ecdsa::Signature::from_der(signature).map_err(|e| CryptoError::Malformed(e.to_string()))?;
                    vk.verify_prehash(hashed, &sig).map_err(|_| CryptoError::BadSignature)
                }
                other => Err(CryptoError::UnsupportedKey(format!("EC curve {other}"))),
            }
        }
        KeyScheme::Dsa => {
            if oid != OID_DSA {
                return Err(CryptoError::KeyMismatch);
            }
            use dsa::pkcs8::DecodePublicKey;
            let vk = dsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| CryptoError::Malformed(e.to_string()))?;
            let sig = dsa::Signature::from_der(signature).map_err(|e| CryptoError::Malformed(e.to_string()))?;
            vk.verify_prehash(hashed, &sig).map_err(|_| CryptoError::BadSignature)
        }
    }
}
