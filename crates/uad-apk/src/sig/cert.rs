//! X.509 certificate identification. Android does not validate certificate chains or validity
//! periods for app signing; certificates are identities, compared by their DER digest.

use super::crypto;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use uad_core::{Sha1Digest, Sha256Digest};
use x509_cert::Certificate;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateInfo {
    /// SHA-256 of the DER certificate: the identity used by Android, Google Play and F-Droid.
    pub sha256: Sha256Digest,
    pub sha1: Sha1Digest,
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub signature_algorithm_oid: String,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<usize>,
    /// SHA-256 of the SubjectPublicKeyInfo DER.
    pub public_key_sha256: Sha256Digest,
    pub self_signed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid X.509 certificate: {0}")]
pub struct CertError(pub String);

/// Parsed certificate plus the raw bytes needed for comparisons.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub der: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub info: CertificateInfo,
}

fn fmt_time(t: &x509_cert::time::Time) -> Option<String> {
    let secs = t.to_unix_duration().as_secs() as i64;
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

pub fn parse_certificate(der_bytes: &[u8]) -> Result<ParsedCert, CertError> {
    let cert = Certificate::from_der(der_bytes).map_err(|e| CertError(e.to_string()))?;
    let tbs = &cert.tbs_certificate;
    let spki_der = tbs.subject_public_key_info.to_der().map_err(|e| CertError(e.to_string()))?;
    let (alg, bits) = crypto::describe_key(&spki_der).unwrap_or_else(|e| (format!("unparsed ({e})"), None));
    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let info = CertificateInfo {
        sha256: Sha256Digest(Sha256::digest(der_bytes).into()),
        sha1: Sha1Digest(Sha1::digest(der_bytes).into()),
        self_signed: subject == issuer,
        subject,
        issuer,
        serial_hex: hex::encode(tbs.serial_number.as_bytes()),
        not_before: fmt_time(&tbs.validity.not_before),
        not_after: fmt_time(&tbs.validity.not_after),
        signature_algorithm_oid: cert.signature_algorithm.oid.to_string(),
        public_key_algorithm: alg,
        public_key_bits: bits,
        public_key_sha256: Sha256Digest(Sha256::digest(&spki_der).into()),
    };
    Ok(ParsedCert {
        der: der_bytes.to_vec(),
        spki_der,
        info,
    })
}
