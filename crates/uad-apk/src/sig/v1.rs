//! JAR signature verification (APK Signature Scheme v1), as used by legacy APKs, by App
//! Bundles signed with `jarsigner` and by F-Droid's signed repository index (`entry.jar`).
//!
//! Steps: PKCS#7/CMS SignedData over the `.SF` file → `.SF` digests of `MANIFEST.MF` (whole or
//! per section) → `MANIFEST.MF` digests of every ZIP entry.

use super::cert::{parse_certificate, CertificateInfo, ParsedCert};
use super::crypto::{self, DigestAlg, KeyScheme};
use base64::Engine;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek};

/// Guard against decompression bombs while hashing entries.
const MAX_TOTAL_UNCOMPRESSED: u64 = 16 * 1024 * 1024 * 1024;
const MAX_META_FILE: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V1SignerReport {
    pub signature_file: String,
    pub block_file: String,
    pub certificate: Option<CertificateInfo>,
    pub digest_algorithm: Option<DigestAlg>,
    pub signature_algorithm_oid: Option<String>,
    pub verified: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct V1Report {
    pub present: bool,
    pub verified: bool,
    pub signers: Vec<V1SignerReport>,
    /// Scheme ids declared in `X-Android-APK-Signed` (anti-stripping protection).
    pub declared_apk_schemes: Vec<u32>,
    pub entries_verified: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub attrs: Vec<(String, String)>,
    pub start: usize,
    pub end: usize,
}

impl Section {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(key, _)| key.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn name(&self) -> Option<&str> {
        self.get("Name")
    }
}

/// Parses a JAR manifest / signature file into its main section and entry sections, keeping the
/// exact byte range of each section (needed for per-section digests).
pub fn parse_manifest(data: &[u8]) -> Result<(Section, Vec<Section>), String> {
    let mut sections = Vec::new();
    let mut cur: Option<Section> = None;
    let mut pos = 0usize;
    while pos < data.len() {
        let line_start = pos;
        let mut end = pos;
        while end < data.len() && data[end] != b'\n' && data[end] != b'\r' {
            end += 1;
        }
        let mut next = end;
        if next < data.len() && data[next] == b'\r' {
            next += 1;
            if next < data.len() && data[next] == b'\n' {
                next += 1;
            }
        } else if next < data.len() && data[next] == b'\n' {
            next += 1;
        }
        let line = &data[line_start..end];
        pos = next;
        if line.is_empty() {
            if let Some(mut s) = cur.take() {
                s.end = pos;
                sections.push(s);
            }
            continue;
        }
        let sec = cur.get_or_insert_with(|| Section {
            attrs: vec![],
            start: line_start,
            end: 0,
        });
        if line[0] == b' ' {
            let (_, v) = sec.attrs.last_mut().ok_or("continuation line without attribute")?;
            v.push_str(&String::from_utf8_lossy(&line[1..]));
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let (k, v) = text
            .split_once(": ")
            .or_else(|| text.split_once(':'))
            .ok_or_else(|| format!("malformed manifest line: {text}"))?;
        sec.attrs.push((k.trim().to_string(), v.to_string()));
    }
    if let Some(mut s) = cur.take() {
        s.end = data.len();
        sections.push(s);
    }
    if sections.is_empty() {
        return Err("empty manifest".into());
    }
    let main = sections.remove(0);
    if main.name().is_some() {
        // No main section: first section is an entry. Treat main as empty.
        let entries = std::iter::once(main).chain(sections).collect();
        return Ok((
            Section {
                attrs: vec![],
                start: 0,
                end: 0,
            },
            entries,
        ));
    }
    Ok((main, sections))
}

/// Digest attributes (`<ALG>-Digest<suffix>`) present in a section, strongest first.
fn digest_attrs(sec: &Section, suffix: &str) -> Vec<(DigestAlg, Vec<u8>)> {
    let mut v: Vec<(DigestAlg, Vec<u8>)> = sec
        .attrs
        .iter()
        .filter_map(|(k, val)| {
            let alg_name = k.strip_suffix(suffix)?;
            let alg = DigestAlg::from_jar_name(alg_name)?;
            let bytes = base64::engine::general_purpose::STANDARD.decode(val.trim()).ok()?;
            Some((alg, bytes))
        })
        .collect();
    v.sort_by_key(|(a, _)| std::cmp::Reverse(a.strength()));
    v
}

fn is_signature_related(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("META-INF/") else { return false };
    if rest.contains('/') {
        return false;
    }
    let l = rest.to_ascii_lowercase();
    l == "manifest.mf" || l.ends_with(".sf") || l.ends_with(".rsa") || l.ends_with(".dsa") || l.ends_with(".ec") || l.starts_with("sig-")
}

fn read_entry<R: Read + Seek>(zip: &mut zip::ZipArchive<R>, name: &str) -> Result<Vec<u8>, String> {
    let e = zip.by_name(name).map_err(|e| format!("{name}: {e}"))?;
    if e.size() > MAX_META_FILE {
        return Err(format!("{name} is too large"));
    }
    let mut v = Vec::with_capacity(e.size() as usize);
    e.take(MAX_META_FILE).read_to_end(&mut v).map_err(|e| format!("{name}: {e}"))?;
    Ok(v)
}

fn key_scheme_for(sig_oid: &str) -> Option<KeyScheme> {
    Some(match sig_oid {
        "1.2.840.113549.1.1.1"
        | "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13"
        | "1.2.840.113549.1.1.14" => KeyScheme::RsaPkcs1v15,
        "1.2.840.10045.2.1" | "1.2.840.10045.4.1" | "1.2.840.10045.4.3.1" | "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4" => {
            KeyScheme::Ecdsa
        }
        "1.2.840.10040.4.1" | "1.2.840.10040.4.3" | "2.16.840.1.101.3.4.3.1" | "2.16.840.1.101.3.4.3.2" => KeyScheme::Dsa,
        _ => return None,
    })
}

const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// Verifies a PKCS#7 SignedData block over `content`; returns the signer certificate.
pub fn verify_pkcs7(block: &[u8], content: &[u8]) -> Result<(ParsedCert, DigestAlg, String), String> {
    let ci = ContentInfo::from_der(block).map_err(|e| format!("malformed PKCS#7: {e}"))?;
    if ci.content_type.to_string() != OID_SIGNED_DATA {
        return Err("PKCS#7 content is not SignedData".into());
    }
    let sd: SignedData = ci.content.decode_as().map_err(|e| format!("malformed SignedData: {e}"))?;
    let si = sd.signer_infos.0.iter().next().ok_or("SignedData has no signers")?;
    let certs: Vec<x509_cert::Certificate> = sd
        .certificates
        .as_ref()
        .map(|cs| {
            cs.0.iter()
                .filter_map(|c| match c {
                    cms::cert::CertificateChoices::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let cert = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs
            .iter()
            .find(|c| c.tbs_certificate.issuer == ias.issuer && c.tbs_certificate.serial_number == ias.serial_number),
        SignerIdentifier::SubjectKeyIdentifier(_) => certs.first(),
    }
    .ok_or("signer certificate not found in SignedData")?;
    let cert_der = cert.to_der().map_err(|e| e.to_string())?;
    let parsed = parse_certificate(&cert_der).map_err(|e| e.to_string())?;
    let digest = DigestAlg::from_oid(&si.digest_alg.oid).ok_or_else(|| format!("unsupported digest {}", si.digest_alg.oid))?;
    let sig_oid = si.signature_algorithm.oid.to_string();
    let scheme = key_scheme_for(&sig_oid).ok_or_else(|| format!("unsupported signature algorithm {sig_oid}"))?;
    let signature = si.signature.as_bytes();

    let signed_bytes: Vec<u8> = match &si.signed_attrs {
        Some(attrs) => {
            let md = attrs
                .iter()
                .find(|a| a.oid.to_string() == OID_MESSAGE_DIGEST)
                .and_then(|a| a.values.iter().next())
                .and_then(|v| v.decode_as::<der::asn1::OctetString>().ok())
                .ok_or("signed attributes lack messageDigest")?;
            if md.as_bytes() != digest.hash(content).as_slice() {
                return Err("messageDigest attribute does not match signature file".into());
            }
            attrs.to_der().map_err(|e| e.to_string())?
        }
        None => content.to_vec(),
    };
    crypto::verify(&parsed.spki_der, scheme, digest, &signed_bytes, signature).map_err(|e| format!("PKCS#7 signature: {e}"))?;
    Ok((parsed, digest, sig_oid))
}

/// Verifies JAR signing of a ZIP archive. `names` are the central-directory entry names.
pub fn verify_jar<R: Read + Seek>(zip: &mut zip::ZipArchive<R>, names: &[String]) -> V1Report {
    let mut rep = V1Report::default();
    let name_set: HashSet<&str> = names.iter().map(String::as_str).collect();
    let sf_files: Vec<String> = names
        .iter()
        .filter(|n| n.starts_with("META-INF/") && !n[9..].contains('/') && n.to_ascii_uppercase().ends_with(".SF"))
        .cloned()
        .collect();
    if sf_files.is_empty() {
        return rep;
    }
    rep.present = true;
    let manifest = match read_entry(zip, "META-INF/MANIFEST.MF") {
        Ok(m) => m,
        Err(e) => {
            rep.errors.push(format!("missing or unreadable META-INF/MANIFEST.MF: {e}"));
            return rep;
        }
    };
    let (_main, mf_entries) = match parse_manifest(&manifest) {
        Ok(v) => v,
        Err(e) => {
            rep.errors.push(format!("invalid MANIFEST.MF: {e}"));
            return rep;
        }
    };
    let mut mf_by_name: BTreeMap<String, &Section> = BTreeMap::new();
    for s in &mf_entries {
        if let Some(n) = s.name() {
            if mf_by_name.insert(n.to_string(), s).is_some() {
                rep.errors.push(format!("duplicate MANIFEST.MF section for {n}"));
            }
        }
    }

    // Entries covered by every signer.
    let mut covered_by_all: Option<HashSet<String>> = None;
    for sf_name in &sf_files {
        let base = &sf_name[..sf_name.len() - 3];
        let block_name = [".RSA", ".DSA", ".EC"]
            .iter()
            .map(|ext| format!("{base}{ext}"))
            .find(|n| name_set.contains(n.as_str()));
        let mut sr = V1SignerReport {
            signature_file: sf_name.clone(),
            block_file: block_name.clone().unwrap_or_default(),
            certificate: None,
            digest_algorithm: None,
            signature_algorithm_oid: None,
            verified: false,
            errors: vec![],
        };
        let result: Result<HashSet<String>, String> = (|| {
            let block_name = block_name.ok_or("no signature block file (.RSA/.DSA/.EC) for signature file")?;
            let sf = read_entry(zip, sf_name)?;
            let block = read_entry(zip, &block_name)?;
            let (cert, dig, sig_oid) = verify_pkcs7(&block, &sf)?;
            sr.certificate = Some(cert.info);
            sr.digest_algorithm = Some(dig);
            sr.signature_algorithm_oid = Some(sig_oid);
            let (sf_main, sf_entries) = parse_manifest(&sf)?;
            if let Some(v) = sf_main.get("X-Android-APK-Signed") {
                for id in v.split(',') {
                    if let Ok(n) = id.trim().parse::<u32>() {
                        if !rep.declared_apk_schemes.contains(&n) {
                            rep.declared_apk_schemes.push(n);
                        }
                    }
                }
            }
            let whole = digest_attrs(&sf_main, "-Digest-Manifest");
            let whole_ok = whole.first().map(|(alg, d)| alg.hash(&manifest) == *d).unwrap_or(false);
            let mut covered = HashSet::new();
            if whole_ok {
                covered.extend(mf_by_name.keys().cloned());
            } else {
                for s in &sf_entries {
                    let Some(n) = s.name() else { continue };
                    let Some(mf_sec) = mf_by_name.get(n) else {
                        return Err(format!("{sf_name} references {n}, absent from MANIFEST.MF"));
                    };
                    let digests = digest_attrs(s, "-Digest");
                    let (alg, expected) = digests.first().ok_or_else(|| format!("{sf_name}: no digest for {n}"))?;
                    if alg.hash(&manifest[mf_sec.start..mf_sec.end]) != *expected {
                        return Err(format!("{sf_name}: MANIFEST.MF section for {n} was modified"));
                    }
                    covered.insert(n.to_string());
                }
            }
            Ok(covered)
        })();
        match result {
            Ok(c) => {
                sr.verified = true;
                covered_by_all = Some(match covered_by_all {
                    None => c,
                    Some(prev) => prev.intersection(&c).cloned().collect(),
                });
            }
            Err(e) => sr.errors.push(e),
        }
        rep.signers.push(sr);
    }
    if rep.signers.iter().any(|s| !s.verified) {
        rep.errors.push("at least one JAR signer failed verification".into());
        return rep;
    }
    let covered = covered_by_all.unwrap_or_default();

    // Every relevant entry must be listed, signed, and match its digest.
    let mut total: u64 = 0;
    let mut seen = HashSet::new();
    for name in names {
        if name.ends_with('/') || is_signature_related(name) {
            continue;
        }
        if !seen.insert(name.clone()) {
            rep.errors.push(format!("duplicate ZIP entry {name}"));
            continue;
        }
        let Some(sec) = mf_by_name.get(name) else {
            rep.errors.push(format!("entry {name} is not listed in MANIFEST.MF"));
            continue;
        };
        if !covered.contains(name) {
            rep.errors.push(format!("entry {name} is not covered by the signature files"));
            continue;
        }
        let digests = digest_attrs(sec, "-Digest");
        if digests.is_empty() {
            rep.errors.push(format!("no supported digest for {name}"));
            continue;
        }
        let mut hashers: Vec<(DigestAlg, crypto::Hasher)> = digests.iter().map(|(a, _)| (*a, a.hasher())).collect();
        let res: Result<(), String> = (|| {
            let mut e = zip.by_name(name).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = e.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > MAX_TOTAL_UNCOMPRESSED {
                    return Err("uncompressed size limit exceeded".into());
                }
                for (_, h) in hashers.iter_mut() {
                    h.update(&buf[..n]);
                }
            }
            Ok(())
        })();
        if let Err(e) = res {
            rep.errors.push(format!("cannot read {name}: {e}"));
            continue;
        }
        let computed: HashMap<DigestAlg, Vec<u8>> = hashers.into_iter().map(|(a, h)| (a, h.finalize())).collect();
        if digests.iter().any(|(a, d)| computed.get(a) != Some(d)) {
            rep.errors.push(format!("digest mismatch for {name} (entry modified)"));
            continue;
        }
        rep.entries_verified += 1;
    }
    for n in mf_by_name.keys() {
        if !name_set.contains(n.as_str()) {
            rep.warnings.push(format!("MANIFEST.MF lists {n}, which is not in the archive"));
        }
    }
    if rep
        .signers
        .iter()
        .any(|s| matches!(s.digest_algorithm, Some(DigestAlg::Md5 | DigestAlg::Sha1)))
    {
        rep.warnings.push("JAR signature uses a weak digest (MD5/SHA-1)".into());
    }
    rep.verified = rep.errors.is_empty();
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sections_and_continuations() {
        let mf = b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\nName: res/very/long/path/that/wraps/over/the/seventy/two/byte/limi\r\n t.png\r\nSHA-256-Digest: abc=\r\n\r\nName: b\r\nSHA1-Digest: x\r\n\r\n";
        let (main, entries) = parse_manifest(mf).unwrap();
        assert_eq!(main.get("Created-By"), Some("test"));
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].name(),
            Some("res/very/long/path/that/wraps/over/the/seventy/two/byte/limit.png")
        );
        let raw = &mf[entries[1].start..entries[1].end];
        assert_eq!(raw, b"Name: b\r\nSHA1-Digest: x\r\n\r\n");
    }

    #[test]
    fn signature_related_names() {
        assert!(is_signature_related("META-INF/CERT.RSA"));
        assert!(is_signature_related("META-INF/MANIFEST.MF"));
        assert!(!is_signature_related("META-INF/services/x.SF"));
        assert!(!is_signature_related("classes.dex"));
    }
}
