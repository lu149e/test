//! APK Signature Scheme v2, v3 and v3.1 verification.
//!
//! Spec: https://source.android.com/docs/security/features/apksigning/v2 and /v3.
//! Signed content is split into three sections (ZIP entries, central directory, EOCD with the
//! CD offset pointing at the signing block); each is digested in 1 MiB chunks
//! (`0xa5 || len || chunk`) and the chunk digests are digested again (`0x5a || count || …`).

use super::cert::{parse_certificate, CertificateInfo, ParsedCert};
use super::crypto::{self, DigestAlg, KeyScheme};
use crate::zipinfo::ZipLayout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub const V2_BLOCK_ID: u32 = 0x7109_871a;
pub const V3_BLOCK_ID: u32 = 0xf053_68c0;
pub const V31_BLOCK_ID: u32 = 0x1b93_ad61;
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;
pub const SOURCE_STAMP_V1_BLOCK_ID: u32 = 0x2b09_189e;
pub const SOURCE_STAMP_V2_BLOCK_ID: u32 = 0x6dff_800d;
pub const DEPENDENCY_INFO_BLOCK_ID: u32 = 0x504b_4453;
pub const PROOF_OF_ROTATION_ATTR_ID: u32 = 0x3ba0_6f8c;
pub const STRIPPING_PROTECTION_ATTR_ID: u32 = 0xbeef_f00d;

const CHUNK: usize = 1024 * 1024;
const VERITY_BLOCK: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentDigestAlg {
    ChunkedSha256,
    ChunkedSha512,
    VerityChunkedSha256,
}

#[derive(Debug, Clone, Copy)]
pub struct SigAlgorithm {
    pub id: u32,
    pub name: &'static str,
    pub scheme: KeyScheme,
    pub digest: DigestAlg,
    pub content: ContentDigestAlg,
}

pub fn signature_algorithm(id: u32) -> Option<SigAlgorithm> {
    use ContentDigestAlg::*;
    use DigestAlg::*;
    use KeyScheme::*;
    let (name, scheme, digest, content) = match id {
        0x0101 => ("RSA_PSS_WITH_SHA256", RsaPss, Sha256, ChunkedSha256),
        0x0102 => ("RSA_PSS_WITH_SHA512", RsaPss, Sha512, ChunkedSha512),
        0x0103 => ("RSA_PKCS1_V1_5_WITH_SHA256", RsaPkcs1v15, Sha256, ChunkedSha256),
        0x0104 => ("RSA_PKCS1_V1_5_WITH_SHA512", RsaPkcs1v15, Sha512, ChunkedSha512),
        0x0201 => ("ECDSA_WITH_SHA256", Ecdsa, Sha256, ChunkedSha256),
        0x0202 => ("ECDSA_WITH_SHA512", Ecdsa, Sha512, ChunkedSha512),
        0x0301 => ("DSA_WITH_SHA256", Dsa, Sha256, ChunkedSha256),
        0x0421 => ("VERITY_RSA_PKCS1_V1_5_WITH_SHA256", RsaPkcs1v15, Sha256, VerityChunkedSha256),
        0x0423 => ("VERITY_ECDSA_WITH_SHA256", Ecdsa, Sha256, VerityChunkedSha256),
        0x0425 => ("VERITY_DSA_WITH_SHA256", Dsa, Sha256, VerityChunkedSha256),
        _ => return None,
    };
    Some(SigAlgorithm { id, name, scheme, digest, content })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerReport {
    pub certificate: Option<CertificateInfo>,
    /// Additional certificates in the signer's chain (rarely used).
    pub extra_certificates: usize,
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    pub signature_algorithms: Vec<String>,
    pub content_digests_verified: Vec<ContentDigestAlg>,
    /// Signing-certificate history from a v3 proof-of-rotation attribute (oldest first).
    pub lineage: Vec<CertificateInfo>,
    pub verified: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemeReport {
    pub scheme: String,
    pub verified: bool,
    pub signers: Vec<SignerReport>,
    pub errors: Vec<String>,
}

/// Length-prefixed (u32 LE) reader.
struct Lp<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Lp<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, p: 0 }
    }
    fn remaining(&self) -> usize {
        self.d.len() - self.p
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.d.get(self.p..self.p + 4).ok_or("truncated u32")?;
        self.p += 4;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn lp(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        let b = self.d.get(self.p..self.p.checked_add(len).ok_or("overflow")?).ok_or_else(|| format!("length-prefixed field of {len} bytes exceeds buffer"))?;
        self.p += len;
        Ok(b)
    }
    fn lp_seq(&mut self) -> Result<Vec<&'a [u8]>, String> {
        let mut inner = Lp::new(self.lp()?);
        let mut out = Vec::new();
        while inner.remaining() > 0 {
            out.push(inner.lp()?);
        }
        Ok(out)
    }
}

/// Computes the requested content digests over the APK in a single streaming pass.
pub fn compute_content_digests(
    f: &mut File,
    layout: &ZipLayout,
    wanted: &BTreeSet<ContentDigestAlg>,
) -> std::io::Result<HashMap<ContentDigestAlg, Vec<u8>>> {
    let want256 = wanted.contains(&ContentDigestAlg::ChunkedSha256);
    let want512 = wanted.contains(&ContentDigestAlg::ChunkedSha512);
    let want_verity = wanted.contains(&ContentDigestAlg::VerityChunkedSha256);

    let mut chunks256: Vec<[u8; 32]> = Vec::new();
    let mut chunks512: Vec<[u8; 64]> = Vec::new();
    let mut verity = VerityBuilder::default();

    let eocd = layout.eocd_for_digest();
    let sections: [(u64, u64); 2] = [(0, layout.entries_end()), (layout.cd_offset, layout.cd_size)];
    let mut buf = vec![0u8; CHUNK];
    let mut process_chunk = |chunk: &[u8]| {
        let len = (chunk.len() as u32).to_le_bytes();
        if want256 {
            let mut h = Sha256::new();
            h.update([0xa5]);
            h.update(len);
            h.update(chunk);
            chunks256.push(h.finalize().into());
        }
        if want512 {
            let mut h = Sha512::new();
            h.update([0xa5]);
            h.update(len);
            h.update(chunk);
            chunks512.push(h.finalize().into());
        }
        if want_verity {
            verity.update(chunk);
        }
    };
    for (start, len) in sections {
        f.seek(SeekFrom::Start(start))?;
        let mut left = len;
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            f.read_exact(&mut buf[..n])?;
            process_chunk(&buf[..n]);
            left -= n as u64;
        }
    }
    process_chunk(&eocd);

    let mut out = HashMap::new();
    if want256 {
        let mut h = Sha256::new();
        h.update([0x5a]);
        h.update((chunks256.len() as u32).to_le_bytes());
        for c in &chunks256 {
            h.update(c);
        }
        out.insert(ContentDigestAlg::ChunkedSha256, h.finalize().to_vec());
    }
    if want512 {
        let mut h = Sha512::new();
        h.update([0x5a]);
        h.update((chunks512.len() as u32).to_le_bytes());
        for c in &chunks512 {
            h.update(c);
        }
        out.insert(ContentDigestAlg::ChunkedSha512, h.finalize().to_vec());
    }
    if want_verity {
        let total = layout.entries_end() + layout.cd_size + eocd.len() as u64;
        let mut d = verity.root().to_vec();
        d.extend_from_slice(&total.to_le_bytes());
        out.insert(ContentDigestAlg::VerityChunkedSha256, d);
    }
    Ok(out)
}

/// Merkle tree (SHA-256, 4 KiB blocks) over the signed content, as built by apksig's
/// `VerityTreeBuilder` for APK signatures: every block digest is salted with 8 zero bytes.
#[derive(Default)]
struct VerityBuilder {
    pending: Vec<u8>,
    leaf_hashes: Vec<u8>,
}

impl VerityBuilder {
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (VERITY_BLOCK - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() == VERITY_BLOCK {
                self.leaf_hashes.extend_from_slice(&salted(&self.pending));
                self.pending.clear();
            }
        }
    }

    fn root(mut self) -> [u8; 32] {
        if !self.pending.is_empty() {
            self.pending.resize(VERITY_BLOCK, 0);
            self.leaf_hashes.extend_from_slice(&salted(&self.pending));
        }
        let mut level = self.leaf_hashes;
        loop {
            let padded = level.len().div_ceil(VERITY_BLOCK).max(1) * VERITY_BLOCK;
            level.resize(padded, 0);
            if level.len() == VERITY_BLOCK {
                return salted(&level);
            }
            level = level.chunks(VERITY_BLOCK).flat_map(salted).collect();
        }
    }
}

const VERITY_SALT: [u8; 8] = [0u8; 8];

fn salted(block: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VERITY_SALT);
    h.update(block);
    h.finalize().into()
}

struct ParsedSigner {
    report: SignerReport,
    /// (content alg, expected digest) for supported algorithms.
    digests: Vec<(ContentDigestAlg, Vec<u8>)>,
    additional_attrs: Vec<(u32, Vec<u8>)>,
}

fn parse_and_verify_signer(raw: &[u8], v3: bool) -> ParsedSigner {
    let mut report = SignerReport {
        certificate: None,
        extra_certificates: 0,
        min_sdk: None,
        max_sdk: None,
        signature_algorithms: vec![],
        content_digests_verified: vec![],
        lineage: vec![],
        verified: false,
        errors: vec![],
        warnings: vec![],
    };
    let mut digests = Vec::new();
    let mut additional_attrs = Vec::new();
    let res: Result<(), String> = (|| {
        let mut r = Lp::new(raw);
        let signed_data = r.lp()?;
        let (outer_min, outer_max) = if v3 { (Some(r.u32()?), Some(r.u32()?)) } else { (None, None) };
        let signatures = r.lp_seq()?;
        let public_key = r.lp()?;

        // Signatures over signed data.
        let mut sig_algs = BTreeSet::new();
        let mut verified_any = false;
        for s in &signatures {
            let mut sr = Lp::new(s);
            let alg_id = sr.u32()?;
            let sig = sr.lp()?;
            sig_algs.insert(alg_id);
            let Some(alg) = signature_algorithm(alg_id) else {
                report.warnings.push(format!("unknown signature algorithm 0x{alg_id:04x} ignored"));
                continue;
            };
            report.signature_algorithms.push(alg.name.to_string());
            crypto::verify(public_key, alg.scheme, alg.digest, signed_data, sig)
                .map_err(|e| format!("{} signature over signed data: {e}", alg.name))?;
            verified_any = true;
        }
        if !verified_any {
            return Err("no supported signature algorithm".into());
        }

        // Signed data.
        let mut sd = Lp::new(signed_data);
        let digest_records = sd.lp_seq()?;
        let certs = sd.lp_seq()?;
        if v3 {
            let min = sd.u32()?;
            let max = sd.u32()?;
            if Some(min) != outer_min || Some(max) != outer_max {
                return Err("SDK range in signed data does not match signer record".into());
            }
            report.min_sdk = Some(min);
            report.max_sdk = Some(max);
        }
        for a in sd.lp_seq()? {
            let mut ar = Lp::new(a);
            let id = ar.u32()?;
            additional_attrs.push((id, a[4..].to_vec()));
        }

        let mut digest_algs = BTreeSet::new();
        for d in &digest_records {
            let mut dr = Lp::new(d);
            let alg_id = dr.u32()?;
            let value = dr.lp()?;
            digest_algs.insert(alg_id);
            if let Some(alg) = signature_algorithm(alg_id) {
                digests.push((alg.content, value.to_vec()));
            }
        }
        if digest_algs != sig_algs {
            return Err("signature algorithms differ between digests and signatures records".into());
        }

        let first = certs.first().ok_or("signer has no certificates")?;
        let cert: ParsedCert = parse_certificate(first).map_err(|e| e.to_string())?;
        if cert.spki_der != public_key {
            return Err("public key does not match the first certificate".into());
        }
        report.certificate = Some(cert.info);
        report.extra_certificates = certs.len() - 1;
        Ok(())
    })();
    if let Err(e) = res {
        report.errors.push(e);
    }
    ParsedSigner { report, digests, additional_attrs }
}

/// Verifies a v3 proof-of-rotation lineage; returns certificates oldest → newest.
fn verify_lineage(attr: &[u8]) -> Result<Vec<ParsedCert>, String> {
    let mut r = Lp::new(attr);
    let version = r.u32()?;
    if version != 1 {
        return Err(format!("unsupported lineage version {version}"));
    }
    // Node layout: lp(signed data = lp(cert) || u32 alg-used-by-previous-to-sign-this),
    // u32 flags, u32 alg-this-cert-uses-to-sign-next, lp(signature by previous cert).
    let mut out: Vec<ParsedCert> = Vec::new();
    let mut prev_outer_alg: Option<u32> = None;
    while r.remaining() > 0 {
        let node = r.lp()?;
        let mut nr = Lp::new(node);
        let signed = nr.lp()?;
        let _flags = nr.u32()?;
        let outer_alg = nr.u32()?;
        let signature = nr.lp()?;
        let mut sr = Lp::new(signed);
        let cert_der = sr.lp()?;
        let signed_alg = sr.u32()?;
        let cert = parse_certificate(cert_der).map_err(|e| e.to_string())?;
        if let (Some(prev), Some(prev_alg)) = (out.last(), prev_outer_alg) {
            if signed_alg != prev_alg {
                return Err("lineage signature algorithm mismatch".into());
            }
            let alg = signature_algorithm(prev_alg).ok_or_else(|| format!("unknown lineage algorithm 0x{prev_alg:x}"))?;
            crypto::verify(&prev.spki_der, alg.scheme, alg.digest, signed, signature)
                .map_err(|e| format!("lineage link to {} not signed by previous certificate: {e}", cert.info.sha256))?;
        }
        prev_outer_alg = Some(outer_alg);
        out.push(cert);
    }
    if out.is_empty() {
        return Err("empty lineage".into());
    }
    Ok(out)
}

/// Verifies one scheme block (`V2_BLOCK_ID`, `V3_BLOCK_ID` or `V31_BLOCK_ID`).
pub fn verify_block(
    f: &mut File,
    layout: &ZipLayout,
    block_id: u32,
    value: &[u8],
    digest_cache: &mut HashMap<ContentDigestAlg, Vec<u8>>,
) -> (SchemeReport, Vec<Vec<(u32, Vec<u8>)>>) {
    let v3 = block_id != V2_BLOCK_ID;
    let scheme = match block_id {
        V2_BLOCK_ID => "v2",
        V3_BLOCK_ID => "v3",
        _ => "v3.1",
    };
    let mut report = SchemeReport { scheme: scheme.into(), verified: false, signers: vec![], errors: vec![] };
    let mut attrs_per_signer = Vec::new();
    let signers = match Lp::new(value).lp_seq() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => {
            report.errors.push("no signers".into());
            return (report, attrs_per_signer);
        }
        Err(e) => {
            report.errors.push(format!("malformed signer list: {e}"));
            return (report, attrs_per_signer);
        }
    };
    for raw in signers {
        let ParsedSigner { report: mut sr, digests, additional_attrs } = parse_and_verify_signer(raw, v3);
        if sr.errors.is_empty() {
            let needed: BTreeSet<_> = digests.iter().map(|(a, _)| *a).filter(|a| !digest_cache.contains_key(a)).collect();
            if !needed.is_empty() {
                match compute_content_digests(f, layout, &needed) {
                    Ok(m) => digest_cache.extend(m),
                    Err(e) => sr.errors.push(format!("I/O error while digesting: {e}")),
                }
            }
            for (alg, expected) in &digests {
                match digest_cache.get(alg) {
                    Some(actual) if actual == expected => {
                        if !sr.content_digests_verified.contains(alg) {
                            sr.content_digests_verified.push(*alg)
                        }
                    }
                    Some(actual) => sr.errors.push(format!(
                        "APK integrity check failed: {alg:?} digest mismatch (expected {}, actual {})",
                        hex::encode(expected),
                        hex::encode(actual)
                    )),
                    None => {}
                }
            }
            if sr.content_digests_verified.is_empty() && sr.errors.is_empty() {
                sr.errors.push("no content digest could be verified".into());
            }
            if v3 {
                if let Some((_, attr)) = additional_attrs.iter().find(|(id, _)| *id == PROOF_OF_ROTATION_ATTR_ID) {
                    match verify_lineage(attr) {
                        Ok(chain) => {
                            let last = chain.last().map(|c| c.info.sha256);
                            if last != sr.certificate.as_ref().map(|c| c.sha256) {
                                sr.errors.push("lineage does not end with the signer certificate".into());
                            }
                            sr.lineage = chain.into_iter().map(|c| c.info).collect();
                        }
                        Err(e) => sr.errors.push(format!("invalid proof-of-rotation: {e}")),
                    }
                }
            }
        }
        sr.verified = sr.errors.is_empty();
        attrs_per_signer.push(additional_attrs);
        report.signers.push(sr);
    }
    report.verified = report.signers.iter().all(|s| s.verified);
    (report, attrs_per_signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verity_root_of_known_input() {
        // Two 4 KiB zero blocks: leaf level = 2 hashes, padded to one block -> root.
        let mut v = VerityBuilder::default();
        v.update(&[0u8; 8192]);
        let leaf = salted(&[0u8; 4096]);
        let mut level = Vec::new();
        level.extend_from_slice(&leaf);
        level.extend_from_slice(&leaf);
        level.resize(4096, 0);
        assert_eq!(v.root(), salted(&level));
    }

    #[test]
    fn lp_reader_bounds() {
        let mut r = Lp::new(&[5, 0, 0, 0, 1, 2]);
        assert!(r.lp().is_err());
        let mut r = Lp::new(&[1, 0]);
        assert!(r.u32().is_err());
    }
}
