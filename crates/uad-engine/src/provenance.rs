//! Verifiable provenance ledger.
//!
//! Every retrieved or generated artifact gets a record describing where it came from, how it
//! was obtained and what was verified. Records form a hash chain (each embeds the previous
//! record's hash) and every record hash is signed with this instance's Ed25519 key, so
//! deletion, reordering or modification of history is detectable (`uad provenance verify`).
//! The chain proves what *this installation* observed; it is not a third-party attestation.

use crate::secrets::write_private;
use crate::store::{ProvenanceRow, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceRecord {
    pub format: u32,
    pub seq: i64,
    pub timestamp: String,
    pub job_id: String,
    pub package: String,
    pub version_code: Option<i64>,
    pub artifact_sha256: String,
    pub artifact_sha1: String,
    pub size: u64,
    pub file_name: String,
    /// `original` (bytes exactly as distributed by the source) or `generated_from_aab`.
    pub origin: String,
    pub kind: serde_json::Value,
    pub provider: String,
    pub channel: String,
    pub device_profile: Option<String>,
    /// Source location with credentials/tokens removed.
    pub source: String,
    /// For generated artifacts: SHA-256 of the input bundle.
    pub derived_from: Option<String>,
    pub tool: Option<String>,
    pub verification: serde_json::Value,
    pub prev_hash: String,
}

pub struct Ledger {
    store: Arc<Store>,
    key: SigningKey,
    lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainReport {
    pub records: usize,
    pub valid: bool,
    pub public_key: String,
    pub errors: Vec<String>,
}

impl Ledger {
    pub fn open(store: Arc<Store>, keys_dir: &Path) -> Result<Self, String> {
        let path = keys_dir.join("provenance.ed25519");
        let key = match std::fs::read_to_string(&path) {
            Ok(s) => {
                let bytes: [u8; 32] = hex::decode(s.trim())
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "bad provenance key length")?;
                SigningKey::from_bytes(&bytes)
            }
            Err(_) => {
                let k = SigningKey::generate(&mut rand::rngs::OsRng);
                write_private(&path, hex::encode(k.to_bytes()).as_bytes()).map_err(|e| e.to_string())?;
                let _ = std::fs::write(keys_dir.join("provenance.pub"), hex::encode(k.verifying_key().to_bytes()));
                k
            }
        };
        Ok(Self {
            store,
            key,
            lock: Mutex::new(()),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Appends a record; `seq` and `prev_hash` are assigned here.
    pub async fn append(&self, mut rec: ProvenanceRecord) -> Result<ProvenanceRow, String> {
        let _g = self.lock.lock().await;
        let (seq, prev) = match self.store.provenance_last().map_err(|e| e.to_string())? {
            Some((s, h)) => (s + 1, h),
            None => (1, GENESIS.to_string()),
        };
        rec.seq = seq;
        rec.prev_hash = prev.clone();
        rec.format = 1;
        let record = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
        let hash = hex::encode(Sha256::digest(record.as_bytes()));
        let signature = hex::encode(self.key.sign(hash.as_bytes()).to_bytes());
        let row = ProvenanceRow {
            seq,
            artifact_sha256: rec.artifact_sha256.clone(),
            record,
            prev_hash: prev,
            hash,
            signature,
        };
        self.store.provenance_insert(&row).map_err(|e| e.to_string())?;
        Ok(row)
    }

    pub fn verify_chain(&self) -> Result<ChainReport, String> {
        let rows = self.store.provenance_rows(None).map_err(|e| e.to_string())?;
        Ok(verify_rows(&rows, &self.key.verifying_key()))
    }
}

/// Verifies a sequence of rows (full chain, starting at seq 1) against a public key.
pub fn verify_rows(rows: &[ProvenanceRow], vk: &VerifyingKey) -> ChainReport {
    let mut errors = vec![];
    let mut prev = GENESIS.to_string();
    for (i, r) in rows.iter().enumerate() {
        let expected_seq = i as i64 + 1;
        if r.seq != expected_seq {
            errors.push(format!("gap or reordering at seq {} (expected {expected_seq})", r.seq));
        }
        let hash = hex::encode(Sha256::digest(r.record.as_bytes()));
        if hash != r.hash {
            errors.push(format!("seq {}: record content does not match its hash (modified)", r.seq));
        }
        match serde_json::from_str::<ProvenanceRecord>(&r.record) {
            Ok(rec) => {
                if rec.prev_hash != prev || r.prev_hash != prev {
                    errors.push(format!("seq {}: broken chain link", r.seq));
                }
                if rec.seq != r.seq {
                    errors.push(format!("seq {}: sequence number inside record differs", r.seq));
                }
            }
            Err(e) => errors.push(format!("seq {}: unreadable record: {e}", r.seq)),
        }
        let sig_ok = hex::decode(&r.signature)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .map(|b| vk.verify(r.hash.as_bytes(), &Signature::from_bytes(&b)).is_ok())
            .unwrap_or(false);
        if !sig_ok {
            errors.push(format!("seq {}: invalid signature", r.seq));
        }
        prev = r.hash.clone();
    }
    ChainReport {
        records: rows.len(),
        valid: errors.is_empty(),
        public_key: hex::encode(vk.to_bytes()),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(sha: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            format: 1,
            seq: 0,
            timestamp: "t".into(),
            job_id: "j".into(),
            package: "com.a.b".into(),
            version_code: Some(1),
            artifact_sha256: sha.into(),
            artifact_sha1: "s".into(),
            size: 1,
            file_name: "a.apk".into(),
            origin: "original".into(),
            kind: serde_json::json!({}),
            provider: "fdroid".into(),
            channel: "c".into(),
            device_profile: None,
            source: "u".into(),
            derived_from: None,
            tool: None,
            verification: serde_json::json!({}),
            prev_hash: String::new(),
        }
    }

    #[tokio::test]
    async fn chain_detects_tampering() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(Store::open(&d.path().join("db"), d.path().join("o"), d.path().join("t")).unwrap());
        let l = Ledger::open(s.clone(), &d.path().join("keys")).unwrap();
        for i in 0..3 {
            l.append(rec(&format!("{i:064}"))).await.unwrap();
        }
        assert!(l.verify_chain().unwrap().valid);
        let rows = s.provenance_rows(None).unwrap();
        let tampered = rows[1].record.replace("fdroid", "evil");
        s._tamper_provenance(2, &tampered).unwrap();
        let r = l.verify_chain().unwrap();
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.contains("modified")));
        // Reopening keeps the same key.
        let l2 = Ledger::open(s, &d.path().join("keys")).unwrap();
        assert_eq!(l2.public_key_hex(), l.public_key_hex());
    }
}
