//! Persistence: SQLite for metadata and a content-addressed object store for files.
//!
//! Objects are stored once per SHA-256 (`objects/ab/cdef…`), which deduplicates identical files
//! across jobs, providers and device profiles. Files are never modified after adoption.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uad_core::{JobState, Sha256Digest};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY,
    input TEXT NOT NULL,
    package TEXT,
    state TEXT NOT NULL,
    options TEXT NOT NULL,
    error TEXT,
    report TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_package ON jobs(package);
CREATE TABLE IF NOT EXISTS job_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job_id);
CREATE TABLE IF NOT EXISTS artifacts(
    sha256 TEXT PRIMARY KEY,
    sha1 TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    analysis TEXT
);
CREATE TABLE IF NOT EXISTS signer_pins(
    package TEXT NOT NULL,
    channel TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    first_job TEXT,
    PRIMARY KEY(package, channel, cert_sha256)
);
CREATE TABLE IF NOT EXISTS provenance(
    seq INTEGER PRIMARY KEY,
    artifact_sha256 TEXT NOT NULL,
    record TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS provenance_artifact ON provenance(artifact_sha256);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRow {
    pub id: String,
    pub input: String,
    pub package: Option<String>,
    pub state: JobState,
    pub options: serde_json::Value,
    pub error: Option<String>,
    pub report: Option<serde_json::Value>,
    pub attempts: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEventRow {
    pub at: String,
    pub from_state: Option<String>,
    pub to_state: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRow {
    pub seq: i64,
    pub artifact_sha256: String,
    pub record: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

pub struct Store {
    conn: Mutex<Connection>,
    objects: PathBuf,
    tmp: PathBuf,
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn row_to_job(r: &rusqlite::Row<'_>) -> rusqlite::Result<JobRow> {
    let state: String = r.get(3)?;
    let options: String = r.get(4)?;
    let report: Option<String> = r.get(6)?;
    Ok(JobRow {
        id: r.get(0)?,
        input: r.get(1)?,
        package: r.get(2)?,
        state: JobState::parse(&state).unwrap_or(JobState::Failed),
        options: serde_json::from_str(&options).unwrap_or(serde_json::Value::Null),
        error: r.get(5)?,
        report: report.and_then(|s| serde_json::from_str(&s).ok()),
        attempts: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

const JOB_COLS: &str = "id, input, package, state, options, error, report, attempts, created_at, updated_at";

impl Store {
    pub fn open(db: &Path, objects: PathBuf, tmp: PathBuf) -> Result<Self> {
        if let Some(d) = db.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::create_dir_all(&objects)?;
        std::fs::create_dir_all(&tmp)?;
        let conn = Connection::open(db)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(SCHEMA)?;
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1')", [])?;
        Ok(Self { conn: Mutex::new(conn), objects, tmp })
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp
    }

    // ---- objects -------------------------------------------------------------------------

    pub fn object_path(&self, sha: &Sha256Digest) -> PathBuf {
        let h = sha.to_hex();
        self.objects.join(&h[..2]).join(&h[2..])
    }

    /// Moves a verified temporary file into the object store (or drops it if already present).
    pub fn adopt(&self, tmp: &Path, sha256: &Sha256Digest, sha1_hex: &str, size: u64) -> Result<PathBuf> {
        let dest = self.object_path(sha256);
        if dest.exists() {
            std::fs::remove_file(tmp)?;
        } else {
            std::fs::create_dir_all(dest.parent().unwrap())?;
            if std::fs::rename(tmp, &dest).is_err() {
                // Different filesystem: copy then remove.
                std::fs::copy(tmp, &dest)?;
                std::fs::remove_file(tmp)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o444));
            }
        }
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO artifacts(sha256, sha1, size, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![sha256.to_hex(), sha1_hex, size as i64, now()],
        )?;
        Ok(dest)
    }

    pub fn artifact_known(&self, sha256: &Sha256Digest) -> Result<bool> {
        let n: i64 = self.conn.lock().unwrap().query_row("SELECT COUNT(*) FROM artifacts WHERE sha256 = ?1", [sha256.to_hex()], |r| r.get(0))?;
        Ok(n > 0 && self.object_path(sha256).exists())
    }

    pub fn artifact_analysis(&self, sha256: &Sha256Digest) -> Result<Option<String>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT analysis FROM artifacts WHERE sha256 = ?1", [sha256.to_hex()], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    pub fn set_artifact_analysis(&self, sha256: &Sha256Digest, json: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("UPDATE artifacts SET analysis = ?2 WHERE sha256 = ?1", params![sha256.to_hex(), json])?;
        Ok(())
    }

    pub fn stats(&self) -> Result<(i64, i64, i64)> {
        let c = self.conn.lock().unwrap();
        let jobs: i64 = c.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))?;
        let (n, bytes): (i64, i64) = c.query_row("SELECT COUNT(*), COALESCE(SUM(size),0) FROM artifacts", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok((jobs, n, bytes))
    }

    // ---- jobs ----------------------------------------------------------------------------

    pub fn insert_job(&self, id: &str, input: &str, options: &serde_json::Value) -> Result<()> {
        let t = now();
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO jobs(id, input, state, options, created_at, updated_at) VALUES (?1, ?2, 'queued', ?3, ?4, ?4)",
            params![id, input, options.to_string(), t],
        )?;
        c.execute("INSERT INTO job_events(job_id, at, to_state, message) VALUES (?1, ?2, 'queued', 'created')", params![id, t])?;
        Ok(())
    }

    /// Records a state transition; fails if the stored state is not `from` (optimistic check).
    pub fn transition(&self, id: &str, from: JobState, to: JobState, message: Option<&str>) -> Result<()> {
        let t = now();
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE jobs SET state = ?3, updated_at = ?4, attempts = attempts + CASE WHEN ?3 = 'resolving' THEN 1 ELSE 0 END WHERE id = ?1 AND state = ?2",
            params![id, from.as_str(), to.as_str(), t],
        )?;
        if n != 1 {
            return Err(StoreError::Other(format!("job {id} is not in state {from}")));
        }
        c.execute(
            "INSERT INTO job_events(job_id, at, from_state, to_state, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, t, from.as_str(), to.as_str(), message],
        )?;
        Ok(())
    }

    pub fn set_job_package(&self, id: &str, package: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("UPDATE jobs SET package = ?2 WHERE id = ?1", params![id, package])?;
        Ok(())
    }

    pub fn set_job_error(&self, id: &str, error: Option<&str>) -> Result<()> {
        self.conn.lock().unwrap().execute("UPDATE jobs SET error = ?2 WHERE id = ?1", params![id, error])?;
        Ok(())
    }

    pub fn set_job_report(&self, id: &str, report: &serde_json::Value) -> Result<()> {
        self.conn.lock().unwrap().execute("UPDATE jobs SET report = ?2, updated_at = ?3 WHERE id = ?1", params![id, report.to_string(), now()])?;
        Ok(())
    }

    pub fn get_job(&self, id: &str) -> Result<Option<JobRow>> {
        Ok(self.conn.lock().unwrap().query_row(&format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1"), [id], row_to_job).optional()?)
    }

    pub fn list_jobs(&self, limit: usize, package: Option<&str>) -> Result<Vec<JobRow>> {
        let c = self.conn.lock().unwrap();
        let mut out = vec![];
        match package {
            Some(p) => {
                let mut st = c.prepare(&format!("SELECT {JOB_COLS} FROM jobs WHERE package = ?1 ORDER BY created_at DESC LIMIT ?2"))?;
                for r in st.query_map(params![p, limit as i64], row_to_job)? {
                    out.push(r?);
                }
            }
            None => {
                let mut st = c.prepare(&format!("SELECT {JOB_COLS} FROM jobs ORDER BY created_at DESC LIMIT ?1"))?;
                for r in st.query_map(params![limit as i64], row_to_job)? {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    pub fn jobs_in_states(&self, states: &[JobState]) -> Result<Vec<JobRow>> {
        let all = self.list_jobs(100_000, None)?;
        Ok(all.into_iter().filter(|j| states.contains(&j.state)).collect())
    }

    pub fn job_events(&self, id: &str) -> Result<Vec<JobEventRow>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT at, from_state, to_state, message FROM job_events WHERE job_id = ?1 ORDER BY id")?;
        let rows = st.query_map([id], |r| Ok(JobEventRow { at: r.get(0)?, from_state: r.get(1)?, to_state: r.get(2)?, message: r.get(3)? }))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---- signer pins -----------------------------------------------------------------------

    pub fn pins(&self, package: &str, channel: &str) -> Result<Vec<String>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT cert_sha256 FROM signer_pins WHERE package = ?1 AND channel = ?2")?;
        let rows = st.query_map(params![package, channel], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn add_pin(&self, package: &str, channel: &str, cert: &str, job: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO signer_pins(package, channel, cert_sha256, first_seen, first_job) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![package, channel, cert, now(), job],
        )?;
        Ok(())
    }

    // ---- provenance --------------------------------------------------------------------------

    pub fn provenance_last(&self) -> Result<Option<(i64, String)>> {
        Ok(self.conn.lock().unwrap().query_row("SELECT seq, hash FROM provenance ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)
    }

    pub fn provenance_insert(&self, row: &ProvenanceRow) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO provenance(seq, artifact_sha256, record, prev_hash, hash, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![row.seq, row.artifact_sha256, row.record, row.prev_hash, row.hash, row.signature],
        )?;
        Ok(())
    }

    pub fn provenance_rows(&self, artifact: Option<&str>) -> Result<Vec<ProvenanceRow>> {
        let c = self.conn.lock().unwrap();
        let map = |r: &rusqlite::Row<'_>| {
            Ok(ProvenanceRow { seq: r.get(0)?, artifact_sha256: r.get(1)?, record: r.get(2)?, prev_hash: r.get(3)?, hash: r.get(4)?, signature: r.get(5)? })
        };
        let mut out = vec![];
        match artifact {
            Some(a) => {
                let mut st = c.prepare("SELECT seq, artifact_sha256, record, prev_hash, hash, signature FROM provenance WHERE artifact_sha256 = ?1 ORDER BY seq")?;
                for r in st.query_map([a], map)? {
                    out.push(r?);
                }
            }
            None => {
                let mut st = c.prepare("SELECT seq, artifact_sha256, record, prev_hash, hash, signature FROM provenance ORDER BY seq")?;
                for r in st.query_map([], map)? {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    /// Test hook: tamper with a stored record.
    #[doc(hidden)]
    pub fn _tamper_provenance(&self, seq: i64, record: &str) -> Result<()> {
        self.conn.lock().unwrap().execute("UPDATE provenance SET record = ?2 WHERE seq = ?1", params![seq, record])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_and_transitions() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("db"), d.path().join("o"), d.path().join("t")).unwrap();
        s.insert_job("j1", "com.a.b", &serde_json::json!({})).unwrap();
        s.transition("j1", JobState::Queued, JobState::Resolving, None).unwrap();
        assert!(s.transition("j1", JobState::Queued, JobState::Resolving, None).is_err(), "stale transition rejected");
        let j = s.get_job("j1").unwrap().unwrap();
        assert_eq!(j.state, JobState::Resolving);
        assert_eq!(j.attempts, 1);
        assert_eq!(s.job_events("j1").unwrap().len(), 2);
    }

    #[test]
    fn content_addressed_dedup() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("db"), d.path().join("o"), d.path().join("t")).unwrap();
        let sha = Sha256Digest([1u8; 32]);
        for _ in 0..2 {
            let t = d.path().join("t").join("x");
            std::fs::write(&t, b"data").unwrap();
            let p = s.adopt(&t, &sha, "00", 4).unwrap();
            assert!(p.exists());
            assert!(!t.exists());
        }
        assert!(s.artifact_known(&sha).unwrap());
        assert_eq!(s.stats().unwrap().1, 1);
    }
}
