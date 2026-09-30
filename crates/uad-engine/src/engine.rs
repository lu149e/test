//! Job orchestration.
//!
//! A job moves through the explicit state machine of [`uad_core::JobState`]; every transition
//! is persisted (with an event log) before work for the next phase starts, so a restart
//! re-queues interrupted jobs and nothing is ever reported as verified without passing through
//! `Verifying`.

use crate::bundletool::Bundletool;
use crate::config::Config;
use crate::download::{DownloadError, Downloader};
use crate::provenance::{Ledger, ProvenanceRecord};
use crate::report::*;
use crate::secrets::FileSecretStore;
use crate::store::{JobEventRow, JobRow, Store};
use futures::future::join_all;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use uad_apk::{ApkAnalysis, Container};
use uad_core::{
    parse_input, Availability, Discovery, DiscoveryRequest, FileRole, JobEvent, JobOptions, JobState, Offer, OfferLayout, Provider, ProviderError,
    SecretStore, Sha256Digest, VariantKind, VerificationOutcome,
};
use uad_providers::play::PlayProvider;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("invalid input: {0}")]
    Input(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Transition(#[from] uad_core::TransitionError),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    #[serde(flatten)]
    pub job: JobRow,
    pub events: Vec<JobEventRow>,
}

struct Cancelled;

pub struct Engine {
    pub cfg: Config,
    pub store: Arc<Store>,
    pub secrets: Arc<FileSecretStore>,
    pub ledger: Ledger,
    providers: Vec<Arc<dyn Provider>>,
    play: Arc<PlayProvider>,
    downloader: Downloader,
    bundletool: Bundletool,
    tx: mpsc::UnboundedSender<String>,
    rx: Mutex<Option<mpsc::UnboundedReceiver<String>>>,
    cancelled: std::sync::Mutex<HashSet<String>>,
}

fn provider_status(e: &ProviderError) -> &'static str {
    match e {
        ProviderError::NotFound => "not_found",
        ProviderError::NotConfigured(_) => "not_configured",
        ProviderError::Denied(_) => "denied",
        ProviderError::Auth(_) => "auth_error",
        _ => "error",
    }
}

fn role_label(r: &FileRole) -> String {
    match r {
        FileRole::Standalone => "standalone APK".into(),
        FileRole::Base => "base APK".into(),
        FileRole::Split(n) => format!("split {n}"),
        FileRole::AppBundle => "app bundle".into(),
        FileRole::Obb(k) => format!("{k} OBB"),
        FileRole::DexMetadata => "dex metadata".into(),
    }
}

impl Engine {
    pub fn open(cfg: Config) -> Result<Arc<Self>, EngineError> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| EngineError::Other(format!("{}: {e}", cfg.data_dir.display())))?;
        let store = Arc::new(Store::open(&cfg.db_path(), cfg.objects_dir(), cfg.tmp_dir())?);
        let secrets = Arc::new(FileSecretStore::open(&cfg.data_dir).map_err(EngineError::Other)?);
        let ledger = Ledger::open(store.clone(), &cfg.keys_dir()).map_err(EngineError::Other)?;
        let cache = cfg.cache_dir();
        let secret_dyn: Arc<dyn SecretStore> = secrets.clone();
        let play = Arc::new(PlayProvider::new(cfg.providers.play.clone(), secret_dyn.clone()));
        let mut providers: Vec<Arc<dyn Provider>> = vec![
            Arc::new(uad_providers::play_web::PlayWebProvider::new(cfg.providers.play_web)),
            play.clone(),
            Arc::new(uad_providers::play_dev::PlayDevProvider::new(cfg.providers.play_dev.clone(), secret_dyn.clone())),
            Arc::new(uad_providers::fdroid::FdroidProvider::new(cfg.providers.fdroid.clone(), cache.clone())),
            Arc::new(uad_providers::local::LocalProvider::new(cfg.providers.local.enabled, cfg.inbox_dir(), &cache)),
        ];
        #[cfg(feature = "emulator")]
        providers.push(Arc::new(uad_providers::emulator::EmulatorProvider::new(cfg.providers.emulator.clone(), &cache)));
        providers.sort_by_key(|p| p.info().priority);
        std::fs::create_dir_all(cfg.inbox_dir()).map_err(|e| EngineError::Other(e.to_string()))?;
        let downloader = Downloader::new(store.clone(), cfg.max_concurrent_downloads, cfg.download_retries, cfg.max_file_bytes);
        let bundletool = Bundletool::new(cfg.bundletool.clone(), &cfg.data_dir);
        let (tx, rx) = mpsc::unbounded_channel();
        Ok(Arc::new(Self {
            cfg,
            store,
            secrets,
            ledger,
            providers,
            play,
            downloader,
            bundletool,
            tx,
            rx: Mutex::new(Some(rx)),
            cancelled: std::sync::Mutex::new(HashSet::new()),
        }))
    }

    pub fn play(&self) -> &PlayProvider {
        &self.play
    }

    pub fn providers_info(&self) -> Vec<uad_core::ProviderInfo> {
        self.providers.iter().map(|p| p.info()).collect()
    }

    /// Re-queues interrupted jobs and starts the worker pool.
    pub async fn start(self: &Arc<Self>) -> Result<(), EngineError> {
        let active: Vec<JobState> = JobState::ALL.into_iter().filter(|s| s.is_active()).collect();
        for j in self.store.jobs_in_states(&active)? {
            tracing::info!("recovering interrupted job {} (was {})", j.id, j.state);
            let to = j.state.next(JobEvent::Retry)?;
            self.store.transition(&j.id, j.state, to, Some("recovered after restart"))?;
        }
        for j in self.store.jobs_in_states(&[JobState::Queued])? {
            let _ = self.tx.send(j.id);
        }
        let rx = self.rx.lock().await.take().ok_or_else(|| EngineError::Other("engine already started".into()))?;
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..self.cfg.max_concurrent_jobs.max(1) {
            let me = self.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                loop {
                    let next = rx.lock().await.recv().await;
                    match next {
                        Some(id) => me.run_job(&id).await,
                        None => break,
                    }
                }
            });
        }
        Ok(())
    }

    pub fn submit(&self, input: &str, options: JobOptions) -> Result<String, EngineError> {
        let parsed = parse_input(input).map_err(|e| EngineError::Input(e.to_string()))?;
        let id = uuid::Uuid::new_v4().to_string();
        self.store.insert_job(&id, input.trim(), &serde_json::to_value(&options).unwrap())?;
        self.store.set_job_package(&id, parsed.package.as_str())?;
        let _ = self.tx.send(id.clone());
        Ok(id)
    }

    /// Creates a job without queueing it (used by the CLI to run it in the foreground).
    pub fn create_job(&self, input: &str, options: JobOptions) -> Result<String, EngineError> {
        let parsed = parse_input(input).map_err(|e| EngineError::Input(e.to_string()))?;
        let id = uuid::Uuid::new_v4().to_string();
        self.store.insert_job(&id, input.trim(), &serde_json::to_value(&options).unwrap())?;
        self.store.set_job_package(&id, parsed.package.as_str())?;
        Ok(id)
    }

    pub fn retry(&self, id: &str) -> Result<(), EngineError> {
        let j = self.store.get_job(id)?.ok_or_else(|| EngineError::NotFound(id.into()))?;
        if !j.state.is_terminal() {
            return Err(EngineError::Conflict(format!("job is {}", j.state)));
        }
        let to = j.state.next(JobEvent::Retry)?;
        self.store.transition(id, j.state, to, Some("retry requested"))?;
        self.store.set_job_error(id, None)?;
        self.cancelled.lock().unwrap().remove(id);
        let _ = self.tx.send(id.to_string());
        Ok(())
    }

    pub fn cancel(&self, id: &str) -> Result<(), EngineError> {
        let j = self.store.get_job(id)?.ok_or_else(|| EngineError::NotFound(id.into()))?;
        if j.state.is_terminal() {
            return Err(EngineError::Conflict(format!("job is {}", j.state)));
        }
        if j.state == JobState::Queued {
            self.store.transition(id, JobState::Queued, JobState::Cancelled, Some("cancelled while queued"))?;
        } else {
            self.cancelled.lock().unwrap().insert(id.to_string());
        }
        Ok(())
    }

    pub fn job(&self, id: &str) -> Result<JobView, EngineError> {
        let job = self.store.get_job(id)?.ok_or_else(|| EngineError::NotFound(id.into()))?;
        let events = self.store.job_events(id)?;
        Ok(JobView { job, events })
    }

    pub fn jobs(&self, limit: usize, package: Option<&str>) -> Result<Vec<JobRow>, EngineError> {
        Ok(self.store.list_jobs(limit, package)?)
    }

    pub fn report(&self, id: &str) -> Result<Option<JobReport>, EngineError> {
        let job = self.store.get_job(id)?.ok_or_else(|| EngineError::NotFound(id.into()))?;
        Ok(job.report.and_then(|r| serde_json::from_value(r).ok()))
    }

    /// Path and file name of a *verified* artifact (only artifacts with a provenance record
    /// are served; unverified bytes stay quarantined in the store).
    pub fn verified_artifact(&self, sha: &str) -> Result<(PathBuf, String), EngineError> {
        let digest: Sha256Digest = sha.parse().map_err(|_| EngineError::Input("bad sha256".into()))?;
        let rows = self.store.provenance_rows(Some(&digest.to_hex()))?;
        let last = rows.last().ok_or_else(|| EngineError::NotFound("no verified artifact with this digest".into()))?;
        let rec: ProvenanceRecord = serde_json::from_str(&last.record).map_err(|e| EngineError::Other(e.to_string()))?;
        let path = self.store.object_path(&digest);
        if !path.exists() {
            return Err(EngineError::NotFound("object missing from store".into()));
        }
        Ok((path, rec.file_name))
    }

    pub fn provenance(&self, sha: &str) -> Result<Vec<serde_json::Value>, EngineError> {
        let rows = self.store.provenance_rows(Some(sha))?;
        Ok(rows
            .into_iter()
            .map(|r| serde_json::json!({"seq": r.seq, "hash": r.hash, "prev_hash": r.prev_hash, "signature": r.signature, "record": serde_json::from_str::<serde_json::Value>(&r.record).unwrap_or_default()}))
            .collect())
    }

    /// Builds (or reuses) an `.apks` archive for a verified split set of a job.
    pub async fn export_split_set(&self, job_id: &str, set_index: usize) -> Result<(PathBuf, String), EngineError> {
        let report = self.report(job_id)?.ok_or_else(|| EngineError::NotFound("job has no report".into()))?;
        let set = report.split_sets.get(set_index).ok_or_else(|| EngineError::NotFound("split set".into()))?;
        let members: Vec<&VariantEntry> = set.members.iter().filter_map(|id| report.variants.iter().find(|v| v.id == *id)).collect();
        if members.is_empty() || members.iter().any(|m| m.verified != Some(true)) {
            return Err(EngineError::Conflict("split set contains unverified members".into()));
        }
        let pkg = report.package.clone().unwrap_or_default();
        let name = format!("{pkg}-{}-{}.apks", set.version_code, set.device_profile.clone().unwrap_or_else(|| set.provider.clone()));
        let dir = self.cfg.data_dir.join("exports").join(job_id);
        tokio::fs::create_dir_all(&dir).await.map_err(|e| EngineError::Other(e.to_string()))?;
        let out = dir.join(format!("set-{set_index}.apks"));
        if !out.exists() {
            let items: Vec<(String, PathBuf, Option<String>, String, u64)> = members
                .iter()
                .map(|m| {
                    let sha: Sha256Digest = m.sha256.as_deref().unwrap_or_default().parse().unwrap_or(Sha256Digest([0; 32]));
                    let split = match &m.role {
                        Some(FileRole::Split(s)) => Some(s.clone()),
                        _ => None,
                    };
                    (m.file_name.clone().unwrap_or_else(|| format!("{}.apk", m.id)), self.store.object_path(&sha), split, sha.to_hex(), m.size.unwrap_or(0))
                })
                .collect();
            let vc = set.version_code;
            let out2 = out.clone();
            tokio::task::spawn_blocking(move || {
                let refs: Vec<(String, &Path, Option<String>, String, u64)> = items.iter().map(|(a, b, c, d, e)| (a.clone(), b.as_path(), c.clone(), d.clone(), *e)).collect();
                uad_apk::apks::write_apks(&out2, &pkg, vc, &refs)
            })
            .await
            .map_err(|e| EngineError::Other(e.to_string()))?
            .map_err(|e| EngineError::Other(e.to_string()))?;
        }
        Ok((out, name))
    }

    /// Moves an uploaded/imported file into the inbox after validating it is an APK/AAB/APKS,
    /// returning the package name it declares.
    pub async fn import_file(&self, tmp: &Path, original_name: &str) -> Result<String, EngineError> {
        let ext = Path::new(original_name).extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
        if !["apk", "aab", "apks", "xapk"].contains(&ext.as_str()) {
            return Err(EngineError::Input("only .apk, .aab, .apks and .xapk files are accepted".into()));
        }
        let t = tmp.to_path_buf();
        let e2 = ext.clone();
        let package = tokio::task::spawn_blocking(move || -> Result<String, String> {
            if e2 == "apks" || e2 == "xapk" {
                let mut z = zip::ZipArchive::new(std::fs::File::open(&t).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                for i in 0..z.len() {
                    let mut f = z.by_index(i).map_err(|e| e.to_string())?;
                    if f.name().ends_with(".apk") {
                        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
                        std::io::copy(&mut f, &mut tmp).map_err(|e| e.to_string())?;
                        if let Ok((_, m)) = uad_apk::peek_manifest(tmp.path()) {
                            return Ok(m.package);
                        }
                    }
                }
                Err("container holds no readable APK".into())
            } else {
                uad_apk::peek_manifest(&t).map(|(_, m)| m.package).map_err(|e| e.to_string())
            }
        })
        .await
        .map_err(|e| EngineError::Other(e.to_string()))?
        .map_err(EngineError::Input)?;
        let (sha, _, _) = crate::download::hash_file(tmp).await.map_err(|e| EngineError::Other(e.to_string()))?;
        let dest = self.cfg.inbox_dir().join(format!("{package}-{}.{ext}", &sha.to_hex()[..16]));
        if tokio::fs::rename(tmp, &dest).await.is_err() {
            tokio::fs::copy(tmp, &dest).await.map_err(|e| EngineError::Other(e.to_string()))?;
            let _ = tokio::fs::remove_file(tmp).await;
        }
        Ok(package)
    }

    // ---- pipeline --------------------------------------------------------------------------

    fn is_cancelled(&self, id: &str) -> bool {
        self.cancelled.lock().unwrap().contains(id)
    }

    fn advance(&self, id: &str, state: &mut JobState, ev: JobEvent, msg: Option<&str>) -> Result<(), EngineError> {
        let to = state.next(ev)?;
        self.store.transition(id, *state, to, msg)?;
        *state = to;
        Ok(())
    }

    /// Runs one job to a terminal state. Errors are recorded on the job, never propagated.
    pub async fn run_job(&self, id: &str) {
        let job = match self.store.get_job(id) {
            Ok(Some(j)) => j,
            _ => return,
        };
        if job.state != JobState::Queued {
            return;
        }
        let mut state = job.state;
        let mut report = JobReport::default();
        let started = Instant::now();
        let res = self.pipeline(&job, &mut state, &mut report).await;
        report.counts = count(&report);
        let _ = self.store.set_job_report(id, &serde_json::to_value(&report).unwrap_or_default());
        match res {
            Ok(Ok(())) => tracing::info!("job {id} finished as {state} in {:?}", started.elapsed()),
            Ok(Err(Cancelled)) => {
                let _ = self.advance(id, &mut state, JobEvent::Cancel, Some("cancelled by user"));
                self.cancelled.lock().unwrap().remove(id);
            }
            Err(e) => {
                tracing::warn!("job {id} failed: {e}");
                let msg = e.to_string();
                let _ = self.store.set_job_error(id, Some(&msg));
                if !state.is_terminal() {
                    let _ = self.advance(id, &mut state, JobEvent::Fail, Some(&msg));
                }
            }
        }
    }

    async fn pipeline(&self, job: &JobRow, state: &mut JobState, report: &mut JobReport) -> Result<Result<(), Cancelled>, EngineError> {
        let id = job.id.as_str();
        let opts: JobOptions = serde_json::from_value(job.options.clone()).unwrap_or_default();
        macro_rules! check_cancel {
            () => {
                if self.is_cancelled(id) {
                    return Ok(Err(Cancelled));
                }
            };
        }

        // Resolving --------------------------------------------------------------------------
        self.advance(id, state, JobEvent::Start, None)?;
        let input = parse_input(&job.input).map_err(|e| EngineError::Input(e.to_string()))?;
        report.package = Some(input.package.to_string());
        report.play_url = Some(input.package.play_url());
        self.advance(id, state, JobEvent::Resolved, Some(input.package.as_str()))?;
        check_cancel!();

        // Discovering ------------------------------------------------------------------------
        let req = DiscoveryRequest {
            package: input.package.clone(),
            version_code: opts.version_code,
            abis: opts.abis.clone(),
            locale: input.hl.clone(),
        };
        let selected: Vec<Arc<dyn Provider>> = self
            .providers
            .iter()
            .filter(|p| {
                let i = p.info();
                i.enabled && (opts.providers.is_empty() || opts.providers.contains(&i.id) || i.id == "play_web")
            })
            .cloned()
            .collect();
        for p in self.providers.iter().filter(|p| !selected.iter().any(|s| s.info().id == p.info().id)) {
            let i = p.info();
            report.providers.push(ProviderOutcome {
                id: i.id,
                name: i.name,
                status: "skipped".into(),
                message: Some(if i.enabled { "excluded by job options".into() } else { i.status }),
                offers: 0,
                duration_ms: 0,
                notes: vec![],
            });
        }
        let timeout = Duration::from_secs(self.cfg.discovery_timeout_secs);
        let results = join_all(selected.iter().map(|p| {
            let req = req.clone();
            let p = p.clone();
            async move {
                let t = Instant::now();
                let r = tokio::time::timeout(timeout, p.discover(&req)).await;
                (p.info(), r, t.elapsed())
            }
        }))
        .await;
        let mut offers: Vec<(i32, Offer)> = vec![];
        let mut discoveries: Vec<(i32, String, Discovery)> = vec![];
        for (info, r, dur) in results {
            let mut outcome = ProviderOutcome { id: info.id.clone(), name: info.name.clone(), status: String::new(), message: None, offers: 0, duration_ms: dur.as_millis(), notes: vec![] };
            match r {
                Err(_) => {
                    outcome.status = "timeout".into();
                    outcome.message = Some(format!("no answer within {}s", timeout.as_secs()));
                }
                Ok(Err(e)) => {
                    outcome.status = provider_status(&e).into();
                    outcome.message = Some(e.to_string());
                }
                Ok(Ok(d)) => {
                    outcome.offers = d.offers.len();
                    outcome.status = if d.offers.is_empty() { "metadata_only".into() } else { "offers".into() };
                    outcome.notes = d.notes.clone();
                    for o in &d.offers {
                        offers.push((info.priority, o.clone()));
                    }
                    discoveries.push((info.priority, info.id.clone(), d));
                }
            }
            report.providers.push(outcome);
        }
        // Metadata: best-ranked provider first, gaps filled from the others.
        discoveries.sort_by_key(|(p, _, _)| *p);
        for (_, _, d) in &discoveries {
            if let Some(m) = &d.metadata {
                match &mut report.metadata {
                    None => report.metadata = Some(m.clone()),
                    Some(cur) => {
                        cur.title = cur.title.clone().or(m.title.clone());
                        cur.developer = cur.developer.clone().or(m.developer.clone());
                        cur.icon_url = cur.icon_url.clone().or(m.icon_url.clone());
                        cur.summary = cur.summary.clone().or(m.summary.clone());
                        cur.version_name = cur.version_name.clone().or(m.version_name.clone());
                        cur.version_code = cur.version_code.or(m.version_code);
                    }
                }
            }
        }
        offers.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.version_code.cmp(&a.1.version_code)));
        let offers: Vec<Offer> = offers.into_iter().map(|(_, o)| o).collect();

        let mut next_id = 0usize;
        for (i, o) in offers.iter().enumerate() {
            for f in &o.files {
                let mut e = VariantEntry::blank(next_id, &o.provider);
                next_id += 1;
                e.channel = Some(o.channel.clone());
                e.device_profile = o.device_profile.clone();
                e.version_code = Some(o.version_code);
                e.version_name = o.version_name.clone();
                e.role = Some(f.role.clone());
                e.file_name = Some(f.file_name.clone());
                e.availability = Availability::Identified;
                e.size = f.size;
                e.abis = o.abis.clone();
                e.min_sdk = o.min_sdk;
                e.source = Some(f.source.redacted());
                e.offer_index = Some(i);
                e.description = Some(format!("{} ({:?} offer)", role_label(&f.role), o.layout));
                report.variants.push(e);
            }
        }
        for (_, _, d) in &discoveries {
            for k in &d.known {
                let mut e = VariantEntry::blank(next_id, &k.provider);
                next_id += 1;
                e.version_code = k.version_code;
                e.version_name = k.version_name.clone();
                e.role = k.role.clone();
                e.abis = k.abis.clone();
                e.availability = k.availability;
                e.description = Some(k.description.clone());
                report.variants.push(e);
            }
            report.notes.extend(d.notes.iter().cloned());
        }
        if offers.is_empty() {
            report.outcome = "none".into();
            report.outcome_description = "No provider offered downloadable files for this app.".into();
            let reasons: Vec<String> = report.providers.iter().filter(|p| p.id != "play_web").map(|p| format!("{}: {}", p.id, p.message.clone().unwrap_or(p.status.clone()))).collect();
            return Err(EngineError::Other(format!("no downloadable offer found ({})", reasons.join("; "))));
        }
        self.advance(id, state, JobEvent::OffersFound, Some(&format!("{} offer(s)", offers.len())))?;
        check_cancel!();

        // Acquiring --------------------------------------------------------------------------
        let (alternatives, extras) = plan(&offers, &opts);
        let mut acquired_any = false;
        for alt in &alternatives {
            let ok = self.acquire_offers(alt, &offers, report).await;
            acquired_any |= report.variants.iter().any(|v| v.sha256.is_some());
            check_cancel!();
            if ok {
                break;
            }
            report.notes.push(format!("offer(s) {alt:?} could not be fully downloaded; trying the next alternative"));
        }
        if !extras.is_empty() {
            self.acquire_offers(&extras, &offers, report).await;
            acquired_any |= report.variants.iter().any(|v| v.sha256.is_some());
        }
        if !acquired_any {
            return Err(EngineError::Other("every download failed".into()));
        }
        self.advance(id, state, JobEvent::Acquired, None)?;
        check_cancel!();

        // Processing -------------------------------------------------------------------------
        let mut analyses: HashMap<usize, ApkAnalysis> = HashMap::new();
        let ids: Vec<usize> = report.variants.iter().filter(|v| v.sha256.is_some()).map(|v| v.id).collect();
        for vid in ids {
            let sha = report.variants[vid].sha256.clone().unwrap();
            match self.analyze_cached(&sha).await {
                Ok(a) => {
                    let v = &mut report.variants[vid];
                    v.kind = Some(a.classification.clone());
                    v.abis = a.native_abis.clone();
                    v.min_sdk = a.manifest.min_sdk;
                    v.origin = Some("original".into());
                    v.version_name = v.version_name.clone().or(a.manifest.version_name.clone());
                    analyses.insert(vid, a);
                }
                Err(e) => {
                    let v = &mut report.variants[vid];
                    v.error = Some(format!("analysis failed: {e}"));
                    v.availability = Availability::Failed;
                    v.verified = Some(false);
                }
            }
        }
        // App bundles → universal APK with bundletool.
        let bundles: Vec<usize> = analyses.iter().filter(|(_, a)| a.container == Container::AppBundle).map(|(k, _)| *k).collect();
        for vid in bundles {
            if !opts.build_universal_from_aab {
                report.notes.push("universal APK generation from the bundle was disabled for this job".into());
                continue;
            }
            check_cancel!();
            match self.generate_universal(id, vid, report).await {
                Ok((new_id, a)) => {
                    analyses.insert(new_id, a);
                }
                Err(e) => report.notes.push(format!("bundletool could not build a universal APK: {e}")),
            }
        }
        // Split sets.
        let mut by_offer: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for v in &report.variants {
            if let (Some(oi), true) = (v.offer_index, analyses.contains_key(&v.id)) {
                if offers[oi].layout == OfferLayout::SplitSet && v.origin.as_deref() == Some("original") && matches!(v.role, Some(FileRole::Base | FileRole::Split(_))) {
                    by_offer.entry(oi).or_default().push(v.id);
                }
            }
        }
        for (oi, members) in by_offer {
            let refs: Vec<(String, &ApkAnalysis)> = members.iter().map(|m| (report.variants[*m].file_name.clone().unwrap_or_default(), &analyses[m])).collect();
            let r = uad_apk::validate_split_set(&refs);
            let o = &offers[oi];
            report.split_sets.push(SplitSetEntry {
                label: format!("{} v{}{}", o.provider, o.version_code, o.device_profile.as_ref().map(|p| format!(" ({p})")).unwrap_or_default()),
                provider: o.provider.clone(),
                device_profile: o.device_profile.clone(),
                offer_index: oi,
                version_code: o.version_code,
                members,
                report: r,
            });
        }
        self.advance(id, state, JobEvent::Processed, None)?;
        check_cancel!();

        // Verifying --------------------------------------------------------------------------
        let pkg = input.package.as_str().to_string();
        let vids: Vec<usize> = analyses.keys().copied().collect();
        for vid in vids {
            let a = &analyses[&vid];
            let offer = report.variants[vid].offer_index.map(|i| &offers[i]);
            let checks = self.verify_entry(id, &pkg, &report.variants[vid], a, offer);
            let failed = checks.iter().any(|c| c.status == CheckStatus::Fail);
            let v = &mut report.variants[vid];
            v.signature_schemes = a.signature.schemes_verified.clone();
            v.signer_sha256 = a.signature.signers.iter().map(|c| c.sha256.to_hex()).collect();
            v.checks = checks;
            v.verified = Some(!failed);
            v.availability = if failed { Availability::Failed } else { Availability::Retrieved };
            if failed && v.error.is_none() {
                v.error = Some("verification failed".into());
            }
        }
        // Split-set failures are reflected on the set; members stay individually verified.
        for vid in 0..report.variants.len() {
            if report.variants[vid].verified == Some(true) {
                let seq = self.record_provenance(id, &pkg, &report.variants[vid], analyses.get(&vid)).await?;
                report.variants[vid].provenance_seq = Some(seq);
            }
        }
        let (outcome, desc) = decide_outcome(report);
        report.outcome = outcome.into();
        report.outcome_description = desc;
        let planned_failed = report.variants.iter().any(|v| v.planned && v.availability == Availability::Failed);
        let result = match (outcome, planned_failed) {
            ("none", _) => VerificationOutcome::None,
            (_, true) => VerificationOutcome::Partial,
            ("variants", _) if report.split_sets.iter().any(|s| !s.report.installable) => VerificationOutcome::Partial,
            _ => VerificationOutcome::All,
        };
        self.advance(id, state, JobEvent::Verified(result), Some(&report.outcome_description))?;
        if result == VerificationOutcome::None {
            self.store.set_job_error(id, Some("no file passed verification"))?;
        }
        Ok(Ok(()))
    }

    async fn acquire_offers(&self, offer_ids: &[usize], offers: &[Offer], report: &mut JobReport) -> bool {
        let targets: Vec<usize> = report.variants.iter().filter(|v| v.offer_index.is_some_and(|i| offer_ids.contains(&i)) && v.sha256.is_none()).map(|v| v.id).collect();
        let jobs = targets.iter().map(|vid| {
            let v = &report.variants[*vid];
            let o = &offers[v.offer_index.unwrap()];
            let f = o.files.iter().find(|f| Some(&f.file_name) == v.file_name.as_ref() && Some(&f.role) == v.role.as_ref()).cloned();
            async move {
                match f {
                    Some(f) => (*vid, self.downloader.fetch(&f.source, &f.expected, f.size).await),
                    None => (*vid, Err(DownloadError::Other("file vanished from offer".into()))),
                }
            }
        });
        let results = join_all(jobs).await;
        let mut all_ok = true;
        for (vid, r) in results {
            let v = &mut report.variants[vid];
            v.planned = true;
            match r {
                Ok(f) => {
                    v.sha256 = Some(f.sha256.to_hex());
                    v.size = Some(f.size);
                    v.deduplicated = f.deduplicated;
                    if f.resumed_from > 0 {
                        v.checks.push(Check::new("download", CheckStatus::Info, format!("resumed at byte {}", f.resumed_from)));
                    }
                }
                Err(e) => {
                    all_ok = false;
                    v.availability = Availability::Failed;
                    v.verified = Some(false);
                    v.error = Some(format!("download failed: {e}"));
                }
            }
        }
        all_ok
    }

    async fn analyze_cached(&self, sha: &str) -> Result<ApkAnalysis, String> {
        let digest: Sha256Digest = sha.parse().map_err(|e: String| e)?;
        if let Ok(Some(json)) = self.store.artifact_analysis(&digest) {
            if let Ok(a) = serde_json::from_str::<ApkAnalysis>(&json) {
                return Ok(a);
            }
        }
        let path = self.store.object_path(&digest);
        let a = tokio::task::spawn_blocking(move || uad_apk::analyze(&path)).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
        if a.sha256 != digest {
            return Err("stored object does not match its digest".into());
        }
        let _ = self.store.set_artifact_analysis(&digest, &serde_json::to_string(&a).unwrap_or_default());
        Ok(a)
    }

    async fn generate_universal(&self, job_id: &str, bundle_vid: usize, report: &mut JobReport) -> Result<(usize, ApkAnalysis), String> {
        let src = report.variants[bundle_vid].clone();
        let sha: Sha256Digest = src.sha256.clone().unwrap_or_default().parse()?;
        let work = self.cfg.tmp_dir().join(format!("bundletool-{job_id}-{bundle_vid}"));
        let generated = self.bundletool.build_universal(&self.store.object_path(&sha), &work).await.map_err(|e| e.to_string())?;
        let fetched = self
            .downloader
            .fetch(&uad_core::FileSource::Local { path: generated.path.clone() }, &Default::default(), None)
            .await
            .map_err(|e| e.to_string())?;
        let _ = tokio::fs::remove_dir_all(&work).await;
        let a = self.analyze_cached(&fetched.sha256.to_hex()).await?;
        let new_id = report.variants.len();
        let mut e = VariantEntry::blank(new_id, &src.provider);
        e.channel = Some(format!("generated locally by {} from bundle {}", generated.tool, sha));
        e.version_code = Some(a.manifest.version_code);
        e.version_name = a.manifest.version_name.clone();
        e.role = Some(FileRole::Standalone);
        e.file_name = Some(format!("{}-{}-universal-generated.apk", a.manifest.package, a.manifest.version_code));
        e.description = Some("universal APK generated from the app bundle (NOT an original file)".into());
        e.availability = Availability::Identified;
        e.planned = true;
        e.kind = Some(VariantKind::GeneratedUniversalApk);
        e.origin = Some("generated_from_aab".into());
        e.sha256 = Some(fetched.sha256.to_hex());
        e.size = Some(fetched.size);
        e.abis = a.native_abis.clone();
        e.min_sdk = a.manifest.min_sdk;
        e.source = Some(format!("bundletool build-apks --mode=universal ({})", generated.tool));
        e.offer_index = src.offer_index;
        e.derived_from = Some(sha.to_hex());
        report.variants.push(e);
        Ok((new_id, a))
    }

    fn verify_entry(&self, job_id: &str, pkg: &str, v: &VariantEntry, a: &ApkAnalysis, offer: Option<&Offer>) -> Vec<Check> {
        let mut checks = vec![];
        let generated = v.origin.as_deref() == Some("generated_from_aab");
        let is_bundle = a.container == Container::AppBundle;
        let sig = &a.signature;

        // Integrity against source-declared digests (enforced by the downloader).
        if let Some(o) = offer {
            let f = o.files.iter().find(|f| Some(&f.file_name) == v.file_name.as_ref());
            match f.map(|f| &f.expected) {
                Some(e) if e.sha256.is_some() || e.sha1.is_some() => checks.push(Check::new(
                    "source_digest",
                    CheckStatus::Pass,
                    format!("matches digest declared by {}{}", o.provider, if e.sha256.is_some() { " (SHA-256)" } else { " (SHA-1)" }),
                )),
                _ if generated => {}
                _ => checks.push(Check::new("source_digest", CheckStatus::Info, "source declared no digest; SHA-256 computed locally")),
            }
        }
        checks.push(Check::new("sha256", CheckStatus::Info, a.sha256.to_hex()));

        // Signature.
        if is_bundle {
            if sig.v1.present {
                checks.push(Check::new(
                    "signature",
                    if sig.verified { CheckStatus::Pass } else { CheckStatus::Fail },
                    if sig.verified { "bundle JAR signature (upload key) verified".to_string() } else { sig.errors.join("; ") },
                ));
            } else {
                checks.push(Check::new("signature", CheckStatus::Warn, "bundle is not signed; integrity rests on the source digest only"));
            }
        } else if sig.verified {
            checks.push(Check::new("signature", CheckStatus::Pass, format!("valid APK signature ({})", sig.schemes_verified.join(", "))));
        } else {
            checks.push(Check::new("signature", CheckStatus::Fail, sig.errors.join("; ")));
        }
        for w in &sig.warnings {
            checks.push(Check::new("signature_policy", CheckStatus::Warn, w.clone()));
        }
        if let Some(c) = sig.current_signer() {
            checks.push(Check::new("signer", CheckStatus::Info, format!("{} — {}", c.sha256, c.subject)));
        }
        if sig.lineage.len() > 1 {
            checks.push(Check::new("key_rotation", CheckStatus::Info, format!("signing key rotated; lineage of {} certificates verified", sig.lineage.len())));
        }

        // Identity of the package.
        if a.manifest.package != pkg {
            checks.push(Check::new("package", CheckStatus::Fail, format!("file declares package {}, expected {pkg}", a.manifest.package)));
        } else {
            checks.push(Check::new("package", CheckStatus::Pass, pkg.to_string()));
        }
        if let (Some(o), false) = (offer, generated) {
            if a.manifest.version_code != o.version_code {
                checks.push(Check::new("version", CheckStatus::Fail, format!("file has versionCode {}, source announced {}", a.manifest.version_code, o.version_code)));
            } else {
                checks.push(Check::new("version", CheckStatus::Pass, format!("versionCode {}", o.version_code)));
            }
        }

        // Source-declared signer.
        if let (Some(t), false, false) = (offer.and_then(|o| o.trust.as_ref()), generated, is_bundle) {
            let ids = sig.identity_digests();
            if t.signer_cert_sha256.iter().any(|d| ids.contains(d)) {
                checks.push(Check::new(
                    "declared_signer",
                    CheckStatus::Pass,
                    format!("signer matches {}{}", t.asserted_by, if t.authenticated { " (cryptographically authenticated)" } else { "" }),
                ));
            } else {
                checks.push(Check::new(
                    "declared_signer",
                    CheckStatus::Fail,
                    format!("signer {:?} differs from the one declared by {}: {:?}", ids.iter().map(|d| d.to_hex()).collect::<Vec<_>>(), t.asserted_by, t.signer_cert_sha256),
                ));
            }
        }

        // Trust-on-first-use pinning of the signer per (package, provider).
        if !generated && !is_bundle && sig.verified && a.manifest.package == pkg {
            let channel = v.provider.clone();
            let ids: Vec<String> = sig.identity_digests().iter().map(|d| d.to_hex()).collect();
            match self.store.pins(pkg, &channel) {
                Ok(pins) if pins.is_empty() => {
                    for idh in sig.signers.iter().map(|c| c.sha256.to_hex()) {
                        let _ = self.store.add_pin(pkg, &channel, &idh, job_id);
                    }
                    checks.push(Check::new("signer_pin", CheckStatus::Info, format!("first time this signer is seen for {pkg} via {channel}: pinned")));
                }
                Ok(pins) => {
                    if ids.iter().any(|i| pins.contains(i)) {
                        checks.push(Check::new("signer_pin", CheckStatus::Pass, "same signer as previously pinned (or rotated from it)"));
                        for idh in sig.signers.iter().map(|c| c.sha256.to_hex()) {
                            let _ = self.store.add_pin(pkg, &channel, &idh, job_id);
                        }
                    } else {
                        checks.push(Check::new(
                            "signer_pin",
                            if self.cfg.strict_signer_pinning { CheckStatus::Fail } else { CheckStatus::Warn },
                            format!("SIGNER CHANGED: pinned {pins:?}, now {ids:?}, without a verified rotation proof"),
                        ));
                    }
                }
                Err(e) => checks.push(Check::new("signer_pin", CheckStatus::Warn, format!("pin store unavailable: {e}"))),
            }
        }

        // Classification vs. what the source claimed.
        if let Some(o) = offer {
            if o.layout == OfferLayout::UniversalApk && !generated && !matches!(a.classification, VariantKind::UniversalApk) {
                checks.push(Check::new("classification", CheckStatus::Warn, format!("source described it as universal; analysis: {:?}", a.classification)));
            }
        }
        if generated {
            checks.push(Check::new("origin", CheckStatus::Info, "generated from an app bundle and signed with the local build key; not an original distribution file"));
        } else {
            checks.push(Check::new("origin", CheckStatus::Info, "original bytes as delivered by the source (never modified or re-signed)"));
        }
        checks.push(Check::new(
            "malware",
            CheckStatus::Info,
            "not assessed: a valid signature proves integrity and signer identity, not that the code is safe or that it came from Google Play",
        ));
        checks
    }

    async fn record_provenance(&self, job_id: &str, pkg: &str, v: &VariantEntry, a: Option<&ApkAnalysis>) -> Result<i64, EngineError> {
        let a = a.ok_or_else(|| EngineError::Other("missing analysis".into()))?;
        let rec = ProvenanceRecord {
            format: 1,
            seq: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id: job_id.into(),
            package: pkg.into(),
            version_code: Some(a.manifest.version_code),
            artifact_sha256: a.sha256.to_hex(),
            artifact_sha1: a.sha1.to_hex(),
            size: a.file_size,
            file_name: v.file_name.clone().unwrap_or_default(),
            origin: v.origin.clone().unwrap_or_else(|| "original".into()),
            kind: serde_json::to_value(&a.classification).unwrap_or_default(),
            provider: v.provider.clone(),
            channel: v.channel.clone().unwrap_or_default(),
            device_profile: v.device_profile.clone(),
            source: v.source.clone().unwrap_or_default(),
            derived_from: v.derived_from.clone(),
            tool: if v.origin.as_deref() == Some("generated_from_aab") { v.source.clone() } else { None },
            verification: serde_json::json!({
                "signature_verified": a.signature.verified,
                "schemes": a.signature.schemes_verified,
                "signers": a.signature.signers.iter().map(|c| c.sha256.to_hex()).collect::<Vec<_>>(),
                "lineage": a.signature.lineage.iter().map(|c| c.sha256.to_hex()).collect::<Vec<_>>(),
                "checks": v.checks,
            }),
            prev_hash: String::new(),
        };
        let row = self.ledger.append(rec).await.map_err(EngineError::Other)?;
        Ok(row.seq)
    }
}

/// Chooses what to download. Returns (ordered alternatives for the preferred result, extras).
pub fn plan(offers: &[Offer], opts: &JobOptions) -> (Vec<Vec<usize>>, Vec<usize>) {
    let universal: Vec<usize> = offers.iter().enumerate().filter(|(_, o)| o.layout == OfferLayout::UniversalApk).map(|(i, _)| i).collect();
    let bundles: Vec<usize> = offers.iter().enumerate().filter(|(_, o)| o.layout == OfferLayout::AppBundle).map(|(i, _)| i).collect();
    let variants: Vec<usize> = offers.iter().enumerate().filter(|(_, o)| matches!(o.layout, OfferLayout::SplitSet | OfferLayout::AbiSpecificApk)).map(|(i, _)| i).collect();
    let rest = |chosen: &[usize]| -> Vec<usize> { (0..offers.len()).filter(|i| !chosen.contains(i)).collect() };
    if !universal.is_empty() {
        let alts = universal.iter().map(|i| vec![*i]).collect::<Vec<_>>();
        let extras = if opts.all_variants { rest(&universal[..1]) } else { vec![] };
        (alts, extras)
    } else if !bundles.is_empty() {
        let alts = bundles.iter().map(|i| vec![*i]).collect::<Vec<_>>();
        let extras = if opts.all_variants { rest(&bundles[..1]) } else { vec![] };
        (alts, extras)
    } else {
        (vec![variants], vec![])
    }
}

fn count(r: &JobReport) -> Counts {
    let mut c = Counts::default();
    for v in &r.variants {
        match v.availability {
            Availability::Known => c.known += 1,
            Availability::Identified => c.identified += 1,
            Availability::Retrieved => c.retrieved += 1,
            Availability::Failed => c.failed += 1,
        }
    }
    c
}

fn decide_outcome(r: &JobReport) -> (&'static str, String) {
    let ok = |v: &&VariantEntry| v.availability == Availability::Retrieved;
    if r.variants.iter().filter(ok).any(|v| v.origin.as_deref() == Some("original") && v.kind == Some(VariantKind::UniversalApk)) {
        return ("universal_original", "Original universal APK retrieved and verified.".into());
    }
    if r.variants.iter().filter(ok).any(|v| v.kind == Some(VariantKind::GeneratedUniversalApk)) {
        return ("universal_generated", "Universal APK generated from the app bundle with bundletool (signed with the local build key, not an original).".into());
    }
    let installable: Vec<&SplitSetEntry> = r
        .split_sets
        .iter()
        .filter(|s| s.report.installable && s.members.iter().all(|m| r.variants.iter().any(|v| v.id == *m && v.availability == Availability::Retrieved)))
        .collect();
    if !installable.is_empty() {
        return ("split_set", format!("No universal APK available; {} verified, installable split APK set(s) retrieved.", installable.len()));
    }
    let n = r.variants.iter().filter(ok).count();
    if n > 0 {
        return ("variants", format!("No universal APK available; {n} verified variant file(s) retrieved."));
    }
    ("none", "Nothing could be retrieved and verified.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uad_core::{PackageName, RemoteFile};

    fn offer(provider: &str, layout: OfferLayout) -> Offer {
        Offer {
            provider: provider.into(),
            package: PackageName::new("com.a.b").unwrap(),
            version_code: 1,
            version_name: None,
            layout,
            files: vec![RemoteFile {
                role: FileRole::Standalone,
                file_name: "a.apk".into(),
                source: uad_core::FileSource::Local { path: "/x".into() },
                size: None,
                expected: Default::default(),
            }],
            abis: vec![],
            min_sdk: None,
            trust: None,
            device_profile: None,
            channel: String::new(),
        }
    }

    #[test]
    fn planning_prefers_universal_then_bundle_then_variants() {
        let o = vec![offer("play", OfferLayout::SplitSet), offer("fdroid", OfferLayout::UniversalApk), offer("local", OfferLayout::AppBundle)];
        let (alts, extras) = plan(&o, &JobOptions::default());
        assert_eq!(alts, vec![vec![1]]);
        assert!(extras.is_empty());
        let (_, extras) = plan(&o, &JobOptions { all_variants: true, ..Default::default() });
        assert_eq!(extras, vec![0, 2]);
        let o2 = vec![offer("play", OfferLayout::SplitSet), offer("local", OfferLayout::AppBundle)];
        assert_eq!(plan(&o2, &JobOptions::default()).0, vec![vec![1]]);
        let o3 = vec![offer("play", OfferLayout::SplitSet), offer("play", OfferLayout::SplitSet), offer("fdroid", OfferLayout::AbiSpecificApk)];
        assert_eq!(plan(&o3, &JobOptions::default()).0, vec![vec![0, 1, 2]]);
    }
}
