//! `uad` — Universal APK Downloader.

mod web;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uad_core::{Abi, Availability, JobOptions, SecretStore};
use uad_engine::{Config, Engine, JobReport};

#[derive(Parser)]
#[command(name = "uad", version, about = "Acquire, verify and store Android apps from their Google Play link")]
struct Cli {
    /// Configuration file (TOML).
    #[arg(long, global = true, env = "UAD_CONFIG")]
    config: Option<PathBuf>,
    /// Override the data directory.
    #[arg(long, global = true, env = "UAD_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the web UI and HTTP API with background workers.
    Serve {
        #[arg(long)]
        listen: Option<String>,
    },
    /// Acquire an app now (Play URL, market:// URI or package name) and export verified files.
    Get(GetArgs),
    /// Analyse and verify a local APK or AAB (offline).
    Analyze {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Check that a set of split APKs is consistent and installable together.
    VerifySet { files: Vec<PathBuf> },
    /// Copy an APK/AAB/APKS into the local inbox.
    Import { file: PathBuf },
    /// List recent jobs.
    Jobs {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Show a job report as JSON.
    Job { id: String },
    /// Show providers and their status.
    Providers,
    /// Store a Google account for the Play provider (exchanges a one-time oauth_token).
    PlayLogin {
        #[arg(long)]
        email: String,
        /// oauth_token cookie from https://accounts.google.com/EmbeddedSetup; prompted if omitted.
        #[arg(long)]
        oauth_token: Option<String>,
    },
    /// Manage encrypted secrets.
    #[command(subcommand)]
    Secrets(SecretsCmd),
    /// Provenance ledger operations.
    #[command(subcommand)]
    Provenance(ProvCmd),
    /// Print the effective configuration.
    Config,
}

#[derive(Args)]
struct GetArgs {
    input: String,
    #[arg(long)]
    version_code: Option<i64>,
    /// Also download every variant, not only the preferred result.
    #[arg(long)]
    all_variants: bool,
    /// Restrict to these providers (repeatable): play_dev, play, fdroid, local, emulator.
    #[arg(long = "provider")]
    providers: Vec<String>,
    /// Restrict ABI-specific variants (repeatable): arm64-v8a, armeabi-v7a, x86, x86_64.
    #[arg(long = "abi")]
    abis: Vec<String>,
    /// Do not build a universal APK from app bundles.
    #[arg(long)]
    no_bundletool: bool,
    /// Directory where verified files are copied.
    #[arg(long, short)]
    out: Option<PathBuf>,
    /// Print the full JSON report.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Set a secret from a file or from stdin (never from the command line).
    Set {
        key: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    List,
    Delete {
        key: String,
    },
}

#[derive(Subcommand)]
enum ProvCmd {
    /// Verify the whole hash chain and signatures.
    Verify,
    /// Show provenance records of an artifact.
    Show { sha256: String },
}

fn load_config(cli: &Cli) -> Result<Config> {
    let mut cfg = Config::load(cli.config.as_deref()).map_err(|e| anyhow!(e))?;
    if let Some(d) = &cli.data_dir {
        cfg.data_dir = d.clone();
    }
    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Analyze { file, json } => return analyze(file, *json),
        Cmd::VerifySet { files } => return verify_set(files),
        _ => {}
    }
    let cfg = load_config(&cli)?;
    match cli.cmd {
        Cmd::Serve { listen } => serve(cfg, listen).await,
        Cmd::Get(a) => get(cfg, a).await,
        Cmd::Import { file } => {
            let engine = Engine::open(cfg)?;
            let tmp = engine.cfg.tmp_dir().join(format!("import-{}", uuid::Uuid::new_v4()));
            std::fs::copy(&file, &tmp).with_context(|| file.display().to_string())?;
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("file.apk");
            let pkg = engine.import_file(&tmp, name).await?;
            println!("imported {} for package {pkg}; run: uad get {pkg} --provider local", file.display());
            Ok(())
        }
        Cmd::Jobs { limit } => {
            let engine = Engine::open(cfg)?;
            for j in engine.jobs(limit, None)? {
                let outcome = j
                    .report
                    .as_ref()
                    .and_then(|r| r.get("outcome"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_string();
                println!(
                    "{}  {:<20} {:<22} {:<40} {}",
                    j.id,
                    j.state,
                    outcome,
                    j.package.unwrap_or_default(),
                    j.created_at
                );
            }
            Ok(())
        }
        Cmd::Job { id } => {
            let engine = Engine::open(cfg)?;
            println!("{}", serde_json::to_string_pretty(&engine.job(&id)?)?);
            Ok(())
        }
        Cmd::Providers => {
            let engine = Engine::open(cfg)?;
            for p in engine.providers_info() {
                println!(
                    "{:<10} {:<8} prio {:>2}  {:?}\n           {}\n           {}",
                    p.id,
                    if p.enabled { "enabled" } else { "disabled" },
                    p.priority,
                    p.kind,
                    p.description,
                    p.status
                );
            }
            Ok(())
        }
        Cmd::PlayLogin { email, oauth_token } => {
            let engine = Engine::open(cfg)?;
            let token = match oauth_token {
                Some(t) => t,
                None => rpassword::prompt_password("oauth_token: ")?,
            };
            engine.play().setup_account(&email, token.trim()).await.map_err(|e| anyhow!("{e}"))?;
            println!("Google account stored (encrypted). Enable [providers.play] in the configuration to use it.");
            Ok(())
        }
        Cmd::Secrets(s) => {
            let engine = Engine::open(cfg)?;
            match s {
                SecretsCmd::Set { key, file } => {
                    let value = match file {
                        Some(f) => std::fs::read_to_string(&f).with_context(|| f.display().to_string())?,
                        None => rpassword::prompt_password(format!("{key}: "))?,
                    };
                    engine.secrets.put(&key, value.trim_end_matches(['\n', '\r'])).map_err(|e| anyhow!(e))?;
                    println!("stored {key}");
                }
                SecretsCmd::List => {
                    for k in engine.secrets.keys() {
                        println!("{k}");
                    }
                    println!("(key source: {:?})", engine.secrets.key_source);
                }
                SecretsCmd::Delete { key } => {
                    engine.secrets.delete(&key).map_err(|e| anyhow!(e))?;
                    println!("deleted {key}");
                }
            }
            Ok(())
        }
        Cmd::Provenance(p) => {
            let engine = Engine::open(cfg)?;
            match p {
                ProvCmd::Verify => {
                    let r = engine.ledger.verify_chain().map_err(|e| anyhow!(e))?;
                    println!("{}", serde_json::to_string_pretty(&r)?);
                    if !r.valid {
                        bail!("provenance chain is NOT valid");
                    }
                }
                ProvCmd::Show { sha256 } => println!("{}", serde_json::to_string_pretty(&engine.provenance(&sha256)?)?),
            }
            Ok(())
        }
        Cmd::Config => {
            println!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
            Ok(())
        }
        Cmd::Analyze { .. } | Cmd::VerifySet { .. } => unreachable!(),
    }
}

async fn serve(cfg: Config, listen: Option<String>) -> Result<()> {
    let addr = listen.unwrap_or_else(|| cfg.listen.clone());
    let token_env = cfg.api_token_env.clone().unwrap_or_else(|| "UAD_API_TOKEN".into());
    let api_token = std::env::var(&token_env).ok().filter(|t| !t.is_empty());
    let engine = Engine::open(cfg)?;
    engine.start().await?;
    let is_loopback = addr.starts_with("127.") || addr.starts_with("localhost") || addr.starts_with("[::1]");
    if api_token.is_none() && !is_loopback {
        bail!("refusing to listen on {addr} without an API token: set {token_env}");
    }
    let app = web::router(web::AppState { engine, api_token });
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| addr.clone())?;
    tracing::info!("listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn print_summary(r: &JobReport, state: &str) {
    println!("\n== {} ({})", r.package.clone().unwrap_or_default(), state);
    if let Some(m) = &r.metadata {
        println!("   {} — {}", m.title.clone().unwrap_or_default(), m.developer.clone().unwrap_or_default());
    }
    println!("   outcome: {} — {}", r.outcome, r.outcome_description);
    println!(
        "   variants: {} known, {} identified, {} retrieved, {} failed",
        r.counts.known, r.counts.identified, r.counts.retrieved, r.counts.failed
    );
    for p in &r.providers {
        println!("   provider {:<9} {:<15} {}", p.id, p.status, p.message.clone().unwrap_or_default());
    }
    for v in r.variants.iter().filter(|v| v.sha256.is_some()) {
        println!(
            "   [{}] {} {} {}\n        sha256 {}",
            v.availability.as_str(),
            v.file_name.clone().unwrap_or_default(),
            v.kind.as_ref().map(|k| format!("{k:?}")).unwrap_or_default(),
            v.error.clone().unwrap_or_default(),
            v.sha256.clone().unwrap_or_default()
        );
        for c in &v.checks {
            println!("        {:<16} {:?}: {}", c.name, c.status, c.detail);
        }
    }
    for s in &r.split_sets {
        println!(
            "   split set {}: installable={} abis={:?} densities={:?} languages={:?}",
            s.label, s.report.installable, s.report.abis, s.report.densities, s.report.languages
        );
    }
}

async fn get(cfg: Config, a: GetArgs) -> Result<()> {
    let abis = a
        .abis
        .iter()
        .map(|s| Abi::parse(s).ok_or_else(|| anyhow!("unknown ABI {s}")))
        .collect::<Result<Vec<_>>>()?;
    let opts = JobOptions {
        version_code: a.version_code,
        providers: a.providers,
        abis,
        all_variants: a.all_variants,
        build_universal_from_aab: !a.no_bundletool,
    };
    let engine: Arc<Engine> = Engine::open(cfg)?;
    let id = engine.create_job(&a.input, opts)?;
    eprintln!("job {id}");
    engine.run_job(&id).await;
    let view = engine.job(&id)?;
    let report = engine.report(&id)?.unwrap_or_default();
    if a.json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        print_summary(&report, view.job.state.as_str());
        if let Some(e) = &view.job.error {
            println!("   error: {e}");
        }
    }
    if let Some(out) = a.out {
        std::fs::create_dir_all(&out)?;
        for v in report.variants.iter().filter(|v| v.availability == Availability::Retrieved) {
            let (path, name) = engine.verified_artifact(v.sha256.as_deref().unwrap_or_default())?;
            let dest = out.join(&name);
            std::fs::copy(&path, &dest)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644));
            }
            println!("   wrote {}", dest.display());
        }
        for (i, s) in report.split_sets.iter().enumerate() {
            if s.report.installable {
                if let Ok((path, name)) = engine.export_split_set(&id, i).await {
                    let dest = out.join(name);
                    std::fs::copy(path, &dest)?;
                    println!("   wrote {}", dest.display());
                }
            }
        }
    }
    if view.job.state.as_str() == "failed" {
        std::process::exit(2);
    }
    Ok(())
}

fn analyze(file: &Path, json: bool) -> Result<()> {
    let a = uad_apk::analyze(file).map_err(|e| anyhow!("{e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&a)?);
        return Ok(());
    }
    let m = &a.manifest;
    println!("{} ({:?})", file.display(), a.container);
    println!(
        "  package        {} versionCode {} versionName {}",
        m.package,
        m.version_code,
        m.version_name.clone().unwrap_or_default()
    );
    println!("  sdk            min {:?} target {:?}", m.min_sdk, m.target_sdk);
    println!("  classification {:?}", a.classification);
    println!("  native ABIs    {:?}", a.native_abis.iter().map(|x| x.as_str()).collect::<Vec<_>>());
    if let Some(s) = &m.split {
        println!("  split          {s}");
    }
    if !m.required_split_types.is_empty() {
        println!("  requires       {:?}", m.required_split_types);
    }
    println!("  sha256         {}", a.sha256);
    println!(
        "  signature      {} (schemes: {})",
        if a.signature.verified { "VERIFIED" } else { "NOT VERIFIED" },
        a.signature.schemes_verified.join(", ")
    );
    for c in &a.signature.signers {
        println!(
            "  signer         {}  {}  {} {}",
            c.sha256,
            c.subject,
            c.public_key_algorithm,
            c.public_key_bits.map(|b| b.to_string()).unwrap_or_default()
        );
    }
    for c in &a.signature.lineage {
        println!("  lineage        {}  {}", c.sha256, c.subject);
    }
    for e in &a.signature.errors {
        println!("  ERROR          {e}");
    }
    for w in a.signature.warnings.iter().chain(a.warnings.iter()) {
        println!("  warning        {w}");
    }
    println!("  note           a valid signature proves integrity and signer identity, not safety or Play origin");
    if !a.signature.verified {
        std::process::exit(3);
    }
    Ok(())
}

fn verify_set(files: &[PathBuf]) -> Result<()> {
    let analyses: Vec<(String, uad_apk::ApkAnalysis)> = files
        .iter()
        .map(|f| Ok((f.display().to_string(), uad_apk::analyze(f).map_err(|e| anyhow!("{}: {e}", f.display()))?)))
        .collect::<Result<_>>()?;
    let refs: Vec<(String, &uad_apk::ApkAnalysis)> = analyses.iter().map(|(n, a)| (n.clone(), a)).collect();
    let r = uad_apk::validate_split_set(&refs);
    println!("{}", serde_json::to_string_pretty(&r)?);
    if !r.installable {
        std::process::exit(3);
    }
    Ok(())
}
