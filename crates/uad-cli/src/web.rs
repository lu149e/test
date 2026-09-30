//! HTTP API and embedded web UI.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use uad_core::JobOptions;
use uad_engine::{Engine, EngineError};

const INDEX: &str = include_str!("../static/index.html");
const MAX_UPLOAD: usize = 2 * 1024 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub api_token: Option<String>,
}

pub struct ApiError(StatusCode, String);

impl From<EngineError> for ApiError {
    fn from(e: EngineError) -> Self {
        let code = match &e {
            EngineError::Input(_) => StatusCode::BAD_REQUEST,
            EngineError::NotFound(_) => StatusCode::NOT_FOUND,
            EngineError::Conflict(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(code, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/providers", get(providers))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/retry", post(retry_job))
        .route("/jobs/{id}/cancel", post(cancel_job))
        .route("/jobs/{id}/sets/{idx}/apks", get(download_set))
        .route("/artifacts/{sha}", get(download_artifact))
        .route("/artifacts/{sha}/provenance", get(artifact_provenance))
        .route("/provenance/verify", get(verify_provenance))
        .route("/upload", post(upload).layer(DefaultBodyLimit::max(MAX_UPLOAD)))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/health", get(health))
        .nest("/api", api)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
    );
    r
}

/// Constant-time comparison of the bearer token.
fn token_ok(expected: &str, got: &str) -> bool {
    let (a, b) = (expected.as_bytes(), got.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = &st.api_token {
        let got = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_string)
            .or_else(|| {
                req.uri()
                    .query()
                    .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=").map(str::to_string)))
            });
        if !got.is_some_and(|g| token_ok(expected, &g)) {
            return ApiError(StatusCode::UNAUTHORIZED, "missing or invalid API token".into()).into_response();
        }
    }
    next.run(req).await
}

async fn health(State(st): State<AppState>) -> impl IntoResponse {
    let (jobs, artifacts, bytes) = st.engine.store.stats().unwrap_or((0, 0, 0));
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "jobs": jobs, "artifacts": artifacts, "stored_bytes": bytes,
        "auth_required": st.api_token.is_some(),
    }))
}

async fn providers(State(st): State<AppState>) -> impl IntoResponse {
    Json(st.engine.providers_info())
}

#[derive(Deserialize)]
struct CreateJob {
    input: String,
    #[serde(default)]
    options: Option<JobOptions>,
}

async fn create_job(State(st): State<AppState>, Json(body): Json<CreateJob>) -> ApiResult<impl IntoResponse> {
    let id = st.engine.submit(&body.input, body.options.unwrap_or_default())?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({"id": id}))))
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    package: Option<String>,
}

async fn list_jobs(State(st): State<AppState>, Query(q): Query<ListQuery>) -> ApiResult<impl IntoResponse> {
    let jobs = st.engine.jobs(q.limit.unwrap_or(50).min(500), q.package.as_deref())?;
    let slim: Vec<serde_json::Value> = jobs
        .into_iter()
        .map(|j| {
            let outcome = j.report.as_ref().and_then(|r| r.get("outcome").cloned());
            let title = j.report.as_ref().and_then(|r| r.pointer("/metadata/title").cloned());
            serde_json::json!({"id": j.id, "input": j.input, "package": j.package, "state": j.state, "error": j.error,
                "created_at": j.created_at, "updated_at": j.updated_at, "outcome": outcome, "title": title})
        })
        .collect();
    Ok(Json(slim))
}

async fn get_job(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.engine.job(&id)?))
}

async fn retry_job(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    st.engine.retry(&id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn cancel_job(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    st.engine.cancel(&id)?;
    Ok(StatusCode::ACCEPTED)
}

fn safe_name(n: &str) -> String {
    let s: String = n
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-+".contains(c) { c } else { '_' })
        .collect();
    if s.is_empty() {
        "download".into()
    } else {
        s
    }
}

async fn send_file(path: std::path::PathBuf, name: &str, content_type: &'static str) -> ApiResult<Response> {
    let f = tokio::fs::File::open(&path)
        .await
        .map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    let len = f.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(f));
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, len)
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", safe_name(name)))
        .body(body)
        .unwrap())
}

async fn download_artifact(State(st): State<AppState>, Path(sha): Path<String>) -> ApiResult<Response> {
    let (path, name) = st.engine.verified_artifact(&sha)?;
    let ct = if name.ends_with(".apk") {
        "application/vnd.android.package-archive"
    } else {
        "application/octet-stream"
    };
    send_file(path, &name, ct).await
}

async fn download_set(State(st): State<AppState>, Path((id, idx)): Path<(String, usize)>) -> ApiResult<Response> {
    let (path, name) = st.engine.export_split_set(&id, idx).await?;
    send_file(path, &name, "application/zip").await
}

async fn artifact_provenance(State(st): State<AppState>, Path(sha): Path<String>) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        serde_json::json!({"public_key": st.engine.ledger.public_key_hex(), "records": st.engine.provenance(&sha)?}),
    ))
}

async fn verify_provenance(State(st): State<AppState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(st.engine.ledger.verify_chain().map_err(EngineError::Other)?))
}

async fn upload(State(st): State<AppState>, mut mp: Multipart) -> ApiResult<impl IntoResponse> {
    while let Some(mut field) = mp.next_field().await.map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))? {
        if field.name() != Some("file") {
            continue;
        }
        let name = field.file_name().unwrap_or("upload.apk").to_string();
        let tmp = st.engine.cfg.tmp_dir().join(format!("upload-{}", uuid::Uuid::new_v4()));
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let mut total = 0usize;
        while let Some(chunk) = field.chunk().await.map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))? {
            total += chunk.len();
            if total > MAX_UPLOAD {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "file too large".into()));
            }
            f.write_all(&chunk)
                .await
                .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        f.flush().await.ok();
        drop(f);
        let package = match st.engine.import_file(&tmp, &name).await {
            Ok(p) => p,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e.into());
            }
        };
        let opts = JobOptions {
            providers: vec!["local".into()],
            ..Default::default()
        };
        let id = st.engine.submit(&package, opts)?;
        return Ok((StatusCode::ACCEPTED, Json(serde_json::json!({"id": id, "package": package}))));
    }
    Err(ApiError(StatusCode::BAD_REQUEST, "multipart field 'file' missing".into()))
}
