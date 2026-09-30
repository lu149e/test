//! Starts the real `uad serve` binary and drives it over HTTP (offline: local import only).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../uad-apk/tests/fixtures").join(p)
}

async fn wait_terminal(c: &reqwest::Client, base: &str, id: &str) -> serde_json::Value {
    for _ in 0..200 {
        let j: serde_json::Value = c.get(format!("{base}/api/jobs/{id}")).send().await.unwrap().json().await.unwrap();
        if ["completed", "partially_completed", "failed", "cancelled"].contains(&j["state"].as_str().unwrap()) {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job did not finish");
}

#[tokio::test]
async fn serve_upload_verify_download() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("uad.toml");
    std::fs::write(
        &cfg,
        format!(
            "data_dir = {:?}\n[providers]\nplay_web = false\n[providers.fdroid]\nenabled = false\n[bundletool]\nenabled = false\n",
            dir.path().join("data")
        ),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_uad"))
            .args(["--config", cfg.to_str().unwrap(), "serve", "--listen", &format!("127.0.0.1:{port}")])
            .env("UAD_API_TOKEN", "test-token")
            .env("NO_PROXY", "127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let anon = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..100 {
        if anon.get(format!("{base}/api/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ui = anon.get(format!("{base}/")).send().await.unwrap();
    assert!(ui.headers().get("content-security-policy").is_some());
    assert!(ui.text().await.unwrap().contains("Universal APK Downloader"));
    assert_eq!(anon.get(format!("{base}/api/jobs")).send().await.unwrap().status(), 401);

    let mut h = reqwest::header::HeaderMap::new();
    h.insert("authorization", "Bearer test-token".parse().unwrap());
    let c = reqwest::Client::builder().no_proxy().default_headers(h).build().unwrap();

    // Invalid input is rejected synchronously.
    let r = c
        .post(format!("{base}/api/jobs"))
        .json(&serde_json::json!({"input": "https://evil.example/x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Upload an APK: it is imported, a job is created and verified.
    let bytes = std::fs::read(fixture("rsa_v1v2v3.apk")).unwrap();
    let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(bytes.clone()).file_name("fixture.apk"));
    let r: serde_json::Value = c
        .post(format!("{base}/api/upload"))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["package"], "com.uad.fixture");
    let job = wait_terminal(&c, &base, r["id"].as_str().unwrap()).await;
    assert_eq!(job["state"], "completed", "{job:#}");
    assert_eq!(job["report"]["outcome"], "universal_original");
    let sha = job["report"]["variants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["availability"] == "retrieved")
        .unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_string();

    let file = c.get(format!("{base}/api/artifacts/{sha}")).send().await.unwrap();
    assert_eq!(file.status(), 200);
    assert!(file.headers()["content-disposition"].to_str().unwrap().contains(".apk"));
    assert_eq!(file.bytes().await.unwrap().to_vec(), bytes, "served bytes are the original bytes");
    // Query-token form used by browser links.
    assert_eq!(
        anon.get(format!("{base}/api/artifacts/{sha}?token=test-token"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        c.get(format!("{base}/api/artifacts/{}", "0".repeat(64))).send().await.unwrap().status(),
        404
    );

    let prov: serde_json::Value = c
        .get(format!("{base}/api/artifacts/{sha}/provenance"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prov["records"][0]["record"]["origin"], "original");
    let chain: serde_json::Value = c.get(format!("{base}/api/provenance/verify")).send().await.unwrap().json().await.unwrap();
    assert_eq!(chain["valid"], true);

    // Uploading something that is not an APK fails cleanly.
    let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("x.apk"));
    assert_eq!(c.post(format!("{base}/api/upload")).multipart(form).send().await.unwrap().status(), 400);
    let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("x.exe"));
    assert_eq!(c.post(format!("{base}/api/upload")).multipart(form).send().await.unwrap().status(), 400);
}

#[test]
fn refuses_public_bind_without_token() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_uad"))
        .args(["--data-dir", dir.path().to_str().unwrap(), "serve", "--listen", "0.0.0.0:0"])
        .env_remove("UAD_API_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("API token"));
}

#[test]
fn analyze_command_reports_tampering() {
    let ok = Command::new(env!("CARGO_BIN_EXE_uad"))
        .args(["analyze", fixture("rsa_v1v2v3.apk").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ok.status.success());
    assert!(String::from_utf8_lossy(&ok.stdout).contains("VERIFIED"));
    let bad = Command::new(env!("CARGO_BIN_EXE_uad"))
        .args(["analyze", fixture("tampered_content.apk").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&bad.stdout).contains("NOT VERIFIED"));
}
