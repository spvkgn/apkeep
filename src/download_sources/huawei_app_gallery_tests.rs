use super::apk_validation::tests::base_apk as fixture;
use super::*;

#[tokio::test]
async fn direct_artifact_truncation_and_invalid_chunk_encoding_report_integrity() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\nZZ\r\n".as_slice(),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private?token=PRIVATE_TOKEN", listener.local_addr().unwrap());
        let artifact = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            assert!(socket.read(&mut buf).await.unwrap() > 0);
            socket.write_all(response).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let server = Server::new(|_| vec![api_reply(&url)]).await;
        let out = tempfile::tempdir().unwrap();
        let report = results::Report::new("huawei-app-gallery", "download", vec![("com.example.app".into(), None)]).unwrap();
        let (ok, mut report) = results::collect(report, injected_download_batch(&test_client(), &server.endpoint,
            vec![("com.example.app".into(), None)], 1, 0, out.path(), "IE")).await;
        artifact.await.unwrap();
        report.finish(ok);
        let bytes = report.json_bytes().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!ok);
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0, "partial or published APK left behind");
        assert_eq!(value["success"], false);
        assert_eq!(value["results"][0]["status"], "error");
        assert_eq!(value["results"][0]["reason"], "integrity");
        assert!(!String::from_utf8(bytes).unwrap().contains("PRIVATE_TOKEN"));
    }
}

#[tokio::test]
async fn direct_request_metadata_and_artifact_failures_keep_typed_distinctions() {
    for metadata in [false, true] {
        for (mode, expected) in [
            ("401", "authentication"),
            ("403", "authentication"),
            ("503", "transport"),
            ("timeout", "timeout"),
            ("malformed", "integrity"),
            ("short", "integrity"),
        ] {
            let server = Server::new(|base| {
                let reply = Reply {
                    status: mode.parse().unwrap_or(200),
                    length: (mode == "short").then_some(100),
                    delay: if mode == "timeout" {
                        Duration::from_secs(2)
                    } else {
                        Duration::ZERO
                    },
                    ..Reply::ok(b"x")
                };
                if metadata {
                    vec![reply]
                } else {
                    vec![
                        api_reply(&format!("{base}/private?token=PRIVATE_TOKEN")),
                        reply,
                    ]
                }
            })
            .await;
            let out = tempfile::tempdir().unwrap();
            let client = test_client();
            let (ok, report) = results::collect(
                results::Report::new(
                    "huawei-app-gallery",
                    "download",
                    vec![("com.example.app".into(), None)],
                )
                .unwrap(),
                injected_download_batch(
                    &client,
                    &server.endpoint,
                    vec![("com.example.app".into(), None)],
                    1,
                    0,
                    out.path(),
                    "IE",
                ),
            )
            .await;
            assert!(!ok);
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
            let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
            assert_eq!(value["results"][0]["status"], "error");
            assert_eq!(value["results"][0]["reason"], expected, "{metadata}/{mode}");
        }
    }
}

#[tokio::test]
async fn refused_connection_stays_transport_without_partial_output() {
    for metadata in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/private?token=PRIVATE_TOKEN",
            listener.local_addr().unwrap()
        );
        drop(listener);
        let server = Server::new(|_| vec![api_reply(&url)]).await;
        let out = tempfile::tempdir().unwrap();
        let (ok, report) = results::collect(
            results::Report::new(
                "huawei-app-gallery",
                "download",
                vec![("com.example.app".into(), None)],
            )
            .unwrap(),
            injected_download_batch(
                &test_client(),
                if metadata { &url } else { &server.endpoint },
                vec![("com.example.app".into(), None)],
                1,
                0,
                out.path(),
                "IE",
            ),
        )
        .await;
        assert!(!ok);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
        assert_eq!(value["results"][0]["reason"], "transport");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ancestor_swap_during_huawei_transfer_pins_publication_and_cleanup() {
    let server = Server::new(|base| {
        vec![
            api_reply(&format!("{base}/full.apk")),
            Reply {
                body_delay: Duration::from_millis(100),
                ..Reply::ok(fixture())
            },
        ]
    })
    .await;
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("out");
    let moved = root.path().join("moved");
    let victim = root.path().join("victim");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&victim).unwrap();
    let client = test_client();
    let (result, ()) = tokio::join!(
        injected_download_one(
            &client,
            &server.endpoint,
            "com.example.app",
            None,
            "CN",
            &original
        ),
        async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while std::fs::read_dir(&original).unwrap().count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            std::fs::rename(&original, &moved).unwrap();
            std::os::unix::fs::symlink(&victim, &original).unwrap();
        }
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(moved.join("com.example.app.apk")).unwrap(),
        fixture()
    );
}

#[tokio::test]
async fn matching_api_hash_does_not_publish_non_apk_bytes() {
    use sha2::{Digest, Sha256};
    let bytes = b"not a ZIP APK".to_vec();
    let server = Server::new(|base| {
        let mut item = entry(&format!("{base}/artifact"));
        item["size"] = json!(bytes.len());
        item["fullSize"] = json!(bytes.len());
        item["sha256"] = json!(hex::encode(Sha256::digest(&bytes)));
        vec![
            Reply::ok(serde_json::to_vec(&json!({"rtnCode":0,"list":[item]})).unwrap()),
            Reply::ok(bytes),
        ]
    })
    .await;
    let out = tempfile::tempdir().unwrap();
    let result = injected_download_one(
        &test_client(),
        &server.endpoint,
        "com.example.app",
        None,
        "IE",
        out.path(),
    )
    .await;
    assert!(
        result.is_err(),
        "matching API metadata must not certify non-APK bytes"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn api_apk_size_above_absolute_cap_is_rejected_before_artifact_request() {
    let server = Server::new(|base| {
        let mut item = entry(&format!("{base}/artifact"));
        item["size"] = json!(2u64 * 1024 * 1024 * 1024 + 1);
        item["fullSize"] = item["size"].clone();
        vec![
            Reply::ok(serde_json::to_vec(&json!({"rtnCode":0,"list":[item]})).unwrap()),
            Reply::ok(fixture()),
        ]
    })
    .await;
    let out = tempfile::tempdir().unwrap();
    let error = injected_download_one(
        &test_client(),
        &server.endpoint,
        "com.example.app",
        None,
        "IE",
        out.path(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, "APK size exceeds 2 GiB limit");
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn production_url_checks_reject_private_metadata_and_artifact_before_connecting() {
    for artifact in [
        "http://127.0.0.1/private",
        "http://169.254.169.254/private",
        "http://[::1]/private",
        "http://user:PRIVATE_TOKEN@example.com/private",
    ] {
        let server = Server::new(|_| vec![api_reply(artifact)]).await;
        let endpoint = reqwest::Url::parse(&server.endpoint).unwrap();
        let addr =
            std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), endpoint.port().unwrap());
        let client = reqwest::Client::builder()
            .no_proxy()
            .resolve("public.fixture", addr)
            .build()
            .unwrap();
        let public_endpoint = server.endpoint.replace("127.0.0.1", "public.fixture");
        let out = tempfile::tempdir().unwrap();
        let error = download_one(
            &client,
            &public_endpoint,
            "com.example.app",
            None,
            "IE",
            out.path(),
            true,
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("public HTTP(S)") || error.contains("invalid APK URL"),
            "{error}"
        );
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        let error = download_one(
            &client,
            &server.endpoint,
            "com.example.app",
            None,
            "IE",
            out.path(),
            true,
        )
        .await
        .unwrap_err();
        assert!(error.contains("API endpoint is not public"));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

async fn injected_download_one(
    client: &reqwest::Client,
    endpoint: &str,
    package: &str,
    version: Option<&str>,
    region: &str,
    out: &std::path::Path,
) -> Result<(), String> {
    download_one(client, endpoint, package, version, region, out, false).await
}
async fn injected_download_batch(
    client: &reqwest::Client,
    endpoint: &str,
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep: u64,
    out: &std::path::Path,
    region: &str,
) -> bool {
    download_batch(
        BatchTransport {
            client,
            public_only: false,
        },
        endpoint,
        apps,
        parallel,
        sleep,
        out,
        region,
    )
    .await
}

#[tokio::test]
async fn production_client_denies_loopback_dns_before_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://localhost:{}/private?token=PRIVATE_TOKEN",
        listener.local_addr().unwrap().port()
    );
    let client = http_client_builder()
        .timeout(Duration::from_millis(80))
        .build()
        .unwrap();
    let _ = client
        .get(url)
        .timeout(Duration::from_millis(80))
        .send()
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "production client connected to loopback"
    );
}

use serde_json::{json, Value};
use std::collections::HashMap;

#[test]
fn form_round_trips_package_and_region_without_injection() {
    for (options, expected) in [(None, "IE"), (Some("region=cn"), "CN")] {
        let region = region(options).unwrap();
        let package = "com.example.\"&serviceCountry=RU+%";
        let encoded = client_api_body(package, &region);
        let parsed = reqwest::Url::parse(&format!("http://localhost/?{encoded}")).unwrap();
        let pairs: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("serviceCountry").map(String::as_str),
            Some(expected)
        );
        let info: serde_json::Value = serde_json::from_str(&pairs["pkgInfo"]).unwrap();
        assert_eq!(info["params"][0]["package"], package);
        assert_eq!(pairs["version"], "12.0.1.301");
        assert_eq!(pairs["firmwareVersion"], "10");
        assert_eq!(pairs["phoneType"], "Pixel 2");
    }
}

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Reply {
    status: u16,
    body: Vec<u8>,
    length: Option<usize>,
    delay: Duration,
    body_delay: Duration,
    headers: String,
}

impl Reply {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            length: None,
            delay: Duration::ZERO,
            body_delay: Duration::ZERO,
            headers: String::new(),
        }
    }
}

struct Server {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn new(replies: impl FnOnce(&str) -> Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let replies = replies(&endpoint);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]);
                        let length: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|s| s.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                tokio::time::sleep(reply.delay).await;
                let head = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.length.unwrap_or(reply.body.len()),
                    reply.headers
                );
                let _ = socket.write_all(head.as_bytes()).await;
                if !reply.body.is_empty() && !reply.body_delay.is_zero() {
                    let _ = socket.write_all(&reply.body[..1]).await;
                    tokio::time::sleep(reply.body_delay).await;
                    let _ = socket.write_all(&reply.body[1..]).await;
                } else {
                    let _ = socket.write_all(&reply.body).await;
                }
                let _ = socket.shutdown().await;
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }
}

fn api_reply(url: &str) -> Reply {
    Reply::ok(serde_json::to_vec(&json!({"rtnCode": 0, "list": [entry(url)]})).unwrap())
}

fn test_client() -> reqwest::Client {
    // Explicitly injected fixture client: retain structural redirect tests without
    // weakening the production public-network policy.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || apk_url(attempt.url().as_str()).is_err() {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .no_proxy()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap()
}

#[tokio::test]
async fn partial_files_are_unpublished_and_cleaned_on_timeout_or_publication_race() {
    for mode in ["success", "timeout", "race"] {
        let server = Server::new(|base| {
            vec![
                api_reply(&format!("{base}/full.apk")),
                Reply {
                    body_delay: if mode == "timeout" {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis(100)
                    },
                    ..Reply::ok(fixture())
                },
            ]
        })
        .await;
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("com.example.app.apk");
        let client = test_client();
        let (result, ()) = tokio::join!(
            injected_download_one(
                &client,
                &server.endpoint,
                "com.example.app",
                None,
                "CN",
                out.path()
            ),
            async {
                tokio::time::timeout(Duration::from_millis(250), async {
                    loop {
                        if std::fs::read_dir(out.path())
                            .unwrap()
                            .any(|e| e.unwrap().metadata().unwrap().len() > 0)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                })
                .await
                .expect("streamed bytes should reach a temporary file");
                assert!(!target.exists(), "partial APK must not be published");
                if mode == "race" {
                    std::fs::write(&target, b"existing").unwrap();
                }
            }
        );
        match mode {
            "success" => {
                result.unwrap();
                assert_eq!(std::fs::read(&target).unwrap(), fixture());
            }
            "timeout" => {
                assert!(result.unwrap_err().contains("timeout"));
                assert!(!target.exists());
            }
            _ => {
                assert!(result.unwrap_err().contains("publish"));
                assert_eq!(std::fs::read(&target).unwrap(), b"existing");
            }
        }
        assert_eq!(
            std::fs::read_dir(out.path()).unwrap().count(),
            usize::from(mode != "timeout")
        );
    }
}

#[tokio::test]
async fn apk_http_and_timeout_errors_never_publish_output() {
    for reply in [
        Reply {
            status: 403,
            ..Reply::ok(b"SECRET".to_vec())
        },
        Reply {
            status: 206,
            ..Reply::ok(fixture())
        },
        Reply {
            delay: Duration::from_secs(1),
            ..Reply::ok(fixture())
        },
    ] {
        let server =
            Server::new(|base| vec![api_reply(&format!("{base}/full.apk?sig=SECRET")), reply])
                .await;
        let out = tempfile::tempdir().unwrap();
        let error = injected_download_one(
            &test_client(),
            &server.endpoint,
            "com.example.app",
            None,
            "CN",
            out.path(),
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("APK HTTP status") || error == "APK timeout",
            "{error}"
        );
        assert!(!error.contains("SECRET"));
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

// The endpoint environment seam exists only inside the cfg(test) test executable.
#[tokio::test]
async fn diagnostic_fixture_child() {
    let Ok(endpoint) = std::env::var("APKEEP_HUAWEI_TEST_ENDPOINT") else {
        return;
    };
    let outpath = std::env::var("APKEEP_HUAWEI_TEST_OUTPATH").unwrap();
    let success = injected_download_batch(
        &test_client(),
        &endpoint,
        vec![("com.example.app".into(), None)],
        1,
        0,
        std::path::Path::new(&outpath),
        "CN",
    )
    .await;
    std::process::exit(if success { 0 } else { 1 });
}

#[tokio::test]
async fn network_diagnostics_reach_non_tty_stderr_with_failure_status() {
    for (reply, expected) in [
        (
            Reply::ok(b"{\"rtnCode\":0,\"list\":[]}".to_vec()),
            "unavailable in configured region/profile",
        ),
        (Reply::ok(b"not JSON SECRET".to_vec()), "malformed API JSON"),
        (
            Reply {
                status: 503,
                ..Reply::ok(b"SECRET".to_vec())
            },
            "API HTTP status 503",
        ),
        (
            Reply {
                delay: Duration::from_secs(1),
                ..Reply::ok(Vec::new())
            },
            "timeout",
        ),
    ] {
        let server = Server::new(|_| vec![reply]).await;
        let out = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "download_sources::huawei_app_gallery::download_tests::diagnostic_fixture_child",
                "--nocapture",
            ])
            .env("APKEEP_HUAWEI_TEST_ENDPOINT", &server.endpoint)
            .env("APKEEP_HUAWEI_TEST_OUTPATH", out.path());
        let result = tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("Huawei AppGallery: com.example.app (region CN)"));
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("SECRET") && !stderr.contains("http://"));
    }
}

#[tokio::test]
async fn redirect_targets_must_also_pass_url_validation() {
    let server = Server::new(|base| {
        vec![
            api_reply(&format!("{base}/full.apk")),
            Reply {
                status: 302,
                headers: format!(
                    "Location: {}\r\n",
                    base.replace("http://", "http://user:SECRET@")
                ),
                ..Reply::ok(Vec::new())
            },
            Reply::ok(fixture()),
        ]
    })
    .await;
    let out = tempfile::tempdir().unwrap();
    let error = injected_download_one(
        &test_client(),
        &server.endpoint,
        "com.example.app",
        None,
        "IE",
        out.path(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, "APK HTTP status 302");
    assert_eq!(server.requests.lock().unwrap().len(), 2);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn valid_redirects_work_and_excessive_redirects_are_bounded() {
    for count in [1, 6] {
        let server = Server::new(|base| {
            let mut replies = vec![api_reply(&format!("{base}/full.apk"))];
            for index in 0..count {
                replies.push(Reply {
                    status: 302,
                    headers: format!("Location: {base}/next{index}.apk\r\n"),
                    ..Reply::ok(Vec::new())
                });
            }
            replies.push(Reply::ok(fixture()));
            replies
        })
        .await;
        let out = tempfile::tempdir().unwrap();
        let result = injected_download_one(
            &test_client(),
            &server.endpoint,
            "com.example.app",
            None,
            "IE",
            out.path(),
        )
        .await;
        if count == 1 {
            result.unwrap();
            assert_eq!(
                std::fs::read(out.path().join("com.example.app.apk")).unwrap(),
                fixture()
            );
        } else {
            assert_eq!(result.unwrap_err(), "APK HTTP status 302");
            assert!(server.requests.lock().unwrap().len() < 8);
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        }
    }
}

#[tokio::test]
async fn existing_nonregular_output_is_never_followed_or_overwritten() {
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("com.example.app.apk");
    std::fs::create_dir(&target).unwrap();
    let error = injected_download_one(
        &test_client(),
        "http://127.0.0.1:1",
        "com.example.app",
        None,
        "IE",
        out.path(),
    )
    .await
    .unwrap_err();
    assert!(error.contains("not a regular file"));
    std::fs::remove_dir(&target).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(out.path().join("nonexistent"), &target).unwrap();
        let error = injected_download_one(
            &test_client(),
            "http://127.0.0.1:1",
            "com.example.app",
            None,
            "IE",
            out.path(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("not a regular file"));
        assert!(!out.path().join("nonexistent").exists());
    }
}

#[test]
fn package_ids_are_safe_single_filenames() {
    for package in ["com.example.app", "com.example_2.App1", "_example.app"] {
        assert!(valid_package(package));
    }
    for package in [
        "",
        "single",
        "com..app",
        "com.example.",
        "com.1app",
        "../escape",
        "com.a/b",
        "com.a\\b",
        "com.example\r\nINJECT",
        "com.example%2e",
        "com.应用",
    ] {
        assert!(!valid_package(package), "{package}");
    }
    assert!(!valid_package(&format!("com.{}", "a".repeat(241))));
}

#[tokio::test]
async fn api_response_is_bounded_before_parsing() {
    let server = Server::new(|_| vec![Reply::ok(vec![b' '; 1024 * 1024 + 1])]).await;
    let out = tempfile::tempdir().unwrap();
    let error = injected_download_one(
        &test_client(),
        &server.endpoint,
        "com.example.app",
        None,
        "CN",
        out.path(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, "API response too large");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn loopback_api_errors_are_distinct_safe_and_never_start_apk_download() {
    for (reply, expected) in [
        (Reply { status: 503, ..Reply::ok(b"SECRET".to_vec()) }, "API HTTP status 503"),
        (Reply::ok(b"not JSON SECRET".to_vec()), "malformed API JSON"),
        (Reply::ok(b"{\"rtnCode\":9,\"list\":[]}".to_vec()), "nonzero rtnCode"),
        (Reply::ok(b"{\"rtnCode\":0,\"list\":[]}".to_vec()), "unavailable in configured region/profile"),
        (Reply { delay: Duration::from_secs(1), ..Reply::ok(Vec::new()) }, "timeout"),
        (Reply::ok(serde_json::to_vec(&json!({"rtnCode":0,"list":[{"package":"com.example.app","isDiff":0,"downurl":"https://example.org/apk?sig=SECRET","size":3}]})).unwrap()), "SHA256"),
    ] {
        let server = Server::new(|_| vec![reply]).await;
        let out = tempfile::tempdir().unwrap();
        let error = injected_download_one(&test_client(), &server.endpoint, "com.example.app", None, "CN", out.path()).await.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("SECRET"));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/?sig=SECRET", socket.local_addr().unwrap());
    drop(socket);
    let out = tempfile::tempdir().unwrap();
    assert_eq!(
        injected_download_one(
            &test_client(),
            &endpoint,
            "com.example.app",
            None,
            "IE",
            out.path()
        )
        .await
        .unwrap_err(),
        "API transport error"
    );
}

#[tokio::test]
async fn typed_report_huawei_loopback_batch_keeps_processing_after_failure_and_aggregates_result() {
    let server = Server::new(|base| {
        vec![
            Reply::ok(b"{\"rtnCode\":0,\"list\":[]}".to_vec()),
            api_reply(&format!("{base}/full.apk")),
            Reply::ok(fixture()),
        ]
    })
    .await;
    let out = tempfile::tempdir().unwrap();
    let apps = vec![
        ("com.missing.app".into(), None),
        ("com.example.app".into(), None),
    ];
    let (ok, report) = crate::results::collect(
        crate::results::Report::new("huawei-app-gallery", "download", apps).unwrap(),
        injected_download_batch(
            &test_client(),
            &server.endpoint,
            vec![
                ("com.missing.app".into(), None),
                ("com.example.app".into(), None),
            ],
            1,
            0,
            out.path(),
            "CN",
        ),
    )
    .await;
    assert!(!ok);
    let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
    assert_eq!(value["results"][0]["status"], "unavailable");
    assert_eq!(value["results"][0]["reason"], "profile_unavailable");
    assert_eq!(value["results"][1]["status"], "success");
    assert_eq!(
        std::fs::read(out.path().join("com.example.app.apk")).unwrap(),
        fixture()
    );
    assert_eq!(server.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn rejects_corrupt_short_oversize_and_truncated_downloads_and_cleans_temporary_files() {
    for (body, length, expected) in [
        (
            {
                let mut bytes = fixture();
                bytes[0] ^= 1;
                bytes
            },
            None,
            "SHA256",
        ),
        (b"ab".to_vec(), None, "size"),
        (
            {
                let mut bytes = fixture();
                bytes.push(0);
                bytes
            },
            None,
            "size",
        ),
        (b"ab".to_vec(), Some(fixture().len()), "transport"),
    ] {
        let server = Server::new(|base| {
            vec![
                api_reply(&format!("{base}/apk?sig=SECRET")),
                Reply {
                    body,
                    length,
                    ..Reply::ok(Vec::new())
                },
            ]
        })
        .await;
        let out = tempfile::tempdir().unwrap();
        let error = injected_download_one(
            &test_client(),
            &server.endpoint,
            "com.example.app",
            None,
            "IE",
            out.path(),
        )
        .await
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("SECRET"));
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn loopback_downloads_complete_apk_and_sends_encoded_form() {
    for region in ["IE", "CN"] {
        let server =
            Server::new(|base| vec![api_reply(&format!("{base}/full.apk")), Reply::ok(fixture())])
                .await;
        let out = tempfile::tempdir().unwrap();
        injected_download_one(
            &test_client(),
            &server.endpoint,
            "com.example.app",
            None,
            region,
            out.path(),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(out.path().join("com.example.app.apk")).unwrap(),
            fixture()
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"));
        assert!(requests[0].contains(&format!("serviceCountry={region}")));
        assert!(requests[1].starts_with("GET /full.apk HTTP/1.1"));
    }
}

fn entry(url: &str) -> Value {
    use sha2::Digest;
    let bytes = fixture();
    json!({"package": "com.example.app", "downurl": url,
        "size": bytes.len(), "fullSize": bytes.len(), "sha256": hex::encode(sha2::Sha256::digest(&bytes)),
        "isDiff": 0})
}

fn parse(entries: Vec<Value>) -> Result<Apk, &'static str> {
    parse_apk(
        &serde_json::to_vec(&json!({"rtnCode": 0, "list": entries})).unwrap(),
        "com.example.app",
    )
}

#[test]
fn rejects_api_errors_missing_code_and_distinguishes_empty_list() {
    for body in [
        json!({"list": []}),
        json!({"rtnCode": "0", "list": []}),
        json!({"rtnCode": 9, "list": [entry("https://example.org/app.apk")]}),
        json!({"rtnCode": 0}),
        json!({"rtnCode": 0, "list": {}}),
    ] {
        assert!(parse_apk(&serde_json::to_vec(&body).unwrap(), "com.example.app").is_err());
    }
    assert_eq!(
        parse(vec![]).unwrap_err(),
        "unavailable in configured region/profile"
    );
    assert!(parse_apk(b"not JSON SECRET", "com.example.app")
        .unwrap_err()
        .contains("JSON"));
}

#[test]
fn rejects_missing_wrong_and_ambiguous_package() {
    let mut missing = entry("https://example.org/app.apk");
    missing.as_object_mut().unwrap().remove("package");
    assert!(parse(vec![missing]).is_err());
    let mut wrong = entry("https://example.org/app.apk");
    wrong["package"] = json!("com.other.app");
    assert!(parse(vec![wrong]).is_err());
    let item = entry("https://example.org/app.apk");
    assert!(parse(vec![item.clone(), item]).is_err());
}

#[test]
fn rejects_delta_split_unknown_or_invalid_integrity_metadata() {
    for (key, value) in [
        ("isDiff", json!(1)),
        ("isDiff", Value::Null),
        ("isDiff", json!("0")),
        (
            "splitInfo",
            json!([{"url": "https://example.org/split.apk"}]),
        ),
        ("isSplit", json!(1)),
        ("sha256", json!("ab")),
        ("sha256", json!("z".repeat(64))),
        ("sha256", Value::Null),
        ("size", json!(0)),
        ("size", json!(-1)),
        ("size", json!("3")),
        ("fullSize", json!(4)),
    ] {
        let mut item = entry("https://example.org/app.apk");
        item[key] = value;
        assert!(parse(vec![item]).is_err(), "accepted {key}");
    }
}

#[test]
fn full_url_is_preferred_but_never_accepts_unsafe_urls() {
    let mut item = entry("https://example.org/fallback.apk");
    item["fullDownUrl"] = json!("https://example.org/full.apk?sig=SECRET");
    assert_eq!(parse(vec![item]).unwrap().url.path(), "/full.apk");
    for url in [
        "file:///tmp/a.apk",
        "ftp://example.org/a.apk",
        "https://user:pass@example.org/a.apk",
        "https://example.org/a.apk#frag",
        "http:///a.apk",
        "https://exa mple.org/a.apk",
        "https://./a.apk",
        "https://-invalid.example/a.apk",
        "https://example..org/a.apk",
        "https://example.org../a.apk",
        "https://bad_.example/a.apk",
        "//example.org/a.apk",
        "https://example.org\\evil",
        " https://example.org/a.apk",
    ] {
        assert!(parse(vec![entry(url)]).is_err(), "accepted {url}");
    }
    let mut missing = entry("https://example.org/app.apk");
    missing.as_object_mut().unwrap().remove("downurl");
    assert!(parse(vec![missing]).is_err());
}

#[test]
fn selects_matching_package_not_first_entry() {
    let mut other = entry("https://wrong.example/app.apk");
    other["package"] = json!("com.other.app");
    let apk = parse(vec![other, entry("https://example.org/full.apk")]).unwrap();
    assert_eq!(apk.url.as_str(), "https://example.org/full.apk");
    assert_eq!(apk.size, fixture().len() as u64);
    assert_eq!(apk.sha256.len(), 32);
}
#[tokio::test]
async fn api_version_code_mismatch_is_rejected_before_publication() {
    let server = Server::new(|base| {
        let mut item = entry(&format!("{base}/artifact"));
        item["versionCode"] = json!(43);
        vec![
            Reply::ok(serde_json::to_vec(&json!({"rtnCode":0,"list":[item]})).unwrap()),
            Reply::ok(fixture()),
        ]
    })
    .await;
    let out = tempfile::tempdir().unwrap();
    let result = injected_download_one(
        &test_client(),
        &server.endpoint,
        "com.example.app",
        None,
        "IE",
        out.path(),
    )
    .await;
    assert!(
        result.is_err(),
        "API versionCode must bind the downloaded manifest"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn matching_api_integrity_never_publishes_invalid_zip_or_manifest() {
    use super::apk_validation::tests::{compiled_apk, duplicate_manifest, manifest, repack};
    use sha2::{Digest, Sha256};
    let valid = fixture();
    let mut crc = repack(&manifest(&valid), &[("assets/data", b"original")]);
    let position = crc.windows(8).position(|b| b == b"original").unwrap();
    crc[position] ^= 1;
    for bytes in [
        compiled_apk("com.other.app", 42, ""),
        compiled_apk("com.example.app", 42, r#"split="config.en""#),
        duplicate_manifest(),
        crc,
        repack(b"<manifest package='com.example.app'/>", &[]),
        valid[..valid.len() - 10].to_vec(),
    ] {
        let server = Server::new(|base| {
            let mut item = entry(&format!("{base}/artifact?sig=PRIVATE_TOKEN"));
            item["size"] = json!(bytes.len());
            item["fullSize"] = json!(bytes.len());
            item["sha256"] = json!(hex::encode(Sha256::digest(&bytes)));
            vec![
                Reply::ok(serde_json::to_vec(&json!({"rtnCode":0,"list":[item]})).unwrap()),
                Reply::ok(bytes),
            ]
        })
        .await;
        let out = tempfile::tempdir().unwrap();
        let error = injected_download_one(
            &test_client(),
            &server.endpoint,
            "com.example.app",
            None,
            "IE",
            out.path(),
        )
        .await
        .unwrap_err();
        assert!(!error.contains("PRIVATE_TOKEN"));
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[test]
fn api_version_code_is_optional_but_malformed_values_are_not_ignored() {
    let mut item = entry("https://example.org/app.apk");
    assert_eq!(parse(vec![item.clone()]).unwrap().version_code, None);
    item["versionCode"] = json!(42);
    assert_eq!(parse(vec![item.clone()]).unwrap().version_code, Some(42));
    for value in [Value::Null, json!("42"), json!(-1), json!(0), json!(1.5)] {
        item["versionCode"] = value;
        assert!(parse(vec![item.clone()]).is_err());
    }
}
