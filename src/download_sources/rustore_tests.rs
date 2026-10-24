use super::*;

#[tokio::test]
async fn direct_artifact_truncation_and_invalid_chunk_encoding_report_integrity() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\nZZ\r\n".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private?token=PRIVATE_TOKEN", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_request(&mut socket).await;
                socket.write_all(response).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let out = tempfile::tempdir().unwrap();
        let report = results::Report::new("ru-store", "download", vec![("com.example.app".into(), None)]).unwrap();
        let (ok, mut report) = results::collect(report, results::observe("com.example.app", None,
            injected_download_apk(url, "com.example.app".into(), out.path(), Rc::new(MultiProgress::new())))).await;
        server.await.unwrap();
        report.finish(ok);
        let bytes = report.json_bytes().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!ok);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0, "partial or published APK left behind");
        assert_eq!(value["success"], false);
        assert_eq!(value["results"][0]["status"], "error");
        assert_eq!(value["results"][0]["reason"], "integrity");
        assert!(!String::from_utf8(bytes).unwrap().contains("PRIVATE_TOKEN"));
    }
}

#[tokio::test]
async fn direct_metadata_body_failure_reports_integrity_not_transport() {
    let (url, server) =
        serve_raw_response(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx".to_vec()).await;
    let (ok, report) = results::collect(
        results::Report::new(
            "ru-store",
            "download",
            vec![("com.example.app".into(), None)],
        )
        .unwrap(),
        results::observe("com.example.app", None, async {
            request_json(local_client().get(url)).await.is_ok()
        }),
    )
    .await;
    server.await.unwrap();
    assert!(!ok);
    let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
    assert_eq!(value["results"][0]["reason"], "integrity");
}

#[tokio::test]
async fn direct_request_metadata_and_artifact_failures_keep_typed_distinctions() {
    for metadata in [false, true] {
        for (reply, expected) in [
            (
                Some(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice(),
                ),
                "authentication",
            ),
            (
                Some(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice(),
                ),
                "authentication",
            ),
            (Some(b"not HTTP\r\n\r\n".as_slice()), "transport"),
            (
                Some(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
                        .as_slice(),
                ),
                "integrity",
            ),
            (None, "timeout"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "http://{}/private?token=PRIVATE_TOKEN",
                listener.local_addr().unwrap()
            );
            let server = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    read_request(&mut socket).await;
                    if let Some(reply) = reply {
                        let _ = socket.write_all(reply).await;
                        let _ = socket.shutdown().await;
                    } else {
                        tokio::spawn(async move {
                            sleep(TokioDuration::from_secs(5)).await;
                            drop(socket);
                        });
                    }
                }
            });
            let out = tempfile::tempdir().unwrap();
            let policy = NetworkPolicy {
                metadata_total: TokioDuration::from_millis(80),
                apk_total: TokioDuration::from_millis(80),
                ..NetworkPolicy::default()
            };
            let (ok, report) = results::collect(
                results::Report::new(
                    "ru-store",
                    "download",
                    vec![("com.example.app".into(), None)],
                )
                .unwrap(),
                results::observe("com.example.app", None, async {
                    if metadata {
                        request_json_with_policy(local_client().get(url), policy)
                            .await
                            .is_ok()
                    } else {
                        injected_download_apk_with_policy(
                            url,
                            "com.example.app".into(),
                            out.path(),
                            Rc::new(MultiProgress::new()),
                            policy,
                        )
                        .await
                    }
                }),
            )
            .await;
            server.abort();
            assert!(!ok);
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
            let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
            assert_eq!(value["results"][0]["status"], "error");
            assert_eq!(
                value["results"][0]["reason"], expected,
                "metadata={metadata}"
            );
        }
    }
}

#[tokio::test]
async fn refused_connection_stays_transport_without_partial_output() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/private?token=PRIVATE_TOKEN",
        listener.local_addr().unwrap()
    );
    drop(listener);
    let out = tempfile::tempdir().unwrap();
    let (ok, report) = results::collect(
        results::Report::new(
            "ru-store",
            "download",
            vec![("com.example.app".into(), None)],
        )
        .unwrap(),
        results::observe(
            "com.example.app",
            None,
            injected_download_apk(
                url,
                "com.example.app".into(),
                out.path(),
                Rc::new(MultiProgress::new()),
            ),
        ),
    )
    .await;
    assert!(!ok);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    let value: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
    assert_eq!(value["results"][0]["reason"], "transport");
}

#[test]
fn rustore_requires_dot_separated_android_package_names() {
    assert!(!valid_package_name("dotless"));
    assert!(valid_package_name("com.example.app"));
}

fn fixture(package: &str) -> Vec<u8> {
    use crate::download_sources::apk_validation::tests::{compiled_apk, manifest, repack};
    repack(&manifest(&compiled_apk(package, 42, "")), &[])
}
fn fixture_body(body: &str, package: &str) -> Vec<u8> {
    if matches!(
        body,
        "synthetic-apk" | "complete-test-apk" | "complete-retry-apk" | "test-apk-bytes"
    ) {
        fixture(package)
    } else {
        body.as_bytes().to_vec()
    }
}

#[tokio::test]
async fn invalid_standalone_apks_never_reach_publication() {
    use crate::download_sources::apk_validation::tests::{base_apk, compiled_apk};
    for bytes in [
        b"not-an-apk".to_vec(),
        compiled_apk("com.other.app", 42, ""),
        compiled_apk("com.example.app", 42, r#"split="config.en""#),
        {
            let mut b = base_apk();
            b.truncate(b.len() - 10);
            b
        },
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/apk", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_request(&mut socket).await;
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
        });
        let out = tempfile::tempdir().unwrap();
        let ok = injected_download_apk(
            url,
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new()),
        )
        .await;
        server.abort();
        let _ = server.await;
        assert!(!ok, "invalid APK was published");
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn typed_artifact_failures_preserve_transport_integrity_auth_and_timeout() {
    use crate::results::{collect, observe, Report};
    for (status, body, expected) in [
        ("500 Server Error", "bad", "transport"),
        ("200 OK", "", "integrity"),
        ("401 Unauthorized", "bad", "authentication"),
        ("403 Forbidden", "bad", "authentication"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/apk", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_request(&mut socket).await;
                let bytes = fixture_body(body, "com.example.ok");
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
        });
        let out = tempfile::tempdir().unwrap();
        let (ok, mut report) = collect(
            Report::new(
                "ru-store",
                "download",
                vec![("com.example.app".into(), None)],
            )
            .unwrap(),
            observe(
                "com.example.app",
                None,
                injected_download_apk(
                    url,
                    "com.example.app".into(),
                    out.path(),
                    Rc::new(MultiProgress::new()),
                ),
            ),
        )
        .await;
        server.abort();
        let _ = server.await;
        assert!(!ok);
        report.finish(ok);
        let j: Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
        assert_eq!(j["results"][0]["reason"], expected, "{status}: {j}");
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn typed_report_mixed_loopback_preserves_duplicates_and_authoritative_absence() {
    use crate::results::{collect, Report};
    let out = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let artifact = format!("{base}/apk");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let req = read_request(&mut socket).await;
            let (status, body) = if req.contains("packageNames=com.example.ok") {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                ("200 OK", "[{\"id\":42}]".to_owned())
            } else if req.contains("packageNames=com.example.absent") {
                ("200 OK", "[]".to_owned())
            } else if req.contains("packageNames=com.example.bad") {
                ("200 OK", "not-json PRIVATE_TOKEN".to_owned())
            } else if req.starts_with("POST ") {
                (
                    "200 OK",
                    json!({"code":"OK", "body":{"downloadUrls":[{"url":artifact}]}}).to_string(),
                )
            } else {
                ("200 OK", "synthetic-apk".to_owned())
            };
            let bytes = fixture_body(&body, "com.example.ok");
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&bytes).await.unwrap();
        }
    });
    let apps = vec![
        ("com.example.ok".into(), None),
        ("com.example.absent".into(), None),
        ("com.example.bad".into(), None),
        ("com.example.ok".into(), None),
        ("com.example.pinned".into(), Some("2".into())),
    ];
    let client = local_client();
    let (ok, mut report) = collect(
        Report::new("ru-store", "download", apps.clone()).unwrap(),
        download_apps_at(
            apps,
            4,
            0,
            out.path(),
            HashMap::from([("rustore_version", "11500")]),
            (&format!("{base}/lookup"), &format!("{base}/link")),
            Some((&client, &client)),
        ),
    )
    .await;
    server.abort();
    let _ = server.await;
    assert!(!ok);
    report.finish(ok);
    let bytes = report.json_bytes().unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_TOKEN"));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let rows = value["results"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for (i, status, reason) in [
        (0, "success", "complete"),
        (1, "not_found", "package_absent"),
        (2, "error", "integrity"),
        (3, "success", "complete"),
        (4, "unavailable", "variant_unavailable"),
    ] {
        assert_eq!(rows[i]["status"], status, "row {i}: {value}");
        assert_eq!(rows[i]["reason"], reason);
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(out.path().join("com.example.ok.apk")).unwrap(),
        fixture("com.example.ok")
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ancestor_swap_during_rustore_transfer_keeps_artifact_and_cleanup_pinned() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("out");
    let moved = root.path().join("moved");
    let victim = root.path().join("victim");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&victim).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let (release, wait) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    fixture("com.example.app").len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        wait.await.unwrap();
        socket.write_all(&fixture("com.example.app")).await.unwrap();
    });
    let (result, ()) = tokio::join!(
        injected_download_apk(
            url,
            "com.example.app".into(),
            &original,
            Rc::new(MultiProgress::new())
        ),
        async {
            tokio::time::timeout(TokioDuration::from_secs(2), async {
                while std::fs::read_dir(&original).unwrap().count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            std::fs::rename(&original, &moved).unwrap();
            std::os::unix::fs::symlink(&victim, &original).unwrap();
            release.send(()).unwrap();
        }
    );
    server.await.unwrap();
    assert!(result);
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(moved.join("com.example.app.apk")).unwrap(),
        fixture("com.example.app")
    );
}

#[tokio::test]
async fn non_success_artifact_responses_never_publish_body() {
    for headers in ["", "Location: file:///not-read\r\n"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/artifact", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                let reply = format!("HTTP/1.1 302 Found\r\n{headers}Content-Length: 3\r\nConnection: close\r\n\r\nbad");
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let out = tempfile::tempdir().unwrap();
        let result = injected_download_apk(
            url,
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new()),
        )
        .await;
        task.abort();
        let _ = task.await;
        assert!(
            !result,
            "a stopped 302 body must not be reported as a downloaded APK"
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn production_artifact_and_metadata_paths_reject_private_initial_urls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = format!(
        "http://{}/private?token=PRIVATE_TOKEN",
        listener.local_addr().unwrap()
    );
    let out = tempfile::tempdir().unwrap();
    for url in [
        local.as_str(),
        "http://169.254.169.254/private",
        "http://[::1]/private",
        "http://user:PRIVATE_TOKEN@example.com/private",
    ] {
        assert!(!tokio::time::timeout(
            TokioDuration::from_millis(500),
            download_apk(
                url.into(),
                "com.example.app".into(),
                out.path(),
                Rc::new(MultiProgress::new())
            )
        )
        .await
        .expect("private URL must fail before network"));
    }
    assert!(
        !download_apps_at(
            vec![("com.example.app".into(), None)],
            1,
            0,
            out.path(),
            HashMap::from([("rustore_version", "11500")]),
            (&local, &local),
            None
        )
        .await
    );
    assert!(
        tokio::time::timeout(TokioDuration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

async fn injected_download_apk(
    url: String,
    name: String,
    out: &Path,
    mp: Rc<MultiProgress>,
) -> bool {
    injected_download_apk_with_policy(url, name, out, mp, NetworkPolicy::default()).await
}
async fn injected_download_apk_with_policy(
    url: String,
    name: String,
    out: &Path,
    mp: Rc<MultiProgress>,
    policy: NetworkPolicy,
) -> bool {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(policy.connect)
        .read_timeout(policy.idle_read)
        .timeout(policy.apk_total)
        .build()
        .unwrap();
    download_apk_with_policy(url, name, out, mp, policy, Some(&client)).await
}

#[tokio::test]
async fn production_client_denies_loopback_dns_before_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://localhost:{}/private?token=PRIVATE_TOKEN",
        listener.local_addr().unwrap().port()
    );
    let client = network_client(NetworkPolicy::default(), TokioDuration::from_millis(80)).unwrap();
    let _ = client
        .get(url)
        .timeout(TokioDuration::from_millis(80))
        .send()
        .await;
    assert!(
        tokio::time::timeout(TokioDuration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "production client connected to loopback"
    );
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Hold a real socket open after sending headers (and optionally initial body bytes).
// The returned task owns the connection until explicitly cancelled by the test.
async fn serve_held_response(prefix: String) -> (String, tokio::task::JoinHandle<()>) {
    let (endpoint, task, _) = serve_counted_held_response(prefix).await;
    (endpoint, task)
}

async fn serve_counted_held_response(
    prefix: String,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "http://{}/private?token=secret-token",
        listener.local_addr().unwrap()
    );
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = attempts.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let prefix = prefix.clone();
            tokio::spawn(async move {
                read_request(&mut stream).await;
                stream.write_all(prefix.as_bytes()).await.unwrap();
                let mut byte = [0];
                let _ = stream.read(&mut byte).await;
            });
        }
    });
    (endpoint, task, attempts)
}

async fn assert_apk_stall_is_bounded(prefix: &str, policy: NetworkPolicy, observe_partial: bool) {
    let out = tempfile::tempdir().unwrap();
    let (endpoint, task, attempts) = serve_counted_held_response(prefix.into()).await;
    let download = tokio::time::timeout(
        TokioDuration::from_millis(800),
        injected_download_apk_with_policy(
            endpoint,
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new()),
            policy,
        ),
    );
    let observer = async {
        if observe_partial {
            tokio::time::timeout(TokioDuration::from_millis(400), async {
                loop {
                    if std::fs::read_dir(out.path()).unwrap().any(|entry| {
                        entry
                            .ok()
                            .and_then(|entry| entry.metadata().ok())
                            .is_some_and(|metadata| metadata.len() > 0)
                    }) {
                        break;
                    }
                    sleep(TokioDuration::from_millis(1)).await;
                }
            })
            .await
            .expect("server's initial body chunk was not written to a temporary file");
        }
    };
    let (result, ()) = tokio::join!(download, observer);
    task.abort();
    assert!(!result.expect("APK stall exceeded the injected deadline"));
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "retries must stop after three attempts"
    );
    assert_eq!(
        std::fs::read_dir(out.path()).unwrap().count(),
        0,
        "APK or partial file leaked"
    );
}

#[tokio::test]
async fn apk_total_deadline_bounds_stalled_headers() {
    assert_apk_stall_is_bounded(
        "",
        NetworkPolicy {
            apk_total: TokioDuration::from_millis(60),
            ..NetworkPolicy::default()
        },
        false,
    )
    .await;
}

#[tokio::test]
async fn apk_total_deadline_cleans_up_after_an_initial_body_chunk() {
    assert_apk_stall_is_bounded(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nsecret-partial-body",
        NetworkPolicy {
            apk_total: TokioDuration::from_millis(60),
            ..NetworkPolicy::default()
        },
        true,
    )
    .await;
}

#[tokio::test]
async fn apk_idle_deadline_bounds_stalled_headers() {
    assert_apk_stall_is_bounded(
        "",
        NetworkPolicy {
            idle_read: TokioDuration::from_millis(60),
            apk_total: TokioDuration::from_secs(5),
            ..NetworkPolicy::default()
        },
        false,
    )
    .await;
}

#[tokio::test]
async fn apk_idle_deadline_cleans_up_after_an_initial_body_chunk() {
    assert_apk_stall_is_bounded(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nsecret-partial-body",
        NetworkPolicy {
            idle_read: TokioDuration::from_millis(60),
            apk_total: TokioDuration::from_secs(5),
            ..NetworkPolicy::default()
        },
        true,
    )
    .await;
}

async fn assert_apk_oversize_is_rejected_early(prefix: &str) {
    let out = tempfile::tempdir().unwrap();
    let (endpoint, task, attempts) = serve_counted_held_response(prefix.into()).await;
    let result = tokio::time::timeout(
        TokioDuration::from_millis(400),
        injected_download_apk_with_policy(
            endpoint,
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new()),
            NetworkPolicy {
                apk_max_bytes: 16,
                ..NetworkPolicy::default()
            },
        ),
    )
    .await;
    task.abort();
    assert!(!result.expect("oversized APK waited for body/EOF instead of rejecting early"));
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn apk_declared_oversize_is_rejected_before_body() {
    assert_apk_oversize_is_rejected_early("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n").await;
}

#[tokio::test]
async fn apk_streamed_oversize_is_rejected_before_eof() {
    assert_apk_oversize_is_rejected_early(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\nsecret-oversized!!\r\n",
    )
    .await;
}

#[tokio::test]
async fn metadata_total_deadline_bounds_headers_and_partial_body() {
    for prefix in [
        "",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n[\r\n",
    ] {
        let (endpoint, task) = serve_held_response(prefix.into()).await;
        let result = tokio::time::timeout(
            TokioDuration::from_millis(400),
            request_json_with_policy(
                local_client().get(endpoint),
                NetworkPolicy {
                    metadata_total: TokioDuration::from_millis(50),
                    ..NetworkPolicy::default()
                },
            ),
        )
        .await;
        task.abort();
        let error = result
            .expect("metadata exceeded its total deadline")
            .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        for secret in ["secret", "http://", "127.0.0.1", "private", "token="] {
            assert!(!error.contains(secret), "{error}");
        }
    }
}

#[test]
fn production_network_limits_are_fixed_and_bounded() {
    let policy = NetworkPolicy::default();
    assert_eq!(policy.connect, TokioDuration::from_secs(15));
    assert_eq!(policy.metadata_total, TokioDuration::from_secs(60));
    assert_eq!(policy.metadata_max_bytes, 4 * 1024 * 1024);
    assert_eq!(policy.apk_total, TokioDuration::from_secs(900));
    assert_eq!(policy.idle_read, TokioDuration::from_secs(30));
    assert_eq!(policy.apk_max_bytes, 2 * 1024 * 1024 * 1024);
}

#[tokio::test]
async fn metadata_streamed_oversize_is_rejected_before_eof() {
    let (endpoint, task) = serve_held_response(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\nsecret-oversized!!\r\n".into(),
    )
    .await;
    let result = tokio::time::timeout(
        TokioDuration::from_millis(250),
        request_json_with_policy(
            local_client().get(endpoint),
            NetworkPolicy {
                metadata_max_bytes: 16,
                ..NetworkPolicy::default()
            },
        ),
    )
    .await;
    task.abort();
    let error = result
        .expect("streamed metadata cap waited for EOF")
        .unwrap_err();
    assert!(error.contains("size limit"), "{error}");
    assert!(!error.contains("secret"));
}

#[tokio::test]
async fn metadata_declared_oversize_is_rejected_before_body() {
    let (endpoint, task) =
        serve_held_response("HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n".into()).await;
    let result = tokio::time::timeout(
        TokioDuration::from_millis(250),
        request_json(local_client().get(endpoint)),
    )
    .await;
    task.abort();
    let error = result
        .expect("oversized metadata waited for its body")
        .unwrap_err();
    assert!(error.contains("size limit"), "{error}");
    assert!(!error.contains("secret"));
}

#[tokio::test]
async fn streamed_caps_accumulate_across_individually_small_chunks() {
    let prefix =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n9\r\nsecret123\r\n";
    let (endpoint, task) = serve_held_response(prefix.into()).await;
    let result = tokio::time::timeout(
        TokioDuration::from_millis(400),
        request_json_with_policy(
            local_client().get(endpoint),
            NetworkPolicy {
                metadata_max_bytes: 16,
                ..NetworkPolicy::default()
            },
        ),
    )
    .await;
    task.abort();
    assert_eq!(
        result
            .expect("metadata cap was applied per chunk instead of cumulatively")
            .unwrap_err(),
        "RuStore metadata size limit exceeded"
    );
    assert_apk_oversize_is_rejected_early(prefix).await;
}

#[tokio::test]
async fn exact_resource_caps_accept_complete_declared_and_streamed_bodies() {
    let metadata = r#"{"ok":true}"#;
    let apk = fixture("com.example.app");
    for chunked in [false, true] {
        let response = |body: &[u8]| {
            let mut bytes = if chunked {
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n", body.len()).into_bytes()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes()
            };
            bytes.extend_from_slice(body);
            if chunked {
                bytes.extend_from_slice(b"\r\n0\r\n\r\n");
            }
            bytes
        };
        let (endpoint, task) = serve_raw_response(response(metadata.as_bytes())).await;
        assert_eq!(
            request_json_with_policy(
                local_client().get(endpoint),
                NetworkPolicy {
                    metadata_max_bytes: metadata.len(),
                    ..NetworkPolicy::default()
                }
            )
            .await
            .unwrap(),
            json!({"ok":true})
        );
        task.await.unwrap();
        let (endpoint, task) = serve_raw_response(response(&apk)).await;
        let out = tempfile::tempdir().unwrap();
        assert!(
            injected_download_apk_with_policy(
                endpoint,
                "com.example.app".into(),
                out.path(),
                Rc::new(MultiProgress::new()),
                NetworkPolicy {
                    apk_max_bytes: apk.len() as u64,
                    ..NetworkPolicy::default()
                }
            )
            .await
        );
        task.await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("com.example.app.apk")).unwrap(),
            apk.as_slice()
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }
}

#[test]
fn network_policy_diagnostics_are_redacted_on_actual_stdout_and_stderr() {
    for test in [
        "apk_total_deadline_bounds_stalled_headers",
        "apk_total_deadline_cleans_up_after_an_initial_body_chunk",
        "apk_idle_deadline_bounds_stalled_headers",
        "apk_idle_deadline_cleans_up_after_an_initial_body_chunk",
        "apk_declared_oversize_is_rejected_before_body",
        "apk_streamed_oversize_is_rejected_before_eof",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{}::{test}", module_path!().split_once("::").unwrap().1),
                "--nocapture",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{test}: {stdout}\n{stderr}");
        assert!(
            stderr.contains(if test.contains("oversize") {
                "size limit"
            } else {
                "timed out"
            }),
            "{test}: {stderr}"
        );
        assert_eq!(stderr.matches("(attempt ").count(), 3, "{test}: {stderr}");
        assert!(
            !stdout.contains("downloaded successfully"),
            "{test}: {stdout}"
        );
        for secret in ["secret-", "http://", "127.0.0.1", "private?", "token="] {
            assert!(!stdout.contains(secret), "{test}: {stdout}");
            assert!(!stderr.contains(secret), "{test}: {stderr}");
        }
    }
}

#[tokio::test]
async fn publication_race_is_nonretryable_and_never_trusts_the_winner() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            read_request(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        fixture("com.example.app").len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket
                .write_all(&fixture("com.example.app")[..1])
                .await
                .unwrap();
            sleep(TokioDuration::from_millis(60)).await;
            let _ = socket.write_all(&fixture("com.example.app")[1..]).await;
        }
    });
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("com.example.app.apk");
    let (result, ()) = tokio::join!(
        injected_download_apk(
            url,
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new())
        ),
        async {
            tokio::time::timeout(TokioDuration::from_secs(1), async {
                while !std::fs::read_dir(out.path())
                    .unwrap()
                    .any(|entry| entry.unwrap().metadata().unwrap().len() > 0)
                {
                    sleep(TokioDuration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            std::fs::write(&target, b"untrusted winner").unwrap();
        }
    );
    server.abort();
    assert!(!result);
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "publication failure must not re-download"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"untrusted winner");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn apk_download_returns_its_actual_success() {
    let out = tempfile::tempdir().unwrap();
    let (endpoint, task) = serve_once("200 OK", "test-apk-bytes").await;
    let result = injected_download_apk(
        endpoint,
        "com.example.app".to_string(),
        out.path(),
        Rc::new(MultiProgress::new()),
    )
    .await;
    task.await.unwrap();
    assert_eq!(
        tokio::fs::read(out.path().join("com.example.app.apk"))
            .await
            .unwrap(),
        fixture("com.example.app")
    );
    assert!(result, "downloader discarded its success status");
}

#[tokio::test]
async fn batch_reports_failed_apk_transfer() {
    let out = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failed_url = format!(
        "http://{}/private.apk?token=secret-token",
        listener.local_addr().unwrap()
    );
    drop(listener);
    let (lookup, lookup_task) = serve_once("200 OK", r#"[{"id":42}]"#).await;
    let (link, link_task) = serve_once(
        "200 OK",
        &json!({"code":"OK", "body":{"downloadUrls":[{"url":failed_url}]}}).to_string(),
    )
    .await;
    let result = tokio::time::timeout(
        TokioDuration::from_secs(5),
        download_apps_at(
            vec![("com.example.app".into(), None)],
            1,
            0,
            out.path(),
            HashMap::from([("rustore_version", "11500")]),
            (&lookup, &link),
            Some((&local_client(), &local_client())),
        ),
    )
    .await
    .unwrap();
    lookup_task.await.unwrap();
    link_task.await.unwrap();
    assert!(!result, "batch discarded a failed APK transfer status");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn unsafe_package_cannot_escape_the_output_directory() {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("output");
    std::fs::create_dir(&out).unwrap();
    let (endpoint, task) = serve_once("200 OK", "test-apk-bytes").await;
    let result = injected_download_apk(
        endpoint,
        "../escaped".into(),
        &out,
        Rc::new(MultiProgress::new()),
    )
    .await;
    // If validation rejects before I/O, the unused loopback server is cancelled.
    task.abort();
    assert!(
        !root.path().join("escaped.apk").exists(),
        "RuStore wrote outside OUTPATH"
    );
    assert!(!result, "RuStore accepted an unsafe package name");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn loopback_batches_preserve_results_files_and_safe_output() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for scenario in [
        "success",
        "transfer-failure",
        "mixed-serial",
        "mixed-parallel",
        "truncated",
        "retry",
        "lookup-failure",
        "link-failure",
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!(
                    "{}::loopback_batch_fixture",
                    module_path!().split_once("::").unwrap().1
                ),
                "--nocapture",
            ])
            .env("APKEEP_TEST_RUSTORE_BATCH", scenario)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("loopback scenario {scenario} timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{scenario}: {stdout}\n{stderr}");
        let success = matches!(scenario, "success" | "retry");
        assert!(
            stdout.contains(&format!("BATCH_RESULT={success}")),
            "{scenario}: {stdout}"
        );
        for secret in ["secret-", "http://", "127.0.0.1", "private.apk", "token="] {
            assert!(
                !stderr.contains(secret),
                "unsafe stderr for {scenario}: {stderr}"
            );
            assert!(
                !stdout.contains(secret),
                "unsafe stdout for {scenario}: {stdout}"
            );
        }
        if scenario == "success" {
            assert!(stderr.is_empty(), "{scenario}: {stderr}");
        } else {
            assert!(
                !stderr.is_empty(),
                "{scenario}: failure missing from stderr"
            );
        }
        if scenario.contains("mixed") {
            assert!(
                stdout.contains("com.example.good downloaded successfully!"),
                "{stdout}"
            );
            assert!(
                stdout.contains("com.example.last downloaded successfully!"),
                "{stdout}"
            );
        }
        assert!(!stderr.contains("downloaded successfully"));
        assert!(!stdout.contains("Could not"));
        assert!(!stdout.contains("Invalid response"));
    }
}

// Invoked by the parent test in a separate process, so stdout/stderr are observed
// without global environment mutation or any production endpoint override.
#[tokio::test]
async fn loopback_batch_fixture() {
    let Ok(scenario) = std::env::var("APKEEP_TEST_RUSTORE_BATCH") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server_base = base.clone();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let server_seen = seen.clone();
    let retry = scenario == "retry";
    let task = tokio::spawn(async move {
        let mut retries = 0;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            let target = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            server_seen.lock().unwrap().push(target.to_string());
            let (status, body, truncated) = if target.starts_with("/lookup") {
                let body = if target.contains("missing") {
                    "[]"
                } else if target.contains("denied") {
                    r#"[{"id":3}]"#
                } else if target.contains("fail") {
                    r#"[{"id":2}]"#
                } else if target.contains("last") {
                    r#"[{"id":5}]"#
                } else if target.contains("truncated") {
                    r#"[{"id":4}]"#
                } else {
                    r#"[{"id":1}]"#
                };
                ("200 OK", body.to_string(), false)
            } else if target == "/link" {
                let body: Value =
                    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
                let id = body["appId"].as_u64().unwrap();
                if id == 3 {
                    (
                        "200 OK",
                        r#"{"code":"DENIED","body":"secret-api-response"}"#.to_string(),
                        false,
                    )
                } else {
                    ("200 OK", json!({"code":"OK","body":{"downloadUrls":[{"url":format!("{server_base}/apk/{id}/private.apk?token=secret-token")}]}}).to_string(), false)
                }
            } else if target.starts_with("/apk/2/") {
                (
                    "503 Service Unavailable",
                    "secret-error-body".to_string(),
                    false,
                )
            } else if target.starts_with("/apk/4/") {
                retries += 1;
                if retry && retries > 1 {
                    ("200 OK", "complete-retry-apk".to_string(), false)
                } else {
                    ("200 OK", "secret-truncated-body".to_string(), true)
                }
            } else {
                ("200 OK", "complete-test-apk".to_string(), false)
            };
            let package = if target.starts_with("/apk/4/") {
                "com.example.truncated"
            } else if target.starts_with("/apk/5/") {
                "com.example.last"
            } else {
                "com.example.good"
            };
            let body = fixture_body(&body, package);
            let length = if truncated {
                body.len() + 100
            } else {
                body.len()
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    let out = tempfile::tempdir().unwrap();
    let packages = match scenario.as_str() {
        "success" => vec![("com.example.good", None)],
        "transfer-failure" => vec![("com.example.fail", None)],
        "truncated" | "retry" => vec![("com.example.truncated", None)],
        "lookup-failure" => vec![("com.example.missing", None)],
        "link-failure" => vec![("com.example.denied", None)],
        _ => vec![
            ("com.example.fail", None),
            ("com.example.good", None),
            ("com.example.missing", None),
            ("com.example.denied", None),
            ("com.example.pinned", Some("1")),
            ("../unsafe", None),
            ("com.example.last", None),
        ],
    };
    let result = download_apps_at(
        packages
            .into_iter()
            .map(|(id, version)| (id.into(), version.map(String::from)))
            .collect(),
        if scenario == "mixed-parallel" { 3 } else { 1 },
        0,
        out.path(),
        HashMap::from([("rustore_version", "11500")]),
        (&format!("{base}/lookup"), &format!("{base}/link")),
        Some((&local_client(), &local_client())),
    )
    .await;
    println!("BATCH_RESULT={result}");
    let mut files = std::fs::read_dir(out.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    files.sort();
    let expected = match scenario.as_str() {
        "success" => vec!["com.example.good.apk"],
        "retry" => vec!["com.example.truncated.apk"],
        "mixed-serial" | "mixed-parallel" => vec!["com.example.good.apk", "com.example.last.apk"],
        _ => vec![],
    };
    assert_eq!(files, expected, "unexpected files or partial leftovers");
    for name in expected {
        let bytes = std::fs::read(out.path().join(name)).unwrap();
        assert_eq!(bytes, fixture(name.strip_suffix(".apk").unwrap()));
    }
    if scenario.contains("mixed") {
        let requests = seen.lock().unwrap();
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("/lookup")).count(),
            5,
            "batch skipped items after a failure"
        );
        assert_eq!(requests.iter().filter(|r| r.as_str() == "/link").count(), 4);
    }
    task.abort();
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "request closed before complete body");
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(request).unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn existing_symlink_is_not_a_successful_apk() {
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("external-target");
    std::fs::write(&target, "unchanged").unwrap();
    let destination = out.path().join("com.example.app.apk");
    std::os::unix::fs::symlink(&target, &destination).unwrap();
    let result = injected_download_apk(
        "http://127.0.0.1:1/secret-path".into(),
        "com.example.app".into(),
        out.path(),
        Rc::new(MultiProgress::new()),
    )
    .await;
    assert!(!result, "existing symlink was accepted as a successful APK");
    assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    assert!(std::fs::symlink_metadata(destination)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[tokio::test]
async fn empty_apk_response_is_a_failed_download() {
    let out = tempfile::tempdir().unwrap();
    let (endpoint, task) = serve_once("200 OK", "").await;
    let result = injected_download_apk(
        endpoint,
        "com.example.app".into(),
        out.path(),
        Rc::new(MultiProgress::new()),
    )
    .await;
    task.await.unwrap();
    assert!(!result, "empty response was published as a successful APK");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn package_validation_rejects_paths_queries_and_control_characters() {
    assert!(valid_package_name(&format!("a.{}", "a".repeat(238))));
    assert!(!valid_package_name(&format!("a.{}", "a".repeat(239))));
    for package in [
        "../escape",
        "/absolute",
        "com/example",
        "com\\example",
        "com..example",
        ".com.example",
        "com.example.",
        "com.example?token=secret",
        "com.example#fragment",
        "com.example\nsecret",
        "com.42",
        "",
        "com.пример",
    ] {
        assert!(!valid_package_name(package));
    }
    for package in [
        "com.example.app",
        "com.Example_42.app",
        "android.app",
        "_example.app",
    ] {
        assert!(valid_package_name(package));
    }
}

#[tokio::test]
async fn existing_regular_file_is_preserved_but_not_trusted() {
    let out = tempfile::tempdir().unwrap();
    let destination = out.path().join("com.example.app.apk");
    std::fs::write(&destination, "existing-apk").unwrap();
    assert!(
        !injected_download_apk(
            "not-a-url".into(),
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new())
        )
        .await
    );
    assert_eq!(std::fs::read(destination).unwrap(), b"existing-apk");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn zero_parallel_is_rejected_by_the_download_helper() {
    let out = tempfile::tempdir().unwrap();
    let result = tokio::time::timeout(
        TokioDuration::from_millis(100),
        download_apps(
            vec![("com.example.app".into(), Some("1".into()))],
            0,
            0,
            out.path(),
            HashMap::from([("rustore_version", "11500")]),
        ),
    )
    .await
    .expect("zero-parallel helper must not hang");
    assert!(!result);
}

#[tokio::test]
async fn truncated_http_body_reports_a_redacted_read_error() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for lookup in [true, false] {
        let (endpoint, task) = serve_raw_response("HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\nsecret-truncated-body".to_string()).await;
        let error = if lookup {
            get_app_id_at(&client, &config.headers, "com.example.app", &endpoint)
                .await
                .unwrap_err()
        } else {
            get_download_url_at(&client, &config, 42, &endpoint)
                .await
                .unwrap_err()
        };
        task.await.unwrap();
        assert!(
            error.contains("network error while reading response"),
            "{error}"
        );
        assert!(!error.contains("secret-"));
    }
}

#[tokio::test]
async fn multiple_download_urls_are_never_saved_as_a_complete_apk() {
    let client = local_client();
    for without_splits in ["false", "true"] {
        let config =
            RustoreOptions::parse(&HashMap::from([("without_splits", without_splits)]), None)
                .unwrap();
        let body = r#"{"code":"OK","body":{"downloadUrls":[{"url":"https://signed.test/base.apk?secret-token"},{"url":"https://signed.test/split.apk?secret-token"}]}}"#;
        let (endpoint, task) = serve_once("200 OK", body).await;
        let result = get_download_url_at(&client, &config, 42, &endpoint).await;
        let request = task.await.unwrap();
        let sent: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(sent["withoutSplits"], without_splits == "true");
        assert!(
            result.is_err(),
            "silently chose first URL from split APK set"
        );
        let error = result.unwrap_err();
        assert!(error.contains("split APKs are not supported"), "{error}");
        assert!(!error.contains("secret-token"));
        assert!(!error.contains("signed.test"));
    }
}

#[tokio::test]
async fn configured_device_and_headers_are_sent_over_http() {
    let options = HashMap::from([
        ("arch", "x86;x86_64"),
        ("sdk_version", "34"),
        ("screen_density", "480"),
        ("locales", "ru_RU;en_US"),
        ("mobile_services", "HMS"),
        ("without_splits", "false"),
        ("rustore_version", "22000"),
        ("user_agent", "Custom/2"),
    ]);
    let config = RustoreOptions::parse(&options, Some("19000")).unwrap();
    let client = local_client();
    let (endpoint, task) = serve_once("200 OK", r#"[{"id":73}]"#).await;
    assert_eq!(
        get_app_id_at(&client, &config.headers, "com.example.app", &endpoint)
            .await
            .unwrap(),
        73
    );
    let lookup = task.await.unwrap().to_lowercase();
    assert!(lookup.contains("rustorevercode: 22000\r\n"));
    assert!(lookup.contains("user-agent: custom/2\r\n"));
    let (endpoint, task) = serve_once(
        "200 OK",
        r#"{"code":"OK","body":{"downloadUrls":[{"url":"https://example.test/app.apk"}]}}"#,
    )
    .await;
    assert_eq!(
        get_download_url_at(&client, &config, 73, &endpoint)
            .await
            .unwrap(),
        "https://example.test/app.apk"
    );
    let request = task.await.unwrap();
    let (headers, body) = request.split_once("\r\n\r\n").unwrap();
    assert!(headers.to_lowercase().contains("rustorevercode: 22000\r\n"));
    assert!(headers.to_lowercase().contains("user-agent: custom/2\r\n"));
    assert!(headers
        .to_lowercase()
        .contains("content-type: application/json\r\n"));
    let body: Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        body,
        json!({
            "appId": 73, "firstInstall": true, "mobileServices": ["HMS"],
            "supportedAbis": ["x86", "x86_64"], "screenDensity": 480,
            "supportedLocales": ["ru_RU", "en_US"], "sdkVersion": 34,
            "withoutSplits": false, "signatureFingerprint": null
        })
    );
}

#[tokio::test]
async fn download_response_requires_a_nonempty_http_url() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for body in [
        "",
        "secret-json-error",
        r#"{"code":"OK"}"#,
        r#"{"code":"OK","body":null}"#,
        r#"{"code":"OK","body":{"downloadUrls":null}}"#,
        r#"{"code":"OK","body":{"downloadUrls":{}}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":42}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":""}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":" "}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":"secret-invalid-url"}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":"file:///secret-path"}]}}"#,
        r#"{"code":"OK","body":{"downloadUrls":[{"url":"https://"}]}}"#,
    ] {
        let (endpoint, task) = serve_once("200 OK", body).await;
        let result = get_download_url_at(&client, &config, 42, &endpoint).await;
        task.await.unwrap();
        assert!(result.is_err(), "accepted malformed download response");
        let error = result.unwrap_err();
        assert!(error.contains("malformed response"), "{error}");
        assert!(!error.contains("secret-"));
    }
}

#[tokio::test]
async fn download_response_code_is_validated_and_redacted() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for (body, expected) in [
        ("{}", "malformed response"),
        ("null", "malformed response"),
        (r#"{"code":null}"#, "malformed response"),
        (r#"{"code":42}"#, "malformed response"),
        (r#"{"code":""}"#, "malformed response"),
        (
            r#"{"code":"DENIED","body":"secret-api-body"}"#,
            "API rejected",
        ),
        (
            r#"{"code":"https://signed.test/?token=secret-api-code"}"#,
            "API rejected",
        ),
    ] {
        let (endpoint, task) = serve_once("200 OK", body).await;
        let error = get_download_url_at(&client, &config, 42, &endpoint)
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("secret-"));
        assert!(!error.contains("signed.test"));
    }
}

#[tokio::test]
async fn lookup_response_errors_distinguish_not_found_from_malformed() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for (body, expected) in [
        ("[]", "not found"),
        ("", "malformed response"),
        ("secret-json-error", "malformed response"),
        ("null", "malformed response"),
        ("{}", "malformed response"),
        ("[{}]", "malformed response"),
        ("[null]", "malformed response"),
        (r#"[{"id":0}]"#, "malformed response"),
        (r#"[{"id":-1}]"#, "malformed response"),
        (r#"[{"id":1.5}]"#, "malformed response"),
        (r#"[{"id":"secret-id"}]"#, "malformed response"),
    ] {
        let (endpoint, task) = serve_once("200 OK", body).await;
        let result = get_app_id_at(&client, &config.headers, "com.example.app", &endpoint).await;
        task.await.unwrap();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("secret-"));
    }
}

#[tokio::test]
async fn network_failures_are_distinct_and_redacted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Keep the port bound without accepting: both requests deterministically time out.
    let endpoint = format!(
        "http://{}/secret-endpoint?token=secret-token",
        listener.local_addr().unwrap()
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(TokioDuration::from_millis(50))
        .build()
        .unwrap();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    let lookup = get_app_id_at(&client, &config.headers, "com.example.app", &endpoint)
        .await
        .unwrap_err();
    let download = get_download_url_at(&client, &config, 42, &endpoint)
        .await
        .unwrap_err();
    for error in [lookup, download] {
        assert!(error.contains("network error"), "{error}");
        assert!(!error.contains("secret-"));
        assert!(!error.contains("127.0.0.1"));
    }
}

#[tokio::test]
async fn http_failures_report_status_without_leaking_body() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for status in [
        "400 Bad Request",
        "403 Forbidden",
        "404 Not Found",
        "429 Too Many Requests",
        "503 Service Unavailable",
    ] {
        let code = status.split_once(' ').unwrap().0;
        for lookup in [true, false] {
            let (endpoint, task) =
                serve_once(status, "https://signed.test/app?token=secret-body").await;
            let result = if lookup {
                format!(
                    "{:?}",
                    get_app_id_at(&client, &config.headers, "com.example.app", &endpoint).await
                )
            } else {
                format!(
                    "{:?}",
                    get_download_url_at(&client, &config, 42, &endpoint).await
                )
            };
            task.await.unwrap();
            assert!(result.contains(&format!("HTTP {code}")), "{result}");
            assert!(!result.contains("secret-body"));
            assert!(!result.contains("signed.test"));
        }
    }
}

async fn serve_once(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
    let body = fixture_body(body, "com.example.app");
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    serve_raw_response(response).await
}

async fn serve_raw_response(
    response: impl Into<Vec<u8>>,
) -> (String, tokio::task::JoinHandle<String>) {
    let response = response.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        tokio::time::timeout(TokioDuration::from_secs(5), async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0, "request closed before complete body");
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(&response).await.unwrap();
            String::from_utf8(request).unwrap()
        })
        .await
        .expect("loopback request timed out")
    });
    (endpoint, task)
}

fn local_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(TokioDuration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn characterizes_lookup_http_responses() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for (status, body, expected) in [
        ("200 OK", "[{\"id\":42}]", Some(42)),
        ("200 OK", "[]", None),
        ("200 OK", "{}", None),
        ("200 OK", "[{\"id\":\"42\"}]", None),
        ("200 OK", "not JSON", None),
        ("404 Not Found", "secret", None),
    ] {
        let (endpoint, task) = serve_once(status, body).await;
        assert_eq!(
            get_app_id_at(&client, &config.headers, "com.example.app", &endpoint)
                .await
                .ok(),
            expected
        );
        let request = task.await.unwrap();
        assert!(request.starts_with("GET /api?packageNames=com.example.app HTTP/1.1\r\n"));
        assert!(request.to_lowercase().contains("rustorevercode: 11500\r\n"));
    }
}

#[tokio::test]
async fn characterizes_download_http_responses() {
    let client = local_client();
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    for (status, body, expected) in [
        (
            "200 OK",
            r#"{"code":"OK","body":{"downloadUrls":[{"url":"https://example.test/app.apk?token=secret"}]}}"#,
            Some("https://example.test/app.apk?token=secret"),
        ),
        ("200 OK", r#"{"code":"DENIED"}"#, None),
        (
            "200 OK",
            r#"{"code":"OK","body":{"downloadUrls":[]}}"#,
            None,
        ),
        ("200 OK", r#"{"code":"OK"}"#, None),
        ("200 OK", "not JSON", None),
        ("400 Bad Request", "secret", None),
    ] {
        let (endpoint, task) = serve_once(status, body).await;
        assert_eq!(
            get_download_url_at(&client, &config, 42, &endpoint)
                .await
                .ok()
                .as_deref(),
            expected
        );
        let request = task.await.unwrap();
        assert!(request.starts_with("POST /api HTTP/1.1\r\n"));
        assert!(request.to_lowercase().contains("rustorevercode: 11500\r\n"));
        let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["appId"], 42);
        assert_eq!(body["withoutSplits"], true);
    }
}

#[test]
fn invalid_device_options_are_rejected_without_echoing_values() {
    for key in ["sdk_version", "screen_density"] {
        for value in [
            "0",
            "-1",
            "+1",
            "4294967296",
            "",
            "1.5",
            "secret-device-value",
        ] {
            let result = RustoreOptions::parse(&HashMap::from([(key, value)]), None);
            assert!(result.is_err(), "accepted invalid {key}");
            let error = result.err().unwrap();
            assert!(error.contains(key));
            assert!(!error.contains("secret-device-value"));
        }
    }
    for key in ["arch", "locales", "mobile_services"] {
        for value in [
            "",
            ";",
            "x86;",
            ";x86",
            "x86;;arm64-v8a",
            " ",
            "secret-list-value\r\n",
        ] {
            let result = RustoreOptions::parse(&HashMap::from([(key, value)]), None);
            assert!(result.is_err(), "accepted invalid {key}");
            let error = result.err().unwrap();
            assert!(error.contains(key));
            assert!(!error.contains("secret-list-value"));
        }
    }
    for value in ["", "TRUE", "1", "secret-bool-value"] {
        let error = RustoreOptions::parse(&HashMap::from([("without_splits", value)]), None)
            .err()
            .unwrap();
        assert!(error.contains("without_splits"));
        assert!(!error.contains("secret-bool-value"));
    }
}

#[test]
fn invalid_version_or_user_agent_never_falls_back_or_leaks_values() {
    for value in [
        "",
        "0",
        "000",
        "-1",
        "+1",
        "1.2",
        " 11500",
        "secret-header-value",
        "11500\r\nsecret-header-value",
    ] {
        for (options, env, source) in [
            (
                HashMap::from([("rustore_version", value)]),
                Some("19000"),
                "rustore_version",
            ),
            (HashMap::new(), Some(value), "APKEEP_RUSTORE_VER"),
        ] {
            let result = RustoreOptions::parse(&options, env);
            assert!(result.is_err(), "accepted invalid version from {source}");
            let error = result.err().unwrap();
            assert!(error.contains(source));
            assert!(!error.contains("secret-header-value"));
        }
    }
    for value in ["", "secret-agent\r\ninjected", "secret-agent\0"] {
        let result = RustoreOptions::parse(&HashMap::from([("user_agent", value)]), None);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.contains("user_agent"));
        assert!(!error.contains("secret-agent"));
    }
}

#[test]
fn header_options_override_environment_and_defaults() {
    for (options, env, version, ua) in [
        (
            HashMap::from([("rustore_version", "22000"), ("user_agent", "Custom/2")]),
            Some("19000"),
            "22000",
            "Custom/2",
        ),
        (
            HashMap::new(),
            Some("19000"),
            "19000",
            "RuStore/1.78.0.1 (Android 11; SDK 30; arm64-v8a; samsung SM-N935F; en)",
        ),
        (
            HashMap::from([("rustore_version", "22000")]),
            Some("bad-secret-env"),
            "22000",
            "RuStore/1.78.0.1 (Android 11; SDK 30; arm64-v8a; samsung SM-N935F; en)",
        ),
    ] {
        let config = RustoreOptions::parse(&options, env).unwrap();
        assert_eq!(config.headers["rustorevercode"], version);
        assert_eq!(config.headers["user-agent"], ua);
    }
}

#[test]
fn device_options_change_download_request() {
    let options = HashMap::from([
        ("arch", "x86;x86_64"),
        ("sdk_version", "34"),
        ("screen_density", "480"),
        ("locales", "ru_RU;en_US"),
        ("mobile_services", "HMS"),
        ("without_splits", "false"),
    ]);
    let config = RustoreOptions::parse(&options, None).unwrap();
    let body: Value = serde_json::from_str(&config.download_request_body(73)).unwrap();
    assert_eq!(
        body,
        json!({
            "appId": 73, "firstInstall": true, "mobileServices": ["HMS"],
            "supportedAbis": ["x86", "x86_64"], "screenDensity": 480,
            "supportedLocales": ["ru_RU", "en_US"], "sdkVersion": 34,
            "withoutSplits": false, "signatureFingerprint": null
        })
    );
}

#[test]
fn characterizes_default_device_request() {
    let config = RustoreOptions::parse(&HashMap::new(), None).unwrap();
    let body: Value = serde_json::from_str(&config.download_request_body(42)).unwrap();
    assert_eq!(
        body,
        json!({
            "appId": 42, "firstInstall": true, "mobileServices": ["GMS", "HMS"],
            "supportedAbis": ["arm64-v8a"], "screenDensity": 420,
            "supportedLocales": ["en_US"], "sdkVersion": 30,
            "withoutSplits": true, "signatureFingerprint": null
        })
    );
}

#[test]
fn characterizes_default_headers() {
    let headers = RustoreOptions::parse(&HashMap::new(), None)
        .unwrap()
        .headers;
    assert_eq!(
        headers["user-agent"],
        "RuStore/1.78.0.1 (Android 11; SDK 30; arm64-v8a; samsung SM-N935F; en)"
    );
    assert_eq!(headers["content-type"], "application/json");
}

#[test]
fn sends_required_rustore_version_header() {
    assert_eq!(
        RustoreOptions::parse(&HashMap::new(), None)
            .unwrap()
            .headers
            .get("ruStoreVerCode")
            .and_then(|v| v.to_str().ok()),
        Some("11500")
    );
}

// This is a child-process CLI-driver test. The transport injection is compiled
// only into this unit-test executable, never into the shipped CLI binary.
#[tokio::test]
async fn typed_report_cli_fixture_child() {
    let Some(root) = std::env::var_os("APKEEP_REPORT_CLI_CHILD") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    if let Some(mode) = std::env::var_os("APKEEP_REPORT_CLI_MODE") {
        let mode = mode.to_str().unwrap();
        let original = root.join("out");
        std::fs::create_dir(&original).unwrap();
        let report = original.join("report.json");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let artifact = format!("{base}/apk");
        let directory = original.clone();
        let moved = root.join("moved");
        let swap = mode == "swap";
        let race = mode == "race";
        tokio::spawn(async move {
            for i in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                read_request(&mut socket).await;
                if i == 0 {
                    if swap {
                        std::fs::rename(&directory, &moved).unwrap();
                        std::fs::create_dir(&directory).unwrap();
                    }
                    if race {
                        std::fs::write(directory.join("report.json"), b"concurrent-winner")
                            .unwrap();
                    }
                }
                let body = match i {
                    0 => "[{\"id\":42}]".to_owned(),
                    1 => {
                        json!({"code":"OK","body":{"downloadUrls":[{"url":artifact}]}}).to_string()
                    }
                    _ => "synthetic-apk".to_owned(),
                };
                let body = fixture_body(&body, "com.example.ok");
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        let matches = crate::cli::app()
            .try_get_matches_from([
                "apkeep",
                "-d",
                "ru-store",
                "-a",
                "com.example.ok",
                "--report-json",
                report.to_str().unwrap(),
                original.to_str().unwrap(),
            ])
            .unwrap();
        #[cfg(target_os = "linux")]
        if let Some(sink) = std::env::var_os("APKEEP_REPORT_CLI_STDOUT") {
            // Redirect only after libtest has listed its tests. This is a
            // child-only OS sink fixture; it is never in the shipped binary.
            use std::os::fd::AsRawFd;
            let failed: std::os::fd::OwnedFd = if sink == "full" {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap()
                    .into()
            } else {
                let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
                drop(reader);
                writer.into()
            };
            assert_eq!(
                unsafe { libc::dup2(failed.as_raw_fd(), libc::STDOUT_FILENO) },
                libc::STDOUT_FILENO
            );
        }
        CLI_FIXTURE
            .scope(
                (
                    format!("{base}/lookup"),
                    format!("{base}/link"),
                    local_client(),
                ),
                crate::run(matches),
            )
            .await;
        return;
    }
    let (lookup, lookup_task) = serve_once("200 OK", "[]").await;
    let csv = root.join("apps.csv");
    let report = root.join("report.json");
    std::fs::write(
        &csv,
        "com.example.absent,\ncom.example.pinned,2\nPRIVATE/INPUT,3\ncom.example.absent,\n",
    )
    .unwrap();
    let matches = crate::cli::app()
        .try_get_matches_from([
            "apkeep",
            "-d",
            "ru-store",
            "-c",
            csv.to_str().unwrap(),
            "-v",
            "2",
            "--report-json",
            report.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .unwrap();
    CLI_FIXTURE
        .scope(
            (lookup.clone(), lookup, local_client()),
            crate::run(matches),
        )
        .await;
    lookup_task.await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn typed_report_child_cli_stdout_failure_retains_completed_apk_but_not_success() {
    for sink in ["full", "broken_pipe"] {
        let root = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "download_sources::rustore::tests::typed_report_cli_fixture_child",
                "--nocapture",
            ])
            .env("APKEEP_REPORT_CLI_CHILD", root.path())
            .env("APKEEP_REPORT_CLI_MODE", "success")
            .env("APKEEP_REPORT_CLI_STDOUT", sink)
            .env("APKEEP_RUSTORE_VER", "11500")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{sink}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        let out = root.path().join("out");
        assert_eq!(
            std::fs::read(out.join("com.example.ok.apk")).unwrap(),
            fixture("com.example.ok")
        );
        let value: Value =
            serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["results"][0]["status"], "error");
        assert_eq!(value["results"][0]["reason"], "local_io");
        assert_eq!(std::fs::read_dir(out).unwrap().count(), 2);
    }
}

#[test]
fn typed_report_child_cli_mixed_loopback_writes_every_ordered_row() {
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "download_sources::rustore::tests::typed_report_cli_fixture_child",
            "--nocapture",
        ])
        .env("APKEEP_REPORT_CLI_CHILD", root.path())
        .env("APKEEP_RUSTORE_VER", "11500")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(root.path().join("report.json")).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let rows = value["results"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["status"], "not_found");
    assert_eq!(rows[1]["reason"], "variant_unavailable");
    assert_eq!(rows[2]["reason"], "invalid_input");
    assert_eq!(rows[3]["status"], "not_found");
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE"));
}

#[test]
fn typed_report_child_cli_pins_parent_and_fails_publication_race_after_download_success() {
    for mode in ["success", "swap", "race"] {
        let root = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "download_sources::rustore::tests::typed_report_cli_fixture_child",
                "--nocapture",
            ])
            .env("APKEEP_REPORT_CLI_CHILD", root.path())
            .env("APKEEP_REPORT_CLI_MODE", mode)
            .env("APKEEP_RUSTORE_VER", "11500")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if mode == "race" { 1 } else { 0 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let out = root
            .path()
            .join(if mode == "swap" { "moved" } else { "out" });
        assert_eq!(
            std::fs::read(out.join("com.example.ok.apk")).unwrap(),
            fixture("com.example.ok")
        );
        let bytes = std::fs::read(out.join("report.json")).unwrap();
        if mode == "race" {
            assert_eq!(bytes, b"concurrent-winner");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Could not publish result report")
            );
        } else {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["success"], true);
            assert_eq!(value["results"][0]["status"], "success");
        }
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 2);
        if mode == "swap" {
            assert_eq!(
                std::fs::read_dir(root.path().join("out")).unwrap().count(),
                0
            );
        }
    }
}
