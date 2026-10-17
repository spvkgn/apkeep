use super::*;

#[tokio::test]
async fn failed_stdout_revokes_success_without_erasing_known_provider_errors() {
    let (_, mut report) = collect(
        Report::new("ru-store", "download", requests()).unwrap(),
        async {
            record("com.example.one", None, Status::Success, Reason::Complete);
            record(
                "com.example.two",
                Some("2.0"),
                Status::Error,
                Reason::Timeout,
            );
        },
    )
    .await;
    report.output_failed();
    report.finish(true);
    assert!(!report.succeeded());
    let value = json(&report);
    assert_eq!(value["success"], false);
    assert_eq!(value["results"][0]["status"], "error");
    assert_eq!(value["results"][0]["reason"], "local_io");
    assert_eq!(value["results"][1]["reason"], "timeout");
}

#[test]
fn message_bearing_io_errors_retain_outer_kind() {
    use std::io::{Error, ErrorKind};
    for (kind, expected) in [
        (ErrorKind::TimedOut, Reason::Timeout),
        (ErrorKind::PermissionDenied, Reason::LocalIo),
        (ErrorKind::Other, Reason::LocalIo),
        (ErrorKind::InvalidData, Reason::Integrity),
    ] {
        assert_eq!(
            failure_reason(&Error::new(kind, "an untyped message, not a category")),
            expected,
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn typed_reqwest_nested_in_io_stays_classifiable_but_outer_timeout_wins() {
    use std::io::{Error, ErrorKind};
    for (outer, expected) in [
        (ErrorKind::Other, Reason::Transport),
        (ErrorKind::TimedOut, Reason::Timeout),
        (ErrorKind::PermissionDenied, Reason::LocalIo),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Keep the bound socket, so refusal cannot be confused with another server.
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            assert!(stream.read(&mut buf).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let error = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(failure_reason(&Error::new(outer, error)), expected);
    }
}

#[tokio::test]
async fn legal_fdroid_components_are_not_frozen_invalid_by_reporting() {
    for (package, version) in [
        ("9legacy", "1.0-rc1"),
        ("dotless", "v+1"),
        ("org.example-app", "release_2"),
    ] {
        let (_, report) = collect(
            Report::new(
                "f-droid",
                "download",
                vec![(package.into(), Some(version.into()))],
            )
            .unwrap(),
            async {
                record(package, Some(version), Status::Success, Reason::Complete);
            },
        )
        .await;
        assert_eq!(json(&report)["results"][0]["status"], "success");
        assert_eq!(json(&report)["results"][0]["package"], package);
        assert_eq!(json(&report)["results"][0]["version"], version);
    }
}

#[tokio::test]
async fn real_transfer_failures_keep_integrity_transport_and_timeout_distinct() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_dl_stream_to_disk::AsyncDownload;
    for (reply, digest, expected) in [
        (
            Some("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad"),
            true,
            Reason::Integrity,
        ),
        (
            Some("HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nbad"),
            false,
            Reason::Integrity,
        ),
        (
            Some("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            false,
            Reason::Integrity,
        ),
        (Some("not HTTP\r\n\r\n"), false, Reason::Transport),
        (None, false, Reason::Timeout),
    ] {
        let out = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/artifact", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            assert!(socket.read(&mut buf).await.unwrap() > 0);
            if let Some(reply) = reply {
                socket.write_all(reply.as_bytes()).await.unwrap();
            } else {
                std::future::pending::<()>().await;
            }
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let mut transfer = AsyncDownload::new(&url, out.path(), "app.apk").with_client(client);
        let err = if digest {
            transfer
                .download_and_verify_sha256(&[0; 32], &None)
                .await
                .unwrap_err()
        } else {
            transfer.download(&None).await.unwrap_err()
        };
        server.abort();
        let _ = server.await;
        assert_eq!(download_reason(&err), expected, "{reply:?}: {err:?}");
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn provider_rejected_safe_looking_inputs_are_not_serialized() {
    let (_, report) = collect(
        Report::new(
            "apk-pure",
            "download",
            vec![("com.example.app".into(), Some("..".into()))],
        )
        .unwrap(),
        async {
            record(
                "com.example.app",
                Some(".."),
                Status::Error,
                Reason::InvalidInput,
            );
        },
    )
    .await;
    let value = json(&report);
    assert!(value["results"][0]["package"].is_null());
    assert!(value["results"][0]["version"].is_null());
}

#[tokio::test]
async fn nested_item_scopes_and_retries_do_not_mix_and_bool_is_not_success() {
    let (_, report) = collect(
        Report::new("ru-store", "download", requests()).unwrap(),
        async {
            let a = observe("com.example.one", None, async {
                error((), Reason::Timeout);
                tokio::task::yield_now().await;
                complete();
                true
            });
            let b = observe("com.example.two", Some("2.0"), async {
                tokio::task::yield_now().await;
                true // no publication evidence
            });
            tokio::join!(a, b);
        },
    )
    .await;
    let value = json(&report);
    assert_eq!(value["results"][0]["status"], "success");
    assert_eq!(value["results"][1]["reason"], "unperformed");
}

#[tokio::test]
async fn supported_version_tokens_remain_safe_in_report() {
    let req = vec![("com.example.app".into(), Some("1.0(beta)[2]".into()))];
    let (_, report) = collect(Report::new("apk-pure", "download", req).unwrap(), async {
        record(
            "com.example.app",
            Some("1.0(beta)[2]"),
            Status::Success,
            Reason::Complete,
        );
    })
    .await;
    assert_eq!(json(&report)["results"][0]["status"], "success");
    assert_eq!(json(&report)["results"][0]["version"], "1.0(beta)[2]");
}

fn requests() -> Vec<(String, Option<String>)> {
    vec![
        ("com.example.one".into(), None),
        ("com.example.two".into(), Some("2.0".into())),
    ]
}
fn json(report: &Report) -> serde_json::Value {
    serde_json::from_slice(&report.json_bytes().unwrap()).unwrap()
}
#[tokio::test]
async fn input_order_and_concurrent_scopes_do_not_mix() {
    let one = collect(
        Report::new("ru-store", "download", requests()).unwrap(),
        async {
            record(
                "com.example.two",
                Some("2.0"),
                Status::NotFound,
                Reason::PackageAbsent,
            );
            tokio::task::yield_now().await;
            record("com.example.one", None, Status::Success, Reason::Complete);
        },
    );
    let two = collect(
        Report::new("f-droid", "download", requests()).unwrap(),
        async {
            record("com.example.one", None, Status::Error, Reason::Transport);
            tokio::task::yield_now().await;
            record(
                "com.example.two",
                Some("2.0"),
                Status::Unavailable,
                Reason::VariantUnavailable,
            );
        },
    );
    let ((_, mut a), (_, mut b)) = tokio::join!(one, two);
    a.finish(false);
    b.finish(false);
    let a = json(&a);
    let b = json(&b);
    assert_eq!(a["results"][0]["status"], "success");
    assert_eq!(a["results"][1]["status"], "not_found");
    assert_eq!(b["results"][0]["status"], "error");
    assert_eq!(b["results"][1]["reason"], "variant_unavailable");
    assert_eq!(a["results"][0]["index"], 0);
    assert_eq!(a["success"], false);
}
#[tokio::test]
async fn aggregate_true_cannot_certify_unperformed_items() {
    let (_, mut report) = collect(
        Report::new("f-droid", "download", requests()).unwrap(),
        async {},
    )
    .await;
    report.finish(true);
    assert_eq!(json(&report)["success"], false);
    assert_eq!(json(&report)["results"][0]["reason"], "unperformed");
}
#[tokio::test]
async fn exact_duplicates_preserve_rows_without_losing_version_keys() {
    let mut req = requests();
    req.push(req[0].clone());
    let (_, mut report) = collect(Report::new("ru-store", "download", req).unwrap(), async {
        record("com.example.one", None, Status::Success, Reason::Complete);
        record("com.example.two", None, Status::Success, Reason::Complete);
    })
    .await;
    report.finish(true);
    let value = json(&report);
    assert_eq!(value["results"].as_array().unwrap().len(), 3);
    assert_eq!(value["results"][0]["status"], "success");
    assert_eq!(value["results"][2]["status"], "success");
    assert_eq!(value["results"][1]["reason"], "unperformed");
    assert_eq!(value["success"], false);
}
#[tokio::test]
async fn invalid_identifiers_and_versions_are_not_echoed() {
    let (_, report) = collect(
        Report::new(
            "f-droid",
            "download",
            vec![("secret\u{1b}[0m".into(), Some("private/token".into()))],
        )
        .unwrap(),
        async {
            record(
                "secret\u{1b}[0m",
                Some("private/token"),
                Status::Success,
                Reason::Complete,
            );
        },
    )
    .await;
    let bytes = report.json_bytes().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("secret") && !text.contains("private/token"));
    let value = json(&report);
    assert!(value["results"][0]["package"].is_null());
    assert!(value["results"][0]["version"].is_null());
    assert_eq!(value["results"][0]["reason"], "invalid_input");
}
#[tokio::test]
async fn inconsistent_or_contradictory_outcomes_fail_closed() {
    let (_, mut report) = collect(
        Report::new("ru-store", "download", requests()).unwrap(),
        async {
            record("com.example.one", None, Status::NotFound, Reason::Transport);
            record(
                "com.example.two",
                Some("2.0"),
                Status::Success,
                Reason::Complete,
            );
            record(
                "com.example.two",
                Some("2.0"),
                Status::Error,
                Reason::Integrity,
            );
        },
    )
    .await;
    report.finish(true);
    assert_eq!(json(&report)["results"][0]["reason"], "unperformed");
    assert_eq!(json(&report)["results"][1]["status"], "error");
    assert_eq!(json(&report)["success"], false);
}
#[tokio::test]
async fn successful_items_allow_explicit_final_success() {
    let (_, mut report) = collect(
        Report::new("ru-store", "download", requests()).unwrap(),
        async {
            record("com.example.one", None, Status::Success, Reason::Complete);
            record(
                "com.example.two",
                Some("2.0"),
                Status::Success,
                Reason::Complete,
            );
        },
    )
    .await;
    report.finish(true);
    assert_eq!(json(&report)["success"], true);
    assert_eq!(json(&report)["schema_version"], 1);
}
#[test]
fn atomic_report_never_overwrites_existing_or_redirects_after_parent_rename() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    std::fs::create_dir(&original).unwrap();
    let pinned = tokio_dl_stream_to_disk::OutputDirectory::open(&original).unwrap();
    let moved = root.path().join("moved");
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    let report = Report::new("f-droid", "download", requests()).unwrap();
    report.write_to(&pinned, "result.json").unwrap();
    assert!(!original.join("result.json").exists());
    let bytes = std::fs::read(moved.join("result.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert!(report.write_to(&pinned, "result.json").is_err());
    assert_eq!(std::fs::read(moved.join("result.json")).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
    for name in [
        "",
        ".",
        "..",
        "../escape.json",
        "/absolute",
        "a/b",
        "a\\b",
        "bad\nname",
    ] {
        assert!(report.write_to(&pinned, name).is_err());
    }
}

#[cfg(unix)]
#[test]
fn report_does_not_follow_existing_symlink() {
    let root = tempfile::tempdir().unwrap();
    let pinned = tokio_dl_stream_to_disk::OutputDirectory::open(root.path()).unwrap();
    let victim = root.path().join("victim");
    std::fs::write(&victim, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, root.path().join("report.json")).unwrap();
    assert!(Report::new("ru-store", "download", requests())
        .unwrap()
        .write_to(&pinned, "report.json")
        .is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn report_input_limits_and_context_are_strict() {
    assert!(Report::new("evil", "download", requests()).is_err());
    assert!(Report::new("f-droid", "oauth-token", requests()).is_err());
    assert!(Report::new(
        "f-droid",
        "download",
        vec![("com.example.app".into(), None); 65537]
    )
    .is_err());
    record("com.example.app", None, Status::Error, Reason::Unperformed); // no active scope is safe
}

#[test]
fn report_serialization_limit_is_enforced_without_partial_publication() {
    let package = format!("com.{}", "a".repeat(236));
    let report = Report::new(
        "ru-store",
        "download",
        vec![(package, Some("1".repeat(200))); 65536],
    )
    .unwrap();
    assert_eq!(
        report.json_bytes().unwrap_err(),
        "result report size limit exceeded"
    );
    let root = tempfile::tempdir().unwrap();
    let directory = tokio_dl_stream_to_disk::OutputDirectory::open(root.path()).unwrap();
    assert!(report.write_to(&directory, "report.json").is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
