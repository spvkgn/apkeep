//! Contract tests for the shared downloader dependency, not public store probes.
use std::time::Duration;
use tokio_dl_stream_to_disk::error::ErrorKind;

#[tokio::test]
async fn stopped_redirect_response_is_never_published_as_an_artifact() {
    let out = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/file", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: file:///not-read\r\nContent-Length: 3\r\n\r\nbad",
            )
            .await
            .unwrap();
    });
    let result = fixture_download(&url, out.path(), "artifact.bin")
        .download(&None)
        .await;
    server.await.unwrap();
    assert!(
        result.is_err(),
        "a stopped 302 is not a successful artifact response"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn chunked_and_unknown_length_abort_before_over_budget_write_without_eof() {
    for chunked in [false, true] {
        for mode in 0..3 {
            let out = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/file", listener.local_addr().unwrap());
            let first_write = std::sync::Arc::new(tokio::sync::Notify::new());
            let signal = first_write.clone();
            let directory = out.path().to_path_buf();
            let disk_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let observed_disk = disk_bytes.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                let headers: &[u8] = if chunked {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nxxxx\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nxxxx"
                };
                socket.write_all(headers).await.unwrap();
                signal.notified().await;
                // Observe actual OS-visible bytes, not only an error or a
                // callback counter. The writer has accepted exactly 4 bytes.
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let size: u64 = std::fs::read_dir(&directory)
                            .unwrap()
                            .filter_map(|e| e.ok().and_then(|e| e.metadata().ok()))
                            .map(|m| m.len())
                            .sum();
                        if size == 4 {
                            observed_disk.store(size, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                        assert!(size <= 8, "actual temporary bytes exceeded cap");
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                })
                .await
                .unwrap();
                socket
                    .write_all(if chunked { b"5\r\nyyyyy\r\n" } else { b"yyyyy" })
                    .await
                    .unwrap();
                // No EOF, no terminating chunk: rejection must be immediate.
                std::future::pending::<()>().await;
                drop(socket);
            });
            let maximum_written = std::rc::Rc::new(std::cell::Cell::new(0));
            let maximum = maximum_written.clone();
            let cb: Option<Box<dyn Fn(u64)>> = Some(Box::new(move |count| {
                maximum.set(maximum.get().max(count));
                first_write.notify_one();
            }));
            let mut download = fixture_download(&url, out.path(), "artifact.bin").with_max_bytes(8);
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                match mode {
                    0 => download.download(&cb).await.map(|_| Vec::new()),
                    1 => download.download_and_return_sha256sum(&cb).await,
                    _ => download.download_and_verify_sha256(&[0; 32], &cb).await,
                }
            })
            .await;
            server.abort();
            let _ = server.await;
            assert!(result
                .expect("byte cap must abort without waiting for EOF or read timeout")
                .is_err());
            assert_eq!(
                maximum_written.get(),
                4,
                "crossing read must never reach write_all"
            );
            assert_eq!(disk_bytes.load(std::sync::atomic::Ordering::SeqCst), 4);
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        }
    }
}

#[tokio::test]
async fn byte_budget_exact_boundary_preserves_hashes_and_rechecks_after_preflight() {
    let body = b"12345678".to_vec();
    for mode in 0..3 {
        for lower_after_get in [false, true] {
            let out = tempfile::tempdir().unwrap();
            let (url, server) = serve(body.clone(), 0).await;
            let mut download = fixture_download(&url, out.path(), "artifact.bin")
                .with_max_bytes(8)
                .get()
                .await
                .unwrap();
            if lower_after_get {
                download = download.with_max_bytes(7);
            }
            let expected = Sha256::digest(&body);
            let written = std::rc::Rc::new(std::cell::Cell::new(0));
            let observed = written.clone();
            let cb: Option<Box<dyn Fn(u64)>> = Some(Box::new(move |count| observed.set(count)));
            let result = match mode {
                0 => download.download(&cb).await.map(|_| Vec::new()),
                1 => download.download_and_return_sha256sum(&cb).await,
                _ => download.download_and_verify_sha256(&expected, &cb).await,
            };
            server.await.unwrap();
            if lower_after_get {
                assert!(result.is_err());
                assert_eq!(
                    written.get(),
                    0,
                    "reduced cap must fail before tempfile/write"
                );
                assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
            } else {
                let digest = result.unwrap();
                if mode != 0 {
                    assert_eq!(digest, expected.to_vec());
                }
                assert_eq!(written.get(), 8);
                assert_eq!(
                    std::fs::read(out.path().join("artifact.bin")).unwrap(),
                    body
                );
                assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
            }
        }
    }
}

#[tokio::test]
async fn existing_regular_output_is_a_skip_without_request() {
    let out = tempfile::tempdir().unwrap();
    std::fs::write(out.path().join("artifact.bin"), b"keep").unwrap();
    for mode in 0..3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let mut download = fixture_download(&url, out.path(), "artifact.bin");
        let error = match mode {
            0 => download.download(&None).await.unwrap_err(),
            1 => download
                .download_and_return_sha256sum(&None)
                .await
                .unwrap_err(),
            _ => download
                .download_and_verify_sha256(&[0; 32], &None)
                .await
                .unwrap_err(),
        };
        assert!(matches!(error.kind(), ErrorKind::FileExists));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(out.path().join("artifact.bin")).unwrap(),
            b"keep"
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_broken_symlink_and_directory_are_errors_not_skips() {
    use std::os::unix::fs::symlink;
    for kind in 0..3 {
        for mode in 0..3 {
            let out = tempfile::tempdir().unwrap();
            let target = out.path().join("target");
            if kind == 0 {
                std::fs::write(&target, b"keep").unwrap();
            }
            let output = out.path().join("artifact.bin");
            if kind == 2 {
                std::fs::create_dir(&output).unwrap();
            } else {
                symlink(&target, &output).unwrap();
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/file", listener.local_addr().unwrap());
            let mut download = fixture_download(&url, out.path(), "artifact.bin");
            let error = match mode {
                0 => download.download(&None).await.unwrap_err(),
                1 => download
                    .download_and_return_sha256sum(&None)
                    .await
                    .unwrap_err(),
                _ => download
                    .download_and_verify_sha256(&[0; 32], &None)
                    .await
                    .unwrap_err(),
            };
            assert!(!matches!(error.kind(), ErrorKind::FileExists));
            assert!(
                tokio::time::timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
            if kind == 0 {
                assert_eq!(std::fs::read(&target).unwrap(), b"keep");
            }
            if kind == 1 {
                assert!(!target.exists());
            }
            assert_eq!(
                std::fs::symlink_metadata(&output).unwrap().is_dir(),
                kind == 2
            );
            assert!(std::fs::read_dir(out.path()).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".apkeep-")));
        }
    }
}

#[tokio::test]
async fn publication_race_never_clobbers_a_late_existing_output() {
    for mode in 0..3 {
        let out = tempfile::tempdir().unwrap();
        let (url, server) = serve(vec![0x42; 24579], 0).await;
        let output = out.path().join("artifact.bin");
        let cb: Option<Box<dyn Fn(u64)>> = Some(Box::new(move |_| {
            if !output.exists() {
                std::fs::write(&output, b"late existing output").unwrap();
            }
        }));
        let mut download = fixture_download(&url, out.path(), "artifact.bin");
        let digest = Sha256::digest(vec![0x42; 24579]);
        let error = match mode {
            0 => download.download(&cb).await.unwrap_err(),
            1 => download
                .download_and_return_sha256sum(&cb)
                .await
                .unwrap_err(),
            _ => download
                .download_and_verify_sha256(&digest, &cb)
                .await
                .unwrap_err(),
        };
        server.await.unwrap();
        assert!(matches!(error.kind(), ErrorKind::FileExists));
        assert_eq!(
            std::fs::read(out.path().join("artifact.bin")).unwrap(),
            b"late existing output"
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn concurrent_same_path_publishes_exactly_one_complete_artifact() {
    let out = tempfile::tempdir().unwrap();
    let a = vec![0xa5; 32769];
    let b = vec![0x5a; 32769];
    let (url_a, server_a) = serve(a.clone(), 0).await;
    let (url_b, server_b) = serve(b.clone(), 0).await;
    let mut first = fixture_download(&url_a, out.path(), "artifact.bin")
        .get()
        .await
        .unwrap();
    let mut second = fixture_download(&url_b, out.path(), "artifact.bin")
        .get()
        .await
        .unwrap();
    let (ra, rb) = tokio::join!(first.download(&None), second.download(&None));
    server_a.await.unwrap();
    server_b.await.unwrap();
    assert_ne!(ra.is_ok(), rb.is_ok());
    let expected = if ra.is_ok() { a } else { b };
    let error = if let Err(error) = ra {
        error
    } else {
        rb.unwrap_err()
    };
    assert!(matches!(error.kind(), ErrorKind::FileExists));
    assert_eq!(
        std::fs::read(out.path().join("artifact.bin")).unwrap(),
        expected
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn dropping_in_progress_transfer_removes_private_file_in_all_modes() {
    for mode in 0..3 {
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("keep.bin"), b"keep").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\npartial")
                .await
                .unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        let written = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = written.clone();
        let cb: Option<Box<dyn Fn(u64)>> = Some(Box::new(move |_| signal.notify_one()));
        let mut download = fixture_download(&url, out.path(), "artifact.bin");
        let mut future = Box::pin(async {
            match mode {
                0 => download.download(&cb).await.map(|_| Vec::new()),
                1 => download.download_and_return_sha256sum(&cb).await,
                _ => download.download_and_verify_sha256(&[0; 32], &cb).await,
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut future => panic!("must remain in progress: {result:?}"),
                _ = written.notified() => {}
            }
        })
        .await
        .unwrap();
        assert!(
            !out.path().join("artifact.bin").exists(),
            "in-flight data must not use final name"
        );
        let entries: Vec<_> = std::fs::read_dir(out.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|n| n.to_string_lossy().starts_with(".apkeep-")));
        drop(future);
        server.abort();
        let _ = server.await;
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read(out.path().join("keep.bin")).unwrap(), b"keep");
    }
}

#[tokio::test]
async fn unsafe_filenames_are_rejected_before_any_request() {
    for name in [
        "",
        ".",
        "..",
        "../escaped.apk",
        "sub/file",
        "sub\\file",
        "/absolute",
        "a\nfile",
        "a\0file",
        "a\u{7f}file",
    ] {
        for preflight in [false, true] {
            let out = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/file", listener.local_addr().unwrap());
            let downloader = fixture_download(&url, out.path(), name);
            let failed = tokio::time::timeout(Duration::from_millis(200), async {
                if preflight {
                    downloader.get().await.is_err()
                } else {
                    let mut downloader = downloader;
                    downloader.download(&None).await.is_err()
                }
            })
            .await
            .expect("invalid name must fail before network I/O");
            assert!(failed, "accepted unsafe name {name:?}");
            assert!(
                tokio::time::timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        }
    }
}

#[tokio::test]
async fn checksum_verification_happens_before_publication() {
    let body = b"verified artifact bytes".to_vec();
    for matching in [false, true] {
        let out = tempfile::tempdir().unwrap();
        let (url, server) = serve(body.clone(), 0).await;
        let expected = if matching {
            Sha256::digest(&body).to_vec()
        } else {
            vec![0; 32]
        };
        let mut downloader = fixture_download(&url, out.path(), "artifact.bin");
        let result = downloader
            .download_and_verify_sha256(&expected, &None)
            .await;
        server.await.unwrap();
        if matching {
            assert_eq!(result.unwrap(), expected);
            assert_eq!(
                std::fs::read(out.path().join("artifact.bin")).unwrap(),
                body
            );
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
        } else {
            assert!(result.is_err());
            assert_eq!(
                std::fs::read_dir(out.path()).unwrap().count(),
                0,
                "checksum mismatch must not leave poisoned output"
            );
        }
    }
}

#[tokio::test]
async fn malformed_checksum_is_rejected_before_request() {
    for size in [0, 1, 31, 33, 64] {
        let out = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let mut downloader = fixture_download(&url, out.path(), "artifact.bin");
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            downloader.download_and_verify_sha256(&vec![0; size], &None),
        )
        .await
        .expect("malformed digest must fail before I/O");
        assert!(result.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_dl_stream_to_disk::AsyncDownload;

// Local fixtures explicitly opt into an unguarded client. Production never
// receives an environment/cfg(test) exception to the public-network policy.
fn fixture_download(url: &str, out: &std::path::Path, name: &str) -> AsyncDownload {
    AsyncDownload::new(url, out, name).with_client(
        reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .read_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap(),
    )
}

async fn serve(body: Vec<u8>, declared_extra: usize) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/file", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut buf = [0; 1024];
            let count = socket.read(&mut buf).await.unwrap();
            assert!(count > 0 && request.len() < 8192);
            request.extend_from_slice(&buf[..count]);
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len() + declared_extra
        );
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
    });
    (endpoint, task)
}

async fn download_case(with_hash: bool, preflight: bool, body: Vec<u8>) {
    let out = tempfile::tempdir().unwrap();
    let (url, server) = serve(body.clone(), 0).await;
    let mut downloader = fixture_download(&url, out.path(), "artifact.bin");
    if preflight {
        downloader = downloader.get().await.unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        if with_hash {
            let hash = downloader
                .download_and_return_sha256sum(&None)
                .await
                .unwrap();
            assert_eq!(hash, Sha256::digest(&body).to_vec());
        } else {
            downloader.download(&None).await.unwrap();
        }
    })
    .await
    .expect("bounded loopback download");
    server.await.unwrap();
    let actual = std::fs::read(out.path().join("artifact.bin")).unwrap();
    assert!(
        actual == body,
        "success returned before all output bytes were visible: actual={}, expected={}",
        actual.len(),
        body.len()
    );
}

#[tokio::test]
async fn plain_download_flushes_complete_output_before_returning() {
    for size in [1, 8193, 1024 * 1024] {
        download_case(false, false, (0..size).map(|i| (i % 251) as u8).collect()).await;
    }
}

#[tokio::test]
async fn sha_download_without_preflight_is_initialized_and_flushed() {
    download_case(true, false, vec![0x5a; 24579]).await;
}

#[tokio::test]
async fn sha_download_with_preflight_flushes_complete_output() {
    download_case(true, true, vec![0xa5; 24579]).await;
}

#[tokio::test]
async fn existing_output_is_not_overwritten_in_either_download_mode() {
    for with_hash in [false, true] {
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("artifact.bin"), b"keep").unwrap();
        let (url, server) = serve(b"replacement".to_vec(), 0).await;
        let mut downloader = fixture_download(&url, out.path(), "artifact.bin")
            .get()
            .await
            .unwrap();
        let failed = if with_hash {
            downloader
                .download_and_return_sha256sum(&None)
                .await
                .is_err()
        } else {
            downloader.download(&None).await.is_err()
        };
        assert!(failed);
        server.await.unwrap();
        assert_eq!(
            std::fs::read(out.path().join("artifact.bin")).unwrap(),
            b"keep"
        );
    }
}

#[tokio::test]
async fn truncated_body_does_not_report_success() {
    for mode in 0..3 {
        let out = tempfile::tempdir().unwrap();
        let (url, server) = serve(b"partial".to_vec(), 1024).await;
        let mut downloader = fixture_download(&url, out.path(), "artifact.bin");
        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            match mode {
                0 => downloader.download(&None).await.is_err(),
                1 => downloader
                    .download_and_return_sha256sum(&None)
                    .await
                    .is_err(),
                _ => downloader
                    .download_and_verify_sha256(&[0; 32], &None)
                    .await
                    .is_err(),
            }
        })
        .await
        .unwrap();
        server.await.unwrap();
        assert!(failed);
        assert_eq!(
            std::fs::read_dir(out.path()).unwrap().count(),
            0,
            "failed response must leave neither final nor temporary output"
        );
    }
}

#[tokio::test]
async fn empty_body_is_rejected_without_output() {
    for with_hash in [false, true] {
        let out = tempfile::tempdir().unwrap();
        let (url, server) = serve(Vec::new(), 0).await;
        let mut downloader = fixture_download(&url, out.path(), "artifact.bin");
        let failed = if with_hash {
            downloader
                .download_and_return_sha256sum(&None)
                .await
                .is_err()
        } else {
            downloader.download(&None).await.is_err()
        };
        server.await.unwrap();
        assert!(failed, "empty response is not an artifact");
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}
