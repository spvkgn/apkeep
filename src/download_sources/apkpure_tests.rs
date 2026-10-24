use super::*;

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn ancestor_swap_during_apkpure_metadata_keeps_artifact_in_original_directory() {
    let server = Server::new(200, |base| format!("(APKJ..{base}/artifact\")"), 200);
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("out");
    let moved = root.path().join("moved");
    let victim = root.path().join("victim");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&victim).unwrap();
    let endpoint = |_: &str| {
        std::fs::rename(&original, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &original).unwrap();
        Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap())
    };
    assert!(
        injected_download_apps_using(
            vec![("com.example.fixture".into(), None)],
            1,
            0,
            &original,
            acknowledged(),
            &fixture_client(),
            &endpoint
        )
        .await
    );
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(moved.join("com.example.fixture.apk")).unwrap(),
        b"offline synthetic artifact\0\xff"
    );
    assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn default_artifact_path_rejects_private_and_credential_urls_without_fetching() {
    for malicious in [
        "http://169.254.169.254/private",
        "http://user:PRIVATE_TOKEN@example.com/private",
    ] {
        let server = Server::new(200, |_| format!("APKJ..{malicious}"), 200);
        let client = fixture_client();
        let response = client
            .get(format!("{}/metadata", server.base))
            .send()
            .await
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        assert!(
            !download_from_response(
                response,
                &download_regex(None),
                "com.example.app".into(),
                out.path(),
                Rc::new(MultiProgress::new()),
                None
            )
            .await
        );
        assert_eq!(server.paths(), ["/metadata"]);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
    let client = fixture_client();
    let response = client
        .get(format!("{}/metadata", server.base))
        .send()
        .await
        .unwrap();
    let out = tempfile::tempdir().unwrap();
    assert!(
        !download_from_response(
            response,
            &download_regex(None),
            "com.example.app".into(),
            out.path(),
            Rc::new(MultiProgress::new()),
            None
        )
        .await
    );
    assert_eq!(server.paths(), ["/metadata"]);
}

async fn injected_download_apps_using(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep: u64,
    out: &Path,
    options: HashMap<&str, &str>,
    client: &Client,
    endpoint: Endpoint<'_>,
) -> bool {
    download_apps_using(
        apps,
        parallel,
        sleep,
        out,
        options,
        DownloadTransport {
            metadata: client,
            endpoint,
            artifact: Some(client),
        },
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
    let client = metadata_client().unwrap();
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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn headers_have_stable_defaults() {
    let headers = http_headers(&HashMap::new());
    assert_eq!(headers.len(), 4);
    assert_eq!(headers["x-cv"], "3172501");
    assert_eq!(headers["x-sv"], "29");
    assert_eq!(headers["x-gp"], "1");
    assert_eq!(
        headers["x-abis"],
        "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64"
    );
}

#[test]
fn headers_translate_semicolon_separated_abis_without_reordering() {
    let headers = http_headers(&HashMap::from([("arch", "x86_64;arm64-v8a;x86")]));
    assert_eq!(headers["x-abis"], "x86_64,arm64-v8a,x86");
    assert_eq!(headers.len(), 4);
}

#[test]
fn invalid_header_values_are_omitted_without_panicking() {
    for arch in ["arm64-v8a\r\nx-injected: yes", "x86\n", "x86\0"] {
        let headers = http_headers(&HashMap::from([("arch", arch)]));
        assert!(!headers.contains_key("x-abis"));
        assert_eq!(headers.len(), 3);
        assert_eq!(headers["x-gp"], "1");
        assert!(!headers.contains_key("x-injected"));
    }
}

#[test]
fn header_parser_currently_preserves_empty_and_unvalidated_abi_values() {
    // Characterization, not an ABI-validation security guarantee.
    for (arch, expected) in [
        ("", ""),
        ("x86;;arm64-v8a", "x86,,arm64-v8a"),
        ("unknown", "unknown"),
    ] {
        assert_eq!(
            http_headers(&HashMap::from([("arch", arch)]))["x-abis"],
            expected
        );
    }
}

#[test]
fn production_url_regex_selects_first_apk_or_xapk_with_stable_capture_indices() {
    let re = download_regex(None);
    for kind in ["APKJ", "XAPKJ"] {
        let body = format!("{kind}..https://cdn.example.org/file.apk?token=fake&v=1\" APKJ..https://other.example.org/second.apk\"");
        let captures = re.captures(&body).unwrap();
        assert_eq!(&captures[1], kind);
        assert_eq!(
            &captures[2],
            "https://cdn.example.org/file.apk?token=fake&v=1"
        );
    }
    assert!(re
        .captures("APKJ..ftp://cdn.example.org/file.apk")
        .is_none());
    assert!(re.captures("no download record").is_none());
}

#[test]
fn production_url_regex_characterizes_unsafe_urls_and_accepts_ephemeral_ports() {
    // These assertions document inherited parsing gaps, not desired URL policy.
    let re = download_regex(None);
    for url in [
        "http://127.0.0.1/internal",
        "http://169.254.169.254/latest/meta-data/",
        "http://user:fake@example.org/file.apk",
    ] {
        assert_eq!(&re.captures(&format!("APKJ..{url}\"")).unwrap()[2], url);
    }
    assert_eq!(
        &re.captures("APKJ..http://127.0.0.1:12345/file.apk\"")
            .unwrap()[2],
        "http://127.0.0.1:12345/file.apk"
    );
    assert_eq!(
        &re.captures("APKJ..https://example.org/file.apk)").unwrap()[2],
        "https://example.org/file.apk)"
    );
}

#[test]
fn versions_url_preserves_normal_package_and_locale_without_network() {
    let url = versions_url("com.example.fixture").unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("api.pureapk.com"));
    assert_eq!(url.path(), "/m/v3/cms/app_version");
    let pairs = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        pairs,
        [
            ("hl".to_owned(), "en-US".to_owned()),
            ("package_name".to_owned(), "com.example.fixture".to_owned())
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn empty_download_batch_is_not_success() {
    let out = tempfile::tempdir().unwrap();
    let result = download_apps(
        Vec::new(),
        1,
        0,
        out.path(),
        HashMap::from([("acknowledge_dangers", "true")]),
    )
    .await;
    assert!(!result);
}

#[tokio::test(flavor = "current_thread")]
async fn empty_version_listing_is_not_success() {
    let result = list_versions(Vec::new(), HashMap::new()).await;
    assert!(!result);
}

#[test]
fn versions_url_rejects_query_fragment_and_path_injection() {
    for app in [
        "com.example.fixture&hl=xx",
        "com.example.fixture#fragment",
        "../escape",
        "com.example/fixture",
        "com.example%2ffixture",
        "com.example\nsecret",
    ] {
        assert!(versions_url(app).is_err(), "must reject unsafe package");
    }
}

#[test]
fn requested_version_regex_escapes_metacharacters_and_ignores_other_versions() {
    let version = "1.2+[beta](rc)";
    let re = download_regex(Some(version));
    let body = format!(":9.9:(APKJ..https://example.org/other.apk\") :{version}:(XAPKJ..https://example.org/wanted.xapk\")");
    let captures = re.captures(&body).unwrap();
    assert_eq!(&captures[1], "XAPKJ");
    assert_eq!(&captures[2], "https://example.org/wanted.xapk");
    assert!(re
        .captures(":1x2beta:(APKJ..https://example.org/other.apk\")")
        .is_none());
    assert!(download_regex(Some("1.0"))
        .captures(":11.0:(APKJ..https://example.org/other.apk\")")
        .is_none());
}

#[test]
fn requested_version_regex_does_not_cross_record_boundaries() {
    let re = download_regex(Some("1.0"));
    let body = ":1.0:(no URL in this record) :2.0:(APKJ..https://example.org/two.apk\")";
    assert!(
        re.captures(body).is_none(),
        "must not download another version"
    );
}

#[test]
fn requested_version_regex_requires_exact_left_token_boundary() {
    for prefix in ["v", "alpha", "2.", "_", "+", "-"] {
        let body = format!(":{prefix}1.0:(APKJ..https://example.org/wrong.apk\")");
        assert!(
            download_regex(Some("1.0")).captures(&body).is_none(),
            "prefix {prefix}"
        );
    }
}

#[test]
fn versions_regex_requires_at_least_forty_hex_digits() {
    let re = versions_regex();
    let hex = "0123456789abcdef0123456789abcdef01234567";
    let body = format!(
        "1.0:({hex}) 2.0-beta:({hex}ab) 3.0:({}) 4.0:({})",
        &hex[..39],
        "z".repeat(40)
    );
    let found = re
        .captures_iter(&body)
        .map(|caps| caps[1].to_owned())
        .collect::<Vec<_>>();
    assert_eq!(found, ["1.0", "2.0-beta"]);
}

#[test]
fn versions_regex_preserves_complete_safe_version_tokens() {
    let re = versions_regex();
    let hex = "a".repeat(40);
    let body = format!("1.0_rc:({hex}) 2.0+build:({hex})");
    let found = re
        .captures_iter(&body)
        .map(|caps| caps[1].to_owned())
        .collect::<Vec<_>>();
    assert_eq!(found, ["1.0_rc", "2.0+build"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_unsafe_output_name_before_path_construction() {
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("downloads");
    std::fs::create_dir(&out).unwrap();
    assert!(!consume(&server, &out, "../escaped").await);
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    assert!(!root.path().join("escaped.apk").exists());
    assert_eq!(server.paths(), ["/metadata"]);
}

// A real loopback HTTP server. Nonblocking accept, bounded socket IO and Drop join
// make both a missing request and a regression safe for the test runner.
struct Server {
    base: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    paths: Arc<Mutex<Vec<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(
        metadata_status: u16,
        metadata: impl FnOnce(&str) -> String,
        artifact_status: u16,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let metadata = metadata(&base);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_paths = Arc::clone(&paths);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !worker_stop.load(std::sync::atomic::Ordering::SeqCst)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let Some(path) = read_path(&mut socket) else {
                            continue;
                        };
                        worker_paths.lock().unwrap().push(path.clone());
                        let (status, body) = if path == "/metadata" {
                            (metadata_status, metadata.as_bytes())
                        } else {
                            (
                                artifact_status,
                                b"offline synthetic artifact\0\xff".as_slice(),
                            )
                        };
                        let head = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        let _ = socket.write_all(head.as_bytes());
                        let _ = socket.write_all(body);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(err) => panic!("fixture accept: {err}"),
                }
            }
        });
        Self {
            base,
            stop,
            paths,
            worker: Some(worker),
        }
    }

    fn raw(reply: Vec<u8>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_paths = Arc::clone(&paths);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !worker_stop.load(std::sync::atomic::Ordering::SeqCst)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        if let Some(path) = read_path(&mut socket) {
                            worker_paths.lock().unwrap().push(path);
                            thread::sleep(delay);
                            let _ = socket.write_all(&reply);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(err) => panic!("fixture accept: {err}"),
                }
            }
        });
        Self {
            base,
            stop,
            paths,
            worker: Some(worker),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn read_path(socket: &mut TcpStream) -> Option<String> {
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buf = [0; 1024];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") && bytes.len() < 8192 {
        match socket.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8(bytes)
        .ok()?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

async fn consume(server: &Server, out: &Path, app: &str) -> bool {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client
        .get(format!("{}/metadata", server.base))
        .send()
        .await
        .unwrap();
    // Use the shipped regex, including its real capture numbering. The existing
    // private Response argument is the only seam; endpoints are never overridden.
    let re = download_regex(None);
    tokio::time::timeout(
        Duration::from_secs(5),
        download_from_response(
            response,
            &re,
            app.to_owned(),
            out,
            Rc::new(MultiProgress::with_draw_target(
                indicatif::ProgressDrawTarget::hidden(),
            )),
            Some(&client),
        ),
    )
    .await
    .expect("bounded loopback download")
}

#[tokio::test(flavor = "current_thread")]
async fn response_downloads_apk_and_xapk_with_immediately_exact_fixture_bytes() {
    for (kind, extension) in [("APKJ", "apk"), ("XAPKJ", "xapk")] {
        let server = Server::new(200, |base| format!("{kind}..{base}/artifact"), 200);
        let out = tempfile::tempdir().unwrap();
        assert!(consume(&server, out.path(), "com.example.fixture@1").await);
        let path = out
            .path()
            .join(format!("com.example.fixture@1.{extension}"));
        // The shared downloader must finish publication before success returns.
        let expected = b"offline synthetic artifact\0\xff";
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
        assert_eq!(server.paths(), ["/metadata", "/artifact"]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn response_metadata_http_error_creates_no_artifact() {
    let server = Server::new(503, |base| format!("APKJ..{base}/artifact"), 200);
    let out = tempfile::tempdir().unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert_eq!(server.paths(), ["/metadata"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_oversized_metadata_without_artifact_request() {
    let server = Server::new(
        200,
        |base| format!("{} APKJ..{base}/artifact", "x".repeat(2 * 1024 * 1024 + 1)),
        200,
    );
    let out = tempfile::tempdir().unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert_eq!(server.paths(), ["/metadata"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_without_url_creates_no_artifact() {
    let server = Server::new(200, |_| "no matching download URL".to_owned(), 200);
    let out = tempfile::tempdir().unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert_eq!(server.paths(), ["/metadata"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_artifact_http_error_creates_no_file() {
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 404);
    let out = tempfile::tempdir().unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert_eq!(server.paths(), ["/metadata", "/artifact"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_preserves_existing_directory_and_reports_failure() {
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
    let out = tempfile::tempdir().unwrap();
    let destination = out.path().join("com.example.fixture.apk");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("marker"), b"preserved").unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert!(destination.is_dir());
    assert_eq!(
        std::fs::read(destination.join("marker")).unwrap(),
        b"preserved"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    assert_eq!(server.paths(), ["/metadata"]);
}

#[tokio::test(flavor = "current_thread")]
async fn response_preserves_existing_file_even_when_network_has_new_bytes() {
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
    let out = tempfile::tempdir().unwrap();
    let file = out.path().join("com.example.fixture.apk");
    std::fs::write(&file, b"original marker").unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read(file).unwrap(), b"original marker");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    // Existing bytes are preserved but rejected; no artifact is fetched.
    assert_eq!(server.paths(), ["/metadata"]);
}

fn fixture_client() -> Client {
    Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_millis(100))
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap()
}

fn acknowledged() -> HashMap<&'static str, &'static str> {
    HashMap::from([("acknowledge_dangers", "true")])
}

#[test]
fn checked_names_preserve_safe_version_and_multiple_arch_suffixes() {
    assert_eq!(
        checked_name(
            "com.example.fixture",
            Some("1.0+[rc](2)"),
            Some("x86;arm64-v8a")
        )
        .unwrap(),
        "com.example.fixture@1.0+[rc](2)@x86;arm64-v8a"
    );
    assert_eq!(checked_name("android", None, None).unwrap(), "android");
    assert_eq!(
        checked_name("com.example.fixture", None, Some("x86_64")).unwrap(),
        "com.example.fixture@x86_64"
    );
}

#[test]
fn checked_names_reject_unsafe_components_and_overlong_filenames() {
    for unsafe_value in [
        "",
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "a@b",
        "a\nSECRET",
        "a\0b",
        "a%2fb",
        "a?b",
        "a#b",
        "a:b",
        "a b",
        "аpp",
    ] {
        assert!(checked_name(unsafe_value, None, None).is_err());
        assert!(checked_name("com.example.fixture", Some(unsafe_value), None).is_err());
        assert!(checked_name("com.example.fixture", None, Some(unsafe_value)).is_err());
    }
    for unsafe_arch in ["x86;;arm64-v8a", ";x86", "x86;", "x86.arm64", "x86+arm64"] {
        assert!(checked_name("com.example.fixture", None, Some(unsafe_arch)).is_err());
    }
    assert!(checked_name(&"a".repeat(201), None, None).is_err());
    assert!(checked_name("com.example.fixture", Some(&"v".repeat(121)), None).is_err());
    assert!(checked_name("com.example.fixture", None, Some(&"a".repeat(101))).is_err());
    assert!(checked_name(&"a".repeat(200), Some(&"v".repeat(120)), None).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_components_never_reach_endpoint_in_download_or_listing() {
    let client = fixture_client();
    let out = tempfile::tempdir().unwrap();
    let forbidden =
        |_: &str| -> Result<Url, &'static str> { panic!("invalid input reached endpoint") };
    let apps = vec![
        ("../unsafe".to_owned(), None),
        (
            "com.example.fixture".to_owned(),
            Some("../version".to_owned()),
        ),
    ];
    assert!(
        !injected_download_apps_using(
            apps.clone(),
            2,
            0,
            out.path(),
            acknowledged(),
            &client,
            &forbidden
        )
        .await
    );
    assert!(!list_versions_using(apps, HashMap::new(), &client, &forbidden).await);
    for arch in ["../arch", "x86;;arm64-v8a", "\nSECRET"] {
        let apps = vec![("com.example.fixture".to_owned(), None)];
        let mut options = acknowledged();
        options.insert("arch", arch);
        assert!(
            !injected_download_apps_using(
                apps.clone(),
                1,
                0,
                out.path(),
                options.clone(),
                &client,
                &forbidden
            )
            .await
        );
        assert!(!list_versions_using(apps, options, &client, &forbidden).await);
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn zero_parallelism_and_missing_acknowledgement_are_false_without_network() {
    let client = fixture_client();
    let out = tempfile::tempdir().unwrap();
    let forbidden =
        |_: &str| -> Result<Url, &'static str> { panic!("invalid batch reached endpoint") };
    let apps = vec![("com.example.fixture".to_owned(), None)];
    assert!(
        !injected_download_apps_using(
            apps.clone(),
            0,
            0,
            out.path(),
            acknowledged(),
            &client,
            &forbidden
        )
        .await
    );
    assert!(
        !injected_download_apps_using(apps, 1, 0, out.path(), HashMap::new(), &client, &forbidden)
            .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn typed_report_download_batch_runs_every_item_and_aggregates_failures() {
    for parallel in [1, 3] {
        let good = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
        let bad = Server::new(503, |_| "unavailable".to_owned(), 200);
        let called = std::cell::RefCell::new(Vec::new());
        let endpoint = |app: &str| {
            called.borrow_mut().push(app.to_owned());
            let server = if app == "com.example.failure" {
                &bad
            } else {
                &good
            };
            Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap())
        };
        let apps = vec![
            ("com.example.failure".to_owned(), None),
            ("../unsafe".to_owned(), None),
            ("com.example.success".to_owned(), None),
            ("com.example.after".to_owned(), None),
        ];
        let out = tempfile::tempdir().unwrap();
        let report = crate::results::Report::new("apk-pure", "download", apps.clone()).unwrap();
        let (ok, report) = crate::results::collect(
            report,
            injected_download_apps_using(
                apps,
                parallel,
                0,
                out.path(),
                acknowledged(),
                &fixture_client(),
                &endpoint,
            ),
        )
        .await;
        assert!(!ok);
        let value: serde_json::Value =
            serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
        assert_eq!(value["results"][0]["reason"], "transport");
        assert_eq!(value["results"][1]["reason"], "invalid_input");
        assert_eq!(value["results"][2]["status"], "success");
        assert_eq!(value["results"][3]["status"], "success");
        for app in ["com.example.success", "com.example.after"] {
            assert_eq!(
                std::fs::read(out.path().join(format!("{app}.apk"))).unwrap(),
                b"offline synthetic artifact\0\xff"
            );
        }
        assert_eq!(called.borrow().len(), 3);
        assert_eq!(bad.paths(), ["/metadata"]);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 2);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn download_batch_success_preserves_safe_version_arch_filename() {
    let server = Server::new(
        200,
        |base| format!(":1.0+rc:(APKJ..{base}/artifact\")"),
        200,
    );
    let endpoint = |_: &str| Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap());
    let out = tempfile::tempdir().unwrap();
    let mut options = acknowledged();
    options.insert("arch", "x86;arm64-v8a");
    let apps = vec![("com.example.fixture".to_owned(), Some("1.0+rc".to_owned()))];
    assert!(
        injected_download_apps_using(
            apps,
            1,
            1,
            out.path(),
            options,
            &fixture_client(),
            &endpoint
        )
        .await
    );
    assert_eq!(
        std::fs::read(
            out.path()
                .join("com.example.fixture@1.0+rc@x86;arm64-v8a.apk")
        )
        .unwrap(),
        b"offline synthetic artifact\0\xff"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn listing_batch_runs_every_item_and_fails_on_empty_metadata() {
    for format in ["plaintext", "json"] {
        let good = Server::new(
            200,
            |_| {
                format!(
                    "1.0:({}) 2.0+rc:({}) 1.0:({})",
                    "a".repeat(40),
                    "b".repeat(40),
                    "a".repeat(40)
                )
            },
            200,
        );
        let empty = Server::new(200, |_| "not version metadata".to_owned(), 200);
        let bad = Server::new(503, |_| "unavailable".to_owned(), 200);
        let called = std::cell::RefCell::new(Vec::new());
        let endpoint = |app: &str| {
            called.borrow_mut().push(app.to_owned());
            let server = match app {
                "com.example.empty" => &empty,
                "com.example.failure" => &bad,
                _ => &good,
            };
            Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap())
        };
        let apps = vec![
            ("com.example.failure".to_owned(), None),
            ("../unsafe".to_owned(), None),
            ("com.example.empty".to_owned(), None),
            ("com.example.after".to_owned(), None),
        ];
        assert!(
            !list_versions_using(
                apps,
                HashMap::from([("output_format", format)]),
                &fixture_client(),
                &endpoint
            )
            .await
        );
        assert_eq!(called.borrow().len(), 3);
        assert_eq!(good.paths(), ["/metadata"]);
        assert!(
            list_versions_using(
                vec![("com.example.after".to_owned(), None)],
                HashMap::from([("output_format", format)]),
                &fixture_client(),
                &endpoint
            )
            .await
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn network_connect_errors_are_false_for_download_and_listing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = Url::parse(&format!(
        "http://{}/secret-token",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    drop(listener);
    let endpoint = |_: &str| Ok(url.clone());
    let apps = vec![("com.example.fixture".to_owned(), None)];
    let out = tempfile::tempdir().unwrap();
    assert!(
        !injected_download_apps_using(
            apps.clone(),
            1,
            0,
            out.path(),
            acknowledged(),
            &fixture_client(),
            &endpoint
        )
        .await
    );
    assert!(!list_versions_using(apps, HashMap::new(), &fixture_client(), &endpoint).await);
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_body_errors_are_results_not_panics() {
    let server = Server::raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\ntruncated".to_vec(),
        Duration::ZERO,
    );
    let endpoint = |_: &str| Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap());
    let apps = vec![("com.example.fixture".to_owned(), None)];
    let out = tempfile::tempdir().unwrap();
    assert!(
        !injected_download_apps_using(
            apps.clone(),
            1,
            0,
            out.path(),
            acknowledged(),
            &fixture_client(),
            &endpoint
        )
        .await
    );
    assert!(!list_versions_using(apps, HashMap::new(), &fixture_client(), &endpoint).await);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_without_content_length_still_obeys_byte_limit() {
    let mut reply = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    reply.extend(vec![b'x'; MAX_METADATA_BYTES + 1]);
    let server = Server::raw(reply, Duration::ZERO);
    let response = fixture_client()
        .get(format!("{}/metadata", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        read_metadata(response).await.unwrap_err(),
        "metadata exceeds size limit"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_at_byte_limit_is_accepted_with_lossy_binary_fields() {
    let mut reply = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    reply.extend(vec![b'x'; MAX_METADATA_BYTES - 1]);
    reply.push(0xff);
    let server = Server::raw(reply, Duration::ZERO);
    let response = fixture_client()
        .get(format!("{}/metadata", server.base))
        .send()
        .await
        .unwrap();
    let body = read_metadata(response).await.unwrap();
    assert!(body.ends_with('\u{fffd}'));
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_client_deadline_bounds_stalled_response() {
    let server = Server::raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::from_millis(350),
    );
    let endpoint = |_: &str| Ok(Url::parse(&format!("{}/metadata", server.base)).unwrap());
    let started = Instant::now();
    let result = request_metadata(
        &fixture_client(),
        &endpoint,
        "com.example.fixture",
        HeaderMap::new(),
    )
    .await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn requested_version_regex_cannot_cross_an_unclosed_record_or_match_suffix() {
    for body in [
        ":1.0:(no URL :2.0:(APKJ..https://example.org/wrong.apk\")",
        ":1.0:(no URL)\n:1.0.1:(APKJ..https://example.org/wrong.apk\")",
        ":1.0+rc:(APKJ..https://example.org/wrong.apk\")",
    ] {
        assert!(download_regex(Some("1.0")).captures(body).is_none());
    }
    assert!(download_regex(Some("1.0"))
        .captures("1.0:(APKJ..https://example.org/correct.apk\")")
        .is_some());
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn response_does_not_treat_symlink_as_successful_skip() {
    let server = Server::new(200, |base| format!("APKJ..{base}/artifact"), 200);
    let out = tempfile::tempdir().unwrap();
    let marker = out.path().join("marker");
    std::fs::write(&marker, b"original").unwrap();
    std::os::unix::fs::symlink(&marker, out.path().join("com.example.fixture.apk")).unwrap();
    assert!(!consume(&server, out.path(), "com.example.fixture").await);
    assert_eq!(std::fs::read(&marker).unwrap(), b"original");
    assert_eq!(server.paths(), ["/metadata"]);
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_artifact_body_retries_fail_without_partial_files() {
    let artifact = Server::raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\ntruncated".to_vec(),
        Duration::ZERO,
    );
    let metadata = Server::new(200, |_| format!("APKJ..{}/artifact", artifact.base), 200);
    let out = tempfile::tempdir().unwrap();
    assert!(!consume(&metadata, out.path(), "com.example.fixture").await);
    assert_eq!(artifact.paths(), ["/artifact", "/artifact", "/artifact"]);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn requested_version_without_url_does_not_fetch_next_versions_artifact() {
    let metadata = Server::new(
        200,
        |base| format!(":1.0:(no URL) :2.0:(APKJ..{base}/artifact\")"),
        200,
    );
    let endpoint = |_: &str| Ok(Url::parse(&format!("{}/metadata", metadata.base)).unwrap());
    let apps = vec![("com.example.fixture".to_owned(), Some("1.0".to_owned()))];
    let out = tempfile::tempdir().unwrap();
    assert!(
        !injected_download_apps_using(
            apps,
            1,
            0,
            out.path(),
            acknowledged(),
            &fixture_client(),
            &endpoint
        )
        .await
    );
    assert_eq!(metadata.paths(), ["/metadata"]);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apkpure_diagnostics_child() {
    if std::env::var_os("APKPURE_TEST_DIAGNOSTICS_CHILD").is_none() {
        return;
    }
    let out = tempfile::tempdir().unwrap();
    let client = fixture_client();
    let forbidden =
        |_: &str| -> Result<Url, &'static str> { panic!("invalid input reached endpoint") };
    for (app, version, arch) in [
        ("RAW_APP_SECRET\n/escape", None, None),
        (
            "com.example.fixture",
            Some("RAW_VERSION_SECRET/escape"),
            None,
        ),
        ("com.example.fixture", None, Some("RAW_ARCH_SECRET/escape")),
    ] {
        let mut options = acknowledged();
        options.insert("output_format", "json");
        if let Some(arch) = arch {
            options.insert("arch", arch);
        }
        let apps = vec![(app.to_owned(), version.map(str::to_owned))];
        assert!(
            !injected_download_apps_using(
                apps.clone(),
                1,
                0,
                out.path(),
                options.clone(),
                &client,
                &forbidden
            )
            .await
        );
        assert!(!list_versions_using(apps, options, &client, &forbidden).await);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = Url::parse(&format!(
        "http://{}/RAW_NETWORK_SECRET?token=RAW_AUTH_SECRET",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    drop(listener);
    let endpoint = |_: &str| Ok(url.clone());
    let apps = vec![("com.example.failure".to_owned(), None)];
    assert!(
        !injected_download_apps_using(
            apps.clone(),
            1,
            0,
            out.path(),
            acknowledged(),
            &client,
            &endpoint
        )
        .await
    );
    assert!(
        !list_versions_using(
            apps,
            HashMap::from([("output_format", "json")]),
            &client,
            &endpoint
        )
        .await
    );
}

#[test]
fn errors_use_stderr_without_raw_unsafe_components_or_network_urls() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "apkpure_diagnostics_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("APKPURE_TEST_DIAGNOSTICS_CHILD", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("APKPure: invalid app, version or architecture component"));
    assert!(stderr.contains("APKPure: metadata request failed or timed out"));
    for token in [
        "RAW_APP_SECRET",
        "RAW_VERSION_SECRET",
        "RAW_ARCH_SECRET",
        "RAW_NETWORK_SECRET",
        "RAW_AUTH_SECRET",
    ] {
        assert!(!stdout.contains(token));
        assert!(!stderr.contains(token));
    }
    let json_lines = stdout
        .lines()
        .filter_map(|line| line.find('{').map(|position| &line[position..]))
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(json_lines.len(), 3);
    assert!(json_lines[..2]
        .iter()
        .all(|value| value["source"] == "APKPure" && value["apps"] == json!({})));
    assert_eq!(
        json_lines[2]["apps"]["com.example.failure"]["error"],
        "metadata request failed or timed out"
    );
}
