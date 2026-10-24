// All backend outcomes and credentials here are synthetic; no Google requests.
use super::*;

#[tokio::test]
async fn real_bounded_play_deadline_has_timeout_outcome_without_authentication() {
    let error = bounded::<()>(Duration::from_millis(1), std::future::pending())
        .await
        .unwrap_err();
    assert_eq!(play_outcome(&error), (Status::Error, Reason::Timeout));
    let (ok, mut report) = results::collect(
        results::Report::new(
            "google-play",
            "download",
            vec![("com.example.app".into(), None)],
        )
        .unwrap(),
        results::observe("com.example.app", None, async {
            let (status, reason) = play_outcome(&error);
            results::note(status, reason);
            false
        }),
    )
    .await;
    report.finish(ok);
    let value: serde_json::Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
    assert_eq!(value["success"], false);
    assert_eq!(value["results"][0]["status"], "error");
    assert_eq!(value["results"][0]["reason"], "timeout");
}

#[tokio::test]
async fn real_google_artifact_adapter_uses_injected_pinned_guard_for_nested_downloads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let out = tempfile::tempdir().unwrap();
    let output = OutputDirectory::open(out.path()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .unwrap();
        }
    });
    let info = (
        Some(url.clone()),
        vec![(Some("config.x86".into()), Some(url))],
        vec![],
        None,
    );
    transfer_play_artifacts(
        "com.fixture.app",
        info,
        &output,
        DownloadSettings {
            split_apk: true,
            ..Default::default()
        },
        Rc::new(MultiProgress::new()),
        Some(reqwest::Client::builder().no_proxy().build().unwrap()),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(
        std::fs::read(out.path().join("com.fixture.app/com.fixture.app.apk")).unwrap(),
        b"good"
    );
    assert_eq!(
        std::fs::read(
            out.path()
                .join("com.fixture.app/com.fixture.app.config.x86.apk")
        )
        .unwrap(),
        b"good"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ancestor_swap_keeps_google_split_publication_and_cleanup_pinned() {
    struct SwappingBackend {
        original: std::path::PathBuf,
        moved: std::path::PathBuf,
        victim: std::path::PathBuf,
        fail: bool,
    }
    impl PlayBackend for SwappingBackend {
        async fn login(&mut self) -> Result<(), GpError> {
            Ok(())
        }
        async fn accept_tos(&mut self) -> Result<(), GpError> {
            Ok(())
        }
        async fn request_token(&mut self, _: &str) -> Result<Option<String>, GpError> {
            Ok(None)
        }
        async fn download(
            &self,
            app: &str,
            out: &OutputDirectory,
            _: DownloadSettings,
            _: Rc<MultiProgress>,
        ) -> Result<(), GpError> {
            let out = out.path();
            split_fixture(out, app);
            std::fs::rename(&self.original, &self.moved).unwrap();
            std::os::unix::fs::symlink(&self.victim, &self.original).unwrap();
            if self.fail {
                Err(GpError::new(ErrorKind::InvalidApp))
            } else {
                Ok(())
            }
        }
    }
    for fail in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("out");
        let moved = root.path().join("moved");
        let victim = root.path().join("victim");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&victim).unwrap();
        let mut backend = SwappingBackend {
            original: original.clone(),
            moved: moved.clone(),
            victim: victim.clone(),
            fail,
        };
        assert_eq!(
            download_with_backend(
                &mut backend,
                vec![("com.fixture.app".into(), None)],
                1,
                0,
                &original,
                false,
                DownloadSettings::default(),
                Limits::default()
            )
            .await,
            !fail
        );
        assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_dir(&moved).unwrap().count(),
            usize::from(!fail)
        );
        if !fail {
            assert!(moved.join("com.fixture.app/com.fixture.app.apk").is_file());
        }
    }
}

#[test]
fn constructor_panic_hook_forwards_unrelated_panics_on_same_and_other_threads() {
    if std::env::var_os("APKEEP_GPAPI_HOOK_FIXTURE").is_some() {
        std::panic::set_hook(Box::new(|_| eprintln!("EXPECTED_UNRELATED_PANIC")));
        assert!(create_api(
            "fixture@example.invalid",
            &mut HashMap::from([("device", "PRIVATE_INVALID_DEVICE")])
        )
        .is_err());
        assert!(std::panic::catch_unwind(|| panic!("unrelated local panic")).is_err());
        std::thread::spawn(|| {
            assert!(std::panic::catch_unwind(|| panic!("unrelated thread panic")).is_err());
        })
        .join()
        .unwrap();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "download_sources::google_play::tests::constructor_panic_hook_forwards_unrelated_panics_on_same_and_other_threads", "--nocapture"])
        .env("APKEEP_GPAPI_HOOK_FIXTURE", "1").output().unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("EXPECTED_UNRELATED_PANIC").count(),
        2,
        "{stderr}"
    );
    assert!(!stderr.contains("PRIVATE_INVALID_DEVICE"));
}

#[tokio::test]
async fn constructor_boundary_recovers_and_preserves_valid_builtin_and_custom_profiles() {
    assert!(create_api(
        "fixture@example.invalid",
        &mut HashMap::from([("device", "PRIVATE_INVALID_DEVICE")])
    )
    .is_err());
    assert!(!IN_CONSTRUCTOR.with(|flag| flag.get()));
    assert!(create_api("fixture@example.invalid", &mut HashMap::new()).is_ok());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "[default]\nSharedLibraries=android.test\nFeatures=android.hardware.camera\nLocales=en_US\nGL.Extensions=GL_EXT_test\n").unwrap();
    assert!(create_api(
        "fixture@example.invalid",
        &mut HashMap::from([
            ("device", "default"),
            ("device_properties_file", file.path().to_str().unwrap())
        ])
    )
    .is_ok());
    std::fs::write(file.path(), vec![b'x'; 256 * 1024 + 1]).unwrap();
    assert!(create_api(
        "fixture@example.invalid",
        &mut HashMap::from([("device_properties_file", file.path().to_str().unwrap())])
    )
    .is_err());
    assert!(!IN_CONSTRUCTOR.with(|flag| flag.get()));
}

use crate::cli;
use gpapi::error::{Error as GpError, ErrorKind};
use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Clone)]
enum Action {
    Single,
    Error,
    SplitFailure,
    PendingPartial,
    SplitSuccess,
    RetrySplit,
    Terminal(fn() -> ErrorKind),
}

#[derive(Default, Clone, Copy)]
enum AuthAction {
    #[default]
    Ok,
    Tos,
    Error,
    Pending,
}

async fn auth_outcome(action: AuthAction) -> Result<(), GpError> {
    match action {
        AuthAction::Ok => Ok(()),
        AuthAction::Tos => Err(GpError::new(ErrorKind::TermsOfService)),
        AuthAction::Error => Err(GpError::from(
            "FAKE_SECRET_EMAIL_TOKEN https://example.invalid/?token=FAKE_SECRET",
        )),
        AuthAction::Pending => std::future::pending().await,
    }
}

#[derive(Default)]
struct OfflineBackend {
    calls: RefCell<Vec<String>>,
    actions: RefCell<VecDeque<Action>>,
    login: AuthAction,
    tos: AuthAction,
    token: AuthAction,
    token_value: Option<Option<String>>,
    stages: RefCell<Vec<std::path::PathBuf>>,
}

impl PlayBackend for OfflineBackend {
    async fn login(&mut self) -> Result<(), GpError> {
        self.calls.borrow_mut().push("login".into());
        auth_outcome(self.login).await
    }
    async fn accept_tos(&mut self) -> Result<(), GpError> {
        self.calls.borrow_mut().push("tos".into());
        auth_outcome(self.tos).await
    }
    async fn request_token(&mut self, _: &str) -> Result<Option<String>, GpError> {
        self.calls.borrow_mut().push("token".into());
        auth_outcome(self.token).await?;
        Ok(self
            .token_value
            .clone()
            .unwrap_or_else(|| Some("OFFLINE_RESULT_TOKEN".into())))
    }
    async fn download(
        &self,
        app: &str,
        out: &OutputDirectory,
        _: DownloadSettings,
        _: Rc<MultiProgress>,
    ) -> Result<(), GpError> {
        let out = out.path();
        self.calls.borrow_mut().push(app.into());
        // Descriptor numbers can be reused after a retry. Observe the actual
        // unique staging entry for cleanup assertions, not the ephemeral fd name.
        self.stages
            .borrow_mut()
            .push(std::fs::read_link(out).unwrap());
        assert_eq!(
            std::fs::read_dir(out).unwrap().count(),
            0,
            "every retry must use clean private staging"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(out).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let action = self.actions.borrow_mut().pop_front().unwrap();
        match action {
            Action::Single => {
                std::fs::write(out.join(format!("{app}.apk")), b"complete APK fixture").unwrap();
                Ok(())
            }
            Action::Error => Err(GpError::new(ErrorKind::InvalidApp)),
            Action::Terminal(kind) => Err(GpError::new(kind())),
            Action::SplitSuccess => {
                split_fixture(out, app);
                Ok(())
            }
            Action::RetrySplit => {
                split_fixture(out, app);
                Err(GpError::from(
                    "FAKE_SECRET_EMAIL_TOKEN https://example.invalid/?token=FAKE_SECRET",
                ))
            }
            Action::PendingPartial => {
                std::fs::write(out.join(format!("{app}.apk")), b"partial").unwrap();
                std::future::pending().await
            }
            Action::SplitFailure => {
                let dir = out.join(app);
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join(format!("{app}.apk")), b"base APK").unwrap();
                std::fs::write(dir.join("main.1.fixture.obb"), b"partial OBB").unwrap();
                Err(GpError::new(ErrorKind::InvalidApp))
            }
        }
    }
}

fn short_limits() -> Limits {
    Limits {
        action: Duration::from_millis(5),
        download: Duration::from_millis(5),
    }
}

#[tokio::test]
async fn login_is_bounded_without_downloading_or_accepting_terms() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend {
        login: AuthAction::Pending,
        ..Default::default()
    };
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits(),
        ),
    )
    .await;
    assert_eq!(result.ok(), Some(false));
    assert_eq!(*backend.calls.borrow(), ["login"]);
}

#[tokio::test]
async fn tos_is_never_accepted_implicitly_and_explicit_accept_is_bounded() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend {
        login: AuthAction::Tos,
        tos: AuthAction::Pending,
        ..Default::default()
    };
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert_eq!(*backend.calls.borrow(), ["login"]);
    backend.calls.borrow_mut().clear();
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            true,
            DownloadSettings::default(),
            short_limits(),
        ),
    )
    .await;
    assert_eq!(result.ok(), Some(false));
    assert_eq!(*backend.calls.borrow(), ["login", "tos"]);
}

#[tokio::test]
async fn every_download_retry_is_bounded_and_partial_files_are_cleaned() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from(vec![Action::PendingPartial; 3]);
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits(),
        ),
    )
    .await;
    assert_eq!(result.ok(), Some(false));
    assert_eq!(
        *backend.calls.borrow(),
        [
            "login",
            "com.fixture.app",
            "com.fixture.app",
            "com.fixture.app"
        ]
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn typed_report_mixed_backend_outcomes_fail_the_batch_but_drain_every_app() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from([Action::Error, Action::Single]);
    let apps = vec![
        ("com.fixture.bad".into(), None),
        ("com.fixture.good".into(), None),
    ];
    let (result, report) = crate::results::collect(
        crate::results::Report::new("google-play", "download", apps).unwrap(),
        download_with_backend(
            &mut backend,
            vec![
                ("com.fixture.bad".into(), None),
                ("com.fixture.good".into(), None),
            ],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            Limits::default(),
        ),
    )
    .await;
    let value: serde_json::Value = serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
    // The fixture's Action::Error is gpapi InvalidApp (not authoritative absence).
    assert_eq!(value["results"][0]["status"], "unavailable");
    assert_eq!(value["results"][0]["reason"], "profile_unavailable");
    assert_eq!(value["results"][1]["status"], "success");
    assert!(!result);
    assert_eq!(
        *backend.calls.borrow(),
        ["login", "com.fixture.bad", "com.fixture.good"]
    );
    assert!(out.path().join("com.fixture.good.apk").is_file());
}

#[tokio::test]
async fn failed_split_download_leaves_no_base_or_obb_or_staging_directory() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    backend.actions.borrow_mut().push_back(Action::SplitFailure);
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.split".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            Limits::default()
        )
        .await
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn invalid_ids_and_pinned_versions_do_not_authenticate() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from(vec![Action::Error; 8]);
    assert!(
        !download_with_backend(
            &mut backend,
            vec![
                ("bad/name".into(), None),
                ("com.fixture.app".into(), Some("123".into()))
            ],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            Limits::default()
        )
        .await
    );
    assert!(backend.calls.borrow().is_empty());
}

#[tokio::test]
async fn token_success_outputs_only_the_result_token() {
    let mut backend = OfflineBackend::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert!(
        request_token_with_backend(
            &mut backend,
            "FAKE_OAUTH",
            short_limits(),
            &mut stdout,
            &mut stderr
        )
        .await
    );
    assert_eq!(stdout, b"OFFLINE_RESULT_TOKEN\n");
    assert!(stderr.is_empty());
    assert_eq!(*backend.calls.borrow(), ["token"]);
}

#[tokio::test]
async fn token_timeout_returns_failure_with_empty_stdout_and_redacted_stderr() {
    let mut backend = OfflineBackend {
        token: AuthAction::Pending,
        ..Default::default()
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        request_token_with_backend(
            &mut backend,
            "FAKE_OAUTH_SECRET",
            short_limits(),
            &mut stdout,
            &mut stderr,
        ),
    )
    .await;
    assert_eq!(result.ok(), Some(false));
    assert!(stdout.is_empty());
    assert!(!stderr.is_empty());
    assert!(!String::from_utf8(stderr)
        .unwrap()
        .contains("FAKE_OAUTH_SECRET"));
}

fn split_fixture(stage: &Path, app: &str) {
    let dir = stage.join(app);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join(format!("{app}.apk")), b"base").unwrap();
    std::fs::write(dir.join(format!("{app}.config.en.apk")), b"split").unwrap();
    std::fs::write(dir.join(format!("main.1.{app}.obb")), b"obb").unwrap();
    std::fs::write(dir.join(format!("{app}.dm")), b"metadata").unwrap();
}

#[test]
fn split_publication_does_not_replace_an_existing_empty_directory() {
    let out = tempfile::tempdir().unwrap();
    let stage = tempfile::tempdir_in(out.path()).unwrap();
    let app = "com.fixture.app";
    split_fixture(stage.path(), app);
    std::fs::create_dir(out.path().join(app)).unwrap();
    assert!(publish_download(stage.path(), out.path(), app).is_err());
    assert_eq!(std::fs::read_dir(out.path().join(app)).unwrap().count(), 0);
}

#[test]
fn incomplete_or_unexpected_staged_artifacts_are_never_published() {
    let app = "com.fixture.app";
    for case in [
        "empty_apk",
        "missing_base",
        "unexpected_root",
        "unexpected_child",
        "both_layouts",
    ] {
        let out = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir_in(out.path()).unwrap();
        match case {
            "empty_apk" => std::fs::write(stage.path().join(format!("{app}.apk")), b"").unwrap(),
            "missing_base" => {
                std::fs::create_dir(stage.path().join(app)).unwrap();
            }
            "unexpected_root" => {
                std::fs::write(stage.path().join(format!("{app}.apk")), b"complete").unwrap();
                std::fs::write(stage.path().join("unfinished.part"), b"partial").unwrap();
            }
            "unexpected_child" => {
                split_fixture(stage.path(), app);
                std::fs::write(stage.path().join(app).join("unfinished.part"), b"partial").unwrap();
            }
            "both_layouts" => {
                split_fixture(stage.path(), app);
                std::fs::write(stage.path().join(format!("{app}.apk")), b"complete").unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            publish_download(stage.path(), out.path(), app).is_err(),
            "{case}"
        );
        assert!(!out.path().join(app).exists(), "{case}");
        assert!(!out.path().join(format!("{app}.apk")).exists(), "{case}");
    }
}

#[tokio::test]
async fn token_failure_and_missing_or_blank_result_never_print_credentials() {
    for (action, token) in [
        (AuthAction::Error, None),
        (AuthAction::Ok, None),
        (AuthAction::Ok, Some(String::new())),
        (AuthAction::Ok, Some(" \n".into())),
    ] {
        let mut backend = OfflineBackend {
            token: action,
            token_value: Some(token),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert!(
            !request_token_with_backend(
                &mut backend,
                "FAKE_OAUTH_SECRET",
                short_limits(),
                &mut stdout,
                &mut stderr
            )
            .await
        );
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(!stderr.is_empty());
        assert!(!stderr.contains("FAKE_SECRET"));
        assert!(!stderr.contains("example.invalid"));
    }
}

#[tokio::test]
async fn successful_parallel_batch_preserves_single_and_split_layouts() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from([Action::Single, Action::SplitSuccess]);
    assert!(
        download_with_backend(
            &mut backend,
            vec![
                ("com.fixture.single".into(), None),
                ("com.fixture.split".into(), None)
            ],
            2,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert!(out.path().join("com.fixture.single.apk").is_file());
    let split = out.path().join("com.fixture.split");
    for name in [
        "com.fixture.split.apk",
        "com.fixture.split.config.en.apk",
        "main.1.com.fixture.split.obb",
        "com.fixture.split.dm",
    ] {
        assert!(split.join(name).is_file());
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 2);
    assert!(backend.stages.borrow().iter().all(|stage| !stage.exists()));
}

#[tokio::test]
async fn retry_after_split_error_uses_fresh_staging_and_exports_only_success() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from([Action::RetrySplit, Action::Single]);
    assert!(
        download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert_eq!(backend.stages.borrow().len(), 2);
    assert_ne!(backend.stages.borrow()[0], backend.stages.borrow()[1]);
    assert!(backend.stages.borrow().iter().all(|stage| !stage.exists()));
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(out.path().join("com.fixture.app.apk")).unwrap(),
        b"complete APK fixture"
    );
}

#[tokio::test]
async fn exhausted_transient_errors_fail_and_clean_every_attempt() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    *backend.actions.borrow_mut() = VecDeque::from(vec![Action::RetrySplit; 3]);
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert_eq!(backend.stages.borrow().len(), 3);
    assert!(backend.stages.borrow().iter().all(|stage| !stage.exists()));
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn terminal_gpapi_errors_are_failures_without_retry() {
    let cases: [fn() -> ErrorKind; 6] = [
        || ErrorKind::FileExists,
        || ErrorKind::DirectoryExists,
        || ErrorKind::InvalidApp,
        || ErrorKind::PermissionDenied,
        || ErrorKind::DirectoryMissing,
        || ErrorKind::Authentication,
    ];
    for kind in cases {
        let out = tempfile::tempdir().unwrap();
        let mut backend = OfflineBackend::default();
        *backend.actions.borrow_mut() = VecDeque::from(vec![Action::Terminal(kind); 3]);
        assert!(
            !download_with_backend(
                &mut backend,
                vec![("com.fixture.app".into(), None)],
                1,
                0,
                out.path(),
                false,
                DownloadSettings::default(),
                short_limits()
            )
            .await
        );
        // Authentication must not trigger repeated authenticated purchase/download calls.
        assert_eq!(backend.stages.borrow().len(), 1);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn invalid_batch_entries_fail_but_do_not_skip_valid_entries() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    backend.actions.borrow_mut().push_back(Action::Single);
    assert!(
        !download_with_backend(
            &mut backend,
            vec![
                ("../invalid".into(), None),
                ("com.fixture.pinned".into(), Some("1".into())),
                ("com.fixture.good".into(), None)
            ],
            2,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert_eq!(*backend.calls.borrow(), ["login", "com.fixture.good"]);
    assert!(out.path().join("com.fixture.good.apk").exists());
}

#[tokio::test]
async fn existing_apk_is_preserved_and_reported_as_failure() {
    let out = tempfile::tempdir().unwrap();
    std::fs::write(out.path().join("com.fixture.app.apk"), b"existing").unwrap();
    let mut backend = OfflineBackend::default();
    backend.actions.borrow_mut().push_back(Action::Single);
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert_eq!(
        std::fs::read(out.path().join("com.fixture.app.apk")).unwrap(),
        b"existing"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn source_and_destination_symlinks_are_not_followed_or_replaced() {
    use std::os::unix::fs::symlink;
    let app = "com.fixture.app";
    for directory in [false, true] {
        let out = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir_in(out.path()).unwrap();
        let target = tempfile::tempdir().unwrap();
        let filename = if directory {
            app.to_owned()
        } else {
            format!("{app}.apk")
        };
        if directory {
            split_fixture(stage.path(), app);
        } else {
            std::fs::write(stage.path().join(&filename), b"complete").unwrap();
        }
        symlink(target.path(), out.path().join(&filename)).unwrap();
        assert!(publish_download(stage.path(), out.path(), app).is_err());
        assert!(std::fs::symlink_metadata(out.path().join(&filename))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }
    for directory in [false, true] {
        let out = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir_in(out.path()).unwrap();
        let target = tempfile::tempdir().unwrap();
        if directory {
            symlink(target.path(), stage.path().join(app)).unwrap();
        } else {
            let source = target.path().join("source.apk");
            std::fs::write(&source, b"complete").unwrap();
            symlink(source, stage.path().join(format!("{app}.apk"))).unwrap();
        }
        assert!(publish_download(stage.path(), out.path(), app).is_err());
        assert!(!out.path().join(app).exists());
        assert!(!out.path().join(format!("{app}.apk")).exists());
    }
}

#[test]
fn unsafe_app_ids_are_rejected_without_reflecting_input() {
    for bad in [
        "",
        "..",
        "../com.fixture",
        "com/fixture",
        "com\\fixture",
        "com..fixture",
        ".com.fixture",
        "com.fixture.",
        "com.fixture\n",
        "https://example.invalid/?token=SECRET",
        "com.123",
    ] {
        assert!(!valid_app_id(bad));
    }
    for good in ["com.fixture", "org.example_APP.app2"] {
        assert!(valid_app_id(good));
    }
}

#[tokio::test]
async fn empty_batch_and_missing_output_do_not_authenticate() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    assert!(
        !download_with_backend(
            &mut backend,
            vec![],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            &out.path().join("missing"),
            false,
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
    assert!(backend.calls.borrow().is_empty());
}

#[tokio::test]
async fn missing_credentials_return_false_instead_of_exiting() {
    let out = tempfile::tempdir().unwrap();
    assert!(
        !download_apps(
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            "offline@example.invalid",
            None,
            None,
            out.path(),
            false,
            HashMap::new()
        )
        .await
    );
}

#[test]
fn backend_error_diagnostics_do_not_expose_raw_credentials_or_urls() {
    for case in ["login", "tos", "download", "token"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!(
                    "{}::offline_error_capture_child",
                    module_path!().split_once("::").unwrap().1
                ),
                "--nocapture",
            ])
            .env("APKEEP_GP_OFFLINE_ERROR_CASE", case)
            .output()
            .unwrap();
        assert!(output.status.success());
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("FAKE_SECRET"));
            assert!(!text.contains("example.invalid"));
        }
        assert!(!output.stderr.is_empty());
    }
}

#[tokio::test]
async fn offline_error_capture_child() {
    let Ok(case) = std::env::var("APKEEP_GP_OFFLINE_ERROR_CASE") else {
        return;
    };
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    match case.as_str() {
        "login" => backend.login = AuthAction::Error,
        "tos" => {
            backend.login = AuthAction::Tos;
            backend.tos = AuthAction::Error;
        }
        "download" => *backend.actions.borrow_mut() = VecDeque::from(vec![Action::RetrySplit; 3]),
        "token" => {
            backend.token = AuthAction::Error;
            assert!(
                !request_token_with_backend(
                    &mut backend,
                    "FAKE_SECRET",
                    short_limits(),
                    &mut std::io::stdout(),
                    &mut std::io::stderr()
                )
                .await
            );
            return;
        }
        _ => panic!("unknown offline scenario"),
    }
    assert!(
        !download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            case == "tos",
            DownloadSettings::default(),
            short_limits()
        )
        .await
    );
}

#[test]
fn local_publication_failure_rolls_back_only_new_split_links() {
    let out = tempfile::tempdir().unwrap();
    let stage = tempfile::tempdir_in(out.path()).unwrap();
    let app = "com.fixture.app";
    split_fixture(stage.path(), app);
    std::fs::write(out.path().join("existing.apk"), b"keep me").unwrap();
    let mut linked = 0;
    let result = publish_download_with_link(stage.path(), out.path(), app, |from, to| {
        linked += 1;
        if linked == 2 {
            return Err(std::io::Error::other("offline injected link error"));
        }
        std::fs::hard_link(from, to)
    });
    assert!(result.is_err());
    assert_eq!(linked, 2);
    assert!(!out.path().join(app).exists());
    assert_eq!(
        std::fs::read(out.path().join("existing.apk")).unwrap(),
        b"keep me"
    );
    assert_eq!(
        std::fs::read_dir(stage.path().join(app)).unwrap().count(),
        4
    );
}

#[tokio::test]
async fn cancelling_the_whole_batch_drops_private_partial_staging() {
    let out = tempfile::tempdir().unwrap();
    let mut backend = OfflineBackend::default();
    backend
        .actions
        .borrow_mut()
        .push_back(Action::PendingPartial);
    assert!(tokio::time::timeout(
        Duration::from_millis(5),
        download_with_backend(
            &mut backend,
            vec![("com.fixture.app".into(), None)],
            1,
            0,
            out.path(),
            false,
            DownloadSettings::default(),
            Limits::default()
        )
    )
    .await
    .is_err());
    assert_eq!(backend.stages.borrow().len(), 1);
    assert!(backend.stages.borrow().iter().all(|stage| !stage.exists()));
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn device_file_fifo_substitution_during_acquisition_is_rejected_without_blocking() {
    const CHILD: &str = "APKEEP_TEST_FIFO_SUBSTITUTION";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = Path::new(&path);
        // Deterministically replace the checked regular file at the exact
        // metadata/open boundary; no FIFO writer exists in either process.
        assert!(std::fs::metadata(path).unwrap().is_file());
        std::fs::remove_file(path).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            super::acquire_device_properties_file(path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let path = fixture.path().join("PRIVATE_DEVICE_FIFO");
    std::fs::write(&path, b"regular profile before substitution").unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "download_sources::google_play::tests::device_file_fifo_substitution_during_acquisition_is_rejected_without_blocking",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() {
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("device file acquisition blocked after FIFO substitution");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn unsupported_version_listing_reports_failure() {
    assert!(!super::list_versions(vec![]));
}

#[test]
fn oauth_and_ini_arguments_parse_without_requiring_an_app_or_outpath() {
    let matches = cli::app()
        .try_get_matches_from([
            "apkeep",
            "--oauth-token",
            "FAKE_OAUTH_NOT_A_CREDENTIAL",
            "-e",
            "offline@example.invalid",
            "-i",
            "fixture.ini",
        ])
        .unwrap();
    assert_eq!(
        matches.get_one::<String>("google_oauth_token").unwrap(),
        "FAKE_OAUTH_NOT_A_CREDENTIAL"
    );
    assert_eq!(
        matches.get_one::<String>("google_email").unwrap(),
        "offline@example.invalid"
    );
    assert_eq!(matches.get_one::<String>("ini").unwrap(), "fixture.ini");
    assert!(matches.get_one::<String>("app").is_none());
    assert!(matches.get_one::<String>("OUTPATH").is_none());
    assert!(!matches.get_flag("google_accept_tos"));
}

#[test]
fn aas_and_auth_arguments_are_distinct_and_do_not_implicitly_accept_tos() {
    for switch in ["--aas-token", "--auth-token"] {
        let matches = cli::app()
            .try_get_matches_from([
                "apkeep",
                "-a",
                "com.example.fixture",
                "-e",
                "offline@example.invalid",
                switch,
                "FAKE_TOKEN_NOT_A_CREDENTIAL",
                "-i",
                "fixture.ini",
                ".",
            ])
            .unwrap();
        let (key, other) = if switch == "--aas-token" {
            ("google_aas_token", "google_auth_token")
        } else {
            ("google_auth_token", "google_aas_token")
        };
        assert_eq!(
            matches.get_one::<String>(key).unwrap(),
            "FAKE_TOKEN_NOT_A_CREDENTIAL"
        );
        assert!(matches.get_one::<String>(other).is_none());
        assert_eq!(matches.get_one::<String>("ini").unwrap(), "fixture.ini");
        assert!(!matches.get_flag("google_accept_tos"));
    }
}
