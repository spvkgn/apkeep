//! Offline child-process preflight: proxy is a closed loopback port, never a store.

#[cfg(unix)]
#[test]
fn untrusted_output_directory_explains_owner_and_write_policy() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o775)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "ru-store", "-a", "com.example.app"])
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("owned by the current user") && stderr.contains("not group/world-writable"),
        "{stderr}"
    );
}

#[test]
fn all_cli_sources_reject_excess_parallelism_before_credentials() {
    for source in [
        "apk-pure",
        "f-droid",
        "google-play",
        "ru-store",
        "huawei-app-gallery",
    ] {
        let out = run(
            &["-d", source, "-a", "com.example.app", "-r", "17", "."],
            None,
        );
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("between 1 and 16"), "{source}: {stderr}");
        assert!(!stderr.contains("Email") && !stderr.contains("terminal"));
    }
}

use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn run(args: &[&str], ini: Option<&str>) -> Output {
    run_with_setup(args, ini, false)
}

fn run_with_setup(args: &[&str], ini: Option<&str>, dangling_default: bool) -> Output {
    run_preflight(args, ini, dangling_default, false)
}

fn run_preflight(
    args: &[&str],
    ini: Option<&str>,
    dangling_default: bool,
    device_fifo: bool,
) -> Output {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    if device_fifo {
        assert!(Command::new("mkfifo")
            .arg(dir.path().join("PRIVATE_DEVICE_FIFO"))
            .status()
            .unwrap()
            .success());
    }
    #[cfg(unix)]
    if dangling_default {
        let config = dir.path().join("config/apkeep");
        fs::create_dir_all(&config).unwrap();
        std::os::unix::fs::symlink(config.join("absent-target"), config.join("apkeep.ini"))
            .unwrap();
    }
    if let Some(contents) = ini {
        fs::write(dir.path().join("config.ini"), contents).unwrap();
    }
    let stdout = dir.path().join("stdout");
    let stderr = dir.path().join("stderr");
    #[cfg(unix)]
    let mut cmd = {
        let mut cmd = Command::new("setsid");
        cmd.arg(env!("CARGO_BIN_EXE_apkeep"));
        cmd
    };
    #[cfg(not(unix))]
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apkeep"));
    let mut child = cmd
        .args(args)
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let timeout = if device_fifo { 2 } else { 5 };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("preflight hung");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: fs::read(stdout).unwrap(),
        stderr: fs::read(stderr).unwrap(),
    }
}

#[test]
fn malformed_explicit_ini_is_rejected_even_with_complete_cli_credentials_without_leaking_values() {
    let out = run(
        &[
            "-d",
            "google-play",
            "-a",
            "com.example.app",
            "-i",
            "config.ini",
            "-e",
            "fixture@example.invalid",
            "-t",
            "FAKE_TEST_CREDENTIAL",
            ".",
        ],
        Some("[SECRET_INI_MARKER\n"),
    );
    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("configuration"), "{error}");
    assert!(!error.contains("SECRET_INI_MARKER") && !error.contains("FAKE_TEST_CREDENTIAL"));
    assert!(out.stdout.is_empty());
}

#[test]
fn missing_default_ini_is_optional_but_existing_malformed_explicit_ini_is_not() {
    let out = run(
        &[
            "-d",
            "google-play",
            "-a",
            "com.example.app",
            "-i",
            "config.ini",
            ".",
        ],
        Some("[MALFORMED_PRIVATE_VALUE\n"),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("configuration"));
    assert!(out.stdout.is_empty());
}

#[test]
fn credential_prompt_refuses_non_terminal_without_echo_or_login() {
    let out = run(
        &[
            "-d",
            "google-play",
            "-a",
            "com.example.app",
            "-e",
            "fixture@example.invalid",
            ".",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("terminal"));
    assert!(out.stdout.is_empty());
}

#[test]
fn oauth_listing_is_an_explicit_error_not_silent_success() {
    let out = run(
        &[
            "--oauth-token",
            "FAKE_TEST_CREDENTIAL",
            "-e",
            "fixture@example.invalid",
            "-l",
        ],
        None,
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("OAuth"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("FAKE_TEST_CREDENTIAL"));
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn dangling_default_ini_is_an_error_not_absent_configuration() {
    let out = run_with_setup(
        &[
            "-d",
            "google-play",
            "-a",
            "com.example.app",
            "-e",
            "fixture@example.invalid",
            "-t",
            "FAKE_TEST_CREDENTIAL",
            ".",
        ],
        None,
        true,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("configuration"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("FAKE_TEST_CREDENTIAL"));
}

#[test]
fn fdroid_rejects_untrusted_app_without_echoing_it() {
    let out = run(
        &[
            "-d",
            "f-droid",
            "-a",
            "DO_NOT_ECHO_FIXTURE\norg.invalid",
            ".",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("DO_NOT_ECHO_FIXTURE"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("DO_NOT_ECHO_FIXTURE"));
}

#[test]
fn oauth_missing_email_is_rejected_without_app_selection_or_network() {
    let out = run(&["--oauth-token", "FAKE_TEST_CREDENTIAL"], None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("email"));
    assert!(out.stdout.is_empty());
}

#[test]
fn bad_google_device_configuration_is_controlled_and_redacted_before_network() {
    for (options, contents) in [
        ("device=PRIVATE_BAD_DEVICE", None),
        ("device_properties_file=PRIVATE_MISSING_FILE", None),
        (
            "device=bad,device_properties_file=config.ini",
            Some("[bad]\nBuild.VERSION.SDK_INT=PRIVATE_BAD_INTEGER\n"),
        ),
        (
            "device=bad,device_properties_file=config.ini",
            Some("[PRIVATE_BROKEN_INI\n"),
        ),
    ] {
        for oauth in [false, true] {
            let mut args = vec![
                "-d",
                "google-play",
                "-e",
                "fixture@example.invalid",
                "-o",
                options,
            ];
            if oauth {
                args.extend(["--oauth-token", "FAKE_PRIVATE_TOKEN"]);
            } else {
                args.extend(["-a", "com.example.app", "-t", "FAKE_PRIVATE_TOKEN", "."]);
            }
            let out = run(&args, contents);
            assert_eq!(out.status.code(), Some(1));
            assert!(out.stdout.is_empty());
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(error.contains("device configuration"), "{error}");
            for raw in ["PRIVATE_", "panicked", "gpapi-", "config.ini", "unwrap"] {
                assert!(!error.contains(raw), "{error}");
            }
        }
    }
}

#[cfg(unix)]
fn reject_google_device_fifo(oauth: bool) {
    let mut args = vec![
        "-d",
        "google-play",
        "-e",
        "fixture@example.invalid",
        "-o",
        "device_properties_file=PRIVATE_DEVICE_FIFO",
    ];
    if oauth {
        args.extend(["--oauth-token", "FAKE_PRIVATE_TOKEN"]);
    } else {
        args.extend(["-a", "com.example.app", "-t", "FAKE_PRIVATE_TOKEN", "."]);
    }
    // No writer is ever opened. A blocking FIFO open must fail this test within
    // two seconds, with the child killed and reaped before the fixture is removed.
    let out = run_preflight(&args, None, false, true);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "Invalid Google Play device configuration\n"
    );
}

#[cfg(unix)]
#[test]
fn google_device_fifo_download_is_rejected_without_blocking_or_leaking() {
    reject_google_device_fifo(false);
}

#[cfg(unix)]
#[test]
fn google_device_fifo_oauth_is_rejected_without_blocking_or_leaking() {
    reject_google_device_fifo(true);
}

#[test]
fn parser_failures_never_echo_raw_values_or_pollute_stdout() {
    for args in [
        vec!["-a", "com.example.app", "-r", "PRIVATE_NUMBER", "."],
        vec!["-a", "com.example.app", "-d", "PRIVATE_SOURCE", "."],
        vec!["-a", "com.example.app", "--PRIVATE_UNKNOWN", "."],
        vec!["-a", "com.example.app"],
    ] {
        let out = run(&args, None);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(!error.contains("PRIVATE_"), "{error}");
    }
}

#[test]
fn json_input_and_outpath_errors_use_redacted_stderr_for_every_source() {
    for source in [
        "google-play",
        "apk-pure",
        "f-droid",
        "ru-store",
        "huawei-app-gallery",
    ] {
        for args in [
            vec![
                "-d",
                source,
                "-l",
                "-c",
                "PRIVATE_MISSING_CSV",
                "-o",
                "output_format=json",
            ],
            vec!["-d", source, "-c", "PRIVATE_MISSING_CSV", "-f", "0", "."],
            vec![
                "-d",
                source,
                "-a",
                "com.example.app",
                "PRIVATE_OUTPATH",
                "-o",
                "output_format=json",
            ],
        ] {
            let out = run(&args, None);
            assert!(!out.status.success());
            assert!(out.stdout.is_empty(), "{source}: {:?}", out.stdout);
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(!error.is_empty());
            for raw in ["PRIVATE_", "Os {", "Custom {", "kind:"] {
                assert!(!error.contains(raw), "{source}: {error}");
            }
        }
    }
}
