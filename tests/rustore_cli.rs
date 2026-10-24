use std::process::Command;

// A version-qualified app never reaches the network, even on the original PR.
// Only child-process environment is configured; the test process is not mutated.
fn run_output(options: &str, version: impl AsRef<std::ffi::OsStr>) -> std::process::Output {
    let out = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-a", "com.example.app@1", "-d", "ru-store", "-o", options])
        .arg(out.path())
        .env("APKEEP_RUSTORE_VER", version)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "RuStore failure exited successfully"
    );
    assert!(
        output.stdout.is_empty(),
        "RuStore failure printed to stdout"
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    output
}

fn run(options: &str, version: impl AsRef<std::ffi::OsStr>) -> String {
    let output = run_output(options, version);
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn invalid_rustore_configuration_exits_unsuccessfully() {
    let output = run_output("sdk_version=secret-value", "11500");
    assert!(
        !output.status.success(),
        "invalid RuStore configuration exited successfully"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid RuStore option sdk_version"),
        "{stderr}"
    );
    assert!(!stderr.contains("secret-value"));
}

#[test]
fn pinned_rustore_apps_fail_the_batch() {
    let output = run_output("", "11500");
    assert!(
        !output.status.success(),
        "unsupported pinned app exited successfully"
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Specific versions"));
}

#[test]
fn empty_rustore_batch_is_an_error() {
    let out = tempfile::tempdir().unwrap();
    let csv = out.path().join("empty.csv");
    std::fs::write(&csv, "\n\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "ru-store", "-c"])
        .arg(csv)
        .arg(out.path())
        .env_remove("APKEEP_RUSTORE_VER")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "empty RuStore batch exited successfully"
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CSV contains no apps"));
}

#[test]
fn pinned_version_diagnostic_does_not_echo_untrusted_version() {
    let out = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-a", "com.example.app@https://secret-user:secret-password@example.invalid/private?token=secret-token", "-d", "ru-store"])
        .arg(out.path()).env_remove("APKEEP_RUSTORE_VER").output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Specific versions"));
    assert!(
        !stderr.contains("secret-"),
        "pinned version leaked into stderr"
    );
    assert!(!stderr.contains("https://"));
}

#[test]
fn rustore_input_errors_are_reported_on_stderr() {
    let out = tempfile::tempdir().unwrap();
    for csv_mode in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_apkeep"));
        command.args(["-d", "ru-store"]);
        if csv_mode {
            command
                .args(["-c", "missing.csv", "--field", "0"])
                .arg(out.path());
        } else {
            command
                .args(["-a", "com.example.app@1"])
                .arg(out.path().join("missing"));
        }
        let output = command.env_remove("APKEEP_RUSTORE_VER").output().unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "RuStore input error was sent to stdout"
        );
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn latest_only_listing_is_explicitly_unsupported_without_network() {
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-a",
            "com.example.app@1",
            "-d",
            "ru-store",
            "-l",
            "-r",
            "0",
            "-o",
            "sdk_version=0",
        ])
        .env("APKEEP_RUSTORE_VER", "secret-invalid-version")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("listing is unsupported"));
}

#[test]
fn invalid_or_overlong_rustore_package_fails_without_echo_or_network() {
    for package in [
        "PRIVATE_PACKAGE\n".to_owned(),
        format!("com.{}", "PRIVATE_PACKAGE".repeat(30)),
    ] {
        for list in [false, true] {
            let out = tempfile::tempdir().unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_apkeep"));
            command.args(["-d", "ru-store", "-a", &package]);
            if list {
                command.arg("-l");
            } else {
                command.arg(out.path());
            }
            let output = command.env_remove("APKEEP_RUSTORE_VER").output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains("Invalid RuStore package name"), "{error}");
            assert!(!error.contains("PRIVATE_PACKAGE"), "{error}");
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn cli_passes_options_to_rustore_before_processing_apps() {
    let output = run("sdk_version=0", "11500");
    assert!(
        output.contains("Invalid RuStore option sdk_version"),
        "{output}"
    );
    assert!(!output.contains("Specific versions"));
}

#[test]
fn cli_rejects_invalid_environment_without_echoing_it() {
    let output = run("", "secret-env-version");
    assert!(output.contains("APKEEP_RUSTORE_VER"), "{output}");
    assert!(!output.contains("secret-env-version"));
    assert!(!output.contains("Specific versions"));
}

#[test]
fn cli_explicit_version_overrides_invalid_environment() {
    let output = run("rustore_version=22000", "secret-env-version");
    assert!(output.contains("Specific versions"), "{output}");
    assert!(!output.contains("Invalid RuStore"));
}

#[cfg(unix)]
#[test]
fn cli_handles_non_unicode_environment_without_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let version = std::ffi::OsString::from_vec(b"secret-env-\xff".to_vec());
    let output = run("", &version);
    assert!(output.contains("APKEEP_RUSTORE_VER"), "{output}");
    assert!(!output.contains("secret-env-"));
    let output = run("rustore_version=22000", &version);
    assert!(output.contains("Specific versions"), "{output}");
    assert!(!output.contains("Invalid RuStore"));
}
