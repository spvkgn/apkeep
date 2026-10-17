use std::process::Command;

#[test]
fn invalid_huawei_options_fail_on_stderr_without_tty() {
    for option in [
        "region=",
        "region=CNN",
        "region=12",
        "region=éé",
        "region",
        "unknown=CN",
        "region=CN,region=IE",
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args([
                "-d",
                "huawei-app-gallery",
                "-a",
                "com.example.app",
                "-l",
                "-o",
                option,
            ])
            .output()
            .unwrap();
        assert!(!result.status.success(), "accepted {option}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("Huawei AppGallery:"));
    }
}

#[test]
fn pinned_versions_and_unsafe_packages_fail_without_network() {
    let out = tempfile::tempdir().unwrap();
    for (app, expected) in [
        ("com.example.app@1.0", "historical versions"),
        ("../outside", "invalid package"),
        ("com.example/a", "invalid package"),
        ("com.example\nFORGED", "invalid package"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args([
                "-d",
                "huawei-app-gallery",
                "-a",
                app,
                out.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("FORGED"));
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn existing_regular_file_is_unverified_and_mixed_batch_fails_without_overwrite() {
    let out = tempfile::tempdir().unwrap();
    let apk = out.path().join("com.example.app.apk");
    std::fs::write(&apk, b"existing").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "huawei-app-gallery",
            "-a",
            "com.example.app",
            out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unverified"));
    let csv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(csv.path(), "com.example.app,\ncom.example.app,1.0\n").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "huawei-app-gallery",
            "-c",
            csv.path().to_str().unwrap(),
            "-v",
            "2",
            out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("historical versions"));
    assert_eq!(std::fs::read(apk).unwrap(), b"existing");
}

#[test]
fn invalid_output_directory_reports_source_specific_stderr() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "huawei-app-gallery",
            "-a",
            "com.example.app",
            file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Huawei AppGallery: OUTPATH"));
}

#[test]
fn listing_rejects_unsafe_package_without_echoing_it() {
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "huawei-app-gallery", "-a", "../outside\nFORGED", "-l"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid package"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("FORGED"));
}

#[test]
fn empty_lists_zero_parallelism_and_invalid_csv_fields_report_stderr() {
    let out = tempfile::tempdir().unwrap();
    let csv = tempfile::NamedTempFile::new().unwrap();
    for extra in [
        vec![],
        vec!["-l"],
        vec!["-f", "0"],
        vec!["-v", "0"],
        vec!["-v", "1"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args([
                "-d",
                "huawei-app-gallery",
                "-c",
                csv.path().to_str().unwrap(),
                out.path().to_str().unwrap(),
            ])
            .args(extra)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("Huawei AppGallery:"),
            "missing diagnostic"
        );
    }
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "huawei-app-gallery",
            "-a",
            "com.example.app",
            "-r",
            "0",
            out.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("parallel must be between 1 and 16"));
}

#[test]
fn source_is_available_and_explains_historical_versions() {
    let result = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "huawei-app-gallery", "-a", "com.example.app", "-l"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("historical versions"));
}
