use std::process::Command;

#[test]
fn no_report_legacy_batch_is_not_subject_to_report_row_limit() {
    let dir = tempfile::tempdir().unwrap();
    let csv = dir.path().join("large.csv");
    std::fs::write(&csv, "com.example.app\n".repeat(65537)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "huawei-app-gallery", "-l", "-c"])
        .arg(&csv)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = dir.path().join("report.json");
    let out = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "huawei-app-gallery", "-l", "-c"])
        .arg(&csv)
        .arg("--report-json")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!report.exists());
}

#[test]
fn report_mixed_invalid_and_pinned_inputs_are_ordered_redacted_and_all_fail() {
    let dir = tempfile::tempdir().unwrap();
    let csv = dir.path().join("apps.csv");
    std::fs::write(
        &csv,
        "com.example.first,1\nPRIVATE/INPUT,2\ncom.example.first,1\n",
    )
    .unwrap();
    let report = dir.path().join("result.json");
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "ru-store", "-c"])
        .arg(csv)
        .args(["-v", "2", "--report-json"])
        .arg(&report)
        .arg(dir.path())
        .env("APKEEP_RUSTORE_VER", "11500")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let bytes = std::fs::read(report).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["results"][0]["reason"], "variant_unavailable");
    assert_eq!(value["results"][1]["reason"], "invalid_input");
    assert!(value["results"][1]["package"].is_null());
    assert_eq!(value["results"][2]["reason"], "variant_unavailable");
}

#[test]
fn report_destination_rejected_before_provider_output() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["existing.json", "com.example.app.apk", "bad.txt"] {
        let report = dir.path().join(name);
        if name == "existing.json" {
            std::fs::write(&report, b"unchanged").unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args([
                "-d",
                "huawei-app-gallery",
                "-l",
                "-a",
                "com.example.app",
                "--report-json",
            ])
            .arg(&report)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        if name == "existing.json" {
            assert_eq!(std::fs::read(report).unwrap(), b"unchanged");
        } else {
            assert!(!report.exists());
        }
    }
}

#[test]
fn oauth_conflict_and_missing_report_value_are_safe_parser_failures() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["--oauth-token", "PRIVATE_TOKEN", "--report-json"])
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_TOKEN"));
    assert!(!report.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "google-play",
            "-l",
            "-a",
            "com.example.app",
            "--report-json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn legacy_huawei_listing_true_does_not_hide_report_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "huawei-app-gallery",
            "-l",
            "-a",
            "com.example.app",
            "--report-json",
        ])
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!output.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(value["results"][0]["reason"], "unsupported");
    assert_eq!(value["success"], false);
}

#[test]
fn missing_google_credentials_report_authentication_without_echo() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args([
            "-d",
            "google-play",
            "-a",
            "com.example.app",
            "--report-json",
        ])
        .arg(&report)
        .arg(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(value["results"][0]["status"], "error");
    assert_eq!(value["results"][0]["reason"], "authentication");
}

#[test]
fn report_flag_collects_ordered_unsupported_listing_rows_without_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let csv = dir.path().join("apps.csv");
    std::fs::write(
        &csv,
        "com.example.first\ncom.example.second\ncom.example.first\n",
    )
    .unwrap();
    let report = dir.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "google-play", "-l", "-c"])
        .arg(csv)
        .arg("--report-json")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("report file must be produced"))
            .unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["source"], "google-play");
    assert_eq!(value["operation"], "list");
    assert_eq!(value["success"], false);
    let rows = value["results"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for (index, package) in [
        "com.example.first",
        "com.example.second",
        "com.example.first",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(rows[index]["index"], index);
        assert_eq!(rows[index]["package"], *package);
        assert_eq!(rows[index]["status"], "unavailable");
        assert_eq!(rows[index]["reason"], "unsupported");
    }
}

#[test]
fn json_listing_stdout_remains_a_single_document_on_metadata_preflight_failure() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    let csv = dir.path().join("apps.csv");
    std::fs::write(&csv, "com.example.first\ncom.example.second\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
        .args(["-d", "f-droid", "-l", "-c"])
        .arg(csv)
        .args(["-o", "output_format=json,repo=invalid", "--report-json"])
        .arg(&report)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let listing: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one listing JSON document");
    assert!(listing.get("error").is_some());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(value["results"].as_array().unwrap().len(), 2);
    for row in value["results"].as_array().unwrap() {
        assert_eq!(row["status"], "error");
    }
}

#[cfg(unix)]
#[test]
fn report_rejects_final_and_parent_symlinks_before_provider_effects() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.json");
    std::fs::write(&victim, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("link.json")).unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("parent")).unwrap();
    for report in [
        dir.path().join("link.json"),
        dir.path().join("parent/report.json"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args([
                "-d",
                "huawei-app-gallery",
                "-l",
                "-a",
                "com.example.app",
                "--report-json",
            ])
            .arg(report)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(std::fs::read(victim).unwrap(), b"unchanged");
    assert!(!dir.path().join("report.json").exists());
}
