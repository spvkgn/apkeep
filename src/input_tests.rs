//! Shared input contracts; fixtures never contain real credentials.

#[tokio::test]
async fn all_direct_providers_reject_excess_parallelism_before_io_or_auth() {
    use crate::download_sources::{apkpure, fdroid, google_play, huawei_app_gallery, rustore};
    use crate::results::{collect, Report};
    for source in [
        "apk-pure",
        "f-droid",
        "google-play",
        "huawei-app-gallery",
        "ru-store",
    ] {
        for parallel in [0, 17, usize::MAX] {
            let apps = vec![("com.example.app".to_owned(), None)];
            let report = Report::new(source, "download", apps.clone()).unwrap();
            let (ok, report) = collect(report, async {
                let out = Path::new("/not-an-existing-output");
                match source {
                    "apk-pure" => {
                        apkpure::download_apps(apps, parallel, 0, out, HashMap::new()).await
                    }
                    "f-droid" => {
                        fdroid::download_apps(apps, parallel, 0, out, HashMap::new()).await
                    }
                    "google-play" => {
                        google_play::download_apps(
                            apps,
                            parallel,
                            0,
                            "",
                            None,
                            None,
                            out,
                            false,
                            HashMap::new(),
                        )
                        .await
                    }
                    "huawei-app-gallery" => {
                        huawei_app_gallery::download_apps(apps, parallel, 0, out, "IE").await
                    }
                    _ => rustore::download_apps(apps, parallel, 0, out, HashMap::new()).await,
                }
            })
            .await;
            assert!(!ok);
            let value: serde_json::Value =
                serde_json::from_slice(&report.json_bytes().unwrap()).unwrap();
            assert_eq!(
                value["results"][0]["reason"], "invalid_input",
                "{source} {parallel}: {value}"
            );
        }
    }
}

#[test]
fn single_app_empty_version_matches_csv_latest_and_preserves_nonempty_version() {
    assert_eq!(
        single_app("com.example.app@"),
        parse_csv_text("com.example.app,".into(), 1, Some(2)).unwrap()[0]
    );
    assert_eq!(
        single_app("com.example.app@1"),
        ("com.example.app".into(), Some("1".into()))
    );
    assert_eq!(
        single_app("com.example.app"),
        ("com.example.app".into(), None)
    );
}

#[test]
fn csv_explicit_empty_record_in_batch_is_error_not_a_blank_line() {
    for (text, version) in [
        ("com.example.app\n\"\"\n", None),
        ("com.example.app,1\n\"\"\n", Some(2)),
    ] {
        assert!(parse_csv_text(text.into(), 1, version).is_err());
    }
}

#[test]
fn csv_selected_controls_are_rejected_and_bom_quoted_field_is_supported() {
    for text in [
        "\"com.example.app\nsecond\",1",
        "com.example.app,\"1\n2\"",
        "\tcom.example.app,1",
    ] {
        assert!(parse_csv_text(text.into(), 1, Some(2)).is_err());
    }
    assert_eq!(
        parse_csv_text("\u{feff}\"com.example.app\",1".into(), 1, Some(2)).unwrap(),
        vec![("com.example.app".into(), Some("1".into()))]
    );
}

#[test]
fn csv_malformed_quotes_cannot_silently_hide_batch_rows() {
    for text in [
        "com.example.app,1.2,\"unterminated\ncom.example.second,2",
        "com.example.app,\"1.2\"junk",
        "com.example.app,1\"2",
    ] {
        assert!(
            parse_csv_text(text.to_owned(), 1, Some(2)).is_err(),
            "malformed quoting accepted"
        );
    }
    assert_eq!(
        parse_csv_text(
            "com.example.app,1.2,\"valid\nmultiline\"".into(),
            1,
            Some(2)
        )
        .unwrap(),
        vec![("com.example.app".into(), Some("1.2".into()))]
    );
}

#[test]
fn csv_missing_requested_columns_is_an_error_not_latest_or_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("apps.csv");
    for (text, field, version) in [("com.example.app\n", 1, Some(2)), ("only-one\n", 2, None)] {
        fs::write(&file, text).unwrap();
        assert!(
            fetch_csv_list(file.to_str().unwrap(), field, version).is_err(),
            "missing field accepted"
        );
    }
}

#[test]
fn csv_quoted_unselected_field_and_escaped_quote_preserve_selected_version() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("apps.csv");
    fs::write(
        &file,
        "\"label,with \"\"quotes\"\"\",com.example.app,1.2\r\n",
    )
    .unwrap();
    assert_eq!(
        fetch_csv_list(file.to_str().unwrap(), 2, Some(3)).unwrap(),
        vec![("com.example.app".into(), Some("1.2".into()))]
    );
}

#[test]
fn csv_empty_app_and_empty_document_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("apps.csv");
    for text in ["", "\n\r\n", ",1.2\n"] {
        fs::write(&file, text).unwrap();
        assert!(fetch_csv_list(file.to_str().unwrap(), 1, Some(2)).is_err());
    }
}
use super::*;

#[test]
fn csv_single_column_handles_crlf_blank_rows_and_final_newline() {
    assert_eq!(
        parse_csv_text("com.example.one\r\n\ncom.example.two\n".to_owned(), 1, None).unwrap(),
        vec![
            ("com.example.one".to_owned(), None),
            ("com.example.two".to_owned(), None)
        ]
    );
}

#[test]
fn csv_selects_app_and_version_columns_in_either_order() {
    assert_eq!(
        parse_csv_text("label,com.example.one,1.2.3".to_owned(), 2, Some(3)).unwrap(),
        vec![("com.example.one".to_owned(), Some("1.2.3".to_owned()))]
    );
    assert_eq!(
        parse_csv_text("1.2.3,label,com.example.one".to_owned(), 3, Some(1)).unwrap(),
        vec![("com.example.one".to_owned(), Some("1.2.3".to_owned()))]
    );
}

#[test]
fn csv_explicit_empty_version_means_latest() {
    assert_eq!(
        parse_csv_text("com.example.one,".to_owned(), 1, Some(2)).unwrap(),
        vec![("com.example.one".to_owned(), None)]
    );
}

#[test]
fn csv_reader_preserves_app_version_and_reports_missing_or_non_utf8_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("apps.csv");
    assert!(fetch_csv_list(path.to_str().unwrap(), 1, None).is_err());
    fs::write(&path, b"\xff").unwrap();
    assert!(fetch_csv_list(path.to_str().unwrap(), 1, None).is_err());
    fs::write(&path, b"com.example.one,2\ncom.example.two,3\n").unwrap();
    assert_eq!(
        fetch_csv_list(path.to_str().unwrap(), 1, Some(2)).unwrap(),
        vec![
            ("com.example.one".to_owned(), Some("2".to_owned())),
            ("com.example.two".to_owned(), Some("3".to_owned()))
        ]
    );
}

#[test]
fn explicit_ini_is_read_without_modifying_its_contents() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("apkeep.ini");
    let bytes = b"[google]\nemail=fixture@example.invalid\naas_token=fixture-only\n";
    fs::write(&path, bytes).unwrap();
    let config = load_config(Some(path.clone())).unwrap();
    assert_eq!(
        config.get("google", "email").as_deref(),
        Some("fixture@example.invalid")
    );
    assert_eq!(
        config.get("google", "aas_token").as_deref(),
        Some("fixture-only")
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn explicit_ini_reports_missing_malformed_and_non_utf8_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("apkeep.ini");
    assert!(load_config(Some(path.clone())).is_err());
    fs::write(&path, b"[unclosed-section\n").unwrap();
    assert!(load_config(Some(path.clone())).is_err());
    fs::write(&path, b"\xff").unwrap();
    assert!(load_config(Some(path)).is_err());
}
