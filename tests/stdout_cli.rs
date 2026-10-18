//! Real offline children: sink failures must not panic or skip report publication.
#[cfg(target_os = "linux")]
fn failing_stdout(sink: &str) -> std::process::Stdio {
    match sink {
        "full" => std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
            .into(),
        "broken_pipe" => {
            let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
            drop(reader);
            std::os::fd::OwnedFd::from(writer).into()
        }
        _ => unreachable!(),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn operational_stdout_failures_are_controlled_and_publish_coherent_reports() {
    for sink in ["full", "broken_pipe"] {
        for (source, package, options, reason) in [
            ("huawei-app-gallery", "com.example.app", "", "local_io"),
            (
                "f-droid",
                "../invalid",
                "output_format=json",
                "invalid_input",
            ),
        ] {
            let out = tempfile::tempdir().unwrap();
            let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_apkeep"));
            child.current_dir(out.path()).args([
                "-d",
                source,
                "-a",
                package,
                "-l",
                "--report-json",
                "result.json",
            ]);
            if !options.is_empty() {
                child.args(["-o", options]);
            }
            let result = child.stdout(failing_stdout(sink)).output().unwrap();
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert_eq!(result.status.code(), Some(1), "{source}/{sink}: {stderr}");
            assert!(!stderr.contains("panicked"), "{source}/{sink}: {stderr}");
            let bytes =
                std::fs::read(out.path().join("result.json")).expect("missing final report");
            let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(report["success"], false);
            assert_eq!(report["source"], source);
            assert_eq!(report["operation"], "list");
            assert_eq!(report["results"][0]["status"], "error");
            assert_eq!(report["results"][0]["reason"], reason);
            assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn operational_stdout_failure_without_report_is_not_success() {
    for sink in ["full", "broken_pipe"] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_apkeep"))
            .args(["-d", "huawei-app-gallery", "-a", "com.example.app", "-l"])
            .stdout(failing_stdout(sink))
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
    }
}
