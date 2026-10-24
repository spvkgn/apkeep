use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bounded_output(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("CLI did not terminate within 3 seconds: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn zero_parallel_is_rejected_before_downloading_or_authentication() {
    let out = tempfile::tempdir().unwrap();
    for source in [
        "ru-store",
        "huawei-app-gallery",
        "google-play",
        "apk-pure",
        "f-droid",
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_apkeep"))
                .args(["-d", source, "-a", "com.example.app@1", "-r", "0"])
                .arg(out.path())
                .env_remove("APKEEP_RUSTORE_VER"),
        );
        assert!(!output.status.success(), "{source} accepted zero parallel");
        assert!(output.stdout.is_empty(), "{source}: {:?}", output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let expected = "parallel must be between 1 and 16";
        assert!(stderr.contains(expected), "{source}: {stderr}");
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
