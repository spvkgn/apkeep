//! Fallible operational stdout. A scoped latch lets the CLI finish its typed
//! report after a failed write, without a global panic hook or silent success.
use std::cell::Cell;
use std::fmt;
use std::future::Future;
use std::io::{self, Write};

tokio::task_local! {
    static FAILED: Cell<bool>;
}

macro_rules! cli_println {
    ($($arg:tt)*) => {
        $crate::output::line(format_args!($($arg)*))
    };
}

pub fn line(args: fmt::Arguments<'_>) {
    line_to(&mut io::stdout().lock(), args);
}

fn line_to(stdout: &mut impl Write, args: fmt::Arguments<'_>) {
    // Flush here, not on drop: buffered failure must reach finalization too.
    if stdout
        .write_fmt(args)
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .is_err()
    {
        let _ = FAILED.try_with(|failed| failed.set(true));
    }
}

/// Every production operational stdout path is polled under this scope. Concurrent
/// item futures share it, but unrelated operations/tests do not share state.
pub async fn capture<T>(future: impl Future<Output = T>) -> (T, bool) {
    FAILED
        .scope(Cell::new(false), async {
            let result = future.await;
            (result, !FAILED.with(Cell::get))
        })
        .await
}

pub fn diagnostic() {
    // stderr can fail too; do not turn the controlled stdout error into a panic.
    let _ = writeln!(io::stderr().lock(), "Could not write operational stdout");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailedSink {
        flush_only: bool,
    }
    impl Write for FailedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.flush_only {
                Ok(bytes.len())
            } else {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        }
    }

    #[tokio::test]
    async fn write_and_flush_failure_are_latched_without_cross_operation_state() {
        for flush_only in [false, true] {
            let (((), good), ((), bad)) = tokio::join!(
                capture(async {
                    let mut bytes = Vec::new();
                    line_to(&mut bytes, format_args!("{}", "unchanged output"));
                    assert_eq!(bytes, b"unchanged output\n");
                    tokio::task::yield_now().await;
                }),
                capture(async {
                    line_to(
                        &mut FailedSink { flush_only },
                        format_args!("not delivered"),
                    );
                    tokio::task::yield_now().await;
                })
            );
            assert!(good);
            assert!(!bad);
        }
        assert!(capture(async {}).await.1);
    }

    #[test]
    fn all_operational_print_macros_use_the_scoped_helper() {
        let unsafe_print = regex::Regex::new(r"\b(?:std::)?(?:print|println)!\s*\(").unwrap();
        for source in [
            include_str!("main.rs"),
            include_str!("download_sources/rustore.rs"),
            include_str!("download_sources/huawei_app_gallery.rs"),
            include_str!("download_sources/apkpure.rs"),
            include_str!("download_sources/fdroid.rs"),
            include_str!("download_sources/google_play.rs"),
        ] {
            assert!(
                !unsafe_print.is_match(source),
                "operational print bypasses fallible stdout"
            );
        }
    }
}
