//! Scoped per-input outcomes. This module never infers store absence from text.
use std::cell::RefCell;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success,
    NotFound,
    Unavailable,
    Error,
}
impl Status {
    fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Complete,
    PackageAbsent,
    VariantUnavailable,
    ProfileUnavailable,
    Unsupported,
    InvalidInput,
    Authentication,
    Transport,
    Timeout,
    Integrity,
    LocalIo,
    Unperformed,
}
impl Reason {
    fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PackageAbsent => "package_absent",
            Self::VariantUnavailable => "variant_unavailable",
            Self::ProfileUnavailable => "profile_unavailable",
            Self::Unsupported => "unsupported",
            Self::InvalidInput => "invalid_input",
            Self::Authentication => "authentication",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Integrity => "integrity",
            Self::LocalIo => "local_io",
            Self::Unperformed => "unperformed",
        }
    }
}

#[derive(Clone, Debug)]
struct Item {
    // Raw lookup keys are retained only in memory, never serialized blindly.
    key: (String, Option<String>),
    status: Status,
    reason: Reason,
}
#[derive(Clone, Debug)]
pub struct Report {
    source: String,
    operation: String,
    items: Vec<Item>,
    succeeded: bool,
}

fn safe_package(value: &str) -> bool {
    // Safe serialization envelope, not Android/store semantic validation.
    // F-Droid permits nonstandard IDs; each source records InvalidInput itself.
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'))
}
fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, b'.' | b'_' | b'-' | b'+' | b'(' | b')' | b'[' | b']')
        })
}
impl Report {
    pub fn new(
        source: &str,
        operation: &str,
        requests: Vec<(String, Option<String>)>,
    ) -> Result<Self, &'static str> {
        if requests.len() > 65536 {
            return Err("result report input limit exceeded");
        }
        if !matches!(
            source,
            "apk-pure" | "f-droid" | "google-play" | "ru-store" | "huawei-app-gallery"
        ) || !matches!(operation, "download" | "list")
        {
            return Err("invalid result report context");
        }
        Ok(Self {
            source: source.to_owned(),
            operation: operation.to_owned(),
            succeeded: false,
            items: requests
                .into_iter()
                .map(|key| {
                    let valid = safe_package(&key.0) && key.1.as_deref().is_none_or(safe_version);
                    Item {
                        key,
                        status: Status::Error,
                        reason: if valid {
                            Reason::Unperformed
                        } else {
                            Reason::InvalidInput
                        },
                    }
                })
                .collect(),
        })
    }
    pub fn finish(&mut self, succeeded: bool) {
        // An uninstrumented/default item cannot become success from an aggregate bool.
        self.succeeded = succeeded
            && !self.items.is_empty()
            && self.items.iter().all(|item| item.status == Status::Success);
    }
    /// A failed operational sink invalidates delivered success/availability,
    /// but does not erase an already-known provider error or invalid-input redaction.
    pub fn output_failed(&mut self) {
        self.succeeded = false;
        for item in &mut self.items {
            if item.status != Status::Error || item.reason == Reason::Unperformed {
                item.status = Status::Error;
                item.reason = Reason::LocalIo;
            }
        }
    }
    pub fn succeeded(&self) -> bool {
        self.succeeded
    }
    /// Publish a complete bounded JSON document into an already pinned directory.
    /// Existing files, symlinks and concurrent winners are never replaced.
    pub fn write_to(
        &self,
        directory: &tokio_dl_stream_to_disk::OutputDirectory,
        name: &str,
    ) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind, Write};
        if name.is_empty()
            || name.len() > 240
            || matches!(name, "." | "..")
            || name
                .chars()
                .any(|c| c == '/' || c == '\\' || c.is_control())
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid report filename",
            ));
        }
        let bytes = self
            .json_bytes()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid result report"))?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".apkeep-report-")
            .tempfile_in(directory.path())?;
        temporary.write_all(&bytes)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(directory.path().join(name))
            .map_err(|e| e.error)?;
        Ok(())
    }

    pub fn json_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let items: Vec<_> = self
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let valid = item.reason != Reason::InvalidInput;
                let package = (valid && safe_package(&item.key.0)).then_some(item.key.0.as_str());
                let version = item.key.1.as_deref().filter(|v| valid && safe_version(v));
                serde_json::json!({"index": index, "package": package, "version": version,
                "status": item.status.name(), "reason": item.reason.name()})
            })
            .collect();
        let bytes = serde_json::to_vec(&serde_json::json!({"schema_version": 1,
            "source": self.source, "operation": self.operation, "success": self.succeeded,
            "results": items}))
        .map_err(|_| "cannot serialize result report")?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("result report size limit exceeded");
        }
        Ok(bytes)
    }
}

tokio::task_local! {
    static ACTIVE_REPORT: RefCell<Report>;
    // Each concurrently polled item has its own retry-local outcome. Spawned
    // tasks do not inherit this scope. Only the owner publishes its final result.
    static ITEM_OUTCOME: RefCell<(Status, Reason)>;
}

pub fn note(status: Status, reason: Reason) {
    let _ = ITEM_OUTCOME.try_with(|slot| *slot.borrow_mut() = (status, reason));
}

pub fn error<T>(value: T, reason: Reason) -> T {
    note(Status::Error, reason);
    value
}

pub fn failure_reason(error: &(dyn std::error::Error + 'static)) -> Reason {
    typed_failure_reason(error).unwrap_or(Reason::Integrity)
}

// Unknown message errors are not evidence of integrity failure inside an I/O
// wrapper. Keep the outer kind's fallback, while preserving recognized types.
fn typed_failure_reason(error: &(dyn std::error::Error + 'static)) -> Option<Reason> {
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return Some(if error.is_timeout() {
            Reason::Timeout
        } else if error.is_body() || error.is_decode() {
            Reason::Integrity
        } else if error
            .status()
            .is_some_and(|s| matches!(s.as_u16(), 401 | 403))
        {
            Reason::Authentication
        } else {
            Reason::Transport
        });
    }
    if error.is::<tokio::time::error::Elapsed>() {
        return Some(Reason::Timeout);
    }
    if let Some(error) = error.downcast_ref::<TransferFailure>() {
        return Some(error.0);
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        use std::io::ErrorKind;
        // Explicit adapter deadlines and local permission failures are decisive,
        // even if a different typed error was attached as their context.
        match error.kind() {
            ErrorKind::TimedOut => return Some(Reason::Timeout),
            ErrorKind::PermissionDenied => return Some(Reason::LocalIo),
            _ => {}
        }
        return Some(
            error
                .get_ref()
                .and_then(|inner| typed_failure_reason(inner))
                .unwrap_or(if error.kind() == ErrorKind::InvalidData {
                    Reason::Integrity
                } else {
                    Reason::LocalIo
                }),
        );
    }
    None
}

#[derive(Debug)]
pub struct TransferFailure(Reason, &'static str);
impl std::fmt::Display for TransferFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for TransferFailure {}
pub fn download_failure(error: tokio_dl_stream_to_disk::error::Error) -> TransferFailure {
    TransferFailure(download_reason(&error), "artifact transfer failed")
}
pub fn sha256_failure(error: tokio_dl_stream_to_disk::error::Error) -> TransferFailure {
    TransferFailure(download_reason(&error), "SHA256-verified transfer failed")
}
pub fn download_reason(error: &tokio_dl_stream_to_disk::error::Error) -> Reason {
    use tokio_dl_stream_to_disk::error::ErrorKind;
    match error.kind() {
        ErrorKind::FileExists | ErrorKind::DirectoryMissing | ErrorKind::PermissionDenied => {
            Reason::LocalIo
        }
        ErrorKind::InvalidResponse => Reason::Transport,
        ErrorKind::IO(error) => failure_reason(error),
        ErrorKind::Other(error) => failure_reason(error.as_ref()),
    }
}

pub fn complete() {
    note(Status::Success, Reason::Complete);
}

/// Preserve the bool facade, but never derive a successful report from that
/// bool alone. Actual successful publication/listing branches must mark complete.
pub async fn observe(
    package: &str,
    version: Option<&str>,
    future: impl Future<Output = bool>,
) -> bool {
    let (ok, (mut status, mut reason)) = ITEM_OUTCOME
        .scope(RefCell::new((Status::Error, Reason::Unperformed)), async {
            let ok = future.await;
            (ok, ITEM_OUTCOME.with(|slot| *slot.borrow()))
        })
        .await;
    if !ok && status == Status::Success {
        status = Status::Error;
        reason = Reason::Unperformed;
    }
    record(package, version, status, reason);
    ok
}

/// Annotate preflight failures before provider work, leaving invalid inputs redacted.
pub fn pending_error(reason: Reason) {
    let _ = ACTIVE_REPORT.try_with(|slot| {
        for item in &mut slot.borrow_mut().items {
            if item.reason == Reason::Unperformed {
                item.reason = reason;
            }
        }
    });
}

pub fn batch_error(apps: &[(String, Option<String>)], reason: Reason) {
    for (package, version) in apps {
        record(package, version.as_deref(), Status::Error, reason);
    }
}

/// Collect within this task's async scope, including concurrently polled item
/// futures. No process-global last error and no cross-request mutable state.
/// Spawned tasks do not inherit the scope: their items stay `unperformed` unless
/// their typed return values are explicitly recorded by the owning task.
pub async fn collect<T>(report: Report, future: impl Future<Output = T>) -> (T, Report) {
    ACTIVE_REPORT
        .scope(RefCell::new(report), async {
            let result = future.await;
            let report = ACTIVE_REPORT.with(|slot| slot.borrow().clone());
            (result, report)
        })
        .await
}

/// Record an actual typed provider outcome. Identical input rows share the same
/// outcome without racing two transfers; their ordered report rows are preserved.
pub fn record(package: &str, version: Option<&str>, status: Status, reason: Reason) {
    // Refuse inconsistent claims; unknown errors must never become absence.
    let consistent = matches!(
        (status, reason),
        (Status::Success, Reason::Complete)
            | (Status::NotFound, Reason::PackageAbsent)
            | (
                Status::Unavailable,
                Reason::VariantUnavailable | Reason::ProfileUnavailable | Reason::Unsupported
            )
            | (
                Status::Error,
                Reason::InvalidInput
                    | Reason::Authentication
                    | Reason::Transport
                    | Reason::Timeout
                    | Reason::Integrity
                    | Reason::LocalIo
                    | Reason::Unperformed
            )
    );
    if !consistent {
        return;
    }
    let _ = ACTIVE_REPORT.try_with(|slot| {
        let mut report = slot.borrow_mut();
        for item in &mut report.items {
            if item.key.0 == package && item.key.1.as_deref() == version {
                if item.reason == Reason::InvalidInput {
                    continue;
                }
                // A later contradictory result fails closed instead of masking
                // an earlier provider failure with success or absence.
                if item.reason != Reason::Unperformed
                    && (item.status != status || item.reason != reason)
                {
                    item.status = Status::Error;
                    item.reason = Reason::Integrity;
                } else {
                    item.status = status;
                    item.reason = reason;
                }
            }
        }
    });
}

#[cfg(test)]
#[path = "results_tests.rs"]
mod tests;
