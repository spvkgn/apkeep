use crate::results::{self, Reason, Status};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};

use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use base64::{engine::general_purpose as b64_general_purpose, Engine as _};
use cryptographic_message_syntax::{SignedData, SignerInfo};
use futures_util::StreamExt;
use indicatif::MultiProgress;
use regex::Regex;
use ring::digest::{Context, SHA256};
use serde_json::{json, Value};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use simple_error::SimpleError;
use tempfile::{tempdir, TempDir};
use tokio::time::{sleep, Duration};
use tokio_dl_stream_to_disk::{
    public_http_client_builder, validate_public_url, AsyncDownload, OutputDirectory,
};
use x509_certificate::certificate::CapturedX509Certificate;

use crate::config;
use crate::consts;
use crate::util::{progress_bar::progress_wrapper, OutputFormat};
#[path = "fdroid/error.rs"]
mod error;
use error::Error as FDroidError;

#[cfg(test)]
#[path = "fdroid_tests.rs"]
mod tests;

async fn retrieve_index(
    options: &HashMap<&str, &str>,
    mp: Rc<MultiProgress>,
    output_format: OutputFormat,
    client: Option<&reqwest::Client>,
) -> Result<Value, Box<dyn Error>> {
    let config_dir = config::config_directory().map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "F-Droid cache directory unavailable.",
        )
    })?;
    retrieve_index_using_cache_pinned(options, mp, output_format, &config_dir, client).await
}

#[cfg(test)]
async fn retrieve_index_using_cache(
    options: &HashMap<&str, &str>,
    mp: Rc<MultiProgress>,
    output_format: OutputFormat,
    config_dir: &Path,
    client: Option<&reqwest::Client>,
) -> Result<Value, Box<dyn Error>> {
    let config_dir = OutputDirectory::open(config_dir)?;
    retrieve_index_using_cache_pinned(options, mp, output_format, &config_dir, client).await
}

async fn retrieve_index_using_cache_pinned(
    options: &HashMap<&str, &str>,
    mp: Rc<MultiProgress>,
    output_format: OutputFormat,
    config_dir: &OutputDirectory,
    client: Option<&reqwest::Client>,
) -> Result<Value, Box<dyn Error>> {
    // Reverify the signed archive on every cache hit. Never reuse the old
    // unsigned JSON cache, shared with verify-index=false and different pins.
    let temp_dir = tempdir()?;
    let (repo, fingerprint, use_entry, verify_index) = repository_options(options)?;
    let cache_dir = config_dir.create_child(Path::new("fdroid-signed-archives"))?;
    let cache_name = hex::encode(Sha256::digest(format!("{repo}:{use_entry}")));
    let cache = cache_dir.path().join(&cache_name);
    let etag =
        download_repository_archive_pinned(&temp_dir, &repo, use_entry, Some(&cache), client)
            .await?;
    let files = extract_archive(&temp_dir, &temp_dir.path().join("jar.zip"))?;
    let json = verify_and_return_json(
        &temp_dir,
        &files,
        &fingerprint,
        verify_index,
        use_entry,
        Rc::clone(&mp),
    )?;
    let index = if use_entry {
        verify_and_return_index_from_entry(
            &temp_dir,
            &repo,
            &json,
            verify_index,
            mp,
            output_format,
            client,
        )
        .await?
    } else {
        json
    };
    let parsed = serde_json::from_str(&index)?;
    // Cache only after the full verification/JSON chain has succeeded.
    if let Some(etag) = etag {
        write_cache_file_pinned(
            &cache_dir,
            &format!("{cache_name}.jar"),
            &fs::read(temp_dir.path().join("jar.zip"))?,
        )?;
        write_cache_file_pinned(&cache_dir, &format!("{cache_name}.etag"), etag.as_bytes())?;
    }
    Ok(parsed)
}

fn repository_options(
    options: &HashMap<&str, &str>,
) -> Result<(String, Vec<u8>, bool, bool), Box<dyn Error>> {
    let mut repo = consts::FDROID_REPO.to_owned();
    let mut fingerprint = consts::FDROID_INDEX_FINGERPRINT.to_vec();
    if let Some(value) = options.get("repo") {
        if let Some((address, pin)) = value.split_once("?fingerprint=") {
            repo = address.to_owned();
            fingerprint = hex::decode(pin)?;
            if fingerprint.len() != 32 {
                return Err(Box::new(SimpleError::new(
                    "F-Droid fingerprint must contain exactly 32 bytes.",
                )));
            }
        } else {
            repo = value.to_string();
        }
    }
    let url = reqwest::Url::parse(&repo)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Box::new(SimpleError::new(
            "Invalid F-Droid repository URL.",
        )));
    }
    let use_entry = !options
        .get("use_entry")
        .is_some_and(|v| *v == "0" || v.eq_ignore_ascii_case("false"));
    let verify_index = options.get("verify-index") != Some(&"false");
    Ok((repo, fingerprint, use_entry, verify_index))
}

// Allowlist, not URL redaction: redirects and third-party error chains may
// contain signed URLs, bodies or credentials. Never Display/Debug/source an
// untrusted error at a user boundary, even if its outer message seems benign.
fn safe_error_summary(err: &(dyn Error + 'static)) -> String {
    if let Some(err) = err.downcast_ref::<reqwest::Error>() {
        if let Some(status) = err.status() {
            return format!("HTTP status {}", status.as_u16());
        }
        return if err.is_timeout() {
            "network request timed out"
        } else if err.is_connect() {
            "network connection failed"
        } else if err.is_body() || err.is_decode() {
            "network response transfer failed"
        } else {
            "network request failed"
        }
        .to_owned();
    }
    if err.is::<tokio::time::error::Elapsed>() {
        "operation timed out"
    } else if err.is::<io::Error>() {
        "filesystem or transfer I/O failed"
    } else if err.is::<serde_json::Error>() {
        "invalid repository JSON"
    } else if err.is::<zip::result::ZipError>() {
        "invalid repository archive"
    } else {
        "repository data validation or verification failed"
    }
    .to_owned()
}

fn print_error(err_msg: &str, output_format: OutputFormat) {
    eprintln!("{}", err_msg);
    if output_format.is_json() {
        cli_println!("{}", json!({"error": err_msg}));
    }
}

pub async fn download_apps(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    options: HashMap<&str, &str>,
) -> bool {
    download_apps_with_client(apps, parallel, sleep_duration, outpath, options, None).await
}

async fn download_apps_with_client(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    options: HashMap<&str, &str>,
    client: Option<&reqwest::Client>,
) -> bool {
    if !super::check_parallel(&apps, parallel) {
        return false;
    }
    let (apps, all_valid) = valid_requests(apps);
    if options
        .get("arch")
        .is_some_and(|value| !safe_component(value))
    {
        results::batch_error(&apps, Reason::InvalidInput);
        eprintln!("Invalid F-Droid architecture.");
        return false;
    }
    if apps.is_empty() {
        eprintln!("No F-Droid applications requested.");
        return false;
    }
    let output = match OutputDirectory::open(outpath) {
        Ok(output) => output,
        Err(_) => {
            results::batch_error(&apps, Reason::LocalIo);
            eprintln!("F-Droid: unsafe output directory");
            return false;
        }
    };
    let mp = Rc::new(MultiProgress::new());
    let index =
        match retrieve_index(&options, Rc::clone(&mp), OutputFormat::Plaintext, client).await {
            Ok(index) => index,
            Err(err) => {
                results::batch_error(&apps, results::failure_reason(err.as_ref()));
                eprintln!(
                    "Could not retrieve verified F-Droid package index: {}",
                    safe_error_summary(err.as_ref())
                );
                return false;
            }
        };
    let (repo, verified_index) = match repository_options(&options) {
        Ok((repo, _, _, verified_index)) => (repo, verified_index),
        Err(_) => {
            results::batch_error(&apps, Reason::InvalidInput);
            return false;
        }
    };
    let downloaded = download_from_index_pinned(
        index,
        apps,
        parallel,
        sleep_duration,
        &output,
        options.get("arch").map(|value| value.to_string()),
        RepositoryDownload {
            repo: &repo,
            client,
            progress: mp,
            verified_index,
        },
    )
    .await;
    downloaded && all_valid
}

fn valid_requests(apps: Vec<(String, Option<String>)>) -> (Vec<(String, Option<String>)>, bool) {
    let mut all_valid = true;
    let apps = apps
        .into_iter()
        .filter(|(id, version)| {
            let valid = safe_component(id) && version.as_deref().is_none_or(safe_component);
            if !valid {
                results::record(id, version.as_deref(), Status::Error, Reason::InvalidInput);
                eprintln!("Invalid F-Droid package/version.");
                all_valid = false;
            }
            valid
        })
        .collect();
    (apps, all_valid)
}

struct RepositoryDownload<'a> {
    repo: &'a str,
    client: Option<&'a reqwest::Client>,
    progress: Rc<MultiProgress>,
    verified_index: bool,
}

#[cfg(test)]
async fn download_from_index(
    index: Value,
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    arch: Option<String>,
    repository: RepositoryDownload<'_>,
) -> bool {
    let output = match OutputDirectory::open(outpath) {
        Ok(output) => output,
        Err(_) => {
            results::batch_error(&apps, Reason::LocalIo);
            eprintln!("F-Droid: unsafe output directory");
            return false;
        }
    };
    download_from_index_pinned(
        index,
        apps,
        parallel,
        sleep_duration,
        &output,
        arch,
        repository,
    )
    .await
}

async fn download_from_index_pinned(
    index: Value,
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    output: &OutputDirectory,
    arch: Option<String>,
    repository: RepositoryDownload<'_>,
) -> bool {
    if !super::check_parallel(&apps, parallel) {
        return false;
    }
    let outpath = output.path();
    let RepositoryDownload {
        repo: configured_repo,
        client,
        progress: mp,
        verified_index,
    } = repository;
    // Architecture is common to this batch. Collapse identical app/version
    // requests before counting selections or spawning jobs for the same path.
    let mut seen = HashSet::new();
    let apps: Vec<_> = apps
        .into_iter()
        .filter(|app| seen.insert(app.clone()))
        .collect();
    let requested = apps.len();
    if requested == 0 {
        eprintln!("No F-Droid applications requested.");
        return false;
    }
    // An index may advertise its canonical origin, but it is not routing
    // authority: both metadata and APK requests stay on the configured mirror.
    let repo = configured_repo.to_owned();
    let requests = apps.clone();
    let failures: Vec<_> = apps
        .iter()
        .map(|(id, _)| selection_failure(&index, id))
        .collect();
    let (jobs, _advertised_repo) =
        match parse_json_for_download_information(index, apps, arch.clone(), Rc::clone(&mp)) {
            Ok(info) => info,
            Err(err) => {
                results::batch_error(&requests, Reason::Integrity);
                eprintln!(
                    "Could not parse F-Droid package index: {}",
                    safe_error_summary(&err)
                );
                return false;
            }
        };
    for ((id, version), (status, reason)) in requests.iter().zip(failures) {
        if !jobs.iter().any(|job| &job.0 == id && &job.1 == version) {
            let (status, reason) = if status == Status::NotFound && !verified_index {
                (Status::Error, Reason::Integrity)
            } else {
                (status, reason)
            };
            results::record(id, version.as_deref(), status, reason);
        }
    }
    let complete_selection = jobs.len() == requested;
    if !complete_selection {
        eprintln!("Some requested F-Droid applications or variants are unavailable/invalid.");
    }
    let outcomes = futures_util::stream::iter(jobs.into_iter().map(|(id, version, name, hash)| {
        let repo = repo.clone();
        let arch = arch.clone();
        let mp = Rc::clone(&mp);
        async move {
            results::observe(&id, version.as_deref(), async {
                results::note(Status::Error, Reason::Integrity);
                let mut label = id.clone();
                if let Some(version) = &version {
                    label.push('@');
                    label.push_str(version);
                }
                if let Some(arch) = arch {
                    label.push('@');
                    label.push_str(&arch);
                }
                let filename = format!("{label}.apk");
                if filename.len() > 255 {
                    results::note(Status::Error, Reason::InvalidInput);
                    eprintln!("F-Droid output filename too long: {label}");
                    return false;
                }
                let target = outpath.join(&filename);
                match fs::symlink_metadata(&target) {
                    Ok(metadata) => {
                        // Existing regular files are successful skips only when the
                        // complete expected digest matches. Symlinks are never skips.
                        let ok = if metadata.file_type().is_file() {
                            match file_matches_sha256(&target, &hash).await {
                                Ok(matches) => matches,
                                Err(err) => {
                                    results::note(Status::Error, results::failure_reason(&err));
                                    eprintln!(
                                        "Could not verify existing {}: {}",
                                        target.display(),
                                        safe_error_summary(&err)
                                    );
                                    false
                                }
                            }
                        } else {
                            results::note(Status::Error, Reason::LocalIo);
                            false
                        };
                        if !ok {
                            eprintln!(
                                "Unsafe or mismatching existing F-Droid destination: {}",
                                target.display()
                            );
                        }
                        if ok {
                            results::complete();
                        }
                        return ok;
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => {
                        results::note(Status::Error, Reason::LocalIo);
                        eprintln!(
                            "Could not inspect {}: {}",
                            target.display(),
                            safe_error_summary(&err)
                        );
                        return false;
                    }
                }
                if sleep_duration > 0 {
                    sleep(Duration::from_millis(sleep_duration)).await;
                }
                let url = format!(
                    "{}/{}",
                    repo.trim_end_matches('/'),
                    name.trim_start_matches('/')
                );
                for attempt in 1..=3 {
                    let transfer = async {
                        let download = AsyncDownload::new_in(&url, output, &filename)?
                            .with_max_bytes(MAX_APK_BYTES)
                            .with_client(http_client_for_url(&url, client)?);
                        let mut dl = download.get().await?;
                        let cb = dl.length().map(|length| {
                            progress_wrapper(Rc::clone(&mp))(filename.clone(), length)
                        });
                        dl.download_and_verify_sha256(&hash, &cb)
                            .await
                            .map_err(results::download_failure)?;
                        Ok::<(), Box<dyn Error>>(())
                    };
                    match tokio::time::timeout(REQUEST_TIMEOUT, transfer).await {
                        Ok(Ok(())) => {
                            cli_println!("{label} downloaded successfully!");
                            results::complete();
                            return true;
                        }
                        Ok(Err(err)) => {
                            results::note(Status::Error, results::failure_reason(err.as_ref()));
                            eprintln!(
                                "F-Droid {label}, attempt {attempt}/3: {}",
                                safe_error_summary(err.as_ref())
                            );
                        }
                        Err(_) => {
                            results::note(Status::Error, Reason::Timeout);
                            eprintln!("F-Droid {label}, attempt {attempt}/3 timed out.");
                        }
                    }
                }
                false
            })
            .await
        }
    }))
    .buffer_unordered(parallel.max(1))
    .collect::<Vec<bool>>()
    .await;
    complete_selection && !outcomes.is_empty() && outcomes.into_iter().all(|ok| ok)
}

async fn file_matches_sha256(path: &Path, expected: &[u8]) -> Result<bool, io::Error> {
    file_matches_sha256_bounded(path, expected, MAX_APK_BYTES, REQUEST_TIMEOUT).await
}

async fn file_matches_sha256_bounded(
    path: &Path,
    expected: &[u8],
    limit: u64,
    deadline: Duration,
) -> Result<bool, io::Error> {
    tokio::time::timeout(deadline, async {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = options.open(path).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Existing APK exceeds size policy.",
            ));
        }
        hash_reader_matches(&mut file, expected, limit).await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Existing APK verification timed out.",
        )
    })?
}

async fn hash_reader_matches<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    expected: &[u8],
    limit: u64,
) -> Result<bool, io::Error> {
    use tokio::io::AsyncReadExt;
    // Size precheck alone is insufficient if a regular file grows while read.
    // Consume at most limit + 1 bytes with a fixed 8 KiB buffer.
    let mut reader = reader.take(limit.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut buffer = [0; 8192];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            break;
        }
        received += length as u64;
        if received > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Existing APK exceeds size policy.",
            ));
        }
        hasher.update(&buffer[..length]);
    }
    Ok(hasher.finalize().as_slice() == expected)
}

type DownloadInformation = (Vec<(String, Option<String>, String, Vec<u8>)>, String);
// Classify an unsuccessful selection without treating corrupt metadata as
// authoritative package absence. Only a missing key in a verified index is absent.
fn selection_failure(index: &Value, id: &str) -> (Status, Reason) {
    let Some(packages) = index.get("packages").and_then(Value::as_object) else {
        return (Status::Error, Reason::Integrity);
    };
    let Some(package) = packages.get(id) else {
        return (Status::NotFound, Reason::PackageAbsent);
    };
    let valid_hash = |v: Option<&str>| {
        v.and_then(|v| hex::decode(v).ok())
            .is_some_and(|h| h.len() == 32)
    };
    let valid_name =
        |v: Option<&str>| v.is_some_and(|v| safe_repo_name(v.strip_prefix('/').unwrap_or(v)));
    let valid_abis = |value: Option<&Value>| {
        value.is_none_or(|v| {
            v.as_array().is_some_and(|abis| {
                abis.iter()
                    .all(|abi| abi.as_str().is_some_and(safe_component))
            })
        })
    };
    let valid = if let Some(entries) = package.as_array() {
        !entries.is_empty()
            && entries.iter().all(|entry| {
                entry.get("versionName").and_then(Value::as_str).is_some()
                    && entry.get("versionCode").and_then(Value::as_u64).is_some()
                    && valid_hash(entry.get("hash").and_then(Value::as_str))
                    && valid_name(entry.get("apkName").and_then(Value::as_str))
                    && valid_abis(entry.get("nativecode"))
            })
    } else if let Some(entries) = package.get("versions").and_then(Value::as_object) {
        !entries.is_empty()
            && entries.values().all(|entry| {
                entry["manifest"]["versionName"].as_str().is_some()
                    && entry["manifest"]["versionCode"].as_u64().is_some()
                    && valid_hash(entry["file"]["sha256"].as_str())
                    && valid_name(entry["file"]["name"].as_str())
                    && valid_abis(entry["manifest"].get("nativecode"))
            })
    } else {
        false
    };
    if valid {
        (Status::Unavailable, Reason::VariantUnavailable)
    } else {
        (Status::Error, Reason::Integrity)
    }
}

/// This currently works for `index-v1.json` as well as an index with version `20002`.  It is
/// flexible enough to parse either, and may work on future index versions as well.  Since `sha256`
/// digests are checked before proceeding, I don't foresee this having an insecure failure mode, so
/// checking the index version and making the parsing overly brittle has no substantive advantage.
fn parse_json_for_download_information(
    index: Value,
    apps: Vec<(String, Option<String>)>,
    app_arch: Option<String>,
    _mp_log: Rc<MultiProgress>,
) -> Result<DownloadInformation, FDroidError> {
    let index_map = index.as_object().ok_or(FDroidError::Dummy)?;
    let repo_address = index_map
        .get("repo")
        .ok_or(FDroidError::Dummy)?
        .get("address")
        .ok_or(FDroidError::Dummy)?
        .as_str()
        .ok_or(FDroidError::Dummy)?;

    let packages = index_map
        .get("packages")
        .ok_or(FDroidError::Dummy)?
        .as_object()
        .ok_or(FDroidError::Dummy)?;

    let fdroid_apps: Vec<(String, Option<String>, String, Vec<u8>)> = apps
        .into_iter()
        .map(|app| {
            let (app_id, app_version) = app;
            if !safe_component(&app_id)
                || app_version
                    .as_deref()
                    .is_some_and(|value| !safe_component(value))
                || app_arch
                    .as_deref()
                    .is_some_and(|value| !safe_component(value))
            {
                eprintln!("Unsafe F-Droid package/version/architecture.");
                return None;
            }
            match packages.get(&app_id) {
                Some(Value::Array(app_array)) => {
                    let mut candidates: Vec<&Value> = app_array.iter().collect();
                    if app_version.is_none() {
                        candidates.retain(|candidate| {
                            candidate
                                .get("versionCode")
                                .and_then(Value::as_u64)
                                .is_some()
                        });
                        candidates.sort_by_key(|candidate| {
                            std::cmp::Reverse(candidate["versionCode"].as_u64().unwrap_or(0))
                        });
                    }
                    for single_app in candidates {
                        if let Value::Object(fdroid_app) = single_app {
                            if let Some(Value::String(version_name)) = fdroid_app.get("versionName")
                            {
                                if app_version
                                    .as_ref()
                                    .is_none_or(|requested| version_name == requested)
                                {
                                    if let (
                                        Some(Value::String(filename)),
                                        Some(Value::String(hash)),
                                    ) = (fdroid_app.get("apkName"), fdroid_app.get("hash"))
                                    {
                                        if let Ok(hash) = hex::decode(hash.to_string()) {
                                            if !safe_repo_name(
                                                filename.strip_prefix('/').unwrap_or(filename),
                                            ) || hash.len() != 32
                                            {
                                                continue;
                                            }
                                            if let Some(arch) = &app_arch {
                                                if let Some(Value::Array(nativecode_array)) =
                                                    fdroid_app.get("nativecode")
                                                {
                                                    if nativecode_array.iter().any(|value| {
                                                        if let Value::String(value_str) = value {
                                                            value_str == arch
                                                        } else {
                                                            false
                                                        }
                                                    }) {
                                                        return Some((
                                                            app_id,
                                                            app_version,
                                                            filename.to_string(),
                                                            hash,
                                                        ));
                                                    }
                                                }
                                            } else {
                                                return Some((
                                                    app_id,
                                                    app_version,
                                                    filename.to_string(),
                                                    hash,
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let arch_str = app_arch
                        .as_ref()
                        .map_or("".to_string(), |x| format!(" {}", x));
                    eprintln!(
                        "Could not find version {}{} of {}.",
                        app_version.as_deref().unwrap_or("latest"),
                        arch_str,
                        app_id
                    );
                    return None;
                }
                Some(Value::Object(app_object)) => {
                    if let Some(Value::Object(versions)) = app_object.get("versions") {
                        let mut latest_version = 0;
                        let mut filename = String::new();
                        let mut hash = Vec::new();
                        for (_, version_value) in versions {
                            if let Value::Object(version) = version_value {
                                if let (Some(Value::Object(manifest)), Some(Value::Object(file))) =
                                    (version.get("manifest"), version.get("file"))
                                {
                                    if let Some(arch) = &app_arch {
                                        if !manifest
                                            .get("nativecode")
                                            .and_then(Value::as_array)
                                            .is_some_and(|abis| {
                                                abis.iter()
                                                    .any(|abi| abi.as_str() == Some(arch.as_str()))
                                            })
                                        {
                                            continue;
                                        }
                                    }
                                    if let (
                                        Some(Value::String(name)),
                                        Some(Value::String(sha256)),
                                    ) = (file.get("name"), file.get("sha256"))
                                    {
                                        let sha256 = match hex::decode(sha256) {
                                            Ok(hash)
                                                if hash.len() == 32
                                                    && safe_repo_name(
                                                        name.strip_prefix('/').unwrap_or(name),
                                                    ) =>
                                            {
                                                hash
                                            }
                                            _ => continue,
                                        };
                                        if app_version.is_some() {
                                            if let Some(Value::String(version_name)) =
                                                manifest.get("versionName")
                                            {
                                                if app_version.as_ref() == Some(version_name) {
                                                    return Some((
                                                        app_id,
                                                        app_version,
                                                        name.to_string(),
                                                        sha256,
                                                    ));
                                                }
                                            }
                                        } else {
                                            if let Some(Value::Number(version_code_number)) =
                                                manifest.get("versionCode")
                                            {
                                                if let Some(version_code) =
                                                    version_code_number.as_u64()
                                                {
                                                    if version_code > latest_version {
                                                        latest_version = version_code;
                                                        filename = name.to_string();
                                                        hash = sha256;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if app_version.is_none() && !filename.is_empty() {
                            return Some((app_id, app_version, filename, hash));
                        }
                    }
                }
                _ => eprintln!("Could not find {} in package list.", app_id),
            }
            None
        })
        .flatten()
        .collect();

    Ok((fdroid_apps, repo_address.to_string()))
}

pub async fn list_versions(
    apps: Vec<(String, Option<String>)>,
    options: HashMap<&str, &str>,
) -> bool {
    list_versions_with_client(apps, options, None).await
}

async fn list_versions_with_client(
    apps: Vec<(String, Option<String>)>,
    options: HashMap<&str, &str>,
    client: Option<&reqwest::Client>,
) -> bool {
    let (apps, all_valid) = valid_requests(apps);
    let output_format = if options
        .get("output_format")
        .is_some_and(|v| v.eq_ignore_ascii_case("json"))
    {
        OutputFormat::Json
    } else {
        OutputFormat::Plaintext
    };
    if apps.is_empty() {
        print_error("No F-Droid applications requested.", output_format);
        return false;
    }
    let index = match retrieve_index(
        &options,
        Rc::new(MultiProgress::new()),
        output_format.clone(),
        client,
    )
    .await
    {
        Ok(index) => index,
        Err(err) => {
            results::batch_error(&apps, results::failure_reason(err.as_ref()));
            print_error(
                &format!(
                    "Could not retrieve F-Droid package index: {}",
                    safe_error_summary(err.as_ref())
                ),
                output_format,
            );
            return false;
        }
    };
    let verified_index = repository_options(&options).is_ok_and(|(_, _, _, verify)| verify);
    match parse_json_display_versions_with_trust(index, apps, output_format.clone(), verified_index)
    {
        Ok(()) => all_valid,
        Err(err) => {
            // The parser has already emitted its single JSON result, including
            // per-app errors. A second JSON object would corrupt stdout.
            eprintln!(
                "Could not list all F-Droid versions: {}",
                safe_error_summary(&err)
            );
            false
        }
    }
}

/// The comments for `parse_json_for_download_information` apply here, too.
#[cfg(test)]
fn parse_json_display_versions(
    index: Value,
    apps: Vec<(String, Option<String>)>,
    output_format: OutputFormat,
) -> Result<(), FDroidError> {
    parse_json_display_versions_with_trust(index, apps, output_format, true)
}
fn parse_json_display_versions_with_trust(
    index: Value,
    apps: Vec<(String, Option<String>)>,
    output_format: OutputFormat,
    verified_index: bool,
) -> Result<(), FDroidError> {
    let packages = match index.get("packages").and_then(Value::as_object) {
        Some(packages) => packages,
        None => {
            results::batch_error(&apps, Reason::Integrity);
            print_error("Invalid F-Droid package index.", output_format);
            return Err(FDroidError::Dummy);
        }
    };
    let mut all_ok = !apps.is_empty();
    let mut json_root = HashMap::new();
    for (app_id, version) in apps {
        let mut versions = HashSet::new();
        let valid = safe_component(&app_id) && version.as_deref().is_none_or(safe_component);
        if valid {
            match packages.get(&app_id) {
                Some(Value::Array(entries)) => {
                    for entry in entries {
                        if let Some(name) = entry.get("versionName").and_then(Value::as_str) {
                            if !name.is_empty() {
                                versions.insert(name.to_owned());
                            }
                        }
                    }
                }
                Some(Value::Object(package)) => {
                    if let Some(entries) = package.get("versions").and_then(Value::as_object) {
                        for entry in entries.values() {
                            if let Some(name) = entry
                                .get("manifest")
                                .and_then(|m| m.get("versionName"))
                                .and_then(Value::as_str)
                            {
                                if !name.is_empty() {
                                    versions.insert(name.to_owned());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if versions.is_empty() {
            let (status, reason) = if !valid {
                (Status::Error, Reason::InvalidInput)
            } else if verified_index && !packages.contains_key(&app_id) {
                (Status::NotFound, Reason::PackageAbsent)
            } else {
                (Status::Error, Reason::Integrity)
            };
            results::record(&app_id, version.as_deref(), status, reason);
            all_ok = false;
            eprintln!("No F-Droid versions available for {app_id} (invalid, missing or malformed package).");
            json_root.insert(
                app_id,
                json!({"error": "No versions available or invalid request."}),
            );
            continue;
        }
        results::record(
            &app_id,
            version.as_deref(),
            Status::Success,
            Reason::Complete,
        );
        let mut versions: Vec<_> = versions.into_iter().collect();
        versions.sort();
        if output_format.is_plaintext() {
            cli_println!(
                "Versions available for {app_id} on F-Droid:\n| {}",
                versions
                    .iter()
                    .map(|version| {
                        version
                            .chars()
                            .map(|ch| {
                                if ch.is_control() {
                                    ch.escape_default().to_string()
                                } else {
                                    ch.to_string()
                                }
                            })
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        json_root.insert(app_id, json!({"available_versions": versions.into_iter().map(|v| json!({"version": v})).collect::<Vec<_>>()}));
    }
    if output_format.is_json() {
        cli_println!("{}", json!({"source": "F-Droid", "apps": json_root}));
    }
    if all_ok {
        Ok(())
    } else {
        Err(FDroidError::Dummy)
    }
}

fn verify_and_return_json(
    dir: &TempDir,
    files: &[String],
    fingerprint: &[u8],
    verify_index: bool,
    use_entry: bool,
    mp: Rc<MultiProgress>,
) -> Result<String, Box<dyn Error>> {
    let re = Regex::new(consts::FDROID_SIGNATURE_BLOCK_FILE_REGEX)?;
    let cert_file = {
        let mut cert_files = vec![];
        for file in files {
            if re.is_match(file) {
                cert_files.push(file.clone());
            }
        }
        if cert_files.is_empty() {
            return Err(Box::new(SimpleError::new(
                "Found no certificate file for F-Droid repository.",
            )));
        }
        if cert_files.len() > 1 {
            return Err(Box::new(SimpleError::new(
                "Found multiple certificate files for F-Droid repository.",
            )));
        }
        dir.path().join(cert_files[0].clone())
    };
    let signed_file = {
        let mut signed_file = cert_file.clone();
        signed_file.set_extension("SF");
        signed_file
    };

    let signed_content = fs::read(signed_file)?;

    if verify_index {
        mp.println("Verifying...")?;
        let signed_data = get_signed_data_from_cert_file(cert_file)?;
        let signer_info = signed_data
            .signers()
            .next()
            .ok_or_else(|| SimpleError::new("No F-Droid signer."))?;
        if let Some(attributes) = signer_info.signed_attributes() {
            if attributes.content_type()
                != &cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA
            {
                return Err(Box::new(SimpleError::new(
                    "Invalid F-Droid CMS signed content type.",
                )));
            }
            // With signedAttrs the signature covers their DER encoding, not .SF.
            signer_info.verify_signature_with_signed_data(&signed_data)?;
            // Signature verification alone does not bind those attributes to .SF.
            signer_info.verify_message_digest_with_content(&signed_content)?;
        } else {
            // Detached CMS without attributes signs the external .SF directly.
            signer_info
                .verify_signature_with_signed_data_and_content(&signed_data, &signed_content)?;
        }
        let cert = signed_data
            .certificates()
            .next()
            .ok_or_else(|| SimpleError::new("No F-Droid certificate."))?;
        let mut context = Context::new(&SHA256);
        context.update(&cert.encode_ber()?);
        let cert_fingerprint = context.finish();
        if cert_fingerprint.as_ref() != fingerprint {
            return Err(Box::new(SimpleError::new("Fingerprint of the key contained in the F-Droid repository does not match the expected fingerprint.")));
        };
    }

    let signed_file_string = std::str::from_utf8(&signed_content)?;
    let manifest_file = dir.path().join("META-INF").join("MANIFEST.MF");
    let manifest_file_data = fs::read(manifest_file)?;
    if verify_index {
        let (signed_file_regex, sha_algorithm_name) = if use_entry {
            (
                Regex::new(r"\r\nSHA-256-Digest-Manifest: (.*)\r\n")?,
                "sha256sum",
            )
        } else {
            (
                Regex::new(r"\r\nSHA1-Digest-Manifest: (.*)\r\n")?,
                "sha1sum",
            )
        };
        let signed_file_manifest_shasum = b64_general_purpose::STANDARD.decode(
            match signed_file_regex.captures(signed_file_string) {
                Some(caps) if caps.len() >= 2 => caps.get(1).ok_or(FDroidError::Dummy)?.as_str(),
                _ => {
                    return Err(Box::new(SimpleError::new(format!(
                        "Could not retrieve the manifest {} from the signed file.",
                        sha_algorithm_name
                    ))));
                }
            },
        )?;
        let actual_manifest_shasum = if use_entry {
            let mut hasher = Sha256::new();
            hasher.update(manifest_file_data.clone());
            Vec::from(hasher.finalize().as_slice())
        } else {
            let mut hasher = Sha1::new();
            hasher.update(manifest_file_data.clone());
            Vec::from(hasher.finalize().as_slice())
        };
        if signed_file_manifest_shasum != actual_manifest_shasum[..] {
            return Err(Box::new(SimpleError::new(format!(
                "The manifest {} from the signed file does not match the actual manifest {}.",
                sha_algorithm_name, sha_algorithm_name
            ))));
        }
    }

    let manifest_file_string = std::str::from_utf8(&manifest_file_data)?;
    let json_file = if use_entry {
        dir.path().join("entry.json")
    } else {
        dir.path().join("index-v1.json")
    };
    let json_file_data = fs::read(json_file)?;
    if verify_index {
        let (manifest_file_regex, file_algo) = if use_entry {
            (
                Regex::new(r"\r\nName: entry\.json\r\nSHA-256-Digest: (.*)\r\n")?,
                "entry sha256sum",
            )
        } else {
            (
                Regex::new(r"\r\nName: index-v1\.json\r\nSHA1-Digest: (.*)\r\n")?,
                "index sha1sum",
            )
        };
        let manifest_file_shasum = b64_general_purpose::STANDARD.decode(
            match manifest_file_regex.captures(manifest_file_string) {
                Some(caps) if caps.len() >= 2 => caps.get(1).ok_or(FDroidError::Dummy)?.as_str(),
                _ => {
                    return Err(Box::new(SimpleError::new(format!(
                        "Could not retrieve the {} from the manifest file.",
                        file_algo
                    ))));
                }
            },
        )?;
        let actual_shasum = if use_entry {
            let mut hasher = Sha256::new();
            hasher.update(json_file_data.clone());
            Vec::from(hasher.finalize().as_slice())
        } else {
            let mut hasher = Sha1::new();
            hasher.update(json_file_data.clone());
            Vec::from(hasher.finalize().as_slice())
        };
        if manifest_file_shasum != actual_shasum[..] {
            return Err(Box::new(SimpleError::new(format!(
                "The {} from the manifest file does not match the actual {}.",
                file_algo, file_algo
            ))));
        }
    }

    Ok(String::from(std::str::from_utf8(&json_file_data)?))
}

async fn verify_and_return_index_from_entry(
    dir: &TempDir,
    repo: &str,
    json: &str,
    verify_index: bool,
    _mp: Rc<MultiProgress>,
    _output_format: OutputFormat,
    client: Option<&reqwest::Client>,
) -> Result<String, Box<dyn Error>> {
    let entry: Value = serde_json::from_str(json)?;
    let index = entry.get("index").ok_or(FDroidError::Dummy)?;
    let name = index
        .get("name")
        .and_then(Value::as_str)
        .ok_or(FDroidError::Dummy)?;
    let index_name = name.strip_prefix('/').unwrap_or(name);
    if !safe_repo_name(index_name) {
        return Err(Box::new(SimpleError::new(
            "Invalid F-Droid entry index name.",
        )));
    }
    let hash = index
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or(FDroidError::Dummy)?;
    let hash = if verify_index {
        match hex::decode(hash) {
            Ok(hash) if hash.len() == 32 => Some(hash),
            _ => {
                return Err(Box::new(SimpleError::new(
                    "Invalid F-Droid entry index sha256: expected 32 bytes of hex.",
                )))
            }
        }
    } else {
        None
    };
    let index_url = format!("{}/{}", repo.trim_end_matches('/'), index_name);
    // The vendor API checks the digest before atomically publishing the file.
    // Never use the legacy download-then-hash API for authenticated content.
    download_metadata(
        &index_url,
        dir.path(),
        index_name,
        hash.as_deref(),
        MAX_METADATA_BYTES,
        REQUEST_TIMEOUT,
        client,
    )
    .await?;
    read_bounded_string(&dir.path().join(index_name), MAX_METADATA_BYTES)
}

const MAX_APK_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

// A caller-supplied client is an explicit trusted transport seam, used by
// loopback fixtures only. Production entry points always pass None. Initial
// URLs need validation as literal IPs never reach reqwest's DNS resolver.
fn http_client_for_url(
    url: &str,
    injected: Option<&reqwest::Client>,
) -> Result<reqwest::Client, Box<dyn Error>> {
    if let Some(client) = injected {
        return Ok(client.clone());
    }
    validate_public_url(&reqwest::Url::parse(url)?)?;
    Ok(public_http_client_builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()?)
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 200
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
}

fn safe_repo_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .split('/')
            .all(|part| safe_component(part) && !part.contains('+'))
}

fn read_bounded_string(path: &Path, limit: u64) -> Result<String, Box<dyn Error>> {
    let input = open_regular_nofollow(path)?;
    let metadata = input.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > limit {
        return Err(Box::new(SimpleError::new(
            "Invalid or oversized F-Droid metadata file.",
        )));
    }
    let mut bytes = Vec::new();
    input.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Box::new(SimpleError::new(
            "F-Droid metadata exceeds size limit.",
        )));
    }
    Ok(String::from_utf8(bytes)?)
}

async fn download_metadata(
    url: &str,
    dir: &Path,
    name: &str,
    expected: Option<&[u8]>,
    limit: u64,
    deadline: Duration,
    client: Option<&reqwest::Client>,
) -> Result<(), Box<dyn Error>> {
    if !safe_repo_name(name) {
        return Err(Box::new(SimpleError::new("Invalid F-Droid metadata path.")));
    }
    let directory = OutputDirectory::open(dir)?;
    let relative = Path::new(name);
    let parent = directory.create_child(
        relative
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let target = parent
        .path()
        .join(relative.file_name().ok_or(FDroidError::Dummy)?);
    let leaf = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(FDroidError::Dummy)?;
    let download = async {
        let download = AsyncDownload::new_in(url, &parent, leaf)?
            .with_max_bytes(limit)
            .with_client(http_client_for_url(url, client)?);
        let mut dl = download.get().await?;
        if dl.length().is_some_and(|length| length > limit) {
            return Err::<(), Box<dyn Error>>(Box::new(SimpleError::new(
                "F-Droid metadata exceeds size limit.",
            )));
        }
        if let Some(expected) = expected {
            dl.download_and_verify_sha256(expected, &None)
                .await
                .map_err(results::sha256_failure)?;
        } else {
            dl.download(&None)
                .await
                .map_err(results::download_failure)?;
        }
        Ok(())
    };
    tokio::time::timeout(deadline, download).await?
}

fn validate_output_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    OutputDirectory::open(path)?;
    Ok(())
}

fn get_signed_data_from_cert_file(
    signature_block_file: PathBuf,
) -> Result<SignedData, Box<dyn Error>> {
    let bytes = fs::read(signature_block_file)?;
    // The high-level SignedData discards eContentType. Require JAR's id-data
    // before conversion, including the no-signedAttrs case (RFC 5652 5.3).
    let raw = cryptographic_message_syntax::asn1::rfc5652::SignedData::decode_ber(&bytes)?;
    if raw.content_info.content_type != cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA {
        return Err(Box::new(SimpleError::new(
            "Invalid F-Droid CMS content type.",
        )));
    }
    match SignedData::try_from(&raw) {
        Ok(signed_data) => {
            let certificates: Vec<&CapturedX509Certificate> = signed_data.certificates().collect();
            if certificates.len() > 1 {
                return Err(Box::new(SimpleError::new(
                    "Too many certificates provided.",
                )));
            }
            if certificates.is_empty() {
                return Err(Box::new(SimpleError::new("No certificate provided.")));
            }
            let signatories: Vec<&SignerInfo> = signed_data.signers().collect();
            if signatories.len() > 1 {
                return Err(Box::new(SimpleError::new("Too many signatories provided.")));
            }
            if signatories.is_empty() {
                return Err(Box::new(SimpleError::new("No signatories provided.")));
            }
            Ok(signed_data)
        }
        Err(err) => Err(Box::new(err)),
    }
}

#[cfg(test)]
async fn download_repository_archive(
    dir: &TempDir,
    repo: &str,
    use_entry: bool,
    cache: Option<&Path>,
    client: Option<&reqwest::Client>,
) -> Result<Option<String>, Box<dyn Error>> {
    let parent = cache
        .map(|cache| -> Result<_, Box<dyn Error>> {
            Ok(OutputDirectory::open(
                cache.parent().ok_or(FDroidError::Dummy)?,
            )?)
        })
        .transpose()?;
    let cache = cache
        .zip(parent.as_ref())
        .map(|(cache, parent)| parent.path().join(cache.file_name().unwrap()));
    download_repository_archive_pinned(dir, repo, use_entry, cache.as_deref(), client).await
}

async fn download_repository_archive_pinned(
    dir: &TempDir,
    repo: &str,
    use_entry: bool,
    cache: Option<&Path>,
    client: Option<&reqwest::Client>,
) -> Result<Option<String>, Box<dyn Error>> {
    let url = format!(
        "{}/{}",
        repo.trim_end_matches('/'),
        if use_entry {
            "entry.jar"
        } else {
            "index-v1.jar"
        }
    );
    let client = http_client_for_url(&url, client)?;
    let mut request = client.get(&url);
    if let Some(cache) = cache {
        let jar = cache.with_extension("jar");
        let etag = cache.with_extension("etag");
        let jar_exists = regular_cache_exists(&jar)?;
        let etag_exists = regular_cache_exists(&etag)?;
        if jar_exists && etag_exists {
            let tag = read_bounded_string(&etag, 8192)?;
            request = request.header(reqwest::header::IF_NONE_MATCH, tag);
        }
    }
    let response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        let cache = cache
            .ok_or_else(|| SimpleError::new("Unexpected F-Droid 304 without signed cache."))?;
        let cached = cache.with_extension("jar");
        let mut input = open_regular_nofollow(&cached)?;
        if input.metadata()?.len() > MAX_METADATA_BYTES {
            return Err(Box::new(SimpleError::new("Invalid F-Droid signed cache.")));
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join("jar.zip"))?;
        if io::copy(&mut (&mut input).take(MAX_METADATA_BYTES + 1), &mut output)?
            > MAX_METADATA_BYTES
        {
            return Err(Box::new(SimpleError::new("Invalid F-Droid signed cache.")));
        }
        output.flush()?;
        return Ok(None);
    }
    let response = response.error_for_status()?;
    // error_for_status alone accepts stopped redirects (3xx). Only the cache
    // branch above may accept 304; reject every other non-success before output.
    if !response.status().is_success() {
        return Err(Box::new(SimpleError::new(
            "F-Droid repository archive returned a non-success HTTP status.",
        )));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .map(|tag| tag.to_str().map(str::to_owned))
        .transpose()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_METADATA_BYTES)
    {
        return Err(Box::new(SimpleError::new(
            "F-Droid repository archive exceeds size limit.",
        )));
    }
    let jar = dir.path().join("jar.zip");
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&jar)
        .await?;
    let mut stream = response.bytes_stream();
    let mut received = 0u64;
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        received += chunk.len() as u64;
        if received > MAX_METADATA_BYTES {
            return Err(Box::new(SimpleError::new(
                "F-Droid repository archive exceeds size limit.",
            )));
        }
        output.write_all(&chunk).await?;
    }
    output.flush().await?;
    drop(output);
    Ok(etag)
}

fn regular_cache_exists(path: &Path) -> Result<bool, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Box::new(SimpleError::new(
            "Unsafe nonregular F-Droid cache file.",
        ))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(Box::new(err)),
    }
}

#[cfg(test)]
fn write_cache_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or(FDroidError::Dummy)?;
    let parent = OutputDirectory::open(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(FDroidError::Dummy)?;
    write_cache_file_pinned(&parent, name, bytes)
}

fn write_cache_file_pinned(
    parent: &OutputDirectory,
    name: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    if !safe_component(name) {
        return Err(Box::new(FDroidError::Dummy));
    }
    let path = parent.path().join(name);
    regular_cache_exists(&path)?;
    let mut file = tempfile::NamedTempFile::new_in(parent.path())?;
    file.write_all(bytes)?;
    file.flush()?;
    file.persist(&path)?;
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let input = options.open(path)?;
    if !input.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    Ok(input)
}

fn extract_archive(dir: &TempDir, jar: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut archive = zip::ZipArchive::new(File::open(jar)?)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(Box::new(SimpleError::new(
            "Too many F-Droid archive entries.",
        )));
    }
    let mut files = Vec::new();
    let mut extracted = 0u64;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name()?.trim_end_matches('/').to_string();
        if !safe_repo_name(&name)
            || file.enclosed_name().is_none()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(Box::new(SimpleError::new("Unsafe F-Droid archive entry.")));
        }
        let path = dir.path().join(&name);
        if file.is_dir() {
            fs::create_dir_all(&path)?;
            continue;
        }
        if file.size() > MAX_METADATA_BYTES - extracted {
            return Err(Box::new(SimpleError::new(
                "F-Droid extracted metadata exceeds size limit.",
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            validate_output_directory(parent)?;
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let length = io::copy(
            &mut (&mut file).take(MAX_METADATA_BYTES - extracted + 1),
            &mut output,
        )?;
        extracted += length;
        if extracted > MAX_METADATA_BYTES {
            return Err(Box::new(SimpleError::new(
                "F-Droid extracted metadata exceeds size limit.",
            )));
        }
        output.flush()?;
        files.push(name);
    }
    Ok(files)
}
