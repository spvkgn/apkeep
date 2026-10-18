use crate::results::{self, Reason, Status};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use futures_util::StreamExt;
use indicatif::MultiProgress;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Response, Url};
use serde_json::json;
use tokio::time::{sleep, timeout, Duration};
use tokio_dl_stream_to_disk::{error::ErrorKind as TDSTDErrorKind, AsyncDownload};

use crate::util::{progress_bar::progress_wrapper, OutputFormat};

#[cfg(test)]
#[path = "apkpure_tests.rs"]
mod tests;

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

fn failure(message: &str) -> bool {
    eprintln!("APKPure: {message}.");
    false
}

fn metadata_client() -> Result<Client, &'static str> {
    tokio_dl_stream_to_disk::public_http_client_builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(METADATA_TIMEOUT)
        .build()
        .map_err(|_| "could not initialize HTTP client")
}

async fn read_metadata(response: Response) -> Result<String, &'static str> {
    results::note(Status::Error, Reason::Integrity);
    if response.status() != reqwest::StatusCode::OK {
        return Err(results::error(
            "invalid metadata HTTP status",
            if matches!(response.status().as_u16(), 401 | 403) {
                Reason::Authentication
            } else {
                Reason::Transport
            },
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_METADATA_BYTES as u64)
    {
        return Err("metadata exceeds size limit");
    }
    timeout(METADATA_TIMEOUT, async {
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                results::error("could not read metadata body", results::failure_reason(&e))
            })?;
            if chunk.len() > MAX_METADATA_BYTES - bytes.len() {
                return Err("metadata exceeds size limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        // APKPure metadata contains binary fields, not UTF-8 JSON.
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
    .await
    .map_err(|_| results::error("metadata body timed out", Reason::Timeout))?
}

fn download_regex(version: Option<&str>) -> Regex {
    match version {
        Some(version) => {
            // A version is a complete token, and its record ends at a closing
            // parenthesis or another record's colon/opening parenthesis. Never
            // borrow a URL from the following version if this one lacks a URL.
            let pattern = format!(
                r"(?:^|[:\s\x00-\x1f]){}:\([^():]*?{}",
                regex::escape(version),
                crate::consts::APKPURE_DOWNLOAD_URL_REGEX,
            );
            Regex::new(&pattern).expect("escaped version and static download pattern")
        }
        None => {
            Regex::new(crate::consts::APKPURE_DOWNLOAD_URL_REGEX).expect("static download pattern")
        }
    }
}

fn versions_url(app_id: &str) -> Result<Url, &'static str> {
    if !safe_package(app_id) {
        return Err("invalid package component");
    }
    let url = Url::parse(&format!(
        "{}{}",
        crate::consts::APKPURE_VERSIONS_URL_FORMAT,
        app_id
    ))
    .map_err(|_| "could not construct metadata URL")?;
    tokio_dl_stream_to_disk::validate_public_url(&url)
        .map_err(|_| "metadata endpoint is not public HTTP(S)")?;
    Ok(url)
}

fn safe_package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.split('.').all(|part| {
            let mut chars = part.bytes();
            matches!(chars.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
                && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && !value.contains("..")
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-()[]".contains(&c))
}

fn safe_arch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.split(';').all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        })
}

fn safe_output_name(value: &str) -> bool {
    if value.len() > 240 {
        return false;
    }
    let parts = value.split('@').collect::<Vec<_>>();
    parts.len() <= 3
        && safe_package(parts[0])
        && parts
            .iter()
            .skip(1)
            .all(|part| safe_version(part) || safe_arch(part))
}

fn checked_name(
    app_id: &str,
    version: Option<&str>,
    arch: Option<&str>,
) -> Result<String, &'static str> {
    if !safe_package(app_id)
        || version.is_some_and(|v| !safe_version(v))
        || arch.is_some_and(|v| !safe_arch(v))
    {
        return Err("invalid app, version or architecture component");
    }
    let mut name = app_id.to_owned();
    for component in [version, arch].into_iter().flatten() {
        name.push('@');
        name.push_str(component);
    }
    if !safe_output_name(&name) {
        return Err("output name exceeds size limit");
    }
    Ok(name)
}

fn versions_regex() -> Regex {
    Regex::new(r"(?:^|[:\s\x00-\x1f])([A-Za-z0-9][A-Za-z0-9._+()\[\]-]{0,119}):\([[:xdigit:]]{40,}")
        .expect("static version pattern")
}

fn http_headers(options: &HashMap<&str, &str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-cv", HeaderValue::from_static("3172501"));
    headers.insert("x-sv", HeaderValue::from_static("29"));
    let arch = options
        .get("arch")
        .map(|arch| arch.split(';').collect::<Vec<_>>().join(","))
        .unwrap_or_else(|| "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64".to_owned());
    if let Ok(value) = HeaderValue::from_str(&arch) {
        headers.insert("x-abis", value);
    }
    headers.insert("x-gp", HeaderValue::from_static("1"));
    headers
}

// These private dependency seams allow loopback tests without a production URL
// override or an environment-controlled endpoint.
type Endpoint<'a> = &'a dyn Fn(&str) -> Result<Url, &'static str>;

struct DownloadTransport<'a> {
    metadata: &'a Client,
    endpoint: Endpoint<'a>,
    artifact: Option<&'a Client>,
}

async fn request_metadata(
    client: &Client,
    endpoint: Endpoint<'_>,
    app_id: &str,
    headers: HeaderMap,
) -> Result<Response, &'static str> {
    let url = endpoint(app_id)?;
    client.get(url).headers(headers).send().await.map_err(|e| {
        results::error(
            "metadata request failed or timed out",
            results::failure_reason(&e),
        )
    })
}

pub async fn download_apps(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    options: HashMap<&str, &str>,
) -> bool {
    match metadata_client() {
        Ok(client) => {
            download_apps_using(
                apps,
                parallel,
                sleep_duration,
                outpath,
                options,
                DownloadTransport {
                    metadata: &client,
                    endpoint: &versions_url,
                    artifact: None,
                },
            )
            .await
        }
        Err(message) => {
            results::batch_error(&apps, Reason::Transport);
            failure(message)
        }
    }
}

async fn download_apps_using(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    options: HashMap<&str, &str>,
    transport: DownloadTransport<'_>,
) -> bool {
    let DownloadTransport {
        metadata: client,
        endpoint,
        artifact: injected_artifact_client,
    } = transport;
    if !matches!(options.get("acknowledge_dangers"), Some(value) if *value == "1" || value.eq_ignore_ascii_case("true"))
    {
        results::batch_error(&apps, Reason::InvalidInput);
        return failure("the dangers of this source must be explicitly acknowledged: https://github.com/EFForg/apkeep/blob/master/USAGE-apkpure.md");
    }
    if !super::check_parallel(&apps, parallel) {
        return false;
    }
    if apps.is_empty() || parallel == 0 {
        results::batch_error(&apps, Reason::InvalidInput);
        return failure("a nonempty batch and positive parallelism are required");
    }
    let output = match tokio_dl_stream_to_disk::OutputDirectory::open(outpath) {
        Ok(output) => output,
        Err(_) => {
            results::batch_error(&apps, Reason::LocalIo);
            return failure("unsafe output directory");
        }
    };
    let output = &output;
    let arch = options.get("arch").copied();
    if arch.is_some_and(|value| !safe_arch(value)) {
        results::batch_error(&apps, Reason::InvalidInput);
        return failure("invalid app, version or architecture component");
    }
    let headers = http_headers(&options);
    let mp = Rc::new(MultiProgress::new());
    let mut seen = HashSet::new();
    let results = futures_util::stream::iter(
        apps.into_iter()
            .filter(|item| seen.insert(item.clone()))
            .map(|(app_id, version)| {
                let headers = headers.clone();
                let mp = Rc::clone(&mp);
                async move {
                    results::observe(&app_id, version.as_deref(), async {
                        results::note(Status::Error, Reason::Integrity);
                        // Validate every user-controlled component before logging, URL
                        // construction or joining a destination path.
                        let name = match checked_name(&app_id, version.as_deref(), arch) {
                            Ok(name) => name,
                            Err(message) => {
                                results::note(Status::Error, Reason::InvalidInput);
                                return failure(message);
                            }
                        };
                        mp.suspend(|| cli_println!("Downloading {name} from APKPure..."));
                        if sleep_duration > 0 {
                            sleep(Duration::from_millis(sleep_duration)).await;
                        }
                        let response =
                            match request_metadata(client, endpoint, &app_id, headers).await {
                                Ok(response) => response,
                                Err(message) => return failure(message),
                            };
                        let re = download_regex(version.as_deref());
                        download_from_response_pinned(
                            response,
                            &re,
                            name,
                            output,
                            mp,
                            injected_artifact_client,
                        )
                        .await
                    })
                    .await
                }
            }),
    )
    .buffer_unordered(parallel)
    .collect::<Vec<bool>>()
    .await;
    // Collect first: Iterator::all over futures would short-circuit a batch.
    results.into_iter().all(|ok| ok)
}

#[cfg(test)]
async fn download_from_response(
    response: Response,
    re: &Regex,
    app_string: String,
    outpath: &Path,
    mp: Rc<MultiProgress>,
    injected_client: Option<&Client>,
) -> bool {
    let output = match tokio_dl_stream_to_disk::OutputDirectory::open(outpath) {
        Ok(output) => output,
        Err(_) => return failure("unsafe output directory"),
    };
    download_from_response_pinned(response, re, app_string, &output, mp, injected_client).await
}

async fn download_from_response_pinned(
    response: Response,
    re: &Regex,
    app_string: String,
    output: &tokio_dl_stream_to_disk::OutputDirectory,
    mp: Rc<MultiProgress>,
    injected_client: Option<&Client>,
) -> bool {
    let outpath = output.path();
    if !safe_output_name(&app_string) {
        results::note(Status::Error, Reason::InvalidInput);
        return failure("invalid app, version or architecture component");
    }
    let body = match read_metadata(response).await {
        Ok(body) => body,
        Err(message) => return failure(message),
    };
    let Some(caps) = re.captures(&body) else {
        return failure("could not get the requested download URL");
    };
    let (Some(kind), Some(download_url)) = (caps.get(1), caps.get(2)) else {
        return failure("invalid download metadata");
    };
    let extension = if kind.as_str() == "XAPKJ" {
        "xapk"
    } else {
        "apk"
    };
    let fname = format!("{app_string}.{extension}");
    // No trusted digest is available here: never bless pre-existing bytes.
    results::note(Status::Error, Reason::LocalIo);
    let destination = outpath.join(&fname);
    match std::fs::symlink_metadata(&destination) {
        Ok(meta) if meta.file_type().is_file() => {
            return failure(
                "output already exists and is unverified; use a fresh output directory",
            );
        }
        Ok(_) => return failure("destination exists and is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return failure("could not inspect destination"),
    }
    for attempt in 1..=3 {
        let download = match AsyncDownload::new_in(download_url.as_str(), output, &fname) {
            Ok(download) => download,
            Err(_) => return failure("cannot pin output directory"),
        };
        let download = match injected_client {
            Some(client) => download.with_client(client.clone()),
            None => download,
        };
        let mut dl = match timeout(METADATA_TIMEOUT, download.get()).await {
            Ok(Ok(dl)) => dl,
            Ok(Err(e)) => {
                results::note(Status::Error, results::failure_reason(e.as_ref()));
                return failure("invalid artifact response or request timeout");
            }
            Err(_) => {
                results::note(Status::Error, Reason::Timeout);
                return failure("invalid artifact response or request timeout");
            }
        };
        let cb = dl
            .length()
            .map(|length| progress_wrapper(Rc::clone(&mp))(fname.clone(), length));
        match timeout(Duration::from_secs(300), dl.download(&cb)).await {
            Ok(Ok(())) => {
                mp.suspend(|| cli_println!("{app_string} downloaded successfully!"));
                results::complete();
                return true;
            }
            Ok(Err(err)) if matches!(err.kind(), TDSTDErrorKind::FileExists) => {
                results::note(Status::Error, Reason::LocalIo);
                return failure(
                    "destination appeared during publication and is unverified; not retrying",
                );
            }
            Ok(Err(err)) if matches!(err.kind(), TDSTDErrorKind::PermissionDenied) => {
                results::note(Status::Error, Reason::LocalIo);
                return failure("permission denied writing artifact");
            }
            Ok(Err(e)) => {
                results::note(Status::Error, results::download_reason(&e));
                eprintln!("APKPure: artifact download failed (attempt {attempt}/3).");
            }
            Err(_) => {
                results::note(Status::Error, Reason::Timeout);
                eprintln!("APKPure: artifact download failed (attempt {attempt}/3).");
            }
        }
    }
    false
}

pub async fn list_versions(
    apps: Vec<(String, Option<String>)>,
    options: HashMap<&str, &str>,
) -> bool {
    match metadata_client() {
        Ok(client) => list_versions_using(apps, options, &client, &versions_url).await,
        Err(message) => {
            results::batch_error(&apps, Reason::Transport);
            failure(message)
        }
    }
}

async fn list_versions_using(
    apps: Vec<(String, Option<String>)>,
    options: HashMap<&str, &str>,
    client: &Client,
    endpoint: Endpoint<'_>,
) -> bool {
    if apps.is_empty() {
        return failure("a nonempty batch is required");
    }
    let output_format = match options.get("output_format") {
        Some(value) if value.eq_ignore_ascii_case("json") => OutputFormat::Json,
        _ => OutputFormat::Plaintext,
    };
    let arch = options.get("arch").copied();
    if arch.is_some_and(|value| !safe_arch(value)) {
        results::batch_error(&apps, Reason::InvalidInput);
        return failure("invalid app, version or architecture component");
    }
    let headers = http_headers(&options);
    let re = versions_regex();
    let mut json_apps = HashMap::new();
    let mut success = true;
    for (app_id, version) in apps {
        if let Err(message) = checked_name(&app_id, version.as_deref(), arch) {
            results::record(
                &app_id,
                version.as_deref(),
                Status::Error,
                Reason::InvalidInput,
            );
            failure(message);
            success = false;
            continue;
        }
        let mut listing = None;
        results::observe(&app_id, version.as_deref(), async {
            results::note(Status::Error, Reason::Integrity);
            let result = async {
                let response = request_metadata(client, endpoint, &app_id, headers.clone()).await?;
                let body = read_metadata(response).await?;
                let versions = re
                    .captures_iter(&body)
                    .filter_map(|caps| caps.get(1))
                    .map(|version| version.as_str())
                    .filter(|version| safe_version(version))
                    .collect::<HashSet<_>>();
                let mut versions = versions.into_iter().map(str::to_owned).collect::<Vec<_>>();
                versions.sort();
                if versions.is_empty() {
                    Err("no versions found in metadata")
                } else {
                    Ok(versions)
                }
            }
            .await;
            let ok = result.is_ok();
            if ok {
                results::complete();
            }
            listing = Some(result);
            ok
        })
        .await;
        match listing.expect("listing outcome assigned") {
            Ok(versions) => {
                if output_format.is_plaintext() {
                    cli_println!(
                        "Versions available for {app_id} on APKPure:\n| {}",
                        versions.join(", ")
                    );
                } else {
                    json_apps.insert(app_id, json!({"available_versions": versions.into_iter().map(|version| json!({"version": version})).collect::<Vec<_>>()}));
                }
            }
            Err(message) => {
                failure(message);
                success = false;
                if output_format.is_json() {
                    json_apps.insert(app_id, json!({"error": message}));
                }
            }
        }
    }
    if output_format.is_json() {
        cli_println!("{}", json!({"source": "APKPure", "apps": json_apps}));
    }
    success
}
