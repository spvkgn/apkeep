//! # Installation
//!
//! Precompiled binaries for `apkeep` on various platforms can be downloaded
//! [here](https://github.com/EFForg/apkeep/releases).
//!
//! To install from `crates.io`, simply [install rust](https://www.rust-lang.org/tools/install) and
//! run
//!
//! ```shell
//! cargo install apkeep
//! ```
//!
//! Or to install from the latest commit in our repository, run
//!
//! ```shell
//! cargo install --git https://github.com/EFForg/apkeep.git
//! ```
//!
//! If using on an Android platform, [`termux`](https://termux.org/) must be installed first.
//! Upgrade to the latest packages with `pkg update`, then install the `apkeep` precompiled binary
//! as described above or run `pkg install apkeep` to install from the `termux` repository.
//!
//! Docker images are also available through the GitHub Container Registry. Aside from using a
//! specific release version, the following floating tags are available:
//!
//! - stable: tracks the latest stable release (recommended)
//! - latest: tracks the latest release, including pre-releases
//! - edge: tracks the latest commit
//!
//! # Usage
//!
//! See [`USAGE`](https://github.com/EFForg/apkeep/blob/master/USAGE).
//!
//! # Examples
//!
//! The simplest example is to download a single APK to the current directory:
//!
//! ```shell
//! apkeep -a com.instagram.android .
//! ```
//!
//! To download directly from the default source, Google Play, you will first have to [obtain an AAS token](USAGE-google-play.md).
//! Then,
//!
//! ```shell
//! apkeep -a com.instagram.android -e 'someone@gmail.com' -t aas_token .
//! ```
//!
//! For more google play usage examples, such as specifying a device configuration, timezone or
//! locale, refer to the [`USAGE-google-play.md`](USAGE-google-play.md) document.
//!
//! To download from the F-Droid open source repository:
//!
//! ```shell
//! apkeep -a org.mozilla.fennec_fdroid -d f-droid .
//! ```
//!
//! For more F-Droid usage examples, such as downloading from F-Droid mirrors or other F-Droid
//! repositories, refer to the [`USAGE-fdroid.md`](USAGE-fdroid.md) document.
//!
//! You can also download from APKPure, but this should be used *only* for research purposes. Please see the [`USAGE-apkpure.md`](USAGE-apkpure.md) document.
//!
//! To download the APK offered by Huawei AppGallery for an explicitly chosen region:
//!
//! ```shell
//! apkeep -a com.icbc -d huawei-app-gallery -o region=CN .
//! ```
//!
//! The compatible default region is `IE`; there is no automatic region fallback. Only the
//! latest APK offered to the configured client profile is available, not historical versions
//! or necessarily the newest public release. See [`USAGE-huawei-app-gallery.md`](USAGE-huawei-app-gallery.md)
//! for regional availability, integrity checks, and error handling.
//!
//! Or, to download from RuStore:
//!
//! ```shell
//! apkeep -a com.vk.calls -d ru-store .
//! ```
//!
//! For RuStore device/client options and its latest-only and split APK limitations,
//! refer to [`USAGE-rustore.md`](USAGE-rustore.md).
//!
//! To download a specific version of an APK (possible for APKPure or F-Droid), use the `@version`
//! convention:
//!
//! ```shell
//! apkeep -a com.instagram.android@1.2.3 .
//! ```
//!
//! Or, to list what versions are available, use `-l`:
//!
//! ```shell
//! apkeep -l -a org.mozilla.fennec_fdroid -d f-droid
//! ```
//!
//! Refer to [`USAGE`](https://github.com/EFForg/apkeep/blob/master/USAGE) to download multiple
//! APKs in a single run.
//!
//! All the above examples can also be used in Docker with minimal changes. For example, to
//! download a single APK to your chosen output directory:
//!
//! ```shell
//! docker run --rm -v output_path:/output ghcr.io/efforg/apkeep:stable -a com.instagram.android
//! /output
//! ```
//!
//! # Specify a CSV file or individual app ID
//!
//! You can either specify a CSV file which lists the apps to download, or an individual app ID.
//! If you specify a CSV file and the app ID is not specified by the first column, you'll have to
//! use the --field option as well.  If you have a simple file with one app ID per line, you can
//! just treat it as a CSV with a single field.
//!
//! # Download Sources
//!
//! You can use this tool to download from a few distinct sources.
//!
//! * The Google Play Store (`-d google-play`), given an email address and AAS token
//! * APKPure (`-d apk-pure`), a third-party site hosting APKs available on the Play Store
//! * Huawei AppGallery (`-d huawei-app-gallery`), with explicit regional selection and
//!   API-size/SHA256-checked downloads; see [`USAGE-huawei-app-gallery.md`](USAGE-huawei-app-gallery.md)
//! * F-Droid (`-d f-droid`), a repository for free and open-source Android apps. `apkeep`
//! authenticates the repository index and checks each APK against its indexed SHA256
//! before publication; an APK that fails verification is not published
//! * RuStore (`-d ru-store`), a Russian app store platform
//!
//! # Usage Note
//!
//! Users should not use app lists or choose so many parallel APK fetches as to place unreasonable
//! or disproportionately large load on the infrastructure of the app distributor.
//!
//! When using with the Google Play Store as the download source, a few considerations should be
//! made:
//!
//! * Google may terminate your Google account based on Terms of Service violations.  Read their
//! [Terms of Service](https://play.google.com/about/play-terms/index.html), avoid violating it,
//! and choose an account where this outcome is acceptable.
//! * Paid and DRM apps will not be available.
//! * Using Tor will make it a lot more likely that the download will fail.

use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use configparser::ini::Ini;

#[macro_use]
mod output;
mod cli;
use cli::DownloadSource;

mod config;
mod consts;
#[cfg(test)]
mod input_tests;
mod results;
mod util;

mod download_sources;
use download_sources::apkpure;
use download_sources::fdroid;
use download_sources::google_play;
use download_sources::rustore;

type CSVList = Vec<(String, Option<String>)>;
fn single_app(app: &str) -> (String, Option<String>) {
    let mut parts = app.splitn(2, '@');
    (
        parts.next().unwrap().to_owned(),
        parts
            .next()
            .filter(|version| !version.is_empty())
            .map(str::to_owned),
    )
}

fn fetch_csv_list(
    csv: &str,
    field: usize,
    version_field: Option<usize>,
) -> Result<CSVList, Box<dyn Error>> {
    let mut text = String::new();
    File::open(csv)
        .map_err(|_| "Could not open CSV input file")?
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "Could not read CSV input file as UTF-8")?;
    parse_csv_text(text, field, version_field)
}

fn parse_csv_text(
    text: String,
    field: usize,
    version_field: Option<usize>,
) -> Result<CSVList, Box<dyn Error>> {
    if text.len() > 8 * 1024 * 1024 {
        return Err("CSV exceeds 8 MiB input limit".into());
    }
    if field == 0 || version_field == Some(0) || version_field == Some(field) {
        return Err("CSV columns must be positive and distinct".into());
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    // csv deliberately accepts malformed quoting; reject ambiguous records before
    // parsing so an unterminated ignored field cannot silently swallow batch rows.
    #[derive(Clone, Copy)]
    enum Quote {
        Start,
        Bare,
        Quoted,
        Closed,
    }
    let mut quote = Quote::Start;
    for byte in text.bytes() {
        quote = match (quote, byte) {
            (Quote::Start, b'"') => Quote::Quoted,
            (Quote::Quoted, b'"') => Quote::Closed,
            (Quote::Quoted, _) => Quote::Quoted,
            (Quote::Closed, b'"') => Quote::Quoted,
            (_, b',' | b'\r' | b'\n') => Quote::Start,
            (Quote::Bare, b'"') | (Quote::Closed, _) => return Err("Invalid CSV quoting".into()),
            (_, _) => Quote::Bare,
        };
    }
    if matches!(quote, Quote::Quoted) {
        return Err("Unterminated CSV quoted field".into());
    }
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut apps = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|_| "Invalid CSV record")?;
        let app = record
            .get(field - 1)
            .ok_or("CSV record is missing the requested app ID field")?;
        if app.chars().any(char::is_control) {
            return Err("CSV app ID contains control characters".into());
        }
        let app = Some(app.trim())
            .filter(|v| !v.is_empty())
            .ok_or("CSV record is missing the requested app ID field")?;
        let version = match version_field {
            Some(column) => {
                let value = record
                    .get(column - 1)
                    .ok_or("CSV record is missing the requested version field")?;
                if value.chars().any(char::is_control) {
                    return Err("CSV version contains control characters".into());
                }
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                }
            }
            None => None,
        };
        apps.push((app.to_owned(), version));
    }
    if apps.is_empty() {
        return Err("CSV contains no apps".into());
    }
    Ok(apps)
}

fn load_config(ini_file: Option<PathBuf>) -> Result<Ini, Box<dyn Error>> {
    let explicit = ini_file.is_some();
    let mut conf = Ini::new();
    let config_path = match ini_file {
        Some(ini_file) => ini_file,
        None => config::config_dir()?.join("apkeep.ini"),
    };
    let config_fp = match File::open(&config_path) {
        Ok(file) => file,
        Err(err)
            if !explicit
                && err.kind() == io::ErrorKind::NotFound
                && matches!(fs::symlink_metadata(&config_path), Err(ref e) if e.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(conf)
        }
        Err(_) => return Err("Could not read Google Play configuration".into()),
    };
    let mut contents = String::new();
    config_fp
        .take(256 * 1024 + 1)
        .read_to_string(&mut contents)
        .map_err(|_| "Could not read Google Play configuration")?;
    if contents.len() > 256 * 1024 {
        return Err("Google Play configuration exceeds size limit".into());
    }
    conf.read(contents)
        .map_err(|_| "Invalid Google Play configuration")?;
    Ok(conf)
}

#[tokio::main]
async fn main() {
    let matches = match cli::app().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            use clap::error::ErrorKind;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                error.exit();
            }
            // clap diagnostics can include raw argv (including paths and tokens).
            let message = match error.kind() {
                ErrorKind::ArgumentConflict => "Some arguments cannot be used with each other",
                ErrorKind::InvalidValue => {
                    "Invalid or missing option value (check options such as --oauth-token)"
                }
                ErrorKind::MissingRequiredArgument => "Missing required app selection or OUTPATH",
                _ => "Invalid command-line arguments; see --help",
            };
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    run(matches).await;
}

async fn run(matches: clap::ArgMatches) {
    let mut download_source = *matches
        .get_one::<DownloadSource>("download_source")
        .unwrap();
    let options: HashMap<&str, &str> = match matches.get_one::<String>("options") {
        Some(options) => {
            let mut options_map = HashMap::new();
            for option in options.split(",") {
                match option.split_once("=") {
                    Some((key, value)) => {
                        options_map.insert(key, value);
                    }
                    None => {}
                }
            }
            options_map
        }
        None => HashMap::new(),
    };

    let oauth_token = matches
        .get_one::<String>("google_oauth_token")
        .map(|v| v.to_string());
    if oauth_token.is_some() {
        download_source = DownloadSource::GooglePlay;
        if matches.get_flag("list_versions") {
            eprintln!("OAuth token retrieval cannot be combined with version listing");
            std::process::exit(1);
        }
        if matches.get_one::<String>("google_email").is_none() {
            eprintln!("OAuth token retrieval requires an explicit email");
            std::process::exit(1);
        }
        if matches.get_one::<String>("app").is_some() || matches.get_one::<String>("csv").is_some()
        {
            eprintln!("OAuth token retrieval cannot be combined with app selection");
            std::process::exit(1);
        }
    }
    let input_error = |message: &str| {
        if download_source == DownloadSource::HuaweiAppGallery {
            eprintln!("Huawei AppGallery: {message}");
        } else if download_source == DownloadSource::RuStore {
            eprintln!("RuStore: {message}");
        } else {
            eprintln!("{message}");
        }
    };
    let list: Vec<(String, Option<String>)> = if oauth_token.is_none() {
        match matches.get_one::<String>("app") {
            Some(app) => {
                vec![single_app(app)]
            }
            None => {
                let csv = matches.get_one::<String>("csv").unwrap();
                let field = *matches.get_one::<usize>("field").unwrap();
                let version_field = matches.get_one::<usize>("version_field").map(|v| *v);
                if field < 1 {
                    input_error("App ID field must be 1 or greater");
                    std::process::exit(1);
                }
                if let Some(version_field) = version_field {
                    if version_field < 1 {
                        input_error("Version field must be 1 or greater");
                        std::process::exit(1);
                    }
                    if field == version_field {
                        input_error("App ID and Version fields must be different");
                        std::process::exit(1);
                    }
                }
                match fetch_csv_list(csv, field, version_field) {
                    Ok(csv_list) => csv_list,
                    Err(err) => {
                        input_error(&err.to_string());
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        Vec::new()
    };

    // Parser/CSV failures above cannot establish a trustworthy input list and
    // deliberately produce no report. Pin/check its destination before any work.
    let report_destination = matches.get_one::<String>("report_json").map(|path| {
        let path = Path::new(path);
        let name = path.file_name().and_then(|n| n.to_str()).filter(|n| {
            n.len() <= 240 && n.ends_with(".json")
                && !n.chars().any(|c| c.is_control() || c == '\\')
        });
        let directory = tokio_dl_stream_to_disk::OutputDirectory::open(
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
        );
        match (name, directory) {
            (Some(name), Ok(directory)) if matches!(fs::symlink_metadata(directory.path().join(name)), Err(e) if e.kind() == io::ErrorKind::NotFound) => (directory, name.to_owned()),
            _ => { eprintln!("Invalid, unsafe or existing result report destination (expected .json)"); std::process::exit(1); }
        }
    });
    let report = if report_destination.is_some() {
        match results::Report::new(
            &download_source.to_string(),
            if matches.get_flag("list_versions") {
                "list"
            } else {
                "download"
            },
            list.clone(),
        ) {
            Ok(report) => Some(report),
            Err(message) => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    // Identical requests share one provider operation but retain all report rows.
    let mut seen = std::collections::HashSet::new();
    let list = list
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect();
    // Keep the large provider-dispatch future on the heap before nesting the
    // output/report scopes (also safe on small executor/test thread stacks).
    let operation = Box::pin(async {
        let huawei_region = if download_source == DownloadSource::HuaweiAppGallery {
            match download_sources::huawei_app_gallery::region(
                matches.get_one::<String>("options").map(String::as_str),
            ) {
                Ok(region) => Some(region),
                Err(error) => {
                    results::pending_error(results::Reason::InvalidInput);
                    eprintln!("Huawei AppGallery: {error}");
                    return false;
                }
            }
        } else {
            None
        };

        if let Some(true) = matches.get_one::<bool>("list_versions") {
            match download_source {
                DownloadSource::APKPure => {
                    if !apkpure::list_versions(list, options).await {
                        return false;
                    }
                }
                DownloadSource::GooglePlay => {
                    if !google_play::list_versions(list) {
                        return false;
                    }
                }
                DownloadSource::FDroid => {
                    if !fdroid::list_versions(list, options).await {
                        return false;
                    }
                }
                DownloadSource::HuaweiAppGallery => {
                    if !download_sources::huawei_app_gallery::list_versions(list) {
                        return false;
                    }
                }
                DownloadSource::RuStore => {
                    if !rustore::list_versions(list).await {
                        return false;
                    }
                }
            }
        } else {
            let parallel = matches.get_one::<usize>("parallel").copied().unwrap();
            if !download_sources::valid_parallel(parallel) {
                results::pending_error(results::Reason::InvalidInput);
                eprintln!("parallel must be between 1 and 16");
                return false;
            }
            let sleep_duration = matches.get_one::<u64>("sleep_duration").copied().unwrap();
            let outpath = if let Some(outpath) = matches.get_one::<String>("OUTPATH") {
                match tokio_dl_stream_to_disk::OutputDirectory::open(Path::new(outpath)) {
                    Ok(_) => Some(PathBuf::from(outpath)),
                    Err(_) => {
                        results::pending_error(results::Reason::LocalIo);
                        input_error("OUTPATH must be a real directory owned by the current user and not group/world-writable (unsafe or inaccessible output directory)");
                        return false;
                    }
                }
            } else if oauth_token.is_none() {
                input_error("OUTPATH must be specified when downloading files");
                return false;
            } else {
                None
            };

            match download_source {
                DownloadSource::HuaweiAppGallery => {
                    if !download_sources::huawei_app_gallery::download_apps(
                        list,
                        parallel,
                        sleep_duration,
                        &outpath.unwrap(),
                        huawei_region.as_deref().unwrap(),
                    )
                    .await
                    {
                        return false;
                    }
                }
                DownloadSource::APKPure => {
                    if !apkpure::download_apps(
                        list,
                        parallel,
                        sleep_duration,
                        &outpath.unwrap(),
                        options,
                    )
                    .await
                    {
                        return false;
                    }
                }
                DownloadSource::GooglePlay => {
                    let mut email = matches
                        .get_one::<String>("google_email")
                        .map(|v| v.to_string());

                    if let (Some(email), Some(oauth_token)) = (&email, &oauth_token) {
                        if !google_play::request_aas_token(email, oauth_token, options).await {
                            return false;
                        }
                    } else {
                        let mut aas_token = matches
                            .get_one::<String>("google_aas_token")
                            .map(|v| v.to_string());
                        let mut auth_token = matches
                            .get_one::<String>("google_auth_token")
                            .map(|v| v.to_string());
                        let accept_tos = matches.get_flag("google_accept_tos");

                        let conf = match load_config(
                            matches.get_one::<String>("ini").map(PathBuf::from),
                        ) {
                            Ok(conf) => conf,
                            Err(_) => {
                                results::pending_error(results::Reason::InvalidInput);
                                eprintln!("Could not load Google Play configuration");
                                return false;
                            }
                        };
                        if email.is_none() {
                            email = conf.get("google", "email");
                        }
                        if aas_token.is_none() && auth_token.is_none() {
                            aas_token = conf.get("google", "aas_token");
                            if aas_token.is_none() {
                                auth_token = conf.get("google", "auth_token");
                            }
                        }
                        if (email.is_none() || (aas_token.is_none() && auth_token.is_none()))
                            && !io::stdin().is_terminal()
                        {
                            results::pending_error(results::Reason::Authentication);
                            eprintln!("Missing Google Play credentials: interactive input requires a terminal");
                            return false;
                        }
                        if email.is_none() {
                            let mut prompt_email = String::new();
                            eprint!("Email: ");
                            if io::stderr().flush().is_err()
                                || io::stdin().read_line(&mut prompt_email).is_err()
                            {
                                results::pending_error(results::Reason::Authentication);
                                eprintln!("Could not read Google Play email");
                                return false;
                            }
                            email = Some(prompt_email.trim().to_string());
                        }
                        if aas_token.is_none() && auth_token.is_none() {
                            let token =
                                match rpassword::prompt_password("AAS Token (or AUTH Token): ") {
                                    Ok(token)
                                        if !token.is_empty()
                                            && !token.chars().any(char::is_whitespace) =>
                                    {
                                        token
                                    }
                                    _ => {
                                        results::pending_error(results::Reason::Authentication);
                                        eprintln!(
                                    "Could not securely read Google Play token from terminal"
                                );
                                        return false;
                                    }
                                };
                            if token.starts_with("ya29.") {
                                auth_token = Some(token);
                            } else {
                                aas_token = Some(token);
                            }
                        }
                        if email
                            .as_deref()
                            .is_none_or(|v| v.is_empty() || v.chars().any(char::is_whitespace))
                            || aas_token
                                .as_deref()
                                .is_some_and(|v| v.is_empty() || v.chars().any(char::is_whitespace))
                            || auth_token
                                .as_deref()
                                .is_some_and(|v| v.is_empty() || v.chars().any(char::is_whitespace))
                        {
                            results::pending_error(results::Reason::Authentication);
                            eprintln!("Invalid Google Play credentials");
                            return false;
                        }

                        if !google_play::download_apps(
                            list,
                            parallel,
                            sleep_duration,
                            &email.unwrap(),
                            aas_token.as_deref(),
                            auth_token.as_deref(),
                            &outpath.unwrap(),
                            accept_tos,
                            options,
                        )
                        .await
                        {
                            return false;
                        }
                    }
                }
                DownloadSource::FDroid => {
                    if !fdroid::download_apps(
                        list,
                        parallel,
                        sleep_duration,
                        &outpath.unwrap(),
                        options,
                    )
                    .await
                    {
                        return false;
                    }
                }
                DownloadSource::RuStore => {
                    if !rustore::download_apps(
                        list,
                        parallel,
                        sleep_duration,
                        &outpath.unwrap(),
                        options,
                    )
                    .await
                    {
                        return false;
                    }
                }
            }
        }
        true
    });
    let operation = output::capture(operation);
    let success = if let Some(mut report) = report {
        let ((success, output_ok), collected) = results::collect(report, operation).await;
        report = collected;
        if !output_ok {
            output::diagnostic();
            report.output_failed();
        }
        report.finish(success && output_ok);
        let mut success = success && output_ok && report.succeeded();
        if let Some((directory, name)) = report_destination {
            if report.write_to(&directory, &name).is_err() {
                eprintln!("Could not publish result report");
                success = false;
            }
        }
        success
    } else {
        let (success, output_ok) = operation.await;
        if !output_ok {
            output::diagnostic();
        }
        success && output_ok
    };
    if !success {
        std::process::exit(1);
    }
}
