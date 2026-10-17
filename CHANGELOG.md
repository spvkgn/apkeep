# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Require public HTTPS, including redirect targets, for RuStore/APKPure/Google Play artifact transfers; retain explicit trusted-client fixtures and hash-verified F-Droid/Huawei HTTP compatibility.
- Preserve typed request/timeout failures and report checksum mismatch, truncated and empty artifacts as integrity failures rather than transport failures.
- Correct direct RuStore/Huawei body failure classification and message-bearing outer I/O timeout/permission precedence, including the Google caller deadline.
- Handle operational stdout write/flush failure with controlled nonzero exit and coherent final reports, retaining completed APKs without claiming delivered success.
- Share the bounded APK validator between Huawei and RuStore; validate RuStore ZIP/CRC, binary manifest, requested package and standalone base before publication (no API digest/version or signer trust claimed).
- Bound parallel downloads to 1–16 at CLI and direct provider entry points; keep default 4.
- Explain output ownership/write-mode requirements in help and diagnostics; require dot-separated RuStore package identifiers consistently.
- Make report serialization accept safe nonstandard F-Droid components without preempting source validation; document unordered JSON object keys.
- Borrow ZIP directory entry names from the capped directory buffer rather than copying each name; retain deliberate expansion/ratio/deadline limits.
- Clarify explicit CLI repository URL trust versus service-side repository allowlisting; arbitrary public ports are not sandboxed.
- Fail the CLI on APKPure, F-Droid and Google Play errors; preserve mixed-batch successes.
- Publish shared downloads atomically without clobbering existing outputs, verify F-Droid SHA256 before publication, and discard failed Google Play staging directories.
- Bound source metadata/download operations and expand loopback, cancellation, race and credential-terminal regressions.
- Parse quoted CSV and reject missing selected columns; fail invalid explicit INI and hide interactive token input.
- Replace the remote release provisioner with an exact-commit, pinned-host native-Linux build collector.
- Replace the yanked zip 8.6.0 lock with zip 9.0.3; retain the documented full-Git-checkout packaging requirement.
- Return nonzero when any RuStore download fails; reject zero parallelism before downloads or authentication.
- Expand offline tests across CLI/input/config, RuStore, APKPure, F-Droid and Google Play listing.
- Stop release artifact collection after failed SSH builds or SCP transfers; test with local command mocks.
- Create missing configuration parent directories and update the locked rustls patch to 0.23.46.
- Add a documented MIT-preserving local patch for the shared downloader: complete writes, flush before return, initialize SHA256 retry streams; test the actual dependency and F-Droid entry read path.
- Add read-only test CI and document testing scope and remaining audit limitations.
- Restore Huawei AppGallery with explicit `-o region=CN` selection (compatible `IE` default, no automatic fallback).
- Validate Huawei API results and complete-APK metadata; verify SHA256 and size before atomic, no-clobber publication.
- Report Huawei failures on stderr, including non-TTY runs, and return a nonzero status if any batch item fails.
- Add offline loopback HTTP and CLI regression tests for Huawei AppGallery.
- Add RuStore support with configurable device/client options and validated API responses

## [1.1.0] - 2026-10-01
- Add warnings and explicit flag requirement to download from APKPure
- Make Googe Play the default download source
- Remove Huawei AppGallery (nonworking)
- Update dependencies

## [1.0.0] - 2026-04-29
- Google Play:
  - Add the ability to download dex metadata for an app
  - Fix authentication bug introduced by Google auth flow change
  - Allow users to specify their own device properties files
  - Allow authentication with auth-token as alternative to aas-token
- Update dependencies

## [0.18.0] - 2025-10-30
- Adding the ability to specify json as an output format when listing versions of an app available
- Using latest `gpapi` dependency, with more device configuration options for Google Play
- For F-Droid, default the entry point specification to true, with the option to disable
- Add more download options and documentation for APKPure
- Update dependencies

## [0.17.0] - 2024-10-11
- Added support for F-Droid entry point specification and new index versions
- Update dependencies

## [0.16.0] - 2024-04-04
- Support Google Play API v3 and document workflow for downloading via Google Play

## [0.15.0] - 2023-01-04
- Add progress bars to all download sources
- Update dependencies

## [0.14.1] - 2022-11-23
- Bugfix release: updating `zstd-sys` dependency, which fixes cross-compilation for Windows

## [0.14.0] - 2022-11-21
- Downloading split APKs downloads the base APK as well
- Switch to OpenSSL 3.0.7
- Update dependencies

## [0.13.0] - 2022-05-26
- Add support for downloading split APKs with `google-play`
- Add support for downloading additional files with `google-play`
- Use the appropriate filename extensions (`xapk` or `apk`) for `apkpure`

## [0.12.2] - 2022-05-18
- Android-only release: switch to OpenSSL 3.0.3 for `termux` releases

## [0.12.1] - 2022-05-11
- Android-only release: fix dependencies to ensure `openssl-1.1` is used

## [0.12.0] - 2022-05-05
- Add a default config file which allows users to store Google credentials
- Allow specifying a custom path to the above config file
- Prompt users for a Google username and password if none is found

## [0.11.0] - 2022-04-22
- Adding `huawei-app-gallery` as a download source

## [0.10.0] - 2022-03-17
### Added
- `options` command-line option to specify options specific to a download source
- With `options`, adding ability to download from a specific F-Droid repo or mirror
- With `options`, adding ability to specify a device configuration and additional options for Google Play
- Documenting `options`

## [0.9.0] - 2022-02-22
- Fix bug where another package is fetched for certain ids in APKPure
- Updated usage for download sources
- Dependency updates

## [0.8.0] - 2021-12-07
### Added
- Cacheing of F-Droid package index to local config directory

## [0.7.0] - 2021-11-29
### Added
- Ability to download versioned apps on APKPure and F-Droid, as well as making it possible in a separate field if you're using a CSV
- Ability to look up what versions are available on these sources using the -l flag
