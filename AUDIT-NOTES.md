# Audit notes and remaining boundaries

This checkout includes a second reliability pass after the original RuStore
status/zero-parallel fixes. These are source changes, **not** a production rollout
or a blanket security certification. Detailed contracts are in [RELIABILITY.md](RELIABILITY.md).

## Addressed in this branch

- APKPure, F-Droid and Google Play callers return aggregate outcomes to main.
  Any failed/invalid item produces a nonzero CLI exit; a mixed batch retains
  successful outputs. Unsupported Google Play listing is explicitly unsuccessful.
- The shared downloader stages privately, completes/flushes writes and publishes
  without overwriting destination entries. Checksum-verified F-Droid downloads
  are checked before publication. Error/cancellation/race regressions exercise
  the actual vendored dependency as well as source callers.
- Source/network deadlines bound work that previously had no explicit policy;
  metadata paths have bounded reads. Timeouts are failures, not store absence.
- Path components and metadata-derived names are checked. APKPure version
  matching no longer borrows the URL of a following version record.
- Linux source output operations now retain directory descriptors across
  transfers, publication and cleanup; Google nested artifacts and F-Droid signed
  cache reads/writes use pinned parents. Original OUTPATH is not canonicalized
  before no-follow traversal. Unsupported platforms/procfs fail closed. This
  prevents ancestor redirection, not malicious-owner/root/same-UID interference,
  post-publication unlink or an untrusted process temporary directory.
- F-Droid repository/index/cache failures are propagated instead of panicking or
  reporting a successful empty operation. Signed archives are reverified on cache
  use rather than trusting an unsigned JSON cache across verification settings.
- Google Play attempts use private per-attempt staging. Caller-policy tests cover
  auth, Terms of Service, retries, deadlines and aggregate outcomes via the same
  backend adapter as real calls, without credentials or accepting real ToS.
- CSV uses a proper CSV reader plus explicit malformed-quote/selected-column
  validation. Missing version columns cannot silently become `latest`.
- An explicit Google Play INI must load even with complete CLI credentials.
  Missing default INI remains optional. Token input is no-echo, non-TTY missing
  credentials fail early, and invalid OAuth/list combinations fail explicitly.
- The remote release script is now an exact-commit source/archive collector with
  pinned SSH host keys and no provisioning or publishing. Local mocks execute
  its remote payload and check the source/artifact identity contract.
- `rustls` remains locked at 0.23.46. The yanked `zip` 8.6.0 lock is replaced with
  9.0.3. Dependency audit reports, advisory database provenance and test logs are
  retained outside the source checkout.

## Source-review contract remediation

Input/OUTPATH and CSV failures now use redacted stderr, including JSON mode.
RuStore bounds package IDs to 240 bytes before network work; unsupported listing
returns status 1 and never echoes invalid input. Empty `-a package@` means latest,
matching an empty selected CSV version. Publication races fail without trusting
another writer's file or repeating a transfer. RuStore/Huawei/APKPure no longer
report existing unverified outputs as successful skips.

Shared public-network policy covers production RuStore/Huawei/APKPure metadata
and artifacts as well as F-Droid, with explicit injected clients for loopback
fixtures. gpapi's own internal HTTP remains outside that policy. These changes
include bounded Huawei ZIP/CRC/native-manifest validation and opt-in schema-1
per-input JSON reports (see RESULTS.md). They do not certify publisher identity,
change the legacy 0/1/2 exit taxonomy, or isolate a hostile local directory owner.
See RELIABILITY.md and source-specific usage for compatibility changes/limits.

## Not certified or not activated

| Area | Remaining boundary |
|---|---|
| Google Play | No real Google login, token exchange, paid entitlement, download or live ToS acceptance. Adapter tests cannot prove gpapi still matches the live service. |
| Public stores | Loopback fixtures cannot certify API availability, anti-bot behavior or that every real response variant is supported. Live checks are separately reported with exact binary hashes. |
| F-Droid trust | Offline signed fixtures test the implementation, not the legitimacy of a chosen custom repository key. `verify-index=false` remains an explicit opt-out and must never be confused with verification. |
| APKPure | Downloads still require `acknowledge_dangers=true`; metadata matching is not publisher-signature or APK-authenticity validation. |
| Existing outputs | RuStore/Huawei/APKPure preserve but reject existing outputs as unverified. F-Droid rechecks indexed SHA256. No overwrite alone is not validation or publisher authenticity. |
| Crash/resource limits | Normal async drop/cancellation is covered. SIGKILL, machine failure, filesystem durability, arbitrary disk exhaustion and atomic rollback of multiple artifacts are not globally guaranteed. |
| Credentials | CLI token arguments remain visible to shell history/process inspection. Successful token-retrieval stdout is intentionally secret-bearing. The no-echo prompt/permission-restricted INI are preferable. |
| Dependencies | `bincode` 2.0.1 is unmaintained (RUSTSEC-2025-0141), inherited through gpapi. This warning alone is not a demonstrated exploitable vulnerability. |
| Registry package | Root `[patch.crates-io]` is effective for the complete Git checkout, not consumers of a published `.crate`. Registry publication needs a separately published dependency strategy. |
| Platforms/releases | Only the local Linux checkout and mocked native-Linux release workflow are exercised. No actual remote builder, cross-compilation, other OS targets, Docker or signed build attestation is certified. |
| Web/service | The separate web false-found candidate has its own tests. Neither that candidate nor these Rust changes replace active production files or binaries automatically. |
| Static analysis | Clippy is run and warnings are retained/reviewed; a successful exit is not a claim of zero warnings. |

Author attribution, original licenses and MIT notices remain preserved, including
EFF/gpapi attribution, the MIT downloader patch and Apache-2.0 rpassword patch.
