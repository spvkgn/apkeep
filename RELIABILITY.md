# Download and CLI reliability contracts

## Status and output

- APKPure, F-Droid and Google Play download/list/token callers report failure
  through the real CLI exit status, not only printed diagnostics. An unsupported
  Google Play or RuStore version listing returns nonzero; it is not a successful
  empty list. Huawei's compatibility listing is only an offline informational
  explanation (status 0 for valid IDs), not a remote availability check.
- Status `1` is an aggregate failure, **not** a stable machine-readable "not found"
  code. It also covers unsupported operations, invalid input, network, integrity
  and local I/O errors. Status `2` denotes argument-parser errors. Do not infer
  store absence from a nonzero exit or missing output. Opt-in
  `--report-json <path>` provides schema-1 ordered typed per-input outcomes;
  see [RESULTS.md](RESULTS.md) for statuses, bounds, preflight and publication.
- All input, CSV and OUTPATH diagnostics use stderr, without raw paths/argv or
  Debug-formatted errors. JSON listing stdout is either empty on preflight failure
  or the source's JSON document, never usage/error text.
- Operational stdout writes and flushes fail with controlled exit 1, including
  `/dev/full` and broken pipes, without preventing final report publication.
  No global panic hook converts failure to success. Existing complete APKs stay
  on disk, but the report revokes delivered success/availability as `local_io`;
  pre-existing typed provider/input errors remain intact. Normal stdout is unchanged.
- Mixed batches retain completed outputs and process remaining valid inputs, but
  any failed/invalid item makes the overall command fail. Consumers must check
  exit status **and** validate the selected completed artifact; neither alone
  certifies application authenticity or installability.
- Errors must not dump credentials, signed URLs, server response bodies or
  unvalidated input into diagnostics. Requesting a new AAS token is deliberately
  an output-producing operation: protect its stdout as a secret.

Download parallelism is 1–16 inclusive (default 4). CLI and direct provider
entry points reject out-of-range values as `invalid_input` before authentication
or network work. This bounds in-flight transfers, not aggregate batch disk usage.

## Files and deadlines

The shared downloader uses a private same-filesystem temporary file, complete
writes and flush, then no-clobber publication. Its F-Droid checksum API verifies
SHA256 **before** the final filename becomes visible. Truncation, empty bodies,
errors and cancellation do not leave the partial under the final name. Existing
regular outputs are not overwritten; existing symlinks/directories are errors.
RuStore, Huawei and APKPure reject pre-existing regular outputs as unverified,
rather than reporting the old successful skip. F-Droid may accept an existing
APK only after checking its indexed SHA256. No-clobber alone is not validation.

Google Play uses a separate private directory for each attempt, retaining gpapi's
plain/split/extra-file layout. Failed or timed-out attempts are discarded rather
than exposing partial files. This is caller-policy coverage, **not** a live
certification of Google authentication or gpapi payloads.

Network policies bound metadata requests and download work. A slow connection
can now return a timeout instead of waiting indefinitely. Intentional batch sleep,
several finite retries and many apps can still make a whole batch take longer
than one request deadline. SIGKILL, machine failure, disk failure and filesystem
semantics are outside normal async-cancellation guarantees. No fsync/crash-durable
transaction or multi-artifact atomicity is claimed.

### Linux filesystem boundary

Every source pins OUTPATH with `OutputDirectory` before network/metadata work,
without first canonicalizing user input. Shared transfers retain an independent
directory descriptor, while direct Huawei/RuStore transfers and Google staging,
nested artifact directories, publication and cleanup use live descriptor paths.
Google uses gpapi's auth/download metadata API, with artifact transfers through
the pinned shared downloader rather than gpapi's pathname-only download method.
F-Droid pins config/cache parents before creating children and keeps them open
through cache reads and atomic writes. Existing APK hash and cache reads acquire
regular files with no-follow/nonblocking open flags; cache hits remain reverified.

Linux procfs is required; unsupported platforms fail closed rather than falling
back to pathname publication. Symlink components and parent traversal are refused.
Ancestors must be root/euid-owned and non-group/other-writable, except sticky
ancestors such as `/tmp`; final directories must be euid-owned and not group/other
writable. Relative paths are supported. Missing config/cache components are
created with mode 0700 via pinned parents.

Descriptors prevent ancestor rename/symlink replacement from redirecting later
operations. This does **not** isolate root, same-UID code, malicious directory
owners, permission/ACL changes, authorized entry deletion or post-publication
unlink. Final-directory write permission is a trust boundary, not a sandbox or
a durable multi-file transaction. Private F-Droid metadata workspaces also rely
on a trusted process temporary directory; untrusted TMPDIR is not supported.

## Public HTTP boundary

Production metadata and artifact clients for RuStore, Huawei, APKPure and F-Droid
use the shared public-network builder and validate initial URLs. F-Droid and Huawei allow HTTP(S) for hash-verified artifacts; RuStore, APKPure
and Google Play artifacts require HTTPS for initial URLs and every redirect.
The shared downloader defaults to public HTTPS; trusted Rust callers supplying
clients own that policy explicitly. No URL credentials are allowed; literal private/link-local/loopback/reserved
addresses and nonpublic DNS answers are refused. Checked DNS answers are passed
directly to the connector, and every redirect is checked again. Environment
proxies are disabled. This is an intentional compatibility restriction: there is
no CLI or environment switch for private endpoints. Loopback tests explicitly
inject trusted clients through private seams; ordinary builds/tests retain the
production policy unless that seam is deliberately used.

Google Play remains a boundary: gpapi's internal authentication/metadata HTTP
clients are not under this builder's control. Do not describe this as uniform
SSRF protection for all Google Play paths. Likewise, URL policy and byte limits
do not verify APK manifests, ZIP CRC, publisher identity, or installability.
RuStore and APKPure offer no API-checksum authenticity guarantee here. RuStore
now checks the bounded ZIP/CRC and binary manifest requested package/standalone
base before publication, without expected API version/digest or signer trust.
APKPure APK/XAPK and Google split/additional-file layouts do not receive this
standalone-base validator; HTTPS is not publisher authentication. Huawei
checks API size/SHA256 and additionally performs bounded ZIP/CRC and binary
manifest package/versionCode/base validation before publication. These structural
checks do not establish a trusted signing identity or certify installability.

### Repository URL trust and APK validation limits

CLI `repo=` is an explicit user-selected public endpoint, including nonstandard
ports; the public-network policy is not a public-port probing sandbox. Services
must fix/allowlist repository origins and options, rather than exposing arbitrary
CLI `repo=` to untrusted callers. The APK Downloader web integration must enforce
its own fixed repository policy. No remote probing claim is made here.

The shared standalone APK validator deliberately limits validation to 60 seconds,
2 GiB expanded data, 1000:1 member expansion, 4 MiB manifest, 32768 entries and
16 MiB central directory; uncommon but legal APKs may be refused. Directory names
are borrowed from the stable capped buffer (total raw names cannot exceed that
16 MiB directory); there is no claimed measured RSS bound. Version comparison is
Android longVersionCode (`versionCodeMajor << 32 | versionCode`), not low32-only.
Huawei API low32-only semantics are not assumed; incompatible major-version
metadata may be rejected. RuStore does not have an expected API version to compare.

For legacy Android zipalign compatibility, only local-header extras may end in
1–3 all-zero bytes at a complete TLV boundary. This is the sub-header remainder
for ordinary 4-byte alignment, not a general malformed-extra fallback. Complete
TLV headers, declared payload lengths, ZIP64/AES refusals and strict central
extras are unchanged. Nonzero short tails and payload overruns remain errors;
short-extra errors are identified as ZIP directory errors, not manifest errors.

## CSV and credentials

CSV is parsed as CSV, not split on commas. Quoted commas, escaped quotes and
multiline quoted fields are supported; malformed quoting is rejected. Selected
app/version columns must be present on every nonblank row. An explicitly empty
version cell or the empty suffix in `-a package@` means `latest`; a missing CSV
version cell is an error. A blank app, empty batch,
control characters in a selected value and inputs over 8 MiB are rejected.

An explicitly selected Google Play INI is mandatory and must parse even when
CLI credentials are complete. An absent default INI is optional; an existing
unreadable/invalid default is an error. Configuration errors never print file
contents. Missing credentials are not read from a pipe as an empty token. The
interactive token prompt disables echo and restores terminal settings on a
normal return, EOF or ordinary Ctrl-C. The local `third-party/rpassword`
Unix patch restores termios before raising SIGINT; retain its original Apache-2.0
license and patch provenance. This is not a SIGKILL/crash guarantee. Prefer a protected INI or the no-echo prompt;
credential arguments can still be exposed through shell history/process listings.
OAuth token retrieval requires email and cannot be combined with version listing.

## Releases and boundaries

See [HACKING.md](HACKING.md) for the exact-source native-Linux remote-build
contract. The script is no longer a provisioning/cross-compilation/publishing
shortcut: it uses one exact local committed source archive, strict pinned SSH
host keys and verified private artifact collection. Real remote builds and
other targets require independent validation.

The Git checkout must include `third-party/tokio-dl-stream-to-disk` (MIT) and
`third-party/rpassword` (Apache-2.0), their original licenses and patch provenance. A normal crates.io consumer does **not** inherit this root
`[patch.crates-io]`; registry packaging/publication is not supported by this change.

The web APK Downloader has a separate staged candidate and separate tests. No
Rust build or local commit replaces its active service or binaries. Store API
compatibility, live Google authentication, Docker, other OS targets and source
trust/authenticity remain distinct integration/security gates.
