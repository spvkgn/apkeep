# Testing apkeep

## Scope

Tests are local and deterministic unless explicitly marked as manual live checks.
`cargo test` never signs into Google Play, accepts Terms of Service, buys apps, or
contacts the public stores. Loopback HTTP tests exercise real HTTP clients against
bounded local servers. CLI tests spawn the real compiled executable with isolated
output/config directories and child-only environment changes.

```sh
cargo test --locked --all-targets
cargo test --offline --manifest-path third-party/tokio-dl-stream-to-disk/Cargo.toml --features sha256sum
cargo build --locked
APKEEP_TEST_BINARY=target/debug/apkeep python3 -B -m unittest discover -s tests
cargo clippy --locked --all-targets
cargo doc --locked --no-deps
bash -n build-remote.sh
```

Add `--offline` only if dependency sources are already cached. Run in a dedicated
worktree and use a distinct `CARGO_TARGET_DIR` for baseline, mutation and candidate
builds: sharing a target directory between different snapshots can silently reuse
the wrong executable. The lockfile is part of the input, not regenerated for tests.

The GitHub Tests workflow runs tests, clippy, documentation and release-script
syntax checks, then verifies that the generated `USAGE` file remains unchanged.
Clippy warnings inherited from upstream are reported, not claimed absent. New
warnings must be reviewed against a clean baseline. Do not execute
`build-remote.sh` against a real host as a test. Its replacement is an exact-source
native build collector, not a provisioning or publishing script. The Python
release tests mock every transport/toolchain action; no SSH is performed.

## Test strategy

- Check failure **status** as well as diagnostic text, files and batch semantics.
- Bound subprocesses and HTTP fixtures; a stalled test must fail, not hang CI.
- Verify output file contents and no-clobber behavior; mere file existence is not
  proof that a download finished or that an APK is valid.
- Keep fixture endpoints private to tests; do not add production endpoint
  overrides to make testing convenient.
- Never put real tokens, passwords, signed download URLs or user configurations
  in fixtures, snapshots or logs.
- Bug fixes need a regression which fails on the original behavior and passes
  after the fix. Characterization tests of existing behavior are identified as
  such, not called RED/GREEN evidence.

## Reliability follow-up

See [RELIABILITY.md](RELIABILITY.md) for batch status, atomic publication, deadlines,
CSV and credential contracts. Google Play caller policy is exercised through the
same bounded backend adapter as the real gpapi caller, with no Google login. The
POSIX terminal test uses a real PTY and a deliberately invalid synthetic token;
it asserts no-echo, terminal restoration and refusal before authentication.

## Source-review contract regressions

Direct RuStore and Huawei socket fixtures distinguish truncated Content-Length and
malformed chunk framing (`integrity`), metadata parsing/schema errors, HTTP 401/403,
request/connect failures and deadlines; failure leaves no APK or private partial.
A synthetic pending future exercises the real Google `bounded`/`play_outcome`
caller deadline without authentication. Message-bearing outer I/O kinds and typed
nested reqwest errors have separate regressions.

`tests/stdout_cli.rs` sends real offline Huawei and F-Droid JSON-list children to
`/dev/full` and a closed pipe: exit 1, no panic, complete coherent report (also
nonzero without a report). A test-only loopback transport runs the actual common
CLI driver through a successful RuStore publication with both failing sinks:
the APK is retained, but report success is false with `error/local_io`. All five
providers' operational print macros use the same scoped fallible helper; an
inventory test guards against bypasses, and write/flush/scope-isolation tests
cover that helper. Clap help and normal JSON/plaintext output remain byte-compatible.

The real child CLI checks stderr-only input/OUTPATH/CSV failures in JSON mode,
redacted gpapi constructor errors (download and OAuth paths), RuStore bounded
package/listing behavior, and rejection of existing unverified files. Store unit
fixtures check one-attempt publication-race failure, production-client refusal of
loopback DNS and private artifact URLs, and successful transfers only through
explicit injected fixture clients. No environment switch disables the production
network policy. Test success does not establish manifest/publisher validity,
live availability or Google Play internal-network coverage.

## Shared downloader dependency

The root Cargo patch uses the MIT-preserving local copy documented in
`third-party/tokio-dl-stream-to-disk/PATCHES.md`. Its direct integration tests
assert immediate byte visibility (not eventual reads), SHA256 stream initialization,
existing-file preservation and truncated-body failures. Keep this patch during
source copies/builds; the root lockfile alone is not sufficient.

## Rereview follow-up regressions

Run vendored transfer tests explicitly with their checksum feature:
`cargo test --offline --manifest-path third-party/tokio-dl-stream-to-disk/Cargo.toml --features sha256sum`.
The standalone vendor manifest has no tracked lockfile; `--locked` is not a valid
first invocation there. Keep the root Cargo.lock unchanged. Rust APK fixtures
require `aapt`, `/usr/share/java/com.android.android-23.jar`, `keytool` and
`apksigner`; no real downloaded APK is embedded. Fixture ZIP timestamps are fixed
for exact-byte assertions across child processes.

Regressions exercise actual shared transfers for checksum/truncation/empty-body
integrity versus malformed-request transport and timeout, public HTTPS initial
refusal, and the exact production redirect policy with no target I/O. The redirect
fixture uses a trusted plaintext source seam; this is a policy test, not a TLS
handshake/downgrade integration certificate. RuStore tests require a real compiled
standalone APK for every successful fixture, reject arbitrary/wrong-package/split/
truncated ZIPs, and retain cancellation/race/pinned-directory contracts. A binary
manifest fixture checks longVersionCode major bits without assuming API low32
semantics. Direct-source and real-child CLI tests check the finite 1–16 bound,
source-specific invalid reporting and output-owner/write-policy diagnostics.

Local-extra alignment regressions mutate a multi-member, offline aapt-derived
APK and update all shifted local offsets plus the EOCD directory offset. They
check 1–3 zero bytes alone/after a complete TLV, preserved manifest/CRC, nonzero
short tails, malformed TLV lengths, ZIP64/AES records (including after a zero
TLV), and strict central-extra rejection. Real downloaded APKs are not fixtures.

## Coverage

With `cargo-llvm-cov` and the matching `llvm-tools-preview` component installed:

```sh
cargo llvm-cov --locked --all-targets --json --output-path coverage.json
```

Put coverage artifacts outside the tracked source tree (or in an ignored output
path). Source-based coverage can include `#[cfg(test)]` modules and child-process
execution; report production-source and test-file numbers separately. A high
line percentage is not evidence for remote API compatibility or cryptographic
trust. No claimed percentage should be inferred from the number of test cases.

## Manual validation boundaries

Authenticated Google login/download, live signed F-Droid indexes, APKPure service
availability/anti-bot behavior, release cross-compilation, Docker publishing and
remote build hosts require separate environments/credentials. Offline fixtures do
not certify those integrations. A live APK check should include fresh destination,
ZIP CRC, manifest/package/version, signature verification and API size/hash where
available, and identify the exact executable/source being exercised.

The web APK Downloader is a separate layer: its scan/job handling and deployment
must be tested separately. Passing Rust tests does not deploy or fix that service.
