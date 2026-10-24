# `apkeep` - A command-line tool for downloading APK files from various sources

To build `apkeep` from source, simply [install rust](https://www.rust-lang.org/tools/install) and in the repository path run

```shell
cargo build
```

If you wish to build the release version, run

```shell
cargo build --release
```

This will compile the binaries and put them in a new `target/` path.

To build and run all in one step, run

```shell
cargo run -- ARGS
```

or

```shell
cargo run --release -- ARGS
```

## Exact-source remote release build

`build-remote.sh` builds **one explicitly selected native Linux Rust target** on
an already provisioned, trusted `apkeep-compiler` host. It is not a provisioning,
cross-compilation, installation or publishing tool. The old nine-artifact
Android/Windows/Linux cross-build workflow has been removed, not reproduced.
Unsupported targets fail; an otherwise accepted Linux target must exactly match
the builder's `rustc -vV` host before Cargo can run.

### Prerequisites (provision separately)

- Local: Bash, Python 3.9+, Git and OpenSSH `ssh`/`scp` clients; a reviewed local
  repository with **no staged or unstaged tracked changes**. Clear
  `assume-unchanged`/`skip-worktree` flags first; sparse/index-hidden files are
  conservatively refused. Untracked files are allowed but never delivered.
- Builder: a non-root build account where practical, Bash, Python 3, `tar`,
  `sha256sum`, native Rust/Cargo on the noninteractive PATH, the native linker and
  development libraries required by this checkout (including OpenSSL/pkg-config
  where applicable), sufficient disk space, and dependencies cached or network
  access for Cargo's locked dependency download. Provision/check the toolchain
  manually; the script never runs `sudo`, apt, dist-upgrade, rustup installers,
  downloaded bootstrap scripts or a Git clone.
- The literal hostname `apkeep-compiler` must resolve through DNS or `/etc/hosts`.
  Authentication must already work noninteractively using the local account's
  default SSH keys/agent and default remote username. There is intentionally no
  arbitrary host/command override. `-F /dev/null` disables SSH configuration and
  aliases; configure name resolution/account access separately.
- Supply a dedicated, existing, nonempty `known_hosts` file containing the
  builder's **independently verified pinned host key**. Obtain/verify its
  fingerprint through a trusted administrator/channel, not blind first-use
  acceptance. Keep this file and its directory protected from untrusted writes.
  Its resolved absolute path may contain only letters/digits, `/`, `.`, `_`, `-`
  (no spaces, OpenSSH `%` tokens or environment expansion expressions).
  Every SSH/SCP call uses `StrictHostKeyChecking=yes`, `BatchMode=yes`, this
  file alone, no global host file or DNS host-key fallback, and no automatic key
  updates. Unknown/changed keys fail rather than prompting or disabling checks.

From the clean repository root, for a builder provisioned for this native target:

```shell
./build-remote.sh \
  --target x86_64-unknown-linux-gnu \
  --known-hosts /absolute/protected/apkeep_known_hosts \
  --output-dir /absolute/private/new-release-directory \
  --commit "$(git rev-parse HEAD)"
```

`--commit` is optional (defaults to local HEAD); if specified it must be a full
40-hex **local commit object ID**, not a branch, tag or short hash. An older
explicit commit is supported, but the current tracked checkout must still be
clean. No fetch/clone is performed. Local `git replace` refs are ignored. The
entire commit is sent as a Git archive, including `Cargo.lock`, committed
`third-party/` patches and any committed `vendor/` tree. Each archived file's
bytes/type/executable mode is checked against the commit before SSH. Archive
attributes that omit or substitute source cause refusal, as do submodules and
absolute/parent-traversing source symlinks. The script does not silently fall
back to an incomplete or different source tree.

Each run creates a private remote `/tmp/apkeep-release.*` directory and an
isolated `CARGO_TARGET_DIR`, checks the uploaded archive's SHA-256, then runs:

```shell
cargo build --release --locked --target REQUESTED_NATIVE_TARGET
```

The local output directory must **not exist**, even as a symlink. It is created
with mode 0700; source and downloads are staged privately inside it. No old
artifact is overwritten. The script downloads `manifest.json` and the binary,
checks the exact source commit, uploaded archive SHA-256, target, nonempty binary
and binary SHA-256, and only then exposes `apkeep-TARGET` and `manifest.json`.
Failed upload/build/download/validation leaves no output artifact. Remote
cleanup is attempted on failure and required before success; if SSH/cleanup
fails, stderr identifies the per-run directory for manual removal. Network loss,
forced process termination or power loss can still require manual cleanup.

This is source/transport identity checking against a **trusted builder**, not a
signed build attestation, a sandbox or a bit-for-bit reproducibility guarantee:
toolchains/system libraries are separately provisioned and not pinned here.
A compromised builder can lie about its result. No real remote build or
cross-platform compilation is established by the local mock tests.

### Offline regression tests

```shell
python3 -B tests/test_release_script.py -v
```

Tests create disposable local Git commits only in temporary fixture repositories.
They run the actual release script and its supplied build payload locally with
fake SSH/SCP/Rust/Cargo executables: **no real SSH connection, Cargo compilation,
source-repository commit, publishing or provisioning**. Coverage includes archive
commit/vendor/lock identity, strict transport options, native-target refusal,
dirty/index-hidden source, injection attempts, manifest/checksum mismatch,
existing-output preservation, cleanup and build/copy fail-stop. The former
"copy all nine artifacts" assertion is intentionally replaced by verified
single-native-artifact success.
