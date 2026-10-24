#!/bin/bash
# Build one native Linux target from an exact, clean, local Git commit.
set -euo pipefail
exec python3 - "$@" <<'PYTHON'
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

HOST = "apkeep-compiler"
# A commit ID must identify its stored object, not a local refs/replace view.
os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
REMOTE_SCRIPT = r'''set -euo pipefail
umask 077
work=$1
commit=$2
target=$3
source_sha256=$4
cd "$work"
printf '%s  source.tar\n' "$source_sha256" | sha256sum --check --status
mkdir source build
tar -xf source.tar -C source
cd source
python3 - "$target" <<'CHECK_HOST'
import subprocess, sys
host = [line[6:] for line in subprocess.check_output(["rustc", "-vV"], text=True).splitlines() if line.startswith("host: ")]
if host != [sys.argv[1]]:
    sys.exit("Unsupported cross target: requested target must equal provisioned rustc host")
CHECK_HOST
export CARGO_TARGET_DIR="$work/build"
cargo build --release --locked --target "$target"
test -s "$CARGO_TARGET_DIR/$target/release/apkeep"
cp "$CARGO_TARGET_DIR/$target/release/apkeep" "$work/apkeep"
python3 - "$work" "$commit" "$target" "$source_sha256" <<'MANIFEST'
import hashlib, json, pathlib, sys
work = pathlib.Path(sys.argv[1])
manifest = {"source_commit": sys.argv[2], "target": sys.argv[3],
            "source_sha256": sys.argv[4],
            "artifact_sha256": hashlib.sha256((work / "apkeep").read_bytes()).hexdigest()}
(work / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
MANIFEST
'''


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def git(*args):
    return subprocess.check_output(["git", *args])


def verify_archive(archive_path, commit):
    """Fail closed if archive attributes would omit/substitute committed bytes."""
    expected = {}
    for entry in git("ls-tree", "-r", "-z", commit).split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise ValueError("Submodules/special Git entries are unsupported")
        expected[os.fsdecode(name)] = (mode, oid.decode())
    for required in ("Cargo.toml", "Cargo.lock"):
        if required not in expected:
            raise ValueError("Commit must include " + required)
    found = set()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            if member.isdir():
                continue
            if member.name not in expected or member.name in found:
                raise ValueError("Unexpected/duplicate archive entry")
            mode, oid = expected[member.name]
            if mode == b"120000" and member.issym():
                target_path = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname))
                if (posixpath.isabs(member.linkname) or ".." in member.linkname.split("/")
                        or target_path == ".." or target_path.startswith("../")):
                    raise ValueError("Source symlink may escape committed tree")
                data = os.fsencode(member.linkname)
            elif mode != b"120000" and member.isfile():
                data = archive.extractfile(member).read()
                if bool(member.mode & 0o111) != (mode == b"100755"):
                    raise ValueError("Archive executable mode mismatch")
            else:
                raise ValueError("Archive file type mismatch")
            digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if digest != oid:
                raise ValueError("Archive differs from committed bytes (export-subst?)")
            found.add(member.name)
    if found != set(expected):
        raise ValueError("Archive omits committed files (export-ignore?)")


def main():
    parser = argparse.ArgumentParser(description=__doc__ or "Exact-source native Linux remote build (no provisioning/publishing)")
    parser.add_argument("--commit", help="full 40-hex local commit; default HEAD")
    parser.add_argument("--target", required=True, help="explicit native Linux Rust target; cross builds refused")
    parser.add_argument("--known-hosts", required=True, help="existing independently pinned OpenSSH known_hosts file")
    parser.add_argument("--output-dir", required=True, help="new private output directory; must not exist")
    args = parser.parse_args()
    if not re.fullmatch(r"(?:x86_64|i686|aarch64|armv7)-unknown-linux-(?:gnu|gnueabihf|musl|musleabihf)", args.target):
        raise ValueError("Unsupported target: only native Linux builds are supported")
    known_hosts = Path(args.known_hosts).resolve(strict=True)
    # OpenSSH expands tokens/environment variables even in -o path values.
    # Accept one literal absolute path, never a list or expansion expression.
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(known_hosts)):
        raise ValueError("known_hosts path must be literal: only letters/digits, / . _ -")
    if not known_hosts.is_file() or known_hosts.stat().st_size == 0:
        raise ValueError("A nonempty pinned known_hosts file is required")
    output = Path(args.output_dir).absolute()
    if os.path.lexists(output):
        raise ValueError("Output directory must not already exist")
    # Ignore untracked files: they are never included by Git archive. Any tracked
    # staged/unstaged change, including in vendored dependencies, blocks SSH.
    if any(entry[:1] != b"H" for entry in git("ls-files", "-v", "-z").split(b"\0") if entry):
        raise ValueError("Index flags could hide dirty files; clear assume-unchanged/skip-worktree first")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Tracked checkout is dirty; commit/review changes before building")
    commit = args.commit or git("rev-parse", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("Commit must be a full 40-hex commit ID")
    commit = commit.lower()
    if git("cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("Requested object is not a commit")
    options = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
               "-o", "UserKnownHostsFile=" + str(known_hosts), "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=15"]
    remote = None
    created_output = False
    success = False
    try:
        # mkdir is exclusive even for symlinks/dangling symlinks; never overwrite.
        output.mkdir(mode=0o700)
        created_output = True
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=output) as staging_name:
            staging = Path(staging_name)
            archive_path = staging / "source.tar"
            with archive_path.open("xb") as stream:
                run(["git", "archive", "--format=tar", commit], stdout=stream)
            verify_archive(archive_path, commit)
            source_sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            response = run(["ssh", *options, HOST, "mktemp -d /tmp/apkeep-release.XXXXXXXXXXXX"],
                           stdout=subprocess.PIPE, text=True).stdout.strip()
            # Only this per-run directory may ever become an rm/scp argument.
            if not re.fullmatch(r"/tmp/apkeep-release\.[A-Za-z0-9]{6,64}", response):
                raise ValueError("Builder returned an invalid temporary directory")
            remote = response
            run(["scp", *options, str(archive_path), HOST + ":" + remote + "/source.tar"])
            command = shlex.join(["bash", "-s", "--", remote, commit, args.target, source_sha256])
            run(["ssh", *options, HOST, command], input=REMOTE_SCRIPT, text=True)
            for name in ("manifest.json", "apkeep"):
                run(["scp", *options, HOST + ":" + remote + "/" + name, str(staging / name)])
            manifest = json.loads((staging / "manifest.json").read_text())
            artifact = staging / "apkeep"
            if (not artifact.is_file() or artifact.is_symlink() or artifact.stat().st_size == 0
                    or manifest.get("source_commit") != commit
                    or manifest.get("source_sha256") != source_sha256
                    or manifest.get("target") != args.target
                    or manifest.get("artifact_sha256") != hashlib.sha256(artifact.read_bytes()).hexdigest()):
                raise ValueError("Downloaded artifact/manifest does not match source, target or checksum")
            # Cleanup must succeed before any verified artifact is exposed.
            run(["ssh", *options, HOST, shlex.join(["rm", "-rf", "--", remote])])
            remote = None
            os.link(artifact, output / ("apkeep-" + args.target))
            os.link(staging / "manifest.json", output / "manifest.json")
        success = True
        print(output)
    finally:
        if remote is not None:
            cleanup = subprocess.run(["ssh", *options, HOST, shlex.join(["rm", "-rf", "--", remote])])
            if cleanup.returncode:
                print("WARNING: remote cleanup failed; remove " + remote + " on " + HOST, file=sys.stderr)
        if created_output and not success:
            shutil.rmtree(output)


try:
    main()
except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
    print("Release build refused/failed: " + str(error), file=sys.stderr)
    sys.exit(1)
PYTHON
