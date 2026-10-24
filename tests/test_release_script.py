"""Offline release tests: real script/archive/remote payload; fake SSH, SCP and Cargo.

The disposable Git fixture is committed locally; the source checkout is never
committed, and no network connection, compiler or publishing command is used.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "build-remote.sh"
TARGET = "x86_64-unknown-linux-gnu"
MOCK = r'''import hashlib, json, os, pathlib, shlex, shutil, subprocess, sys, tarfile, uuid
root = pathlib.Path(os.environ["MOCK_ROOT"])
kind = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "trace").open("a") as log:
    log.write(json.dumps({"tool": kind, "args": args}) + "\n")
mode = os.environ.get("MOCK_MODE", "")
if kind == "ssh":
    command = args[-1]
    if command.startswith("mktemp "):
        if mode == "connect-fail": sys.exit(42)
        if mode == "invalid-temp":
            print("/tmp/apkeep-release.BAD;touch PWNED")
            sys.exit(0)
        remote = pathlib.Path("/tmp/apkeep-release." + uuid.uuid4().hex)
        remote.mkdir(mode=0o700)
        (root / "remote").symlink_to(remote, target_is_directory=True)
        print(remote)
    elif command.startswith("bash -s -- "):
        payload = sys.stdin.read()
        (root / "remote-script").write_text(payload)
        if mode == "build-fail": sys.exit(42)
        run = subprocess.run(["/bin/bash", "-s", "--"] + shlex.split(command)[3:], input=payload, text=True)
        if run.returncode: sys.exit(run.returncode)
        manifest = root / "remote" / "manifest.json"
        data = json.loads(manifest.read_text())
        if mode == "wrong-commit": data["source_commit"] = "0" * 40
        if mode == "wrong-target": data["target"] = "aarch64-unknown-linux-gnu"
        if mode == "wrong-archive": data["source_sha256"] = "0" * 64
        if mode == "bad-checksum": data["artifact_sha256"] = "0" * 64
        manifest.write_text(json.dumps(data))
        if mode == "empty-artifact": (root / "remote" / "apkeep").write_bytes(b"")
    elif command.startswith("rm -rf -- "):
        if mode == "cleanup-fail": sys.exit(44)
        shutil.rmtree(shlex.split(command)[3])
    else:
        raise RuntimeError("Unexpected remote command: " + command)
elif kind == "scp":
    source, destination = args[-2:]
    if ":" not in source:
        if mode == "upload-fail": sys.exit(46)
        shutil.copyfile(source, destination.split(":", 1)[1])
        if mode == "tamper-upload":
            with pathlib.Path(destination.split(":", 1)[1]).open("ab") as stream:
                stream.write(b"tampered")
        with tarfile.open(source) as archive:
            (root / "archive-files").write_text(json.dumps(archive.getnames()))
            (root / "archive-vendor").write_bytes(archive.extractfile("third-party/local/lib.rs").read())
        (root / "delivered.tar").write_bytes(pathlib.Path(source).read_bytes())
    else:
        if mode == "copy-fail": sys.exit(43)
        shutil.copyfile(source.split(":", 1)[1], destination)
elif kind == "rustc":
    print("rustc 1.0\nhost: " + os.environ.get("MOCK_HOST", "x86_64-unknown-linux-gnu"))
elif kind == "cargo":
    if mode == "cargo-fail": sys.exit(45)
    target = args[args.index("--target") + 1]
    artifact = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / target / "release" / "apkeep"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"mock native executable\n")
else:
    raise RuntimeError(kind)
'''


class ReleaseScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apkeep-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup_mock_remote)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("ssh", "scp", "rustc", "cargo"):
            executable = self.bin / name
            executable.write_text(f"#!{sys.executable}\n" + MOCK)
            executable.chmod(0o700)
        self.git("init", "-q")
        self.git("config", "user.name", "Offline fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        for name, value in {
            "Cargo.toml": "[package]\nname='apkeep'\nversion='0.0.0'\n",
            "Cargo.lock": "# committed lock\n",
            "third-party/local/lib.rs": "// committed vendor\n",
            "vendor/also-present": "committed vendor tree\n",
        }.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        self.git("add", ".")
        self.git("commit", "-qm", "offline committed fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.known_hosts = self.root / "pinned-hosts"
        self.known_hosts.write_text("apkeep-compiler ssh-ed25519 TEST-PIN\n")
        self.output = self.root / "result"
        self.env = os.environ | {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "MOCK_ROOT": str(self.root),
        }

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True)

    def run_release(self, *extra, mode=""):
        return subprocess.run(
            ["/bin/bash", str(SCRIPT), "--target", TARGET,
             "--known-hosts", str(self.known_hosts), "--output-dir", str(self.output), *extra],
            cwd=self.repo, env=self.env | {"MOCK_MODE": mode},
            capture_output=True, text=True, timeout=20,
        )

    def trace(self):
        trace = self.root / "trace"
        return [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []

    def cleanup_mock_remote(self):
        remote = self.root / "remote"
        if remote.is_symlink() and remote.exists():
            shutil.rmtree(remote.resolve())

    def assert_failed_without_output(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.output.exists())

    def test_failed_remote_build_stops_before_copying_artifacts(self):
        result = self.run_release(mode="build-fail")
        self.assert_failed_without_output(result)
        copies = [call for call in self.trace() if call["tool"] == "scp"]
        self.assertEqual(len(copies), 1)  # source upload only
        self.assertFalse((self.root / "remote").exists())

    def test_failed_copy_stops_at_first_artifact(self):
        result = self.run_release(mode="copy-fail")
        self.assert_failed_without_output(result)
        copies = [call for call in self.trace() if call["tool"] == "scp"]
        self.assertEqual(len(copies), 2)  # upload, then failed manifest download
        self.assertFalse((self.root / "remote").exists())

    def test_failed_cargo_stops_before_downloading_artifacts(self):
        result = self.run_release(mode="cargo-fail")
        self.assert_failed_without_output(result)
        self.assertEqual(len([c for c in self.trace() if c["tool"] == "scp"]), 1)
        self.assertFalse((self.root / "remote").exists())

    def test_failed_initial_connection_creates_no_artifacts(self):
        result = self.run_release(mode="connect-fail")
        self.assert_failed_without_output(result)
        self.assertEqual([c["tool"] for c in self.trace()], ["ssh"])

    def test_invalid_remote_directory_never_becomes_shell_or_cleanup_argument(self):
        result = self.run_release(mode="invalid-temp")
        self.assert_failed_without_output(result)
        self.assertEqual([c["tool"] for c in self.trace()], ["ssh"])
        self.assertIn("invalid temporary directory", result.stderr)
        self.assertFalse((self.repo / "PWNED").exists())

    def test_failed_upload_cleans_remote_without_building(self):
        result = self.run_release(mode="upload-fail")
        self.assert_failed_without_output(result)
        self.assertFalse((self.root / "remote").exists())
        self.assertFalse((self.root / "remote-script").exists())

    def test_tampered_source_archive_is_rejected_before_cargo(self):
        result = self.run_release(mode="tamper-upload")
        self.assert_failed_without_output(result)
        self.assertFalse((self.root / "remote").exists())
        self.assertFalse(any(c["tool"] == "cargo" for c in self.trace()))

    def test_builder_host_cannot_be_overridden(self):
        result = self.run_release("--host", "attacker;touch PWNED")
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.repo / "PWNED").exists())

    def test_cleanup_failure_does_not_expose_artifact(self):
        result = self.run_release(mode="cleanup-fail")
        self.assert_failed_without_output(result)
        self.assertIn("remote cleanup failed", result.stderr)

    def assert_invalid_download(self, mode):
        result = self.run_release(mode=mode)
        self.assert_failed_without_output(result)
        self.assertFalse((self.root / "remote").exists())
        self.assertIn("does not match", result.stderr)

    def test_wrong_source_commit_is_rejected(self):
        self.assert_invalid_download("wrong-commit")

    def test_wrong_source_archive_checksum_is_rejected(self):
        self.assert_invalid_download("wrong-archive")

    def test_wrong_target_manifest_is_rejected(self):
        self.assert_invalid_download("wrong-target")

    def test_wrong_artifact_checksum_is_rejected(self):
        self.assert_invalid_download("bad-checksum")

    def test_empty_artifact_is_rejected(self):
        self.assert_invalid_download("empty-artifact")

    def test_cross_compilation_is_explicitly_refused(self):
        self.env["MOCK_HOST"] = "aarch64-unknown-linux-gnu"
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertIn("Unsupported cross target", result.stderr)
        self.assertFalse(any(c["tool"] == "cargo" for c in self.trace()))
        self.assertFalse((self.root / "remote").exists())

    def test_unstaged_changes_refuse_before_ssh(self):
        (self.repo / "Cargo.lock").write_text("dirty\n")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])
        self.assertIn("dirty", result.stderr)

    def test_staged_vendor_changes_refuse_before_ssh(self):
        (self.repo / "third-party/local/lib.rs").write_text("dirty vendor\n")
        self.git("add", ".")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_assume_unchanged_cannot_hide_dirty_source(self):
        self.git("update-index", "--assume-unchanged", "Cargo.lock")
        (self.repo / "Cargo.lock").write_text("hidden dirty lock\n")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_skip_worktree_cannot_hide_dirty_source(self):
        self.git("update-index", "--skip-worktree", "Cargo.lock")
        (self.repo / "Cargo.lock").write_text("hidden dirty lock\n")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_escaping_source_symlink_refuses_before_ssh(self):
        (self.repo / "unsafe-link").symlink_to("/etc/passwd")
        self.git("add", ".")
        self.git("commit", "-qm", "unsafe symlink fixture")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_symlink_parent_traversal_refuses_before_ssh(self):
        (self.repo / "dir-link").symlink_to(".")
        (self.repo / "escape-link").symlink_to("dir-link/../outside")
        self.git("add", ".")
        self.git("commit", "-qm", "symlink traversal fixture")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_known_hosts_token_expansion_refuses_before_ssh(self):
        self.known_hosts = self.root / "pins-%h"
        self.known_hosts.write_text("apkeep-compiler ssh-ed25519 TEST-PIN\n")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_nonexistent_pin_file_refuses_before_ssh(self):
        self.known_hosts.unlink()
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_empty_pin_file_refuses_before_ssh(self):
        self.known_hosts.write_text("")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_text("unchanged")
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertEqual(self.trace(), [])

    def test_dangling_output_symlink_is_preserved(self):
        self.output.symlink_to(self.root / "absent")
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(self.trace(), [])

    def test_unsupported_target_refuses_before_ssh(self):
        result = self.run_release("--target", "x86_64-pc-windows-msvc")
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_target_command_injection_refuses_before_ssh(self):
        result = self.run_release("--target", "x86_64-unknown-linux-gnu;touch PWNED")
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.repo / "PWNED").exists())

    def test_short_commit_refuses_before_ssh(self):
        result = self.run_release("--commit", self.commit[:12])
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_branch_name_refuses_before_ssh(self):
        result = self.run_release("--commit", "HEAD")
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_commit_command_injection_refuses_before_ssh(self):
        result = self.run_release("--commit", self.commit + ";touch PWNED")
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])
        self.assertFalse((self.repo / "PWNED").exists())

    def test_git_replace_cannot_substitute_other_source_for_commit(self):
        (self.repo / "third-party/local/lib.rs").write_text("// replaced source\n")
        self.git("add", ".")
        self.git("commit", "-qm", "replacement fixture")
        replacement = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("replace", self.commit, replacement)
        result = self.run_release("--commit", self.commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "archive-vendor").read_text(), "// committed vendor\n")

    def test_explicit_old_commit_is_delivered_not_new_head(self):
        (self.repo / "third-party/local/lib.rs").write_text("// newer vendor\n")
        self.git("add", ".")
        self.git("commit", "-qm", "second fixture commit")
        result = self.run_release("--commit", self.commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "archive-vendor").read_text(), "// committed vendor\n")
        self.assertEqual(json.loads((self.output / "manifest.json").read_text())["source_commit"], self.commit)

    def test_export_ignore_cannot_silently_omit_vendor(self):
        (self.repo / ".gitattributes").write_text("third-party export-ignore\n")
        self.git("add", ".")
        self.git("commit", "-qm", "archive attribute fixture")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_export_subst_cannot_silently_change_source(self):
        (self.repo / ".gitattributes").write_text("Cargo.lock export-subst\n")
        (self.repo / "Cargo.lock").write_text("$Format:%H$\n")
        self.git("add", ".")
        self.git("commit", "-qm", "archive substitution fixture")
        result = self.run_release()
        self.assert_failed_without_output(result)
        self.assertEqual(self.trace(), [])

    def test_success_delivers_exact_commit_and_verifies_native_artifact(self):
        (self.repo / "untracked-secret").write_text("must not ship")
        result = self.run_release()
        self.assertEqual(result.returncode, 0, result.stderr)
        files = json.loads((self.root / "archive-files").read_text())
        self.assertIn("Cargo.lock", files)
        self.assertIn("vendor/also-present", files)
        self.assertIn("third-party/local/lib.rs", files)
        self.assertNotIn("untracked-secret", files)
        self.assertEqual((self.root / "archive-vendor").read_text(), "// committed vendor\n")
        commit_in_archive = subprocess.run(
            ["git", "get-tar-commit-id"], input=(self.root / "delivered.tar").read_bytes(),
            capture_output=True, check=True,
        ).stdout.decode().strip()
        self.assertEqual(commit_in_archive, self.commit)
        manifest = json.loads((self.output / "manifest.json").read_text())
        artifact = self.output / ("apkeep-" + TARGET)
        self.assertEqual(manifest["source_commit"], self.commit)
        self.assertEqual(manifest["target"], TARGET)
        self.assertEqual(manifest["artifact_sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.root / "remote").exists())
        calls = self.trace()
        for call in calls:
            if call["tool"] in ("ssh", "scp"):
                args = call["args"]
                for option in ("StrictHostKeyChecking=yes", "BatchMode=yes",
                               "UserKnownHostsFile=" + str(self.known_hosts),
                               "GlobalKnownHostsFile=/dev/null"):
                    self.assertIn(option, args)
                self.assertEqual(args[:2], ["-F", "/dev/null"])
        cargo = [call["args"] for call in calls if call["tool"] == "cargo"]
        self.assertEqual(cargo, [["build", "--release", "--locked", "--target", TARGET]])
        payload = (self.root / "remote-script").read_text()
        for unsafe in ("sudo", "dist-upgrade", "git clone", "rustup", "curl ", "wget "):
            self.assertNotIn(unsafe, payload)


if __name__ == "__main__":
    unittest.main()
