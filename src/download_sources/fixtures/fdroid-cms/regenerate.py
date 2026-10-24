#!/usr/bin/env python3
"""Regenerate synthetic CMS fixtures; a fresh ephemeral private key is discarded."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    tests = Path(__file__).resolve().parents[2] / "fdroid_tests.rs"
    match = re.search(r'const SIGNED_FILE: &str = (".*?");', tests.read_text())
    if match is None:
        raise RuntimeError("SIGNED_FILE fixture not found")
    sf = json.loads(match.group(1)).encode()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)

        def openssl(*arguments):
            return subprocess.run(
                ["openssl", *arguments], cwd=directory, check=True, capture_output=True
            ).stdout

        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
            "/CN=apkeep CMS regression fixture", "-days", "3650", "-set_serial", "1",
            "-keyout", "key.pem", "-out", "cert.pem",
        )
        (directory / "fixture.sf").write_bytes(sf)
        (directory / "other.sf").write_bytes(
            sf.replace(b"Signature-Version: 1.0", b"Signature-Version: 9.9")
        )
        for name, content, extra in [
            ("attrs-detached.der", "fixture.sf", []),
            ("attrs-wrong-type.der", "fixture.sf", ["-econtent_type", "1.2.840.113549.1.7.2"]),
            ("noattrs-wrong-type.der", "fixture.sf", ["-noattr", "-econtent_type", "1.2.840.113549.1.7.2"]),
            ("attrs-embedded-other.der", "other.sf", ["-nodetach"]),
        ]:
            openssl(
                "cms", "-sign", "-binary", "-nosmimecap", "-md", "sha256",
                "-in", content, "-signer", "cert.pem", "-inkey", "key.pem",
                "-outform", "DER", "-out", str(output / name), *extra,
            )
        certificate = openssl("x509", "-in", "cert.pem", "-outform", "DER")
        (output / "fingerprint.txt").write_text(hashlib.sha256(certificate).hexdigest() + "\n")
        openssl(
            "cms", "-verify", "-binary", "-inform", "DER", "-in",
            str(output / "attrs-detached.der"), "-content", "fixture.sf",
            "-CAfile", "cert.pem", "-purpose", "any", "-out", "verified.sf",
        )
        assert (directory / "verified.sf").read_bytes() == sf
    print("Generated four CMS fixtures and certificate pin; OpenSSL verification passed.")


if __name__ == "__main__":
    main()
