# Offline CMS regression fixtures

Synthetic fixtures authored for apkeep with OpenSSL 3.0.2; no public repository
metadata or third-party fixture was copied. The test-only self-signed certificate
is embedded in each DER file. Its private key existed only in a temporary directory
and was discarded. `fingerprint.txt` pins that certificate, not F-Droid's real key.
No OpenSSL executable, key, network, or certificate-validity check is needed to run
the Rust tests (trust is the certificate pin, as in the repository verifier).

All signatures use RSA-2048/SHA256 and the `SIGNED_FILE` bytes in
`fdroid_tests.rs`:

- `attrs-detached.der`: valid detached CMS with signed attributes.
- `attrs-wrong-type.der`: valid signature/digest but wrong eContentType and
  content-type attribute (`id-signedData`, not JAR's `id-data`).
- `noattrs-wrong-type.der`: same forbidden eContentType, without signed attributes.
- `attrs-embedded-other.der`: valid CMS with signed attributes and encapsulated
  content whose harmless `Signature-Version` header differs from external `.SF`;
  verifies why checking the embedded digest instead of external `.SF` is unsafe.

Tests also mutate the unsigned eContentType without altering the valid signature
over attributes, mutate the signature/messageDigest, and remove required attribute
OIDs. The pre-existing inline fixture covers valid detached CMS without attributes.

Regenerate using Python's standard library and OpenSSL (no private key retained):

```sh
python3 src/download_sources/fixtures/fdroid-cms/regenerate.py \
  --output src/download_sources/fixtures/fdroid-cms
```

This regenerates equivalent test cases, not byte-identical artifacts: a fresh key,
certificate dates and signing time intentionally produce new bytes and a new pin.
The generator independently verifies the detached signature/content with OpenSSL
using its explicit test CA and `-purpose any`; verification is not disabled.
To exercise regeneration without replacing tracked fixtures, pass a scratch output
directory instead. To refresh fixtures, replace all four DER files and the pin as a
set, then run the F-Droid tests.
