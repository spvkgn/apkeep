APKPure is a clone of the Google Play Store which has been found modifying apps available on Google Play to [distribute malware](https://vpnrevie.ws/apkpure-fake-telegram-collector/). This download source should be used *only* for research purposes. If you acknowledge the dangers and still wish to proceed, please add the `-o` option `acknowledge_dangers=true` to explicitly allow downloading from this source:

```shell
apkeep -a  com.instagram.android -d apk-pure -o 'acknowledge_dangers=true' .
```

More options can be passed with the `-o` option. For instance, download a specific architecture variant of an app with `arch=`:

```shell
apkeep -a com.instagram.android -d apk-pure -o 'acknowledge_dangers=true,arch=x86' .
```

To specify multiple architectures, separate the `arch=` specification with a semicolon. The following shows the default `arch` option:

```shell
apkeep -a com.instagram.android -d apk-pure -o 'acknowledge_dangers=true,arch=arm64-v8a;armeabi-v7a;armeabi;x86;x86_64' .
```

You can also list the versions available, either specifying a specific architecture or not. This does not require the `acknowledge_dangers=true` option:

```shell
apkeep -l -d apk-pure -a com.instagram.android -o 'arch=x86'
apkeep -l -d apk-pure -a com.instagram.android
```

### Reliability and input handling

Downloads and version listings process every valid item in a batch. The command
returns a failure status if any item fails, if the batch is empty, or if a version
listing contains no usable versions. Successful downloads/listings from other
items are retained. Diagnostics go to stderr (including when JSON output is
selected); raw invalid components and network URLs are not included in errors.

Package IDs must be ASCII dot-separated identifiers (letters/underscore first in
each segment, then letters/digits/underscore; at most 200 bytes). Versions must
start with an ASCII letter or digit and contain only ASCII letters, digits,
`._+-()[]`, with no `..` sequence (at most 120 bytes). Each architecture must
start with an ASCII letter or digit and contain only ASCII letters, digits,
underscore or hyphen. Multiple architectures remain semicolon-separated (at most
100 bytes total), with no empty entries. Unknown but safely named architecture
values are passed through; this does not guarantee APKPure offers that ABI.
Unsafe/path-like, empty, control-character and overlong components are rejected
before a metadata request or destination path is constructed. The complete output
stem is limited to 240 bytes.

Safe filenames keep the existing layout: `package.apk`, `package@version.apk`,
`package@arch.apk`, or `package@version@arch.apk` (and `.xapk` for XAPK responses).
An explicitly requested version matches a complete version token inside its own
record; a URL belonging to a later version is not used as a fallback.

Metadata responses must have HTTP status 200 and are limited to 2 MiB, including
responses without `Content-Length`. The metadata client has a 10-second connect
timeout and a 30-second total request timeout. Metadata body failures are reported
without panicking. Artifact header requests are additionally bounded to 30
seconds, and each of at most three body-download attempts to 300 seconds (the
shared downloader may apply stricter deadlines).

Existing regular output files are preserved but rejected as unverified, rather
than reported as successful skips (a deliberate compatibility change). A destination
created during publication is also an unverified failure, not a reason to repeat
the download. Use a fresh output directory. Directories and symlinks are failures. These
reliability checks do **not** make APKPure trustworthy, validate APK signatures,
or add an APKPure checksum/authenticity guarantee. The research-only warning
above still applies.

Artifacts are capped at 2 GiB, including unknown-length/chunked responses, with
limits enforced before writes by the shared downloader.

Production metadata and artifact requests enforce the shared public-network-only
policy (including DNS and redirects): no URL credentials, private, loopback,
link-local or reserved addresses; environment proxies are not used. There is no
CLI/environment bypass. See [RELIABILITY.md](RELIABILITY.md#public-http-boundary).
OUTPATH and its ancestors must be trusted and not concurrently replaced by other
users: path-based no-clobber publication is not a dirfd/openat defense against a
hostile local directory owner.
