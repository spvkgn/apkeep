To download from the F-Droid open source repository:

```shell
apkeep -a org.mozilla.fennec_fdroid -d f-droid .
```

More advanced options for this download source can be passed with the `-o` option.  For instance, to use an F-Droid mirror:

```shell
apkeep -a org.mozilla.fennec_fdroid -d f-droid -o repo=https://cloudflare.f-droid.org/repo .
```

The selected `repo` is used for **both metadata and APK downloads**. The
index's advertised `repo.address` is not a request destination; an index cannot
silently switch APK requests back to its canonical origin or to another host.

In addition to specifying a mirror, a wholly separate F-Droid repo can be specified along with its fingerprint:

```shell
apkeep -a org.torproject.android -d f-droid -o repo=https://guardianproject.info/fdroid/repo?fingerprint=B7C2EEFD8DAC7806AF67DFCD92EB18126BC08312A7F2D6F3862E46013C7A6135 .
```

If a repo only supports the old (v1) package index, the newer [entry point specification](https://f-droid.org/docs/All_our_APIs/#the-repo-index) can be disabled by use of the `use_entry` option:

```shell
apkeep -a org.torproject.android -d f-droid -o repo=https://guardianproject.info/fdroid/repo?fingerprint=B7C2EEFD8DAC7806AF67DFCD92EB18126BC08312A7F2D6F3862E46013C7A6135,use_entry=false .
```

## Reliability and verification policy

- Downloads and version listings succeed only when **every** requested app succeeds. An empty request, missing app/version/ABI, malformed metadata, HTTP error, timeout, filesystem error or checksum mismatch is a failure. Valid jobs still run when another job fails; the CLI reports an unsuccessful overall result and diagnostics on stderr.
- Identical app/version/ABI requests within a download batch share one job and do not cause a false selection failure or competing writes. For v1 indexes, an unpinned request selects the greatest numeric `versionCode` among valid candidates matching the requested ABI, not the first array entry or the greatest `versionName`. Candidates without a nonnegative integer version code cannot satisfy an unpinned v1 request; an explicitly pinned version name does not require a version code.
- APKs and the index referenced by a verified entry are checked against their expected SHA256 **before** atomic, no-clobber publication. Failed/truncated transfers and checksum mismatches do not leave a final APK/index file. An existing regular APK counts as a successful skip only if its SHA256 matches; mismatching files are preserved and reported as failures. Symlinks, dangling symlinks, directories and other nonregular destinations are errors, never successful skips.
- Package IDs, requested versions and ABI values must be nonempty ASCII path components using letters, digits, `.`, `_`, `-` or `+` (not `.` or `..`, at most 200 bytes per component). Generated APK filenames must fit within 255 bytes. Output directory components must be existing real directories: symlinks and parent (`..`) traversal are rejected.
- Entry/index and APK repository filenames must contain only literal repository-relative components using ASCII letters, digits, `.`, `_` or `-`. One leading `/` is normalized; empty, `.` and `..` components, encoded separators, backslashes, query/fragment syntax and full URLs are rejected. Safe nested paths remain supported. APK candidates must carry a hex SHA256 representing exactly 32 bytes; malformed or unsafe candidates are ignored, making an unresolved request fail.
- GETs have a 15-second connect deadline, a 30-second read deadline and a 120-second overall F-Droid transfer deadline (per APK attempt, up to three attempts). Each APK is limited to **2 GiB**, including unknown-length/chunked responses; advertised oversize lengths are rejected before body transfer and streamed bytes are capped before writing. Metadata downloads and archive extraction are bounded to 128 MiB; archives are limited to 4096 entries. Unsafe archive entries and extraction errors fail closed.
- Existing APK verification streams through an 8 KiB buffer, rather than allocating the entire file. Regular files larger than 2 GiB are rejected before hashing; a bounded reader consumes at most the cap plus one sentinel byte if a file grows while read. Opening, inspecting and hashing an existing APK share a 120-second deadline. A size/deadline failure preserves the existing file and is not a successful skip.
- All normal metadata and APK HTTP clients enforce a public-network-only policy: HTTP(S), no URL credentials, no loopback/private/link-local/reserved destinations, checked DNS answers pinned to the actual connection, and revalidation of every redirect. Environment proxies are not used. This intentionally **disables private repositories**, even with a valid signing pin or `verify-index=false`; index authentication does not grant permission to contact internal services. There is no CLI/environment network-policy bypass. Local fixtures use a separate, explicit internal client-injection API, not the production entry points.
- Conditional GET caching stores **signed archives**, not trusted unsigned JSON. Every cached archive is reverified against the current signature/fingerprint policy, including after HTTP 304; the old JSON/etag cache is not reused. Missing ETags cause a fresh download, not a panic. Corrupt or nonregular cache entries produce an error. No network, cache or parsing error silently disables verification.

The explicit `verify-index=false` debugging option below is still supported; it disables repository authentication and the entry's index hash check, **not** APK hash checking. It is never selected automatically after a failure.

A special option can also be used to skip verification of the repository index.  *Only use for debugging purposes*:

```shell
apkeep -a org.torproject.android -d f-droid -o repo=https://guardianproject.info/fdroid/repo,verify-index=false .
```

It is also possible to download a specific architecture variant of an app with the `arch=` option:

```shell
apkeep -a org.videloan.vlc@3.5.4 -d f-droid -o arch=arm64-v8a .
```

To list what versions are available, use `-l`:

```shell
apkeep -l -a org.mozilla.fennec_fdroid -d f-droid
```

To output the list in json, use the `output_format=json` option:

```shell
apkeep -l -a org.mozilla.fennec_fdroid -d f-droid -o output_format=json
```
