# Per-input JSON result reports (schema 1)

Opt in with `--report-json /private/existing/directory/result.json`. This writes a
separate file, never report JSON on stdout. Existing plaintext and JSON version
listing stdout remains unchanged. OAuth token retrieval conflicts with this flag
and is rejected by the parser before token output, prompting or network work.

```json
{"schema_version":1,"source":"ru-store","operation":"download","success":false,"results":[{"index":0,"package":"com.example.app","version":null,"status":"unavailable","reason":"variant_unavailable"}]}
```

JSON object keys are unordered; consumers must parse fields, not compare key order.

Sources use their CLI names: `apk-pure`, `f-droid`, `google-play`, `ru-store`,
`huawei-app-gallery`. Operations are `download` or `list`. Indexes are zero-based
input positions. Input order and exact duplicates are retained. Identical
package/version requests share one provider operation; a batch does not relaunch
one CLI per input or retrieve the F-Droid index repeatedly.

## Status and reason contract

| Status | Stable reasons | Meaning |
|---|---|---|
| `success` | `complete` | Artifact publication completed, an existing F-Droid APK matched the index SHA256, or an actual supported version listing completed. |
| `not_found` | `package_absent` | Authoritative absence: an empty RuStore lookup, or a missing package key in an authenticated F-Droid index. |
| `unavailable` | `variant_unavailable` | Requested version/ABI or supported complete-artifact variant cannot be supplied. |
| `unavailable` | `profile_unavailable` | Huawei returned an empty regional/profile response, or Google returned `InvalidApp` without authoritative global-absence semantics. |
| `unavailable` | `unsupported` | This provider does not support the requested listing operation. |
| `error` | `invalid_input`, `authentication`, `transport`, `timeout`, `integrity`, `local_io`, `unperformed` | Input/preflight, account, network, validation or local filesystem failure. `unperformed` is the conservative default when no trustworthy typed result was established. |

Unrecognized APKPure metadata/regex misses are errors, not package absence.
F-Droid wrong ABI/version is not package absence; malformed metadata is an error.
Disabling F-Droid index verification (`verify-index=false`) cannot establish
`not_found`. Metadata retrieval failure leaves one error per requested input.
Provider-returned numeric codes are not guessed into undocumented absence/auth
meanings. Generic Google string errors remain `error/unperformed`.

Checksum mismatches, empty bodies and incomplete/decode-failed artifact bodies are
`integrity`; request/connect failures are `transport`, and deadlines stay `timeout`.
The direct RuStore/Huawei body readers preserve these distinctions, including
metadata body framing failures versus malformed JSON/API/schema outcomes. HTTP
401/403 remain `authentication`. A message-bearing I/O `TimedOut` retains
`timeout`, and `PermissionDenied` retains `local_io`; recognized typed nested
transport errors remain classifiable, while an unrecognized message in an
`Other` I/O wrapper falls back to `local_io`, never string matching.

Operational stdout writes/flushes are fallible. A failed sink (including a broken
pipe or full device) causes controlled exit 1, not a panic. An established report
is still finalized with `success:false`: completed/available outcomes and pending
rows become `error/local_io`, while known provider/input errors retain their
reason and redaction. Already published APKs are retained; the failed command is
not a successful deliverable. Healthy listing plaintext/JSON and help bytes are
unchanged. Parser help/version output remains owned by clap.

Only allowlisted, length-bounded package/version tokens are serialized. The package
allowlist is a safe serialization envelope (ASCII letters/digits, `.`, `_`, `-`,
`+`, at most 255 bytes, excluding empty/`.`/`..`), not an Android syntax check.
This preserves legal nonstandard F-Droid identifiers. Each provider still rejects
its own invalid inputs and explicitly marks them `invalid_input`. Invalid
input rows have `null` identifiers, with `error/invalid_input`. Diagnostics, response bodies,
URLs, paths and credentials are not report fields. Safe package/version fields
are input identifiers, not a claim that a store authenticated those identifiers.
Do not reinterpret a missing result/report as `not_found`.

## Publication, bounds and exit status

The report's existing parent directory is opened and pinned **before** provider
work. The destination must end in `.json`, must not exist (including symlinks),
and must pass the pinned-directory ownership/mode/no-follow policy. `.apk`,
`.xapk` and directory/artifact collisions are excluded by this extension rule.
The CLI never overwrites the destination, including a concurrent winner. A
private same-directory temporary file is completely written, flushed and synced,
then published with no-clobber semantics; failures remove the temporary file.
Linux/procfs constraints and malicious-owner/same-UID limitations are the same as
[RELIABILITY.md](RELIABILITY.md). This is not a crash-durable transaction over
both the report and all APKs.

There are at most 65,536 input rows and at most 16 MiB of serialized report JSON.
Report construction/publication failure is nonzero; already completed APKs are
retained. Overall `success` requires both the legacy aggregate bool and explicit
successful outcomes for every input. An uninstrumented path cannot silently turn
into success. With the flag enabled, a legacy successful informational Huawei
listing still exits 1 and reports `unavailable/unsupported`; without it, the
legacy informational status/stdout behavior remains available.

Argument parsing failures (exit 2), unreadable/malformed/empty CSV, invalid CSV
column selection, input-count overflow and unsafe/existing report destinations
are rejected before a report can be established and **produce no report**.
Other preflight failures after a valid input list/report destination are reported
as safe per-input errors and exit 1. CLI diagnostics never echo raw rejected argv.

## Implementation and tests

`src/results.rs` scopes reports to an async task (`collect`) and each concurrently
polled item to its own typed outcome (`observe`). Source branches annotate typed
reasons; retries publish only the final item result. There is no process-global
last-error state or stderr/stdout parsing. Spawned tasks do not inherit report
state and must return typed outcomes to their owner. Legacy source bool facades
are preserved.

Tests cover ordered mixed outcomes, duplicates, invalid-input redaction,
authoritative absence, unsupported listing, metadata failures, retry/concurrent
scope isolation, no-clobber publication and parent renames. Normal child CLI
tests exercise the shipped argument/report path without network. A separate
child **unit-test executable** invokes the same CLI driver with a task-scoped
RuStore loopback transport; this injection is `cfg(test)` only, with no shipped
endpoint override. It checks actual JSON files and CLI exit status, successful
artifact retention, report-parent pinning and report-publication collision after
successful download. No public-store/account availability or publisher trust is
certified by these fixtures.
