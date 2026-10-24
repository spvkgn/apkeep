To download directly from the Google Play Store, you have two authentication options:

## Option 1: Using OAuth Token (recommended for personal accounts)

First, obtain an OAuth token by visiting the Google [embedded setup page](https://accounts.google.com/EmbeddedSetup) and:

- Open the browser debugging console to the `Network` tab
- Log in
- If the "Google Terms of Services" pop up, click `I agree` (there may be some delay afterwards)
- Select the last request from `accounts.google.com` in the `Network` tab
- Select the `Cookies` tab of this request
- One of the response cookies is `oauth_token`
- Copy the `value` field (it will start with `oauth2_4/`)

It can only be used once, in order to obtain the AAS token which can be used subsequently. To obtain this token:

```shell
apkeep -e 'someone@gmail.com' --oauth-token oauth2_4/...
```

An AAS token should be printed. You can use this to download an app:

```shell
apkeep -a com.instagram.android -e 'someone@gmail.com' -t some_aas_token .
```

## Option 2: Using AUTH Token (for token dispensers)

If you have an AUTH token from a token dispenser (e.g., Aurora Store's dispenser), you can use it directly with the `--auth-token` flag:

```shell
apkeep -a com.instagram.android -d google-play -e 'dispenser_email@gmail.com' --auth-token 'ya29.a0...' .
```

AUTH tokens typically start with `ya29.`. Terms of Service are never accepted implicitly. If Google requires acceptance, read the [Google Play terms](https://play.google.com/about/play-terms/index.html) and pass `--accept-tos` only if you intentionally agree.

## Device Configuration

Both options will use a default device configuration of `px_9a`, a timezone of `UTC`, and a locale of `en_US`. To specify a different device profile, use the `-o` option:

```shell
apkeep -a com.instagram.android -d google-play -o device=ad_g3_pro -e 'someone@gmail.com' -t some_aas_token .
```

Available devices are specified [here](https://github.com/EFForg/rs-google-play/blob/master/gpapi/device.properties).

To specify your own device properties file (e.g. one you've exported from Aurora Store's spoof manager):

```shell
apkeep -a com.instagram.android -d google-play -o device=default,device_properties_file=/path/to/device.properties .
```

Likewise, a separate timezone or locale can also be specified:

```shell
apkeep -a com.instagram.android -d google-play -o device=ad_g3_pro,locale=es_MX -e 'someone@gmail.com' -t some_aas_token .
```

Note that if the app you're downloading is region-locked and not available in your region, the locale and timezone changes alone will not let apkeep download it. 
In that case the download will fail with a `Invalid app response` error. 
To download a region-locked app you first need to bind it to your account by downloading it with an IP address from a region it's available in.
After the first download, you can download the app from any region.


This option attempts to download a split APK if available, and falls back to the full APK:

```shell
apkeep -a hk.easyvan.app.client -d google-play -o split_apk=true -e 'someone@gmail.com' -t some_aas_token .
```

A full list of options:

* `device`: specify a device profile as described above
* `device_properties_file`: specify a custom device properties file
* `locale`: specify a locale
* `timezone`: specify a timezone 
* `split_apk`: when set to `1` or `true`, attempts to download a [split APK](https://developer.android.com/studio/build/configure-apk-splits)
* `include_dex_metadata`: when set to `1` or `true`, attempts to download the DexMetadata (dm) file for an app, which contains the apps' cloud profile
* `include_additional_files`: when set to `1` or `true`, attempts to download any [additional `obb` expansion files](https://developer.android.com/google/play/expansion-files) for the app

If you prefer not to provide your credentials on the command line, you can specify them in a config file named `apkeep.ini`. This config file may have to be created, and must be located in the user config directory under the subpath `apkeep`. Usually on Linux systems this will be `~/.config/apkeep/apkeep.ini`. In this file specify your email and token:

```ini
[google]
email = someone@gmail.com
aas_token = some_aas_token
# OR use auth_token instead of aas_token:
# auth_token = ya29.a0...
```

Optionally, the path to this `ini` file can be specified:

```shell
apkeep -a com.instagram.android -d google-play -i ~/path/to/some.ini .
```

## Device-constructor failures

Custom device properties are read from a regular file into a private snapshot,
limited to 256 KiB, before gpapi construction. Unknown built-in devices, missing
or malformed custom files, missing profiles and typed-field parsing failures
produce a controlled, redacted device-configuration error before authentication
or other network work (including OAuth-to-AAS exchange). gpapi 6.1.0 exposes only
panicking constructors; a narrow synchronous unwind boundary suppresses only
those constructor panic diagnostics on the current thread, forwarding unrelated
panics to the previous hook. This is not a claim that all later gpapi internals
are panic-free or use the shared public-network HTTP policy.

## Failure handling and output safety

- A batch succeeds only if every requested app succeeds. Failed apps, unsupported
  `app@version` requests, invalid package IDs and existing destinations produce a
  failure exit status; other valid apps in the batch are still processed.
- Google Play version listing is unsupported and returns a failure exit status.
  Only the latest version can be requested. Package IDs must be dot-separated
  ASCII identifiers (letters first in each component, then letters, digits or
  underscores), with a maximum length of 255 bytes.
- Login, explicit Terms of Service acceptance and OAuth-to-AAS token exchange each
  have a 120-second deadline. Each complete app-download attempt, including its
  metadata and split/OBB transfers, has a 600-second deadline. Transient download
  errors and timeouts get at most three attempts total; permanent app, credentials
  or local destination errors are not retried. These limits do not include an
  explicitly configured inter-download sleep or time spent waiting for a batch slot.
- Every app attempt uses a fresh staging directory inside `OUTPATH` (owner-only
  access on Unix). API errors, timeouts and cancelled futures clean that staging
  directory instead of exporting a base APK, incomplete splits or OBB files.
  Files are published only after the entire API download succeeds and its output
  has been checked for a nonempty base APK and regular expected artifacts.
- Output layouts are unchanged: a standalone APK is `OUTPATH/package.apk`;
  split APKs, expansion files or dex metadata use `OUTPATH/package/` as needed.
  Existing files, directories and symlinks are never replaced. Publishing uses
  same-filesystem hard links, so the output filesystem must support them. A split
  directory is reserved exclusively and local publication errors roll back links
  created by this invocation; directory publication is not a single atomic rename.
- Authentication and download failures use redacted messages on stderr, not raw
  API errors or signed download URLs. Successful OAuth-to-AAS exchange deliberately
  prints **only the resulting token** on stdout; failure prints no token. Treat
  captured stdout as a secret and do not attach it to bug reports.

The caller's reliability tests use an offline backend and local fixture files.
They do not authenticate to Google, download real apps, or accept real terms.
