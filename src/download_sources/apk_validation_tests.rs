use super::*;

#[test]
fn long_version_code_compares_major_bits_not_only_low32() {
    // Extend an aapt-compiled binary XML fixture with versionCodeMajor. The
    // installed Android-23 resource jar predates that attribute, so add its
    // binary representation explicitly rather than claiming a live API fixture.
    let mut xml = manifest(&base_apk());
    let old_size = u32_at(&xml, 12).unwrap() as usize;
    let count = u32_at(&xml, 16).unwrap();
    let data_start = u32_at(&xml, 28).unwrap() as usize;
    assert_eq!(u32_at(&xml, 20).unwrap(), 0); // no styles
    assert_eq!(u32_at(&xml, 24).unwrap() & 0x100, 0); // UTF-16
    let mut pool = xml[8..8 + old_size].to_vec();
    pool.splice(
        28 + count as usize * 4..28 + count as usize * 4,
        ((old_size - data_start) as u32).to_le_bytes(),
    );
    let name: Vec<u16> = "versionCodeMajor".encode_utf16().collect();
    pool.extend_from_slice(&(name.len() as u16).to_le_bytes());
    for ch in name {
        pool.extend_from_slice(&ch.to_le_bytes());
    }
    pool.extend_from_slice(&[0, 0]);
    while !pool.len().is_multiple_of(4) {
        pool.push(0);
    }
    let size = pool.len() as u32;
    pool[4..8].copy_from_slice(&size.to_le_bytes());
    pool[8..12].copy_from_slice(&(count + 1).to_le_bytes());
    pool[20..24].copy_from_slice(&((data_start + 4) as u32).to_le_bytes());
    xml.splice(8..8 + old_size, pool);
    let mut pos = 8 + size as usize;
    while u16_at(&xml, pos).unwrap() != 0x102 {
        pos += u32_at(&xml, pos + 4).unwrap() as usize;
    }
    let start = pos + 16 + u16_at(&xml, pos + 24).unwrap() as usize;
    let n = u16_at(&xml, pos + 28).unwrap();
    let attrs = &xml[start..start + n as usize * 20];
    let version = attrs
        .as_chunks::<20>()
        .0
        .iter()
        .find(|a| a[15] == 0x10)
        .unwrap();
    let mut major = version.to_vec();
    major[4..8].copy_from_slice(&count.to_le_bytes());
    major[8..12].copy_from_slice(&NONE.to_le_bytes());
    major[16..20].copy_from_slice(&1u32.to_le_bytes());
    let chunk_size = u32_at(&xml, pos + 4).unwrap();
    xml.splice(start + n as usize * 20..start + n as usize * 20, major);
    xml[pos + 4..pos + 8].copy_from_slice(&(chunk_size + 20).to_le_bytes());
    xml[pos + 28..pos + 30].copy_from_slice(&(n + 1).to_le_bytes());
    let total = xml.len() as u32;
    xml[4..8].copy_from_slice(&total.to_le_bytes());
    let apk = repack(&xml, &[]);
    assert_eq!(
        check(&apk, "com.example.app", Some((1u64 << 32) | 42)),
        Ok(())
    );
    assert!(check(&apk, "com.example.app", Some(42)).is_err());
    assert_eq!(check(&apk, "com.example.app", None), Ok(()));
}

use std::io::{Cursor, Write};

// Synthetic, resource-only APKs compiled offline. No production APKs are copied.
pub(crate) fn compiled_apk(package: &str, version: u32, extra: &str) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("AndroidManifest.xml");
    std::fs::write(&manifest, format!(r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="{version}" {extra}><uses-sdk android:minSdkVersion="21"/><application android:hasCode="false"/></manifest>"#)).unwrap();
    let output = directory.path().join("fixture.apk");
    let result = std::process::Command::new("aapt").args(["package", "-f", "-M"]).arg(&manifest)
        .args(["-I", "/usr/share/java/com.android.android-23.jar", "-F"]).arg(&output).output()
        .expect("offline APK tests require aapt and Android framework jar (not production dependencies)");
    assert!(
        result.status.success(),
        "aapt fixture compilation: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::read(output).unwrap()
}

pub(crate) fn base_apk() -> Vec<u8> {
    static APK: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    APK.get_or_init(|| compiled_apk("com.example.app", 42, ""))
        .clone()
}

pub(crate) fn repack(manifest: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .last_modified_time(zip::DateTime::default())
        .compression_method(zip::CompressionMethod::Stored);
    writer.start_file("AndroidManifest.xml", options).unwrap();
    writer.write_all(manifest).unwrap();
    for (name, bytes) in extra {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

pub(crate) fn manifest(bytes: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut result = Vec::new();
    archive
        .by_name("AndroidManifest.xml")
        .unwrap()
        .read_to_end(&mut result)
        .unwrap();
    result
}

fn check(bytes: &[u8], package: &str, version: Option<u64>) -> Result<(), &'static str> {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    validate(&mut file, package, version)
}

fn with_cdata() -> Vec<u8> {
    let mut xml = manifest(&base_apk());
    let mut pos = 8;
    while u16_at(&xml, pos).unwrap() != 0x103 {
        pos += u32_at(&xml, pos + 4).unwrap() as usize;
    }
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&0x104u16.to_le_bytes());
    chunk.extend_from_slice(&16u16.to_le_bytes());
    chunk.extend_from_slice(&28u32.to_le_bytes());
    chunk.extend_from_slice(&1u32.to_le_bytes());
    chunk.extend_from_slice(&NONE.to_le_bytes());
    chunk.extend_from_slice(&0u32.to_le_bytes()); // valid pool string
    chunk.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // TYPE_NULL Res_value
    xml.splice(pos..pos, chunk);
    let len = xml.len() as u32;
    xml[4..8].copy_from_slice(&len.to_le_bytes());
    xml
}

#[test]
fn valid_cdata_and_invalid_cdata_references_are_distinguished() {
    let xml = with_cdata();
    assert_eq!(
        check(&repack(&xml, &[]), "com.example.app", Some(42)),
        Ok(())
    );
    let pos = xml
        .windows(8)
        .position(|b| b == [4, 1, 16, 0, 28, 0, 0, 0])
        .unwrap();
    for (offset, bytes) in [(16, u32::MAX.to_le_bytes()), (24, u32::MAX.to_le_bytes())] {
        let mut bad = xml.clone();
        if offset == 24 {
            bad[pos + 20..pos + 24].copy_from_slice(&[8, 0, 0, 3]);
        }
        bad[pos + offset..pos + offset + 4].copy_from_slice(&bytes);
        assert!(check(&repack(&bad, &[]), "com.example.app", None).is_err());
    }
    let mut bad = xml.clone();
    bad[pos + 22] = 1; // reserved byte
    assert!(check(&repack(&bad, &[]), "com.example.app", None).is_err());
}

// Insert extras into the first member of a multi-entry, aapt-derived fixture.
// Update every shifted local offset and the EOCD, not just the extra length;
// otherwise a directory-offset failure could mask the extra parser regression.
fn with_zip_extra(extra: &[u8], local: bool) -> Vec<u8> {
    let mut apk = repack(&manifest(&base_apk()), &[("assets/data", b"fixture")]);
    let end = apk.len() - 22;
    let directory = u32_at(&apk, end + 16).unwrap() as usize;
    let count = u16_at(&apk, end + 10).unwrap() as usize;
    assert_eq!(count, 2);
    let name_len = u16_at(&apk, directory + 28).unwrap() as usize;
    assert_eq!(u16_at(&apk, directory + 30).unwrap(), 0);
    let added = extra.len();
    if local {
        assert_eq!(u32_at(&apk, directory + 42).unwrap(), 0);
        assert_eq!(u16_at(&apk, 28).unwrap(), 0);
        apk[28..30].copy_from_slice(&(added as u16).to_le_bytes());
        let mut pos = directory;
        for _ in 0..count {
            let offset = u32_at(&apk, pos + 42).unwrap();
            if offset > 0 {
                apk[pos + 42..pos + 46].copy_from_slice(&(offset + added as u32).to_le_bytes());
            }
            pos += 46
                + u16_at(&apk, pos + 28).unwrap() as usize
                + u16_at(&apk, pos + 30).unwrap() as usize
                + u16_at(&apk, pos + 32).unwrap() as usize;
        }
        apk[end + 16..end + 20].copy_from_slice(&((directory + added) as u32).to_le_bytes());
        apk.splice(30 + name_len..30 + name_len, extra.iter().copied());
    } else {
        let size = u32_at(&apk, end + 12).unwrap();
        apk[end + 12..end + 16].copy_from_slice(&(size + added as u32).to_le_bytes());
        apk[directory + 30..directory + 32].copy_from_slice(&(added as u16).to_le_bytes());
        let start = directory + 46 + name_len;
        apk.splice(start..start, extra.iter().copied());
    }
    apk
}

#[test]
fn short_zero_local_alignment_tails_preserve_valid_apk_contents() {
    // Legacy zipalign pads local extras with 1..=3 zero bytes for 4-byte
    // alignment, either alone or after a complete, non-special TLV record.
    for prefix in [&[][..], &[0xfe, 0xca, 1, 0, 0xab][..]] {
        for length in 1..=3 {
            let mut extra = prefix.to_vec();
            extra.extend(std::iter::repeat_n(0, length));
            let apk = with_zip_extra(&extra, true);
            let mut archive = zip::ZipArchive::new(Cursor::new(&apk)).unwrap();
            for index in 0..archive.len() {
                let mut bytes = Vec::new();
                archive
                    .by_index(index)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
            }
            assert_eq!(manifest(&apk), manifest(&base_apk()));
            assert_eq!(
                check(&apk, "com.example.app", Some(42)),
                Ok(()),
                "extra {extra:?}"
            );
        }
    }
}

#[test]
fn nonzero_short_local_tails_are_zip_errors_not_manifest_errors() {
    for prefix in [&[][..], &[0xfe, 0xca, 1, 0, 0xab][..]] {
        for length in 1..=3 {
            for nonzero in 0..length {
                let mut extra = prefix.to_vec();
                extra.extend(std::iter::repeat_n(0, length));
                extra[prefix.len() + nonzero] = 1;
                assert_eq!(
                    check(&with_zip_extra(&extra, true), "com.example.app", None),
                    Err("invalid APK ZIP directory"),
                    "extra {extra:?}"
                );
            }
        }
    }
}

#[test]
fn local_padding_does_not_hide_malformed_tlv_lengths_or_headers() {
    for extra in [
        &[0xfe, 0xca, 3, 0, 0, 0][..], // payload overrun, not a zero tail
        &[0xfe, 0xca, 0xff, 0xff, 0, 0, 0][..],
        &[0, 0, 1, 0][..], // complete zero-kind header still needs its payload
        &[0, 0, 0, 1, 0, 0, 0][..],
        &[0xfe, 0xca, 0, 0, 0xfe][..], // truncated next header
    ] {
        assert_eq!(
            check(&with_zip_extra(extra, true), "com.example.app", None),
            Err("invalid APK ZIP directory"),
            "extra {extra:?}"
        );
    }
}

#[test]
fn zip64_and_aes_extras_remain_rejected_in_local_and_central_headers() {
    for local in [false, true] {
        for kind in [1u16, 0x9901] {
            for prefix in [&[][..], &[0xfe, 0xca, 0, 0][..], &[0, 0, 0, 0][..]] {
                let mut extra = prefix.to_vec();
                extra.extend_from_slice(&kind.to_le_bytes());
                extra.extend_from_slice(&0u16.to_le_bytes());
                extra.extend_from_slice(&[0, 0]);
                assert_eq!(
                    check(&with_zip_extra(&extra, local), "com.example.app", None),
                    Err("unsupported APK ZIP extra field"),
                    "local {local}, extra {extra:?}"
                );
            }
            // A zero TLV before a forbidden record is parsed above, not
            // treated as padding that could hide the following header.
        }
    }
}

#[test]
fn central_extra_policy_stays_strict_for_short_zero_alignment_tails() {
    for prefix in [&[][..], &[0xfe, 0xca, 1, 0, 0xab][..]] {
        // A well-formed non-special TLV itself is still valid centrally.
        assert_eq!(
            check(&with_zip_extra(prefix, false), "com.example.app", Some(42)),
            Ok(())
        );
        for length in 1..=3 {
            let mut extra = prefix.to_vec();
            extra.extend(std::iter::repeat_n(0, length));
            assert_eq!(
                check(&with_zip_extra(&extra, false), "com.example.app", None),
                Err("invalid APK ZIP directory"),
                "extra {extra:?}"
            );
        }
    }
}

#[test]
fn compiled_binary_base_manifest_is_accepted() {
    assert_eq!(check(&base_apk(), "com.example.app", Some(42)), Ok(()));
}

#[test]
fn manifest_package_is_bound_to_requested_package() {
    assert!(
        check(
            &compiled_apk("com.other.app", 42, ""),
            "com.example.app",
            None
        )
        .is_err(),
        "wrong manifest package must fail"
    );
}
#[test]
fn split_manifest_is_not_a_standalone_base_apk() {
    let split = compiled_apk("com.example.app", 42, r#"split="config.en""#);
    assert!(
        check(&split, "com.example.app", None).is_err(),
        "split APK must fail even when API claims full APK"
    );
}

#[test]
fn manifest_version_code_matches_api_when_supplied() {
    assert!(
        check(&base_apk(), "com.example.app", Some(43)).is_err(),
        "wrong manifest versionCode must fail"
    );
}

pub(crate) fn duplicate_manifest() -> Vec<u8> {
    let xml = manifest(&base_apk());
    let mut apk = repack(&xml, &[("AndroidManifest.xm_", &xml)]);
    let positions: Vec<_> = apk
        .windows(19)
        .enumerate()
        .filter_map(|(i, b)| (b == b"AndroidManifest.xm_").then_some(i))
        .collect();
    for i in positions {
        apk[i + 18] = b'l';
    }
    apk
}

#[test]
fn duplicate_manifest_is_rejected_before_zip_name_deduplication() {
    assert!(
        check(&duplicate_manifest(), "com.example.app", None).is_err(),
        "duplicate central-directory manifest entries must fail"
    );
}

#[test]
fn unsafe_archive_member_paths_are_rejected_without_extraction() {
    for path in [
        "../escape",
        "/absolute",
        "a/../escape",
        "a\\b",
        "a//b",
        "C:/escape",
    ] {
        let apk = repack(&manifest(&base_apk()), &[(path, b"data")]);
        assert!(
            check(&apk, "com.example.app", None).is_err(),
            "accepted unsafe member {path}"
        );
    }
}

#[test]
fn malicious_zip_metadata_is_budgeted_before_zip_parser_allocation() {
    let apk = base_apk();
    let eocd = apk.windows(4).rposition(|b| b == b"PK\x05\x06").unwrap();
    let mut many_entries = apk.clone();
    many_entries[eocd + 8..eocd + 12].copy_from_slice(&[0xff; 4]);
    assert_eq!(
        check(&many_entries, "com.example.app", None),
        Err("APK ZIP directory limit")
    );
    let mut huge_directory = apk.clone();
    huge_directory[eocd + 12..eocd + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        check(&huge_directory, "com.example.app", None),
        Err("APK ZIP directory limit")
    );
    let mut expansion = repack(&manifest(&apk), &[("assets/payload", b"a")]);
    let central: Vec<_> = expansion
        .windows(4)
        .enumerate()
        .filter_map(|(i, b)| (b == b"PK\x01\x02").then_some(i))
        .collect();
    expansion[central[1] + 24..central[1] + 28]
        .copy_from_slice(&(2u32 * 1024 * 1024 * 1024 + 1).to_le_bytes());
    assert_eq!(
        check(&expansion, "com.example.app", None),
        Err("APK ZIP expansion/ratio limit")
    );
}

#[test]
fn crc_is_checked_for_every_member_not_only_the_manifest() {
    let mut apk = repack(&manifest(&base_apk()), &[("assets/data", b"original")]);
    let offset = apk.windows(8).position(|b| b == b"original").unwrap();
    apk[offset] ^= 1;
    assert_eq!(
        check(&apk, "com.example.app", None),
        Err("APK ZIP CRC/read failure")
    );
}

#[test]
fn manifest_requires_application_element() {
    let mut xml = manifest(&base_apk());
    // Drop the application's start/end nodes, retaining well-formed binary XML.
    let mut position = 8;
    let mut starts = 0;
    let mut ranges = Vec::new();
    while position < xml.len() {
        let kind = u16_at(&xml, position).unwrap();
        let length = u32_at(&xml, position + 4).unwrap() as usize;
        if kind == 0x102 {
            starts += 1;
        }
        if starts == 3 && matches!(kind, 0x102 | 0x103) {
            ranges.push(position..position + length);
        }
        position += length;
        if ranges.len() == 2 {
            break;
        }
    }
    assert_eq!(ranges.len(), 2);
    for range in ranges.into_iter().rev() {
        xml.drain(range);
    }
    let size = xml.len() as u32;
    xml[4..8].copy_from_slice(&size.to_le_bytes());
    assert!(
        check(&repack(&xml, &[]), "com.example.app", None).is_err(),
        "manifest-only container is not a base APK"
    );
}

#[test]
fn xml_decoder_rejects_truncation_and_never_panics_on_malformed_chunks() {
    let xml = manifest(&base_apk());
    for length in 0..xml.len() {
        assert!(
            validate_manifest(&xml[..length], "com.example.app", None, Instant::now()).is_err()
        );
    }
    for offset in (8..xml.len()).step_by(4) {
        let mut altered = xml.clone();
        altered[offset..offset + 4.min(xml.len() - offset)].fill(0xff);
        let _ = validate_manifest(&altered, "com.example.app", None, Instant::now());
    }
}

#[test]
fn android_version_attribute_resource_id_cannot_disagree_with_its_name() {
    let mut xml = manifest(&base_apk());
    let mut pos = 8;
    while u16_at(&xml, pos).unwrap() != 0x180 {
        pos += u32_at(&xml, pos + 4).unwrap() as usize;
    }
    let end = pos + u32_at(&xml, pos + 4).unwrap() as usize;
    let version = (pos + 8..end)
        .step_by(4)
        .find(|i| u32_at(&xml, *i).unwrap() == 0x0101021b)
        .unwrap();
    xml[version..version + 4].copy_from_slice(&0x0101021cu32.to_le_bytes());
    assert!(
        check(&repack(&xml, &[]), "com.example.app", Some(42)).is_err(),
        "Android resolves attribute resource IDs, not only their text names"
    );
}

#[test]
fn package_raw_value_cannot_disagree_with_typed_value() {
    let mut xml = manifest(&base_apk());
    let pool_size = u32_at(&xml, 12).unwrap() as usize;
    let strings = Strings::new(&xml[8..8 + pool_size]).unwrap();
    let mut pos = 8 + pool_size;
    while u16_at(&xml, pos).unwrap() != 0x102 {
        pos += u32_at(&xml, pos + 4).unwrap() as usize;
    }
    let start = pos + 16 + u16_at(&xml, pos + 24).unwrap() as usize;
    let count = u16_at(&xml, pos + 28).unwrap() as usize;
    let offset = (0..count)
        .map(|i| start + i * 20)
        .find(|i| strings.get(u32_at(&xml, i + 4).unwrap()).unwrap() == "package")
        .unwrap();
    let key = u32_at(&xml, offset + 4).unwrap();
    xml[offset + 8..offset + 12].copy_from_slice(&key.to_le_bytes());
    assert!(check(&repack(&xml, &[]), "com.example.app", None).is_err());
}

#[test]
fn manifest_size_and_member_ratio_are_checked_before_decompression() {
    let oversized = repack(&vec![0; MAX_MANIFEST + 1], &[]);
    assert_eq!(
        check(&oversized, "com.example.app", None),
        Err("APK manifest size limit")
    );
    let mut ratio = repack(&manifest(&base_apk()), &[("assets/data", b"a")]);
    let central = ratio.windows(4).rposition(|b| b == b"PK\x01\x02").unwrap();
    ratio[central + 10..central + 12].copy_from_slice(&8u16.to_le_bytes());
    ratio[central + 24..central + 28].copy_from_slice(&1001u32.to_le_bytes());
    assert_eq!(
        check(&ratio, "com.example.app", None),
        Err("APK ZIP expansion/ratio limit")
    );
}

#[test]
fn encrypted_unsupported_and_inconsistent_local_headers_are_rejected() {
    let apk = base_apk();
    let central = apk.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
    for (offset, replacement) in [(central + 8, 1u16), (central + 10, 12), (6, 1)] {
        let mut changed = apk.clone();
        changed[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
        assert!(check(&changed, "com.example.app", None).is_err());
    }
}

#[test]
fn validation_deadlines_are_enforced_without_sleeping() {
    let old = Instant::now() - DEADLINE - Duration::from_secs(1);
    let xml = manifest(&base_apk());
    assert_eq!(
        validate_manifest(&xml, "com.example.app", None, old),
        Err("APK validation timeout")
    );
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&base_apk()).unwrap();
    assert_eq!(
        guard_directory(&mut file, old),
        Err("APK validation timeout")
    );
}

#[test]
fn string_pool_decoding_has_a_cumulative_budget() {
    let xml = manifest(&base_apk());
    let size = u32_at(&xml, 12).unwrap() as usize;
    let strings = Strings::new(&xml[8..8 + size]).unwrap();
    assert!(strings.get(0).is_ok());
    strings.decoded.set(16 * 1024 * 1024);
    assert_eq!(strings.get(0), Err("APK manifest string budget"));
}

#[test]
fn synthetic_signed_base_apk_with_signing_block_is_accepted_without_trust_claim() {
    let directory = tempfile::tempdir().unwrap();
    let unsigned = directory.path().join("unsigned.apk");
    let signed = directory.path().join("signed.apk");
    let keystore = directory.path().join("synthetic.jks");
    std::fs::write(&unsigned, base_apk()).unwrap();
    let generated = std::process::Command::new("keytool")
        .args([
            "-genkeypair",
            "-alias",
            "fixture",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "1",
            "-dname",
            "CN=Offline APK Test",
            "-storepass",
            "fixturepass",
            "-keypass",
            "fixturepass",
            "-keystore",
        ])
        .arg(&keystore)
        .output()
        .expect("signed synthetic fixture requires keytool");
    assert!(
        generated.status.success(),
        "keytool: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let signing = std::process::Command::new("apksigner")
        .args(["sign", "--ks"])
        .arg(&keystore)
        .args([
            "--ks-pass",
            "pass:fixturepass",
            "--key-pass",
            "pass:fixturepass",
            "--out",
        ])
        .arg(&signed)
        .arg(&unsigned)
        .output()
        .expect("signed synthetic fixture requires apksigner");
    assert!(
        signing.status.success(),
        "apksigner sign: {}",
        String::from_utf8_lossy(&signing.stderr)
    );
    let verification = std::process::Command::new("apksigner")
        .args(["verify", "--verbose"])
        .arg(&signed)
        .output()
        .unwrap();
    assert!(
        verification.status.success(),
        "synthetic fixture signature: {}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert!(String::from_utf8_lossy(&verification.stdout)
        .contains("Verified using v2 scheme (APK Signature Scheme v2): true"));
    assert_eq!(
        check(
            &std::fs::read(&signed).unwrap(),
            "com.example.app",
            Some(42)
        ),
        Ok(())
    );
    // This locally generated signer is NOT a trusted Huawei/publisher identity.
}
