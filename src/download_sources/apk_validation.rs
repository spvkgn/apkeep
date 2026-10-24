//! Bounded, in-process APK structure checks; not publisher authentication.
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(60);

pub(super) fn validate(
    file: &mut std::fs::File,
    package: &str,
    version: Option<u64>,
) -> Result<(), &'static str> {
    let started = Instant::now();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot read APK")?;
    let expected_entries = guard_directory(file, started)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot read APK")?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| "invalid APK ZIP")?;
    if archive.len() != expected_entries {
        return Err("inconsistent APK ZIP directory");
    }
    let mut total = 0u64;
    let mut manifest = None;
    let mut buffer = [0u8; 32 * 1024];
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|_| "invalid APK ZIP member")?;
        let is_manifest = member.name_raw() == b"AndroidManifest.xml";
        let mut bytes = Vec::new();
        let mut size = 0u64;
        loop {
            if started.elapsed() > DEADLINE {
                return Err("APK validation timeout");
            }
            let count = member
                .read(&mut buffer)
                .map_err(|_| "APK ZIP CRC/read failure")?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or("APK expansion limit")?;
            size += count as u64;
            if total > MAX_EXPANDED || size > member.size() {
                return Err("APK expansion limit");
            }
            if is_manifest {
                if bytes.len() + count > MAX_MANIFEST {
                    return Err("APK manifest size limit");
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        if size != member.size() {
            return Err("APK ZIP size mismatch");
        }
        if is_manifest && manifest.replace(bytes).is_some() {
            return Err("duplicate APK manifest");
        }
    }
    validate_manifest(
        &manifest.ok_or("missing APK manifest")?,
        package,
        version,
        started,
    )
}

#[cfg(test)]
#[path = "apk_validation_tests.rs"]
pub(super) mod tests;

const INVALID_XML: &str = "invalid binary APK manifest";
const NONE: u32 = u32::MAX;
const ANDROID: &str = "http://schemas.android.com/apk/res/android";
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    let raw = bytes
        .get(offset..offset.checked_add(2).ok_or(INVALID_XML)?)
        .ok_or(INVALID_XML)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let raw = bytes
        .get(offset..offset.checked_add(4).ok_or(INVALID_XML)?)
        .ok_or(INVALID_XML)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

struct Strings<'a> {
    bytes: &'a [u8],
    count: usize,
    start: usize,
    end: usize,
    utf8: bool,
    decoded: std::cell::Cell<usize>,
}
impl<'a> Strings<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let count = u32_at(bytes, 8)? as usize;
        let styles = u32_at(bytes, 12)? as usize;
        let start = u32_at(bytes, 20)? as usize;
        let styles_start = u32_at(bytes, 24)? as usize;
        let end = if styles_start == 0 {
            bytes.len()
        } else {
            styles_start
        };
        if u16_at(bytes, 2)? != 28
            || count > 131072
            || styles > count
            || 28 + (count + styles) * 4 > start
            || start > end
            || end > bytes.len()
        {
            return Err(INVALID_XML);
        }
        Ok(Self {
            bytes,
            count,
            start,
            end,
            utf8: u32_at(bytes, 16)? & 0x100 != 0,
            decoded: std::cell::Cell::new(0),
        })
    }
    fn charge(&self, bytes: usize) -> Result<(), &'static str> {
        let total = self.decoded.get().checked_add(bytes).ok_or(INVALID_XML)?;
        if total > 16 * 1024 * 1024 {
            return Err("APK manifest string budget");
        }
        self.decoded.set(total);
        Ok(())
    }
    fn get(&self, index: u32) -> Result<String, &'static str> {
        if index as usize >= self.count {
            return Err(INVALID_XML);
        }
        let offset = self
            .start
            .checked_add(u32_at(self.bytes, 28 + index as usize * 4)? as usize)
            .ok_or(INVALID_XML)?;
        let bytes = self.bytes.get(offset..self.end).ok_or(INVALID_XML)?;
        if self.utf8 {
            fn length(bytes: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
                let first = *bytes.get(*pos).ok_or(INVALID_XML)?;
                *pos += 1;
                Ok(if first & 0x80 != 0 {
                    let second = *bytes.get(*pos).ok_or(INVALID_XML)?;
                    *pos += 1;
                    ((first as usize & 0x7f) << 8) | second as usize
                } else {
                    first as usize
                })
            }
            let mut pos = 0;
            let characters = length(bytes, &mut pos)?;
            let len = length(bytes, &mut pos)?;
            if len > 65536 || bytes.get(pos + len) != Some(&0) {
                return Err(INVALID_XML);
            }
            self.charge(len)?;
            let text = std::str::from_utf8(bytes.get(pos..pos + len).ok_or(INVALID_XML)?)
                .map_err(|_| INVALID_XML)?;
            if text.encode_utf16().count() != characters || text.contains('\0') {
                return Err(INVALID_XML);
            }
            Ok(text.to_owned())
        } else {
            let first = u16_at(bytes, 0)?;
            let (len, pos) = if first & 0x8000 != 0 {
                (
                    (((first as usize & 0x7fff) << 16) | u16_at(bytes, 2)? as usize),
                    4,
                )
            } else {
                (first as usize, 2)
            };
            if len > 32768 || u16_at(bytes, pos + len * 2)? != 0 {
                return Err(INVALID_XML);
            }
            self.charge(len * 4)?;
            let words = (0..len)
                .map(|i| u16_at(bytes, pos + i * 2))
                .collect::<Result<Vec<_>, _>>()?;
            let text = String::from_utf16(&words).map_err(|_| INVALID_XML)?;
            if text.contains('\0') {
                return Err(INVALID_XML);
            }
            Ok(text)
        }
    }
}

fn validate_manifest(
    bytes: &[u8],
    package: &str,
    version: Option<u64>,
    started: Instant,
) -> Result<(), &'static str> {
    if u16_at(bytes, 0)? != 3 || u16_at(bytes, 2)? != 8 || u32_at(bytes, 4)? as usize != bytes.len()
    {
        return Err(INVALID_XML);
    }
    let mut pos = 8;
    let mut pool = None;
    let mut stack = Vec::new();
    let mut root = false;
    let mut manifest_package = None;
    let mut version_code = None;
    let mut version_major = 0u32;
    let mut applications = 0;
    let mut resource_map: Option<&[u8]> = None;
    while pos < bytes.len() {
        if started.elapsed() > DEADLINE {
            return Err("APK validation timeout");
        }
        let kind = u16_at(bytes, pos)?;
        let header = u16_at(bytes, pos + 2)? as usize;
        let size = u32_at(bytes, pos + 4)? as usize;
        if header < 8 || size < header || size & 3 != 0 {
            return Err(INVALID_XML);
        }
        let chunk = bytes
            .get(pos..pos.checked_add(size).ok_or(INVALID_XML)?)
            .ok_or(INVALID_XML)?;
        match kind {
            1 if pool.is_none() && !root => pool = Some(Strings::new(chunk)?),
            0x180 if !root && header == 8 && pool.is_some() && resource_map.is_none() => {
                if (size - 8) / 4 > pool.as_ref().ok_or(INVALID_XML)?.count {
                    return Err(INVALID_XML);
                }
                resource_map = Some(&chunk[8..]);
            }
            0x100 | 0x101 if header == 16 && size == 24 && pool.is_some() => {
                let strings = pool.as_ref().ok_or(INVALID_XML)?;
                strings.get(u32_at(chunk, 16)?)?;
                strings.get(u32_at(chunk, 20)?)?;
            }
            0x102 if header == 16 && size >= 36 => {
                let strings = pool.as_ref().ok_or(INVALID_XML)?;
                let namespace = u32_at(chunk, 16)?;
                let name_index = u32_at(chunk, 20)?;
                let name = strings.get(name_index)?;
                if name == "uses-split" {
                    return Err("unsupported split APK manifest");
                }
                if name == "application" {
                    if stack.len() != 1 || namespace != NONE {
                        return Err(INVALID_XML);
                    }
                    applications += 1;
                }
                let is_root = stack.is_empty();
                if is_root {
                    if root || name != "manifest" || namespace != NONE {
                        return Err(INVALID_XML);
                    }
                    root = true;
                }
                if stack.len() >= 256 {
                    return Err(INVALID_XML);
                }
                stack.push((namespace, name_index));
                let offset = 16 + u16_at(chunk, 24)? as usize;
                let width = u16_at(chunk, 26)? as usize;
                let count = u16_at(chunk, 28)? as usize;
                if offset < 36 || width != 20 || offset + count * width > size {
                    return Err(INVALID_XML);
                }
                let mut attributes = std::collections::HashSet::new();
                let mut resource_ids = std::collections::HashSet::new();
                for index in 0..count {
                    let attr = &chunk[offset + index * width..offset + (index + 1) * width];
                    let ns = u32_at(attr, 0)?;
                    let key_index = u32_at(attr, 4)?;
                    let key = strings.get(key_index)?;
                    let resource_id = resource_map
                        .and_then(|map| u32_at(map, key_index as usize * 4).ok())
                        .unwrap_or(0);
                    let namespace = if ns == NONE {
                        String::new()
                    } else {
                        strings.get(ns)?
                    };
                    if resource_id != 0 && !resource_ids.insert(resource_id) {
                        return Err(INVALID_XML);
                    }
                    if (key == "versionCode" && namespace == ANDROID && resource_id != 0x0101021b)
                        || (resource_id == 0x0101021b
                            && (key != "versionCode" || namespace != ANDROID))
                        || (key == "package" && namespace.is_empty() && resource_id != 0)
                    {
                        return Err(INVALID_XML);
                    }
                    if !attributes.insert((namespace.clone(), key.clone()))
                        || u16_at(attr, 12)? != 8
                        || attr[14] != 0
                    {
                        return Err(INVALID_XML);
                    }
                    let data = u32_at(attr, 16)?;
                    let raw = u32_at(attr, 8)?;
                    if attr[15] == 3 && raw != NONE && strings.get(raw)? != strings.get(data)? {
                        return Err(INVALID_XML);
                    }
                    if (is_root
                        && namespace.is_empty()
                        && matches!(key.as_str(), "split" | "configForSplit"))
                        || (namespace == ANDROID
                            && matches!(
                                key.as_str(),
                                "isFeatureSplit"
                                    | "isSplitRequired"
                                    | "configForSplit"
                                    | "splitTypes"
                                    | "requiredSplitTypes"
                            )
                            && !(attr[15] == 0x12 && data == 0))
                    {
                        return Err("unsupported split APK manifest");
                    }
                    if is_root && namespace.is_empty() && key == "package" {
                        if attr[15] != 3 {
                            return Err(INVALID_XML);
                        }
                        manifest_package = Some(strings.get(data)?);
                    }
                    if is_root
                        && namespace == ANDROID
                        && (key == "versionCode" || key == "versionCodeMajor")
                    {
                        if !matches!(attr[15], 0x10 | 0x11) {
                            return Err(INVALID_XML);
                        }
                        if raw != NONE {
                            let text = strings.get(raw)?;
                            let number = match text.strip_prefix("0x") {
                                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                                None => text.parse::<u32>().ok(),
                            };
                            if number != Some(data) {
                                return Err(INVALID_XML);
                            }
                        }
                        if key == "versionCode" {
                            version_code = Some(data);
                        } else {
                            version_major = data;
                        }
                    }
                }
            }
            // Binary XML may carry text/whitespace nodes inside elements.
            // They do not alter identity attributes, but their string/value
            // references and complete fixed layout must still be valid.
            0x104 if header == 16 && size == 28 && !stack.is_empty() => {
                let strings = pool.as_ref().ok_or(INVALID_XML)?;
                strings.get(u32_at(chunk, 16)?)?;
                let value_size = u16_at(chunk, 20)?;
                let data_type = chunk[23];
                let data = u32_at(chunk, 24)?;
                if chunk[22] != 0
                    || (value_size == 0 && (data_type != 0 || data != 0))
                    || !matches!(value_size, 0 | 8)
                {
                    return Err(INVALID_XML);
                }
                if data_type == 3 {
                    strings.get(data)?;
                }
            }
            0x103 if header == 16 && size == 24 => {
                if stack.pop() != Some((u32_at(chunk, 16)?, u32_at(chunk, 20)?)) {
                    return Err(INVALID_XML);
                }
            }
            _ => return Err(INVALID_XML),
        }
        pos += size;
    }
    if !root || !stack.is_empty() || applications != 1 {
        return Err(INVALID_XML);
    }
    if manifest_package.as_deref() != Some(package) {
        return Err("APK manifest package mismatch");
    }
    let low = version_code
        .filter(|v| *v > 0)
        .ok_or("missing/invalid APK manifest versionCode")?;
    let actual = ((version_major as u64) << 32) | low as u64;
    if actual > i64::MAX as u64 || version.is_some_and(|expected| expected != actual) {
        return Err("APK manifest versionCode mismatch");
    }
    Ok(())
}

const INVALID_ZIP: &str = "invalid APK ZIP directory";
const MAX_ENTRIES: usize = 32768;
const MAX_DIRECTORY: usize = 16 * 1024 * 1024;

// This runs BEFORE ZipArchive::new: ZIP's declared counts/sizes must not choose
// allocation sizes. ZIP64/multi-disk/overlapping/encrypted/non-Android methods
// are intentionally unsupported, rather than passed to a general decoder.
fn guard_directory(file: &mut std::fs::File, started: Instant) -> Result<usize, &'static str> {
    let length = file.metadata().map_err(|_| INVALID_ZIP)?.len();
    if !(22..=MAX_EXPANDED).contains(&length) {
        return Err(INVALID_ZIP);
    }
    let tail_length = length.min(65557) as usize;
    file.seek(SeekFrom::End(-(tail_length as i64)))
        .map_err(|_| INVALID_ZIP)?;
    let mut tail = vec![0u8; tail_length];
    file.read_exact(&mut tail).map_err(|_| INVALID_ZIP)?;
    let end = tail
        .windows(4)
        .rposition(|b| b == b"PK\x05\x06")
        .ok_or(INVALID_ZIP)?;
    let eocd = tail.get(end..).ok_or(INVALID_ZIP)?;
    if eocd.len() < 22
        || 22 + u16_at(eocd, 20)? as usize != eocd.len()
        || u16_at(eocd, 4)? != 0
        || u16_at(eocd, 6)? != 0
        || u16_at(eocd, 8)? != u16_at(eocd, 10)?
    {
        return Err(INVALID_ZIP);
    }
    let count = u16_at(eocd, 10)? as usize;
    let size = u32_at(eocd, 12)? as usize;
    let offset = u32_at(eocd, 16)? as u64;
    if count == 0
        || count > MAX_ENTRIES
        || size > MAX_DIRECTORY
        || size < count * 46
        || offset == u32::MAX as u64
    {
        return Err("APK ZIP directory limit");
    }
    let end_offset = length - tail_length as u64 + end as u64;
    if offset.checked_add(size as u64) != Some(end_offset)
        || (end >= 20 && &tail[end - 20..end - 16] == b"PK\x06\x07")
    {
        return Err(INVALID_ZIP);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| INVALID_ZIP)?;
    let mut directory = vec![0u8; size];
    file.read_exact(&mut directory).map_err(|_| INVALID_ZIP)?;
    let mut position = 0usize;
    let mut expanded = 0u64;
    let mut names = std::collections::HashSet::new();
    let mut ranges = Vec::with_capacity(count);
    let mut manifests = 0;
    for _ in 0..count {
        if started.elapsed() > DEADLINE {
            return Err("APK validation timeout");
        }
        let header = directory.get(position..position + 46).ok_or(INVALID_ZIP)?;
        if &header[..4] != b"PK\x01\x02" {
            return Err(INVALID_ZIP);
        }
        let flags = u16_at(header, 8)?;
        let method = u16_at(header, 10)?;
        if flags & !0x080e != 0 || !matches!(method, 0 | 8) || u16_at(header, 34)? != 0 {
            return Err("unsupported APK ZIP member");
        }
        let compressed = u32_at(header, 20)? as u64;
        let uncompressed = u32_at(header, 24)? as u64;
        expanded = expanded
            .checked_add(uncompressed)
            .ok_or("APK ZIP expansion/ratio limit")?;
        if expanded > MAX_EXPANDED
            || uncompressed > compressed.saturating_mul(1000)
            || (method == 0 && uncompressed != compressed)
        {
            return Err("APK ZIP expansion/ratio limit");
        }
        let name_size = u16_at(header, 28)? as usize;
        let extra_size = u16_at(header, 30)? as usize;
        let comment_size = u16_at(header, 32)? as usize;
        if name_size == 0 || name_size > 4096 {
            return Err("unsafe APK ZIP member path");
        }
        let name_end = position + 46 + name_size;
        let entry_end = name_end + extra_size + comment_size;
        let name = directory.get(position + 46..name_end).ok_or(INVALID_ZIP)?;
        let text = std::str::from_utf8(name).map_err(|_| "unsafe APK ZIP member path")?;
        if text.contains(['\\', '\0', ':'])
            || text.starts_with('/')
            || text
                .trim_end_matches('/')
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("unsafe APK ZIP member path");
        }
        if !names.insert(name) {
            return Err("duplicate APK ZIP member");
        }
        if name == b"AndroidManifest.xml" {
            manifests += 1;
            if uncompressed > MAX_MANIFEST as u64 {
                return Err("APK manifest size limit");
            }
        }
        let mode = (u32_at(header, 38)? >> 16) & 0o170000;
        if !matches!(mode, 0 | 0o100000 | 0o040000) {
            return Err("unsupported APK ZIP member type");
        }
        check_extra(
            directory
                .get(name_end..name_end + extra_size)
                .ok_or(INVALID_ZIP)?,
            false,
        )?;
        if entry_end > directory.len() {
            return Err(INVALID_ZIP);
        }
        let local_offset = u32_at(header, 42)? as u64;
        if local_offset
            .checked_add(30)
            .filter(|end| *end <= offset)
            .is_none()
        {
            return Err(INVALID_ZIP);
        }
        file.seek(SeekFrom::Start(local_offset))
            .map_err(|_| INVALID_ZIP)?;
        let mut local = [0u8; 30];
        file.read_exact(&mut local).map_err(|_| INVALID_ZIP)?;
        if &local[..4] != b"PK\x03\x04"
            || u16_at(&local, 6)? != flags
            || u16_at(&local, 8)? != method
            || u16_at(&local, 26)? as usize != name_size
        {
            return Err(INVALID_ZIP);
        }
        if flags & 8 == 0
            && (u32_at(&local, 14)? != u32_at(header, 16)?
                || u32_at(&local, 18)? as u64 != compressed
                || u32_at(&local, 22)? as u64 != uncompressed)
        {
            return Err(INVALID_ZIP);
        }
        let local_extra_size = u16_at(&local, 28)? as usize;
        let data_start = local_offset + 30 + name_size as u64 + local_extra_size as u64;
        let data_end = data_start.checked_add(compressed).ok_or(INVALID_ZIP)?;
        if data_end > offset {
            return Err(INVALID_ZIP);
        }
        let mut local_name_extra = vec![0u8; name_size + local_extra_size];
        file.read_exact(&mut local_name_extra)
            .map_err(|_| INVALID_ZIP)?;
        if &local_name_extra[..name_size] != name {
            return Err(INVALID_ZIP);
        }
        check_extra(&local_name_extra[name_size..], true)?;
        ranges.push((local_offset, data_end));
        position = entry_end;
    }
    ranges.sort_unstable();
    if position != size
        || manifests != 1
        || ranges[0].0 != 0
        || ranges.windows(2).any(|r| r[0].1 > r[1].0)
    {
        return Err(INVALID_ZIP);
    }
    Ok(count)
}

fn check_extra(bytes: &[u8], local: bool) -> Result<(), &'static str> {
    let mut pos = 0;
    while pos < bytes.len() {
        let remaining = &bytes[pos..];
        if remaining.len() < 4 {
            // Legacy Android zipalign appends zero bytes to LOCAL extras for
            // 4-byte alignment. Accept only a 1..=3-byte tail at a TLV boundary:
            // it cannot contain a record header. Central extras stay strict;
            // complete headers and their declared lengths are never skipped.
            return if local && remaining.iter().all(|byte| *byte == 0) {
                Ok(())
            } else {
                Err(INVALID_ZIP)
            };
        }
        let kind = u16_at(bytes, pos)?;
        let size = u16_at(bytes, pos + 2)? as usize;
        if kind == 1 || kind == 0x9901 {
            return Err("unsupported APK ZIP extra field");
        }
        pos += 4 + size;
        if pos > bytes.len() {
            return Err(INVALID_ZIP);
        }
    }
    Ok(())
}
