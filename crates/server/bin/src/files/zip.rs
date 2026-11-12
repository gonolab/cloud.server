//! Streaming ZIP archives for "Download as .zip" in the web file UI.
//!
//! - Entries are **stored**, not compressed: the archive is as large as its files and costs no
//!   CPU, and nothing has to be buffered. Most of what people keep (photos, videos, office
//!   documents, archives) does not compress anyway.
//! - Each file's CRC-32 and size follow its data in a **data descriptor** (general purpose
//!   bit 3), so a file is read exactly once, in order, while it is sent.
//! - **ZIP64** records are added where sizes, offsets or the entry count exceed the classic
//!   limits (4 GiB, 65,535 entries), and names are UTF-8 (bit 11). Modification times are
//!   stored as DOS times (UTC) and as UNIX times in the extended timestamp field.
//!
//! [`ZipWriter`] only produces the bytes around the file contents; the caller sends the file
//! data in between and reports its CRC and length.

use std::io;

/// Larger sizes and offsets need ZIP64 fields.
const MAX_32: u64 = 0xFFFF_FFFF;

/// Extra field: ZIP64 extended information.
const ZIP64_EXTRA: u16 = 0x0001;
/// Extra field: extended timestamp (UNIX modification time).
const TIME_EXTRA: u16 = 0x5455;

/// Version needed to extract: 2.0 for plain entries, 4.5 for ZIP64.
const VERSION_PLAIN: u16 = 20;
const VERSION_ZIP64: u16 = 45;
/// Version made by: UNIX (3), specification 4.5.
const MADE_BY: u16 = (3 << 8) | 45;

/// General purpose flags: sizes in a data descriptor (bit 3), UTF-8 names (bit 11).
const FLAGS_FILE: u16 = 0x0808;
const FLAGS_DIR: u16 = 0x0800;

/// One entry, as the central directory needs it.
#[derive(Debug)]
struct Entry {
    name: Vec<u8>,
    is_dir: bool,
    /// ZIP64 fields in the local header and the data descriptor.
    zip64: bool,
    crc: u32,
    size: u64,
    offset: u64,
    dos_time: u16,
    dos_date: u16,
    mtime: u32,
}

/// Builds an archive entry by entry (see the module documentation).
#[derive(Debug, Default)]
pub struct ZipWriter {
    offset: u64,
    entries: Vec<Entry>,
    /// The file whose data is being sent.
    open: Option<Entry>,
}

fn u16le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A 32-bit field, or the ZIP64 marker for larger values.
fn clamp32(value: u64) -> u32 {
    u32::try_from(value)
        .ok()
        .filter(|v| u64::from(*v) < MAX_32)
        .unwrap_or(u32::MAX)
}

/// The DOS time and date of UNIX seconds (UTC); times before 1980 become 1980-01-01.
fn dos_time(unix: i64) -> (u16, u16) {
    const DOS_EPOCH: i64 = 315_532_800; // 1980-01-01T00:00:00Z
    let unix = unix.max(DOS_EPOCH);
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let year = (year - 1980).clamp(0, 127);
    let time = ((secs / 3600) << 11) | ((secs % 3600 / 60) << 5) | ((secs % 60) / 2);
    let date = (year << 9) | (month << 5) | day;
    (
        u16::try_from(time).unwrap_or(0),
        u16::try_from(date).unwrap_or(0x21),
    )
}

impl ZipWriter {
    /// An empty archive.
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&self, name: &str, is_dir: bool, mtime: i64, zip64: bool) -> Entry {
        let (dos_time, dos_date) = dos_time(mtime);
        Entry {
            name: name.as_bytes().to_vec(),
            is_dir,
            zip64,
            crc: 0,
            size: 0,
            offset: self.offset,
            dos_time,
            dos_date,
            mtime: u32::try_from(mtime.max(0)).unwrap_or(u32::MAX),
        }
    }

    fn local_header(entry: &Entry) -> Vec<u8> {
        let mut extra = Vec::new();
        if entry.zip64 {
            u16le(&mut extra, ZIP64_EXTRA);
            u16le(&mut extra, 16);
            u64le(&mut extra, 0);
            u64le(&mut extra, 0);
        }
        u16le(&mut extra, TIME_EXTRA);
        u16le(&mut extra, 5);
        extra.push(1);
        u32le(&mut extra, entry.mtime);

        let mut out = Vec::with_capacity(30 + entry.name.len() + extra.len());
        u32le(&mut out, 0x0403_4b50);
        u16le(
            &mut out,
            if entry.zip64 {
                VERSION_ZIP64
            } else {
                VERSION_PLAIN
            },
        );
        u16le(&mut out, if entry.is_dir { FLAGS_DIR } else { FLAGS_FILE });
        u16le(&mut out, 0); // stored
        u16le(&mut out, entry.dos_time);
        u16le(&mut out, entry.dos_date);
        u32le(&mut out, 0); // CRC-32: in the data descriptor
        let size = if entry.zip64 { u32::MAX } else { 0 };
        u32le(&mut out, size);
        u32le(&mut out, size);
        u16le(
            &mut out,
            u16::try_from(entry.name.len()).unwrap_or(u16::MAX),
        );
        u16le(&mut out, u16::try_from(extra.len()).unwrap_or(u16::MAX));
        out.extend_from_slice(&entry.name);
        out.extend_from_slice(&extra);
        out
    }

    /// The local header of a directory (`name` ends with `/`).
    pub fn dir(&mut self, name: &str, mtime: i64) -> Vec<u8> {
        let entry = self.entry(name, true, mtime, false);
        let header = Self::local_header(&entry);
        self.offset += header.len() as u64;
        self.entries.push(entry);
        header
    }

    /// The local header of a file whose data follows; `expected` is its size as far as it is
    /// known, which decides whether its sizes need ZIP64 fields.
    pub fn begin_file(&mut self, name: &str, mtime: i64, expected: u64) -> Vec<u8> {
        // Leave room for a file that grows a little while it is read.
        let zip64 = expected >= MAX_32 - (1 << 24);
        let entry = self.entry(name, false, mtime, zip64);
        let header = Self::local_header(&entry);
        self.offset += header.len() as u64;
        self.open = Some(entry);
        header
    }

    /// The data descriptor after the data of the file started by [`begin_file`]: its CRC-32
    /// and length as sent. Fails when the file grew past 4 GiB without ZIP64 fields.
    ///
    /// [`begin_file`]: Self::begin_file
    pub fn end_file(&mut self, crc: u32, size: u64) -> io::Result<Vec<u8>> {
        let mut entry = self
            .open
            .take()
            .ok_or_else(|| io::Error::other("no file entry is open"))?;
        if !entry.zip64 && size >= MAX_32 {
            return Err(io::Error::other(
                "a file grew past 4 GiB while it was archived",
            ));
        }
        entry.crc = crc;
        entry.size = size;
        let mut out = Vec::with_capacity(24);
        u32le(&mut out, 0x0807_4b50);
        u32le(&mut out, crc);
        if entry.zip64 {
            u64le(&mut out, size);
            u64le(&mut out, size);
        } else {
            u32le(&mut out, clamp32(size));
            u32le(&mut out, clamp32(size));
        }
        self.offset += size + out.len() as u64;
        self.entries.push(entry);
        Ok(out)
    }

    /// The central directory and the end records.
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();
        let start = self.offset;
        for entry in &self.entries {
            let big_size = entry.size >= MAX_32;
            let big_offset = entry.offset >= MAX_32;
            let mut extra = Vec::new();
            if big_size || big_offset {
                let mut fields = Vec::new();
                if big_size {
                    u64le(&mut fields, entry.size);
                    u64le(&mut fields, entry.size);
                }
                if big_offset {
                    u64le(&mut fields, entry.offset);
                }
                u16le(&mut extra, ZIP64_EXTRA);
                u16le(&mut extra, u16::try_from(fields.len()).unwrap_or(0));
                extra.extend_from_slice(&fields);
            }
            u16le(&mut extra, TIME_EXTRA);
            u16le(&mut extra, 5);
            extra.push(1);
            u32le(&mut extra, entry.mtime);

            let needs64 = entry.zip64 || big_size || big_offset;
            u32le(&mut out, 0x0201_4b50);
            u16le(&mut out, MADE_BY);
            u16le(
                &mut out,
                if needs64 {
                    VERSION_ZIP64
                } else {
                    VERSION_PLAIN
                },
            );
            u16le(&mut out, if entry.is_dir { FLAGS_DIR } else { FLAGS_FILE });
            u16le(&mut out, 0);
            u16le(&mut out, entry.dos_time);
            u16le(&mut out, entry.dos_date);
            u32le(&mut out, entry.crc);
            u32le(&mut out, clamp32(entry.size));
            u32le(&mut out, clamp32(entry.size));
            u16le(
                &mut out,
                u16::try_from(entry.name.len()).unwrap_or(u16::MAX),
            );
            u16le(&mut out, u16::try_from(extra.len()).unwrap_or(u16::MAX));
            u16le(&mut out, 0); // comment
            u16le(&mut out, 0); // disk
            u16le(&mut out, 0); // internal attributes
            let mode: u32 = if entry.is_dir { 0o40755 } else { 0o100_644 };
            u32le(&mut out, mode << 16 | if entry.is_dir { 0x10 } else { 0 });
            u32le(&mut out, clamp32(entry.offset));
            out.extend_from_slice(&entry.name);
            out.extend_from_slice(&extra);
        }
        let size = out.len() as u64;
        let count = self.entries.len() as u64;
        if count >= 0xFFFF || start >= MAX_32 || size >= MAX_32 {
            let record = start + size;
            u32le(&mut out, 0x0606_4b50);
            u64le(&mut out, 44);
            u16le(&mut out, MADE_BY);
            u16le(&mut out, VERSION_ZIP64);
            u32le(&mut out, 0);
            u32le(&mut out, 0);
            u64le(&mut out, count);
            u64le(&mut out, count);
            u64le(&mut out, size);
            u64le(&mut out, start);
            u32le(&mut out, 0x0706_4b50);
            u32le(&mut out, 0);
            u64le(&mut out, record);
            u32le(&mut out, 1);
        }
        let count16 = u16::try_from(count)
            .ok()
            .filter(|c| *c < 0xFFFF)
            .unwrap_or(0xFFFF);
        u32le(&mut out, 0x0605_4b50);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        u16le(&mut out, count16);
        u16le(&mut out, count16);
        u32le(&mut out, clamp32(size));
        u32le(&mut out, clamp32(start));
        u16le(&mut out, 0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn u32at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    /// An archive of one folder and two files, built as the web UI streams it.
    fn archive() -> Vec<u8> {
        let mut zip = ZipWriter::new();
        let mut out = zip.dir("docs/", 1_700_000_000);
        for (name, data) in [("docs/a.txt", &b"hello"[..]), ("docs/Über b.txt", &b""[..])] {
            out.extend(zip.begin_file(name, 1_700_000_000, data.len() as u64));
            out.extend_from_slice(data);
            out.extend(
                zip.end_file(crc32fast::hash(data), data.len() as u64)
                    .unwrap(),
            );
        }
        out.extend(zip.finish());
        out
    }

    #[test]
    fn the_end_record_points_at_every_entry() {
        let bytes = archive();
        let end = bytes.len() - 22;
        assert_eq!(u32at(&bytes, end), 0x0605_4b50);
        assert_eq!(u16at(&bytes, end + 10), 3, "entries");
        let cd_size = u32at(&bytes, end + 12) as usize;
        let cd_start = u32at(&bytes, end + 16) as usize;
        assert_eq!(cd_start + cd_size, end);

        // Walk the central directory and check each local header it points at.
        let mut at = cd_start;
        let mut names = Vec::new();
        while at < end {
            assert_eq!(u32at(&bytes, at), 0x0201_4b50);
            let crc = u32at(&bytes, at + 16);
            let size = u32at(&bytes, at + 24) as usize;
            let name_len = u16at(&bytes, at + 28) as usize;
            let extra_len = u16at(&bytes, at + 30) as usize;
            let local = u32at(&bytes, at + 42) as usize;
            let name = String::from_utf8(bytes[at + 46..at + 46 + name_len].to_vec()).unwrap();
            assert_eq!(u32at(&bytes, local), 0x0403_4b50, "{name}");
            let local_name_len = u16at(&bytes, local + 26) as usize;
            let local_extra_len = u16at(&bytes, local + 28) as usize;
            let data = local + 30 + local_name_len + local_extra_len;
            assert_eq!(crc32fast::hash(&bytes[data..data + size]), crc, "{name}");
            if !name.ends_with('/') {
                assert_eq!(
                    u32at(&bytes, data + size),
                    0x0807_4b50,
                    "descriptor of {name}"
                );
            }
            names.push(name);
            at += 46 + name_len + extra_len;
        }
        assert_eq!(names, ["docs/", "docs/a.txt", "docs/Über b.txt"]);
    }

    #[test]
    fn dos_times_are_utc() {
        // 2023-11-14 22:13:20 UTC
        let (time, date) = dos_time(1_700_000_000);
        assert_eq!(date, (43 << 9) | (11 << 5) | 14);
        assert_eq!(time, (22 << 11) | (13 << 5) | 10);
        assert_eq!(dos_time(0).1, (1 << 5) | 1, "before 1980: 1980-01-01");
    }

    #[test]
    fn large_files_get_zip64_fields() {
        let mut zip = ZipWriter::new();
        let header = zip.begin_file("big.bin", 0, 5 << 30);
        assert_eq!(u16at(&header, 4), VERSION_ZIP64);
        assert_eq!(u32at(&header, 18), u32::MAX);
        let descriptor = zip.end_file(7, 5 << 30).unwrap();
        assert_eq!(descriptor.len(), 4 + 4 + 8 + 8);
        let tail = zip.finish();
        // ZIP64 end record and locator before the classic end record.
        let end = tail.len() - 22;
        assert_eq!(u32at(&tail, end - 20), 0x0706_4b50);
        assert_eq!(u32at(&tail, end - 20 - 56), 0x0606_4b50);

        let mut small = ZipWriter::new();
        small.begin_file("grew.bin", 0, 10);
        assert!(
            small.end_file(0, 5 << 30).is_err(),
            "no ZIP64 fields announced"
        );
    }
}
