use crate::error::FirmLensError;
use crate::model::{
    ExtractionCounters, IngestionLimits, IngestionOutcome, IngestionProvenance, InputKind,
    SkippedEntry,
};
use flate2::read::{DeflateDecoder, GzDecoder};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use tar::{Archive, EntryType};
use tempfile::TempDir;

/// Result of preparing an input artifact for scanning.
pub struct StagedIngestion {
    pub provenance: IngestionProvenance,
    /// Present only if the input is a directory or a valid archive that passed all checks.
    pub scan_root: Option<PathBuf>,
    /// Holds the temporary directory alive until scanning finishes.
    pub temp_workspace: Option<TempDir>,
    /// Any partial-coverage markers emitted during ingestion (e.g. `nested_archive_not_expanded`).
    pub ingestion_skips: Vec<SkippedEntry>,
}

/// Reader wrapper that enforces a strict byte cap and a cooperative wall-clock deadline.
pub struct BoundedReader<R> {
    inner: R,
    bytes_read: u64,
    max_bytes: u64,
    limit_code: &'static str,
    started_at: Instant,
    timeout: Duration,
}

impl<R: Read> BoundedReader<R> {
    pub fn new(
        inner: R,
        max_bytes: u64,
        limit_code: &'static str,
        started_at: Instant,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            bytes_read: 0,
            max_bytes,
            limit_code,
            started_at,
            timeout,
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn check_deadline(&self) -> io::Result<()> {
        if self.started_at.elapsed() > self.timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "cooperative ingestion deadline exceeded ({:?})",
                    self.timeout
                ),
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        let n = self.inner.read(buf)?;
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        if self.bytes_read > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: read {} bytes exceeding limit of {} bytes",
                    self.limit_code, self.bytes_read, self.max_bytes
                ),
            ));
        }
        Ok(n)
    }
}

/// Classify an input path based on filesystem metadata, extension, and header magic bytes.
pub fn classify_input(path: &Path) -> Result<InputKind, FirmLensError> {
    let meta = fs::symlink_metadata(path).map_err(|e| FirmLensError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    if meta.file_type().is_symlink() {
        return Err(FirmLensError::IngestionRejected {
            code: "symlink_input_rejected".to_string(),
            message: "root input path must not be a symbolic link".to_string(),
        });
    }

    if meta.is_dir() {
        return Ok(InputKind::Directory);
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut header = [0u8; 512];
    let mut f = File::open(path).map_err(|e| FirmLensError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let n = f.read(&mut header).map_err(|e| FirmLensError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    let has_gzip_magic = n >= 2 && header[0] == 0x1f && header[1] == 0x8b;
    let has_ustar_magic = n >= 262 && &header[257..262] == b"ustar";
    let has_zip_magic =
        n >= 4 && (&header[0..4] == b"PK\x03\x04" || &header[0..4] == b"PK\x05\x06");

    if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") || has_gzip_magic {
        return Ok(InputKind::TarGzArchive);
    }

    if file_name.ends_with(".tar") || has_ustar_magic {
        return Ok(InputKind::TarArchive);
    }

    if file_name.ends_with(".zip") || has_zip_magic {
        return Ok(InputKind::ZipArchive);
    }

    Ok(InputKind::BinaryImage)
}

/// Validate a relative path from an archive header against traversal, depth, and unsafe characters.
pub fn validate_archive_member_path(
    raw_path: &Path,
    max_depth: usize,
) -> Result<PathBuf, FirmLensError> {
    let raw_str = raw_path
        .to_str()
        .ok_or_else(|| FirmLensError::IngestionRejected {
            code: "non_utf8_member_path".to_string(),
            message: "archive member path is not valid UTF-8".to_string(),
        })?;

    if raw_str.is_empty() || raw_str.contains('\0') || raw_str.contains('\\') {
        return Err(FirmLensError::IngestionRejected {
            code: "unsafe_member_path".to_string(),
            message: "archive member path contains empty, NUL, or backslash characters".to_string(),
        });
    }

    let mut normalized = PathBuf::new();
    let mut depth = 0usize;

    for component in raw_path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => {
                let part_str = part
                    .to_str()
                    .ok_or_else(|| FirmLensError::IngestionRejected {
                        code: "non_utf8_component".to_string(),
                        message: "archive path component is not valid UTF-8".to_string(),
                    })?;
                if part_str.is_empty() || part_str.contains(':') {
                    return Err(FirmLensError::IngestionRejected {
                        code: "invalid_path_component".to_string(),
                        message: format!("invalid archive path component '{part_str}'"),
                    });
                }
                depth += 1;
                if depth > max_depth {
                    return Err(FirmLensError::IngestionRejected {
                        code: "max_extraction_depth_exceeded".to_string(),
                        message: format!(
                            "archive member exceeds maximum extraction depth of {max_depth}"
                        ),
                    });
                }
                normalized.push(part_str);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FirmLensError::IngestionRejected {
                    code: "path_traversal_rejected".to_string(),
                    message: format!("unsafe path traversal or absolute path in '{raw_str}'"),
                });
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(FirmLensError::IngestionRejected {
            code: "empty_normalized_path".to_string(),
            message: "archive member normalized to an empty path".to_string(),
        });
    }

    Ok(normalized)
}

fn is_nested_archive_name(path: &Path) -> bool {
    let lower = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    lower.ends_with(".tar")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".gz")
        || lower.ends_with(".zip")
}

/// Ingest an input artifact (directory, TAR, TAR.GZ, ZIP, or binary image) under strict security boundaries.
pub fn ingest_input(
    input_path: &Path,
    limits: &IngestionLimits,
) -> Result<StagedIngestion, FirmLensError> {
    if !input_path.exists() && fs::symlink_metadata(input_path).is_err() {
        return Err(FirmLensError::InputNotFound {
            path: input_path.to_path_buf(),
        });
    }

    let kind = classify_input(input_path)?;
    match kind {
        InputKind::Directory => Ok(StagedIngestion {
            provenance: IngestionProvenance {
                input_kind: InputKind::Directory,
                outcome: IngestionOutcome::DirectoryScanned,
                ingestion_limits: limits.clone(),
                counters: ExtractionCounters::default(),
                rejection_reason: None,
                cleanup_verified: true,
            },
            scan_root: Some(input_path.to_path_buf()),
            temp_workspace: None,
            ingestion_skips: Vec::new(),
        }),
        InputKind::BinaryImage => Ok(StagedIngestion {
            provenance: IngestionProvenance {
                input_kind: InputKind::BinaryImage,
                outcome: IngestionOutcome::UnsupportedImage,
                ingestion_limits: limits.clone(),
                counters: ExtractionCounters::default(),
                rejection_reason: Some(
                    "arbitrary firmware filesystem extraction is disabled; only directories and bounded TAR/TAR.GZ/ZIP archives are extracted".to_string(),
                ),
                cleanup_verified: true,
            },
            scan_root: None,
            temp_workspace: None,
            ingestion_skips: Vec::new(),
        }),
        InputKind::TarArchive | InputKind::TarGzArchive => {
            extract_bounded_tar(input_path, kind, limits)
        }
        InputKind::ZipArchive => extract_bounded_zip(input_path, limits),
    }
}

fn extract_bounded_tar(
    input_path: &Path,
    kind: InputKind,
    limits: &IngestionLimits,
) -> Result<StagedIngestion, FirmLensError> {
    let started_at = Instant::now();
    let timeout = Duration::from_millis(limits.ingestion_timeout_ms);

    let meta = fs::symlink_metadata(input_path).map_err(|e| FirmLensError::Io {
        path: input_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    if meta.len() > limits.max_input_bytes {
        return Ok(rejected_archive_stage(
            kind,
            limits,
            ExtractionCounters {
                input_bytes_read: meta.len(),
                ..ExtractionCounters::default()
            },
            format!(
                "input_size_exceeded: archive size ({} bytes) exceeds max_input_bytes ({} bytes)",
                meta.len(),
                limits.max_input_bytes
            ),
            true,
        ));
    }

    let temp_dir = tempfile::Builder::new()
        .prefix("firmlens-stage-")
        .tempdir()
        .map_err(|e| FirmLensError::Io {
            path: input_path.to_path_buf(),
            reason: format!("failed to create staging workspace: {e}"),
        })?;

    let mut counters = ExtractionCounters::default();
    let mut ingestion_skips = Vec::new();

    let file = File::open(input_path).map_err(|e| FirmLensError::Io {
        path: input_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    let input_bounded = BoundedReader::new(
        file,
        limits.max_input_bytes,
        "max_input_bytes_exceeded",
        started_at,
        timeout,
    );

    let extraction_result = match kind {
        InputKind::TarArchive => {
            let expanded_bounded = BoundedReader::new(
                input_bounded,
                limits.max_expanded_bytes,
                "max_expanded_bytes_exceeded",
                started_at,
                timeout,
            );
            unpack_tar_stream(
                expanded_bounded,
                temp_dir.path(),
                limits,
                started_at,
                timeout,
                &mut counters,
                &mut ingestion_skips,
            )
        }
        InputKind::TarGzArchive => {
            let gz_decoder = GzDecoder::new(input_bounded);
            let expanded_bounded = BoundedReader::new(
                gz_decoder,
                limits.max_expanded_bytes,
                "max_expanded_bytes_exceeded",
                started_at,
                timeout,
            );
            unpack_tar_stream(
                expanded_bounded,
                temp_dir.path(),
                limits,
                started_at,
                timeout,
                &mut counters,
                &mut ingestion_skips,
            )
        }
        _ => unreachable!(),
    };

    counters.input_bytes_read = meta.len();

    match extraction_result {
        Ok(()) => Ok(StagedIngestion {
            provenance: IngestionProvenance {
                input_kind: kind,
                outcome: IngestionOutcome::ArchiveExtracted,
                ingestion_limits: limits.clone(),
                counters,
                rejection_reason: None,
                cleanup_verified: false,
            },
            scan_root: Some(temp_dir.path().to_path_buf()),
            temp_workspace: Some(temp_dir),
            ingestion_skips,
        }),
        Err(reason) => {
            let cleanup_ok = temp_dir.close().is_ok();
            Ok(rejected_archive_stage(
                kind, limits, counters, reason, cleanup_ok,
            ))
        }
    }
}

fn rejected_archive_stage(
    kind: InputKind,
    limits: &IngestionLimits,
    counters: ExtractionCounters,
    reason: String,
    cleanup_verified: bool,
) -> StagedIngestion {
    StagedIngestion {
        provenance: IngestionProvenance {
            input_kind: kind,
            outcome: IngestionOutcome::RejectedArchive,
            ingestion_limits: limits.clone(),
            counters,
            rejection_reason: Some(reason),
            cleanup_verified,
        },
        scan_root: None,
        temp_workspace: None,
        ingestion_skips: Vec::new(),
    }
}

fn unpack_tar_stream<R: Read>(
    reader: BoundedReader<R>,
    staging_root: &Path,
    limits: &IngestionLimits,
    started_at: Instant,
    timeout: Duration,
    counters: &mut ExtractionCounters,
    ingestion_skips: &mut Vec<SkippedEntry>,
) -> Result<(), String> {
    let mut archive = Archive::new(reader);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    // Track canonical lowercase paths to reject case-folding collisions across Linux/macOS/Windows.
    let mut seen_paths_lower = BTreeSet::new();
    let mut created_files = BTreeSet::new();

    let entries = archive
        .entries()
        .map_err(|e| format!("corrupt_tar_stream: {e}"))?;

    for entry_res in entries {
        if started_at.elapsed() > timeout {
            return Err(format!(
                "ingestion_timeout: cooperative deadline of {} ms exceeded",
                limits.ingestion_timeout_ms
            ));
        }

        let mut entry = entry_res.map_err(|e| format!("malformed_tar_entry: {e}"))?;
        counters.archive_entries_seen += 1;

        if counters.archive_entries_seen > limits.max_archive_entries {
            return Err(format!(
                "max_archive_entries_exceeded: archive exceeds {} entries",
                limits.max_archive_entries
            ));
        }

        let entry_type = entry.header().entry_type();
        match entry_type {
            EntryType::Regular | EntryType::Continuous => {}
            EntryType::Directory => {}
            EntryType::Symlink | EntryType::Link => {
                return Err(format!(
                    "link_member_rejected: archive contains forbidden link member ({entry_type:?})"
                ));
            }
            EntryType::XHeader
            | EntryType::XGlobalHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => {
                return Err(format!(
                    "extension_header_rejected: PAX/GNU extension headers are not allowed ({entry_type:?})"
                ));
            }
            EntryType::GNUSparse => {
                return Err("sparse_member_rejected: GNU sparse files are not allowed".to_string());
            }
            _ => {
                return Err(format!(
                    "special_member_rejected: unsupported TAR entry type ({entry_type:?})"
                ));
            }
        }

        let raw_path = entry
            .path()
            .map_err(|e| format!("invalid_member_path: {e}"))?
            .into_owned();

        // Allow harmless root "." directory entry if present
        if matches!(entry_type, EntryType::Directory)
            && (raw_path == Path::new(".") || raw_path == Path::new("./"))
        {
            continue;
        }

        let rel_path = validate_archive_member_path(&raw_path, limits.max_extraction_depth)
            .map_err(|e| e.to_string())?;
        let rel_display = rel_path.to_string_lossy().replace('\\', "/");
        let lower_key = rel_display.to_ascii_lowercase();

        let declared_size = entry
            .header()
            .size()
            .map_err(|e| format!("invalid_member_size: {e}"))?;
        if declared_size > limits.max_member_bytes {
            return Err(format!(
                "max_member_bytes_exceeded: member '{}' size ({} bytes) exceeds limit ({} bytes)",
                rel_display, declared_size, limits.max_member_bytes
            ));
        }

        let dest_path = staging_root.join(&rel_path);

        if matches!(entry_type, EntryType::Directory) {
            if created_files.contains(&lower_key) {
                return Err(format!(
                    "conflicting_member_path: directory '{rel_display}' conflicts with an existing file"
                ));
            }
            fs::create_dir_all(&dest_path)
                .map_err(|e| format!("mkdir_failed for '{rel_display}': {e}"))?;
            counters.extracted_directories += 1;
            continue;
        }

        // Regular file: reject duplicates or case-aliasing collisions
        if !seen_paths_lower.insert(lower_key.clone()) {
            return Err(format!(
                "duplicate_or_aliased_member: '{rel_display}' collides with an earlier archive entry"
            ));
        }

        counters.extracted_files += 1;
        if counters.extracted_files > limits.max_extracted_files {
            return Err(format!(
                "max_extracted_files_exceeded: archive exceeds {} regular files",
                limits.max_extracted_files
            ));
        }

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("parent_mkdir_failed for '{rel_display}': {e}"))?;
        }

        let mut out_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .map_err(|e| format!("create_file_failed for '{rel_display}': {e}"))?;

        let mut member_reader = BoundedReader::new(
            &mut entry,
            limits.max_member_bytes,
            "max_member_bytes_exceeded",
            started_at,
            timeout,
        );

        io::copy(&mut member_reader, &mut out_file)
            .map_err(|e| format!("member_write_failed for '{rel_display}': {e}"))?;
        out_file
            .flush()
            .map_err(|e| format!("member_flush_failed for '{rel_display}': {e}"))?;

        created_files.insert(lower_key);

        if is_nested_archive_name(&rel_path) {
            counters.nested_archives_detected += 1;
            ingestion_skips.push(SkippedEntry {
                path: rel_display,
                reason: "nested_archive_not_expanded".to_string(),
            });
        }
    }

    counters.expanded_stream_bytes = archive.into_inner().bytes_read();
    Ok(())
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn find_zip_eocd(buf: &[u8]) -> Option<usize> {
    if buf.len() < 22 {
        return None;
    }
    let min_pos = buf.len().saturating_sub(22 + 65535);
    for pos in (min_pos..=buf.len() - 22).rev() {
        if &buf[pos..pos + 4] == b"PK\x05\x06" {
            let comment_len = read_u16_le(buf, pos + 20)? as usize;
            if pos + 22 + comment_len == buf.len() {
                return Some(pos);
            }
        }
    }
    None
}

fn extract_bounded_zip(
    input_path: &Path,
    limits: &IngestionLimits,
) -> Result<StagedIngestion, FirmLensError> {
    let started_at = Instant::now();
    let timeout = Duration::from_millis(limits.ingestion_timeout_ms);

    let meta = fs::symlink_metadata(input_path).map_err(|e| FirmLensError::Io {
        path: input_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    if meta.len() > limits.max_input_bytes {
        return Ok(rejected_archive_stage(
            InputKind::ZipArchive,
            limits,
            ExtractionCounters {
                input_bytes_read: meta.len(),
                ..ExtractionCounters::default()
            },
            format!(
                "input_size_exceeded: archive size ({} bytes) exceeds max_input_bytes ({} bytes)",
                meta.len(),
                limits.max_input_bytes
            ),
            true,
        ));
    }

    let temp_dir = tempfile::Builder::new()
        .prefix("firmlens-stage-zip-")
        .tempdir()
        .map_err(|e| FirmLensError::Io {
            path: input_path.to_path_buf(),
            reason: format!("failed to create staging workspace: {e}"),
        })?;

    let mut counters = ExtractionCounters::default();
    let mut ingestion_skips = Vec::new();

    let file = File::open(input_path).map_err(|e| FirmLensError::Io {
        path: input_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    let mut bounded_file = BoundedReader::new(
        file,
        limits.max_input_bytes,
        "max_input_bytes_exceeded",
        started_at,
        timeout,
    );

    let mut zip_bytes = Vec::with_capacity(meta.len() as usize);
    let read_res = bounded_file.read_to_end(&mut zip_bytes);
    counters.input_bytes_read = bounded_file.bytes_read();

    let extraction_result = match read_res {
        Ok(_) => unpack_zip_bytes(
            &zip_bytes,
            temp_dir.path(),
            limits,
            started_at,
            timeout,
            &mut counters,
            &mut ingestion_skips,
        ),
        Err(e) => Err(format!("zip_read_failed: {e}")),
    };

    match extraction_result {
        Ok(()) => Ok(StagedIngestion {
            provenance: IngestionProvenance {
                input_kind: InputKind::ZipArchive,
                outcome: IngestionOutcome::ArchiveExtracted,
                ingestion_limits: limits.clone(),
                counters,
                rejection_reason: None,
                cleanup_verified: false,
            },
            scan_root: Some(temp_dir.path().to_path_buf()),
            temp_workspace: Some(temp_dir),
            ingestion_skips,
        }),
        Err(reason) => {
            let cleanup_ok = temp_dir.close().is_ok();
            Ok(rejected_archive_stage(
                InputKind::ZipArchive,
                limits,
                counters,
                reason,
                cleanup_ok,
            ))
        }
    }
}

fn unpack_zip_bytes(
    buf: &[u8],
    staging_root: &Path,
    limits: &IngestionLimits,
    started_at: Instant,
    timeout: Duration,
    counters: &mut ExtractionCounters,
    ingestion_skips: &mut Vec<SkippedEntry>,
) -> Result<(), String> {
    let eocd_pos = find_zip_eocd(buf).ok_or_else(|| {
        "corrupt_zip_stream: End of Central Directory (EOCD) not found".to_string()
    })?;

    let total_entries = read_u16_le(buf, eocd_pos + 10)
        .ok_or_else(|| "corrupt_zip_stream: invalid EOCD entry count".to_string())?
        as usize;
    let cd_size = read_u32_le(buf, eocd_pos + 12)
        .ok_or_else(|| "corrupt_zip_stream: invalid central directory size".to_string())?
        as usize;
    let cd_offset = read_u32_le(buf, eocd_pos + 16)
        .ok_or_else(|| "corrupt_zip_stream: invalid central directory offset".to_string())?
        as usize;

    if cd_offset.saturating_add(cd_size) > eocd_pos {
        return Err("corrupt_zip_stream: central directory bounds exceed EOCD offset".to_string());
    }

    let mut seen_paths_lower = BTreeSet::new();
    let mut created_files = BTreeSet::new();
    let mut cursor = cd_offset;
    let cd_end = cd_offset + cd_size;

    for _ in 0..total_entries {
        if started_at.elapsed() > timeout {
            return Err(format!(
                "ingestion_timeout: cooperative deadline of {} ms exceeded",
                limits.ingestion_timeout_ms
            ));
        }

        if cursor + 46 > cd_end || &buf[cursor..cursor + 4] != b"PK\x01\x02" {
            return Err(
                "corrupt_zip_stream: invalid Central Directory header signature".to_string(),
            );
        }

        counters.archive_entries_seen += 1;
        if counters.archive_entries_seen > limits.max_archive_entries {
            return Err(format!(
                "max_archive_entries_exceeded: archive exceeds {} entries",
                limits.max_archive_entries
            ));
        }

        let version_made_by = read_u16_le(buf, cursor + 4).unwrap_or(0);
        let os_made_by = version_made_by >> 8;
        let flags = read_u16_le(buf, cursor + 8).unwrap_or(0);
        if flags & 0x0001 != 0 {
            return Err(
                "encrypted_zip_rejected: encrypted ZIP entries are not supported".to_string(),
            );
        }

        let method = read_u16_le(buf, cursor + 10).unwrap_or(0);
        let comp_size = read_u32_le(buf, cursor + 20).unwrap_or(0) as usize;
        let uncomp_size = read_u32_le(buf, cursor + 24).unwrap_or(0) as u64;
        let name_len = read_u16_le(buf, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16_le(buf, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16_le(buf, cursor + 32).unwrap_or(0) as usize;
        let external_attr = read_u32_le(buf, cursor + 38).unwrap_or(0);
        let local_hdr_offset = read_u32_le(buf, cursor + 42).unwrap_or(0) as usize;

        let name_end = cursor + 46 + name_len;
        let entry_end = name_end + extra_len + comment_len;
        if entry_end > cd_end {
            return Err("corrupt_zip_stream: central directory entry truncated".to_string());
        }

        let raw_name_cow = String::from_utf8_lossy(&buf[cursor + 46..name_end]);
        let normalized_sep = raw_name_cow.replace('\\', "/");
        cursor = entry_end;

        // Check UNIX mode in upper 16 bits of external_attr only when created by UNIX (os_made_by == 3)
        let unix_mode = if os_made_by == 3 {
            (external_attr >> 16) & 0o170000
        } else {
            0
        };
        if unix_mode == 0o120000 {
            return Err(
                "link_member_rejected: ZIP archive contains forbidden symbolic link".to_string(),
            );
        }
        if unix_mode != 0 && unix_mode != 0o100000 && unix_mode != 0o040000 {
            return Err(format!(
                "special_member_rejected: unsupported UNIX file mode in ZIP ({unix_mode:#o})"
            ));
        }

        let is_dos_dir = (os_made_by == 0 || os_made_by == 10) && (external_attr & 0x10 != 0);
        let is_dir = normalized_sep.ends_with('/') || unix_mode == 0o040000 || is_dos_dir;
        let clean_raw = normalized_sep.trim_end_matches('/');
        if clean_raw.is_empty() || clean_raw == "." {
            continue;
        }

        let raw_path = Path::new(clean_raw);
        let rel_path = validate_archive_member_path(raw_path, limits.max_extraction_depth)
            .map_err(|e| e.to_string())?;
        let rel_display = rel_path.to_string_lossy().replace('\\', "/");
        let lower_key = rel_display.to_ascii_lowercase();
        let dest_path = staging_root.join(&rel_path);

        if is_dir {
            if created_files.contains(&lower_key) {
                return Err(format!(
                    "conflicting_member_path: directory '{rel_display}' conflicts with an existing file"
                ));
            }
            fs::create_dir_all(&dest_path)
                .map_err(|e| format!("mkdir_failed for '{rel_display}': {e}"))?;
            counters.extracted_directories += 1;
            continue;
        }

        if uncomp_size > limits.max_member_bytes {
            return Err(format!(
                "max_member_bytes_exceeded: member '{}' size ({} bytes) exceeds limit ({} bytes)",
                rel_display, uncomp_size, limits.max_member_bytes
            ));
        }

        if !seen_paths_lower.insert(lower_key.clone()) {
            return Err(format!(
                "duplicate_or_aliased_member: '{rel_display}' collides with an earlier archive entry"
            ));
        }

        counters.extracted_files += 1;
        if counters.extracted_files > limits.max_extracted_files {
            return Err(format!(
                "max_extracted_files_exceeded: archive exceeds {} regular files",
                limits.max_extracted_files
            ));
        }

        // Validate Local File Header at local_hdr_offset
        if local_hdr_offset + 30 > buf.len()
            || &buf[local_hdr_offset..local_hdr_offset + 4] != b"PK\x03\x04"
        {
            return Err(format!(
                "corrupt_zip_stream: invalid Local File Header for '{rel_display}'"
            ));
        }
        let l_name_len = read_u16_le(buf, local_hdr_offset + 26).unwrap_or(0) as usize;
        let l_extra_len = read_u16_le(buf, local_hdr_offset + 28).unwrap_or(0) as usize;
        let data_start = local_hdr_offset + 30 + l_name_len + l_extra_len;
        let data_end = data_start.saturating_add(comp_size);
        if data_end > buf.len() {
            return Err(format!(
                "corrupt_zip_stream: compressed data bounds out of range for '{rel_display}'"
            ));
        }
        let comp_slice = &buf[data_start..data_end];

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("parent_mkdir_failed for '{rel_display}': {e}"))?;
        }

        let mut out_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest_path)
            .map_err(|e| format!("create_file_failed for '{rel_display}': {e}"))?;

        let remaining_expanded = limits
            .max_expanded_bytes
            .saturating_sub(counters.expanded_stream_bytes);
        let effective_cap = limits.max_member_bytes.min(remaining_expanded);
        let limit_code = if remaining_expanded < limits.max_member_bytes {
            "max_expanded_bytes_exceeded"
        } else {
            "max_member_bytes_exceeded"
        };

        let bytes_written = match method {
            0 => {
                let mut reader =
                    BoundedReader::new(comp_slice, effective_cap, limit_code, started_at, timeout);
                io::copy(&mut reader, &mut out_file)
                    .map_err(|e| format!("member_write_failed for '{rel_display}': {e}"))?
            }
            8 => {
                let decoder = DeflateDecoder::new(comp_slice);
                let mut reader =
                    BoundedReader::new(decoder, effective_cap, limit_code, started_at, timeout);
                io::copy(&mut reader, &mut out_file)
                    .map_err(|e| format!("member_write_failed for '{rel_display}': {e}"))?
            }
            other => {
                return Err(format!(
                    "unsupported_zip_method: compression method {other} in '{rel_display}' is not supported (only Stored=0 and Deflate=8)"
                ));
            }
        };

        out_file
            .flush()
            .map_err(|e| format!("member_flush_failed for '{rel_display}': {e}"))?;

        counters.expanded_stream_bytes =
            counters.expanded_stream_bytes.saturating_add(bytes_written);
        created_files.insert(lower_key);

        if is_nested_archive_name(&rel_path) {
            counters.nested_archives_detected += 1;
            ingestion_skips.push(SkippedEntry {
                path: rel_display,
                reason: "nested_archive_not_expanded".to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

    #[test]
    fn rejects_parent_traversal_paths() {
        let res = validate_archive_member_path(Path::new("../../etc/shadow"), 32);
        assert!(res.is_err());
    }

    #[test]
    fn rejects_excessive_depth() {
        let deep = Path::new("a/b/c/d/e/f");
        assert!(validate_archive_member_path(deep, 4).is_err());
        assert!(validate_archive_member_path(deep, 6).is_ok());
    }

    #[test]
    fn rejects_archive_with_symlink_and_discards_staged_files() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("malicious.tar");
        {
            let file = File::create(&tar_path).unwrap();
            let mut builder = Builder::new(file);

            let data = b"password = \"hunter2\"\n";
            let mut header = Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/app.conf", &data[..])
                .unwrap();

            let mut sym_header = Header::new_gnu();
            sym_header.set_entry_type(EntryType::Symlink);
            sym_header.set_size(0);
            sym_header.set_cksum();
            builder
                .append_link(&mut sym_header, "etc/passwd_link", "/etc/passwd")
                .unwrap();
            builder.finish().unwrap();
        }

        let staged = ingest_input(&tar_path, &IngestionLimits::default()).unwrap();
        assert_eq!(staged.provenance.outcome, IngestionOutcome::RejectedArchive);
        assert!(staged.scan_root.is_none());
        assert!(staged.temp_workspace.is_none());
        assert!(staged.provenance.cleanup_verified);
        assert!(staged
            .provenance
            .rejection_reason
            .unwrap()
            .contains("link_member_rejected"));
    }

    #[test]
    fn enforces_decompression_bomb_expanded_limit() {
        let dir = tempfile::tempdir().unwrap();
        let tgz_path = dir.path().join("bomb.tar.gz");
        {
            let file = File::create(&tgz_path).unwrap();
            let gz = GzEncoder::new(file, Compression::best());
            let mut builder = Builder::new(gz);

            let payload = vec![b'A'; 64 * 1024];
            let mut header = Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/large.conf", payload.as_slice())
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }

        let limits = IngestionLimits {
            max_expanded_bytes: 16 * 1024, // 16 KiB limit vs 64 KiB expanded payload
            ..IngestionLimits::default()
        };
        let staged = ingest_input(&tgz_path, &limits).unwrap();
        assert_eq!(staged.provenance.outcome, IngestionOutcome::RejectedArchive);
        assert!(staged.scan_root.is_none());
        assert!(staged
            .provenance
            .rejection_reason
            .unwrap()
            .contains("max_expanded_bytes_exceeded"));
    }

    #[test]
    fn records_nested_archive_without_recursive_expansion() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("outer.tar");
        {
            let file = File::create(&tar_path).unwrap();
            let mut builder = Builder::new(file);

            let inner_bytes = b"not expanded inner tar payload";
            let mut header = Header::new_gnu();
            header.set_size(inner_bytes.len() as u64);
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "opt/inner.tar.gz", &inner_bytes[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let staged = ingest_input(&tar_path, &IngestionLimits::default()).unwrap();
        assert_eq!(
            staged.provenance.outcome,
            IngestionOutcome::ArchiveExtracted
        );
        assert_eq!(staged.provenance.counters.nested_archives_detected, 1);
        assert_eq!(staged.ingestion_skips.len(), 1);
        assert_eq!(
            staged.ingestion_skips[0].reason,
            "nested_archive_not_expanded"
        );
    }
}
