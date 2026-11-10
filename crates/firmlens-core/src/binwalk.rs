use crate::model::{
    ExtractionCounters, IdentificationResult, IdentificationStatus, SignatureMatch,
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{Builder, TempDir};
use walkdir::WalkDir;

pub const DEFAULT_BINWALK_IMAGE: &str = "firmlens-binwalk:3.1.0";
pub const EXPECTED_BINWALK_VERSION: &str = "3.1.0";
const MAX_CONTAINER_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB stdout/stderr cap
/// Floor applied to extraction wall-clock timeouts (firmware unpack can exceed archive ingest).
pub const MIN_EXTRACTION_TIMEOUT: Duration = Duration::from_secs(180);

/// Outcome of an isolated Binwalk filesystem extraction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionStatus {
    Extracted,
    Unavailable,
    Failed,
    Empty,
}

/// Host-side result of containerized Binwalk extraction.
///
/// `workspace` owns the temporary directory tree. Dropping it (or calling
/// [`TempDir::close`]) deletes extracted content — use this as the cleanup guarantee.
#[derive(Debug)]
pub struct BinwalkExtractionResult {
    pub status: ExtractionStatus,
    pub identification: IdentificationResult,
    pub workspace: Option<TempDir>,
    pub scan_root: Option<PathBuf>,
    pub counters: ExtractionCounters,
    pub note: Option<String>,
}

impl BinwalkExtractionResult {
    fn unavailable(note: impl Into<String>) -> Self {
        let note = note.into();
        Self {
            status: ExtractionStatus::Unavailable,
            identification: IdentificationResult {
                status: IdentificationStatus::Unavailable,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(note.clone()),
            },
            workspace: None,
            scan_root: None,
            counters: ExtractionCounters::default(),
            note: Some(note),
        }
    }

    fn failed(
        verified_version: Option<String>,
        isolated: bool,
        note: impl Into<String>,
        signatures: Vec<SignatureMatch>,
    ) -> Self {
        let note = note.into();
        Self {
            status: ExtractionStatus::Failed,
            identification: IdentificationResult {
                status: IdentificationStatus::Failed,
                tool_version: verified_version,
                isolated_container: isolated,
                signatures,
                note: Some(note.clone()),
            },
            workspace: None,
            scan_root: None,
            counters: ExtractionCounters::default(),
            note: Some(note),
        }
    }
}

/// Run isolated Binwalk v3 signature identification inside a restricted Docker container.
/// Never falls back to an unsandboxed host binary and never passes extraction flags.
pub fn identify_image_in_container(
    input_path: &Path,
    image_override: Option<&str>,
    max_input_bytes: u64,
    timeout: Duration,
) -> IdentificationResult {
    let prepared = match prepare_isolated_binwalk(image_override, timeout) {
        Ok(p) => p,
        Err(note) => {
            return IdentificationResult {
                status: IdentificationStatus::Unavailable,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(note),
            };
        }
    };

    let staging_dir = match Builder::new().prefix("firmlens-bw-id-").tempdir() {
        Ok(d) => d,
        Err(_) => {
            return IdentificationResult {
                status: IdentificationStatus::Failed,
                tool_version: Some(prepared.verified_version.clone()),
                isolated_container: false,
                signatures: Vec::new(),
                note: Some("Failed to create temporary staging directory.".to_string()),
            };
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(staging_dir.path(), fs::Permissions::from_mode(0o755));
    }

    let staged_file = staging_dir.path().join("firmware.bin");
    if let Err(msg) = copy_bounded_input(input_path, &staged_file, max_input_bytes) {
        let _ = staging_dir.close();
        return IdentificationResult {
            status: IdentificationStatus::Failed,
            tool_version: Some(prepared.verified_version),
            isolated_container: false,
            signatures: Vec::new(),
            note: Some(msg),
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o644));
    }

    let mount_spec = format!(
        "type=bind,source={},target=/input/firmware.bin,readonly",
        staged_file.display()
    );

    // Identification only (never -e / --extract / -M / --matryoshka)
    let scan_args = [
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--user",
        "65534:65534",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--mount",
        &mount_spec,
        prepared.image.as_str(),
        "/input/firmware.bin",
    ];

    let run_res = run_bounded_command("docker", &scan_args, timeout);
    let _ = staging_dir.close();

    match run_res {
        Ok(out) if out.exit_code == Some(0) => {
            let signatures = parse_and_sanitize_binwalk_output(&out.stdout);
            IdentificationResult {
                status: IdentificationStatus::Identified,
                tool_version: Some(prepared.verified_version),
                isolated_container: true,
                signatures,
                note: Some(
                    "Identified signatures are offsets only; no files were extracted or scanned."
                        .to_string(),
                ),
            }
        }
        Ok(out) => IdentificationResult {
            status: IdentificationStatus::Failed,
            tool_version: Some(prepared.verified_version),
            isolated_container: true,
            signatures: Vec::new(),
            note: Some(format!(
                "Isolated Binwalk container exited with non-zero status ({:?}).",
                out.exit_code
            )),
        },
        Err(reason) => IdentificationResult {
            status: IdentificationStatus::Failed,
            tool_version: Some(prepared.verified_version),
            isolated_container: true,
            signatures: Vec::new(),
            note: Some(format!("Isolated Binwalk execution failed: {reason}.")),
        },
    }
}

/// Extract firmware filesystem contents via isolated Binwalk v3 (`--extract --matryoshka`).
///
/// Security properties:
/// - argv-only Docker invocation (no shell) with fixed container paths (no command injection)
/// - never falls back to a host `binwalk` binary
/// - wall-clock timeout with process kill
/// - extracted tree is returned inside a [`TempDir`] so Drop / `close()` always deletes it
/// - post-extraction file/byte budgets are enforced before the tree is accepted for scanning
pub fn extract_image_in_container(
    input_path: &Path,
    image_override: Option<&str>,
    max_input_bytes: u64,
    max_extracted_files: usize,
    max_expanded_bytes: u64,
    timeout: Duration,
) -> BinwalkExtractionResult {
    let timeout = timeout.max(MIN_EXTRACTION_TIMEOUT);

    let prepared = match prepare_isolated_binwalk(image_override, timeout) {
        Ok(p) => p,
        Err(note) => return BinwalkExtractionResult::unavailable(note),
    };

    let workspace = match Builder::new().prefix("firmlens-bw-ex-").tempdir() {
        Ok(d) => d,
        Err(_) => {
            return BinwalkExtractionResult::failed(
                Some(prepared.verified_version),
                false,
                "Failed to create temporary extraction workspace.",
                Vec::new(),
            );
        }
    };

    let input_dir = workspace.path().join("input");
    let output_dir = workspace.path().join("output");
    if fs::create_dir_all(&input_dir).is_err() || fs::create_dir_all(&output_dir).is_err() {
        let _ = workspace.close();
        return BinwalkExtractionResult::failed(
            Some(prepared.verified_version),
            false,
            "Failed to create extraction input/output directories.",
            Vec::new(),
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(workspace.path(), fs::Permissions::from_mode(0o755));
        let _ = fs::set_permissions(&input_dir, fs::Permissions::from_mode(0o755));
        // World-writable so the unprivileged container UID can materialize files.
        let _ = fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o777));
    }

    let staged_file = input_dir.join("firmware.bin");
    if let Err(msg) = copy_bounded_input(input_path, &staged_file, max_input_bytes) {
        let _ = workspace.close();
        return BinwalkExtractionResult::failed(
            Some(prepared.verified_version),
            false,
            msg,
            Vec::new(),
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o644));
    }

    let input_mount = format!(
        "type=bind,source={},target=/input,readonly",
        input_dir.display()
    );
    let output_mount = format!("type=bind,source={},target=/output", output_dir.display());

    // Prefer the invoking host UID so extracted files remain deletable without root.
    // Fall back to the image's unprivileged UID when host identity is unavailable.
    let user_spec = host_docker_user_spec().unwrap_or_else(|| "10001:10001".to_string());

    // Fixed container paths only — never interpolate untrusted filenames into argv.
    // `--extract --matryoshka` unpacks nested SquashFS/LZMA/etc. layers inside the container.
    // Root inside the container is intentionally avoided; extractors that tolerate non-root
    // (e.g. sasquatch exit code 2) keep host cleanup reliable.
    let extract_args = [
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--user",
        user_spec.as_str(),
        "--pids-limit=128",
        "--memory=1g",
        "--cpus=1",
        "--mount",
        &input_mount,
        "--mount",
        &output_mount,
        "-e",
        "BINWALK_RM_EXTRACTION_SYMLINK=1",
        prepared.image.as_str(),
        "--extract",
        "--matryoshka",
        "--quiet",
        "--directory",
        "/output",
        "/input/firmware.bin",
    ];

    let run_res = run_bounded_command("docker", &extract_args, timeout);

    let (stdout, stderr, exit_ok) = match run_res {
        Ok(out) => {
            // Binwalk may return non-zero when some nested extractors warn; accept 0.
            let ok = out.exit_code == Some(0);
            (out.stdout, out.stderr, ok)
        }
        Err(reason) => {
            let _ = workspace.close();
            return BinwalkExtractionResult::failed(
                Some(prepared.verified_version),
                true,
                format!("Isolated Binwalk extraction failed: {reason}."),
                Vec::new(),
            );
        }
    };

    let signatures = parse_and_sanitize_binwalk_output(&stdout);
    // Also sanitize stderr categories only if stdout was empty (still never echo raw text).
    let signatures = if signatures.is_empty() {
        parse_and_sanitize_binwalk_output(&stderr)
    } else {
        signatures
    };

    let counters =
        match inventory_extracted_tree(&output_dir, max_extracted_files, max_expanded_bytes) {
            Ok(c) => c,
            Err(reason) => {
                let _ = workspace.close();
                return BinwalkExtractionResult::failed(
                    Some(prepared.verified_version.clone()),
                    true,
                    reason,
                    signatures,
                );
            }
        };

    if counters.extracted_files == 0 {
        let note = if exit_ok {
            "Isolated Binwalk extraction completed but produced no regular files.".to_string()
        } else {
            "Isolated Binwalk extraction exited non-zero and produced no regular files.".to_string()
        };
        let _ = workspace.close();
        return BinwalkExtractionResult {
            status: ExtractionStatus::Empty,
            identification: IdentificationResult {
                status: if signatures.is_empty() {
                    IdentificationStatus::Failed
                } else {
                    IdentificationStatus::Identified
                },
                tool_version: Some(prepared.verified_version),
                isolated_container: true,
                signatures,
                note: Some(note.clone()),
            },
            workspace: None,
            scan_root: None,
            counters,
            note: Some(note),
        };
    }

    let note = format!(
        "Isolated Binwalk extracted {} regular file(s) ({} bytes) under a temporary workspace; signatures and extracted files are distinct report fields.",
        counters.extracted_files, counters.expanded_stream_bytes
    );

    BinwalkExtractionResult {
        status: ExtractionStatus::Extracted,
        identification: IdentificationResult {
            status: IdentificationStatus::Identified,
            tool_version: Some(prepared.verified_version),
            isolated_container: true,
            signatures,
            note: Some(note.clone()),
        },
        scan_root: Some(output_dir),
        workspace: Some(workspace),
        counters,
        note: Some(note),
    }
}

struct PreparedBinwalk {
    image: String,
    verified_version: String,
}

fn prepare_isolated_binwalk(
    image_override: Option<&str>,
    timeout: Duration,
) -> Result<PreparedBinwalk, String> {
    let image = resolve_image_name(image_override)?;

    let inspect_timeout = timeout.min(Duration::from_secs(10));
    match run_bounded_command(
        "docker",
        &["image", "inspect", "--format", "{{.Id}}", image.as_str()],
        inspect_timeout,
    ) {
        Ok(out) if out.exit_code == Some(0) && !out.stdout.trim().is_empty() => {}
        Ok(_) => {
            return Err(format!(
                "Trusted Docker image '{image}' is not available locally (automatic pulls are disabled)."
            ));
        }
        Err(reason) => {
            return Err(format!(
                "Docker isolation runtime unavailable ({reason}); no unsandboxed host fallback is permitted."
            ));
        }
    }

    let version_args = [
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--user",
        "65534:65534",
        "--pids-limit=32",
        "--memory=256m",
        "--cpus=1",
        image.as_str(),
        "--version",
    ];

    let verified_version = match run_bounded_command("docker", &version_args, inspect_timeout) {
        Ok(out) if out.exit_code == Some(0) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            if !is_pinned_binwalk_version(&combined) {
                return Err(format!(
                    "Container Binwalk version did not match required pinned release {EXPECTED_BINWALK_VERSION}."
                ));
            }
            format!("binwalk {EXPECTED_BINWALK_VERSION}")
        }
        Ok(_) | Err(_) => {
            return Err(
                "Failed to verify Binwalk version under required Docker isolation controls."
                    .to_string(),
            );
        }
    };

    Ok(PreparedBinwalk {
        image,
        verified_version,
    })
}

fn resolve_image_name(image_override: Option<&str>) -> Result<String, String> {
    let image = image_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BINWALK_IMAGE);

    if image.starts_with('-') || image.contains('\0') || image.chars().any(char::is_whitespace) {
        return Err("Invalid or unsafe Docker image reference rejected.".to_string());
    }
    Ok(image.to_string())
}

fn host_docker_user_spec() -> Option<String> {
    #[cfg(unix)]
    {
        // libc UID/GID of the FirmLens process — keeps bind-mounted extractions deletable.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        Some(format!("{uid}:{gid}"))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn inventory_extracted_tree(
    root: &Path,
    max_files: usize,
    max_bytes: u64,
) -> Result<ExtractionCounters, String> {
    let mut counters = ExtractionCounters::default();

    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        let entry = entry.map_err(|_| {
            "Failed to traverse isolated Binwalk extraction output (IO error).".to_string()
        })?;

        if entry.depth() == 0 {
            continue;
        }

        counters.archive_entries_seen += 1;
        if counters.archive_entries_seen > max_files.saturating_mul(2).max(20_000) {
            return Err(
                "Isolated Binwalk extraction exceeded maximum archive entry budget.".to_string(),
            );
        }

        let ft = entry.file_type();
        if ft.is_symlink() {
            // Do not follow; count and leave for the scanner skip path / cleanup.
            continue;
        }
        if ft.is_dir() {
            counters.extracted_directories += 1;
            continue;
        }
        if !ft.is_file() {
            continue;
        }

        counters.extracted_files += 1;
        if counters.extracted_files > max_files {
            return Err(format!(
                "Isolated Binwalk extraction exceeded max_extracted_files ({max_files})."
            ));
        }

        let meta = fs::symlink_metadata(entry.path()).map_err(|_| {
            "Failed to read metadata for an extracted file under the isolation boundary."
                .to_string()
        })?;
        counters.expanded_stream_bytes = counters.expanded_stream_bytes.saturating_add(meta.len());
        if counters.expanded_stream_bytes > max_bytes {
            return Err(format!(
                "Isolated Binwalk extraction exceeded max_expanded_bytes ({max_bytes})."
            ));
        }
    }

    Ok(counters)
}

fn copy_bounded_input(src: &Path, dst: &Path, max_bytes: u64) -> Result<(), String> {
    let meta = fs::symlink_metadata(src)
        .map_err(|_| "Failed to read input image metadata.".to_string())?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err("Input image must be a regular file (symlinks rejected).".to_string());
    }
    if meta.len() > max_bytes {
        return Err(format!(
            "Input image size ({} bytes) exceeds max_input_bytes ({max_bytes} bytes).",
            meta.len()
        ));
    }

    let mut reader = File::open(src)
        .map_err(|_| "Failed to open input image for staging.".to_string())?
        .take(max_bytes + 1);
    let mut writer =
        File::create(dst).map_err(|_| "Failed to create staged image file.".to_string())?;

    let copied = io::copy(&mut reader, &mut writer)
        .map_err(|_| "Failed to copy input image to staging workspace.".to_string())?;
    if copied > max_bytes {
        return Err(format!(
            "Input image exceeded max_input_bytes ({max_bytes} bytes) while staging."
        ));
    }
    Ok(())
}

struct BoundedCommandOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_bounded_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<BoundedCommandOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn '{program}': {e}"))?;

    let stdout_pipe = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr_pipe = child.stderr.take().ok_or("missing stderr pipe")?;

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe
            .take(MAX_CONTAINER_OUTPUT_BYTES as u64)
            .read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe
            .take(MAX_CONTAINER_OUTPUT_BYTES as u64)
            .read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "command timed out after {} ms",
                        timeout.as_millis()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("error waiting for command: {e}"));
            }
        }
    };

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    Ok(BoundedCommandOutput {
        exit_code: status.code(),
        stdout,
        stderr,
    })
}

pub fn is_pinned_binwalk_version(version_output: &str) -> bool {
    version_output.lines().any(|line| {
        let lower = line.trim().to_ascii_lowercase();
        (lower.starts_with("binwalk ") || lower.contains("binwalk"))
            && lower
                .split_whitespace()
                .any(|tok| tok == EXPECTED_BINWALK_VERSION)
    })
}

/// Parse Binwalk v3 stdout (table or JSON) and sanitize all descriptions into fixed categories
/// so raw embedded strings, filenames, or comments are never serialized.
pub fn parse_and_sanitize_binwalk_output(raw_output: &str) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();

    // Support JSON array/object output if emitted
    let trimmed = raw_output.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            collect_json_signatures(&val, &mut matches);
        }
    }

    // Standard Binwalk CLI table lines: `<DECIMAL> <0xHEX> <DESCRIPTION>`
    if matches.is_empty() {
        for line in raw_output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("DECIMAL") || line.starts_with("---") {
                continue;
            }
            let mut parts = line.splitn(3, char::is_whitespace);
            let Some(dec_str) = parts.next() else {
                continue;
            };
            let Ok(offset) = dec_str.parse::<u64>() else {
                continue;
            };
            let rest = line[dec_str.len()..].trim_start();
            let mut hex_and_desc = rest.splitn(2, char::is_whitespace);
            let Some(hex_str) = hex_and_desc.next() else {
                continue;
            };
            if !hex_str.starts_with("0x") && !hex_str.starts_with("0X") {
                continue;
            }
            let Some(desc) = hex_and_desc.next() else {
                continue;
            };
            let category = sanitize_signature_category(desc).to_string();
            matches.push(SignatureMatch { offset, category });
        }
    }

    matches.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.category.cmp(&b.category))
    });
    matches.dedup();
    matches
}

fn collect_json_signatures(val: &serde_json::Value, out: &mut Vec<SignatureMatch>) {
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_signatures(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(offset) = map.get("offset").and_then(|v| v.as_u64()) {
                let raw_label = map
                    .get("name")
                    .or_else(|| map.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                out.push(SignatureMatch {
                    offset,
                    category: sanitize_signature_category(raw_label).to_string(),
                });
            }
            for v in map.values() {
                if v.is_array() || v.is_object() {
                    collect_json_signatures(v, out);
                }
            }
        }
        _ => {}
    }
}

/// Map arbitrary Binwalk signature names/descriptions to a closed set of safe category labels.
/// Never returns raw substrings from the binary image.
pub fn sanitize_signature_category(raw_desc: &str) -> &'static str {
    let lower = raw_desc.trim().to_ascii_lowercase();
    if lower.contains("squashfs") {
        "squashfs_filesystem"
    } else if lower.contains("jffs2") {
        "jffs2_filesystem"
    } else if lower.contains("ubifs") {
        "ubifs_filesystem"
    } else if lower.contains("ubi ") || lower.starts_with("ubi") {
        "ubi_image"
    } else if lower.contains("cramfs") {
        "cramfs_filesystem"
    } else if lower.contains("romfs") {
        "romfs_filesystem"
    } else if lower.contains("ext2") || lower.contains("ext3") || lower.contains("ext4") {
        "ext_filesystem"
    } else if lower.contains("gzip") {
        "gzip_compressed_data"
    } else if lower.contains("zlib") {
        "zlib_compressed_data"
    } else if lower.contains("xz ") || lower.starts_with("xz") {
        "xz_compressed_data"
    } else if lower.contains("lzma") {
        "lzma_compressed_data"
    } else if lower.contains("zstd") || lower.contains("zstandard") {
        "zstd_compressed_data"
    } else if lower.contains("bzip2") {
        "bzip2_compressed_data"
    } else if lower.contains("lz4") {
        "lz4_compressed_data"
    } else if lower.contains("cpio") {
        "cpio_archive"
    } else if lower.contains("posix tar") || lower.contains("tar archive") || lower == "tar" {
        "tar_archive"
    } else if lower.contains("zip") {
        "zip_archive"
    } else if lower.contains("u-boot") || lower.contains("uimage") {
        "uimage_or_uboot"
    } else if lower.contains("flattened device tree") || lower.contains("dtb") {
        "device_tree_blob"
    } else if lower.contains("elf") {
        "elf_binary"
    } else if lower.contains("certificate")
        || lower.contains("private key")
        || lower.contains("x509")
    {
        "certificate_or_key_header"
    } else {
        "other_signature"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_image_rejects_injection_shaped_names() {
        assert!(resolve_image_name(Some("-e")).is_err());
        assert!(resolve_image_name(Some("img;rm -rf /")).is_err());
        assert!(resolve_image_name(Some("firmlens-binwalk:3.1.0")).is_ok());
    }

    #[test]
    fn extraction_budget_rejects_oversized_trees() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.bin"), vec![0u8; 64]).unwrap();
        fs::write(dir.path().join("b.bin"), vec![0u8; 64]).unwrap();
        let err = inventory_extracted_tree(dir.path(), 1, 1024).unwrap_err();
        assert!(err.contains("max_extracted_files"));
    }
}
