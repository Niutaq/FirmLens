use crate::model::{IdentificationResult, IdentificationStatus, SignatureMatch};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::Builder;

pub const DEFAULT_BINWALK_IMAGE: &str = "firmlens-binwalk:3.1.0";
pub const EXPECTED_BINWALK_VERSION: &str = "3.1.0";
const MAX_CONTAINER_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB output cap

/// Run isolated Binwalk v3 signature identification inside a restricted Docker container.
/// Never falls back to an unsandboxed host binary and never passes extraction flags.
pub fn identify_image_in_container(
    input_path: &Path,
    image_override: Option<&str>,
    max_input_bytes: u64,
    timeout: Duration,
) -> IdentificationResult {
    let image = image_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BINWALK_IMAGE);

    if image.starts_with('-') || image.contains('\0') || image.chars().any(char::is_whitespace) {
        return IdentificationResult {
            status: IdentificationStatus::Unavailable,
            tool_version: None,
            isolated_container: false,
            signatures: Vec::new(),
            note: Some("Invalid or unsafe Docker image reference rejected.".to_string()),
        };
    }

    // 1. Verify Docker daemon and local image presence without pulling from network
    let inspect_timeout = timeout.min(Duration::from_secs(10));
    match run_bounded_command(
        "docker",
        &["image", "inspect", "--format", "{{.Id}}", image],
        inspect_timeout,
    ) {
        Ok(out) if out.exit_code == Some(0) && !out.stdout.trim().is_empty() => {}
        Ok(_) => {
            return IdentificationResult {
                status: IdentificationStatus::Unavailable,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(format!(
                    "Trusted Docker image '{image}' is not available locally (automatic pulls are disabled)."
                )),
            };
        }
        Err(reason) => {
            return IdentificationResult {
                status: IdentificationStatus::Unavailable,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(format!(
                    "Docker isolation runtime unavailable ({reason}); no unsandboxed host fallback is permitted."
                )),
            };
        }
    }

    // 2. Verify pinned Binwalk v3 version inside the restricted container boundary
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
        image,
        "--version",
    ];

    let verified_version = match run_bounded_command("docker", &version_args, inspect_timeout) {
        Ok(out) if out.exit_code == Some(0) => {
            let combined = format!("{}\n{}", out.stdout, out.stderr);
            if !is_pinned_binwalk_version(&combined) {
                return IdentificationResult {
                    status: IdentificationStatus::Unavailable,
                    tool_version: None,
                    isolated_container: true,
                    signatures: Vec::new(),
                    note: Some(format!(
                        "Container Binwalk version did not match required pinned release {EXPECTED_BINWALK_VERSION}."
                    )),
                };
            }
            format!("binwalk {EXPECTED_BINWALK_VERSION}")
        }
        Ok(_) | Err(_) => {
            return IdentificationResult {
                status: IdentificationStatus::Unavailable,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(
                    "Failed to verify Binwalk version under required Docker isolation controls."
                        .to_string(),
                ),
            };
        }
    };

    // 3. Stage the input file into a clean temporary directory with read-only world permissions
    let staging_dir = match Builder::new().prefix("firmlens-bw-").tempdir() {
        Ok(d) => d,
        Err(_) => {
            return IdentificationResult {
                status: IdentificationStatus::Failed,
                tool_version: Some(verified_version),
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
            tool_version: Some(verified_version),
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

    // 4. Execute identification only (never -e / --extract / -M / --matryoshka)
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
        image,
        "/input/firmware.bin",
    ];

    let run_res = run_bounded_command("docker", &scan_args, timeout);
    let _ = staging_dir.close();

    match run_res {
        Ok(out) if out.exit_code == Some(0) => {
            let signatures = parse_and_sanitize_binwalk_output(&out.stdout);
            IdentificationResult {
                status: IdentificationStatus::Identified,
                tool_version: Some(verified_version),
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
            tool_version: Some(verified_version),
            isolated_container: true,
            signatures: Vec::new(),
            note: Some(format!(
                "Isolated Binwalk container exited with non-zero status ({:?}).",
                out.exit_code
            )),
        },
        Err(reason) => IdentificationResult {
            status: IdentificationStatus::Failed,
            tool_version: Some(verified_version),
            isolated_container: true,
            signatures: Vec::new(),
            note: Some(format!("Isolated Binwalk execution failed: {reason}.")),
        },
    }
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
