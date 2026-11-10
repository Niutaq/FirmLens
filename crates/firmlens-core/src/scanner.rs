use crate::detector::{analyze_file_bytes, classify_file_type};
use crate::error::FirmLensError;
use crate::model::{
    CandidateStatus, FileAnalysisStatus, FileInventoryEntry, FileTypeClass, Finding, FindingKind,
    IdentificationStatus, IngestionLimits, IngestionOutcome, InputKind, ReportMetadata,
    ScanErrorEntry, ScanLimits, ScanReport, Severity, SkippedEntry, SummaryCounts,
    SuppressedCandidate, RULESET_VERSION, SCANNER_VERSION, SCHEMA_VERSION,
};
use crate::pipeline::prepare_scan_workspace;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

/// Options controlling a single FirmLens scan invocation.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub scan_limits: ScanLimits,
    pub ingestion_limits: IngestionLimits,
    /// Optional output path so the scanner never analyzes its own target report path.
    pub excluded_output_path: Option<PathBuf>,
    /// Isolated Binwalk signature identification only (no filesystem extraction).
    pub enable_binwalk: bool,
    /// Isolated Binwalk `--extract --matryoshka` unpack before static analysis.
    pub enable_binwalk_extract: bool,
    pub binwalk_image: Option<String>,
    /// When true, standalone binary/config file inputs (`InputKind::BinaryImage`) are also
    /// inspected for embedded credential strings and PEM keys up to `max_file_bytes`.
    /// Also used as a fallback when `--binwalk-extract` is requested but unpacking fails.
    pub scan_binary_image_payload: bool,
}

const EXCLUDED_DIR_NAMES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    "dist",
    "build",
    "generated-fixtures",
    ".tooling",
];

fn is_excluded_directory_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    EXCLUDED_DIR_NAMES.iter().any(|&d| d == lower)
}

fn classify_file_exclusion(rel_path: &str, file_name: &str) -> Option<&'static str> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_rel = rel_path.to_ascii_lowercase();

    if lower_name.ends_with(".firmlens.json")
        || (lower_name.starts_with("report") && lower_name.ends_with(".json"))
    {
        return Some("generated_report");
    }

    if lower_name.ends_with(".md")
        || lower_name.ends_with(".markdown")
        || lower_name.ends_with(".rst")
        || lower_name.ends_with(".adoc")
        || lower_name == "readme"
        || lower_name.starts_with("readme.")
        || lower_name == "license"
        || lower_name.starts_with("license.")
        || lower_rel.starts_with("docs/")
    {
        return Some("documentation");
    }

    None
}

/// Execute a deterministic scan on a directory, TAR/TAR.GZ archive, or firmware image.
pub fn scan_path(input_path: &Path, options: &ScanOptions) -> Result<ScanReport, FirmLensError> {
    scan_staged_ingestion(input_path, options)
}

/// Two-stage scan entry used by [`crate::pipeline`]: prepare workspace (optional unpack),
/// analyze the tree, then always tear down temporary extraction directories.
pub fn scan_staged_ingestion(
    input_path: &Path,
    options: &ScanOptions,
) -> Result<ScanReport, FirmLensError> {
    let started_wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let started_inst = Instant::now();

    let (mut staged, identification) = prepare_scan_workspace(input_path, options)?;

    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<SuppressedCandidate> = Vec::new();
    let mut inventory: Vec<FileInventoryEntry> = Vec::new();
    let mut skipped_files: Vec<SkippedEntry> = staged.ingestion_skips.clone();
    let mut errors: Vec<ScanErrorEntry> = Vec::new();

    let mut files_scanned = 0usize;
    let mut total_bytes_read = 0u64;
    let mut entries_seen = 0usize;
    let mut budget_exhausted = false;

    let canonical_excluded_output = options
        .excluded_output_path
        .as_ref()
        .and_then(|p| fs::canonicalize(p).ok().or_else(|| Some(p.clone())));

    if let Some(ref scan_root) = staged.scan_root {
        let mut walker = WalkDir::new(scan_root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();

        while let Some(entry_res) = walker.next() {
            let entry = match entry_res {
                Ok(e) => e,
                Err(err) => {
                    let err_path = err
                        .path()
                        .and_then(|p| p.strip_prefix(scan_root).ok())
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|| "<unknown>".to_string());
                    errors.push(ScanErrorEntry {
                        path: err_path,
                        code: "traversal_error".to_string(),
                        message: "filesystem entry could not be accessed during traversal"
                            .to_string(),
                    });
                    continue;
                }
            };

            if entry.path() == scan_root {
                continue;
            }

            let rel_path = entry
                .path()
                .strip_prefix(scan_root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .replace('\\', "/");

            entries_seen += 1;
            if entries_seen > options.scan_limits.max_entries {
                skipped_files.push(SkippedEntry {
                    path: rel_path,
                    reason: "max_entries_limit_exceeded".to_string(),
                });
                budget_exhausted = true;
                break;
            }

            if entry.depth() > options.scan_limits.max_depth {
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                skipped_files.push(SkippedEntry {
                    path: rel_path,
                    reason: "max_depth_limit_exceeded".to_string(),
                });
                continue;
            }

            let file_name = entry.file_name().to_string_lossy();

            // Never follow or analyze symbolic links
            if entry.path_is_symlink() || entry.file_type().is_symlink() {
                skipped_files.push(SkippedEntry {
                    path: rel_path,
                    reason: "symlink_not_followed".to_string(),
                });
                continue;
            }

            if entry.file_type().is_dir() {
                if is_excluded_directory_name(&file_name) {
                    walker.skip_current_dir();
                    skipped_files.push(SkippedEntry {
                        path: rel_path,
                        reason: "excluded_directory".to_string(),
                    });
                }
                continue;
            }

            if !entry.file_type().is_file() {
                skipped_files.push(SkippedEntry {
                    path: rel_path,
                    reason: "special_file_skipped".to_string(),
                });
                continue;
            }

            if let Some(ref excluded_out) = canonical_excluded_output {
                if entry.path() == excluded_out
                    || fs::canonicalize(entry.path()).ok().as_ref() == Some(excluded_out)
                {
                    skipped_files.push(SkippedEntry {
                        path: rel_path,
                        reason: "output_report_path".to_string(),
                    });
                    continue;
                }
            }

            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => {
                    errors.push(ScanErrorEntry {
                        path: rel_path,
                        code: "metadata_error".to_string(),
                        message: "failed to read file metadata".to_string(),
                    });
                    continue;
                }
            };

            let file_size = meta.len();

            if let Some(reason) = classify_file_exclusion(&rel_path, &file_name) {
                skipped_files.push(SkippedEntry {
                    path: rel_path.clone(),
                    reason: reason.to_string(),
                });
                inventory.push(FileInventoryEntry {
                    path: rel_path,
                    file_type: FileTypeClass::Documentation,
                    size_bytes: file_size,
                    analysis_status: FileAnalysisStatus::Skipped,
                    actionable_findings: 0,
                    review_candidates: 0,
                    informational_hints: 0,
                    suppressed_candidates: 0,
                });
                continue;
            }

            if file_size > options.scan_limits.max_file_bytes {
                skipped_files.push(SkippedEntry {
                    path: rel_path.clone(),
                    reason: "max_file_bytes_exceeded".to_string(),
                });
                inventory.push(FileInventoryEntry {
                    path: rel_path.clone(),
                    file_type: classify_file_type(&rel_path, false),
                    size_bytes: file_size,
                    analysis_status: FileAnalysisStatus::TruncatedOrLimited,
                    actionable_findings: 0,
                    review_candidates: 0,
                    informational_hints: 0,
                    suppressed_candidates: 0,
                });
                continue;
            }

            if total_bytes_read.saturating_add(file_size) > options.scan_limits.max_total_bytes {
                skipped_files.push(SkippedEntry {
                    path: rel_path.clone(),
                    reason: "max_total_bytes_exceeded".to_string(),
                });
                inventory.push(FileInventoryEntry {
                    path: rel_path.clone(),
                    file_type: classify_file_type(&rel_path, false),
                    size_bytes: file_size,
                    analysis_status: FileAnalysisStatus::TruncatedOrLimited,
                    actionable_findings: 0,
                    review_candidates: 0,
                    informational_hints: 0,
                    suppressed_candidates: 0,
                });
                budget_exhausted = true;
                continue;
            }

            let mut buf = Vec::with_capacity(file_size as usize);
            let read_res = File::open(entry.path()).and_then(|f| {
                f.take(options.scan_limits.max_file_bytes)
                    .read_to_end(&mut buf)
            });

            if read_res.is_err() {
                errors.push(ScanErrorEntry {
                    path: rel_path.clone(),
                    code: "file_read_error".to_string(),
                    message: "failed to read file bytes".to_string(),
                });
                inventory.push(FileInventoryEntry {
                    path: rel_path.clone(),
                    file_type: classify_file_type(&rel_path, false),
                    size_bytes: file_size,
                    analysis_status: FileAnalysisStatus::Error,
                    actionable_findings: 0,
                    review_candidates: 0,
                    informational_hints: 0,
                    suppressed_candidates: 0,
                });
                continue;
            }

            files_scanned += 1;
            total_bytes_read += buf.len() as u64;

            let is_bin = buf.contains(&0) || std::str::from_utf8(&buf).is_err();
            let file_type = classify_file_type(&rel_path, is_bin);
            let mut file_outcome =
                analyze_file_bytes(&rel_path, &buf, options.scan_limits.max_record_bytes);

            let f_actionable = file_outcome
                .findings
                .iter()
                .filter(|f| f.kind == FindingKind::Finding && f.status.is_actionable())
                .count();
            let f_review = file_outcome
                .findings
                .iter()
                .filter(|f| {
                    f.kind == FindingKind::Finding && f.status == CandidateStatus::RequiresReview
                })
                .count();
            let f_hints = file_outcome
                .findings
                .iter()
                .filter(|f| f.kind == FindingKind::Hint)
                .count();
            let f_supp = file_outcome.suppressed.len();

            let mut analysis_status = FileAnalysisStatus::Scanned;
            for f in file_outcome.findings.drain(..) {
                if findings.len() + suppressed.len() < options.scan_limits.max_findings {
                    findings.push(f);
                } else {
                    analysis_status = FileAnalysisStatus::TruncatedOrLimited;
                    budget_exhausted = true;
                }
            }
            for s in file_outcome.suppressed.drain(..) {
                if findings.len() + suppressed.len() < options.scan_limits.max_findings {
                    suppressed.push(s);
                } else {
                    analysis_status = FileAnalysisStatus::TruncatedOrLimited;
                    budget_exhausted = true;
                }
            }

            inventory.push(FileInventoryEntry {
                path: rel_path,
                file_type,
                size_bytes: file_size,
                analysis_status,
                actionable_findings: f_actionable,
                review_candidates: f_review,
                informational_hints: f_hints,
                suppressed_candidates: f_supp,
            });
        }
    } else if staged.provenance.input_kind == InputKind::BinaryImage
        && options.scan_binary_image_payload
    {
        // Optional raw binary payload scan / fallback when no extracted tree is available.
        let rel_path = input_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("firmware.bin")
            .to_string();

        if let Ok(meta) = fs::symlink_metadata(input_path) {
            let file_size = meta.len();
            if file_size <= options.scan_limits.max_file_bytes {
                let mut buf = Vec::with_capacity(file_size as usize);
                if File::open(input_path)
                    .and_then(|f| {
                        f.take(options.scan_limits.max_file_bytes)
                            .read_to_end(&mut buf)
                    })
                    .is_ok()
                {
                    files_scanned = 1;
                    total_bytes_read = buf.len() as u64;
                    let is_bin = buf.contains(&0) || std::str::from_utf8(&buf).is_err();
                    let file_type = classify_file_type(&rel_path, is_bin);
                    let mut file_outcome =
                        analyze_file_bytes(&rel_path, &buf, options.scan_limits.max_record_bytes);

                    let f_actionable = file_outcome
                        .findings
                        .iter()
                        .filter(|f| f.kind == FindingKind::Finding && f.status.is_actionable())
                        .count();
                    let f_review = file_outcome
                        .findings
                        .iter()
                        .filter(|f| {
                            f.kind == FindingKind::Finding
                                && f.status == CandidateStatus::RequiresReview
                        })
                        .count();
                    let f_hints = file_outcome
                        .findings
                        .iter()
                        .filter(|f| f.kind == FindingKind::Hint)
                        .count();
                    let f_supp = file_outcome.suppressed.len();

                    findings.append(&mut file_outcome.findings);
                    suppressed.append(&mut file_outcome.suppressed);

                    inventory.push(FileInventoryEntry {
                        path: rel_path,
                        file_type,
                        size_bytes: file_size,
                        analysis_status: FileAnalysisStatus::Scanned,
                        actionable_findings: f_actionable,
                        review_candidates: f_review,
                        informational_hints: f_hints,
                        suppressed_candidates: f_supp,
                    });
                }
            } else {
                skipped_files.push(SkippedEntry {
                    path: rel_path.clone(),
                    reason: "max_file_bytes_exceeded".to_string(),
                });
                inventory.push(FileInventoryEntry {
                    path: rel_path,
                    file_type: FileTypeClass::DataOrBinary,
                    size_bytes: file_size,
                    analysis_status: FileAnalysisStatus::TruncatedOrLimited,
                    actionable_findings: 0,
                    review_candidates: 0,
                    informational_hints: 0,
                    suppressed_candidates: 0,
                });
                budget_exhausted = true;
            }
        }
    }

    // Explicitly close and verify cleanup of temporary extraction directory if present
    if let Some(temp_ws) = staged.temp_workspace.take() {
        match temp_ws.close() {
            Ok(()) => {
                staged.provenance.cleanup_verified = true;
            }
            Err(e) => {
                staged.provenance.cleanup_verified = false;
                errors.push(ScanErrorEntry {
                    path: "<staging_workspace>".to_string(),
                    code: "staging_cleanup_failed".to_string(),
                    message: format!("failed to remove temporary extraction directory: {e}"),
                });
            }
        }
    }

    // Deterministic ordering across platforms
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.byte_offset.cmp(&b.byte_offset))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    suppressed.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.byte_offset.cmp(&b.byte_offset))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    inventory.sort_by(|a, b| a.path.cmp(&b.path));
    skipped_files.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.reason.cmp(&b.reason)));
    errors.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.code.cmp(&b.code)));

    let actionable_findings = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Finding && f.status.is_actionable())
        .count();
    let review_candidates = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Finding && f.status == CandidateStatus::RequiresReview)
        .count();
    let informational_hints = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Hint)
        .count();

    let mut by_severity = BTreeMap::new();
    for f in &findings {
        let key = match f.severity {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        *by_severity.entry(key.to_string()).or_insert(0) += 1;
    }

    let partial = budget_exhausted
        || !skipped_files.is_empty()
        || !errors.is_empty()
        || matches!(
            staged.provenance.outcome,
            IngestionOutcome::RejectedArchive | IngestionOutcome::UnsupportedImage
        )
        || staged.provenance.counters.nested_archives_detected > 0
        || matches!(
            identification.status,
            IdentificationStatus::Unavailable | IdentificationStatus::Failed
        );

    let duration_ms = started_inst.elapsed().as_millis() as u64;

    Ok(ScanReport {
        schema_version: SCHEMA_VERSION.to_string(),
        metadata: ReportMetadata {
            scanner_version: SCANNER_VERSION.to_string(),
            ruleset_version: RULESET_VERSION.to_string(),
            root: input_path.to_string_lossy().to_string(),
            started_unix_ms: started_wall,
            duration_ms,
            files_scanned,
            bytes_read: total_bytes_read,
            limits: options.scan_limits.clone(),
        },
        ingestion: staged.provenance,
        identification,
        summary: SummaryCounts {
            total_findings: findings.len(),
            actionable_findings,
            review_candidates,
            informational_hints,
            suppressed_candidates: suppressed.len(),
            by_severity,
            skipped_entries: skipped_files.len(),
            scan_errors: errors.len(),
        },
        findings,
        suppressed,
        inventory,
        skipped_files,
        errors,
        partial,
    })
}
