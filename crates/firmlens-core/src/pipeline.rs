//! Two-stage analysis coordinator: isolated unpack → static scan → guaranteed cleanup.
//!
//! Binary vendor images (`.bin` / `.chk` / SquashFS envelopes) are not scanned as opaque
//! compressed streams when extraction is enabled. Instead:
//!
//! 1. **Unpack** — `binwalk --extract --matryoshka` runs inside the pinned Docker boundary
//! 2. **Scan** — the existing lexical detector walks the materialized tree
//! 3. **Cleanup** — the extraction [`tempfile::TempDir`] is closed even when scanning fails
//!
//! The core API remains synchronous (portable, no Tokio dependency). Adapters MUST run
//! [`crate::scanner::scan_path`] / [`analyze_path`] on a blocking worker pool so HTTP / UI
//! event loops are never stalled by Binwalk wall-clock work.

use crate::binwalk::{
    extract_image_in_container, identify_image_in_container, BinwalkExtractionResult,
    ExtractionStatus, MIN_EXTRACTION_TIMEOUT,
};
use crate::error::FirmLensError;
use crate::ingestion::{ingest_input, StagedIngestion};
use crate::model::{
    IdentificationResult, IdentificationStatus, IngestionOutcome, InputKind, ScanReport,
};
use crate::scanner::{scan_staged_ingestion, ScanOptions};
use std::path::Path;
use std::time::Duration;

/// Prepare a scan workspace, optionally promoting binary images through isolated Binwalk unpack.
pub fn prepare_scan_workspace(
    input_path: &Path,
    options: &ScanOptions,
) -> Result<(StagedIngestion, IdentificationResult), FirmLensError> {
    let mut staged = ingest_input(input_path, &options.ingestion_limits)?;
    let mut identification = IdentificationResult::default();

    if staged.provenance.input_kind != InputKind::BinaryImage {
        if options.enable_binwalk {
            identification = IdentificationResult {
                status: IdentificationStatus::NotRequested,
                tool_version: None,
                isolated_container: false,
                signatures: Vec::new(),
                note: Some(
                    "Binwalk applies only to unexpanded binary images; filesystem/archive inputs are scanned directly."
                        .to_string(),
                ),
            };
        }
        return Ok((staged, identification));
    }

    if options.enable_binwalk_extract {
        let extract_timeout = Duration::from_millis(options.ingestion_limits.ingestion_timeout_ms)
            .max(MIN_EXTRACTION_TIMEOUT);
        let extracted = extract_image_in_container(
            input_path,
            options.binwalk_image.as_deref(),
            options.ingestion_limits.max_input_bytes,
            options.ingestion_limits.max_extracted_files,
            options.ingestion_limits.max_expanded_bytes,
            extract_timeout,
        );
        apply_extraction_to_staged(&mut staged, &mut identification, extracted);
        return Ok((staged, identification));
    }

    if options.enable_binwalk {
        identification = identify_image_in_container(
            input_path,
            options.binwalk_image.as_deref(),
            options.ingestion_limits.max_input_bytes,
            Duration::from_millis(options.ingestion_limits.ingestion_timeout_ms),
        );
    } else {
        identification = IdentificationResult {
            status: IdentificationStatus::NotRequested,
            tool_version: None,
            isolated_container: false,
            signatures: Vec::new(),
            note: Some(
                "Unsupported binary image; pass --binwalk-extract to unpack via isolated Binwalk, or --binwalk for signature identification only."
                    .to_string(),
            ),
        };
    }

    Ok((staged, identification))
}

fn apply_extraction_to_staged(
    staged: &mut StagedIngestion,
    identification: &mut IdentificationResult,
    extracted: BinwalkExtractionResult,
) {
    *identification = extracted.identification;

    match extracted.status {
        ExtractionStatus::Extracted => {
            if let (Some(root), Some(workspace)) = (extracted.scan_root, extracted.workspace) {
                staged.scan_root = Some(root);
                staged.temp_workspace = Some(workspace);
                staged.provenance.outcome = IngestionOutcome::ImageExtracted;
                staged.provenance.counters = extracted.counters;
                staged.provenance.rejection_reason = None;
                // cleanup_verified is set later when the TempDir is closed after scanning.
                staged.provenance.cleanup_verified = false;
            } else {
                staged.provenance.rejection_reason = Some(extracted.note.unwrap_or_else(|| {
                    "Binwalk reported extraction success without a usable workspace.".to_string()
                }));
            }
        }
        ExtractionStatus::Unavailable | ExtractionStatus::Failed | ExtractionStatus::Empty => {
            staged.provenance.rejection_reason = Some(extracted.note.unwrap_or_else(|| {
                "Isolated Binwalk extraction did not yield a scannable filesystem tree.".to_string()
            }));
            // Keep UnsupportedImage; caller may fall back to bounded raw binary payload scan.
        }
    }
}

/// Full two-stage analysis entry point used by CLI/API adapters.
///
/// Equivalent to [`crate::scanner::scan_path`], kept here so adapters can depend on the
/// pipeline module as the explicit orchestration surface.
pub fn analyze_path(input_path: &Path, options: &ScanOptions) -> Result<ScanReport, FirmLensError> {
    scan_staged_ingestion(input_path, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanOptions;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn binary_image_without_extract_stays_unsupported() {
        let dir = tempdir().unwrap();
        let img = dir.path().join("device.chk");
        fs::write(&img, b"COMPRESSED_FIRMWARE_PLACEHOLDER").unwrap();

        let (staged, ident) = prepare_scan_workspace(&img, &ScanOptions::default()).unwrap();
        assert_eq!(
            staged.provenance.outcome,
            IngestionOutcome::UnsupportedImage
        );
        assert!(staged.scan_root.is_none());
        assert_eq!(ident.status, IdentificationStatus::NotRequested);
    }

    #[test]
    fn extract_with_missing_image_does_not_leave_workspace() {
        let dir = tempdir().unwrap();
        let img = dir.path().join("device.bin");
        fs::write(&img, b"COMPRESSED_FIRMWARE_PLACEHOLDER").unwrap();

        let opts = ScanOptions {
            enable_binwalk_extract: true,
            binwalk_image: Some("firmlens-nonexistent-image:0.0.0-invalid".to_string()),
            ..Default::default()
        };
        let (staged, ident) = prepare_scan_workspace(&img, &opts).unwrap();
        assert_eq!(
            staged.provenance.outcome,
            IngestionOutcome::UnsupportedImage
        );
        assert!(staged.temp_workspace.is_none());
        assert_eq!(ident.status, IdentificationStatus::Unavailable);
    }
}
