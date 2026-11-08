use firmlens_core::{
    is_pinned_binwalk_version, parse_and_sanitize_binwalk_output, scan_path, IdentificationStatus,
    IngestionOutcome, InputKind, ScanOptions, SignatureMatch,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn corrupt_gzip_archive_is_rejected_and_marks_partial_coverage() {
    let dir = tempdir().unwrap();
    let bad_gz = dir.path().join("corrupt.tar.gz");
    // Gzip magic bytes followed by truncated/corrupted deflate stream
    fs::write(&bad_gz, b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xff\x00").unwrap();

    let report = scan_path(&bad_gz, &ScanOptions::default()).unwrap();
    assert!(report.partial);
    assert_eq!(report.ingestion.input_kind, InputKind::TarGzArchive);
    assert_eq!(report.ingestion.outcome, IngestionOutcome::RejectedArchive);
    assert!(report.ingestion.cleanup_verified);
    assert_eq!(report.metadata.files_scanned, 0);
}

#[test]
fn unsupported_binary_image_without_binwalk_is_partial_and_zero_files() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("router-rootfs.bin");
    fs::write(&img_path, b"hsqs\x00\x00\x00\x01SYNTHETIC_IMAGE_DATA").unwrap();

    let report = scan_path(&img_path, &ScanOptions::default()).unwrap();
    assert!(report.partial);
    assert_eq!(report.ingestion.input_kind, InputKind::BinaryImage);
    assert_eq!(report.ingestion.outcome, IngestionOutcome::UnsupportedImage);
    assert_eq!(
        report.identification.status,
        IdentificationStatus::NotRequested
    );
    assert_eq!(report.metadata.files_scanned, 0);
}

#[test]
fn binwalk_with_missing_local_image_reports_unavailable_without_host_fallback() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("firmware.bin");
    fs::write(&img_path, b"FIRMLENS_TEST_BINARY_IMAGE_HEADER").unwrap();

    let opts = ScanOptions {
        enable_binwalk: true,
        binwalk_image: Some("firmlens-nonexistent-image:0.0.0-invalid".to_string()),
        ..Default::default()
    };

    let report = scan_path(&img_path, &opts).unwrap();
    assert!(report.partial);
    assert_eq!(report.metadata.files_scanned, 0);
    assert_eq!(
        report.identification.status,
        IdentificationStatus::Unavailable
    );
    assert!(!report.identification.isolated_container);
}

#[test]
fn binwalk_output_parser_sanitizes_raw_descriptions_and_never_echoes_secrets() {
    let sample_table = "\
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
256           0x100           gzip compressed data, was \"secret-internal-key-name.tar\", last modified: 2026-11-05
1024          0x400           Squashfs filesystem, little endian, version 4.0, compression:xz, size: 4192304 bytes
4096          0x1000          zlib compressed data, best compression, embedded_pass=SuperSecret99
";

    let parsed = parse_and_sanitize_binwalk_output(sample_table);
    assert_eq!(
        parsed,
        vec![
            SignatureMatch {
                offset: 256,
                category: "gzip_compressed_data".to_string(),
            },
            SignatureMatch {
                offset: 1024,
                category: "squashfs_filesystem".to_string(),
            },
            SignatureMatch {
                offset: 4096,
                category: "zlib_compressed_data".to_string(),
            },
        ]
    );

    let serialized = serde_json::to_string(&parsed).unwrap();
    assert!(!serialized.contains("secret-internal-key-name.tar"));
    assert!(!serialized.contains("SuperSecret99"));
}

#[test]
fn binwalk_version_matcher_accepts_only_pinned_3_1_0() {
    assert!(is_pinned_binwalk_version("binwalk 3.1.0\n"));
    assert!(!is_pinned_binwalk_version("binwalk 2.3.4\n"));
    assert!(!is_pinned_binwalk_version("binwalk 3.2.0\n"));
}

#[test]
#[ignore = "Requires locally built Docker image firmlens-binwalk:3.1.0"]
fn live_binwalk() {
    let dir = tempdir().unwrap();
    let img_path = dir.path().join("signature-test.bin");

    // Build synthetic image with preamble + valid gzip stream at offset 256
    let mut image_bytes = Vec::new();
    image_bytes.extend_from_slice(b"FIRMLENS-SYNTH-IMAGE-V1\x00");
    image_bytes.resize(256, 0xff);

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(b"synthetic_firmware_component=1\nversion=0.2.0\n")
        .unwrap();
    let gz_segment = gz.finish().unwrap();
    image_bytes.extend_from_slice(&gz_segment);
    image_bytes.extend_from_slice(&[0u8; 128]);

    fs::write(&img_path, &image_bytes).unwrap();

    let opts = ScanOptions {
        enable_binwalk: true,
        binwalk_image: None,
        ..Default::default()
    };

    let report = scan_path(&img_path, &opts).unwrap();
    assert!(report.partial);
    assert_eq!(report.metadata.files_scanned, 0);
    assert_eq!(
        report.identification.status,
        IdentificationStatus::Identified,
        "Expected Identified status, got: {:?}",
        report.identification
    );
    assert!(report.identification.isolated_container);
    assert_eq!(
        report.identification.tool_version.as_deref(),
        Some("binwalk 3.1.0")
    );
    assert!(
        report
            .identification
            .signatures
            .iter()
            .any(|s| s.offset == 256 && s.category == "gzip_compressed_data"),
        "Expected gzip_compressed_data at offset 256, got: {:?}",
        report.identification.signatures
    );
}
