pub mod binwalk;
pub mod detector;
pub mod error;
pub mod ingestion;
pub mod model;
pub mod pipeline;
pub mod rules;
pub mod scanner;

pub use binwalk::{
    extract_image_in_container, identify_image_in_container, is_pinned_binwalk_version,
    parse_and_sanitize_binwalk_output, sanitize_signature_category, BinwalkExtractionResult,
    ExtractionStatus, DEFAULT_BINWALK_IMAGE, EXPECTED_BINWALK_VERSION, MIN_EXTRACTION_TIMEOUT,
};
pub use detector::{analyze_file_bytes, classify_file_type, strip_inline_comment};
pub use error::FirmLensError;
pub use ingestion::{classify_input, ingest_input, BoundedReader, StagedIngestion};
pub use model::*;
pub use pipeline::{analyze_path, prepare_scan_workspace};
pub use rules::{find_rule, list_rules, RuleMetadata, RULES};
pub use scanner::{scan_path, scan_staged_ingestion, ScanOptions};
