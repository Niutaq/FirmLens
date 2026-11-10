use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "2.2";
pub const SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RULESET_VERSION: &str = "2";

/// Scanner resource limits for directory traversal and file inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_record_bytes: usize,
    pub max_findings: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,    // 8 MiB per file
            max_total_bytes: 128 * 1024 * 1024, // 128 MiB total read
            max_entries: 100_000,               // 100,000 entries
            max_depth: 64,                      // max directory depth 64
            max_record_bytes: 16 * 1024,        // 16 KiB per record/line
            max_findings: 10_000,               // 10,000 candidates including suppressions
        }
    }
}

/// Bounded archive extraction limits for TAR / TAR.GZ ingestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestionLimits {
    pub max_input_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_member_bytes: u64,
    pub max_extracted_files: usize,
    pub max_archive_entries: usize,
    pub max_extraction_depth: usize,
    pub ingestion_timeout_ms: u64,
}

impl Default for IngestionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 * 1024 * 1024,    // 128 MiB input archive
            max_expanded_bytes: 256 * 1024 * 1024, // 256 MiB expanded TAR stream
            max_member_bytes: 8 * 1024 * 1024,     // 8 MiB per archive member
            max_extracted_files: 10_000,           // 10,000 regular files
            max_archive_entries: 20_000,           // 20,000 entries/nodes
            max_extraction_depth: 32,              // 32 path components
            ingestion_timeout_ms: 30_000,          // 30s cooperative deadline
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Directory,
    TarArchive,
    TarGzArchive,
    ZipArchive,
    BinaryImage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IngestionOutcome {
    DirectoryScanned,
    ArchiveExtracted,
    /// Firmware image unpacked via isolated Binwalk v3 extraction (`--extract --matryoshka`).
    ImageExtracted,
    RejectedArchive,
    UnsupportedImage,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractionCounters {
    pub input_bytes_read: u64,
    pub expanded_stream_bytes: u64,
    pub extracted_files: usize,
    pub extracted_directories: usize,
    pub archive_entries_seen: usize,
    pub nested_archives_detected: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestionProvenance {
    pub input_kind: InputKind,
    pub outcome: IngestionOutcome,
    pub ingestion_limits: IngestionLimits,
    pub counters: ExtractionCounters,
    pub rejection_reason: Option<String>,
    pub cleanup_verified: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationStatus {
    NotRequested,
    Identified,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureMatch {
    pub offset: u64,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentificationResult {
    pub status: IdentificationStatus,
    pub tool_version: Option<String>,
    pub isolated_container: bool,
    pub signatures: Vec<SignatureMatch>,
    pub note: Option<String>,
}

impl Default for IdentificationResult {
    fn default() -> Self {
        Self {
            status: IdentificationStatus::NotRequested,
            tool_version: None,
            isolated_container: false,
            signatures: Vec::new(),
            note: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Finding,
    Hint,
}

/// Transparent candidate classification status replacing opaque confidence percentages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    ConfirmedByStructuralRule,
    LikelySecret,
    RequiresReview,
    BenignOrSuppressed,
}

impl CandidateStatus {
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::ConfirmedByStructuralRule | Self::LikelySecret)
    }
}

/// Named evidence signal and its integer policy point contribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSignal {
    pub name: String,
    pub points: i32,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub kind: FindingKind,
    pub status: CandidateStatus,
    pub policy_points: i32,
    pub signals: Vec<EvidenceSignal>,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub byte_offset: u64,
    /// Fixed redacted evidence string; never contains the raw secret value.
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuppressedCandidate {
    pub rule_id: String,
    pub category: String,
    pub status: CandidateStatus,
    pub suppression_reason: String,
    pub policy_points: i32,
    pub signals: Vec<EvidenceSignal>,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub byte_offset: u64,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileTypeClass {
    Config,
    KeyOrCert,
    Script,
    DataOrBinary,
    Documentation,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileAnalysisStatus {
    Scanned,
    Skipped,
    TruncatedOrLimited,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileInventoryEntry {
    pub path: String,
    pub file_type: FileTypeClass,
    pub size_bytes: u64,
    pub analysis_status: FileAnalysisStatus,
    pub actionable_findings: usize,
    pub review_candidates: usize,
    pub informational_hints: usize,
    pub suppressed_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedEntry {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanErrorEntry {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportMetadata {
    pub scanner_version: String,
    pub ruleset_version: String,
    pub root: String,
    pub started_unix_ms: u64,
    pub duration_ms: u64,
    pub files_scanned: usize,
    pub bytes_read: u64,
    pub limits: ScanLimits,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryCounts {
    pub total_findings: usize,
    pub actionable_findings: usize,
    pub review_candidates: usize,
    pub informational_hints: usize,
    pub suppressed_candidates: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub skipped_entries: usize,
    pub scan_errors: usize,
}

/// Complete JSON Schema 2.2 scan report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    pub schema_version: String,
    pub metadata: ReportMetadata,
    pub ingestion: IngestionProvenance,
    pub identification: IdentificationResult,
    pub summary: SummaryCounts,
    pub findings: Vec<Finding>,
    pub suppressed: Vec<SuppressedCandidate>,
    pub inventory: Vec<FileInventoryEntry>,
    pub skipped_files: Vec<SkippedEntry>,
    pub errors: Vec<ScanErrorEntry>,
    pub partial: bool,
}
