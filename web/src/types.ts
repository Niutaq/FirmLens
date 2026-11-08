export type Severity = "high" | "medium" | "low" | "info";
export type FindingKind = "finding" | "hint";
export type CandidateStatus =
  | "confirmed_by_structural_rule"
  | "likely_secret"
  | "requires_review"
  | "benign_or_suppressed";

export type InputKind =
  | "directory"
  | "tar_archive"
  | "tar_gz_archive"
  | "binary_image";

export type IngestionOutcome =
  | "directory_scanned"
  | "archive_extracted"
  | "rejected_archive"
  | "unsupported_image";

export type FileTypeClass =
  | "config"
  | "key_or_cert"
  | "script"
  | "data_or_binary"
  | "documentation"
  | "other";

export type FileAnalysisStatus =
  | "scanned"
  | "skipped"
  | "truncated_or_limited"
  | "error";

export interface EvidenceSignal {
  name: string;
  points: number;
  detail: string;
}

export interface Finding {
  rule_id: string;
  category: string;
  severity: Severity;
  kind: FindingKind;
  status: CandidateStatus;
  policy_points: number;
  signals: EvidenceSignal[];
  file_path: string;
  line_number: number | null;
  byte_offset: number;
  evidence: string;
  explanation: string;
  remediation: string;
}

export interface SuppressedCandidate {
  rule_id: string;
  category: string;
  status: CandidateStatus;
  suppression_reason: string;
  policy_points: number;
  signals: EvidenceSignal[];
  file_path: string;
  line_number: number | null;
  byte_offset: number;
  evidence: string;
}

export interface FileInventoryEntry {
  path: string;
  file_type: FileTypeClass;
  size_bytes: number;
  analysis_status: FileAnalysisStatus;
  actionable_findings: number;
  review_candidates: number;
  informational_hints: number;
  suppressed_candidates: number;
}

export interface SkippedEntry {
  path: string;
  reason: string;
}

export interface ScanErrorEntry {
  path: string;
  code: string;
  message: string;
}

export interface SummaryCounts {
  total_findings: number;
  actionable_findings: number;
  review_candidates: number;
  informational_hints: number;
  suppressed_candidates: number;
  by_severity: Record<string, number>;
  skipped_entries: number;
  scan_errors: number;
}

export interface IngestionProvenance {
  input_kind: InputKind;
  outcome: IngestionOutcome;
  ingestion_limits: {
    max_input_bytes: number;
    max_expanded_bytes: number;
    max_member_bytes: number;
    max_extracted_files: number;
    max_archive_entries: number;
    max_extraction_depth: number;
    ingestion_timeout_ms: number;
  };
  counters: {
    input_bytes_read: number;
    expanded_stream_bytes: number;
    extracted_files: number;
    extracted_directories: number;
    archive_entries_seen: number;
    nested_archives_detected: number;
  };
  rejection_reason: string | null;
  cleanup_verified: boolean;
}

export interface ScanReport {
  schema_version: string;
  metadata: {
    scanner_version: string;
    ruleset_version: string;
    root: string;
    started_unix_ms: number;
    duration_ms: number;
    files_scanned: number;
    bytes_read: number;
  };
  ingestion: IngestionProvenance;
  summary: SummaryCounts;
  findings: Finding[];
  suppressed: SuppressedCandidate[];
  inventory: FileInventoryEntry[];
  skipped_files: SkippedEntry[];
  errors: ScanErrorEntry[];
  partial: boolean;
}

export interface StoredScan {
  id: string;
  filename: string;
  created_unix_ms: number;
  report: ScanReport;
}

export interface DiffDeltaCounts {
  actionable_delta: number;
  review_delta: number;
  hints_delta: number;
  suppressed_delta: number;
  skipped_delta: number;
  files_scanned_delta: number;
}

export interface DiffResponse {
  base_id: string;
  base_filename: string;
  target_id: string;
  target_filename: string;
  base_partial: boolean;
  target_partial: boolean;
  coverage_warning: string | null;
  delta: DiffDeltaCounts;
  resolved_findings: Finding[];
  new_findings: Finding[];
  unchanged_findings: Finding[];
}
