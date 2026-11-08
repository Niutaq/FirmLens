# Reporting & JSON Schema 2.1

FirmLens emits deterministic reports in JSON Schema `2.1` (`SCHEMA_VERSION = "2.1"`). Schema `2.1` preserves all Schema `2.0` fields (policy-point evidence signals, candidate status classification, ingestion provenance, and optional Binwalk identification) and adds a bounded `inventory` (`Vec<FileInventoryEntry>`) so CLI and web consumers can inspect per-file scan outcomes.

## 1. Top-Level `ScanReport` Structure

- `schema_version`: `"2.1"`
- `metadata`: `ReportMetadata` containing `scanner_version` (`"0.2.0"`), `ruleset_version` (`"2"`), `root`, `started_unix_ms`, `duration_ms`, `files_scanned`, `bytes_read`, and `limits` (`ScanLimits`: `max_file_bytes`, `max_total_bytes`, `max_entries`, `max_depth`, `max_record_bytes`, `max_findings`).
- `ingestion`: `IngestionProvenance` describing `input_kind` (`directory`, `tar_archive`, `tar_gz_archive`, `binary_image`), `outcome` (`directory_scanned`, `archive_extracted`, `rejected_archive`, `unsupported_image`), `ingestion_limits` (`IngestionLimits`), `counters` (`ExtractionCounters`), `rejection_reason`, and `cleanup_verified`.
- `identification`: `IdentificationResult` for optional isolated Binwalk v3 signature detection (`status`: `not_requested`, `identified`, `unavailable`, `failed`; `tool_version`, `isolated_container`, `signatures`, `note`).
- `summary`: `SummaryCounts` with explicit counts for `total_findings`, `actionable_findings`, `review_candidates`, `informational_hints`, `suppressed_candidates`, `by_severity`, `skipped_entries`, and `scan_errors`.
- `findings`: Deterministically ordered `Vec<Finding>` containing actionable (`confirmed_by_structural_rule`, `likely_secret`), review (`requires_review`), and hint (`kind = "hint"`) items.
- `suppressed`: Deterministically ordered `Vec<SuppressedCandidate>` with explicit `suppression_reason` and redacted `evidence`.
- `inventory`: Bounded `Vec<FileInventoryEntry>` listing relative `path`, `file_type` (`config`, `key_or_cert`, `script`, `data_or_binary`, `documentation`, `other`), `size_bytes`, `analysis_status` (`scanned`, `skipped`, `truncated_or_limited`, `error`), and per-file finding/suppressed counters.
- `skipped_files` & `errors`: Explicit records (`Vec<SkippedEntry>` and `Vec<ScanErrorEntry>`) for every excluded/skipped path and non-fatal traversal error.
- `partial`: `bool` — `true` if **any** file was excluded or skipped, any scan/ingestion error occurred, an archive was rejected or unsupported, a budget was exhausted, or a nested archive was not expanded.

## 2. CLI Exit Codes

| Exit Code | Condition |
| --- | --- |
| `0` | Full scoped scan (`partial == false`) and either `--fail-on-findings` was not set or `actionable_findings == 0`. |
| `1` | Fatal runtime error (non-existent input path, invalid CLI limit, or `--output` target already exists / cannot be written). |
| `2` | Partial coverage (`partial == true`) due to any exclusion, skip, rejected archive, unsupported image, or nested archive; or `clap` CLI argument syntax error. |
| `3` | Full scoped scan (`partial == false`), `--fail-on-findings` is set, and `actionable_findings > 0`. |

> **Precedence Rule:** Partial coverage (`2`) always takes precedence over `--fail-on-findings` (`3`) so incomplete visibility is never mistaken for a complete scan.
