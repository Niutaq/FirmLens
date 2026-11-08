import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { computeClientReportDiff, formatDelta } from "./diff";
import {
  formatAnalysisStatus,
  formatFileType,
  formatSeverity,
  formatSuppressionReason,
  formatVectorLabel,
  RULE_CATALOG,
  UI_TEXT,
} from "./i18n";
import type { StoredScan } from "./types";

function makeMockStoredScan(
  id: string,
  filename: string,
  actionable: number,
  suppressed: number,
  partial: boolean,
): StoredScan {
  return {
    id,
    filename,
    created_unix_ms: 1700000000000,
    report: {
      schema_version: "2.1",
      metadata: {
        scanner_version: "0.2.0",
        ruleset_version: "2",
        root: filename,
        started_unix_ms: 1700000000000,
        duration_ms: 3,
        files_scanned: 4,
        bytes_read: 1024,
      },
      ingestion: {
        input_kind: "tar_archive",
        outcome: "archive_extracted",
        ingestion_limits: {
          max_input_bytes: 134217728,
          max_expanded_bytes: 268435456,
          max_member_bytes: 8388608,
          max_extracted_files: 10000,
          max_archive_entries: 20000,
          max_extraction_depth: 32,
          ingestion_timeout_ms: 30000,
        },
        counters: {
          input_bytes_read: 2048,
          expanded_stream_bytes: 2048,
          extracted_files: 4,
          extracted_directories: 3,
          archive_entries_seen: 7,
          nested_archives_detected: 0,
        },
        rejection_reason: null,
        cleanup_verified: true,
      },
      summary: {
        total_findings: actionable,
        actionable_findings: actionable,
        review_candidates: 0,
        informational_hints: 0,
        suppressed_candidates: suppressed,
        by_severity: actionable > 0 ? { high: actionable } : {},
        skipped_entries: partial ? 1 : 0,
        scan_errors: 0,
      },
      findings:
        actionable > 0
          ? [
              {
                rule_id: "FL001",
                category: "hardcoded_password",
                severity: "high",
                kind: "finding",
                status: "confirmed_by_structural_rule",
                policy_points: 100,
                signals: [
                  {
                    name: "recognized_assignment_key",
                    points: 45,
                    detail: "Recognized sensitive assignment key",
                  },
                ],
                file_path: "etc/gateway.conf",
                line_number: 5,
                byte_offset: 147,
                evidence: "password = [REDACTED]",
                explanation: "Hardcoded password",
                remediation: "Use external store",
              },
            ]
          : [],
      suppressed: [],
      inventory: [],
      skipped_files: partial
        ? [{ path: "docs/Notes.md", reason: "documentation" }]
        : [],
      errors: [],
      partial,
    },
  };
}

describe("computeClientReportDiff", () => {
  it("computes deltas and preserves partial coverage warning", () => {
    const base = makeMockStoredScan("1", "vulnerable.tar", 12, 5, true);
    const target = makeMockStoredScan("2", "hardened.tar.gz", 0, 12, true);
    const diff = computeClientReportDiff(base, target);

    assert.equal(diff.delta.actionable_delta, -12);
    assert.equal(diff.delta.suppressed_delta, 7);
    assert.equal(diff.resolved_findings.length, 1);
    assert.equal(diff.new_findings.length, 0);
    assert.ok(diff.coverage_warning?.includes("not proof of improved security"));
    assert.equal(formatDelta(diff.delta.actionable_delta), "-12");
    assert.equal(formatDelta(diff.delta.suppressed_delta), "+7");
  });

  it("maintains full EN/PL localization parity and CWE/OWASP IoT mappings for FL001–FL012", () => {
    const enKeys = Object.keys(UI_TEXT.en).sort();
    const plKeys = Object.keys(UI_TEXT.pl).sort();
    assert.deepEqual(enKeys, plKeys);

    for (let i = 1; i <= 12; i++) {
      const ruleId = `FL${String(i).padStart(3, "0")}`;
      const meta = RULE_CATALOG[ruleId];
      assert.ok(meta, `Missing RULE_CATALOG entry for ${ruleId}`);
      assert.ok(meta.cwe.startsWith("CWE-"));
      assert.ok(meta.owaspIot.startsWith("OWASP IoT"));
      assert.ok(meta.etsi.startsWith("ETSI EN 303 645"));
      assert.ok(meta.subject.en.length > 0 && meta.subject.pl.length > 0);
      assert.ok(!meta.subject.en.includes("(") && !meta.subject.pl.includes("("));
      assert.ok(meta.explanation.en.length > 0 && meta.explanation.pl.length > 0);
      assert.ok(meta.remediation.en.length > 0 && meta.remediation.pl.length > 0);
    }

    for (const navKey of ["dashboard", "findings", "files", "diff"] as const) {
      assert.ok(!UI_TEXT.en[navKey].includes("("));
      assert.ok(!UI_TEXT.pl[navKey].includes("("));
    }

    assert.equal(formatFileType("config", "pl"), "Konfiguracja");
    assert.equal(formatFileType("other", "pl"), "Inny");
    assert.equal(formatAnalysisStatus("scanned", "pl"), "Przeskanowany");
    assert.equal(formatSeverity("high", "pl"), "WYSOKIE");
    assert.equal(formatSuppressionReason("env_or_template_reference", "pl"), "Zmienna środowiskowa / Szablon");
    assert.equal(formatVectorLabel("auth", "pl"), "Autoryzacja");
  });
});
