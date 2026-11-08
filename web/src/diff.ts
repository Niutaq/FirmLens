import type { DiffResponse, Finding, StoredScan } from "./types";

function findingIdentityKey(f: Finding): string {
  return `${f.file_path}::${f.rule_id}::${f.byte_offset}::${f.kind}::${f.status}`;
}

export function computeClientReportDiff(
  base: StoredScan,
  target: StoredScan,
): DiffResponse {
  const baseMap = new Map<string, Finding>();
  for (const f of base.report.findings) {
    baseMap.set(findingIdentityKey(f), f);
  }

  const targetMap = new Map<string, Finding>();
  for (const f of target.report.findings) {
    targetMap.set(findingIdentityKey(f), f);
  }

  const resolved_findings: Finding[] = [];
  const unchanged_findings: Finding[] = [];
  for (const [k, f] of baseMap.entries()) {
    if (targetMap.has(k)) {
      unchanged_findings.push(f);
    } else {
      resolved_findings.push(f);
    }
  }

  const new_findings: Finding[] = [];
  for (const [k, f] of targetMap.entries()) {
    if (!baseMap.has(k)) {
      new_findings.push(f);
    }
  }

  const coverage_warning =
    base.report.partial || target.report.partial
      ? "One or both reports have partial coverage (excluded files, errors, or unexpanded archives). Fewer findings in a partial scan is not proof of improved security."
      : null;

  return {
    base_id: base.id,
    base_filename: base.filename,
    target_id: target.id,
    target_filename: target.filename,
    base_partial: base.report.partial,
    target_partial: target.report.partial,
    coverage_warning,
    delta: {
      actionable_delta:
        target.report.summary.actionable_findings -
        base.report.summary.actionable_findings,
      review_delta:
        target.report.summary.review_candidates -
        base.report.summary.review_candidates,
      hints_delta:
        target.report.summary.informational_hints -
        base.report.summary.informational_hints,
      suppressed_delta:
        target.report.summary.suppressed_candidates -
        base.report.summary.suppressed_candidates,
      skipped_delta:
        target.report.summary.skipped_entries -
        base.report.summary.skipped_entries,
      files_scanned_delta:
        target.report.metadata.files_scanned -
        base.report.metadata.files_scanned,
    },
    resolved_findings,
    new_findings,
    unchanged_findings,
  };
}

export function formatDelta(n: number): string {
  if (n > 0) return `+${n}`;
  return `${n}`;
}
