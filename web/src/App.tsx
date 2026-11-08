import React, { useEffect, useRef, useState } from "react";
import type { DiffResponse, Finding, ScanReport, StoredScan, SuppressedCandidate } from "./types";
import { computeClientReportDiff, formatDelta } from "./diff";
import {
  formatAnalysisStatus,
  formatFileType,
  formatSeverity,
  formatSuppressionReason,
  formatVectorLabel,
  type Locale,
  RULE_CATALOG,
  UI_TEXT,
} from "./i18n";

type ActiveTab = "overview" | "findings" | "files" | "diff";
type FindingFilter = "all" | "actionable" | "review" | "hints" | "suppressed";

interface HistoryNavState {
  tab: ActiveTab;
  file: string | null;
  focusedKey: string | null;
  filter: FindingFilter;
  query: string;
}

function BrandLogoSvg() {
  return (
    <svg width="30" height="30" viewBox="0 0 1024 1024" role="img" aria-label="FirmLens Icon">
      <defs>
        <path
          id="fl-blade"
          d="M805 242 C520 310 172 520 172 770 C172 815 190 855 218 884 L560 884 C380 884 290 800 290 700 C290 540 520 360 805 242 Z"
        />
        <mask id="fl-gap" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024">
          <rect width="1024" height="1024" fill="#FFFFFF" />
          <use
            href="#fl-blade"
            fill="#000000"
            stroke="#000000"
            strokeWidth="44"
            strokeLinejoin="round"
          />
        </mask>
      </defs>
      <g mask="url(#fl-gap)">
        <polygon points="512,140 218,405 218,884 512,884" fill="#2A2F38" />
        <polygon points="512,140 805,405 805,884 512,884" fill="#121722" />
      </g>
      <use href="#fl-blade" fill="#08CE88" />
    </svg>
  );
}

function NavIcon({ tab }: { tab: ActiveTab }) {
  if (tab === "overview") {
    return (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </svg>
    );
  }
  if (tab === "findings") {
    return (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    );
  }
  if (tab === "files") {
    return (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
        <polyline points="16 18 22 12 16 6" />
        <polyline points="8 6 2 12 8 18" />
      </svg>
    );
  }
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
      <line x1="18" y1="20" x2="18" y2="10" />
      <line x1="12" y1="20" x2="12" y2="4" />
      <line x1="6" y1="20" x2="6" y2="14" />
    </svg>
  );
}

function makeFindingKey(ruleId: string, filePath: string, byteOffset: number, lineNumber: number | null): string {
  return `${filePath}::${lineNumber ?? 0}::${byteOffset}::${ruleId}`;
}

function getProblemTitle(ruleId: string, fallback: string, lang: Locale): string {
  const meta = RULE_CATALOG[ruleId];
  return meta ? meta.subject[lang] : fallback;
}

function PostureDonutCard({
  report,
  lang,
  onSelectFilter,
}: {
  report: ScanReport;
  lang: Locale;
  onSelectFilter: (filter: FindingFilter) => void;
}) {
  const t = UI_TEXT[lang];
  const actionable = report.summary.actionable_findings;
  const reviewAndHints =
    report.summary.review_candidates + report.summary.informational_hints;
  const suppressed = report.summary.suppressed_candidates;
  const total = actionable + reviewAndHints + suppressed;

  const radius = 54;
  const circumference = 2 * Math.PI * radius;

  const supLen = total > 0 ? (suppressed / total) * circumference : circumference;
  const actLen = total > 0 ? (actionable / total) * circumference : 0;
  const revLen = total > 0 ? (reviewAndHints / total) * circumference : 0;

  return (
    <div className="white-card">
      <div className="card-title-row">
        <h3 className="card-title">{t.postureTitle}</h3>
      </div>
      <div className="donut-stage">
        <svg width="148" height="148" viewBox="0 0 160 160" role="img" aria-label={t.postureTitle}>
          <circle cx="80" cy="80" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="15" />
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="none"
            stroke="#2ce59b"
            strokeWidth="15"
            strokeDasharray={`${supLen} ${circumference}`}
            strokeDashoffset={0}
            transform="rotate(-90 80 80)"
            style={{ cursor: "pointer" }}
            onClick={() => onSelectFilter("suppressed")}
          />
          {revLen > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="#f59e0b"
              strokeWidth="15"
              strokeDasharray={`${revLen} ${circumference}`}
              strokeDashoffset={-supLen}
              transform="rotate(-90 80 80)"
              style={{ cursor: "pointer" }}
              onClick={() =>
                onSelectFilter(report.summary.review_candidates > 0 ? "review" : "hints")
              }
            />
          )}
          {actLen > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="#ff5c77"
              strokeWidth="15"
              strokeDasharray={`${actLen} ${circumference}`}
              strokeDashoffset={-(supLen + revLen)}
              transform="rotate(-90 80 80)"
              style={{ cursor: "pointer" }}
              onClick={() => onSelectFilter("actionable")}
            />
          )}
          <text x="80" y="82" textAnchor="middle" fill="#111827" fontSize="28" fontWeight="800">
            {total}
          </text>
          <text x="80" y="100" textAnchor="middle" fill="#6b7280" fontSize="9.5" fontWeight="600">
            {t.candidatesLabel}
          </text>
        </svg>
      </div>
      <div className="legend-row">
        <button type="button" className="legend-btn" onClick={() => onSelectFilter("actionable")}>
          <span className="status-dot status-dot-danger" /> {t.actionableLegend}: <strong>{actionable}</strong>
        </button>
        <button type="button" className="legend-btn" onClick={() => onSelectFilter("suppressed")}>
          <span className="status-dot status-dot-safe" /> {t.suppressedLegend}: <strong>{suppressed}</strong>
        </button>
        {reviewAndHints > 0 && (
          <button
            type="button"
            className="legend-btn"
            onClick={() =>
              onSelectFilter(report.summary.review_candidates > 0 ? "review" : "hints")
            }
          >
            <span className="status-dot status-dot-warn" /> {t.reviewHintLegend}: <strong>{reviewAndHints}</strong>
          </button>
        )}
      </div>
    </div>
  );
}

function VectorTasksBarCard({
  report,
  lang,
  onSelectVector,
}: {
  report: ScanReport;
  lang: Locale;
  onSelectVector: (vectorKey: "auth" | "cloud" | "tls" | "net" | "safe") => void;
}) {
  const t = UI_TEXT[lang];
  const counts = {
    auth: 0,
    cloud: 0,
    tls: 0,
    net: 0,
    safe: report.summary.suppressed_candidates,
  };

  for (const f of report.findings) {
    if (f.rule_id === "FL001" || f.rule_id === "FL004" || f.rule_id === "FL005") {
      counts.auth += 1;
    } else if (
      f.rule_id === "FL002" ||
      f.rule_id === "FL010" ||
      f.rule_id === "FL011" ||
      f.rule_id === "FL012"
    ) {
      counts.cloud += 1;
    } else if (f.rule_id === "FL003" || f.rule_id === "FL007") {
      counts.tls += 1;
    } else {
      counts.net += 1;
    }
  }

  const items: Array<{
    key: "auth" | "cloud" | "tls" | "net" | "safe";
    label: string;
    value: number;
    color: string;
  }> = [
    { key: "auth", label: formatVectorLabel("auth", lang), value: counts.auth, color: "#ff5c77" },
    { key: "cloud", label: formatVectorLabel("cloud", lang), value: counts.cloud, color: "#6366f1" },
    { key: "tls", label: formatVectorLabel("tls", lang), value: counts.tls, color: "#f59e0b" },
    { key: "net", label: formatVectorLabel("net", lang), value: counts.net, color: "#32d2f2" },
    { key: "safe", label: formatVectorLabel("safe", lang), value: counts.safe, color: "#2ce59b" },
  ];

  const maxScale = Math.max(8, ...items.map((i) => i.value));

  return (
    <div className="white-card">
      <div className="card-title-row">
        <h3 className="card-title">{t.vectorsTitle}</h3>
      </div>
      <div className="bar-chart-stage">
        <div className="y-axis">
          <span>{maxScale}</span>
          <span>{Math.round(maxScale / 2)}</span>
          <span>0</span>
        </div>
        <div className="bars-plot">
          {items.map((item) => {
            const pct = Math.max(16, Math.round((item.value / maxScale) * 100));
            return (
              <button
                key={item.key}
                type="button"
                className="bar-col bar-col-interactive"
                onClick={() => onSelectVector(item.key)}
                title={`${item.label}: ${item.value}`}
              >
                <div
                  className="bar-fill"
                  style={{
                    height: `${pct}%`,
                    background: item.color,
                  }}
                >
                  {item.value}
                </div>
                <span className="bar-x-label">{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function CompactFileTreeCard({
  report,
  lang,
  onSelectFile,
}: {
  report: ScanReport;
  lang: Locale;
  onSelectFile: (filePath: string) => void;
}) {
  const t = UI_TEXT[lang];
  return (
    <div className="white-card">
      <div className="card-title-row">
        <h3 className="card-title">{t.selectedTreeTitle}</h3>
        <span className="badge badge-info">{report.inventory.length}</span>
      </div>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "4px",
          overflowY: "auto",
          maxHeight: "190px",
        }}
      >
        {report.inventory.map((entry) => {
          const isVuln = entry.actionable_findings > 0;
          const isSkipped = entry.analysis_status !== "scanned";
          return (
            <button
              key={entry.path}
              type="button"
              className="inspector-tree-item"
              onClick={() => onSelectFile(entry.path)}
            >
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.45rem",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                <span
                  className={`status-dot ${
                    isVuln
                      ? "status-dot-danger"
                      : isSkipped
                        ? "status-dot-warn"
                        : "status-dot-safe"
                  }`}
                />
                <span className="mono-path-text">{entry.path}</span>
              </span>
              <span style={{ color: "#6b7280", fontWeight: 700, fontSize: "0.72rem" }}>
                {entry.actionable_findings > 0
                  ? `${entry.actionable_findings}`
                  : entry.suppressed_candidates > 0
                    ? t.kpiSuppressed
                    : formatAnalysisStatus(entry.analysis_status, lang)}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function SonarCodeInspector({
  report,
  selectedFilePath,
  focusedFindingKey,
  lang,
  onViewFindingsTab,
}: {
  report: ScanReport;
  selectedFilePath: string | null;
  focusedFindingKey: string | null;
  lang: Locale;
  onViewFindingsTab: (filePath: string) => void;
}) {
  const t = UI_TEXT[lang];
  const focusedRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (focusedFindingKey && focusedRef.current) {
      focusedRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [focusedFindingKey, selectedFilePath]);

  const activePath =
    selectedFilePath && report.inventory.some((i) => i.path === selectedFilePath)
      ? selectedFilePath
      : report.inventory.find((i) => i.actionable_findings > 0)?.path ??
        report.inventory[0]?.path ??
        null;

  if (!activePath) {
    return (
      <div className="sonar-inspector-card">
        <p className="subtitle">{t.codeInspectorEmpty}</p>
      </div>
    );
  }

  const fileMeta = report.inventory.find((i) => i.path === activePath);
  const fileFindings: Finding[] = report.findings.filter((f) => f.file_path === activePath);
  const fileSuppressed: SuppressedCandidate[] = report.suppressed.filter(
    (s) => s.file_path === activePath,
  );

  type CodeAnnotationItem =
    | { kind: "finding"; data: Finding; key: string; sortLine: number }
    | { kind: "suppressed"; data: SuppressedCandidate; key: string; sortLine: number };

  const items: CodeAnnotationItem[] = [
    ...fileFindings.map((f) => ({
      kind: "finding" as const,
      data: f,
      key: makeFindingKey(f.rule_id, f.file_path, f.byte_offset, f.line_number),
      sortLine: f.line_number ?? f.byte_offset,
    })),
    ...fileSuppressed.map((s) => ({
      kind: "suppressed" as const,
      data: s,
      key: makeFindingKey(s.rule_id, s.file_path, s.byte_offset, s.line_number),
      sortLine: s.line_number ?? s.byte_offset,
    })),
  ].sort((a, b) => a.sortLine - b.sortLine);

  return (
    <div className="sonar-inspector-card" data-testid="sonar-code-inspector">
      <div className="sonar-file-header">
        <div className="sonar-file-title-group">
          <span className="sonar-file-icon" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
          </span>
          <code className="sonar-file-path">{activePath}</code>
          {fileMeta && (
            <>
              <span className="std-pill">{formatFileType(fileMeta.file_type, lang)}</span>
              <span className="std-pill">{fileMeta.size_bytes} B</span>
            </>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          {fileFindings.length > 0 && (
            <button
              type="button"
              className="btn"
              style={{ fontSize: "0.74rem", padding: "0.3rem 0.65rem" }}
              onClick={() => onViewFindingsTab(activePath)}
            >
              {t.viewAllFindingsInFile}
            </button>
          )}
        </div>
      </div>

      <div className="sonar-code-viewport">
        {items.length === 0 ? (
          <div className="sonar-empty-file-state">
            <span
              className={`status-dot ${
                fileMeta?.analysis_status === "scanned" ? "status-dot-safe" : "status-dot-warn"
              }`}
            />
            <span>
              {fileMeta?.analysis_status === "scanned"
                ? t.cleanFileMessage
                : t.skippedFileMessage}
            </span>
          </div>
        ) : (
          items.map((item) => {
            const isFocused = focusedFindingKey === item.key;
            if (item.kind === "finding") {
              const f = item.data;
              const meta = RULE_CATALOG[f.rule_id];
              const problemName = getProblemTitle(f.rule_id, f.category, lang);
              const lineNo = f.line_number;
              const prevLine = lineNo && lineNo > 1 ? lineNo - 1 : null;
              const nextLine = lineNo ? lineNo + 1 : null;

              return (
                <div
                  key={item.key}
                  ref={isFocused ? focusedRef : undefined}
                  className={`sonar-snippet-block ${
                    isFocused ? "sonar-snippet-focused" : ""
                  }`}
                  data-testid="sonar-snippet-block"
                >
                  <div className="sonar-code-lines">
                    {prevLine !== null && (
                      <div className="sonar-code-line sonar-code-line-context">
                        <span className="sonar-line-num">{prevLine}</span>
                        <span className="sonar-line-code"># ...</span>
                      </div>
                    )}
                    <div className="sonar-code-line sonar-code-line-vuln">
                      <span className="sonar-line-num">
                        {lineNo !== null ? lineNo : `@${f.byte_offset}`}
                      </span>
                      <span className="sonar-line-code">
                        <span className="sonar-vuln-wave">{f.evidence}</span>
                      </span>
                    </div>
                    {nextLine !== null && (
                      <div className="sonar-code-line sonar-code-line-context">
                        <span className="sonar-line-num">{nextLine}</span>
                        <span className="sonar-line-code"># ...</span>
                      </div>
                    )}
                  </div>

                  {/* SonarCloud / SonarQube Inline Issue Callout Box */}
                  <div className="sonar-issue-box sonar-issue-box-vuln">
                    <div className="sonar-issue-header">
                      <div className="sonar-issue-title-wrap">
                        <span className={`badge badge-${f.severity}`}>
                          {formatSeverity(f.severity, lang)}
                        </span>
                        <strong className="sonar-issue-title">{problemName}</strong>
                      </div>
                      <div className="sonar-issue-tags">
                        {meta && (
                          <>
                            <span className="std-pill">{meta.cwe}</span>
                            <span className="std-pill">{meta.owaspIot}</span>
                            <span className="std-pill">{meta.etsi}</span>
                          </>
                        )}
                      </div>
                    </div>
                    <p className="sonar-issue-desc">
                      {meta ? meta.explanation[lang] : f.explanation}
                    </p>
                    <div className="sonar-issue-remediation">
                      <strong>{t.remediationLabel}</strong>{" "}
                      {meta ? meta.remediation[lang] : f.remediation}
                    </div>
                  </div>
                </div>
              );
            }

            const s = item.data;
            const meta = RULE_CATALOG[s.rule_id];
            const problemName = getProblemTitle(
              s.rule_id,
              formatSuppressionReason(s.suppression_reason, lang),
              lang,
            );
            const lineNo = s.line_number;

            return (
              <div
                key={item.key}
                ref={isFocused ? focusedRef : undefined}
                className={`sonar-snippet-block ${
                  isFocused ? "sonar-snippet-focused" : ""
                }`}
              >
                <div className="sonar-code-lines">
                  <div className="sonar-code-line sonar-code-line-safe">
                    <span className="sonar-line-num">
                      {lineNo !== null ? lineNo : `@${s.byte_offset}`}
                    </span>
                    <span className="sonar-line-code">{s.evidence}</span>
                  </div>
                </div>
                <div className="sonar-issue-box sonar-issue-box-safe">
                  <div className="sonar-issue-header">
                    <div className="sonar-issue-title-wrap">
                      <span className="badge badge-info">
                        {formatSuppressionReason(s.suppression_reason, lang)}
                      </span>
                      <strong className="sonar-issue-title">{problemName}</strong>
                    </div>
                    {meta && <span className="std-pill">{meta.cwe}</span>}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export function App() {
  const [lang, setLang] = useState<Locale>(() => {
    try {
      const saved = window.localStorage.getItem("firmlens_lang");
      if (saved === "pl" || saved === "en") return saved;
    } catch {
      // ignore
    }
    return "en";
  });

  const [scans, setScans] = useState<StoredScan[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("overview");
  const [uploading, setUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [findingFilter, setFindingFilter] = useState<FindingFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [fileStatusFilter, setFileStatusFilter] = useState<string>("all");

  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [focusedFindingKey, setFocusedFindingKey] = useState<string | null>(null);

  const [diffBaseId, setDiffBaseId] = useState<string>("");
  const [diffTargetId, setDiffTargetId] = useState<string>("");
  const [apiDiff, setApiDiff] = useState<DiffResponse | null>(null);

  const [showRulesModal, setShowRulesModal] = useState(false);

  const t = UI_TEXT[lang];
  const selectedScan = scans.find((s) => s.id === selectedId) ?? scans[0] ?? null;

  // Sync navigation state with Browser History so Mouse 4 (Back) and Mouse 5 (Forward) work natively
  function pushNavHistory(next: Partial<HistoryNavState>) {
    const state: HistoryNavState = {
      tab: next.tab ?? activeTab,
      file: next.file !== undefined ? next.file : selectedFilePath,
      focusedKey: next.focusedKey !== undefined ? next.focusedKey : focusedFindingKey,
      filter: next.filter ?? findingFilter,
      query: next.query !== undefined ? next.query : searchQuery,
    };
    setActiveTab(state.tab);
    setSelectedFilePath(state.file);
    setFocusedFindingKey(state.focusedKey);
    setFindingFilter(state.filter);
    setSearchQuery(state.query);
    try {
      const url = `#${state.tab}${state.file ? `:${encodeURIComponent(state.file)}` : ""}`;
      window.history.pushState(state, "", url);
    } catch {
      // ignore in restricted environments
    }
  }

  useEffect(() => {
    try {
      const initial: HistoryNavState = {
        tab: "overview",
        file: null,
        focusedKey: null,
        filter: "all",
        query: "",
      };
      window.history.replaceState(initial, "");
    } catch {
      // ignore
    }

    function onPopState(ev: PopStateEvent) {
      const st = ev.state as HistoryNavState | null;
      if (st && st.tab) {
        setActiveTab(st.tab);
        setSelectedFilePath(st.file ?? null);
        setFocusedFindingKey(st.focusedKey ?? null);
        setFindingFilter(st.filter ?? "all");
        setSearchQuery(st.query ?? "");
      }
    }

    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  function changeLanguage(next: Locale) {
    setLang(next);
    try {
      window.localStorage.setItem("firmlens_lang", next);
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    void refreshScans();
    const timer = window.setInterval(() => {
      void refreshScans();
    }, 3000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (scans.length >= 2 && (!diffBaseId || !diffTargetId)) {
      const oldest = scans[scans.length - 1];
      const newest = scans[0];
      if (oldest && newest && oldest.id !== newest.id) {
        setDiffBaseId(oldest.id);
        setDiffTargetId(newest.id);
      }
    }
  }, [scans, diffBaseId, diffTargetId]);

  useEffect(() => {
    if (activeTab === "diff" && diffBaseId && diffTargetId) {
      void fetchDiff(diffBaseId, diffTargetId);
    }
  }, [activeTab, diffBaseId, diffTargetId]);

  async function refreshScans() {
    try {
      const res = await fetch("/api/scans");
      if (!res.ok) return;
      const list: Array<{ id: string }> = await res.json();
      const loaded: StoredScan[] = [];
      for (const item of list) {
        const detailRes = await fetch(`/api/scans/${encodeURIComponent(item.id)}`);
        if (detailRes.ok) {
          loaded.push((await detailRes.json()) as StoredScan);
        }
      }
      setScans(loaded);
      setSelectedId((prev) => {
        if (prev && loaded.some((s) => s.id === prev)) return prev;
        return loaded[0]?.id ?? null;
      });
    } catch {
      // Offline or API not started yet
    }
  }

  async function handleDeleteScan(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    try {
      await fetch(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
    } catch {
      // ignore
    }
    setScans((prev) => {
      const remaining = prev.filter((s) => s.id !== id);
      if (selectedId === id) {
        setSelectedId(remaining[0]?.id ?? null);
      }
      return remaining;
    });
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    setErrorMsg(null);
    setUploading(true);

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const res = await fetch(
          `/api/scans?filename=${encodeURIComponent(file.name)}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/octet-stream",
              "X-Filename": file.name,
            },
            body: file,
          },
        );
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({ error: res.statusText }));
          throw new Error(errBody.error || `Upload failed: ${res.status}`);
        }
        const created = (await res.json()) as StoredScan;
        setScans((prev) => [created, ...prev.filter((p) => p.id !== created.id)].slice(0, 8));
        setSelectedId(created.id);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  }

  async function fetchDiff(baseId: string, targetId: string) {
    try {
      const res = await fetch(
        `/api/diff?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`,
      );
      if (res.ok) {
        setApiDiff((await res.json()) as DiffResponse);
        return;
      }
    } catch {
      // Fallback
    }
    const b = scans.find((s) => s.id === baseId);
    const tScan = scans.find((s) => s.id === targetId);
    if (b && tScan) {
      setApiDiff(computeClientReportDiff(b, tScan));
    }
  }

  function handleExportJson(scan: StoredScan) {
    const blob = new Blob([JSON.stringify(scan.report, null, 2) + "\n"], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stem = scan.filename.replace(/(\.tar\.gz|\.tgz|\.tar)$/i, "");
    a.download = `${stem}.firmlens.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function handleOpenInFileInspector(
    filePath: string,
    ruleId?: string,
    byteOffset?: number,
    lineNumber?: number | null,
  ) {
    const key =
      ruleId !== undefined && byteOffset !== undefined
        ? makeFindingKey(ruleId, filePath, byteOffset, lineNumber ?? null)
        : null;
    pushNavHistory({
      tab: "files",
      file: filePath,
      focusedKey: key,
    });
  }

  function handleJumpToFileFindings(filePath: string) {
    pushNavHistory({
      tab: "findings",
      filter: "all",
      query: filePath,
    });
  }

  function handleSelectRuleFilter(ruleSubject: string) {
    setShowRulesModal(false);
    pushNavHistory({
      tab: "findings",
      filter: "all",
      query: ruleSubject,
    });
  }

  function handleSelectVectorFilter(vectorKey: "auth" | "cloud" | "tls" | "net" | "safe") {
    if (vectorKey === "safe") {
      pushNavHistory({
        tab: "findings",
        filter: "suppressed",
        query: "",
      });
      return;
    }
    pushNavHistory({
      tab: "findings",
      filter: "all",
      query: `vector:${vectorKey}`,
    });
  }

  function matchesSearchQuery(ruleId: string, filePath: string, extraText: string): boolean {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return true;
    if (q.startsWith("vector:")) {
      const vec = q.slice("vector:".length);
      const meta = RULE_CATALOG[ruleId];
      return meta?.vector === vec;
    }
    const meta = RULE_CATALOG[ruleId];
    const stdText = meta ? `${meta.cwe} ${meta.owaspIot} ${meta.subject.en} ${meta.subject.pl}` : "";
    return `${ruleId} ${filePath} ${extraText} ${stdText}`.toLowerCase().includes(q);
  }

  return (
    <div className="app-shell-top">
      {/* Full-Width Top Navigation Deck */}
      <header className="top-command-header">
        <div className="top-command-inner">
          <div className="brand-block">
            <div className="brand-logo-mark" aria-hidden="true">
              <BrandLogoSvg />
            </div>
            <h1>FirmLens</h1>
          </div>

          <nav className="top-nav-dock" aria-label="Report views">
            {(["overview", "findings", "files", "diff"] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                className={`top-nav-tab ${activeTab === tab ? "active" : ""}`}
                onClick={() => pushNavHistory({ tab })}
                data-testid={`tab-${tab}`}
              >
                <NavIcon tab={tab} />
                <span>
                  {tab === "overview" && t.dashboard}
                  {tab === "findings" && t.findings}
                  {tab === "files" && t.files}
                  {tab === "diff" && t.diff}
                </span>
                {selectedScan && tab === "findings" && (
                  <span className="top-nav-pill">
                    {selectedScan.report.findings.length +
                      selectedScan.report.suppressed.length}
                  </span>
                )}
                {selectedScan && tab === "files" && (
                  <span className="top-nav-pill">{selectedScan.report.inventory.length}</span>
                )}
              </button>
            ))}
          </nav>

          <div className="top-command-actions">
            <label htmlFor="archive-upload-input" className="btn btn-primary top-upload-btn">
              {uploading ? t.uploading : `+ ${t.uploadBtn}`}
            </label>
            <input
              id="archive-upload-input"
              data-testid="archive-upload-input"
              type="file"
              accept=".tar,.tar.gz,.tgz"
              multiple
              onChange={handleFileUpload}
              disabled={uploading}
              style={{ display: "none" }}
            />

            <button
              type="button"
              className="top-action-btn"
              onClick={() => setShowRulesModal(true)}
              data-testid="open-rules-modal-btn"
            >
              {t.rulesCatalogBtn}
            </button>

            <div className="lang-switch" role="group" aria-label="Language selector">
              <button
                type="button"
                className={`lang-btn ${lang === "en" ? "active" : ""}`}
                onClick={() => changeLanguage("en")}
                data-testid="lang-toggle-en"
              >
                EN
              </button>
              <button
                type="button"
                className={`lang-btn ${lang === "pl" ? "active" : ""}`}
                onClick={() => changeLanguage("pl")}
                data-testid="lang-toggle-pl"
              >
                PL
              </button>
            </div>

            {selectedScan && (
              <button
                type="button"
                className="top-action-btn"
                onClick={() => handleExportJson(selectedScan)}
                data-testid="export-json-btn"
              >
                {t.exportJson}
              </button>
            )}
          </div>
        </div>

        {/* Sleek Horizontal Retained Scans Switcher Bar */}
        <div className="scans-ribbon">
          <div className="scans-ribbon-inner">
            <span className="scans-ribbon-label">
              {t.retainedScans}: {scans.length}/8
            </span>
            {scans.length === 0 ? (
              <span className="scans-ribbon-empty">{t.emptyScansHint}</span>
            ) : (
              <ul className="scans-pill-list" data-testid="retained-scans-list">
                {scans.map((s) => {
                  const actCount = s.report.summary.actionable_findings;
                  return (
                    <li
                      key={s.id}
                      className={`scan-pill-item ${selectedScan?.id === s.id ? "active" : ""}`}
                      onClick={() => setSelectedId(s.id)}
                      data-testid={`scan-item-${s.filename}`}
                    >
                      <span
                        className={`status-dot ${
                          actCount > 0 ? "status-dot-danger" : "status-dot-safe"
                        }`}
                      />
                      <span className="scan-pill-name">{s.filename}</span>
                      <span className="scan-pill-meta">
                        {actCount} {t.actionableShort} · {s.report.summary.suppressed_candidates}{" "}
                        {t.suppressedShort}
                      </span>
                      <button
                        type="button"
                        className="scan-delete-btn"
                        title={t.deleteScanTitle}
                        onClick={(e) => void handleDeleteScan(e, s.id)}
                      >
                        ×
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="main-workspace">
        <div className="workspace-container">
          {errorMsg && (
            <div className="banner banner-error" role="alert">
              {errorMsg}
            </div>
          )}

          {!selectedScan ? (
            <div className="white-card">
              <h2 className="page-heading">{t.headingOverview}</h2>
              <p className="subtitle">{t.emptyDashboardSub}</p>
            </div>
          ) : (
            <>
              <div className="page-heading-row">
                <h2 className="page-heading">
                  {activeTab === "overview" && selectedScan.filename}
                  {activeTab === "findings" && t.headingFindings}
                  {activeTab === "files" && t.headingFiles}
                  {activeTab === "diff" && t.headingDiff}
                </h2>
                <span className="subtitle">
                  {selectedScan.report.metadata.duration_ms} ms
                </span>
              </div>

              {activeTab === "overview" && (
                <section data-testid="view-overview">
                  {selectedScan.report.partial ? (
                    <div className="banner banner-warning" data-testid="partial-coverage-banner">
                      <strong>{t.partialBannerTitle}</strong> {selectedScan.report.summary.skipped_entries} {t.kpiSkipped.toLowerCase()}.
                    </div>
                  ) : (
                    <div className="banner banner-success" data-testid="full-coverage-banner">
                      <strong>{t.fullBannerTitle}</strong>
                    </div>
                  )}

                  {/* Clean 4-Card KPI Row */}
                  <div className="metrics-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
                    <button
                      type="button"
                      className="metric-card metric-card-btn accent-danger"
                      onClick={() =>
                        pushNavHistory({
                          tab: "findings",
                          filter: "actionable",
                          query: "",
                        })
                      }
                    >
                      <div className="metric-value" data-testid="metric-actionable">
                        {selectedScan.report.summary.actionable_findings}
                      </div>
                      <div className="metric-label">{t.kpiActionable}</div>
                    </button>

                    <button
                      type="button"
                      className="metric-card metric-card-btn accent-safe"
                      onClick={() =>
                        pushNavHistory({
                          tab: "findings",
                          filter: "suppressed",
                          query: "",
                        })
                      }
                    >
                      <div className="metric-value" data-testid="metric-suppressed">
                        {selectedScan.report.summary.suppressed_candidates}
                      </div>
                      <div className="metric-label">{t.kpiSuppressed}</div>
                    </button>

                    <button
                      type="button"
                      className="metric-card metric-card-btn accent-warn"
                      onClick={() =>
                        pushNavHistory({
                          tab: "findings",
                          filter:
                            selectedScan.report.summary.review_candidates > 0 ? "review" : "hints",
                          query: "",
                        })
                      }
                    >
                      <div className="metric-value" data-testid="metric-review">
                        {selectedScan.report.summary.review_candidates +
                          selectedScan.report.summary.informational_hints}
                      </div>
                      <div className="metric-label">{t.reviewHintLegend}</div>
                    </button>

                    <button
                      type="button"
                      className="metric-card metric-card-btn accent-cyan"
                      onClick={() => {
                        setFileStatusFilter("all");
                        pushNavHistory({ tab: "files" });
                      }}
                    >
                      <div className="metric-value" data-testid="metric-files-scanned">
                        {selectedScan.report.metadata.files_scanned}
                      </div>
                      <div className="metric-label">{t.kpiFilesScanned}</div>
                    </button>
                  </div>

                  {/* Clean 3-Card Row: Donut + IoT Vectors + File List */}
                  <div className="analytics-grid">
                    <PostureDonutCard
                      report={selectedScan.report}
                      lang={lang}
                      onSelectFilter={(flt) =>
                        pushNavHistory({
                          tab: "findings",
                          filter: flt,
                          query: "",
                        })
                      }
                    />
                    <VectorTasksBarCard
                      report={selectedScan.report}
                      lang={lang}
                      onSelectVector={handleSelectVectorFilter}
                    />
                    <CompactFileTreeCard
                      report={selectedScan.report}
                      lang={lang}
                      onSelectFile={(path) => handleOpenInFileInspector(path)}
                    />
                  </div>
                </section>
              )}

              {activeTab === "findings" && (
                <section data-testid="view-findings">
                  <div className="filter-row">
                    <select
                      className="input-control"
                      value={findingFilter}
                      onChange={(e) => setFindingFilter(e.target.value as FindingFilter)}
                      aria-label="Filter findings by status"
                    >
                      <option value="all">{t.filterAll}</option>
                      <option value="actionable">{t.filterActionable}</option>
                      <option value="review">{t.filterReview}</option>
                      <option value="hints">{t.filterHints}</option>
                      <option value="suppressed">{t.filterSuppressed}</option>
                    </select>
                    <input
                      type="search"
                      className="input-control"
                      style={{ minWidth: "280px" }}
                      placeholder={t.searchPlaceholder}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    {(searchQuery || findingFilter !== "all") && (
                      <button
                        type="button"
                        className="btn"
                        onClick={() => {
                          setSearchQuery("");
                          setFindingFilter("all");
                        }}
                      >
                        {t.clearFilter}
                      </button>
                    )}
                  </div>

                  {findingFilter !== "suppressed" &&
                    selectedScan.report.findings
                      .filter((f) => {
                        if (
                          findingFilter === "actionable" &&
                          !(
                            f.kind === "finding" &&
                            (f.status === "confirmed_by_structural_rule" ||
                              f.status === "likely_secret")
                          )
                        ) {
                          return false;
                        }
                        if (
                          findingFilter === "review" &&
                          !(f.kind === "finding" && f.status === "requires_review")
                        ) {
                          return false;
                        }
                        if (findingFilter === "hints" && f.kind !== "hint") {
                          return false;
                        }
                        return matchesSearchQuery(f.rule_id, f.file_path, f.category);
                      })
                      .map((f, idx) => {
                        const meta = RULE_CATALOG[f.rule_id];
                        const problemTitle = getProblemTitle(f.rule_id, f.category, lang);
                        return (
                          <div
                            key={`${f.rule_id}-${f.file_path}-${f.byte_offset}-${idx}`}
                            className="finding-card"
                            data-testid="finding-card"
                          >
                            <div className="finding-card-top">
                              <div className="finding-title-group">
                                <span className={`badge badge-${f.severity}`}>
                                  {formatSeverity(f.severity, lang)}
                                </span>
                                <strong className="finding-problem-name">{problemTitle}</strong>
                                {meta && <span className="std-pill">{meta.cwe}</span>}
                              </div>

                              {/* Clickable SonarCloud/SonarQube File & Config Link */}
                              <button
                                type="button"
                                className="sonar-file-link"
                                onClick={() =>
                                  handleOpenInFileInspector(
                                    f.file_path,
                                    f.rule_id,
                                    f.byte_offset,
                                    f.line_number,
                                  )
                                }
                                data-testid="inspect-in-file-btn"
                              >
                                <span className="sonar-file-link-path">
                                  {f.file_path}
                                  {f.line_number ? ` : ${t.lineLabel} ${f.line_number}` : ""}
                                </span>
                                <span className="sonar-file-link-cta">
                                  {t.openInFileBtn} ↗
                                </span>
                              </button>
                            </div>

                            {/* Inline SonarQube-style Code Snippet Preview */}
                            <div
                              className="finding-inline-code"
                              onClick={() =>
                                handleOpenInFileInspector(
                                  f.file_path,
                                  f.rule_id,
                                  f.byte_offset,
                                  f.line_number,
                                )
                              }
                              title={t.openInFileBtn}
                            >
                              <span className="finding-inline-gutter">
                                {f.line_number ?? `@${f.byte_offset}`}
                              </span>
                              <code className="finding-inline-evidence">{f.evidence}</code>
                            </div>

                            <details style={{ marginTop: "0.45rem", fontSize: "0.8rem", color: "#4b5563" }}>
                              <summary style={{ cursor: "pointer", fontWeight: 600 }}>
                                {lang === "pl" ? "Szczegóły i zalecenia" : "Details & Remediation"}
                              </summary>
                              <div style={{ marginTop: "0.35rem" }}>
                                {meta ? meta.explanation[lang] : f.explanation}
                              </div>
                              <div style={{ marginTop: "0.25rem" }}>
                                <strong>{t.remediationLabel}</strong>{" "}
                                {meta ? meta.remediation[lang] : f.remediation}
                              </div>
                              {meta && (
                                <div style={{ marginTop: "0.35rem" }}>
                                  <span className="std-pill">{meta.owaspIot}</span>
                                  <span className="std-pill">{meta.etsi}</span>
                                </div>
                              )}
                            </details>
                          </div>
                        );
                      })}

                  {(findingFilter === "all" || findingFilter === "suppressed") &&
                    selectedScan.report.suppressed
                      .filter((s) =>
                        matchesSearchQuery(s.rule_id, s.file_path, s.suppression_reason),
                      )
                      .map((s, idx) => {
                        const problemTitle = getProblemTitle(
                          s.rule_id,
                          formatSuppressionReason(s.suppression_reason, lang),
                          lang,
                        );
                        return (
                          <div
                            key={`supp-${s.rule_id}-${s.file_path}-${s.byte_offset}-${idx}`}
                            className="finding-card"
                            data-testid="suppressed-card"
                          >
                            <div className="finding-card-top">
                              <div className="finding-title-group">
                                <span className="badge badge-info">
                                  {formatSuppressionReason(s.suppression_reason, lang)}
                                </span>
                                <strong className="finding-problem-name">{problemTitle}</strong>
                              </div>
                              <button
                                type="button"
                                className="sonar-file-link"
                                onClick={() =>
                                  handleOpenInFileInspector(
                                    s.file_path,
                                    s.rule_id,
                                    s.byte_offset,
                                    s.line_number,
                                  )
                                }
                              >
                                <span className="sonar-file-link-path">
                                  {s.file_path}
                                  {s.line_number ? ` : ${t.lineLabel} ${s.line_number}` : ""}
                                </span>
                                <span className="sonar-file-link-cta">
                                  {t.openInFileBtn} ↗
                                </span>
                              </button>
                            </div>
                            <div className="finding-inline-code finding-inline-code-safe">
                              <span className="finding-inline-gutter">
                                {s.line_number ?? `@${s.byte_offset}`}
                              </span>
                              <code className="finding-inline-evidence">{s.evidence}</code>
                            </div>
                          </div>
                        );
                      })}
                </section>
              )}

              {activeTab === "files" && (
                <section data-testid="view-files" className="files-workbench-grid">
                  <div className="white-card files-table-card">
                    <div className="filter-row">
                      <select
                        className="input-control"
                        value={fileStatusFilter}
                        onChange={(e) => setFileStatusFilter(e.target.value)}
                        aria-label="Filter files by analysis status"
                      >
                        <option value="all">{t.allStatuses}</option>
                        <option value="scanned">{t.statusScanned}</option>
                        <option value="skipped">{t.statusSkipped}</option>
                      </select>
                    </div>
                    <div className="table-scroll-wrap">
                      <table className="data-table" data-testid="files-inventory-table">
                        <thead>
                          <tr>
                            <th>{t.pathCol}</th>
                            <th>{t.typeCol}</th>
                            <th>{t.statusCol}</th>
                            <th>{t.kpiActionable}</th>
                            <th>{t.kpiSuppressed}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedScan.report.inventory
                            .filter((entry) =>
                              fileStatusFilter === "all"
                                ? true
                                : entry.analysis_status === fileStatusFilter,
                            )
                            .map((entry) => {
                              const isSelected =
                                (selectedFilePath ??
                                  selectedScan.report.inventory.find(
                                    (i) => i.actionable_findings > 0,
                                  )?.path ??
                                  selectedScan.report.inventory[0]?.path) === entry.path;
                              return (
                                <tr
                                  key={entry.path}
                                  className={isSelected ? "table-row-selected" : ""}
                                  style={{ cursor: "pointer" }}
                                  onClick={() => handleOpenInFileInspector(entry.path)}
                                >
                                  <td className="path-cell">
                                    <code>{entry.path}</code>
                                  </td>
                                  <td>{formatFileType(entry.file_type, lang)}</td>
                                  <td>{formatAnalysisStatus(entry.analysis_status, lang)}</td>
                                  <td>
                                    {entry.actionable_findings > 0 ? (
                                      <span className="badge badge-high">
                                        {entry.actionable_findings}
                                      </span>
                                    ) : (
                                      0
                                    )}
                                  </td>
                                  <td>{entry.suppressed_candidates}</td>
                                </tr>
                              );
                            })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* SonarCloud / SonarQube Style File & Config Fragment Viewer */}
                  <SonarCodeInspector
                    report={selectedScan.report}
                    selectedFilePath={selectedFilePath}
                    focusedFindingKey={focusedFindingKey}
                    lang={lang}
                    onViewFindingsTab={handleJumpToFileFindings}
                  />
                </section>
              )}

              {activeTab === "diff" && (
                <section data-testid="view-diff" className="white-card">
                  <div className="filter-row">
                    <label style={{ fontSize: "0.82rem", fontWeight: 600 }}>
                      {t.baseScanLabel}{" "}
                      <select
                        className="input-control"
                        value={diffBaseId}
                        onChange={(e) => setDiffBaseId(e.target.value)}
                        data-testid="diff-base-select"
                      >
                        <option value="">{t.selectBase}</option>
                        {scans.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.filename} : {s.report.summary.actionable_findings} {t.actionableShort}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label style={{ fontSize: "0.82rem", fontWeight: 600 }}>
                      {t.targetScanLabel}{" "}
                      <select
                        className="input-control"
                        value={diffTargetId}
                        onChange={(e) => setDiffTargetId(e.target.value)}
                        data-testid="diff-target-select"
                      >
                        <option value="">{t.selectTarget}</option>
                        {scans.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.filename} : {s.report.summary.actionable_findings} {t.actionableShort}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>

                  {apiDiff ? (
                    <>
                      {apiDiff.coverage_warning && (
                        <div className="banner banner-warning" data-testid="diff-coverage-warning">
                          <strong>{t.coverageCaveat}</strong> {t.partialBannerTitle}
                        </div>
                      )}

                      <div
                        className="metrics-grid"
                        style={{ gridTemplateColumns: "repeat(4, 1fr)" }}
                      >
                        <div className="metric-card accent-safe">
                          <div className="metric-value" data-testid="diff-actionable-delta">
                            {formatDelta(apiDiff.delta.actionable_delta)}
                          </div>
                          <div className="metric-label">{t.actionableDelta}</div>
                        </div>
                        <div className="metric-card accent-cyan">
                          <div className="metric-value" data-testid="diff-suppressed-delta">
                            {formatDelta(apiDiff.delta.suppressed_delta)}
                          </div>
                          <div className="metric-label">{t.suppressedDelta}</div>
                        </div>
                        <div className="metric-card accent-safe">
                          <div className="metric-value" data-testid="diff-resolved-count">
                            {apiDiff.resolved_findings.length}
                          </div>
                          <div className="metric-label">{t.resolvedCandidates}</div>
                        </div>
                        <div className="metric-card accent-danger">
                          <div className="metric-value" data-testid="diff-new-count">
                            {apiDiff.new_findings.length}
                          </div>
                          <div className="metric-label">{t.newCandidates}</div>
                        </div>
                      </div>

                      <h3 className="card-title" style={{ marginBottom: "0.5rem" }}>
                        {t.resolvedFindingsTitle}: {apiDiff.resolved_findings.length}
                      </h3>
                      {apiDiff.resolved_findings.map((f, idx) => (
                        <div key={`res-${idx}`} className="finding-card">
                          <div className="finding-card-top">
                            <strong>{getProblemTitle(f.rule_id, f.category, lang)}</strong>
                            <code>
                              {f.file_path}
                              {f.line_number ? `:${f.line_number}` : ""}
                            </code>
                          </div>
                          <div style={{ marginTop: "0.3rem" }}>
                            <code>{f.evidence}</code>
                          </div>
                        </div>
                      ))}
                    </>
                  ) : (
                    <p className="subtitle">{t.diffEmptyHint}</p>
                  )}
                </section>
              )}
            </>
          )}
        </div>
      </main>

      {/* Modal: IoT Security Standards & Vulnerability Catalog */}
      {showRulesModal && (
        <div
          className="modal-backdrop"
          onClick={() => setShowRulesModal(false)}
          role="dialog"
          aria-modal="true"
        >
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="page-heading" style={{ fontSize: "0.95rem" }}>
                {t.modalRulesTitle}
              </h3>
              <button type="button" className="btn" onClick={() => setShowRulesModal(false)}>
                {t.closeBtn}
              </button>
            </div>
            <div className="modal-body">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{lang === "pl" ? "Problem bezpieczeństwa" : "Vulnerability / Issue"}</th>
                    <th>CWE / Standard</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {Object.values(RULE_CATALOG).map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <strong>{rule.subject[lang]}</strong>
                      </td>
                      <td>
                        <span className="std-pill">{rule.cwe}</span>
                        <span className="std-pill">{rule.etsi}</span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn"
                          style={{ fontSize: "0.72rem", padding: "0.25rem 0.5rem" }}
                          onClick={() => handleSelectRuleFilter(rule.subject[lang])}
                        >
                          {t.inspectRuleBtn}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
