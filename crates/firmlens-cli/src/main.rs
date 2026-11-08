use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use firmlens_core::{
    list_rules, scan_path, CandidateStatus, FindingKind, IdentificationStatus, IngestionLimits,
    ScanLimits, ScanOptions, ScanReport, Severity,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "firmlens",
    version,
    about = "Firmware-aware static security analyzer for embedded credentials and unsafe IoT configurations"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan an unpacked firmware directory, bounded TAR/TAR.GZ archive, or firmware image
    Scan(Box<ScanArgs>),
    /// Inspect built-in detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Debug, Subcommand)]
enum RulesAction {
    /// List all registered detection rules and their metadata
    List {
        /// Output format (text or json)
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Path to target firmware directory, TAR/TAR.GZ archive, or image file
    pub path: PathBuf,

    /// Output format (defaults to text on stdout, or json when --output is given)
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write report to a new file (must not already exist; defaults to JSON format)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Return exit code 3 when a full scoped report contains actionable findings
    #[arg(long)]
    pub fail_on_findings: bool,

    /// Maximum bytes read per regular file during traversal
    #[arg(long)]
    pub max_file_bytes: Option<u64>,

    /// Maximum cumulative bytes read across all scanned files
    #[arg(long)]
    pub max_total_bytes: Option<u64>,

    /// Maximum directory traversal entries visited
    #[arg(long)]
    pub max_entries: Option<usize>,

    /// Maximum directory traversal depth
    #[arg(long)]
    pub max_depth: Option<usize>,

    /// Maximum line/record length in bytes for text analysis
    #[arg(long)]
    pub max_record_bytes: Option<usize>,

    /// Maximum total findings and suppressed candidates retained
    #[arg(long)]
    pub max_findings: Option<usize>,

    /// Maximum compressed/raw input archive size in bytes
    #[arg(long)]
    pub max_input_bytes: Option<u64>,

    /// Maximum expanded TAR stream size in bytes
    #[arg(long)]
    pub max_expanded_bytes: Option<u64>,

    /// Maximum size of any single extracted archive member in bytes
    #[arg(long)]
    pub max_member_bytes: Option<u64>,

    /// Maximum regular files extracted from an archive
    #[arg(long)]
    pub max_extracted_files: Option<usize>,

    /// Maximum archive entries/materialized path nodes
    #[arg(long)]
    pub max_archive_entries: Option<usize>,

    /// Maximum relative path component depth inside an archive
    #[arg(long)]
    pub max_extraction_depth: Option<usize>,

    /// Cooperative archive ingestion deadline in milliseconds
    #[arg(long)]
    pub ingestion_timeout_ms: Option<u64>,

    /// Run isolated Binwalk v3 signature identification on unsupported binary images
    #[arg(long)]
    pub binwalk: bool,

    /// Override trusted local Docker image or digest for Binwalk v3 identification
    #[arg(long)]
    pub binwalk_image: Option<String>,
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .try_init();
}

fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Rules {
            action: RulesAction::List { format },
        } => {
            run_rules_list(format)?;
            Ok(ExitCode::from(0))
        }
        Commands::Scan(args) => run_scan(*args),
    }
}

fn run_rules_list(format: OutputFormat) -> Result<()> {
    let rules = list_rules();
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(rules)
                .context("failed to serialize rules list to JSON")?;
            println!("{json}");
        }
        OutputFormat::Text => {
            println!(
                "FirmLens Detection Rules (v{}, {} rules):",
                firmlens_core::RULESET_VERSION,
                rules.len()
            );
            println!(
                "{:<6}  {:<8}  {:<18}  {:<26}  SUBJECT",
                "ID", "SEVERITY", "CWE", "CATEGORY"
            );
            println!("{}", "-".repeat(98));
            for rule in rules {
                let sev = match rule.default_severity {
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                    Severity::Info => "info",
                };
                println!(
                    "{:<6}  {:<8}  {:<18}  {:<26}  {}",
                    rule.id, sev, rule.cwe, rule.category, rule.subject
                );
            }
        }
    }
    Ok(())
}

fn validate_output_path(input_path: &Path, output_path: &Path) -> Result<()> {
    if output_path.as_os_str().is_empty() {
        bail!("output path must not be empty");
    }
    if std::fs::symlink_metadata(output_path).is_ok() {
        bail!(
            "refusing to overwrite existing output path: {}",
            output_path.display()
        );
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            let parent_meta = std::fs::metadata(parent).with_context(|| {
                format!(
                    "output parent directory does not exist: {}",
                    parent.display()
                )
            })?;
            if !parent_meta.is_dir() {
                bail!(
                    "output parent path is not a directory: {}",
                    parent.display()
                );
            }
        }
    }
    if input_path == output_path {
        bail!("output path must not match input path");
    }
    Ok(())
}

fn build_scan_options(args: &ScanArgs) -> Result<ScanOptions> {
    let mut scan_limits = ScanLimits::default();
    if let Some(v) = args.max_file_bytes {
        if v == 0 {
            bail!("--max-file-bytes must be greater than 0");
        }
        scan_limits.max_file_bytes = v;
    }
    if let Some(v) = args.max_total_bytes {
        if v == 0 {
            bail!("--max-total-bytes must be greater than 0");
        }
        scan_limits.max_total_bytes = v;
    }
    if let Some(v) = args.max_entries {
        if v == 0 {
            bail!("--max-entries must be greater than 0");
        }
        scan_limits.max_entries = v;
    }
    if let Some(v) = args.max_depth {
        if v == 0 {
            bail!("--max-depth must be greater than 0");
        }
        scan_limits.max_depth = v;
    }
    if let Some(v) = args.max_record_bytes {
        if v == 0 {
            bail!("--max-record-bytes must be greater than 0");
        }
        scan_limits.max_record_bytes = v;
    }
    if let Some(v) = args.max_findings {
        if v == 0 {
            bail!("--max-findings must be greater than 0");
        }
        scan_limits.max_findings = v;
    }

    let mut ingestion_limits = IngestionLimits::default();
    if let Some(v) = args.max_input_bytes {
        if v == 0 {
            bail!("--max-input-bytes must be greater than 0");
        }
        ingestion_limits.max_input_bytes = v;
    }
    if let Some(v) = args.max_expanded_bytes {
        if v == 0 {
            bail!("--max-expanded-bytes must be greater than 0");
        }
        ingestion_limits.max_expanded_bytes = v;
    }
    if let Some(v) = args.max_member_bytes {
        if v == 0 {
            bail!("--max-member-bytes must be greater than 0");
        }
        ingestion_limits.max_member_bytes = v;
    }
    if let Some(v) = args.max_extracted_files {
        if v == 0 {
            bail!("--max-extracted-files must be greater than 0");
        }
        ingestion_limits.max_extracted_files = v;
    }
    if let Some(v) = args.max_archive_entries {
        if v == 0 {
            bail!("--max-archive-entries must be greater than 0");
        }
        ingestion_limits.max_archive_entries = v;
    }
    if let Some(v) = args.max_extraction_depth {
        if v == 0 {
            bail!("--max-extraction-depth must be greater than 0");
        }
        ingestion_limits.max_extraction_depth = v;
    }
    if let Some(v) = args.ingestion_timeout_ms {
        if v == 0 {
            bail!("--ingestion-timeout-ms must be greater than 0");
        }
        ingestion_limits.ingestion_timeout_ms = v;
    }

    if let Some(ref img) = args.binwalk_image {
        if img.trim().is_empty() || img.starts_with('-') {
            bail!("--binwalk-image must be a valid non-empty image reference");
        }
    }

    Ok(ScanOptions {
        scan_limits,
        ingestion_limits,
        excluded_output_path: args.output.clone(),
        enable_binwalk: args.binwalk,
        binwalk_image: args.binwalk_image.clone(),
        scan_binary_image_payload: !args.binwalk,
    })
}

fn run_scan(args: ScanArgs) -> Result<ExitCode> {
    if let Some(ref out_path) = args.output {
        validate_output_path(&args.path, out_path)?;
    }

    let options = build_scan_options(&args)?;
    let report = scan_path(&args.path, &options)
        .with_context(|| format!("failed to scan input path '{}'", args.path.display()))?;

    tracing::info!(
        schema_version = %report.schema_version,
        files_scanned = report.metadata.files_scanned,
        bytes_read = report.metadata.bytes_read,
        actionable_findings = report.summary.actionable_findings,
        review_candidates = report.summary.review_candidates,
        informational_hints = report.summary.informational_hints,
        suppressed_candidates = report.summary.suppressed_candidates,
        skipped_entries = report.summary.skipped_entries,
        scan_errors = report.summary.scan_errors,
        partial = report.partial,
        "scan completed"
    );

    let effective_format = args.format.unwrap_or(if args.output.is_some() {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    });

    let rendered = match effective_format {
        OutputFormat::Json => {
            let mut s = serde_json::to_string_pretty(&report)
                .context("failed to serialize scan report to JSON")?;
            s.push('\n');
            s
        }
        OutputFormat::Text => format_text_report(&report),
    };

    if let Some(ref out_path) = args.output {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out_path)
            .with_context(|| {
                format!(
                    "failed to create new output report file '{}'",
                    out_path.display()
                )
            })?;
        file.write_all(rendered.as_bytes())
            .with_context(|| format!("failed to write scan report to '{}'", out_path.display()))?;
        file.flush()?;
    } else {
        print!("{rendered}");
    }

    if report.partial {
        Ok(ExitCode::from(2))
    } else if args.fail_on_findings && report.summary.actionable_findings > 0 {
        Ok(ExitCode::from(3))
    } else {
        Ok(ExitCode::from(0))
    }
}

fn format_text_report(report: &ScanReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let coverage_label = if report.partial {
        "PARTIAL (incomplete or excluded scope)"
    } else {
        "FULL (all in-scope files analyzed)"
    };

    let _ = writeln!(
        out,
        "FirmLens v{} | Schema {} | Ruleset v{}",
        report.metadata.scanner_version, report.schema_version, report.metadata.ruleset_version
    );
    let _ = writeln!(out, "Target:           {}", report.metadata.root);
    let _ = writeln!(
        out,
        "Ingestion:        {:?} ({:?})",
        report.ingestion.outcome, report.ingestion.input_kind
    );
    if let Some(ref reason) = report.ingestion.rejection_reason {
        let _ = writeln!(out, "Rejection reason: {}", reason);
    }
    if report.identification.status != IdentificationStatus::NotRequested
        || report.identification.note.is_some()
    {
        let _ = writeln!(
            out,
            "Identification:   {:?} (isolated_container={}, version={})",
            report.identification.status,
            report.identification.isolated_container,
            report
                .identification
                .tool_version
                .as_deref()
                .unwrap_or("none")
        );
        if let Some(ref note) = report.identification.note {
            let _ = writeln!(out, "Ident. Note:      {}", note);
        }
        for sig in &report.identification.signatures {
            let _ = writeln!(
                out,
                "  * Signature at offset {} (0x{:x}): {}",
                sig.offset, sig.offset, sig.category
            );
        }
    }
    let _ = writeln!(out, "Coverage:         {}", coverage_label);
    let _ = writeln!(
        out,
        "Scanned:          {} files ({} bytes) in {} ms",
        report.metadata.files_scanned, report.metadata.bytes_read, report.metadata.duration_ms
    );
    let _ = writeln!(
        out,
        "Summary:          {} actionable | {} review | {} hints | {} suppressed | {} skipped | {} errors",
        report.summary.actionable_findings,
        report.summary.review_candidates,
        report.summary.informational_hints,
        report.summary.suppressed_candidates,
        report.summary.skipped_entries,
        report.summary.scan_errors
    );

    if !report.findings.is_empty() {
        let _ = writeln!(out, "\nFindings & Candidates ({}):", report.findings.len());
        for f in &report.findings {
            let sev = match f.severity {
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            };
            let kind = match f.kind {
                FindingKind::Finding => "finding",
                FindingKind::Hint => "hint",
            };
            let status = match f.status {
                CandidateStatus::ConfirmedByStructuralRule => "confirmed_by_structural_rule",
                CandidateStatus::LikelySecret => "likely_secret",
                CandidateStatus::RequiresReview => "requires_review",
                CandidateStatus::BenignOrSuppressed => "benign_or_suppressed",
            };
            let loc = match f.line_number {
                Some(line) => format!("{}:{} (offset {})", f.file_path, line, f.byte_offset),
                None => format!("{} (offset {})", f.file_path, f.byte_offset),
            };
            let _ = writeln!(
                out,
                "  - [{}] {} ({}, {}, {} pts) at {}",
                sev, f.rule_id, kind, status, f.policy_points, loc
            );
            let _ = writeln!(out, "    Evidence: {}", f.evidence);
        }
    }

    if !report.suppressed.is_empty() {
        let _ = writeln!(
            out,
            "\nSuppressed Candidates ({}):",
            report.suppressed.len()
        );
        for s in &report.suppressed {
            let loc = match s.line_number {
                Some(line) => format!("{}:{}", s.file_path, line),
                None => format!("{} (offset {})", s.file_path, s.byte_offset),
            };
            let _ = writeln!(
                out,
                "  - {} ({}) at {} -> {}",
                s.rule_id, s.suppression_reason, loc, s.evidence
            );
        }
    }

    if !report.skipped_files.is_empty() {
        let _ = writeln!(out, "\nSkipped Entries ({}):", report.skipped_files.len());
        for sk in &report.skipped_files {
            let _ = writeln!(out, "  - {}: {}", sk.path, sk.reason);
        }
    }

    if !report.errors.is_empty() {
        let _ = writeln!(out, "\nScan Errors ({}):", report.errors.len());
        for err in &report.errors {
            let _ = writeln!(out, "  - {} [{}]: {}", err.path, err.code, err.message);
        }
    }

    out
}
