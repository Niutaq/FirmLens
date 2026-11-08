use firmlens_core::ScanReport;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn firmlens_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firmlens"))
}

#[test]
fn cli_evaluates_ground_truth_fixtures_and_never_leaks_secrets() {
    let root = repo_root();
    let expected_raw =
        fs::read_to_string(root.join("fixtures/expected.json")).expect("read expected.json");
    let expected: serde_json::Value =
        serde_json::from_str(&expected_raw).expect("parse expected.json");

    // 1. Vulnerable fixture -> exit 2 (partial due to excluded Markdown), 12 actionable, 1 hint, 0 review, 5 suppressed
    let vuln_out = Command::new(firmlens_bin())
        .args(["scan", "fixtures/vulnerable", "--format", "json"])
        .current_dir(&root)
        .output()
        .expect("run firmlens on vulnerable");
    assert_eq!(vuln_out.status.code(), Some(2));
    let vuln_stdout = String::from_utf8(vuln_out.stdout).expect("utf8 stdout");

    // Ensure no synthetic secret literals appear anywhere in serialized output
    for forbidden in [
        "SyntheticRootPass_v2!Invalid",
        "fl_synth_tok_998877665544332211",
        "synth_master_hmac_key_0102030405",
        "SynthUriPass99",
        "private_synth_rw",
        "SynthMqttBrokerSecret_42",
        "SynthCloudDeviceSymmetricKey_Base64Placeholder==",
        "SynthBootstrapClaimToken_2026",
        "SynthIamServiceAccountKey_NonFunctional",
        "MIIBOgIBAAJBALRSyntheticNonFunctionalKeyBodyForStaticAnalysisOnly0123456789",
    ] {
        assert!(
            !vuln_stdout.contains(forbidden),
            "secret literal leaked into report: {forbidden}"
        );
    }

    let vuln_report: ScanReport = serde_json::from_str(&vuln_stdout).expect("parse vuln report");
    let exp_vuln = &expected["fixtures"]["vulnerable"];
    assert_eq!(
        vuln_report.summary.actionable_findings as u64,
        exp_vuln["actionable_findings"].as_u64().unwrap()
    );
    assert_eq!(
        vuln_report.summary.informational_hints as u64,
        exp_vuln["informational_hints"].as_u64().unwrap()
    );
    assert_eq!(
        vuln_report.summary.review_candidates as u64,
        exp_vuln["review_candidates"].as_u64().unwrap()
    );
    assert_eq!(
        vuln_report.summary.suppressed_candidates as u64,
        exp_vuln["suppressed_candidates"].as_u64().unwrap()
    );
    assert!(vuln_report.partial);

    // 2. Hardened fixture -> exit 2, 0 actionable, 0 hints, 0 review, 12 suppressed
    let hard_out = Command::new(firmlens_bin())
        .args(["scan", "fixtures/hardened", "--format", "json"])
        .current_dir(&root)
        .output()
        .expect("run firmlens on hardened");
    assert_eq!(hard_out.status.code(), Some(2));
    let hard_report: ScanReport =
        serde_json::from_slice(&hard_out.stdout).expect("parse hardened report");
    let exp_hard = &expected["fixtures"]["hardened"];
    assert_eq!(
        hard_report.summary.actionable_findings as u64,
        exp_hard["actionable_findings"].as_u64().unwrap()
    );
    assert_eq!(
        hard_report.summary.suppressed_candidates as u64,
        exp_hard["suppressed_candidates"].as_u64().unwrap()
    );
    assert!(hard_report.partial);

    // 3. Benign fixture -> exit 0 (full coverage), 0 actionable, 0 hints, 1 review, 6 suppressed
    let ben_out = Command::new(firmlens_bin())
        .args([
            "scan",
            "fixtures/benign",
            "--format",
            "json",
            "--fail-on-findings",
        ])
        .current_dir(&root)
        .output()
        .expect("run firmlens on benign");
    assert_eq!(ben_out.status.code(), Some(0));
    let ben_report: ScanReport =
        serde_json::from_slice(&ben_out.stdout).expect("parse benign report");
    let exp_ben = &expected["fixtures"]["benign"];
    assert_eq!(
        ben_report.summary.actionable_findings as u64,
        exp_ben["actionable_findings"].as_u64().unwrap()
    );
    assert_eq!(
        ben_report.summary.review_candidates as u64,
        exp_ben["review_candidates"].as_u64().unwrap()
    );
    assert_eq!(
        ben_report.summary.suppressed_candidates as u64,
        exp_ben["suppressed_candidates"].as_u64().unwrap()
    );
    assert!(!ben_report.partial);
}

#[test]
fn cli_enforces_output_no_overwrite_and_exit_code_precedence() {
    let dir = tempdir().expect("tempdir");
    let target_dir = dir.path().join("full-vuln");
    fs::create_dir_all(&target_dir).unwrap();
    fs::write(
        target_dir.join("device.conf"),
        "password = \"SynthTestPass123!\"\n",
    )
    .unwrap();

    let report_path = dir.path().join("report.json");

    // Full scoped scan with actionable finding + --fail-on-findings -> exit code 3
    let out1 = Command::new(firmlens_bin())
        .args([
            "scan",
            target_dir.to_str().unwrap(),
            "--output",
            report_path.to_str().unwrap(),
            "--fail-on-findings",
        ])
        .output()
        .expect("run firmlens with --output and --fail-on-findings");
    assert_eq!(out1.status.code(), Some(3));
    assert!(report_path.is_file());

    let parsed: ScanReport =
        serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
    assert!(!parsed.partial);
    assert_eq!(parsed.summary.actionable_findings, 1);

    // Rerunning with the same --output path must refuse to overwrite and exit 1
    let out2 = Command::new(firmlens_bin())
        .args([
            "scan",
            target_dir.to_str().unwrap(),
            "--output",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run firmlens on existing output path");
    assert_eq!(out2.status.code(), Some(1));

    // Partial coverage takes precedence over exit 3 when --fail-on-findings is set
    fs::write(target_dir.join("README.md"), "# Excluded doc\n").unwrap();
    let out3 = Command::new(firmlens_bin())
        .args([
            "scan",
            target_dir.to_str().unwrap(),
            "--fail-on-findings",
            "--format",
            "json",
        ])
        .env("RUST_LOG", "info")
        .output()
        .expect("run firmlens with partial coverage and RUST_LOG=info");
    assert_eq!(out3.status.code(), Some(2));
    // Verify stdout is still valid uncontaminated JSON even with RUST_LOG=info
    let parsed_partial: ScanReport =
        serde_json::from_slice(&out3.stdout).expect("uncontaminated JSON stdout");
    assert!(parsed_partial.partial);
}
