use crate::model::{
    CandidateStatus, EvidenceSignal, FileTypeClass, Finding, FindingKind, Severity,
    SuppressedCandidate,
};
use crate::rules::find_rule;
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

const PRIVATE_KEY_BEGIN_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

const PUBLIC_PEM_BEGIN_MARKERS: &[&str] = &[
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----",
];

#[derive(Debug, Default)]
pub struct FileDetectionOutcome {
    pub findings: Vec<Finding>,
    pub suppressed: Vec<SuppressedCandidate>,
}

/// Classify a relative file path into a high-level inventory type.
pub fn classify_file_type(rel_path: &str, is_binary: bool) -> FileTypeClass {
    let lower = rel_path.to_ascii_lowercase();
    if lower.ends_with(".md")
        || lower.ends_with(".markdown")
        || lower.ends_with(".rst")
        || lower.ends_with(".adoc")
        || lower.ends_with("/readme")
        || lower == "readme"
        || lower.starts_with("readme.")
        || lower.ends_with("/license")
        || lower == "license"
        || lower.starts_with("license.")
    {
        return FileTypeClass::Documentation;
    }
    if lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.ends_with(".crt")
        || lower.ends_with(".cer")
        || lower.contains("/tls/")
        || lower.contains("/certs/")
        || lower.contains("/keys/")
    {
        return FileTypeClass::KeyOrCert;
    }
    if lower.ends_with(".sh") || lower.ends_with(".init") || lower.contains("/init.d/") {
        return FileTypeClass::Script;
    }
    if lower.ends_with(".conf")
        || lower.ends_with(".cfg")
        || lower.ends_with(".ini")
        || lower.ends_with(".env")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".toml")
        || lower.starts_with("etc/")
    {
        return FileTypeClass::Config;
    }
    if is_binary
        || lower.ends_with(".dat")
        || lower.ends_with(".bin")
        || lower.ends_with(".fw")
        || lower.ends_with(".img")
        || lower.ends_with(".chk")
        || lower.ends_with(".pat")
        || lower.ends_with(".rom")
        || lower.ends_with(".ubi")
    {
        return FileTypeClass::DataOrBinary;
    }
    FileTypeClass::Other
}

/// Strip inline `#` or `;` comments outside single or double quotes when preceded by whitespace.
pub fn strip_inline_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }

    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (idx, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if b == b'\\' && (in_single || in_double) {
            escaped = true;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if !in_single
            && !in_double
            && (b == b'#' || b == b';')
            && (idx == 0 || bytes[idx - 1].is_ascii_whitespace())
        {
            return line[..idx].trim_end();
        }
    }

    line.trim_end()
}

/// Inspect a file buffer (UTF-8 text or raw binary data) and return deterministic findings and suppressions.
pub fn analyze_file_bytes(
    rel_path: &str,
    bytes: &[u8],
    max_record_bytes: usize,
) -> FileDetectionOutcome {
    let is_probably_binary = bytes.contains(&0)
        || std::str::from_utf8(bytes).is_err()
        || Path::new(rel_path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                matches!(
                    e.to_ascii_lowercase().as_str(),
                    "dat" | "bin" | "fw" | "img" | "chk" | "pat" | "rom" | "ubi"
                )
            })
            .unwrap_or(false);

    if is_probably_binary {
        return analyze_binary_bytes(rel_path, bytes);
    }

    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return analyze_binary_bytes(rel_path, bytes),
    };

    analyze_text_content(rel_path, text, max_record_bytes)
}

fn analyze_text_content(
    rel_path: &str,
    text: &str,
    max_record_bytes: usize,
) -> FileDetectionOutcome {
    let mut outcome = FileDetectionOutcome::default();
    let file_class = classify_file_type(rel_path, false);

    // 1. Check for PEM structures across the file first.
    inspect_pem_blocks_in_text(rel_path, text, file_class, &mut outcome);

    // 2. Line-by-line contextual inspection with INI section state.
    let mut current_section = String::new();
    let mut byte_cursor = 0usize;

    for (idx, raw_line) in text.split_inclusive('\n').enumerate() {
        let line_number = idx + 1;
        let line_offset = byte_cursor as u64;
        byte_cursor += raw_line.len();

        let line_trimmed_newline = raw_line.trim_end_matches(&['\r', '\n'][..]);
        if line_trimmed_newline.len() > max_record_bytes {
            continue;
        }

        let active = strip_inline_comment(line_trimmed_newline).trim();
        if active.is_empty() {
            continue;
        }

        // Skip lines that are PEM headers/bodies already processed
        if active.starts_with("-----BEGIN ") || active.starts_with("-----END ") {
            continue;
        }

        // Track INI section header: [section_name]
        if active.starts_with('[') && active.ends_with(']') && active.len() > 2 {
            current_section = active[1..active.len() - 1].trim().to_ascii_lowercase();
            continue;
        }

        // Parse key = value or key : value assignment
        if let Some((raw_key, raw_val, val_delta)) = split_assignment(line_trimmed_newline, active)
        {
            let key_norm = normalize_key(raw_key);
            let val_clean = unquote_value(raw_val.trim());
            let exact_offset = line_offset + val_delta as u64;

            evaluate_assignment(
                rel_path,
                file_class,
                &current_section,
                &key_norm,
                val_clean,
                Some(line_number),
                exact_offset,
                &mut outcome,
            );
        } else if let Some(uri_match) = find_uri_candidate(active) {
            let delta = line_trimmed_newline.find(uri_match).unwrap_or(0);
            evaluate_uri_value(
                rel_path,
                file_class,
                &current_section,
                "uri",
                uri_match,
                Some(line_number),
                line_offset + delta as u64,
                &mut outcome,
            );
        }
    }

    outcome
}

fn inspect_pem_blocks_in_text(
    rel_path: &str,
    text: &str,
    file_class: FileTypeClass,
    outcome: &mut FileDetectionOutcome,
) {
    // Public certificates/keys: record suppression if file is a key/cert config or contains public cert block
    for &pub_marker in PUBLIC_PEM_BEGIN_MARKERS {
        let mut search_from = 0usize;
        while let Some(rel_idx) = text[search_from..].find(pub_marker) {
            let start_idx = search_from + rel_idx;
            let line_no = text[..start_idx].bytes().filter(|&b| b == b'\n').count() + 1;
            let rule = find_rule("FL003").expect("FL003 exists");
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: "public_certificate_or_key".to_string(),
                policy_points: 0,
                signals: vec![EvidenceSignal {
                    name: "public_pem_header".to_string(),
                    points: -100,
                    detail: "Public certificate or public key PEM block is not a private key"
                        .to_string(),
                }],
                file_path: rel_path.to_string(),
                line_number: Some(line_no),
                byte_offset: start_idx as u64,
                evidence: "public certificate/key = [SUPPRESSED]".to_string(),
            });
            search_from = start_idx + pub_marker.len();
        }
    }

    for &begin_marker in PRIVATE_KEY_BEGIN_MARKERS {
        let end_marker = begin_marker.replacen("-----BEGIN ", "-----END ", 1);
        let mut search_from = 0usize;
        while let Some(rel_idx) = text[search_from..].find(begin_marker) {
            let start_idx = search_from + rel_idx;
            let line_no = text[..start_idx].bytes().filter(|&b| b == b'\n').count() + 1;
            let after_begin = start_idx + begin_marker.len();

            if let Some(end_rel) = text[after_begin..].find(&end_marker) {
                let body = text[after_begin..after_begin + end_rel].trim();
                let is_placeholder_body = body.is_empty()
                    || body.contains("REDACTED")
                    || body.contains("PLACEHOLDER")
                    || body.contains("EXAMPLE")
                    || body.contains("...")
                    || body.len() < 16;

                let rule = find_rule("FL003").expect("FL003 exists");
                if is_placeholder_body {
                    outcome.suppressed.push(SuppressedCandidate {
                        rule_id: rule.id.to_string(),
                        category: rule.category.to_string(),
                        status: CandidateStatus::BenignOrSuppressed,
                        suppression_reason: "placeholder_pem_body".to_string(),
                        policy_points: 10,
                        signals: vec![EvidenceSignal {
                            name: "placeholder_suppression".to_string(),
                            points: -80,
                            detail: "PEM private-key delimiters contain placeholder or truncated sample text".to_string(),
                        }],
                        file_path: rel_path.to_string(),
                        line_number: Some(line_no),
                        byte_offset: start_idx as u64,
                        evidence: rule.redacted_evidence.to_string(),
                    });
                } else {
                    let mut signals = vec![
                        file_type_signal(file_class),
                        EvidenceSignal {
                            name: "pem_private_key_envelope".to_string(),
                            points: 75,
                            detail:
                                "Matching BEGIN/END PEM private-key delimiters with base64 body"
                                    .to_string(),
                        },
                    ];
                    let total_points: i32 = signals.iter().map(|s| s.points).sum();
                    signals.shrink_to_fit();

                    outcome.findings.push(Finding {
                        rule_id: rule.id.to_string(),
                        category: rule.category.to_string(),
                        severity: Severity::High,
                        kind: FindingKind::Finding,
                        status: CandidateStatus::ConfirmedByStructuralRule,
                        policy_points: total_points,
                        signals,
                        file_path: rel_path.to_string(),
                        line_number: Some(line_no),
                        byte_offset: start_idx as u64,
                        evidence: rule.redacted_evidence.to_string(),
                        explanation: rule.explanation.to_string(),
                        remediation: rule.remediation.to_string(),
                    });
                }
                search_from = after_begin + end_rel + end_marker.len();
            } else {
                // Incomplete marker -> informational hint
                let rule = find_rule("FL003").expect("FL003 exists");
                let signals = vec![
                    file_type_signal(file_class),
                    EvidenceSignal {
                        name: "incomplete_pem_marker".to_string(),
                        points: 30,
                        detail: "Isolated BEGIN private-key marker without matching END delimiter"
                            .to_string(),
                    },
                ];
                let total_points: i32 = signals.iter().map(|s| s.points).sum();
                outcome.findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    category: rule.category.to_string(),
                    severity: Severity::Info,
                    kind: FindingKind::Hint,
                    status: CandidateStatus::RequiresReview,
                    policy_points: total_points,
                    signals,
                    file_path: rel_path.to_string(),
                    line_number: Some(line_no),
                    byte_offset: start_idx as u64,
                    evidence: rule.redacted_evidence.to_string(),
                    explanation: "An isolated or incomplete private-key marker was found. This is an informational hint, not proof of an embedded key.".to_string(),
                    remediation: "Inspect the surrounding data in a controlled environment to determine whether a key is present.".to_string(),
                });
                search_from = after_begin;
            }
        }
    }
}

fn split_assignment<'a>(raw_line: &'a str, active: &'a str) -> Option<(&'a str, &'a str, usize)> {
    // Find '=' or ':' outside quotes, preferring the earliest assignment separator
    let bytes = active.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'=' || b == b':' {
            // Avoid splitting URI schemes like http:// or mqtts:// when no key precedes them
            if b == b':' && active[idx + 1..].starts_with("//") {
                return None;
            }
            let key = active[..idx].trim();
            let val = active[idx + 1..].trim();
            if key.is_empty() {
                return None;
            }
            let lead_ws = raw_line.len() - raw_line.trim_start().len();
            return Some((key, val, lead_ws));
        }
    }
    // Also support SNMP-style directives like `rocommunity public` or `rwcommunity private`
    let mut parts = active.splitn(2, char::is_whitespace);
    if let (Some(first), Some(rest)) = (parts.next(), parts.next()) {
        let lower = first.to_ascii_lowercase();
        if lower == "rocommunity" || lower == "rwcommunity" {
            let lead_ws = raw_line.len() - raw_line.trim_start().len();
            return Some((first, rest.trim(), lead_ws));
        }
    }
    None
}

fn normalize_key(raw_key: &str) -> String {
    raw_key
        .trim()
        .trim_matches(&['"', '\''][..])
        .replace(['-', '.', ' '], "_")
        .to_ascii_lowercase()
}

fn unquote_value(val: &str) -> &str {
    let trimmed = val.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn file_type_signal(file_class: FileTypeClass) -> EvidenceSignal {
    match file_class {
        FileTypeClass::Config => EvidenceSignal {
            name: "config_file_location".to_string(),
            points: 20,
            detail: "Candidate located in configuration file".to_string(),
        },
        FileTypeClass::KeyOrCert => EvidenceSignal {
            name: "key_or_cert_file_location".to_string(),
            points: 25,
            detail: "Candidate located in cryptographic key/certificate path".to_string(),
        },
        FileTypeClass::Script => EvidenceSignal {
            name: "script_file_location".to_string(),
            points: 15,
            detail: "Candidate located in initialization or runtime script".to_string(),
        },
        FileTypeClass::DataOrBinary => EvidenceSignal {
            name: "binary_data_stream".to_string(),
            points: 15,
            detail: "Candidate extracted from raw binary or data artifact".to_string(),
        },
        _ => EvidenceSignal {
            name: "general_file_location".to_string(),
            points: 10,
            detail: "Candidate located in general filesystem entry".to_string(),
        },
    }
}

/// Check if a value is an external reference, environment substitution, or obvious placeholder.
fn classify_suppression_reason(val: &str) -> Option<&'static str> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Some("empty_value");
    }
    if (trimmed.starts_with("${") && trimmed.ends_with('}'))
        || (trimmed.starts_with("$(") && trimmed.ends_with(')'))
        || (trimmed.starts_with("{{") && trimmed.ends_with("}}"))
        || (trimmed.starts_with('$')
            && trimmed.len() > 1
            && trimmed[1..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        return Some("env_or_template_reference");
    }
    if (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || trimmed.starts_with("/run/secrets/")
        || trimmed.starts_with("/var/run/secrets/")
        || trimmed.starts_with("/mnt/secure/")
        || trimmed.starts_with("tpm2:")
        || trimmed.starts_with("pkcs11:")
        || trimmed.starts_with("vault:")
        || trimmed.starts_with("arn:aws:secretsmanager:")
        || trimmed.starts_with("file:///run/secrets/")
        || trimmed.starts_with("systemd-creds:")
    {
        return Some("external_secret_reference");
    }

    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "changeme"
            | "change_me"
            | "replace_me"
            | "replaceme"
            | "todo"
            | "tbd"
            | "none"
            | "null"
            | "nil"
            | "disabled"
            | "unset"
            | "example"
            | "sample"
            | "placeholder"
            | "your_password_here"
            | "your_api_key_here"
            | "your_token_here"
            | "********"
            | "******"
            | "xxxx"
            | "[redacted]"
            | "redacted"
    ) || lower.starts_with("example_")
        || lower.starts_with("placeholder_")
        || lower.starts_with("dummy_")
    {
        return Some("placeholder_value");
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn evaluate_assignment(
    rel_path: &str,
    file_class: FileTypeClass,
    section: &str,
    key: &str,
    val: &str,
    line_number: Option<usize>,
    byte_offset: u64,
    outcome: &mut FileDetectionOutcome,
) {
    let lower_path = rel_path.to_ascii_lowercase();
    let lower_val = val.trim().to_ascii_lowercase();

    // 1. Check FL007: TLS verification disabled vs safe enabled
    if is_tls_verify_key(key) {
        let rule = find_rule("FL007").expect("FL007 exists");
        if is_tls_verify_disabled_value(key, &lower_val) {
            let signals = vec![
                file_type_signal(file_class),
                EvidenceSignal {
                    name: "tls_verification_disabled_directive".to_string(),
                    points: 80,
                    detail: format!("Key '{key}' explicitly disables certificate validation"),
                },
            ];
            let points = signals.iter().map(|s| s.points).sum();
            outcome.findings.push(Finding {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                severity: rule.default_severity,
                kind: FindingKind::Finding,
                status: CandidateStatus::ConfirmedByStructuralRule,
                policy_points: points,
                signals,
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: rule.redacted_evidence.to_string(),
                explanation: rule.explanation.to_string(),
                remediation: rule.remediation.to_string(),
            });
        } else if is_tls_verify_enabled_value(key, &lower_val) {
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: "safe_configuration_value".to_string(),
                policy_points: 0,
                signals: vec![EvidenceSignal {
                    name: "tls_verification_enabled".to_string(),
                    points: -80,
                    detail: format!("Key '{key}' enforces TLS verification"),
                }],
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: "TLS verification = enabled".to_string(),
            });
        }
        return;
    }

    // 2. Check FL008: Anonymous access enabled vs safe disabled
    if is_anonymous_access_key(key) {
        let rule = find_rule("FL008").expect("FL008 exists");
        if matches!(
            lower_val.as_str(),
            "true" | "yes" | "1" | "enabled" | "on" | "allow"
        ) {
            let signals = vec![
                file_type_signal(file_class),
                EvidenceSignal {
                    name: "anonymous_access_enabled_directive".to_string(),
                    points: 80,
                    detail: format!("Key '{key}' explicitly enables anonymous access"),
                },
            ];
            let points = signals.iter().map(|s| s.points).sum();
            outcome.findings.push(Finding {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                severity: rule.default_severity,
                kind: FindingKind::Finding,
                status: CandidateStatus::ConfirmedByStructuralRule,
                policy_points: points,
                signals,
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: rule.redacted_evidence.to_string(),
                explanation: rule.explanation.to_string(),
                remediation: rule.remediation.to_string(),
            });
        } else if matches!(
            lower_val.as_str(),
            "false" | "no" | "0" | "disabled" | "off" | "deny"
        ) {
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: "safe_configuration_value".to_string(),
                policy_points: 0,
                signals: vec![EvidenceSignal {
                    name: "anonymous_access_disabled".to_string(),
                    points: -80,
                    detail: format!("Key '{key}' disables anonymous access"),
                }],
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: "anonymous access = disabled".to_string(),
            });
        }
        return;
    }

    // 3. Check if value is a URI (FL006)
    if val.contains("://") {
        evaluate_uri_value(
            rel_path,
            file_class,
            section,
            key,
            val,
            line_number,
            byte_offset,
            outcome,
        );
        return;
    }

    // 4. Ignore non-secret identifiers (usernames, hosts, ports, client IDs, public cert paths)
    if is_non_secret_identifier_key(key) {
        return;
    }

    // 5. Check for ambiguous review-only configuration keys (e.g., key profile / fallback auth hint)
    if is_review_candidate_key(key) {
        if let Some(reason) = classify_suppression_reason(val) {
            let rule = find_rule("FL005").expect("FL005 exists");
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: reason.to_string(),
                policy_points: 0,
                signals: vec![EvidenceSignal {
                    name: "suppressed_reference".to_string(),
                    points: -60,
                    detail: format!("Suppressed due to {reason}"),
                }],
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: rule.redacted_evidence.to_string(),
            });
            return;
        }
        let rule = find_rule("FL005").expect("FL005 exists");
        let signals = vec![
            file_type_signal(file_class),
            EvidenceSignal {
                name: "ambiguous_credential_key".to_string(),
                points: 35,
                detail: format!(
                    "Key '{key}' contains credential-adjacent terminology requiring human review"
                ),
            },
        ];
        let points = signals.iter().map(|s| s.points).sum();
        outcome.findings.push(Finding {
            rule_id: rule.id.to_string(),
            category: rule.category.to_string(),
            severity: Severity::Low,
            kind: FindingKind::Finding,
            status: CandidateStatus::RequiresReview,
            policy_points: points,
            signals,
            file_path: rel_path.to_string(),
            line_number,
            byte_offset,
            evidence: rule.redacted_evidence.to_string(),
            explanation: rule.explanation.to_string(),
            remediation: rule.remediation.to_string(),
        });
        return;
    }

    // 6. Classify secret-bearing assignment rule (`FL001`..`FL005`, `FL009`..`FL012`)
    let matched_rule_id = match classify_secret_key(key, section, &lower_path, val) {
        Some(id) => id,
        None => return,
    };

    let rule = find_rule(matched_rule_id).expect("rule exists in registry");

    // Check if value is a placeholder, env var, or external secret store reference
    if let Some(reason) = classify_suppression_reason(val) {
        outcome.suppressed.push(SuppressedCandidate {
            rule_id: rule.id.to_string(),
            category: rule.category.to_string(),
            status: CandidateStatus::BenignOrSuppressed,
            suppression_reason: reason.to_string(),
            policy_points: 0,
            signals: vec![
                file_type_signal(file_class),
                EvidenceSignal {
                    name: "placeholder_or_external_reference".to_string(),
                    points: -80,
                    detail: format!("Value suppressed ({reason})"),
                },
            ],
            file_path: rel_path.to_string(),
            line_number,
            byte_offset,
            evidence: rule.redacted_evidence.to_string(),
        });
        return;
    }

    let mut signals = vec![
        file_type_signal(file_class),
        EvidenceSignal {
            name: "recognized_assignment_key".to_string(),
            points: 45,
            detail: format!(
                "Recognized sensitive assignment key '{key}' for {}",
                rule.id
            ),
        },
        EvidenceSignal {
            name: "non_empty_literal".to_string(),
            points: 20,
            detail: "Assignment contains a concrete non-placeholder literal".to_string(),
        },
    ];

    if !section.is_empty() {
        signals.push(EvidenceSignal {
            name: "ini_section_context".to_string(),
            points: 15,
            detail: format!("Located inside [{section}] configuration section"),
        });
    }

    if matches!(matched_rule_id, "FL002" | "FL010" | "FL011" | "FL012") {
        signals.push(EvidenceSignal {
            name: "iot_domain_context".to_string(),
            points: 15,
            detail: format!("Matched IoT/Cloud operational context for {matched_rule_id}"),
        });
    }

    let total_points: i32 = signals.iter().map(|s| s.points).sum();
    let status = if matched_rule_id == "FL005" {
        CandidateStatus::LikelySecret
    } else {
        CandidateStatus::ConfirmedByStructuralRule
    };

    outcome.findings.push(Finding {
        rule_id: rule.id.to_string(),
        category: rule.category.to_string(),
        severity: rule.default_severity,
        kind: FindingKind::Finding,
        status,
        policy_points: total_points,
        signals,
        file_path: rel_path.to_string(),
        line_number,
        byte_offset,
        evidence: rule.redacted_evidence.to_string(),
        explanation: rule.explanation.to_string(),
        remediation: rule.remediation.to_string(),
    });
}

#[allow(clippy::too_many_arguments)]
fn evaluate_uri_value(
    rel_path: &str,
    file_class: FileTypeClass,
    _section: &str,
    _key: &str,
    uri_val: &str,
    line_number: Option<usize>,
    byte_offset: u64,
    outcome: &mut FileDetectionOutcome,
) {
    static URI_RE: OnceLock<Regex> = OnceLock::new();
    let re = URI_RE.get_or_init(|| {
        Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@:\s]+):([^@\s]+)@([^\s]+)$").unwrap()
    });

    let trimmed = unquote_value(uri_val.trim());
    if let Some(caps) = re.captures(trimmed) {
        let password_part = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let rule = find_rule("FL006").expect("FL006 exists");

        if let Some(reason) = classify_suppression_reason(password_part) {
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: reason.to_string(),
                policy_points: 0,
                signals: vec![
                    file_type_signal(file_class),
                    EvidenceSignal {
                        name: "uri_userinfo_placeholder".to_string(),
                        points: -80,
                        detail: format!("URI userinfo password suppressed ({reason})"),
                    },
                ],
                file_path: rel_path.to_string(),
                line_number,
                byte_offset,
                evidence: rule.redacted_evidence.to_string(),
            });
            return;
        }

        let signals = vec![
            file_type_signal(file_class),
            EvidenceSignal {
                name: "uri_userinfo_credentials".to_string(),
                points: 75,
                detail: "URI contains literal user:password authentication segment".to_string(),
            },
        ];
        let total_points = signals.iter().map(|s| s.points).sum();

        outcome.findings.push(Finding {
            rule_id: rule.id.to_string(),
            category: rule.category.to_string(),
            severity: rule.default_severity,
            kind: FindingKind::Finding,
            status: CandidateStatus::ConfirmedByStructuralRule,
            policy_points: total_points,
            signals,
            file_path: rel_path.to_string(),
            line_number,
            byte_offset,
            evidence: rule.redacted_evidence.to_string(),
            explanation: rule.explanation.to_string(),
            remediation: rule.remediation.to_string(),
        });
    }
}

fn find_uri_candidate(line: &str) -> Option<&str> {
    for token in line.split_whitespace() {
        let clean = unquote_value(token.trim_end_matches(&[',', ';'][..]));
        if clean.contains("://") && clean.contains('@') {
            return Some(clean);
        }
    }
    None
}

fn is_tls_verify_key(key: &str) -> bool {
    matches!(
        key,
        "tls_verify"
            | "verify_tls"
            | "ssl_verify"
            | "verify_ssl"
            | "verify_peer"
            | "tls_verify_peer"
            | "insecure_skip_verify"
            | "tls_insecure"
    )
}

fn is_tls_verify_disabled_value(key: &str, lower_val: &str) -> bool {
    if key == "insecure_skip_verify" || key == "tls_insecure" {
        matches!(lower_val, "true" | "yes" | "1" | "enabled" | "on")
    } else {
        matches!(
            lower_val,
            "false" | "no" | "0" | "disabled" | "off" | "none" | "never"
        )
    }
}

fn is_tls_verify_enabled_value(key: &str, lower_val: &str) -> bool {
    if key == "insecure_skip_verify" || key == "tls_insecure" {
        matches!(lower_val, "false" | "no" | "0" | "disabled" | "off")
    } else {
        matches!(
            lower_val,
            "true" | "yes" | "1" | "enabled" | "on" | "required" | "strict"
        )
    }
}

fn is_anonymous_access_key(key: &str) -> bool {
    matches!(
        key,
        "allow_anonymous"
            | "anonymous_access"
            | "mqtt_allow_anonymous"
            | "enable_anonymous"
            | "anonymous_login"
    )
}

fn is_non_secret_identifier_key(key: &str) -> bool {
    matches!(
        key,
        "username"
            | "user"
            | "mqtt_user"
            | "mqtt_username"
            | "client_id"
            | "device_id"
            | "tenant_id"
            | "project_id"
            | "subscription_id"
            | "key_id"
            | "public_key_id"
            | "public_key"
            | "cert_file"
            | "ca_file"
            | "ca_cert"
            | "certificate_path"
            | "host"
            | "hostname"
            | "broker"
            | "broker_host"
            | "endpoint"
            | "port"
            | "topic"
            | "qos"
            | "keepalive"
            | "timeout"
            | "region"
            | "firmware_version"
            | "build_id"
            | "hardware_rev"
            | "token_ttl"
            | "token_expiry"
            | "password_policy"
            | "auth_mode"
            | "auth_method"
    ) || key.ends_with("_username")
        || key.ends_with("_user")
        || key.ends_with("_id")
        || key.ends_with("_host")
        || key.ends_with("_hostname")
        || key.ends_with("_port")
        || key.ends_with("_ttl")
        || key.ends_with("_expiry")
        || key.ends_with("_timeout")
        || key.ends_with("_policy")
        || key.ends_with("_path")
        || key.ends_with("_file")
        || key.ends_with("_mode")
        || key.ends_with("_version")
}

fn is_review_candidate_key(key: &str) -> bool {
    matches!(
        key,
        "legacy_auth_token_hint"
            | "fallback_credential_seed"
            | "calibration_auth_seed"
            | "diagnostic_key_material"
            | "debug_auth_profile"
    ) || key.ends_with("_auth_seed")
        || key.ends_with("_credential_seed")
        || key.ends_with("_token_hint")
        || key.ends_with("_password_hint")
        || key.ends_with("_auth_profile")
}

fn classify_secret_key(
    key: &str,
    section: &str,
    lower_path: &str,
    val: &str,
) -> Option<&'static str> {
    let in_mqtt_context = section.contains("mqtt")
        || section.contains("broker")
        || lower_path.contains("mqtt")
        || key.starts_with("mqtt_")
        || key.starts_with("broker_");

    let in_cloud_context = section.contains("cloud")
        || section.contains("iot_hub")
        || section.contains("aws_iot")
        || section.contains("azure_iot")
        || lower_path.contains("cloud")
        || key.starts_with("cloud_")
        || key.starts_with("iot_hub_")
        || key.starts_with("aws_iot_")
        || key.starts_with("azure_iot_");

    let in_provisioning_context = section.contains("provisioning")
        || section.contains("bootstrap")
        || section.contains("enrollment")
        || lower_path.contains("provision")
        || lower_path.contains("bootstrap")
        || key.starts_with("provisioning_")
        || key.starts_with("bootstrap_")
        || key.starts_with("enrollment_")
        || key.starts_with("claim_");

    let in_service_account_context = section.contains("service_account")
        || lower_path.contains("service_account")
        || lower_path.contains("service-account")
        || key.starts_with("service_account_")
        || key.starts_with("iam_service_");

    let is_password_like = matches!(key, "password" | "passwd" | "pwd" | "pass")
        || key.ends_with("_password")
        || key.ends_with("_passwd")
        || key.ends_with("_pwd")
        || key.ends_with("_pass");

    let is_token_or_api_key_like = matches!(key, "token" | "api_key" | "apikey" | "api_token")
        || key.ends_with("_token")
        || key.ends_with("_api_key")
        || key.ends_with("_apikey");

    let is_secret_or_key_like = matches!(key, "secret" | "credential" | "psk" | "shared_key")
        || key.ends_with("_secret")
        || key.ends_with("_credential")
        || key.ends_with("_psk")
        || key.ends_with("_private_key")
        || key.ends_with("_secret_key")
        || key.ends_with("_symmetric_key")
        || key.ends_with("_access_key")
        || key.ends_with("_shared_key")
        || key.ends_with("_encryption_key");

    // FL009: SNMP community strings
    if matches!(
        key,
        "snmp_community"
            | "rocommunity"
            | "rwcommunity"
            | "community_string"
            | "snmp_ro_community"
            | "snmp_rw_community"
    ) || key.ends_with("_community")
    {
        return Some("FL009");
    }

    // FL012: Embedded service-account credentials
    if in_service_account_context
        && (is_password_like
            || is_token_or_api_key_like
            || is_secret_or_key_like
            || key.ends_with("_key"))
    {
        return Some("FL012");
    }

    // FL011: Provisioning / bootstrap credentials
    if in_provisioning_context
        && (is_password_like
            || is_token_or_api_key_like
            || is_secret_or_key_like
            || key.ends_with("_key"))
    {
        return Some("FL011");
    }

    // FL010: Device-to-cloud authentication credentials
    if (in_cloud_context
        && (is_password_like
            || is_token_or_api_key_like
            || is_secret_or_key_like
            || key.ends_with("_key")))
        || matches!(
            key,
            "shared_access_key" | "device_symmetric_key" | "device_cloud_token"
        )
        || (val.contains("HostName=") && val.contains("SharedAccessKey="))
    {
        return Some("FL010");
    }

    // FL002: MQTT credential assignments
    if in_mqtt_context && (is_password_like || is_token_or_api_key_like || is_secret_or_key_like) {
        return Some("FL002");
    }

    // FL004: API tokens/keys
    if is_token_or_api_key_like {
        return Some("FL004");
    }

    // FL001: Literal password assignments
    if is_password_like {
        return Some("FL001");
    }

    // FL005: Generic secret/credential assignments
    if is_secret_or_key_like {
        return Some("FL005");
    }

    None
}

fn analyze_binary_bytes(rel_path: &str, bytes: &[u8]) -> FileDetectionOutcome {
    static BIN_AC: OnceLock<AhoCorasick> = OnceLock::new();
    const PATTERNS: &[&str] = &[
        "api_token=",
        "api_key=",
        "auth_token=",
        "webhook_token=",
        "password=",
        "admin_password=",
        "root_password=",
        "wifi_password=",
        "default_password=",
        "user_password=",
        "http_passwd=",
        "passwd=",
        "wpa_psk=",
        "mqtt_password=",
        "mqtt_pass=",
        "master_secret=",
        "secret_key=",
        "snmp_community=",
        "iot_hub_sas_key=",
        "shared_access_key=",
        "provisioning_token=",
        "bootstrap_secret=",
        "service_account_secret=",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN RSA PUBLIC KEY-----",
    ];

    let ac = BIN_AC.get_or_init(|| AhoCorasick::new(PATTERNS).unwrap());
    let mut outcome = FileDetectionOutcome::default();
    let file_class = FileTypeClass::DataOrBinary;

    for mat in ac.find_iter(bytes) {
        let pat_idx = mat.pattern().as_usize();
        let start = mat.start();
        let end = mat.end();

        if pat_idx <= 22 {
            // Assignment pattern in binary stream
            let slice_after = &bytes[end..bytes.len().min(end + 128)];
            let val_len = slice_after
                .iter()
                .position(|&b| b == 0 || b == b'\n' || b == b'\r' || !b.is_ascii_graphic())
                .unwrap_or(slice_after.len());
            if val_len == 0 {
                continue;
            }
            let val_raw = String::from_utf8_lossy(&slice_after[..val_len]);
            let val_str = unquote_value(val_raw.trim());
            let rule_id = match pat_idx {
                0..=3 => "FL004",
                4..=12 => "FL001",
                13 | 14 => "FL002",
                15 | 16 => "FL005",
                17 => "FL009",
                18 | 19 => "FL010",
                20 | 21 => "FL011",
                22 => "FL012",
                _ => "FL005",
            };
            let rule = find_rule(rule_id).expect("rule exists");

            if let Some(reason) = classify_suppression_reason(val_str) {
                outcome.suppressed.push(SuppressedCandidate {
                    rule_id: rule.id.to_string(),
                    category: rule.category.to_string(),
                    status: CandidateStatus::BenignOrSuppressed,
                    suppression_reason: reason.to_string(),
                    policy_points: 0,
                    signals: vec![
                        file_type_signal(file_class),
                        EvidenceSignal {
                            name: "binary_placeholder_suppression".to_string(),
                            points: -80,
                            detail: format!("Binary embedded assignment suppressed ({reason})"),
                        },
                    ],
                    file_path: rel_path.to_string(),
                    line_number: None,
                    byte_offset: start as u64,
                    evidence: rule.redacted_evidence.to_string(),
                });
                continue;
            }

            let signals = vec![
                file_type_signal(file_class),
                EvidenceSignal {
                    name: "binary_embedded_assignment".to_string(),
                    points: 55,
                    detail: format!(
                        "Embedded ASCII credential assignment pattern '{}' in binary payload",
                        PATTERNS[pat_idx]
                    ),
                },
                EvidenceSignal {
                    name: "non_empty_literal".to_string(),
                    points: 20,
                    detail: "Binary literal contains non-placeholder value".to_string(),
                },
            ];
            let points = signals.iter().map(|s| s.points).sum();
            outcome.findings.push(Finding {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                severity: rule.default_severity,
                kind: FindingKind::Finding,
                status: CandidateStatus::ConfirmedByStructuralRule,
                policy_points: points,
                signals,
                file_path: rel_path.to_string(),
                line_number: None,
                byte_offset: start as u64,
                evidence: rule.redacted_evidence.to_string(),
                explanation: rule.explanation.to_string(),
                remediation: rule.remediation.to_string(),
            });
        } else if pat_idx <= 26 {
            // PEM private-key marker in binary stream
            let marker = PATTERNS[pat_idx];
            let end_marker = marker.replacen("-----BEGIN ", "-----END ", 1);
            let tail = String::from_utf8_lossy(&bytes[end..bytes.len().min(end + 4096)]);
            let rule = find_rule("FL003").expect("FL003 exists");

            if tail.contains(&end_marker) {
                let signals = vec![
                    file_type_signal(file_class),
                    EvidenceSignal {
                        name: "binary_pem_private_key".to_string(),
                        points: 75,
                        detail: "Complete PEM private-key block embedded in binary data"
                            .to_string(),
                    },
                ];
                let points = signals.iter().map(|s| s.points).sum();
                outcome.findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    category: rule.category.to_string(),
                    severity: Severity::High,
                    kind: FindingKind::Finding,
                    status: CandidateStatus::ConfirmedByStructuralRule,
                    policy_points: points,
                    signals,
                    file_path: rel_path.to_string(),
                    line_number: None,
                    byte_offset: start as u64,
                    evidence: rule.redacted_evidence.to_string(),
                    explanation: rule.explanation.to_string(),
                    remediation: rule.remediation.to_string(),
                });
            } else {
                let signals = vec![
                    file_type_signal(file_class),
                    EvidenceSignal {
                        name: "incomplete_pem_marker".to_string(),
                        points: 30,
                        detail: "Isolated BEGIN private-key marker in binary payload".to_string(),
                    },
                ];
                let points = signals.iter().map(|s| s.points).sum();
                outcome.findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    category: rule.category.to_string(),
                    severity: Severity::Info,
                    kind: FindingKind::Hint,
                    status: CandidateStatus::RequiresReview,
                    policy_points: points,
                    signals,
                    file_path: rel_path.to_string(),
                    line_number: None,
                    byte_offset: start as u64,
                    evidence: rule.redacted_evidence.to_string(),
                    explanation: "An isolated or incomplete private-key marker was found. This is an informational hint, not proof of an embedded key.".to_string(),
                    remediation: "Inspect the surrounding data in a controlled environment to determine whether a key is present.".to_string(),
                });
            }
        } else {
            // Public PEM certificate or public key in binary stream -> record as suppressed
            let rule = find_rule("FL003").expect("FL003 exists");
            outcome.suppressed.push(SuppressedCandidate {
                rule_id: rule.id.to_string(),
                category: rule.category.to_string(),
                status: CandidateStatus::BenignOrSuppressed,
                suppression_reason: "public_certificate_or_key".to_string(),
                policy_points: 0,
                signals: vec![EvidenceSignal {
                    name: "public_pem_header".to_string(),
                    points: -100,
                    detail: "Public certificate or public key PEM block in binary image is not a private key"
                        .to_string(),
                }],
                file_path: rel_path.to_string(),
                line_number: None,
                byte_offset: start as u64,
                evidence: "public certificate/key = [SUPPRESSED]".to_string(),
            });
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_inline_comments_only_outside_quotes() {
        assert_eq!(
            strip_inline_comment("password = \"p@ss#123;ok\" # inline comment"),
            "password = \"p@ss#123;ok\""
        );
        assert_eq!(
            strip_inline_comment("api_key = abc#def ; trailing note"),
            "api_key = abc#def"
        );
    }

    #[test]
    fn redacts_finding_and_never_emits_secret_literal() {
        let sample = "password = \"SuperSecretIoTRootPass99!\"\n";
        let res = analyze_file_bytes("etc/gateway.conf", sample.as_bytes(), 16384);
        assert_eq!(res.findings.len(), 1);
        assert_eq!(res.findings[0].rule_id, "FL001");
        assert_eq!(res.findings[0].evidence, "password = [REDACTED]");
        let serialized = serde_json::to_string(&res.findings).unwrap();
        assert!(!serialized.contains("SuperSecretIoTRootPass99!"));
    }

    #[test]
    fn suppresses_env_placeholders_with_explicit_reason() {
        let sample = "password = \"${DEVICE_RUNTIME_PASS}\"\napi_token = \"<INJECTED_AT_BOOT>\"\n";
        let res = analyze_file_bytes("etc/gateway.conf", sample.as_bytes(), 16384);
        assert!(res.findings.is_empty());
        assert_eq!(res.suppressed.len(), 2);
        assert_eq!(
            res.suppressed[0].suppression_reason,
            "env_or_template_reference"
        );
        assert_eq!(
            res.suppressed[1].suppression_reason,
            "external_secret_reference"
        );
    }

    #[test]
    fn detects_arbitrary_dynamic_keys_and_contexts() {
        let sample = "\
[zigbee_radio]
zigbee_network_psk = \"9f8e7d6c5b4a3f2e1d0c\"
radius_auth_password = \"CustomRadiusSecret!\"
custom_ota_api_key = \"ota_live_key_abc123\"
device_serial_id = \"SN-998877\"

[mqtt_upstream_bridge]
bridge_pass = \"BridgeUpstreamSecret42\"
";
        let res = analyze_file_bytes("etc/custom-vendor.conf", sample.as_bytes(), 16384);
        let rules: Vec<&str> = res.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(rules, vec!["FL005", "FL001", "FL004", "FL002"]);
    }
}
