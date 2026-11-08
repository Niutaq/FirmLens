# Reproducible Evaluation Protocol

FirmLens evaluates detection rules against three deterministic, synthetic fixture trees (`fixtures/vulnerable`, `fixtures/hardened`, and `fixtures/benign`) and their corresponding TAR/TAR.GZ archives (`generated-fixtures/`). Ground-truth expectations are versioned in [fixtures/expected.json](../fixtures/expected.json).

## 1. Synthetic Fixture Design

All credentials, tokens, URIs, and PEM structures in `fixtures/` are **invented and nonfunctional**; all domains use RFC 2606 `.invalid` suffixes (`.iot.invalid`, `.cloud.invalid`, `.vendor.invalid`).

| Fixture Set | Purpose | Files Scanned | Excluded Docs | Actionable | Hints | Review | Suppressed | Partial |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `fixtures/vulnerable` | Exercises all 12 rules (`FL001`–`FL012`) across `.conf`, `.ini`, `.json`, `.yaml`, `.sh`, `.pem`, `.dat`, plus an incomplete PEM hint and 5 benign/placeholder controls. | 7 | 1 (`README.md`) | **12** | **1** | **0** | **5** | `true` (exit `2`) |
| `fixtures/hardened` | Mirrors the exact service architecture of `vulnerable` after remediation: external secret references (`/run/secrets/...`), `${ENV_VAR}` templates, TLS verification enabled, anonymous access disabled, and public certificates. | 7 | 1 (`README.md`) | **0** | **0** | **0** | **12** | `true` (exit `2`) |
| `fixtures/benign` | Clean configuration tree with ordinary endpoints, public certificates, device identifiers, and one ambiguous legacy review token (`requires_review`) with no documentation files. | 4 | 0 | **0** | **0** | **1** | **6** | `false` (exit `0`) |

## 2. Interpreting Results Honestly

1. **Zero Actionable False Positives vs. Review Candidates**: On `fixtures/benign`, `actionable_findings == 0`, while `review_candidates == 1` is deliberately retained to demonstrate that ambiguous tokens are surfaced for human review rather than silently dropped or over-claimed as confirmed secrets.
2. **Partial Coverage on `vulnerable` and `hardened`**: Both trees include a `README.md` file that is intentionally excluded by documentation filter rules. Consequently, both reports set `partial = true` and `skipped_entries = 1`. When comparing `vulnerable` and `hardened` via `/api/diff` or the web UI, the reduction of actionable findings from `12` to `0` is always accompanied by an explicit partial-coverage caveat.
3. **Rule-Aligned Scope**: These fixtures validate rule determinism, contextual suppression, and redaction invariants across directory and archive ingestion; they are not a substitute for an empirical benchmark on third-party firmware corpora.

## 3. Reproducing the Evaluation

```bash
python3 scripts/generate_fixtures.py
python3 scripts/generate_archives.py
cargo test --workspace --locked
python3 scripts/check_web_workflow.py
```
