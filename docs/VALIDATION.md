# Observed Validation Results

This document records the verification steps executed locally on Linux (`x86_64-unknown-linux-gnu`) and what is configured in `.github/workflows/ci.yml` for cross-platform CI (`ubuntu-latest`, `macos-latest`, `windows-latest`).

## 1. Local Verification Summary (Linux)

| Check | Command | Observed Result |
| --- | --- | --- |
| Rust Formatting | `cargo fmt --all -- --check` | **PASS** |
| Rust Clippy Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **PASS** (0 warnings) |
| Workspace Build | `cargo build --workspace --locked` | **PASS** (`firmlens-core`, `firmlens-cli`, `firmlens-api`) |
| Workspace Unit & Integration Tests | `cargo test --workspace --locked` | **PASS** (20 active tests across `firmlens-core`, `firmlens-cli`, `firmlens-api`) |
| Fixture & Archive Reproducibility | `python3 scripts/generate_fixtures.py && python3 scripts/generate_archives.py` | **PASS** (`fixtures/` and `generated-fixtures/` match `fixtures/expected.json`) |
| CLI vs. HTTP API Parity & Diff | `python3 scripts/check_web_workflow.py` | **PASS** (identical findings, suppressions, and summary metrics across CLI and `/api/scans` + `/api/diff`) |
| Web Dependencies & Lockfile | `cd web && npm ci` | **PASS** (0 vulnerabilities) |
| Web Unit Tests (`diff.test.ts`) | `cd web && npm test` | **PASS** |
| Web TypeScript Check | `cd web && npm run typecheck` | **PASS** |
| Web Production Bundle | `cd web && npm run build` | **PASS** (`dist/` built cleanly with Vite) |

## 2. Optional / Environment-Dependent Checks

- **Isolated Binwalk v3 Container Test (`live_binwalk`)**:
  - Command: `docker build -t firmlens-binwalk:3.1.0 containers/binwalk && cargo test -p firmlens-core --locked --test ingestion live_binwalk -- --ignored`
  - Extraction: `cargo test -p firmlens-core --locked --test ingestion live_binwalk_extract_gzip_layer -- --ignored`
  - Status: Covered by the `binwalk-identification` job in `.github/workflows/ci.yml` and tested via unit/sanitization tests in `firmlens-core` when the local `firmlens-binwalk:3.1.0` image is not prebuilt.
- **Playwright Browser E2E (`npm run test:e2e`)**:
  - Command: `cd web && npx playwright install --with-deps chromium && npm run test:e2e`
  - Status: Configured in `web/e2e/workflow.spec.ts` and the `web` job in `.github/workflows/ci.yml`; CLI/API parity is verified locally without browser binaries via `python3 scripts/check_web_workflow.py`.
