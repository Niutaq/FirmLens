# Working on FirmLens

FirmLens is a static firmware security research toolkit. Keep it working and measurable.

## Architecture
- `firmlens-core` owns traversal, limits, extraction, detection and report models. Its public API must work without the CLI, HTTP or a database.
- `firmlens-cli` owns clap arguments, terminal formatting, JSON serialization and exit codes.
- `firmlens-api` is a thin local Axum adapter over the core. `web/` owns React presentation; never duplicate detection in either adapter.
- Keep uploads, workers and retained reports bounded. Bind to loopback, validate browser origins and Host, and never accept server filesystem paths from HTTP clients.

## Rust conventions
- Use stable Rust, format with rustfmt, prefer explicit structs/enums and small functions.
- Return typed errors from the library and contextual errors from the CLI. Do not panic on user input.
- Keep findings deterministically ordered. Add meaningful regression tests for security behavior.
- Avoid unsafe Rust, global mutable state and unnecessary abstractions.
- Support Linux, macOS and Windows. Keep shared scripts portable (Python standard library when needed), use `std::path`, and isolate platform-specific filesystem safeguards behind `cfg` with platform tests. Do not make PowerShell a build or test prerequisite.

## Security rules
- Analyze synthetic fixtures only during development. Never execute firmware, extracted content or sample commands.
- Never include source lines, credential values, key bodies or reversible encodings of them in reports, logs or errors. Redact before constructing public findings.
- Never follow symlinks. Preserve file, byte, record, entry, depth and finding limits. Treat partial coverage explicitly.
- Exclude build directories and generated reports. Never overwrite input files to write a report.
- Do not treat a public certificate, endpoint or random identifier as a secret.
- Document threat-model limitations instead of claiming exhaustive or race-proof analysis.

## Validation
Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo build --workspace --locked`, and `cargo test --workspace --locked`.
Exercise `cargo run -p firmlens-cli -- scan fixtures/vulnerable --format json` and compare with `fixtures/hardened`.
For web changes run `npm ci`, `npm test`, `npm run typecheck`, and `npm run build` in `web/`. Use `python scripts/check_web_workflow.py` for real CLI/API consistency after building Rust. Browser workflow instructions are in docs/WEB_APPLICATION.md. Never substitute mocked production findings for engine reports.
Update docs/SESSION_HANDOFF.md after each verified milestone, not just at session end. Record failed/unavailable checks honestly. Do not commit unless requested.

## Documentation
Update README usage when flags change; document JSON schema changes, confidence policy, limitations and fixture expectations. Use fictional, nonfunctional credentials and reserved `.invalid` domains. Research claims must be tied to reproducible measurements, not detection counts alone.

## Scope
Prefer maintainable local code. No microservices, databases, message brokers, Kubernetes, firmware execution or speculative frameworks. Do not silently substitute mocks for features.

Ingestion supports bounded TAR/TAR.GZ processing; arbitrary firmware extraction remains disabled. Binwalk identification must run inside the configured isolation boundary, never through an unsandboxed fallback. Treat signatures and extracted files as distinct outcomes.
