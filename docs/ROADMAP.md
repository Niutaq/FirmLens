# Roadmap & Scope Boundaries

FirmLens is maintained as a focused, measurable static firmware security research toolkit. Every milestone prioritizes deterministic behavior, explicit coverage reporting, and strict redaction over speculative features.

## Completed Milestones (v0.2 · Schema 2.1)

- **Core Engine (`firmlens-core`)**:
  - JSON Schema `2.1` report model with per-file inventory (`FileInventoryEntry`), explicit `EvidenceSignal` policy-point breakdown, and candidate statuses (`confirmed_by_structural_rule`, `likely_secret`, `requires_review`, `benign_or_suppressed`).
  - Redaction-by-construction ensuring secret values, URI passwords, key bodies, and raw Binwalk descriptions never enter public findings or error messages.
  - Bounded `TAR` and `TAR.GZ` ingestion with Zip-Slip prevention, symlink/special-file rejection, case-collision detection, all-or-nothing temporary workspace cleanup, and single-envelope nesting limits (`nested_archive_not_expanded`).
  - 12 lexical-contextual IoT & NetSecOps rules (`FL001`–`FL012`) with INI section tracking, inline comment handling, placeholder/reference suppression, and binary `Aho-Corasick` string scanning.
- **Isolated Signature Identification (`containers/binwalk`)**:
  - Optional Binwalk v3 (`3.1.0`) invocation behind a read-only, network-disabled, capability-dropped Docker boundary with sanitized category labels.
- **CLI & Local Web Application (`firmlens-cli`, `firmlens-api`, `web/`)**:
  - Deterministic CLI with `rules list`, `scan`, safe `--output` file creation, and exit codes `0/1/2/3`.
  - Loopback-only Axum API (`127.0.0.1:8787`) and React 19 UI supporting bounded archive uploads, `Overview`, `Findings`, `Files`, and `Diff` views, and Schema 2.1 JSON export.

## Non-Goals (Out of Scope by Design)

- Firmware emulation, binary execution, or live network validation of discovered credentials.
- Unsandboxed host extraction of SquashFS, UBIFS, JFFS2, cramfs, or arbitrary vendor partition images.
- Opaque LLM/AI scoring or entropy-only secret claims without structural/contextual evidence signals.
- Multi-tenant cloud deployment, external databases, or remote filesystem path scanning over HTTP.
