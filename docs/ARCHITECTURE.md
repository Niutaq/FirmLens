# Architecture (`FirmLens` v0.2)

FirmLens is structured as a modular Cargo workspace with a single analysis engine (`firmlens-core`) and two thin adapters (`firmlens-cli` and `firmlens-api` + `web/`). Neither adapter duplicates traversal, extraction, redaction, or detection logic.

## 1. Crate Responsibilities

| Component | Path | Responsibility |
| --- | --- | --- |
| **`firmlens-core`** | `crates/firmlens-core` | Pure library crate owning `ScanReport` (JSON Schema 2.2), bounded TAR/TAR.GZ/ZIP ingestion (`ingestion.rs`), isolated Docker Binwalk v3 identification/extraction (`binwalk.rs`, `pipeline.rs`), lexical-contextual secret & configuration detection (`detector.rs`, `rules.rs`), deterministic directory traversal (`scanner.rs`), and typed errors (`error.rs`). Operates without HTTP, CLI, or a database. |
| **`firmlens-cli`** | `crates/firmlens-cli` | Command-line interface (`clap`), human-readable terminal summaries, deterministic JSON report emission, atomic new-file creation (`--output`), `RUST_LOG` diagnostics on `stderr`, and exit code mapping (`0`, `1`, `2`, `3`). |
| **`firmlens-api`** | `crates/firmlens-api` | Loopback-only (`127.0.0.1:8787`) Axum HTTP adapter. Streams bounded `.tar`/`.tar.gz`/`.tgz` uploads to temporary workspaces, invokes `firmlens_core::scan_path` inside bounded worker permits, retains up to 8 sanitized reports in memory, and computes structural report diffs (`/api/diff`). |
| **`web/`** | `web/` | Local React 19 + TypeScript + Vite single-page interface for uploading archives, inspecting `Overview`, `Findings`, `Files`, and `Diff` views, and exporting Schema 2.1 JSON reports. |

## 2. End-to-End Analysis Pipeline

1. **Input Classification & Ingestion (`ingestion.rs`, `pipeline.rs`)**
   - Unpacked directories are traversed directly with `follow_links(false)` (`IngestionOutcome::DirectoryScanned`).
   - `.tar`, `.tar.gz`, `.tgz`, and `.zip` files are extracted into an ephemeral temporary directory using two-stage `BoundedReader` streams (`max_input_bytes`, `max_expanded_bytes`, `max_member_bytes`) and strict component validation (`IngestionOutcome::ArchiveExtracted`). Any disallowed member aborts and deletes the entire staging directory (`IngestionOutcome::RejectedArchive`).
   - Opaque binary images optionally unpack via isolated Binwalk v3 (`--binwalk-extract` → `IngestionOutcome::ImageExtracted`). Without unpacking they remain `UnsupportedImage` (`partial = true`) and may run signature identification (`--binwalk`) and/or bounded raw binary payload scanning.
2. **Traversal & Inventory (`scanner.rs`)**
   - Files and directories are sorted deterministically by normalized relative path.
   - Build/VCS directories, generated `*.firmlens.json` / `report*.json` files, and documentation (`*.md`, `*.rst`, `*.adoc`, `README*`, `LICENSE*`) are explicitly excluded and recorded in `skipped_files` and `inventory` (`FileAnalysisStatus::Skipped`).
   - Every visited file within `max_entries` is recorded in `inventory: Vec<FileInventoryEntry>`.
3. **Lexical-Contextual Evaluation & Redaction (`detector.rs`, `rules.rs`)**
   - Text configurations and scripts are scanned line-by-line while tracking INI sections, inline comments outside quotes, key names, and literal value characteristics.
   - Binary files (`.bin`, `.dat`, or non-UTF-8 blobs) are scanned for printable ASCII segments using an `Aho-Corasick` automaton over sensitive keywords and protocol prefixes.
   - Raw secret values and private key bodies are discarded immediately after computing `EvidenceSignal` policy points and a fixed redacted string (`password = [REDACTED]`, `private key material = [REDACTED]`, etc.).
4. **Report Finalization (`model.rs`)**
   - Candidates are partitioned into `findings` (`confirmed_by_structural_rule`, `likely_secret`, `requires_review`, plus `kind = "hint"`) and `suppressed` (`benign_or_suppressed`), sorted deterministically, and summarized with an explicit `partial` coverage boolean.
