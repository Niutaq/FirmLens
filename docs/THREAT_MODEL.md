# Threat Model & Security Boundaries

FirmLens analyzes untrusted firmware filesystem trees and bounded archive envelopes (`TAR`, `TAR.GZ`). Because static analysis tools are frequently run in CI/CD pipelines and analyst workstations against adversarial or malformed third-party firmware images, the parser and extractor are treated as a primary attack surface.

## 1. Untrusted Archive Ingestion Threats & Controls

| Threat Vector | Attack Mechanism | FirmLens Control (`crates/firmlens-core/src/ingestion.rs`) |
| --- | --- | --- |
| **Decompression Bomb (Gzip / TAR Bomb)** | A small `.tar.gz` expands to tens of gigabytes, exhausting disk or RAM in the CI runner. | Dual-layer `BoundedReader`: caps raw compressed input (`max_input_bytes = 128 MiB`), expanded TAR stream (`max_expanded_bytes = 256 MiB`), and individual member payload (`max_member_bytes = 8 MiB`). |
| **Path Traversal (Zip Slip)** | Archive member names contain `../../etc/cron.d/pwn`, `/etc/passwd`, or Windows drive prefixes `C:\...`. | `validate_archive_member_path` inspects every `std::path::Component`, rejecting `ParentDir`, `RootDir`, `Prefix`, backslashes, NUL bytes, colons, and paths deeper than `max_extraction_depth = 32`. |
| **Symlink / Hardlink Escape** | Archive creates a symlink `etc/config -> /etc/shadow` followed by a regular file read or write through that symlink. | Every TAR header `EntryType` is allowlisted (`Regular`, `Continuous`, `Directory` only). `Symlink` and `Link` immediately abort extraction. |
| **Special Device Nodes & FIFOs** | Archive creates a named pipe (`FIFO`) that blocks reader threads indefinitely, or device nodes (`Char`, `Block`). | All non-regular, non-directory TAR entry types (`Fifo`, `Char`, `Block`, `GNUSparse`, `XHeader`, `XGlobalHeader`, `GNULongName`, `GNULongLink`) are rejected before touching the filesystem. |
| **Case-Folding / Duplicate Aliasing** | Archive includes both `etc/Config` and `etc/config` to confuse policy evaluation on case-insensitive filesystems (macOS/Windows) vs Linux. | Canonical lowercase path tracking (`seen_paths_lower`) combined with `OpenOptions::create_new(true)` rejects duplicate or case-colliding entries across all operating systems. |
| **Partial-Extraction False Clean** | An archive contains 5 valid files followed by a malicious 6th entry; naive scanners analyze the first 5 files and report results. | **All-or-nothing staging**: any rejected entry triggers `temp_dir.close()`, discards the entire workspace, sets `IngestionOutcome::RejectedArchive`, and marks the report `partial = true` with `0` scanned files. |
| **Recursive Nested Archive Bombs** | Nested `.tar.gz` inside `.tar.gz` causes exponential CPU/disk amplification. | Maximum archive nesting is strictly **1 outer envelope**. Inner `.tar`/`.tar.gz`/`.gz` files are never recursively expanded; they are recorded as `nested_archive_not_expanded` (`partial = true`). |

## 2. Limitations Declared Explicitly

1. **Cooperative Deadlines**: `BoundedReader` checks `ingestion_timeout_ms` (default 30,000 ms) on every `Read::read` call. It is not an OS kernel pre-emptive kill signal against blocking network filesystems.
2. **Same-User Concurrent Mutation (TOCTOU)**: When scanning an unpacked local directory directly, FirmLens assumes the directory tree is not concurrently mutated by another process running under the same OS UID.
3. **No Arbitrary Filesystem Mounting**: Raw SquashFS, UBIFS, JFFS2, or kernel loopback mounts are never invoked on the host. Optional binary signature identification via Binwalk v3 is restricted to an isolated, network-disabled Docker container.
