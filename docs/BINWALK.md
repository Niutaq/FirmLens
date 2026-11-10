# Binwalk v3 Integration Decision

## Context
FirmLens evaluates unpacked directories and bounded `TAR`/`TAR.GZ`/`ZIP` archives natively in Rust. Opaque firmware images (`.bin`, `.img`, `.chk`, SquashFS/LZMA envelopes) require a second stage: isolated Binwalk unpacking before lexical static analysis. Scanning the compressed vendor blob directly yields false negatives because credential and config detectors never see plaintext files such as `/etc/shadow` or `.cgi` scripts.

## Evaluated Approaches
1. **Direct In-Process Library (`binwalk = "3.1.0"` crate):**
   - Pulls native system library dependencies (`fontconfig`/`freetype` via `plotters`) into every platform build, complicating portable Windows/macOS/Linux compilation.
   - Runs complex binary signature parsers inside the same OS process and memory space as the FirmLens scanner.
2. **Isolated Containerized CLI (`firmlens-binwalk:3.1.0`):**
   - Keeps `firmlens-core` 100% portable Rust without C/C++ linker prerequisites.
   - Enforces OS-level process, network, filesystem, capability, UID, PID, CPU, memory, and wall-clock timeout boundaries around Binwalk v3 (`3.1.0`).

## Two-Stage Pipeline
1. **Identification** (`--binwalk`): read-only signature offsets; never extracts files.
2. **Extraction** (`--binwalk-extract`): `binwalk --extract --matryoshka --directory /output /input/firmware.bin` inside Docker, then FirmLens walks the materialized tree and deletes the temporary workspace (RAII via `tempfile::TempDir`, including on scan errors).
3. **Reporting**: `ingestion.outcome = image_extracted` when unpack succeeds; `identification.signatures` remain a separate field from scanned findings.

Orchestration lives in `crates/firmlens-core/src/pipeline.rs`. The library API is synchronous; `firmlens-api` runs `scan_path` on `tokio::task::spawn_blocking` so unpacking never blocks the Axum reactor.

## Security Controls
- **No automatic image pulls:** FirmLens checks for the local image via `docker image inspect` and passes `--pull=never`.
- **Exact version check:** FirmLens verifies `binwalk 3.1.0` before accepting output.
- **Strict container flags (both modes):**
  - `--network=none`
  - `--cap-drop=ALL`
  - `--security-opt=no-new-privileges`
  - `--pids-limit`, `--memory`, `--cpus` caps
  - argv-only invocation with fixed container paths (`/input/firmware.bin`, `/output`) — untrusted filenames never enter the argument vector (command-injection resistant)
  - Wall-clock timeout with process kill (extraction floor: 180s)
- **Identification mode extras:** `--read-only` root filesystem, `--user 65534:65534`, single read-only bind of the staged input.
- **Extraction mode extras:** writable bind for `/output`, host UID/GID when available (so cleanup does not require root on the host), `BINWALK_RM_EXTRACTION_SYMLINK=1`, post-extraction file/byte budgets (`max_extracted_files`, `max_expanded_bytes`).
- **No unsandboxed host fallback:** If Docker or the trusted image is unavailable, status is `unavailable` / `unsupported_image` and the API may fall back only to bounded in-process binary string scanning — never to a host `binwalk` binary.
- **Sanitized output:** Raw Binwalk descriptions are mapped to fixed category identifiers before constructing `SignatureMatch`.
- **Cleanup:** Temporary extraction trees are always removed after analysis (`cleanup_verified` in the report).

## Container Extractors
`containers/binwalk/Dockerfile` ships Binwalk 3.1.0 plus bounded helpers (`sasquatch`, `squashfs-tools`, compression/archive utilities) required for nested SquashFS/LZMA firmware envelopes. FirmLens still never executes firmware payloads.
