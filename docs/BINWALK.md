# Binwalk v3 Integration Decision

## Context
FirmLens evaluates unpacked directories and bounded `TAR`/`TAR.GZ` archives natively in Rust. For opaque firmware images (`.bin`, `.img`, SquashFS, UBI, bootloader blobs), researchers often want to know what headers or filesystems exist at specific byte offsets without executing arbitrary third-party extractors on the host.

## Evaluated Approaches
1. **Direct In-Process Library (`binwalk = "3.1.0"` crate):**
   - Pulls native system library dependencies (`fontconfig`/`freetype` via `plotters`) into every platform build, complicating portable Windows/macOS/Linux compilation.
   - Runs complex binary signature parsers inside the same OS process and memory space as the FirmLens scanner.
2. **Isolated Containerized CLI (`firmlens-binwalk:3.1.0`):**
   - Keeps `firmlens-core` 100% portable Rust without C/C++ linker prerequisites.
   - Enforces OS-level process, network, filesystem, capability, UID, PID, CPU, memory, and wall-clock timeout boundaries around Binwalk v3 (`3.1.0`).

## Security Controls
- **No automatic image pulls:** FirmLens checks for the local image via `docker image inspect` and passes `--pull=never`.
- **Exact version check:** FirmLens verifies `binwalk 3.1.0` before accepting output.
- **Strict container flags:**
  - `--network=none`
  - `--cap-drop=ALL`
  - `--security-opt=no-new-privileges`
  - `--read-only` root filesystem
  - `--user 65534:65534` (unprivileged nobody UID/GID)
  - `--pids-limit=64`, `--memory=512m`, `--cpus=1`
  - Single read-only bind mount of a staged copy of the input file (`/input/firmware.bin:ro`).
- **Identification only (never extraction):** Extraction (`-e`) and recursive (`-M`) flags are never passed.
- **Sanitized output:** Raw Binwalk descriptions (which may echo filenames or strings embedded in the binary) are mapped to fixed category identifiers before constructing `SignatureMatch`.
- **No unsandboxed host fallback:** If Docker or the trusted image is unavailable, `identification.status` is reported as `unavailable` and the scan remains `partial: true`.
