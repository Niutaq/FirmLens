# FirmLens Local Web Application (`firmlens-api` & `web/`)

## Architecture & Security Boundary
- `firmlens-api` binds strictly to `127.0.0.1:8787` (or a loopback override via `FIRMLENS_API_HOST`/`FIRMLENS_API_PORT`; non-loopback addresses are rejected at startup).
- Every HTTP request is checked for a loopback `Host` header (`127.0.0.1`, `localhost`, `[::1]`) and, when present, a loopback `Origin` header (`http://127.0.0.1:5173`, etc.).
- Server filesystem paths (`?path=...` or JSON bodies) are never accepted from HTTP clients. Clients must stream a bounded `.tar`, `.tar.gz`, or `.tgz` archive.
- Resource limits:
  - Up to **4** concurrent admitted uploads/jobs (`429 Too Many Requests` when exceeded).
  - Up to **2** concurrent scan workers (`tokio::task::spawn_blocking`).
  - Up to **8** retained scan reports in memory (FIFO eviction; restarting clears memory).
  - Up to **128 MiB** per uploaded archive (`413 Payload Too Large` when exceeded).
- Neither `firmlens-api` nor `web/` duplicates detection logic; all reports come directly from `firmlens_core::scan_path`.

## HTTP Endpoints
- `GET /api/health` — Server status, schema version (`2.1`), ruleset version (`2`), and active limits.
- `GET /api/rules` — Metadata for all 12 registered rules (`FL001`–`FL012`), including MITRE CWE, OWASP IoT Top 10, and ETSI EN 303 645 standard mappings.
- `GET /api/scans` — Summary list of retained scans in memory (newest first).
- `POST /api/scans?filename=<archive.tar.gz>` — Bounded binary stream (or `multipart/form-data`) upload and immediate analysis.
- `GET /api/scans/{id}` — Full stored scan metadata and Schema 2.1 `ScanReport`.
- `DELETE /api/scans/{id}` — Remove a retained scan from memory.
- `GET /api/scans/{id}/report` — Download the raw Schema 2.1 JSON report (`*.firmlens.json`).
- `GET /api/diff?base={id1}&target={id2}` — Structural comparison between two retained scans, including explicit partial-coverage caveats.

## Interactive Web UI Features (`EN / PL`) & USB Auto-Scanner
- **Full Bilingual Interface (`EN / PL`):** Switch between English and Polish at any time via the topbar `EN | PL` toggle (stored in `localStorage`).
- **Interactive Dashboard Charts & KPI Cards:** Clicking any posture segment/legend, IoT Vector bar (`Auth`, `Cloud`, `TLS/Key`, `Net/URI`, `Safe`), Rule Profile column (`01–12`), or bottom KPI card jumps directly to the filtered **Findings** or **Files** view.
- **IoT Rules & CWE Reference Modal:** Inspect all 12 rules (`FL001–FL012`) alongside their MITRE CWE, OWASP IoT Top 10, and ETSI EN 303 645 mappings.
- **USB Pendrive & Hotfolder Auto-Scanner (`scripts/usb_watch.py`):** Monitors `dropzone/` or removable USB media mounts (`/media/$USER`, `/run/media/$USER`, `/Volumes`) and streams newly detected `.tar`/`.tar.gz`/`.tgz` archives (or packaged rootfs directories) to `127.0.0.1:8787/api/scans` so they appear live in the Web UI while **Auto-Sync** is enabled:
```bash
python3 scripts/usb_watch.py --auto-usb
```

## Running & Validating Locally

One-command portable task runner (generates fixtures/archives, builds `firmlens-api`, and starts both `127.0.0.1:8787` and `127.0.0.1:5173`):
```bash
python3 scripts/task.py dev    # or: make dev
python3 scripts/task.py check  # or: make check
python3 scripts/task.py demo   # or: make demo
```

Or step-by-step:
```bash
cargo build --workspace --locked
python3 scripts/generate_archives.py
python3 scripts/check_web_workflow.py
```

For the React frontend in `web/`:
```bash
cd web
npm install
npm test
npm run typecheck
npm run build
```
