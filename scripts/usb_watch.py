#!/usr/bin/env python3
"""Portable USB Pendrive & Hotfolder Auto-Scanner for FirmLens.

Uses only the Python 3 standard library. Monitors a local dropzone directory
and optionally removable USB mount roots (/media, /run/media, /Volumes).
When a new .tar, .tar.gz, or .tgz firmware archive (or an unpacked firmware
subdirectory) is detected, it streams the bounded archive to the local
firmlens-api loopback server (http://127.0.0.1:8787/api/scans) so the report
appears immediately in the Web UI. Never follows symlinks or executes content.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DROPZONE = REPO_ROOT / "dropzone"
DEFAULT_API_URL = "http://127.0.0.1:8787"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024  # 128 MiB


def sanitize_stem(name: str) -> str:
    cleaned = "".join(
        c if (c.isalnum() or c in ".-_") else "_" for c in name.strip()
    ).lstrip(".")
    return cleaned or "usb-firmware"


def pack_directory_to_tar_gz(source_dir: Path, max_bytes: int = MAX_ARCHIVE_BYTES) -> bytes:
    """Safely package an unpacked firmware directory into an in-memory USTAR .tar.gz
    without following symlinks.
    """
    buf = io.BytesIO()
    total_bytes = 0
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for root, dirs, files in os.walk(source_dir, followlinks=False):
            root_path = Path(root)
            # Filter out symlinks and hidden VCS/build dirs
            dirs[:] = sorted(
                d
                for d in dirs
                if not d.startswith(".")
                and not (root_path / d).is_symlink()
            )
            for fname in sorted(files):
                fpath = root_path / fname
                if fpath.is_symlink() or not fpath.is_file():
                    continue
                rel_posix = fpath.relative_to(source_dir).as_posix()
                if len(rel_posix) > 100:
                    continue
                data = fpath.read_bytes()
                total_bytes += len(data)
                if total_bytes > max_bytes:
                    raise ValueError(f"Directory exceeds {max_bytes} byte limit")
                info = tarfile.TarInfo(name=rel_posix)
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 1700000000
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=1700000000) as gz:
        gz.write(buf.getvalue())
    return gz_buf.getvalue()


def discover_usb_mount_dirs() -> list[Path]:
    """Return existing removable media directories on Linux / macOS."""
    candidates: list[Path] = []
    user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    roots = [
        Path("/media") / user if user else Path("/media"),
        Path("/run/media") / user if user else Path("/run/media"),
        Path("/Volumes"),
    ]
    for root in roots:
        try:
            if root.is_dir() and not root.is_symlink():
                for child in sorted(root.iterdir()):
                    if child.is_dir() and not child.is_symlink():
                        candidates.append(child)
        except OSError:
            continue
    return candidates


def upload_archive_bytes(api_url: str, filename: str, payload: bytes) -> dict:
    url = f"{api_url.rstrip('/')}/api/scans?filename={filename}"
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Filename": filename,
            "Origin": "http://127.0.0.1:5173",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scan_watch_roots(
    watch_dirs: list[Path],
    api_url: str,
    seen: set[str],
    pack_subdirs: bool,
) -> int:
    uploaded = 0
    for base_dir in watch_dirs:
        if not base_dir.is_dir() or base_dir.is_symlink():
            continue
        try:
            entries = sorted(base_dir.iterdir())
        except OSError:
            continue

        for entry in entries:
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue

            lower = entry.name.lower()
            if entry.is_file() and (
                lower.endswith(".tar.gz")
                or lower.endswith(".tgz")
                or lower.endswith(".tar")
            ):
                if stat.st_size == 0 or stat.st_size > MAX_ARCHIVE_BYTES:
                    continue
                sig = f"file:{entry.resolve()}:{stat.st_size}:{int(stat.st_mtime)}"
                if sig in seen:
                    continue
                payload = entry.read_bytes()
                digest = hashlib.sha256(payload).hexdigest()[:12]
                safe_name = sanitize_stem(entry.name)
                try:
                    res = upload_archive_bytes(api_url, safe_name, payload)
                    summary = res.get("report", {}).get("summary", {})
                    print(
                        f"[USB-Guard] Scanned archive '{safe_name}' (sha256:{digest}) -> "
                        f"actionable={summary.get('actionable_findings', 0)}, "
                        f"suppressed={summary.get('suppressed_candidates', 0)}"
                    )
                    seen.add(sig)
                    uploaded += 1
                except urllib.error.URLError as err:
                    print(f"[USB-Guard] API upload failed for {safe_name}: {err}", file=sys.stderr)
            elif pack_subdirs and entry.is_dir():
                sig = f"dir:{entry.resolve()}:{int(stat.st_mtime)}"
                if sig in seen:
                    continue
                safe_name = f"{sanitize_stem(entry.name)}.tar.gz"
                try:
                    payload = pack_directory_to_tar_gz(entry)
                    res = upload_archive_bytes(api_url, safe_name, payload)
                    summary = res.get("report", {}).get("summary", {})
                    print(
                        f"[USB-Guard] Packaged & scanned folder '{entry.name}' as '{safe_name}' -> "
                        f"actionable={summary.get('actionable_findings', 0)}, "
                        f"suppressed={summary.get('suppressed_candidates', 0)}"
                    )
                    seen.add(sig)
                    uploaded += 1
                except Exception as err:
                    print(f"[USB-Guard] Skipping folder {entry.name}: {err}", file=sys.stderr)
    return uploaded


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FirmLens USB Pendrive & Hotfolder Auto-Scanner"
    )
    parser.add_argument(
        "--watch-dir",
        action="append",
        default=[],
        help="Directory or USB mount path to watch (defaults to ./dropzone)",
    )
    parser.add_argument(
        "--auto-usb",
        action="store_true",
        help="Automatically include removable USB media mounts (/media, /run/media, /Volumes)",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"Loopback firmlens-api URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.5,
        help="Polling interval in seconds (default: 2.5)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Scan current contents of watch directories once and exit",
    )
    parser.add_argument(
        "--pack-subdirs",
        action="store_true",
        default=True,
        help="Automatically package unpacked firmware subdirectories into .tar.gz streams",
    )
    args = parser.parse_args()

    watch_dirs = [Path(p).resolve() for p in args.watch_dir]
    if not watch_dirs:
        DEFAULT_DROPZONE.mkdir(parents=True, exist_ok=True)
        watch_dirs.append(DEFAULT_DROPZONE)

    seen: set[str] = set()
    print(f"[USB-Guard] Monitoring base directories: {[str(d) for d in watch_dirs]}")
    if args.auto_usb:
        print("[USB-Guard] Auto-USB removable media detection: ENABLED")

    try:
        while True:
            active_dirs = list(watch_dirs)
            if args.auto_usb:
                for usb_dir in discover_usb_mount_dirs():
                    if usb_dir not in active_dirs:
                        active_dirs.append(usb_dir)

            scan_watch_roots(active_dirs, args.api_url, seen, args.pack_subdirs)
            if args.once:
                break
            time.sleep(max(0.5, args.interval))
    except KeyboardInterrupt:
        print("\n[USB-Guard] Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
