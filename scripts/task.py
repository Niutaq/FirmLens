#!/usr/bin/env python3
"""Portable task runner for FirmLens (Linux, macOS, Windows).

Usage:
  python3 scripts/task.py dev       # Build & launch local API (127.0.0.1:8787) + React UI (127.0.0.1:5173)
  python3 scripts/task.py check     # Run full Rust + Python + Web validation suite
  python3 scripts/task.py demo      # Run CLI scans on fixtures and print a comparison table
  python3 scripts/task.py binwalk   # Build isolated Binwalk v3 Docker image and scan signature-test.bin
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    if shutil.which("npm", path=env.get("PATH")) is None:
        nvm_bins = sorted(
            glob.glob(str(Path.home() / ".nvm" / "versions" / "node" / "*" / "bin")),
            reverse=True,
        )
        if nvm_bins:
            env["PATH"] = f"{nvm_bins[0]}{os.pathsep}{env.get('PATH', '')}"
    return env


def run_step(cmd: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print(f"\n==> {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=str(cwd), env=env or build_env(), check=True)


def ensure_fixtures_and_archives(env: dict[str, str]) -> None:
    run_step([sys.executable, "scripts/generate_fixtures.py"], env=env)
    run_step([sys.executable, "scripts/generate_archives.py"], env=env)


def cmd_demo(env: dict[str, str]) -> None:
    ensure_fixtures_and_archives(env)
    run_step(["cargo", "build", "-p", "firmlens-cli", "--locked"], env=env)
    exe = ROOT / "target" / "debug" / ("firmlens.exe" if os.name == "nt" else "firmlens")

    targets = [
        ("fixtures/vulnerable", "Directory (vulnerable)"),
        ("fixtures/hardened", "Directory (hardened)"),
        ("fixtures/benign", "Directory (benign)"),
        ("generated-fixtures/vulnerable.tar", "Archive (vulnerable.tar)"),
        ("generated-fixtures/hardened.tar.gz", "Archive (hardened.tar.gz)"),
        ("generated-fixtures/benign.tar.gz", "Archive (benign.tar.gz)"),
    ]

    print("\n" + "=" * 88)
    print(
        f"{'TARGET':<34} {'EXIT':>4} {'ACTIONABLE':>10} {'REVIEW':>7} {'HINTS':>6} {'SUPPRESSED':>10} {'COVERAGE':>10}"
    )
    print("-" * 88)
    for rel_path, label in targets:
        proc = subprocess.run(
            [str(exe), "scan", rel_path, "--format", "json"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        report = json.loads(proc.stdout)
        s = report["summary"]
        cov = "PARTIAL" if report["partial"] else "FULL"
        print(
            f"{label:<34} {proc.returncode:>4} {s['actionable_findings']:>10} "
            f"{s['review_candidates']:>7} {s['informational_hints']:>6} "
            f"{s['suppressed_candidates']:>10} {cov:>10}"
        )
    print("=" * 88)


def cmd_check(env: dict[str, str]) -> None:
    run_step(["cargo", "fmt", "--all", "--", "--check"], env=env)
    run_step(
        ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
        env=env,
    )
    run_step(["cargo", "build", "--workspace", "--locked"], env=env)
    run_step(["cargo", "test", "--workspace", "--locked"], env=env)
    ensure_fixtures_and_archives(env)
    run_step([sys.executable, "scripts/check_web_workflow.py"], env=env)

    npm_bin = shutil.which("npm", path=env.get("PATH"))
    if npm_bin is None:
        raise RuntimeError("npm not found in PATH or ~/.nvm/versions/node/*/bin")

    if not (WEB_DIR / "node_modules").exists():
        run_step([npm_bin, "ci"], cwd=WEB_DIR, env=env)
    run_step([npm_bin, "test"], cwd=WEB_DIR, env=env)
    run_step([npm_bin, "run", "typecheck"], cwd=WEB_DIR, env=env)
    run_step([npm_bin, "run", "build"], cwd=WEB_DIR, env=env)
    print("\n[OK] Full FirmLens validation suite passed.")


def cmd_dev(env: dict[str, str]) -> None:
    ensure_fixtures_and_archives(env)
    run_step(["cargo", "build", "-p", "firmlens-api", "--locked"], env=env)

    npm_bin = shutil.which("npm", path=env.get("PATH"))
    if npm_bin is None:
        raise RuntimeError("npm not found in PATH or ~/.nvm/versions/node/*/bin")

    if not (WEB_DIR / "node_modules").exists():
        run_step([npm_bin, "install"], cwd=WEB_DIR, env=env)

    api_exe = ROOT / "target" / "debug" / (
        "firmlens-api.exe" if os.name == "nt" else "firmlens-api"
    )

    print("\nStarting firmlens-api on http://127.0.0.1:8787 ...", flush=True)
    api_proc = subprocess.Popen([str(api_exe)], cwd=str(ROOT), env=env)

    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen("http://127.0.0.1:8787/api/health", timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.15)

        print("Starting Vite React frontend on http://127.0.0.1:5173 ...", flush=True)
        print("Upload archives from: generated-fixtures/vulnerable.tar & hardened.tar.gz")
        print("Press Ctrl+C to stop both servers.\n", flush=True)
        web_proc = subprocess.Popen([npm_bin, "run", "dev"], cwd=str(WEB_DIR), env=env)
        try:
            while True:
                if api_proc.poll() is not None:
                    raise RuntimeError(f"firmlens-api exited with code {api_proc.returncode}")
                if web_proc.poll() is not None:
                    break
                time.sleep(0.5)
        finally:
            if web_proc.poll() is None:
                web_proc.terminate()
                try:
                    web_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    web_proc.kill()
    except KeyboardInterrupt:
        print("\nStopping FirmLens servers...", flush=True)
    finally:
        if api_proc.poll() is None:
            api_proc.terminate()
            try:
                api_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_proc.kill()


def cmd_binwalk(env: dict[str, str]) -> None:
    ensure_fixtures_and_archives(env)
    run_step(["docker", "build", "-t", "firmlens-binwalk:3.1.0", "containers/binwalk"], env=env)
    run_step(
        [
            "cargo",
            "run",
            "-p",
            "firmlens-cli",
            "--locked",
            "--",
            "scan",
            "generated-fixtures/signature-test.bin",
            "--binwalk",
        ],
        env=env,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="FirmLens portable task runner")
    parser.add_argument(
        "action",
        choices=["dev", "check", "demo", "binwalk"],
        help="Task to execute",
    )
    args = parser.parse_args()
    env = build_env()

    if args.action == "dev":
        cmd_dev(env)
    elif args.action == "check":
        cmd_check(env)
    elif args.action == "demo":
        cmd_demo(env)
    elif args.action == "binwalk":
        cmd_binwalk(env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
