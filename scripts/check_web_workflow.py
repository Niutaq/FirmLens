#!/usr/bin/env python3
"""End-to-end consistency verifier between firmlens-cli and firmlens-api.

Uses only the Python 3 standard library. Starts firmlens-api on an ephemeral
loopback port, uploads generated archive fixtures, compares the HTTP JSON
reports against CLI JSON output, and validates security boundaries and Diff.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_ROOT = REPO_ROOT / "generated-fixtures"


def find_binary(name: str) -> Path:
    exe_suffix = ".exe" if os.name == "nt" else ""
    for profile in ("debug", "release"):
        candidate = REPO_ROOT / "target" / profile / f"{name}{exe_suffix}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Binary '{name}' not found in target/debug or target/release; run 'cargo build --workspace --locked' first."
    )


def pick_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def http_request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def run_cli_json(cli_bin: Path, archive_path: Path) -> dict:
    proc = subprocess.run(
        [str(cli_bin), "scan", str(archive_path), "--format", "json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 2):
        raise RuntimeError(
            f"CLI scan failed with exit {proc.returncode}: {proc.stderr}"
        )
    return json.loads(proc.stdout)


def assert_reports_equivalent(cli_rep: dict, api_rep: dict, label: str) -> None:
    for key in (
        "schema_version",
        "summary",
        "findings",
        "suppressed",
        "inventory",
        "skipped_files",
        "errors",
        "partial",
    ):
        if cli_rep.get(key) != api_rep.get(key):
            raise AssertionError(
                f"Mismatch in '{key}' for {label}:\nCLI={cli_rep.get(key)}\nAPI={api_rep.get(key)}"
            )
    if cli_rep["ingestion"]["outcome"] != api_rep["ingestion"]["outcome"]:
        raise AssertionError(f"Mismatch in ingestion outcome for {label}")
    if cli_rep["ingestion"]["input_kind"] != api_rep["ingestion"]["input_kind"]:
        raise AssertionError(f"Mismatch in ingestion input_kind for {label}")


def main() -> None:
    if not (GENERATED_ROOT / "vulnerable.tar").is_file():
        import generate_archives

        generate_archives.main()

    cli_bin = find_binary("firmlens")
    api_bin = find_binary("firmlens-api")
    port = pick_free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env["FIRMLENS_API_HOST"] = "127.0.0.1"
    env["FIRMLENS_API_PORT"] = str(port)

    api_proc = subprocess.Popen(
        [str(api_bin)],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        # 1. Wait for health endpoint
        ready = False
        for _ in range(50):
            try:
                status, body = http_request(f"{base_url}/api/health")
                if status == 200:
                    health = json.loads(body.decode("utf-8"))
                    assert health["status"] == "ok"
                    assert health["schema_version"] == "2.2"
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)

        if not ready:
            raise RuntimeError("firmlens-api did not become ready on loopback port")

        # 2. Verify security boundaries (Origin check and server filesystem path rejection)
        status_bad_origin, _ = http_request(
            f"{base_url}/api/health",
            headers={"Origin": "https://malicious.invalid"},
        )
        assert status_bad_origin == 403, f"Expected 403 for untrusted Origin, got {status_bad_origin}"

        status_path_inject, _ = http_request(
            f"{base_url}/api/scans?path=fixtures/vulnerable",
            method="POST",
            data=b"invalid",
        )
        assert status_path_inject == 400, f"Expected 400 for server path parameter, got {status_path_inject}"

        # 3. Compare CLI vs API reports across archives
        scan_ids: dict[str, str] = {}
        for filename in ("vulnerable.tar", "hardened.tar.gz", "benign.tar.gz"):
            archive_path = GENERATED_ROOT / filename
            cli_report = run_cli_json(cli_bin, archive_path)

            status_up, up_body = http_request(
                f"{base_url}/api/scans?filename={filename}",
                method="POST",
                data=archive_path.read_bytes(),
                headers={
                    "Content-Type": "application/octet-stream",
                    "Origin": "http://127.0.0.1:5173",
                },
            )
            assert status_up == 201, f"Expected 201 on upload of {filename}, got {status_up}: {up_body!r}"
            stored = json.loads(up_body.decode("utf-8"))
            scan_ids[filename] = stored["id"]
            api_report = stored["report"]

            assert api_report["metadata"]["root"] == filename
            assert_reports_equivalent(cli_report, api_report, filename)

            # Verify raw JSON export endpoint matches stored report
            status_exp, exp_body = http_request(
                f"{base_url}/api/scans/{stored['id']}/report"
            )
            assert status_exp == 200
            exported_report = json.loads(exp_body.decode("utf-8"))
            assert exported_report == api_report

        # 4. Verify Diff endpoint between vulnerable.tar and hardened.tar.gz
        vuln_id = scan_ids["vulnerable.tar"]
        hard_id = scan_ids["hardened.tar.gz"]
        status_diff, diff_body = http_request(
            f"{base_url}/api/diff?base={vuln_id}&target={hard_id}"
        )
        assert status_diff == 200
        diff = json.loads(diff_body.decode("utf-8"))
        assert diff["delta"]["actionable_delta"] == -12
        assert diff["delta"]["suppressed_delta"] == 7
        assert len(diff["resolved_findings"]) == 13
        assert len(diff["new_findings"]) == 0
        assert diff["coverage_warning"] is not None

        print("CLI and HTTP API workflow verification passed (all reports and diffs consistent).")
    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()


if __name__ == "__main__":
    main()
