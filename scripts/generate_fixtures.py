#!/usr/bin/env python3
"""Deterministic generator for FirmLens synthetic directory and binary fixtures.

Uses only the Python 3 standard library and writes byte-identical UTF-8 (LF)
and binary fixture files across Linux, macOS, and Windows.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_ROOT = REPO_ROOT / "fixtures"


def write_text_lf(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = content.replace("\r\n", "\n")
    path.write_bytes(normalized.encode("utf-8"))


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def generate_vulnerable(root: Path) -> None:
    write_text_lf(
        root / "docs" / "Configuration-Notes.md",
        """# Vulnerable Fixture Notes (Excluded Documentation)

This synthetic Markdown file is intentionally excluded from static credential
scanning so the report records partial coverage (`documentation_excluded`).
""",
    )

    write_text_lf(
        root / "etc" / "gateway.conf",
        """# Synthetic vulnerable gateway configuration (all credentials fictional)
[system]
device_id = "gw-eu-central-01"
hostname = "gateway.edge.invalid"
admin_password = "SyntheticRootPass_v2!Invalid"
webhook_token = "fl_synth_tok_998877665544332211"
master_secret = "synth_master_hmac_key_0102030405"
update_uri = "https://updater:SynthUriPass99@updates.firmware.invalid/v2/manifest.json"
tls_verify = false
allow_anonymous = true
snmp_community = "private_synth_rw"
default_password = "${RUNTIME_BACKUP_PASS}"
auth_token = "changeme"
""",
    )

    write_text_lf(
        root / "etc" / "mqtt-cloud.ini",
        """# Synthetic vulnerable Cloud-IoT & MQTT configuration
[mqtt]
broker_host = "mqtt.telemetry.invalid"
mqtt_username = "gateway_telemetry"
mqtt_password = "SynthMqttBrokerSecret_42"

[cloud]
endpoint = "iot-hub.cloud.invalid"
iot_hub_sas_key = "SynthCloudDeviceSymmetricKey_Base64Placeholder=="

[provisioning]
provisioning_token = "SynthBootstrapClaimToken_2026"
bootstrap_secret = "<PROVISIONED_AT_FACTORY>"

[service_account]
service_account_secret = "SynthIamServiceAccountKey_NonFunctional"
""",
    )

    write_text_lf(
        root / "etc" / "tls" / "device-ident.pem",
        """-----BEGIN CERTIFICATE-----
MIIBSyntheticPublicCertificateDataNotASecret0123456789ABCDEF==
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
PLACEHOLDER_KEY_MATERIAL_NOT_DEPLOYED
-----END PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALRSyntheticNonFunctionalKeyBodyForStaticAnalysisOnly0123456789
-----END RSA PRIVATE KEY-----
""",
    )

    # Inert binary blob containing an isolated incomplete private-key marker (Hint)
    boot_fragment = (
        b"\x00FIRMLENS_SYNTH_BIN_V2\x00"
        b"build_id=2026.11-vuln\x00"
        b"-----BEGIN EC PRIVATE KEY-----\x00"
        b"truncated_nonfunctional_binary_marker\x00"
    )
    write_bytes(root / "var" / "cache" / "boot-fragment.dat", boot_fragment)


def generate_hardened(root: Path) -> None:
    write_text_lf(
        root / "docs" / "Hardening-Guide.md",
        """# Hardened Fixture Notes (Excluded Documentation)

All credentials in this fixture reference external runtime secret stores,
hardware security modules, or environment variables.
""",
    )

    write_text_lf(
        root / "etc" / "gateway.conf",
        """# Synthetic hardened gateway configuration
[system]
device_id = "gw-eu-central-01"
hostname = "gateway.edge.invalid"
admin_password = "/run/secrets/admin_password"
webhook_token = "${WEBHOOK_RUNTIME_TOKEN}"
master_secret = "tpm2:handle:0x81010001"
update_uri = "https://updater:${UPDATE_AUTH_TOKEN}@updates.firmware.invalid/v2/manifest.json"
tls_verify = true
allow_anonymous = false
snmp_community = "disabled"
""",
    )

    write_text_lf(
        root / "etc" / "mqtt-cloud.ini",
        """# Synthetic hardened Cloud-IoT & MQTT configuration
[mqtt]
broker_host = "mqtt.telemetry.invalid"
mqtt_username = "gateway_telemetry"
mqtt_password = "/run/secrets/mqtt_password"

[cloud]
endpoint = "iot-hub.cloud.invalid"
iot_hub_sas_key = "pkcs11:token=iot-tpm;object=cloud-key"

[provisioning]
provisioning_token = "${FACTORY_CLAIM_TOKEN}"

[service_account]
service_account_secret = "vault:secret/data/iot/service-account"
""",
    )

    write_text_lf(
        root / "etc" / "tls" / "ca-bundle.pem",
        """-----BEGIN CERTIFICATE-----
MIIBSyntheticPublicRootCertificateBundleData0123456789ABCDEF==
-----END CERTIFICATE-----
""",
    )

    boot_profile = (
        b"\x00FIRMLENS_SYNTH_SAFE_BIN\x00"
        b"hardware_rev=2.1\x00"
        b"auth_mode=mtls_tpm2\x00"
    )
    write_bytes(root / "var" / "cache" / "boot-profile.dat", boot_profile)


def generate_benign(root: Path) -> None:
    write_text_lf(
        root / "etc" / "network-defaults.conf",
        """# Synthetic known-benign configuration (no excluded docs -> full coverage)
[network]
hostname = "sensor-node.local.invalid"
endpoint = "https://telemetry.sensor.invalid:8443/v1/status"
tls_verify = true
allow_anonymous = false
wifi_password = "changeme"
api_key = "${SENSOR_API_KEY}"

[diagnostics]
calibration_auth_seed = "cal_profile_v4_static_table"
""",
    )

    write_text_lf(
        root / "etc" / "tls" / "public-root.pem",
        """-----BEGIN CERTIFICATE-----
MIIBSyntheticPublicRootCaCertificateData0123456789ABCDEF==
-----END CERTIFICATE-----
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKSyntheticPublicVerificationKeyOnly==
-----END PUBLIC KEY-----
""",
    )

    radio_cal = (
        b"\x00FIRMLENS_CAL_DATA\x00"
        b"channel_plan=eu868\x00"
        b"tx_power_dbm=14\x00"
    )
    write_bytes(root / "var" / "cache" / "radio-cal.dat", radio_cal)


def generate_expected_json(path: Path) -> None:
    expected = {
        "schema_version": "2.1",
        "fixtures": {
            "vulnerable": {
                "actionable_findings": 12,
                "informational_hints": 1,
                "review_candidates": 0,
                "suppressed_candidates": 5,
                "skipped_entries": 1,
                "partial": True,
                "expected_exit_code": 2,
                "expected_rules": [
                    "FL001",
                    "FL002",
                    "FL003",
                    "FL004",
                    "FL005",
                    "FL006",
                    "FL007",
                    "FL008",
                    "FL009",
                    "FL010",
                    "FL011",
                    "FL012",
                ],
            },
            "hardened": {
                "actionable_findings": 0,
                "informational_hints": 0,
                "review_candidates": 0,
                "suppressed_candidates": 12,
                "skipped_entries": 1,
                "partial": True,
                "expected_exit_code": 2,
                "expected_rules": [],
            },
            "benign": {
                "actionable_findings": 0,
                "informational_hints": 0,
                "review_candidates": 1,
                "suppressed_candidates": 6,
                "skipped_entries": 0,
                "partial": False,
                "expected_exit_code": 0,
                "expected_rules": ["FL005"],
            },
        },
    }
    write_text_lf(path, json.dumps(expected, indent=2) + "\n")


def main() -> None:
    generate_vulnerable(FIXTURES_ROOT / "vulnerable")
    generate_hardened(FIXTURES_ROOT / "hardened")
    generate_benign(FIXTURES_ROOT / "benign")
    generate_expected_json(FIXTURES_ROOT / "expected.json")
    print("Generated synthetic fixtures in fixtures/")


if __name__ == "__main__":
    main()
