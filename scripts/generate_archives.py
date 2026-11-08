#!/usr/bin/env python3
"""Deterministic portable TAR/TAR.GZ and binary image generator for FirmLens.

Uses only the Python 3 standard library. Emits POSIX ustar archives without PAX
extensions, symbolic links, or special files, plus a synthetic binary image
for optional Binwalk v3 signature identification tests.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_ROOT = REPO_ROOT / "fixtures"
GENERATED_ROOT = REPO_ROOT / "generated-fixtures"


def build_ustar_bytes(source_dir: Path) -> bytes:
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Missing fixture directory: {source_dir}")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        paths = sorted(source_dir.rglob("*"), key=lambda p: p.relative_to(source_dir).as_posix())
        for path in paths:
            rel_posix = path.relative_to(source_dir).as_posix()
            info = tarfile.TarInfo(name=rel_posix)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 1700000000

            if path.is_dir():
                if not info.name.endswith("/"):
                    info.name += "/"
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                tf.addfile(info)
            elif path.is_file():
                data = path.read_bytes()
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

    return buf.getvalue()


def write_tar(source_dir: Path, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(build_ustar_bytes(source_dir))


def write_tar_gz(source_dir: Path, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    raw_tar = build_ustar_bytes(source_dir)
    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=1700000000) as gz:
        gz.write(raw_tar)
    target_path.write_bytes(gz_buf.getvalue())


def write_signature_test_image(target_path: Path) -> None:
    """Create a synthetic non-executable firmware image containing recognizable
    header signatures (e.g. embedded gzip stream and zlib block) for isolated
    Binwalk v3 identification tests.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)

    header = b"FIRMLENS-SYNTH-IMAGE-V1\x00" + (b"\xff" * 232)  # 256 bytes preamble

    inner_gzip_buf = io.BytesIO()
    with gzip.GzipFile(
        filename="rootfs-meta.txt", mode="wb", fileobj=inner_gzip_buf, mtime=1700000000
    ) as gz:
        gz.write(b"synthetic_firmware_component=1\nversion=0.2.0\n")
    gzip_segment = inner_gzip_buf.getvalue()

    padding = b"\x00" * (512 - (len(gzip_segment) % 512))
    zlib_segment = zlib.compress(b"FIRMLENS_SYNTH_ZLIB_BLOCK_PAYLOAD_" * 8, level=9)
    trailer = b"\x00" * 128

    image_bytes = header + gzip_segment + padding + zlib_segment + trailer
    target_path.write_bytes(image_bytes)


def build_virtual_tar_gz(files: dict[str, bytes], target_path: Path) -> None:
    """Build a deterministic USTAR .tar.gz archive from an in-memory path->bytes map."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    dirs_added: set[str] = set()

    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for rel_posix in sorted(files.keys()):
            parts = rel_posix.split("/")
            for i in range(1, len(parts)):
                dir_path = "/".join(parts[:i]) + "/"
                if dir_path not in dirs_added:
                    dirs_added.add(dir_path)
                    dinfo = tarfile.TarInfo(name=dir_path)
                    dinfo.type = tarfile.DIRTYPE
                    dinfo.mode = 0o755
                    dinfo.uid = 0
                    dinfo.gid = 0
                    dinfo.uname = "root"
                    dinfo.gname = "root"
                    dinfo.mtime = 1700000000
                    tf.addfile(dinfo)

            data = files[rel_posix]
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
    target_path.write_bytes(gz_buf.getvalue())


def generate_iot_hardware_bundles() -> None:
    """Generate realistic SmartHome, Raspberry Pi 4, and OpenWrt Zigbee gateway
    firmware bundles (using nonfunctional synthetic credentials safe for GitHub).
    """
    rpi_v1_files: dict[str, bytes] = {
        "boot/firmware/cmdline.txt": b"console=serial0,115200 console=tty1 root=PARTUUID=738a4d67-02 rootfstype=ext4 fsck.repair=yes rootwait\n",
        "boot/firmware/wpa_supplicant.conf": (
            "# Raspberry Pi 4 SmartHome Hub Wi-Fi bootstrap (synthetic)\n"
            "[wifi]\n"
            'ssid = "SmartHome-IoT-VLAN"\n'
            'wifi_password = "RpiSmartHomeWifi_Synth2026!Invalid"\n'
        ).encode("utf-8"),
        "etc/mosquitto/mosquitto.conf": (
            "# Mosquitto Broker on Raspberry Pi SmartHome Hub\n"
            "[mqtt]\n"
            "listener = 1883\n"
            "allow_anonymous = true\n"
            'mqtt_username = "zigbee_bridge"\n'
            'mqtt_password = "SynthMosquittoBridgePass_8812"\n'
        ).encode("utf-8"),
        "opt/zigbee2mqtt/configuration.ini": (
            "# Zigbee2MQTT CC2652P Coordinator Config\n"
            "[mqtt]\n"
            'broker = "mqtt://zigbee_bridge:SynthZigbeeUriPass99@127.0.0.1:1883"\n'
            "tls_verify = false\n\n"
            "[cloud]\n"
            'iot_hub_sas_key = "SynthRpiCloudHubSymmetricKey_NonFunctional=="\n'
            'webhook_token = "fl_synth_ha_webhook_776655443322"\n'
        ).encode("utf-8"),
        "etc/homeassistant/provisioning.conf": (
            "[provisioning]\n"
            'provisioning_token = "SynthMatterThreadClaimToken_Rpi4"\n'
            'service_account_secret = "SynthHomeCloudServiceKey_Invalid"\n'
            'backup_password = "${HA_VAULT_RUNTIME_SECRET}"\n'
        ).encode("utf-8"),
        "etc/ssl/private/rpi-matter-bridge.pem": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBSyntheticRpiMatterBridgePublicCertNotASecret012345==\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEISyntheticNonFunctionalRpiMatterPrivateKeyBodyForTestingOnly\n"
            "-----END EC PRIVATE KEY-----\n"
        ).encode("utf-8"),
        "var/cache/eeprom-pieeprom.bin": (
            b"\x00RPI4_EEPROM_BOOTLOADER_SYNTH\x00"
            b"board=bcm2711-rpi-4-b\x00"
            b"-----BEGIN RSA PRIVATE KEY-----\x00"
            b"truncated_bootloader_key_marker_hint\x00"
        ),
    }
    build_virtual_tar_gz(rpi_v1_files, GENERATED_ROOT / "rpi4-smarthome-hub-v1.tar.gz")

    rpi_v2_hardened: dict[str, bytes] = {
        "boot/firmware/cmdline.txt": b"console=serial0,115200 console=tty1 root=PARTUUID=738a4d67-02 rootfstype=ext4 fsck.repair=yes rootwait\n",
        "boot/firmware/wpa_supplicant.conf": (
            "# Raspberry Pi 4 SmartHome Hub Wi-Fi bootstrap (hardened)\n"
            "[wifi]\n"
            'ssid = "SmartHome-IoT-VLAN"\n'
            'wifi_password = "/run/secrets/wpa_psk"\n'
        ).encode("utf-8"),
        "etc/mosquitto/mosquitto.conf": (
            "# Mosquitto Broker on Raspberry Pi SmartHome Hub (hardened)\n"
            "[mqtt]\n"
            "listener = 8883\n"
            "allow_anonymous = false\n"
            'mqtt_username = "zigbee_bridge"\n'
            'mqtt_password = "${MOSQUITTO_RUNTIME_PASSWORD}"\n'
        ).encode("utf-8"),
        "opt/zigbee2mqtt/configuration.ini": (
            "# Zigbee2MQTT CC2652P Coordinator Config (hardened)\n"
            "[mqtt]\n"
            'broker = "mqtts://zigbee_bridge:${Z2M_MQTT_SECRET}@127.0.0.1:8883"\n'
            "tls_verify = true\n\n"
            "[cloud]\n"
            'iot_hub_sas_key = "tpm2:handle:0x81010009"\n'
            'webhook_token = "${HA_WEBHOOK_TOKEN}"\n'
        ).encode("utf-8"),
        "etc/homeassistant/provisioning.conf": (
            "[provisioning]\n"
            'provisioning_token = "<PROVISIONED_AT_PAIRING>"\n'
            'service_account_secret = "/run/secrets/ha_cloud_sa"\n'
            'backup_password = "${HA_VAULT_RUNTIME_SECRET}"\n'
        ).encode("utf-8"),
        "etc/ssl/private/rpi-matter-bridge.pem": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBSyntheticRpiMatterBridgePublicCertNotASecret012345==\n"
            "-----END CERTIFICATE-----\n"
        ).encode("utf-8"),
    }
    build_virtual_tar_gz(
        rpi_v2_hardened, GENERATED_ROOT / "rpi4-smarthome-hub-v2-hardened.tar.gz"
    )

    ipcam_ota_files: dict[str, bytes] = {
        "etc/camera/rtsp-stream.conf": (
            "# Smart IP Camera RTSP & ONVIF Daemon\n"
            "[onvif]\n"
            'device_model = "CamPro-PoE-4K"\n'
            'admin_password = "SynthOnvifCamAdmin_2026!Invalid"\n'
            'rtsp_stream_uri = "rtsp://stream_user:SynthRtspPass77@127.0.0.1:554/live/ch0"\n'
            "snmp_community = \"private_cam_rw\"\n"
        ).encode("utf-8"),
        "etc/cloud/p2p-tunnel.ini": (
            "[cloud]\n"
            'relay_host = "p2p.smartcam.invalid"\n'
            'api_key = "fl_synth_cam_cloud_key_1122334455"\n'
            'master_secret = "synth_cam_aes_ota_signing_secret_99"\n'
            "tls_verify = false\n"
        ).encode("utf-8"),
        "usr/share/ota/version.txt": b"fw_version=2.4.1-ota\nhw_rev=hi3516dv300\n",
    }
    build_virtual_tar_gz(ipcam_ota_files, GENERATED_ROOT / "smart-ipcam-ota.tar.gz")


def main() -> None:
    # Ensure base fixtures exist first
    if not (FIXTURES_ROOT / "vulnerable").is_dir():
        import generate_fixtures

        generate_fixtures.main()

    write_tar(FIXTURES_ROOT / "vulnerable", GENERATED_ROOT / "vulnerable.tar")
    write_tar_gz(FIXTURES_ROOT / "vulnerable", GENERATED_ROOT / "vulnerable.tar.gz")
    write_tar(FIXTURES_ROOT / "hardened", GENERATED_ROOT / "hardened.tar")
    write_tar_gz(FIXTURES_ROOT / "hardened", GENERATED_ROOT / "hardened.tar.gz")
    write_tar(FIXTURES_ROOT / "benign", GENERATED_ROOT / "benign.tar")
    write_tar_gz(FIXTURES_ROOT / "benign", GENERATED_ROOT / "benign.tar.gz")
    write_signature_test_image(GENERATED_ROOT / "signature-test.bin")
    generate_iot_hardware_bundles()
    print("Generated archive and binary fixtures in generated-fixtures/")


if __name__ == "__main__":
    main()
