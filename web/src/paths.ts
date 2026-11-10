/**
 * Shorten binwalk-extracted firmware paths for UI display.
 * Full paths stay in `title` / selection keys; only the label is shortened.
 *
 * Example:
 *   DIR815A1_FW103b01.bin.extracted/F008C/squashfs-root/etc/services/INET/inet_ppp4.php
 *   → etc/services/INET/inet_ppp4.php
 */
export function displayFirmwarePath(path: string): string {
  const normalized = path.replaceAll("\\", "/");
  const squash = /(?:^|\/)squashfs-root\/(.*)$/.exec(normalized);
  if (squash) {
    return squash[1] || "squashfs-root/";
  }
  const withoutEnvelope = normalized.replace(/^[^/]+\.extracted\/[^/]+\//, "");
  return withoutEnvelope || normalized;
}
