/**
 * Browser file-picker filters and upload filename validation.
 *
 * macOS native pickers treat the last dotted suffix as the extension. Putting
 * compound forms like `.tar.gz` in `accept` often breaks the dialog so only
 * `.zip` (or nothing useful) stays selectable. Prefer final suffixes (`.gz`)
 * plus MIME types in `accept`, and enforce compound names in JS.
 */

/** Suffixes accepted by firmlens-api (longest-first for matching). */
export const ALLOWED_UPLOAD_SUFFIXES = [
  ".tar.gz",
  ".tgz",
  ".tar",
  ".zip",
  ".bin",
  ".img",
  ".fw",
  ".chk",
  ".pat",
  ".rom",
  ".ubi",
  ".dat",
  ".conf",
  ".cfg",
  ".ini",
  ".env",
  ".pem",
  ".key",
  ".json",
  ".yaml",
  ".yml",
] as const;

/**
 * `accept` value safe for Chrome/Safari/macOS file dialogs.
 * Uses `.gz` (not `.tar.gz`) so `foo.tar.gz` remains selectable.
 */
export const UPLOAD_FILE_ACCEPT = [
  "application/gzip",
  "application/x-gzip",
  "application/x-tar",
  "application/x-gtar",
  "application/zip",
  "application/x-zip-compressed",
  "application/octet-stream",
  ".tar",
  ".gz",
  ".tgz",
  ".zip",
  ".bin",
  ".img",
  ".fw",
  ".chk",
  ".pat",
  ".rom",
  ".ubi",
  ".dat",
  ".conf",
  ".cfg",
  ".ini",
  ".env",
  ".pem",
  ".key",
  ".json",
  ".yaml",
  ".yml",
].join(",");

export function isAllowedUploadFilename(filename: string): boolean {
  const lower = filename.trim().toLowerCase();
  return ALLOWED_UPLOAD_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}
