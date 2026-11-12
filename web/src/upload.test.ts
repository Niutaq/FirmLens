import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_UPLOAD_SUFFIXES,
  isAllowedUploadFilename,
  UPLOAD_FILE_ACCEPT,
} from "./upload";

describe("upload filename filters", () => {
  it("accepts compound archive names and vendor image suffixes", () => {
    assert.equal(isAllowedUploadFilename("hardened.tar.gz"), true);
    assert.equal(isAllowedUploadFilename("bundle.tgz"), true);
    assert.equal(isAllowedUploadFilename("rootfs.tar"), true);
    assert.equal(isAllowedUploadFilename("smart-ipcam-v1.zip"), true);
    assert.equal(isAllowedUploadFilename("DIR815A1_FW103b01.bin"), true);
    assert.equal(isAllowedUploadFilename("Config.JSON"), true);
  });

  it("rejects unsupported or incomplete names", () => {
    assert.equal(isAllowedUploadFilename("notes.md"), false);
    assert.equal(isAllowedUploadFilename("payload.gz"), false);
    assert.equal(isAllowedUploadFilename("firmware"), false);
    assert.equal(isAllowedUploadFilename(""), false);
  });

  it("keeps macOS-safe accept tokens without compound .tar.gz", () => {
    assert.match(UPLOAD_FILE_ACCEPT, /(^|,)\.gz(,|$)/);
    assert.match(UPLOAD_FILE_ACCEPT, /(^|,)\.tar(,|$)/);
    assert.match(UPLOAD_FILE_ACCEPT, /(^|,)\.zip(,|$)/);
    assert.match(UPLOAD_FILE_ACCEPT, /(^|,)\.bin(,|$)/);
    assert.equal(UPLOAD_FILE_ACCEPT.includes(".tar.gz"), false);
    assert.equal(ALLOWED_UPLOAD_SUFFIXES[0], ".tar.gz");
  });
});
