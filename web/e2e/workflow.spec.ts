import { test, expect } from "@playwright/test";
import path from "node:path";

test("uploads vulnerable.tar and hardened.tar.gz, inspects Overview/Findings/Files/Diff, and exports JSON", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("h1")).toHaveText("FirmLens");

  const vulnPath = path.resolve(
    import.meta.dirname,
    "../../generated-fixtures/vulnerable.tar",
  );
  const hardPath = path.resolve(
    import.meta.dirname,
    "../../generated-fixtures/hardened.tar.gz",
  );

  const fileInput = page.getByTestId("archive-upload-input");
  await fileInput.setInputFiles([vulnPath, hardPath]);

  await expect(page.getByTestId("scan-item-vulnerable.tar")).toBeVisible();
  await expect(page.getByTestId("scan-item-hardened.tar.gz")).toBeVisible();

  // Select vulnerable.tar and verify Overview
  await page.getByTestId("scan-item-vulnerable.tar").click();
  await expect(page.getByTestId("partial-coverage-banner")).toBeVisible();
  await expect(page.getByTestId("metric-actionable")).toHaveText("12");
  await expect(page.getByTestId("metric-suppressed")).toHaveText("5");

  // Verify Findings tab and SonarQube-style jump to file & vulnerable config fragment
  await page.getByTestId("tab-findings").click();
  await expect(page.getByTestId("view-findings")).toBeVisible();
  await expect(page.getByTestId("finding-card")).toHaveCount(13);

  await page.getByTestId("inspect-in-file-btn").first().click();
  await expect(page.getByTestId("files-inventory-table")).toBeVisible();
  await expect(page.getByTestId("sonar-code-inspector")).toBeVisible();
  await expect(page.getByTestId("sonar-snippet-block").first()).toBeVisible();

  // Verify Diff tab
  await page.getByTestId("tab-diff").click();
  await expect(page.getByTestId("diff-coverage-warning")).toBeVisible();
  await expect(page.getByTestId("diff-actionable-delta")).toHaveText("-12");

  // Verify Export JSON download
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId("export-json-btn").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("vulnerable.firmlens.json");
});
