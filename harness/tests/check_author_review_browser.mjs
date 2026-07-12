import { chromium } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const packetPath = process.argv[2];
if (!packetPath) {
  throw new Error("usage: node check_author_review_browser.mjs PATH");
}

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ acceptDownloads: true });
const page = await context.newPage();
const networkRequests = [];
const pageErrors = [];
const consoleErrors = [];

page.on("request", (request) => {
  if (/^(?:https?|wss?):/u.test(request.url())) networkRequests.push(request.url());
});
page.on("pageerror", (error) => pageErrors.push(error.message));
page.on("console", (message) => {
  if (message.type() === "error") consoleErrors.push(message.text());
});

try {
  await page.goto(pathToFileURL(resolve(packetPath)).href, { waitUntil: "load" });
  await page.locator("#progress-copy").waitFor({ state: "visible" });
  assert(await page.locator("#progress-copy").textContent() === "0 of 64 reviewed", "initial progress differs");
  assert(await page.locator("#positions .position").count() >= 3, "position cards are missing");
  assert((await page.locator("#response").textContent()).trim().length > 0, "response is blank");

  await page.locator("#confirm-decision").click();
  await page.locator("#progress-copy").filter({ hasText: "1 of 64 reviewed" }).waitFor();

  const primary = page.locator("#primary-select");
  const current = await primary.inputValue();
  const options = await primary.locator("option").evaluateAll((values) => (
    values.map((value) => value.value)
  ));
  const replacement = options.find((value) => value !== current && value !== "__NULL__");
  assert(replacement, "no correction option is available");
  await primary.selectOption(replacement);
  assert(await page.locator("#confirm-decision").isDisabled(), "confirmation remained enabled after an edit");
  await page.locator("#correct-decision").click();
  await page.locator("#progress-copy").filter({ hasText: "2 of 64 reviewed" }).waitFor();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("#export-draft").click(),
  ]);
  const downloadedPath = await download.path();
  assert(downloadedPath, "draft download has no local path");
  const draft = JSON.parse(await readFile(downloadedPath, "utf8"));
  assert(draft.status === "author-review-in-progress", "draft status differs");
  assert(draft.decisions.filter((value) => value.decision === "confirm").length === 1, "confirmation was not exported");
  assert(draft.decisions.filter((value) => value.decision === "correct").length === 1, "correction was not exported");
  assert(draft.decisions.find((value) => value.decision === "correct").review_note === null, "optional correction note changed");

  await page.evaluate(() => localStorage.clear());
  await page.reload({ waitUntil: "load" });
  assert(await page.locator("#progress-copy").textContent() === "0 of 64 reviewed", "local reset failed");
  page.once("dialog", (dialog) => dialog.accept());
  await page.locator("#import-file").setInputFiles(downloadedPath);
  await page.locator("#progress-copy").filter({ hasText: "2 of 64 reviewed" }).waitFor();

  assert(networkRequests.length === 0, `network requests observed: ${networkRequests.join(", ")}`);
  assert(pageErrors.length === 0, `page errors observed: ${pageErrors.join(" | ")}`);
  assert(consoleErrors.length === 0, `console errors observed: ${consoleErrors.join(" | ")}`);
  process.stdout.write("Author review browser check passed: offline load, confirm, correct, export, and import.\n");
} finally {
  await browser.close();
}
