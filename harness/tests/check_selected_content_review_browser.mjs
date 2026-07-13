import { chromium } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const packetPath = process.argv[2];
const exportPath = process.argv[3];
if (!packetPath || !exportPath) {
  throw new Error(
    "usage: node check_selected_content_review_browser.mjs PACKET EXPORT",
  );
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
  assert(
    await page.locator("#progress-copy").textContent() ===
      "0 of 4 attestations complete",
    "initial progress differs",
  );
  assert(await page.locator(".question-review").count() === 2, "question count differs");
  assert(
    await page.locator(".full-question-record").count() === 2,
    "complete question records are missing",
  );
  assert(await page.locator(".mapping-card").count() === 24, "mapping count differs");
  assert(
    await page.getByText("Review decision", { exact: true }).count() === 24,
    "mapping review decisions are missing",
  );

  const embedded = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(atob(await page.locator("#packet-data").textContent()), (value) =>
        value.charCodeAt(0),
      ),
    ),
  );
  const displayedQuestions = await page.locator(".question-json").allTextContents();
  assert(displayedQuestions.length === embedded.questions.length, "question JSON count differs");
  displayedQuestions.forEach((value, index) => {
    assert(
      value === JSON.stringify(embedded.questions[index].question, null, 2),
      `bound question JSON differs at index ${index}`,
    );
  });

  const approvals = page.locator('.attestation-card input[type="checkbox"]');
  assert(await approvals.count() === 4, "attestation count differs");
  for (let index = 0; index < 4; index += 1) await approvals.nth(index).check();
  assert(
    await page.locator("#progress-copy").textContent() ===
      "4 of 4 attestations complete",
    "complete progress differs",
  );
  assert(!(await page.locator("#finish-review").isDisabled()), "finish remained disabled");

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("#finish-review").click(),
  ]);
  await download.saveAs(resolve(exportPath));
  const exported = JSON.parse(await readFile(resolve(exportPath), "utf8"));
  assert(exported.status === "complete-selected-content-review", "export status differs");
  assert(exported.content_decisions.length === 2, "content decisions differ");
  assert(exported.mapping_attestations.length === 2, "mapping attestations differ");
  assert(
    exported.mapping_attestations.reduce((sum, value) => sum + value.mapping_count, 0) ===
      24,
    "exported mapping count differs",
  );
  assert(
    !JSON.stringify(exported).includes(embedded.mappings[0].response_text),
    "export leaks response text",
  );
  assert(networkRequests.length === 0, `network requests observed: ${networkRequests.join(", ")}`);
  assert(pageErrors.length === 0, `page errors observed: ${pageErrors.join(" | ")}`);
  assert(consoleErrors.length === 0, `console errors observed: ${consoleErrors.join(" | ")}`);
  process.stdout.write(
    "Selected-content browser check passed: complete records, 24 mappings, four attestations, and exact export.\n",
  );
} finally {
  await browser.close();
}
