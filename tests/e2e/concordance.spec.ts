import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("loads only same-origin static resources", async ({ page, baseURL }) => {
  const requests: string[] = [];
  const pageErrors: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.goto("/", { waitUntil: "networkidle" });

  await expect(page.getByLabel("Methodological limitation")).toContainText(
    "Agreement is not truth",
  );
  await expect(page.getByRole("status")).toContainText("No answer below is a real model run");
  expect(pageErrors).toEqual([]);
  const expectedOrigin = new URL(baseURL ?? "http://127.0.0.1:4173").origin;
  expect(
    requests.filter((request) => new URL(request).origin !== expectedOrigin),
  ).toEqual([]);
});

test("has no detectable WCAG A or AA violations", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "chromium", "One desktop scan covers the shared DOM");
  await page.goto("/");
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    results.violations.map((violation) => `${violation.id}: ${violation.help}`).join("\n"),
  ).toEqual([]);
});

test("variant, challenge, and raw receipts work from the keyboard", async ({ page }) => {
  await page.goto("/");
  const caseC = page.locator("#case-c");
  const framed = caseC.getByRole("radio", { name: "Framed phrasing" });
  await framed.focus();
  await page.keyboard.press("Space");
  await expect(framed).toBeChecked();
  await expect(caseC.locator('.case-controls [aria-live="polite"]')).toContainText(
    "Map and receipts updated",
  );
  await expect(caseC.locator(".model-detail")).toContainText("East reading");

  const caseA = page.locator("#case-a");
  const challenge = caseA.locator("button.challenge-button");
  await expect(challenge).toHaveAccessibleName("Challenge this consensus");
  await challenge.focus();
  await page.keyboard.press("Enter");
  await expect(challenge).toHaveAttribute("aria-pressed", "true");
  await expect(caseA.getByText(/Recovered under challenge/).first()).toBeVisible();

  const betaReceipt = page.locator('#case-b details.receipt[data-model="beta"]');
  await betaReceipt.locator("summary").click();
  const raw = betaReceipt.locator("pre[data-raw-response]");
  await expect(raw).toContainText("<strong>not markup</strong>");
  await expect(raw.locator("strong")).toHaveCount(0);
});

test("mobile layout remains legible without horizontal overflow", async ({ page }) => {
  await page.goto("/");
  await page.locator("#case-c").scrollIntoViewIfNeeded();
  const framed = page
    .locator("#case-c")
    .getByRole("radio", { name: "Framed phrasing" });
  await framed.focus();
  await page.keyboard.press("Space");
  await expect(framed).toBeChecked();

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport + 1);
  await expect(page.locator("#case-c .semantic-position").first()).toBeVisible();
});

test("reduced-motion preference disables smooth scrolling and preserves meaning", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");

  expect(
    await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior),
  ).toBe("auto");
  const challenge = page
    .locator("#case-a")
    .getByRole("button", { name: "Challenge this consensus" });
  await challenge.click();
  await expect(page.locator("#case-a .model-detail")).toContainText("Pine reading");
  await expect(page.locator("#case-a .case-controls [aria-live='polite']")).toContainText(
    "Challenge answers shown",
  );
});
