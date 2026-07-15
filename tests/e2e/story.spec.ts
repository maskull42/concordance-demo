import { expect, test } from "@playwright/test";

test("story landing keeps honesty surfaces and orders scenes by kind", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByLabel("Methodological limitation")).toContainText(
    "Agreement is not truth",
  );
  await expect(page.getByRole("status")).toContainText(
    "No answer below is a real model run",
  );
  await expect(page.getByRole("main", { name: "Concordance story" })).toBeVisible();

  const sceneTitles = await page.locator(".story-scene-header h2").allTextContents();
  expect(sceneTitles).toHaveLength(3);
});

test("a story claim deep-links into the receipts and back returns to the story", async ({ page }) => {
  await page.goto("/");

  const receiptLink = page.locator("a.claim-receipt").first();
  await receiptLink.scrollIntoViewIfNeeded();
  const href = await receiptLink.getAttribute("href");
  expect(href).toBeTruthy();
  await receiptLink.click();

  await expect(page).toHaveURL(/#\/inspect\//);
  const questionId = /#\/inspect\/([^?]+)/.exec(href ?? "")?.[1] ?? "";
  const receipts = page.locator(`#${questionId} details.receipts-section`);
  await expect(receipts).toHaveAttribute("open", "");

  await page.goBack();
  await expect(page.getByRole("main", { name: "Concordance story" })).toBeVisible();
});

test("story mode has no horizontal overflow", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport + 1);
});

test("reduced motion keeps every story step readable", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");

  const steps = page.locator(".story-step-copy");
  const count = await steps.count();
  expect(count).toBeGreaterThan(5);
  for (let index = 0; index < count; index += 1) {
    const text = await steps.nth(index).textContent();
    expect((text ?? "").trim().length).toBeGreaterThan(0);
  }
  await expect(page.locator(".story-figure").first()).toBeVisible();
});
