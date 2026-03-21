import { chromium } from "playwright";

async function clickNav(page, view) {
  await page.locator(`.nav-item[data-view="${view}"]`).click();
}

async function textContent(page, selector) {
  return (await page.locator(selector).textContent())?.trim() || "";
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const failures = [];
  const checks = [];
  const pageErrors = [];

  page.on("pageerror", error => {
    pageErrors.push(String(error));
  });

  page.on("console", message => {
    if (message.type() === "error") {
      pageErrors.push(message.text());
    }
  });

  function record(name, passed, detail) {
    checks.push({ name, passed, detail });
    if (!passed) {
      failures.push(`${name}: ${detail}`);
    }
  }

  try {
    await page.goto("http://127.0.0.1:8080", { waitUntil: "networkidle" });
    await page.evaluate(() => {
      localStorage.clear();
      window.location.reload();
    });
    await page.waitForLoadState("networkidle");

    record(
      "startup-defaults-to-demo",
      (await textContent(page, "#live-status")).includes("Demo Mode"),
      await textContent(page, "#live-status")
    );

    await page.fill("#api-base-url-input", "http://127.0.0.1:8001");
    await page.fill("#api-key-input", "change-this-api-key");
    await page.click("#save-api-key");
    await page.waitForTimeout(2500);

    record(
      "connection-health-visible",
      (await textContent(page, "#api-hint")).toLowerCase().includes("api ok") || (await textContent(page, "#api-hint")).toLowerCase().includes("database reachable"),
      await textContent(page, "#api-hint")
    );

    await page.reload({ waitUntil: "networkidle" });
    record(
      "saved-api-base-url-restored",
      await page.inputValue("#api-base-url-input") === "http://127.0.0.1:8001",
      await page.inputValue("#api-base-url-input")
    );

    record(
      "dashboard-populates",
      (await textContent(page, "#total-attacks")) !== "0",
      await textContent(page, "#total-attacks")
    );

    await clickNav(page, "alerts");
    await page.waitForTimeout(1000);
    const firstAlert = page.locator("#event-feed .feed-item-button").first();
    const alertCount = await page.locator("#event-feed .feed-item-button").count();
    record(
      "alerts-render",
      alertCount > 0,
      `alerts=${alertCount}; feedCount=${await textContent(page, "#feed-count")}; view=${await page.locator("#view-alerts").getAttribute("style")}`
    );
    if (alertCount > 0) {
      await firstAlert.click();
      record(
        "alert-detail-renders",
        !(await textContent(page, "#alert-detail")).includes("Choose an alert"),
        await textContent(page, "#detail-status")
      );
    }

    await page.fill("#username", "admin");
    await page.fill("#password", "admin123");
    await page.click("#login-button");
    await page.waitForTimeout(2000);
    record(
      "login-succeeds",
      (await textContent(page, "#current-user")).includes("admin"),
      await textContent(page, "#current-user")
    );

    await clickNav(page, "alerts");
    await page.waitForTimeout(800);
    if (await page.locator("#event-feed .feed-item-button").count()) {
      await page.locator("#event-feed .feed-item-button").first().click();
      await page.click('button:has-text("Create Case")');
      await page.waitForTimeout(1800);
    }

    await clickNav(page, "cases");
    await page.waitForTimeout(1200);
    const caseCount = await page.locator("#cases-list .case-card").count();
    record(
      "case-created",
      caseCount > 0,
      await textContent(page, "#cases-status")
    );

    if (caseCount > 0) {
      await page.click('#cases-list .case-card');
      const caseDetail = await textContent(page, "#case-detail");
      record(
        "case-detail-renders",
        !caseDetail.includes("Case details appear here"),
        caseDetail.slice(0, 120)
      );

      await page.click('button:has-text("Set High Priority")');
      await page.waitForTimeout(1000);
      await page.click('button:has-text("Close")');
      await page.waitForTimeout(1200);
      record(
        "case-actions-work",
        (await textContent(page, "#case-detail")).toLowerCase().includes("closed"),
        await textContent(page, "#case-detail")
      );
    }

    await page.fill("#global-search", "credential");
    await page.waitForTimeout(1200);
    record(
      "search-results-open",
      await page.locator("#search-results [data-kind]").count() > 0,
      await textContent(page, "#search-status")
    );
    await page.locator('#search-results [data-kind="case"]').first().click();
    await page.waitForTimeout(1000);
    record(
      "search-routes-to-case",
      await page.locator("#cases-list .case-card.is-selected").count() > 0,
      await textContent(page, "#cases-status")
    );

    await page.fill("#global-search", "");
    await page.waitForTimeout(600);
    record(
      "search-empty-closes-panel",
      !(await page.locator("#search-panel").isVisible()),
      `visible=${await page.locator("#search-panel").isVisible()}`
    );

    await page.fill("#global-search", "zzzz-no-match");
    await page.waitForTimeout(1200);
    record(
      "search-no-results-safe",
      (await textContent(page, "#search-results")).includes("No results found"),
      await textContent(page, "#search-results")
    );

    await clickNav(page, "investigations");
    await page.waitForTimeout(1000);
    record(
      "investigation-view-safe",
      !(await textContent(page, "#alert-detail")).includes("undefined"),
      await textContent(page, "#detail-status")
    );

    await page.click("#logout-btn");
    await page.waitForTimeout(1000);
    record(
      "logout-safe",
      (await textContent(page, "#live-status")).includes("Demo Mode"),
      await textContent(page, "#live-status")
    );

    await page.fill("#api-key-input", "");
    await page.click("#save-api-key");
    await page.waitForTimeout(1000);
    await page.reload({ waitUntil: "networkidle" });
    record(
      "api-key-removal-safe",
      (await textContent(page, "#live-status")).includes("Demo Mode"),
      await textContent(page, "#live-status")
    );
  } finally {
    await browser.close();
  }

  if (pageErrors.length) {
    failures.push(`page-errors: ${pageErrors.join(" | ")}`);
  }

  console.log(JSON.stringify({ checks, failures, pageErrors }, null, 2));
  if (failures.length) {
    process.exitCode = 1;
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
