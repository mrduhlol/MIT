import { test, expect } from "@playwright/test";

const dialog = (page: import("@playwright/test").Page) => page.locator("dialog[open]");

test("integration selector communicates availability and scopes at desktop and mobile sizes", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Add Server", exact: true }).click();
  await expect(dialog(page).getByRole("heading", { name: "Connect Data Source", exact: true })).toBeVisible();
  for (const name of ["Website / Web Application", "Linux Server", "Cloud Infrastructure", "Identity Provider", "Simulated Demo Source"])
    await expect(dialog(page).getByRole("button", { name, exact: true })).toBeVisible();
  await page.screenshot({ path: "../artifacts/connect-source-desktop.png" });
  await dialog(page).getByRole("button", { name: "Cloud Infrastructure", exact: true }).click();
  await expect(dialog(page).getByText("Not implemented", { exact: true })).toBeVisible();
  await expect(dialog(page).getByRole("button", { name: "Save integration", exact: true })).toHaveCount(0);
  await dialog(page).getByRole("button", { name: "All integrations", exact: true }).click();
  await dialog(page).getByRole("button", { name: "Identity Provider", exact: true }).click();
  await expect(dialog(page).getByText("Not implemented", { exact: true })).toBeVisible();
  await dialog(page).getByRole("button", { name: "All integrations", exact: true }).click();
  await page.setViewportSize({ width: 390, height: 680 });
  await page.screenshot({ path: "../artifacts/connect-source-mobile.png" });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await dialog(page).getByRole("button", { name: "Linux Server", exact: true }).click();
  await expect(dialog(page).getByText("No SSH credentials or remote shell access")).toBeVisible();
  await expect(dialog(page).getByLabel("Agent mode", { exact: true })).toHaveCount(0);
  await expect(dialog(page).getByLabel("Website URL (optional)", { exact: true })).toHaveCount(0);
});

test("website setup requires successful validation and invalidates it when permissions change", async ({ page }) => {
  let testCalls = 0;
  const key = "mock-ui-credential-not-a-real-secret";
  await page.route("**/api/sources/website/test", async route => {
    testCalls += 1;
    const body = route.request().postDataJSON();
    expect(body.api_key).toBe(key);
    if (testCalls === 1) return route.fulfill({ status: 502, json: { detail: "The API rejected the credential or its permissions." } });
    return route.fulfill({ json: { valid: true, available_categories: ["authentication", "account_changes"], granted_permissions: ["authentication"], enabled_categories: body.categories, event_count: 1, mode: "simulated" } });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add Server", exact: true }).click();
  await dialog(page).getByRole("button", { name: "Website / Web Application", exact: true }).click();
  await dialog(page).getByLabel("Website name", { exact: true }).fill("Website UI fixture");
  await dialog(page).getByLabel("Base URL", { exact: true }).fill("https://example.test");
  await dialog(page).getByLabel(/^Security-events API endpoint/).fill("https://example.test/security-events");
  await dialog(page).getByLabel(/^API key/).fill(key);
  await expect(dialog(page).getByLabel(/^API key/)).toHaveAttribute("type", "password");
  const save = dialog(page).getByRole("button", { name: "Save integration", exact: true });
  await expect(save).toBeDisabled();
  await dialog(page).getByRole("button", { name: "Test Connection", exact: true }).click();
  await expect(dialog(page).getByRole("alert")).toContainText("rejected");
  await expect(save).toBeDisabled();
  await dialog(page).getByRole("button", { name: "Test Connection", exact: true }).click();
  await expect(dialog(page).getByRole("heading", { name: "Authentication verified", exact: true })).toBeVisible();
  await expect(save).toBeEnabled();
  await dialog(page).getByRole("checkbox", { name: "Account changes", exact: true }).check();
  await expect(save).toBeDisabled();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Add Server", exact: true }).click();
  await dialog(page).getByRole("button", { name: "Website / Web Application", exact: true }).click();
  await expect(dialog(page).getByLabel(/^API key/)).toHaveValue("");
});

test("actual authenticated HTTPS website connects, ingests, narrows permissions, disconnects and revokes", async ({ page, request }) => {
  const { readFileSync } = await import("node:fs");
  const key = readFileSync("../.agent-state/browser-website.key", "utf8").trim();
  const session = await (await request.get("/api/session")).json();
  const headers = { "X-SOC-Token": session.token };
  let sourceId = "";
  try {
    await page.goto("/");
    await page.getByRole("button", { name: "Add Server", exact: true }).click();
    await dialog(page).getByRole("button", { name: "Website / Web Application", exact: true }).click();
    await page.screenshot({ path: "../artifacts/connect-website-blank.png" });
    await dialog(page).getByLabel("Website name", { exact: true }).fill("Browser HTTPS website fixture");
    await dialog(page).getByLabel("Base URL", { exact: true }).fill("https://localhost:9445");
    await dialog(page).getByLabel(/^Security-events API endpoint/).fill("https://localhost:9445/security-events");
    await dialog(page).getByLabel(/^API key/).fill(key);
    await dialog(page).getByRole("button", { name: "Test Connection", exact: true }).click();
    await expect(dialog(page).getByRole("heading", { name: "Authentication verified", exact: true })).toBeVisible();
    await expect(dialog(page).getByText("Simulated — synthetic API events", { exact: true })).toBeVisible();
    const saved = page.waitForResponse(response => response.url().endsWith("/api/sources/website") && response.request().method() === "POST");
    await dialog(page).getByRole("button", { name: "Save integration", exact: true }).click();
    const registration = await (await saved).json();
    sourceId = registration.source.id;
    expect(sourceId).toMatch(/^src-/);
    await expect(dialog(page)).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Browser HTTPS website fixture", exact: true })).toBeVisible();
    await expect(page.getByText("SIMULATED FEED", { exact: false }).first()).toBeVisible();
    await page.getByRole("button", { name: "Fetch events", exact: true }).click();
    await expect.poll(async () => (await (await request.get("/api/sources/" + sourceId, { headers })).json()).events.length).toBe(1);
    await page.getByRole("button", { name: "Edit Permissions", exact: true }).click();
    await dialog(page).getByRole("checkbox", { name: "Account changes", exact: true }).check();
    await dialog(page).getByRole("button", { name: "Save permissions", exact: true }).click();
    await expect(dialog(page)).toHaveCount(0);
    await page.getByRole("button", { name: "Fetch events", exact: true }).click();
    await expect.poll(async () => (await (await request.get("/api/sources/" + sourceId, { headers })).json()).events.length).toBe(2);
    await page.getByRole("button", { name: "Disconnect", exact: true }).click();
    await dialog(page).getByRole("button", { name: "Confirm disconnect", exact: true }).click();
    await expect(page.getByRole("button", { name: "Fetch events", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Resume connection", exact: true }).click();
    await expect(page.getByRole("button", { name: "Fetch events", exact: true })).toBeEnabled();
    await page.getByRole("button", { name: "Revoke Credentials", exact: true }).click();
    await dialog(page).getByRole("button", { name: "Confirm revoke credentials", exact: true }).click();
    await expect(dialog(page)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Test Connection", exact: true })).toBeDisabled();
    const detail = await (await request.get("/api/sources/" + sourceId, { headers })).json();
    expect(detail.source.status).toBe("revoked");
    expect(detail.events.every((event: { telemetry_mode: string }) => event.telemetry_mode === "simulated")).toBe(true);
    expect(JSON.stringify(detail)).not.toContain(key);
  } finally {
    if (sourceId) await request.post("/api/sources/" + sourceId + "/revoke", { headers, data: {} });
  }
});
