import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { csvCell } from "../src/logExport";
let adminHeaders: Record<string, string> = {};

test.beforeEach(async ({ request }) => {
  const session = await (await request.get("/api/session")).json();
  const headers = { "X-SOC-Token": session.token };
  adminHeaders = headers;
  await request.post("/api/agent/settings", {
    headers,
    data: { enabled: false, interval_seconds: 300 },
  });
  expect((await request.post("/api/reset", { headers })).ok()).toBeTruthy();
  expect(
    (
      await request.post("/api/replay", { headers, data: { mode: "all" } })
    ).ok(),
  ).toBeTruthy();
});

test.afterEach(async ({ request }) => {
  const session = await (await request.get("/api/session")).json();
  const headers = { "X-SOC-Token": session.token };
  adminHeaders = headers;
  await request.post("/api/agent/settings", {
    headers,
    data: { enabled: false, interval_seconds: 300 },
  });
  await request.post("/api/reset", { headers });
  await request.post("/api/replay", { headers, data: { mode: "all" } });
});

test("investigate an incident and approve only after explicit confirmation", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", { name: "Review incidents", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Investigate incident", exact: true })
    .click();
  await page.screenshot({
    path: "../artifacts/soc-desktop.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Approve", exact: true })
    .first()
    .click();
  const confirm = page.getByRole("button", {
    name: "Confirm approval",
    exact: true,
  });
  await expect(confirm).toBeDisabled();
  await page.getByLabel(/analyst/i).fill("Browser test analyst");
  await page
    .getByLabel(/reason/i)
    .fill("Reviewed the correlated synthetic evidence.");
  await page.getByRole("checkbox").check();
  await confirm.click();
  await expect(confirm).not.toBeVisible();
  await expect
    .poll(async () => {
      const data = await (
        await request.get("/api/dashboard", { headers: adminHeaders })
      ).json();
      return data.actions.filter(
        (a: { status: string }) => a.status === "approved",
      ).length;
    })
    .toBe(1);
  const state = await (
    await request.get("/api/dashboard", { headers: adminHeaders })
  ).json();
  expect(
    state.sandbox.isolated_hosts.length +
      state.sandbox.revoked_identities.length,
  ).toBe(1);
  expect(
    state.actions.some((a: { status: string }) => a.status === "pending"),
  ).toBeTruthy();
});

test("mobile interface loads without horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "Run patrol", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Run patrol", exact: true }).click();
  await expect(
    page.getByText(
      "Patrol completed. Results recorded; no containment actions executed.",
      { exact: true },
    ),
  ).toBeVisible({ timeout: 20_000 });
  await page.screenshot({
    path: "../artifacts/advanced-mobile.png",
    fullPage: true,
  });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(overflow).toBeFalsy();
});

test("agent patrol, analytics and schedule controls work without approving responses", async ({
  page,
  request,
}) => {
  const before = await (
    await request.get("/api/agent", { headers: adminHeaders })
  ).json();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Event activity", exact: true })).not.toBeVisible();
  await page.getByText("Activity charts and details", { exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Event activity", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("img", { name: /Events and suspicious signals over time/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Run patrol", exact: true }).click();
  await expect(
    page.getByText(
      "Patrol completed. Results recorded; no containment actions executed.",
      { exact: true },
    ),
  ).toBeVisible({ timeout: 20_000 });
  const agent = await (
    await request.get("/api/agent", { headers: adminHeaders })
  ).json();
  expect(agent.runs[0].id).not.toBe(before.runs[0]?.id);
  expect(agent.runs[0].status).toBe("completed");
  expect(agent.runs[0].events_analyzed).toBeGreaterThan(0);
  await expect(
    page.getByRole("img", { name: /Measured patrol duration/ }),
  ).toBeVisible();
  const state = await (
    await request.get("/api/dashboard", { headers: adminHeaders })
  ).json();
  expect(state.actions.length).toBeGreaterThan(0);
  expect(
    state.actions.every(
      (action: { status: string }) => action.status === "pending",
    ),
  ).toBeTruthy();
  expect(state.sandbox).toEqual({ isolated_hosts: [], revoked_identities: [] });
  const analyticsResponse = page.waitForResponse(
    (response) =>
      response.url().includes("/api/analytics?window_minutes=60") &&
      response.ok(),
  );
  await page
    .getByLabel("Analytics time window", { exact: true })
    .selectOption("60");
  expect((await (await analyticsResponse).json()).window_minutes).toBe(60);
  await page.getByText("Patrol schedule", { exact: true }).click();
  await page
    .getByLabel("Patrol frequency", { exact: true })
    .selectOption("900");
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get("/api/agent", { headers: adminHeaders })
          ).json()
        ).interval_seconds,
    )
    .toBe(900);
  await page
    .getByRole("button", { name: "Resume patrol", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Pause patrol", exact: true }),
  ).toBeVisible();
  expect(
    (await (await request.get("/api/agent", { headers: adminHeaders })).json())
      .enabled,
  ).toBe(true);
  await page.getByRole("button", { name: "Pause patrol", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Resume patrol", exact: true }),
  ).toBeVisible();
  expect(
    (await (await request.get("/api/agent", { headers: adminHeaders })).json())
      .next_run_at,
  ).toBeNull();
  await page.screenshot({
    path: "../artifacts/advanced-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("telemetry filters, paused display and JSON export match the selected records", async ({
  page,
  request,
}) => {
  const dashboard = await (
    await request.get("/api/dashboard", { headers: adminHeaders })
  ).json();
  const criticalIds = new Set(
    dashboard.incidents
      .filter(
        (incident: { severity: string }) => incident.severity === "critical",
      )
      .flatMap((incident: { event_ids: string[] }) => incident.event_ids),
  );
  const expected = dashboard.events.filter(
    (event: {
      source: string;
      suspicious: boolean;
      id: string;
      identity: string;
    }) =>
      event.source === "email" &&
      event.suspicious &&
      criticalIds.has(event.id) &&
      event.identity.includes("maya"),
  );
  expect(expected.length).toBeGreaterThan(0);
  await page.goto("/");
  await page.getByRole("button", { name: "Logs", exact: true }).click();
  await page.getByLabel("Filter events", { exact: true }).selectOption("email");
  await page
    .getByLabel("Filter severity", { exact: true })
    .selectOption("critical");
  await page.getByLabel("Search events", { exact: true }).fill("maya");
  await expect(page.locator("tbody tr")).toHaveCount(expected.length);
  const downloadPromise = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Download JSON", exact: true })
    .click();
  const download = await downloadPromise;
  const downloaded = JSON.parse(
    await readFile((await download.path())!, "utf8"),
  );
  expect(downloaded).toEqual(expected);
  await page.getByLabel("Filter severity", { exact: true }).selectOption("all");
  const count = await page.locator("tbody tr").count();
  await page
    .getByRole("button", { name: "Pause live feed", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Resume live feed", exact: true }),
  ).toBeVisible();
  const session = await (await request.get("/api/session")).json();
  const refreshed = page.waitForResponse(
    (response) => response.url().endsWith("/api/dashboard") && response.ok(),
  );
  await request.post("/api/reset", {
    headers: { "X-SOC-Token": session.token },
  });
  await refreshed;
  await expect(page.locator("tbody tr")).toHaveCount(count);
  await page
    .getByRole("button", { name: "Resume live feed", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "No matching events", exact: true }),
  ).toBeVisible();
});

test("CSV export escapes spreadsheet formulas and delimiters", () => {
  expect(csvCell('=HYPERLINK("https://example.invalid")')).toBe(
    '"\'=HYPERLINK(""https://example.invalid"")"',
  );
  expect(csvCell("  +SUM(1,2)")).toBe('"\'  +SUM(1,2)"');
  expect(csvCell('name,"quoted"')).toBe('"name,""quoted"""');
  expect(csvCell(null)).toBe('"null"');
});
