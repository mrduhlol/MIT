import { test, expect } from "@playwright/test";

test.beforeEach(async ({ request }) => {
  const session = await (await request.get("/api/session")).json();
  const headers = { "X-SOC-Token": session.token };
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
  await request.post("/api/reset", { headers });
  await request.post("/api/replay", { headers, data: { mode: "all" } });
});

test("investigate an incident and approve only after explicit confirmation", async ({
  page,
  request,
}) => {
  await page.goto("/");
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
      const data = await (await request.get("/api/dashboard")).json();
      return data.actions.filter(
        (a: { status: string }) => a.status === "approved",
      ).length;
    })
    .toBe(1);
  const state = await (await request.get("/api/dashboard")).json();
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
    page.getByRole("button", { name: "Investigate incident", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "../artifacts/soc-mobile.png",
    fullPage: true,
  });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1,
  );
  expect(overflow).toBeFalsy();
});
