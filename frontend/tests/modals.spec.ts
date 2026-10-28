import { test, expect, type Page } from "@playwright/test";

const visibleDialog = (page: Page) => page.locator("dialog[open]");
const opener = (page: Page) => page.getByRole("button", { name: "Add Server", exact: true }).first();

async function settleFrames(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}

async function centered(page: Page, dialog = visibleDialog(page)) {
  await expect(dialog).toHaveCount(1);
  await expect(dialog).toBeVisible();
  await expect.poll(async () => dialog.evaluate(element => {
    const rect = element.getBoundingClientRect();
    return Math.max(Math.abs(rect.x + rect.width / 2 - innerWidth / 2), Math.abs(rect.y + rect.height / 2 - innerHeight / 2));
  })).toBeLessThanOrEqual(1);
}

async function openAdd(page: Page) {
  await opener(page).click();
  await centered(page);
  await expect(visibleDialog(page).getByRole("heading", { name: "Connect Data Source", exact: true })).toBeVisible();
  await visibleDialog(page).getByRole("button", { name: "Simulated Demo Source", exact: true }).click();
  await centered(page);
}

async function mockServerApi(page: Page) {
  const server = {
    id: "srv-modal-fixture", name: "Modal test fixture", hostname: "modal-test.invalid", website_url: null,
    mode: "simulated", status: "pending", last_seen_at: null, metrics: null, event_count: 0, threat_count: 0,
    incident_ids: [], created_at: "2026-10-28T08:00:00+00:00",
  };
  let registered = false;
  const source = { ...server, type: "simulated", available_categories: ["health_metrics", "authentication"], granted_permissions: [], enabled_categories: ["health_metrics", "authentication"], last_success_at: null, last_event_at: null, last_heartbeat_at: null, error: null };
  await page.route("**/api/sources**", async route => {
    if (route.request().method() !== "GET") return route.abort();
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path === "/api/sources" ? { sources: registered ? [source] : [] } : { source, events: [], incidents: [] } });
  });
  const enrollment = () => ({ server, enrollment_token: "TEST_FIXTURE_NOT_A_VALID_ENROLLMENT_CREDENTIAL", expires_at: "2099-01-01T00:00:00+00:00" });
  await page.route("**/api/servers**", async route => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.pathname === "/api/servers" && method === "POST") {
      registered = true;
      await route.fulfill({ json: enrollment() });
    } else if (url.pathname === "/api/servers" && method === "GET") {
      await route.fulfill({ json: { servers: registered ? [server] : [] } });
    } else if (url.pathname.endsWith("/enrollment") && method === "POST") {
      await route.fulfill({ json: enrollment() });
    } else if (method === "GET") {
      await route.fulfill({ json: { server, events: [], incidents: [], metric_history: [] } });
    } else {
      await route.abort(); // No real registration, revocation, or credential mutation.
    }
  });
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(opener(page)).toBeEnabled();
});

test("Add Server is viewport-centered with separately animated blurred backdrop", async ({ page }) => {
  await openAdd(page);
  const dialog = visibleDialog(page);
  await expect(dialog.getByLabel("Server name", { exact: true })).toBeFocused();
  const appearance = await dialog.evaluate(element => {
    const own = getComputedStyle(element);
    const backdrop = getComputedStyle(element, "::backdrop");
    return { duration: own.animationDuration, animation: own.animationName, backdropDuration: backdrop.animationDuration,
      backdropAnimation: backdrop.animationName, blur: backdrop.backdropFilter, fallback: backdrop.backgroundColor,
      labelledBy: element.getAttribute("aria-labelledby") };
  });
  expect(appearance.duration.split(",").map(value => value.trim())).toContain("0.2s");
  expect(appearance.backdropDuration.split(",").map(value => value.trim())).toContain("0.2s");
  expect(appearance.animation).not.toBe("none");
  expect(appearance.backdropAnimation).not.toBe("none");
  expect(appearance.backdropAnimation).not.toBe(appearance.animation);
  expect(appearance.blur).toBe("blur(5px)");
  expect(appearance.fallback).toMatch(/^rgba?\(/);
  expect(appearance.fallback).not.toBe("rgba(0, 0, 0, 0)");
  expect(appearance.labelledBy).toBeTruthy();
  await page.screenshot({ path: new URL("../../artifacts/modal-desktop.png", import.meta.url).pathname, fullPage: false });
});

test("native dialog traps focus and Escape or close restores its opener across repeated openings", async ({ page }) => {
  for (let iteration = 0; iteration < 3; iteration += 1) {
    await openAdd(page);
    const dialog = visibleDialog(page);
    const first = dialog.getByRole("button", { name: "All integrations", exact: true });
    const last = dialog.getByRole("button", { name: "Create server", exact: true });
    await first.focus();
    await page.keyboard.press("Shift+Tab");
    await expect(last).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(first).toBeFocused();
    // Native showModal makes the rest of the document inert to focus.
    await opener(page).evaluate(element => element.focus());
    await expect(first).toBeFocused();
    if (iteration === 1) await dialog.getByRole("button", { name: "Close Connect Data Source", exact: true }).click();
    else await page.keyboard.press("Escape");
    await expect(visibleDialog(page)).toHaveCount(0);
    await expect(opener(page)).toBeFocused();
  }
});

test("background scrolling is locked and prior scroll/styles are restored", async ({ page }) => {
  // Enter Servers before adding a long test-only background so navigation does
  // not itself change document height during the scroll-restoration check.
  await openAdd(page);
  await page.keyboard.press("Escape");
  const before = await page.evaluate(() => {
    const spacer = document.createElement("div");
    spacer.id = "modal-scroll-fixture";
    spacer.style.cssText = "height:1800px;position:relative;";
    const marker = document.createElement("div");
    marker.id = "modal-background-marker";
    marker.style.cssText = "height:10px;width:10px;";
    spacer.append(marker);
    document.querySelector(".app-shell")!.append(spacer);
    document.body.style.paddingRight = "7px";
    window.scrollTo(0, 240);
    return { scroll: scrollY, inline: document.body.getAttribute("style") };
  });
  expect(before.scroll).toBeGreaterThan(0);
  await opener(page).evaluate(element => { element.focus({ preventScroll: true }); element.click(); });
  await centered(page);
  const locked = await page.evaluate(() => ({ scroll: scrollY, marker: document.querySelector("#modal-background-marker")!.getBoundingClientRect().top }));
  await page.mouse.move(3, 3);
  await page.mouse.wheel(0, 700);
  await settleFrames(page);
  expect(await page.evaluate(() => scrollY)).toBe(locked.scroll);
  expect(await page.locator("#modal-background-marker").evaluate(element => element.getBoundingClientRect().top)).toBeCloseTo(locked.marker, 1);
  await page.keyboard.press("Escape");
  await expect(visibleDialog(page)).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(before.scroll);
  expect(await page.evaluate(() => document.body.getAttribute("style"))).toBe(before.inline);
});

test("backdrop dismisses only a pristine form and interior padding never dismisses", async ({ page }) => {
  await openAdd(page);
  await page.mouse.click(3, 3);
  await expect(visibleDialog(page)).toHaveCount(0);
  await expect(opener(page)).toBeFocused();
  await openAdd(page);
  const box = (await visibleDialog(page).boundingBox())!;
  await page.mouse.click(box.x + 6, box.y + 6);
  await expect(visibleDialog(page)).toHaveCount(1);
  await visibleDialog(page).getByLabel("Server name", { exact: true }).fill("Unsaved fixture");
  await page.mouse.click(3, 3);
  await expect(visibleDialog(page)).toHaveCount(1);
  await expect(visibleDialog(page).getByLabel("Server name", { exact: true })).toHaveValue("Unsaved fixture");
  await page.keyboard.press("Escape");
  await expect(visibleDialog(page)).toHaveCount(0);
});

for (const viewport of [{ width: 390, height: 600 }, { width: 740, height: 360 }]) {
  test(`dialog fits ${viewport.width}x${viewport.height} with reachable internally scrolling actions`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await openAdd(page);
    await visibleDialog(page).getByRole("button", { name: "All integrations", exact: true }).click();
    await visibleDialog(page).getByRole("button", { name: "Website / Web Application", exact: true }).click();
    await centered(page);
    const dialog = visibleDialog(page);
    const geometry = await dialog.evaluate(element => {
      const rect = element.getBoundingClientRect();
      return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
        scrollHeight: element.scrollHeight, clientHeight: element.clientHeight };
    });
    expect(geometry.left).toBeGreaterThanOrEqual(7);
    expect(geometry.right).toBeLessThanOrEqual(viewport.width - 7);
    expect(geometry.top).toBeGreaterThanOrEqual(7);
    expect(geometry.bottom).toBeLessThanOrEqual(viewport.height - 7);
    expect(geometry.scrollHeight).toBeGreaterThan(geometry.clientHeight);
    if (viewport.width === 390) await page.screenshot({ path: new URL("../../artifacts/modal-mobile.png", import.meta.url).pathname, fullPage: false });
    const submit = dialog.getByRole("button", { name: "Save integration", exact: true });
    await submit.scrollIntoViewIfNeeded();
    await expect(submit).toBeInViewport({ ratio: 1 });
    expect(await dialog.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
    await centered(page);
    await page.keyboard.press("Escape");
  });
}

test("resize and transformed clipped app ancestors cannot displace the modal", async ({ page }) => {
  await page.evaluate(() => {
    for (const selector of ["#root", ".app-shell"]) {
      const element = document.querySelector<HTMLElement>(selector)!;
      element.style.transform = "translate(37px, 19px) scale(.92)";
      element.style.overflow = "hidden";
      element.style.maxHeight = "600px";
      element.style.position = "relative";
      element.style.zIndex = "2147483647";
    }
  });
  await openAdd(page);
  expect(await visibleDialog(page).evaluate(element => element.parentElement === document.body)).toBe(true);
  await page.setViewportSize({ width: 820, height: 620 });
  await centered(page);
  await page.setViewportSize({ width: 1200, height: 840 });
  await centered(page);
});

test("reduced motion disables dialog and backdrop animation while retaining readable backdrop", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openAdd(page);
  const styles = await visibleDialog(page).evaluate(element => ({
    dialog: getComputedStyle(element).animationName,
    backdrop: getComputedStyle(element, "::backdrop").animationName,
    blur: getComputedStyle(element, "::backdrop").backdropFilter,
  }));
  expect(styles.dialog).toBe("none");
  expect(styles.backdrop).toBe("none");
  expect(styles.blur).toBe("blur(5px)");
});

test("reset uses the same centered modal and closes without resetting on Escape", async ({ page }) => {
  const reset = page.getByRole("button", { name: "Reset", exact: true });
  await reset.click();
  await centered(page);
  await expect(visibleDialog(page).getByRole("heading", { name: "Restart the simulation?", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(visibleDialog(page)).toHaveCount(0);
  await expect(reset).toBeFocused();
});

test("mocked enrollment handoffs keep scroll lock and never dismiss one-time instructions on backdrop", async ({ page }) => {
  await mockServerApi(page);
  await openAdd(page);
  await visibleDialog(page).getByLabel("Server name", { exact: true }).fill("Modal test fixture");
  await visibleDialog(page).getByLabel(/^Hostname/).fill("modal-test.invalid");
  await visibleDialog(page).getByRole("button", { name: "Create server", exact: true }).click();
  await expect(visibleDialog(page).getByLabel("Enrollment token", { exact: true })).toHaveValue("TEST_FIXTURE_NOT_A_VALID_ENROLLMENT_CREDENTIAL");
  await centered(page);
  await page.mouse.click(3, 3);
  await expect(visibleDialog(page).getByLabel("Enrollment token", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.body.style.position)).toBe("fixed");
  await visibleDialog(page).getByRole("button", { name: "Close enrollment instructions", exact: true }).first().click();
  await expect(visibleDialog(page)).toHaveCount(0);
  await expect(opener(page)).toBeFocused();
  const rotate = page.getByRole("button", { name: "Rotate enrollment", exact: true });
  await rotate.click();
  await centered(page);
  await visibleDialog(page).getByRole("button", { name: "Rotate credentials", exact: true }).click();
  await expect(visibleDialog(page).getByLabel("Enrollment token", { exact: true })).toBeVisible();
  await centered(page);
  expect(await page.evaluate(() => document.body.style.position)).toBe("fixed");
  await page.mouse.click(3, 3);
  await expect(visibleDialog(page)).toHaveCount(1);
  await visibleDialog(page).getByRole("button", { name: "Close enrollment instructions", exact: true }).first().click();
  await expect(visibleDialog(page)).toHaveCount(0);
  await expect(rotate).toBeFocused();
  expect(await page.evaluate(() => document.body.style.position)).not.toBe("fixed");
});
