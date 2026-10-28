import { test, expect } from "@playwright/test";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

test("Add Server to verified HTTPS collector, incident review, and revoke", async ({
  page,
  request,
}) => {
  const directory = mkdtempSync(join(tmpdir(), "soc-enrollment-e2e-"));
  chmodSync(directory, 0o700);
  const hostname = "browser-demo-" + Date.now();
  const session = await (await request.get("/api/session")).json();
  const headers = { "X-SOC-Token": session.token };
  let serverId = "";
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page.goto("/");
    await page.getByRole("button", { name: "Add Server", exact: true }).click();
    await page
      .getByLabel("Server name", { exact: true })
      .fill("Browser demo Linux");
    await page.getByLabel(/^Hostname/).fill(hostname);
    await page
      .getByLabel("Website URL (optional)", { exact: true })
      .fill("https://example.test");
    await page
      .getByLabel("Agent mode", { exact: true })
      .selectOption("simulated");
    const created = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/servers") && r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Create server", exact: true })
      .click();
    const registration = await (await created).json();
    serverId = registration.server.id;
    await expect(
      page.getByLabel("Enrollment token", { exact: true }),
    ).toBeVisible();
    const tokenFile = join(directory, "enrollment.txt");
    writeFileSync(tokenFile, registration.enrollment_token, { mode: 0o600 });
    const stateDir = join(directory, "state");
    // Token only enters an owner-only file, never shell args, process output or screenshots.
    execFileSync(
      "../backend/.venv/bin/python",
      [
        "../agent/soc_agent.py",
        "enroll",
        "--url",
        "https://localhost:8443",
        "--ca-cert",
        resolve("../.local-tls/ca.crt"),
        "--state-dir",
        stateDir,
        "--token-file",
        tokenFile,
        "--hostname",
        hostname,
        "--mode",
        "simulated",
      ],
      { stdio: "pipe", timeout: 20_000 },
    );
    execFileSync(
      "../backend/.venv/bin/python",
      ["../agent/soc_agent.py", "run", "--state-dir", stateDir, "--once"],
      { stdio: "pipe", timeout: 25_000 },
    );
    await page
      .getByRole("button", {
        name: "Close enrollment instructions",
        exact: true,
      })
      .last()
      .click();
    await expect(
      page.getByLabel("Enrollment token", { exact: true }),
    ).not.toBeVisible();
    await expect
      .poll(
        async () =>
          (
            await (
              await request.get("/api/servers/" + serverId, { headers })
            ).json()
          ).server.status,
      )
      .toBe("online");
    const detail = await (
      await request.get("/api/servers/" + serverId, { headers })
    ).json();
    expect(detail.server.metrics.cpu_percent).toBe(24);
    expect(detail.events.length).toBe(3);
    expect(detail.incidents.length).toBe(1);
    expect(
      detail.events.every(
        (e: { telemetry_mode: string }) => e.telemetry_mode === "simulated",
      ),
    ).toBe(true);
    await expect(page.getByText("24.0%", { exact: true }).first()).toBeVisible({
      timeout: 10_000,
    });
    await page.screenshot({
      path: "../artifacts/servers-desktop.png",
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: "../artifacts/servers-mobile.png",
      fullPage: true,
    });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth + 1,
      ),
    ).toBe(false);
    await page.setViewportSize({ width: 1280, height: 900 });
    // Existing investigation/approval API and UI remain the only response path.
    const incidentId = detail.incidents[0].id;
    const investigation = await (
      await request.post("/api/incidents/" + incidentId + "/investigate", {
        headers,
        data: {},
      })
    ).json();
    expect(
      investigation.recommendations.every(
        (a: { status: string }) => a.status === "pending",
      ),
    ).toBe(true);
    const action = investigation.recommendations[0];
    const rejected = await request.post(
      "/api/actions/" + action.id + "/decision",
      {
        headers,
        data: {
          decision: "reject",
          confirmed: false,
          actor: "Browser reviewer",
          reason: "Keep demo collection running",
        },
      },
    );
    expect(rejected.ok()).toBe(true);
    const forbidden = await request.post(
      "/api/actions/" + action.id + "/decision",
      {
        headers,
        data: {
          decision: "approve",
          confirmed: true,
          actor: "Browser reviewer",
          reason: "Cannot override rejected decision",
        },
      },
    );
    expect(forbidden.status()).toBe(409);
    await request.post("/api/servers/" + serverId + "/revoke", {
      headers,
      data: {},
    });
    const credential = JSON.parse(
      readFileSync(join(stateDir, "credentials.json"), "utf8"),
    );
    const denied = await request.post("/api/agent/ingest", {
      headers: { Authorization: "Bearer " + credential.agent_token },
      data: {},
    });
    expect(denied.status()).toBe(401);
    expect(
      (
        await (
          await request.get("/api/servers/" + serverId, { headers })
        ).json()
      ).server.status,
    ).toBe("revoked");
    await page
      .getByRole("button", { name: "Agent overview", exact: true })
      .click();
    await page.getByRole("button", { name: "Servers", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Add Server", exact: true }),
    ).not.toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    if (serverId)
      await request.post("/api/servers/" + serverId + "/revoke", {
        headers,
        data: {},
      });
    rmSync(directory, { recursive: true, force: true });
  }
});
