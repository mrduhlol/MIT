import { existsSync, mkdtempSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { defineConfig } from "@playwright/test";

const baseURL = process.env.SOC_TEST_BASE_URL || "https://localhost:8445";
process.env.SOC_TEST_BASE_URL = baseURL;
const testDirectory = mkdtempSync(resolve(tmpdir(), "soc-browser-"));

export default defineConfig({
  testDir: "./tests",
  projects: [
    { name: "dashboard", testIgnore: "servers.spec.ts" },
    { name: "enrollment", testMatch: "servers.spec.ts", dependencies: ["dashboard"] },
  ],
  timeout: 90_000,
  expect: { timeout: 12_000 },
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    screenshot: "off",
    trace: "off",
    launchOptions: {
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ||
        ["/usr/lib/chromium/chromium", "/usr/bin/chromium"].find(existsSync),
      args: ["--no-sandbox"],
    },
  },
  webServer: [{
    command: "../backend/.venv/bin/python -m uvicorn backend.app.main:app --app-dir .. --host 127.0.0.1 --port 8445 --no-proxy-headers --ssl-keyfile ../.local-tls/server.key --ssl-certfile ../.local-tls/server.crt",
    url: baseURL + "/api/health",
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    env: { SOC_DB_PATH: resolve(testDirectory, "soc.sqlite"), SOC_CONNECTOR_ALLOWED_ORIGINS: "https://localhost:9445", SOC_CONNECTOR_CA_FILE: resolve("../.local-tls/ca.crt") },
  }, {
    command: "../backend/.venv/bin/python ../scripts/demo_website.py --port 9445 --key-file ../.agent-state/browser-website.key --cert ../.local-tls/server.crt --tls-key ../.local-tls/server.key",
    url: "https://localhost:9445/security-events",
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
  }],
});
