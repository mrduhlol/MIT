import { existsSync } from "node:fs";
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "modals.spec.ts",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "https://localhost:8443",
    // Browser QA of the dedicated local development certificate only.
    // The Linux collector continues to require verified CA trust/hostname.
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    launchOptions: {
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ||
        ["/usr/lib/chromium/chromium", "/usr/bin/chromium"].find(existsSync),
      args: ["--no-sandbox"],
    },
    screenshot: "only-on-failure",
  },
  // Intentionally no webServer: use the single existing HTTPS backend.
});
