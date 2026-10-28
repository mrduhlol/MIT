import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
export default defineConfig({
  testDir: "./tests",
  testMatch: "servers.spec.ts",
  timeout: 90_000,
  workers: 1,
  use: {
    baseURL: "https://localhost:8443",
    // Browser QA only: the real Python collector verifies the local CA independently.
    ignoreHTTPSErrors: true,
    screenshot: "off",
    trace: "off",
    launchOptions: {
      executablePath:
        process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ||
        ["/usr/lib/chromium/chromium", "/usr/bin/chromium"].find(existsSync),
      args: ["--no-sandbox"],
    },
  },
});
