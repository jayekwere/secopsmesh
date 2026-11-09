import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  reporter: [
    ["list"],
    ["junit", { outputFile: "../reports/browser-junit.xml" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:8080",
    viewport: { width: 1440, height: 1000 },
    trace: "off",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "../.venv/bin/python ../scripts/browser-server.py",
    url: "http://127.0.0.1:8080/health",
    reuseExistingServer: !process.env.CI,
    timeout: 60000,
  },
});
