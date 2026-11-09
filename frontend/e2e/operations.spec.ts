import { test, expect, Page } from "@playwright/test";
import fs from "node:fs";
const tokens = () =>
  JSON.parse(fs.readFileSync("../.runtime/tokens.json", "utf8"));
async function login(page: Page, role = "analyst") {
  await page
    .getByLabel("Access credential", { exact: true })
    .fill(tokens()[role]);
  await page
    .getByRole("button", { name: "Connect to workspace", exact: true })
    .click();
  await expect(
    page.getByRole("navigation", { name: "Main navigation" }),
  ).toBeVisible();
}
test("authenticated evidence viewer filters real source records", async ({
  page,
}) => {
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await page.getByRole("textbox", { name: "Search findings" }).fill("wazuh");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page
    .getByRole("button", {
      name: "Synthetic suspicious credential access",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("heading", { name: "Redacted source evidence" }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toContainText("[REDACTED]");
  await expect(page.getByRole("dialog")).not.toContainText(
    "synthetic-redaction-canary",
  );
});
test("investigation and deterministic detection replay use backend results", async ({
  page,
}) => {
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Incidents", exact: true }).click();
  await page
    .getByRole("button", {
      name: /Related security activity: lab:hybrid-identity/,
    })
    .click();
  await page
    .getByRole("button", { name: "Investigate evidence", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toContainText("Evidence citations");
  await expect(page.getByRole("dialog")).toContainText("compromise certainty");
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByRole("button", { name: "Detections", exact: true }).click();
  await page
    .getByRole("button", { name: "Replay detections", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Replay evaluation" }),
  ).toBeVisible();
  await expect(page.locator("pre")).toContainText("hybrid-identity-pivot");
});
test("three independent browser sessions approve, contain, verify and roll back", async ({
  page,
}) => {
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Incidents", exact: true }).click();
  await page
    .getByRole("button", {
      name: /Related security activity: lab:hybrid-identity/,
    })
    .click();
  await page
    .getByRole("button", {
      name: "Propose containment · lab-host",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("button", { name: "Approve exact plan", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByTitle("Switch credential").click();
  await login(page, "approver");
  await page.getByRole("button", { name: "Approvals", exact: true }).click();
  await page
    .getByRole("button", { name: /contain · lab-host/ })
    .last()
    .click();
  await expect(
    page.getByRole("heading", { name: "Exact plan for review" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Approve exact plan", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Execute approved plan", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByTitle("Switch credential").click();
  await login(page, "executor");
  await page.getByRole("button", { name: "Automation", exact: true }).click();
  await page
    .getByRole("button", { name: /contain · lab-host/ })
    .last()
    .click();
  await page
    .getByRole("button", { name: "Execute approved plan", exact: true })
    .click();
  await expect(page.getByRole("dialog").locator("pre").last()).toContainText(
    '"verified": true',
  );
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByTitle("Switch credential").click();
  await login(page);
  await page.getByRole("button", { name: "Automation", exact: true }).click();
  await page
    .getByRole("button", { name: /contain · lab-host/ })
    .last()
    .click();
  await page
    .getByRole("button", { name: "Propose authorized rollback", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByTitle("Switch credential").click();
  await login(page, "approver");
  await page.getByRole("button", { name: "Approvals", exact: true }).click();
  await page
    .getByRole("button", { name: /rollback · lab-host/ })
    .last()
    .click();
  await page
    .getByRole("button", { name: "Approve exact plan", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Close inspector", exact: true })
    .click();
  await page.getByTitle("Switch credential").click();
  await login(page, "executor");
  await page.getByRole("button", { name: "Automation", exact: true }).click();
  await page
    .getByRole("button", { name: /rollback · lab-host/ })
    .last()
    .click();
  await page
    .getByRole("button", { name: "Execute approved plan", exact: true })
    .click();
  await expect(page.getByRole("dialog").locator("pre").last()).toContainText(
    '"observed_status": 200',
  );
});
test("audit verification and provider status never claim live cloud acceptance", async ({
  page,
}) => {
  await page.goto("/");
  await login(page, "observer");
  await page.getByRole("button", { name: "Audit trail", exact: true }).click();
  await page
    .getByRole("button", { name: "Verify audit chain", exact: true })
    .click();
  await expect(page.getByText("Chain verified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Integrations", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(13);
  await expect(
    page.getByText("contract-tested; live acceptance pending", { exact: true }),
  ).toHaveCount(13);
});
test("small-screen navigation and tables remain usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await expect(
    page.getByRole("textbox", { name: "Search findings" }),
  ).toBeVisible();
  await page
    .getByRole("textbox", { name: "Search findings" })
    .fill("guardduty");
  await page
    .getByRole("button", {
      name: "Synthetic anomalous API activity",
      exact: true,
    })
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
});
