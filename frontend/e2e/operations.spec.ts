import { test, expect, Page } from "@playwright/test";
import fs from "node:fs";
const tokens = () =>
  JSON.parse(
    fs.readFileSync(
      JSON.parse(fs.readFileSync("../.runtime/e2e-session.json", "utf8"))
        .token_file,
      "utf8",
    ),
  );
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

test("completed replay is cleared across a real tenant switch", async ({
  page,
}) => {
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Detections", exact: true }).click();
  await page
    .getByRole("button", { name: "Replay detections", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Replay evaluation", exact: true }),
  ).toBeVisible();
  const report = JSON.parse(await page.locator("pre").innerText());
  const privateEvidenceId = report.detections[0].evidence_ids[0];
  await page.getByTitle("Switch credential").click();
  await login(page, "other_observer");
  await expect(
    page.getByText("lab-other workspace", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Detections", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Replay evaluation", exact: true }),
  ).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(privateEvidenceId);
});

test("late refresh cannot restore prior-tenant evidence", async ({ page }) => {
  await page.goto("/");
  await login(page);
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await expect(
    page.getByText("Synthetic suspicious credential access", { exact: true }),
  ).toBeVisible();
  let release!: () => void;
  let observed!: () => void;
  let settled!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const started = new Promise<void>((resolve) => (observed = resolve));
  const finished = new Promise<void>((resolve) => (settled = resolve));
  let intercepted = false;
  await page.route("**/api/events", async (route) => {
    if (
      !intercepted &&
      route.request().headers().authorization === "Bearer " + tokens().analyst
    ) {
      intercepted = true;
      const response = await route.fetch();
      observed();
      await held;
      try {
        await route.fulfill({ response });
      } catch {
        /* sign-out intentionally aborts the old request */
      } finally {
        settled();
      }
    } else await route.continue();
  });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await started;
  await page.getByTitle("Switch credential").click();
  await login(page, "other_observer");
  await expect(
    page.getByText("lab-other workspace", { exact: true }),
  ).toBeVisible();
  release();
  await finished;
  await expect(
    page.getByText("Synthetic suspicious credential access", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("late incident inspection cannot cross a credential boundary", async ({
  page,
}) => {
  await page.goto("/");
  await login(page);
  let release!: () => void;
  let observed!: () => void;
  let settled!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const started = new Promise<void>((resolve) => (observed = resolve));
  const finished = new Promise<void>((resolve) => (settled = resolve));
  await page.route(/\/api\/incidents\/[a-f0-9]{64}$/, async (route) => {
    const response = await route.fetch();
    observed();
    await held;
    try {
      await route.fulfill({ response });
    } catch {
      /* aborted old-session request */
    } finally {
      settled();
    }
  });
  await page.getByRole("button", { name: "Incidents", exact: true }).click();
  await page
    .getByRole("button", {
      name: /Related security activity: lab:hybrid-identity/,
    })
    .click();
  await started;
  await page.getByTitle("Switch credential").click();
  await login(page, "other_observer");
  await expect(
    page.getByText("lab-other workspace", { exact: true }),
  ).toBeVisible();
  release();
  await finished;
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("lab:hybrid-identity");
});
