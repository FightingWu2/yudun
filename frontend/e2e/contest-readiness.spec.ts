import { expect, test, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const contestDir = resolve(process.cwd(), "..", "artifacts", "contest");

async function blockExternalNetwork(page: Page): Promise<string[]> {
  const blocked: string[] = [];
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
      await route.continue();
    } else {
      blocked.push(url.origin);
      await route.abort("internetdisconnected");
    }
  });
  return blocked;
}

test("1280x720 guarded demo remains operable with external network blocked", async ({
  page,
}) => {
  mkdirSync(contestDir, { recursive: true });
  await page.setViewportSize({ width: 1280, height: 720 });
  const externalRequests = await blockExternalNetwork(page);
  const timings: Record<string, number> = {};

  let started = performance.now();
  await page.goto("/");
  await expect(page.getByTestId("replay-console")).toBeVisible();
  timings.frontend_load = Number((performance.now() - started).toFixed(2));

  started = performance.now();
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByTestId("global-state")).toContainText("IDLE");
  timings.reset = Number((performance.now() - started).toFixed(2));

  const fullStarted = performance.now();
  started = performance.now();
  await page.getByTestId("start-replay").click();
  await expect(page.getByTestId("global-state")).toContainText(
    "WAITING_APPROVAL",
  );
  timings.replay_to_approval = Number((performance.now() - started).toFixed(2));
  await page.getByTestId("detection-signals").screenshot({
    path: resolve(contestDir, "01_detection.png"),
  });

  await page.getByTestId("evidence-index").locator("button").first().click();
  await expect(page.getByTestId("evidence-drawer")).toBeVisible();
  await page.getByTestId("evidence-drawer").screenshot({
    path: resolve(contestDir, "02_evidence.png"),
  });
  await page.getByRole("button", { name: "×" }).click();

  await page.getByRole("button", { name: "Evidence & Investigation" }).click();
  await page.getByTestId("agent-tasks").screenshot({
    path: resolve(contestDir, "03_agent_task.png"),
  });
  await page.getByTestId("attack-timeline").screenshot({
    path: resolve(contestDir, "04_timeline.png"),
  });

  await page.getByRole("button", { name: "Response & Verification" }).click();
  await page.getByTestId("policy-engine").screenshot({
    path: resolve(contestDir, "05_policy.png"),
  });
  await page.getByLabel("Local Role").selectOption("APPROVER");
  await expect(page.getByTestId("approve-action")).toBeVisible();
  await page.getByTestId("approval-panel").screenshot({
    path: resolve(contestDir, "06_approval_or_preauthorization.png"),
  });
  started = performance.now();
  await page.getByTestId("approve-action").click();
  await expect(page.getByTestId("global-state")).toContainText("CLOSED");
  timings.approval_resume = Number((performance.now() - started).toFixed(2));
  timings.full_demo = Number((performance.now() - fullStarted).toFixed(2));
  await page.getByTestId("execution-results").screenshot({
    path: resolve(contestDir, "07_execution.png"),
  });
  await page.getByTestId("verification-results").screenshot({
    path: resolve(contestDir, "08_verification.png"),
  });

  await page.getByRole("button", { name: "Audit & Trace" }).click();
  await page.getByTestId("audit-integrity").screenshot({
    path: resolve(contestDir, "09_audit.png"),
  });
  await page.getByTestId("reasoning-trace").screenshot({
    path: resolve(contestDir, "10_reasoning_trace.png"),
  });
  await expect(page.getByTestId("audit-integrity")).toContainText("VALID");
  expect(externalRequests).toEqual([]);

  writeFileSync(
    resolve(process.cwd(), "..", "artifacts", "contest_device_report.json"),
    `${JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        viewport: "1280x720",
        external_network: "BLOCKED",
        external_requests_attempted: externalRequests,
        result: "PASS",
        timings_ms: timings,
      },
      null,
      2,
    )}\n`,
  );
});

test("1440x900 autonomous demo exposes sandbox preauthorization and no approval", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const externalRequests = await blockExternalNetwork(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Reset" }).click();
  await page
    .getByLabel("Execution mode")
    .selectOption("COMPETITION_AUTONOMOUS");
  await expect(page.getByTestId("sandbox-only-banner")).toBeVisible();
  await page.getByTestId("start-replay").click();
  await expect(page.getByTestId("global-state")).toContainText("CLOSED");
  await page.getByRole("button", { name: "Response & Verification" }).click();
  await expect(page.getByTestId("preauthorization-panel")).toContainText(
    "Human Approval Count: 0",
  );
  await expect(page.getByTestId("verification-results")).toContainText(
    "6/6 PASS",
  );
  await expect(page.getByTestId("approve-action")).toHaveCount(0);
  expect(externalRequests).toEqual([]);
});
