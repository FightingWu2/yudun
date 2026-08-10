import { expect, test, type Page } from "@playwright/test";

async function post(
  page: Page,
  path: string,
  role: string,
  body?: Record<string, unknown>,
) {
  return page.request.post(`http://127.0.0.1:8000/api/v1${path}`, {
    headers: { "X-Demo-Role": role },
    data: body,
  });
}

async function startFailure(
  page: Page,
  flag: "model_failure" | "force_verification_failure",
) {
  const sources = await page.request.get(
    "http://127.0.0.1:8000/api/v1/replay/sources",
    {
      headers: { "X-Demo-Role": "ADMIN" },
    },
  );
  const payload = (await sources.json()) as {
    official: Array<{ capture_id: string }>;
    synthetic: Array<{ scenario_id: string }>;
  };
  await post(page, "/replay/reset", "ADMIN");
  return post(page, "/replay/start", "ADMIN", {
    official_capture_id: payload.official[0].capture_id,
    synthetic_scenario_id: payload.synthetic[0].scenario_id,
    [flag]: true,
  });
}

test("human rejection is visible and leaves sandbox unchanged", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Reset" }).click();
  await page.getByTestId("start-replay").click();
  await expect(page.getByTestId("global-state")).toContainText(
    "WAITING_APPROVAL",
  );
  await page.getByRole("button", { name: "Response & Verification" }).click();
  await page.getByLabel("Local Role").selectOption("APPROVER");
  const before = await page.getByTestId("mock-state-before").textContent();
  await page.getByTestId("reject-action").click();
  await expect(page.getByTestId("global-state")).toContainText("REJECTED");
  await expect(page.getByTestId("execution-results")).toHaveCount(0);
  expect(await page.getByTestId("mock-state-before").textContent()).toBe(
    before,
  );
});

test("verification failure is displayed as ROTATED and REPLAN, never CLOSED", async ({
  page,
}) => {
  await page.goto("/");
  expect((await startFailure(page, "force_verification_failure")).ok()).toBe(
    true,
  );
  await page.reload();
  await page.getByRole("button", { name: "Response & Verification" }).click();
  await page.getByLabel("Local Role").selectOption("APPROVER");
  await page.getByTestId("approve-action").click();
  await expect(page.getByTestId("global-state")).toContainText("ROTATED");
  await expect(page.getByTestId("verification-results")).toContainText(
    "Verification FAILED",
  );
  await expect(page.getByTestId("verification-results")).toContainText(
    "REPLAN",
  );
  await expect(page.getByTestId("global-state")).not.toContainText("CLOSED");
});

test("model failure is truthful, has no action execution, and sources stay distinct", async ({
  page,
}) => {
  await page.goto("/");
  expect((await startFailure(page, "model_failure")).ok()).toBe(true);
  await page.reload();
  await expect(page.getByTestId("global-state")).toContainText(
    "MANUAL_REQUIRED",
  );
  await expect(page.getByTestId("model-provider")).toHaveText(
    "DETERMINISTIC_TEST",
  );
  await expect(page.getByTestId("replay-console")).toContainText("OFFICIAL");
  await expect(page.getByTestId("replay-console")).toContainText("SYNTHETIC");
  await expect(page.getByTestId("execution-results")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("sk-test-secret-value");
});
