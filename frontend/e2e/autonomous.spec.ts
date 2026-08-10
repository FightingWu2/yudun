import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

interface Sources {
  official: Array<{ capture_id: string }>;
  synthetic: Array<{ scenario_id: string }>;
}

interface Status {
  run_id: string;
  incident_id: string;
  stage: string;
  run_mode: string;
  node_timings_ms: Record<string, number[]>;
}

interface Bundle {
  incident: { status: string };
  actions: {
    approvals: unknown[];
    preauthorizations: Array<{
      preauthorization_id: string;
      decision: string;
      guard_checks: Array<{ check_id: string; passed: boolean }>;
    }>;
    executions: Array<{ operation_results: unknown[] }>;
  };
  verification: Array<{
    next_step: string;
    assertions: Array<{ assertion_type: string; passed: boolean }>;
  }>;
  audit: { chain_valid: boolean };
  reasoning_trace: Array<{ stage: string }>;
}

async function json<T>(
  response: Awaited<ReturnType<APIRequestContext["get"]>>,
) {
  expect(response.ok(), await response.text()).toBe(true);
  return (await response.json()) as T;
}

async function runAutonomous(
  page: Page,
  forceVerificationFailure = false,
): Promise<{ status: Status; bundle: Bundle }> {
  const sources = await json<Sources>(
    await page.request.get("http://127.0.0.1:8000/api/v1/replay/sources", {
      headers: { "X-Demo-Role": "ADMIN" },
    }),
  );
  await page.request.post("http://127.0.0.1:8000/api/v1/replay/reset", {
    headers: { "X-Demo-Role": "ADMIN" },
  });
  const status = await json<Status>(
    await page.request.post("http://127.0.0.1:8000/api/v1/replay/start", {
      headers: { "X-Demo-Role": "ADMIN" },
      data: {
        official_capture_id: sources.official[0].capture_id,
        synthetic_scenario_id: sources.synthetic[0].scenario_id,
        run_mode: "COMPETITION_AUTONOMOUS",
        force_verification_failure: forceVerificationFailure,
      },
    }),
  );
  const bundle = await json<Bundle>(
    await page.request.get(
      `http://127.0.0.1:8000/api/v1/incidents/${status.incident_id}/bundle`,
      { headers: { "X-Demo-Role": "ADMIN" } },
    ),
  );
  return { status, bundle };
}

test("three autonomous sandbox runs close with policy preauthorization and zero approvals", async ({
  page,
}) => {
  const report: Array<Record<string, unknown>> = [];
  const runIds = new Set<string>();
  const incidentIds = new Set<string>();

  for (let index = 1; index <= 3; index += 1) {
    const started = performance.now();
    const { status, bundle } = await runAutonomous(page);
    expect(status.stage).toBe("CLOSED");
    expect(status.run_mode).toBe("COMPETITION_AUTONOMOUS");
    expect(bundle.incident.status).toBe("CLOSED");
    expect(bundle.actions.approvals).toHaveLength(0);
    expect(bundle.actions.preauthorizations).toHaveLength(1);
    expect(bundle.actions.preauthorizations[0].decision).toBe(
      "AUTO_PREAUTHORIZED",
    );
    expect(
      bundle.actions.preauthorizations[0].guard_checks.every(
        (guard) => guard.passed,
      ),
    ).toBe(true);
    expect(bundle.actions.executions).toHaveLength(1);
    expect(bundle.actions.executions[0].operation_results).toHaveLength(3);
    expect(
      bundle.verification[0].assertions.every((assertion) => assertion.passed),
    ).toBe(true);
    expect(bundle.audit.chain_valid).toBe(true);
    expect(runIds.has(status.run_id)).toBe(false);
    expect(incidentIds.has(status.incident_id)).toBe(false);
    runIds.add(status.run_id);
    incidentIds.add(status.incident_id);
    report.push({
      run: index,
      run_id: status.run_id,
      incident_id: status.incident_id,
      approvals: 0,
      preauthorization: bundle.actions.preauthorizations[0],
      execution_steps: 3,
      verification: "6/6 PASS",
      audit_chain: "VALID",
      duration_ms: Number((performance.now() - started).toFixed(2)),
      node_timings_ms: status.node_timings_ms,
    });
  }

  const artifacts = resolve(process.cwd(), "..", "artifacts");
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(
    resolve(artifacts, "autonomous_sandbox_report.json"),
    `${JSON.stringify({ generated_at: new Date().toISOString(), runs: report }, null, 2)}\n`,
  );
});

test("autonomous verification failure replans and never closes", async ({
  page,
}) => {
  const { status, bundle } = await runAutonomous(page, true);
  expect(status.stage).toBe("VERIFICATION_FAILED_REPLAN");
  expect(bundle.incident.status).toBe("ROTATED");
  expect(bundle.actions.approvals).toHaveLength(0);
  expect(bundle.actions.preauthorizations).toHaveLength(1);
  expect(bundle.verification[0].next_step).toBe("REPLAN");
  expect(bundle.reasoning_trace.some((node) => node.stage === "REPLAN")).toBe(
    true,
  );
});

test("autonomous mode is explicit and visibly sandbox-only in the UI", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByTestId("global-state")).toContainText("IDLE");
  await page
    .getByLabel("Execution mode")
    .selectOption("COMPETITION_AUTONOMOUS");
  await expect(page.getByTestId("sandbox-only-banner")).toContainText(
    "SANDBOX ONLY",
  );
  await page.getByTestId("start-replay").click();
  await expect(page.getByTestId("global-state")).toContainText("CLOSED");
  await page.getByRole("button", { name: "Response & Verification" }).click();
  await expect(page.getByTestId("preauthorization-panel")).toContainText(
    "AUTO_PREAUTHORIZED",
  );
  await expect(page.getByTestId("preauthorization-panel")).toContainText(
    "Human Approval Count: 0",
  );
  await expect(page.getByTestId("approve-action")).toHaveCount(0);
});
