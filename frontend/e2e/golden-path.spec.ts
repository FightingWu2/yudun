import { expect, test, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

interface RuntimeView {
  run_id: string;
  incident_id: string;
  started_at: string;
  ended_at: string;
  stage: string;
  run_mode: string;
  model_provider: string;
  node_timings_ms: Record<string, number[]>;
}

interface BundleView {
  incident: { status: string };
  signals: unknown[];
  evidence: Array<{ source_type: string }>;
  official_evidence: Array<{ source_type: string }>;
  tasks: unknown[];
  findings: unknown[];
  facts: Array<{ fact_type: string }>;
  actions: {
    executions: Array<{ operation_results: unknown[] }>;
    policies: Array<{ decision: string }>;
  };
  verification: Array<{
    assertions: Array<{
      assertion_type: string;
      passed: boolean;
      evidence_refs: string[];
    }>;
  }>;
  audit: { chain_valid: boolean; records: unknown[] };
  mock_state: Record<string, unknown>;
}

async function current<T>(
  page: Page,
  path: string,
  role = "ADMIN",
): Promise<T> {
  return page.evaluate(
    async ({ path: target, role: selectedRole }) => {
      const response = await fetch(`/api/v1${target}`, {
        headers: { "X-Demo-Role": selectedRole },
      });
      if (!response.ok) throw new Error(await response.text());
      return response.json() as Promise<T>;
    },
    { path, role },
  );
}

test("three guarded browser replays remain isolated and close safely", async ({
  page,
}) => {
  const reports: Array<Record<string, unknown>> = [];
  const incidentIds = new Set<string>();
  const runIds = new Set<string>();
  const artifacts = resolve(process.cwd(), "..", "artifacts");
  mkdirSync(artifacts, { recursive: true });

  await page.goto("/");
  await expect(page.getByTestId("replay-console")).toBeVisible();

  for (let run = 1; run <= 3; run += 1) {
    const wallStarted = new Date().toISOString();
    const begin = performance.now();

    await page.getByRole("button", { name: "Reset" }).click();
    await expect(page.getByTestId("global-state")).toContainText("IDLE");
    await page.getByTestId("start-replay").click();
    await expect(page.getByTestId("global-state")).toContainText(
      "WAITING_APPROVAL",
    );
    await expect(page.getByTestId("incident-overview")).toContainText(
      "Confirmed Facts",
    );

    const preApproval = await current<RuntimeView>(page, "/runtime/status");
    const preBundle = await current<BundleView>(
      page,
      `/incidents/${preApproval.incident_id}/bundle`,
    );
    expect(preBundle.signals.length).toBeGreaterThan(0);
    expect(preBundle.tasks.length).toBeGreaterThanOrEqual(3);
    expect(preBundle.findings.length).toBeGreaterThan(0);
    expect(preBundle.facts).toHaveLength(6);
    expect(preBundle.actions.policies.at(-1)?.decision).toBe(
      "ALLOW_WITH_APPROVAL",
    );
    expect(preBundle.actions.executions).toHaveLength(0);

    await page
      .getByRole("button", { name: "Evidence & Investigation" })
      .click();
    await expect(page.getByText("Finding → Fact")).toBeVisible();
    await expect(page.getByText("6/6")).toBeVisible();
    await expect(page.getByText("确定性证据时间线")).toBeVisible();

    await page.getByRole("button", { name: "Response & Verification" }).click();
    await expect(page.getByTestId("approval-panel")).toBeVisible();
    if (run === 3) {
      await page.screenshot({
        path: resolve(artifacts, "demo_response_before_approval.png"),
        fullPage: true,
      });
    }
    await page.getByLabel("Local Role").selectOption("APPROVER");
    await page.getByTestId("approve-action").click();
    await expect(page.getByTestId("global-state")).toContainText("CLOSED");
    await expect(page.getByTestId("execution-results")).toBeVisible();
    await expect(page.getByTestId("verification-results")).toContainText(
      "6/6 PASS",
    );

    await page.getByRole("button", { name: "Audit & Trace" }).click();
    await expect(page.getByTestId("audit-integrity")).toContainText("VALID");
    await expect(page.getByText("Evidence-driven object chain")).toBeVisible();
    if (run === 3) {
      await page.screenshot({
        path: resolve(artifacts, "demo_audit_closed.png"),
        fullPage: true,
      });
    }

    const runtime = await current<RuntimeView>(page, "/runtime/status");
    const bundle = await current<BundleView>(
      page,
      `/incidents/${runtime.incident_id}/bundle`,
    );
    expect(runtime.stage).toBe("CLOSED");
    expect(bundle.incident.status).toBe("CLOSED");
    expect(
      bundle.verification.at(-1)?.assertions.every((item) => item.passed),
    ).toBe(true);
    expect(bundle.audit.chain_valid).toBe(true);
    expect(bundle.actions.executions).toHaveLength(1);
    expect(bundle.actions.executions[0].operation_results).toHaveLength(3);
    expect(
      bundle.official_evidence.every((item) => item.source_type === "OFFICIAL"),
    ).toBe(true);
    expect(
      bundle.evidence.some((item) => item.source_type === "SYNTHETIC"),
    ).toBe(true);
    expect(incidentIds.has(runtime.incident_id)).toBe(false);
    incidentIds.add(runtime.incident_id);
    expect(runIds.has(runtime.run_id)).toBe(false);
    runIds.add(runtime.run_id);

    reports.push({
      run_number: run,
      run_id: runtime.run_id,
      incident_id: runtime.incident_id,
      start: runtime.started_at || wallStarted,
      end: runtime.ended_at || new Date().toISOString(),
      duration_ms: Number((performance.now() - begin).toFixed(2)),
      stage_durations_ms: runtime.node_timings_ms,
      objects: {
        signals: bundle.signals.length,
        tasks: bundle.tasks.length,
        findings: bundle.findings.length,
        facts: bundle.facts.length,
        execution_steps: bundle.actions.executions[0].operation_results.length,
        audit_records: bundle.audit.records.length,
      },
      verification: {
        passed: 6,
        total: 6,
        assertions: bundle.verification[0].assertions.map((item) => ({
          assertion_type: item.assertion_type,
          passed: item.passed,
          evidence_refs: item.evidence_refs,
        })),
      },
      mock_before_approval: preBundle.mock_state,
      mock_after_execution: bundle.mock_state,
      audit_status: "VALID",
      source_types: ["OFFICIAL", "SYNTHETIC", "MOCK", "SYSTEM"],
      model_provider: runtime.model_provider,
      run_mode: runtime.run_mode,
      test_result: "PASS",
    });

    await page.getByRole("button", { name: "Detection & Incident" }).click();
    await page.getByLabel("Local Role").selectOption("ADMIN");
  }

  writeFileSync(
    resolve(artifacts, "golden_path_product_report.json"),
    `${JSON.stringify({ generated_at: new Date().toISOString(), runs: reports }, null, 2)}\n`,
    "utf8",
  );
});
