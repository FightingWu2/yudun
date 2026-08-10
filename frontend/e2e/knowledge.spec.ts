import { expect, test, type Page } from "@playwright/test";

interface KnowledgeHit {
  doc_id: string;
  title: string;
  score: number;
  snippet: string;
}

interface KnowledgeSearchResult {
  query: string;
  total: number;
  mode: string;
  hits: KnowledgeHit[];
}

interface RuntimeView {
  incident_id: string | null;
  stage: string;
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

test("security knowledge workspace searches the built-in knowledge base", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Security Knowledge" }).click();
  await expect(page.getByText("安全知识检索")).toBeVisible();
  await expect(page.getByTestId("knowledge-documents")).toBeVisible();
  await expect(page.getByTestId("knowledge-documents")).toContainText(
    "ATT&CK T1078",
  );

  await page
    .getByPlaceholder("检索规则说明、处置手册、ATT&CK 技战术…")
    .fill("凭据泄露 处置");
  await page.getByRole("button", { name: "检索" }).click();

  await expect(page.getByTestId("knowledge-results")).toBeVisible();
  await expect(page.getByTestId("knowledge-results")).toContainText(
    "kno-playbook-leak-response",
  );
});

test("knowledge REST search returns deterministic ranked hits", async ({
  page,
}) => {
  await page.goto("/");
  const result = await current<KnowledgeSearchResult>(
    page,
    "/knowledge/search?q=resource%20hijacking%20GPU&limit=3",
  );
  expect(result.total).toBeGreaterThan(0);
  expect(result.hits[0].doc_id).toBe("kno-attack-t1496");
  expect(result.hits[0].score).toBeGreaterThan(0);
});

test("investigation finding cites knowledge references during replay", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByTestId("replay-console")).toBeVisible();

  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByTestId("global-state")).toContainText("IDLE");
  await page.getByTestId("start-replay").click();
  await expect(page.getByTestId("global-state")).toContainText(
    "WAITING_APPROVAL",
  );

  const runtime = await current<RuntimeView>(page, "/runtime/status");
  expect(runtime.incident_id).toBeTruthy();

  const bundle = await current<{
    findings: Array<{ finding_type: string; knowledge_refs: string[] }>;
    results: Array<{ knowledge_refs: string[] }>;
  }>(page, `/incidents/${runtime.incident_id}/bundle`);
  const investigation = bundle.findings.find(
    (item) => item.finding_type === "INVESTIGATION_FINDING",
  );
  expect(investigation?.knowledge_refs?.length).toBeGreaterThan(0);
  expect(investigation?.knowledge_refs?.[0]).toMatch(/^kno-/);

  // The UI must render the citation on the finding card.
  await page
    .getByRole("button", { name: "Evidence & Investigation" })
    .click();
  await expect(page.getByTestId("agent-tasks")).toContainText("Knowledge ·");
});
