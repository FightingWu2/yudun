# Security Knowledge RAG 实现文档

> 实现日期：2026-08-10　|　文档编号：15　|　关联：`docs/6`、`docs/10`、`docs/13`
> 状态：**IMPLEMENTED**（离线确定性；无公网依赖；可重复验收）

本文档说明御盾智核「Security Knowledge RAG」的实现设计、数据流、检索算法、Agent 集成、REST API、前端展示、验收方法与边界。它遵循 `docs/6 §3` 对 RAG 的定位：

> **RAG 是「安全知识搜索器」**，检索规则说明、处置手册和历史事件。检索结果只能作为**参考材料**，不能直接成为攻击事实或授权依据。

---

## 1. 目标与非目标

### 1.1 目标

1. 建立一份可离线使用的安全知识库：内置条目 + 可从 `data/knowledge/` 导入的 Markdown / JSON 文档。
2. 提供确定性混合检索：SQLite FTS5 关键词召回 + TF-IDF 重排。
3. 把知识检索接入 **Investigation Agent**：作为受控工具 `search_knowledge`，引用结果记录在 Finding 的 `knowledge_refs` 上，并全程审计。
4. 提供独立的 RAG 查询 REST API 与前端「Security Knowledge」工作区。
5. 用 pytest、`make knowledge-rag` 报告与 Playwright E2E 完成可重复验收。

### 1.2 非目标（明确不做）

- ❌ 知识条目**不会**成为 `ConfirmedFact`、授权依据或策略输入。
- ❌ 不引入外部向量库（无 milvus/faiss/chromadb 依赖）；比赛现场可能断网，离线确定性优先。
- ❌ 不做模型端到端 Embedding（不调用 DeepSeek/Qwen embedding 接口）；如后续接入真实模型，属于可选增强，不改变确定性主链。
- ❌ 不改变既有 Golden Path 的 Policy、审批、执行、验证语义。

---

## 2. 总体架构

```
┌────────────────────────────────────────────────────────────────────────┐
│ data/knowledge/*.md|json ──► loader.py ──┐                             │
│ builtin.py（21 条内置）───────────────► │                             │
│                                          ▼                             │
│                            KnowledgeService（engine）                  │
│                              · 文档清单（内存）                          │
│                              · TF-IDF 倒排索引（ranking.py）             │
│                              · FTS5 虚表 knowledge_fts（business.db）   │
└───────┬────────────────────────────────────────────────────────────────┘
        │ search() / list_documents() / reload()
        ├───────────────────────────────────────────────┐
        ▼                                                ▼
┌──────────────────────┐                     ┌───────────────────────────┐
│ REST API             │                     │ AgentRuntime              │
│ GET /knowledge/...   │                     │ run_investigation:        │
│（独立知识面板）       │                     │  · authorize(search_knowledge)
│                      │                     │  · search → knowledge_context
│                      │                     │  · finding.knowledge_refs  │
└──────────────────────┘                     └───────────┬───────────────┘
        ▲                                                 │
        │ frontend/src/App.tsx                            ▼
        │ · Security Knowledge 工作区（05）         GoldenPathWorkflow
        │ · Investigation 工作区展示 Finding 知识引用      （DemoRuntime 注入）
        └─────────────────────────────────────────────────┘
```

### 2.1 新增模块

| 文件 | 职责 | 依赖 |
| --- | --- | --- |
| `backend/app/knowledge/tokenize.py` | 分词：英文小写词 + 中文 bigram | 纯标准库 |
| `backend/app/knowledge/ranking.py` | FTS MATCH 表达式、TF-IDF 索引与排序、snippet | 纯标准库 |
| `backend/app/knowledge/builtin.py` | 21 条内置安全知识（ATT&CK/云凭据/CI 供应链/检测/处置/云滥用） | 纯数据 |
| `backend/app/knowledge/loader.py` | 加载内置 + `data/knowledge/` 的 md/json | 纯标准库 |
| `backend/app/knowledge/schemas.py` | `KnowledgeDocument` / `KnowledgeHit` / `KnowledgeSearchResult` / `KnowledgeIndexStatus` / `KnowledgeReloadResult` | Pydantic |
| `backend/app/knowledge/service.py` | `KnowledgeService`：索引、FTS5 同步、混合检索、reload、status | SQLAlchemy |

> 检索核心（`tokenize` / `ranking` / `loader` / `builtin`）刻意保持**零 ORM / 零 Pydantic 依赖**，使算法可在最小环境单独单测。

---

## 3. 检索算法：FTS5 召回 + TF-IDF 重排

### 3.1 两阶段流程

1. **召回（candidate recall）**：`fts_match_expression(query)` 把用户查询转成**全引号包裹**的 FTS5 `MATCH` 表达式（每个词 `"term"` 用 `OR` 连接），对 `knowledge_fts` 虚表执行匹配，得到候选 `doc_id` 集合。
   - 安全：所有 term 都被双引号包裹，用户输入无法注入 FTS5 查询操作符。
   - 降级：FTS5 不可用或表达式为空时，候选集退化为全量文档（TF-IDF 全量排序仍可用）。
2. **重排（ranking）**：`score_tfidf` 对候选集计算加权 TF-IDF 相似度：
   - 词频子线性加权 `(1 + log(tf))`，长度归一化 `1 / sqrt(doc_len)`，`idf = log(1 + n / df)`；
   - 得分归一化到 `[0,1]`；命中词列表 `matched_terms` 与首个命中的 `snippet` 一并返回。

### 3.2 分词

- 英文：小写、按 `[a-z0-9_\-\.]+` 切词，过滤小停用词表（保留 `key`/`secret` 等安全相关词）。
- 中文：`NFKC` 规范化后按**连续 CJK 段做双字 bigram**（如「供应链」→ `供应`+`应链`），使 unicode61 tokenizer 的 FTS5 与 TF-IDF 处于同一 term 空间。

### 3.3 检索模式标识

`mode` 字段：`FTS5+TFIDF`（标准）/ `TFIDF_ONLY`（FTS5 不可用的 SQLite 构建）。前端与报告会如实展示，不伪装。

---

## 4. 知识库：内置 + 可导入

### 4.1 内置条目（21 条）

| 类别 | 条目数 | 示例 |
| --- | --- | --- |
| `ATTACK_TECHNIQUE` | 6 | T1078 有效账号、T1110 暴力破解、T1195 供应链投毒、T1190 公开应用利用、T1496 资源劫持、T1530 未保护敏感数据 |
| `CI_SUPPLY_CHAIN` | 3 | 第三方 Action 篡改识别、CI 环境变量凭据风险、CI 凭据绑定更新 |
| `CLOUD_CREDENTIAL` | 4 | 云访问密钥安全使用、凭据泄露路径、凭据轮换最佳实践、IAM 最小权限 |
| `DETECTION_RULE` | 3 | 敏感数据读取检测、高成本资源创建检测、云 API 调用异常检测 |
| `RESPONSE_PLAYBOOK` | 3 | API 凭据泄露应急响应、冻结旧密钥、恢复验证断言 |
| `CLOUD_ABUSE` | 2 | 云 API 滥用典型模式、证据链与审计完整性 |

内容约束：条目**不得包含明文密钥模式**（如 `access key: <value>`），与项目 `StrictSchema` 的防明文密钥校验一致。

### 4.2 导入文档（可扩展）

- 目录：`data/knowledge/*.md` 或 `*.json`。
- Markdown：可选 `---` frontmatter（`id/title/category/type/tags/source/version`）+ 正文。
- JSON：对象或对象数组，字段对应 `KnowledgeDocument`。
- 加载语义：`id` 冲突时**导入文档覆盖内置**；每次 `reload()` 或 DemoRuntime 重建索引时重新扫描。
- 随仓样例：`data/knowledge/ci-supply-chain-playbook.md`（用于演示「内置 + 导入」双来源与计数断言）。

---

## 5. Agent 工具集成（受控 + 审计）

### 5.1 新工具

`backend/app/tools/registry.py` 新增受控工具：

| 字段 | 值 |
| --- | --- |
| `tool_id` | `search_knowledge` |
| 允许 Agent | `MAIN_AGENT`、`INVESTIGATION_AGENT`、`AUDIT_AGENT` |
| 权限 | `knowledge:read` |
| 风险 | `READ_ONLY` |
| 审计 | `DENIAL_AND_SUCCESS` |

### 5.2 Investigation Agent 流程

`AgentRuntime.run_investigation`（`backend/app/agents/runtime.py`）：

1. 校验任务必须声明 `get_evidence`；若任务 `allowed_tools` 含 `search_knowledge`，则执行 `_authorize(...)`（经 ToolRegistry 判定，拒绝即抛 `PermissionDeniedError` 并写 `TOOL_ACCESS_DENIED`）。
2. 确定性构造查询：`task_goal + 前两条证据 summary`。
3. `KnowledgeService.search(query, limit=3)` 取前 3 个命中，注入模型 payload 的 `knowledge_context`（doc_id / title / snippet / score）——**仅供模型作参考上下文**。
4. 检索到的 `doc_id` 写入该任务的 `AgentFinding.knowledge_refs` 与 `AgentResult.knowledge_refs`（默认空列表，向后兼容）。

> 关键：`knowledge_refs` 由**确定性代码**写入，不依赖模型自由发挥；模型输出仍须通过 Pydantic 校验，知识引用不参与事实晋升。

### 5.3 Main Agent 规划授权

`main-plan-v1` fixture 的 `requested_tools` 已包含 `search_knowledge`；`create_planned_task` 授权子任务时 `granted_permissions` 已加入 `knowledge:read`，保证子 Agent 可合法声明并调用该工具。

---

## 6. REST API

Base `/api/v1`，认证头 `X-Demo-Role`。

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/knowledge/status` | 全部 | 索引模式、文档数、导入数、类别分布、FTS 可用性 |
| GET | `/knowledge/documents` | 全部 | 知识库目录（`{ documents, total }`） |
| GET | `/knowledge/search?q=&limit=` | 全部 | 混合检索，返回排序命中（`q`≤200，`limit` 1–20） |
| POST | `/knowledge/reload` | ADMIN | 重新扫描 `data/knowledge/` 重建索引 |

实现位置：`backend/app/api/routes.py` → `DemoRuntime.knowledge_*`（`backend/app/application/demo.py`）。`DemoRuntime` 持有 `KnowledgeService`，在构造与 `reset()` 后重建（business.db 重建导致 FTS5 虚表重建）。

---

## 7. 前端

### 7.1 新工作区「Security Knowledge」（05）

`frontend/src/App.tsx` 新增 `KnowledgeWorkspace`：

- 顶部展示索引状态（`mode` / 文档数 / 导入数）。
- 检索框：输入关键词回车或点「检索」，展示排序命中（doc_id、score、snippet、命中词）。
- 知识库目录：可展开的条目列表，展示 title、content、source/version、tags。
- 数据来自 `/knowledge/status`、`/knowledge/documents`、`/knowledge/search`。

### 7.2 Investigation 工作区

Agent Finding 卡片在 `knowledge_refs` 非空时展示一行 `Knowledge · kno-xxx · kno-yyy`，直观呈现 RAG 引用。

### 7.3 类型

`frontend/src/api.ts` 新增 `KnowledgeDocument` / `KnowledgeHit` / `KnowledgeSearchResult` / `KnowledgeIndexStatus` / `KnowledgeCategory`，`Finding` 增加可选 `knowledge_refs`。

---

## 8. 数据字典（新增对象）

| 字段 | 说明 |
| --- | --- |
| `KnowledgeDocument.doc_id` | 可读 slug，`kno-` 前缀，跨重放稳定（类似 rule_id/scenario_id） |
| `KnowledgeDocument.category` | 见第 4.1 节枚举 |
| `KnowledgeDocument.doc_type` | `reference / playbook / rule / note` |
| `KnowledgeHit.score` | 归一化 TF-IDF 相似度 `[0,1]` |
| `KnowledgeHit.matched_terms` | 命中的查询 term |
| `KnowledgeHit.snippet` | 首个命中词附近的 160 字窗口 |
| `KnowledgeSearchResult.mode` | `FTS5+TFIDF` / `TFIDF_ONLY` |
| `AgentFinding.knowledge_refs` | 该 Finding 引用的知识 doc_id 列表（仅参考材料） |

---

## 9. 验收

### 9.1 单元 / 集成测试

- `backend/tests/unit/test_knowledge.py`：分词、FTS 表达式安全、TF-IDF 排序、内置/导入加载、schema 校验、Service 检索/降级/reload/序列化。
- `backend/tests/integration/test_knowledge_agent.py`：Golden Path 全链路上 Investigation Finding 生成 `knowledge_refs`，且 `search_knowledge` 以受控方式被审计；无 KnowledgeService 时优雅降级为空引用。

### 9.2 确定性报告

```bash
make knowledge-rag
# → artifacts/knowledge_rag_report.json
```

报告断言 6 组固定查询的 top 命中与期望 doc_id 一致（全部 PASS 才返回 0），并输出索引统计与逐查询耗时。

### 9.3 浏览器 E2E

`frontend/e2e/knowledge.spec.ts`（已纳入 `make demo-e2e`）：

1. 知识工作区：目录渲染、检索「凭据泄露 处置」命中 `kno-playbook-leak-response`。
2. REST：`/knowledge/search?q=resource hijacking GPU` 返回 `kno-attack-t1496` 且 score>0。
3. 全链路：Reset → Start → WAITING_APPROVAL，Investigation Finding 携带 `kno-` 引用，前端 Finding 卡片显示 `Knowledge ·`。

### 9.4 权威回归

在宿主机执行 `make check && make demo-e2e && make knowledge-rag && make contest-preflight` 复核。VM 内已复验检索算法与全部 6 组查询预期（Python 标准库 + 原生 sqlite3 FTS5）。

---

## 10. 边界与已知限制

1. **知识≠事实**：RAG 命中永远只是参考材料；`ConfirmedFact` 必须由确定性 Fact Validator 从证据晋升。
2. **离线优先**：检索不依赖公网；真实模型 Embedding 未接入，属可选增强。
3. **中文检索粒度**：bigram 分词对专业术语的语义召回有限；FTS5 与 TF-IDF 均为词面匹配，不涉及向量语义。
4. **索引生命周期**：`reset()` 重建 business.db，知识索引随之重建；导入文档必须在 `data/knowledge/` 中持久化，`reload` 或下次启动生效。
5. **规模**：知识库设计面向百级条目；超大知识库可平滑替换为向量方案，`KnowledgeService.search` 接口保持稳定。

---

## 11. 与既有文档的状态衔接

- `docs/10-赛题三重任务证明矩阵.md`：Security Knowledge RAG 行由 `P1 PENDING` 更新为 `IMPLEMENTED`（见下）。
- `docs/6-赛题三重任务适配说明.md`：§3 的 RAG 定位从「P1【待设计】」更新为「已实现」。
- `README.md`：未完成能力清单移除 RAG。
- `docs/12` / `docs/14`：为冻结交接快照，保持原状。
