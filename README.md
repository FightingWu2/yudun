# 御盾智核

御盾智核 P0 Golden Path 的模块化单体工程。当前已完成 DEV-001～DEV-030：可信基础、官方 PCAP 与证据化检测、Synthetic 主链、受限多智能体协作、确定性 Policy、人工审批、Mock 动态处置、恢复验证、LangGraph 后端闭环，以及可重复验收的 REST/SSE 与浏览器演示台。

## 环境

- Python 3.11（由 `uv` 管理）
- Node.js 20+ / npm

## 安装

```bash
make install
make install-frontend
```

## 启动

同时启动基础前后端：

```bash
make dev
```

也可分别启动：

```bash
make dev-backend
make dev-frontend
```

后端健康检查：<http://127.0.0.1:8000/health>；前端：<http://127.0.0.1:5173>。

浏览器首次进入使用 `ADMIN` 选择两个明确标识的数据源并启动重放；进入处置页后切换 `APPROVER` 才能批准或拒绝。重置当前演示：

```bash
make demo-reset
```

## 检查

```bash
make check
```

数据库迁移：

```bash
make migrate
make downgrade
```

运行可重复的后端 Golden Path（使用 Deterministic Test Model，不访问公网）：

```bash
make golden-path
```

结果写入 `artifacts/golden_path_backend_report.json`。

运行三轮真实浏览器 Golden Path 与浏览器安全失败验收：

```bash
make demo-e2e
```

结果写入 `artifacts/golden_path_product_report.json`，演示截图也位于 `artifacts/`。

真实模型现实性检查：

```bash
make live-model-smoke
```

可选真实模型配置见 `.env.example`。未配置时系统和界面明确显示 `DETERMINISTIC_TEST`。深信服平台接入、真实云生产处置仍未实现（Sandbox 自治能力已实现）。

Security Knowledge RAG 已实现（离线确定性 FTS5 + TF-IDF 混合检索，内置知识库 + `data/knowledge/` 可导入文档，Agent 受控工具 `search_knowledge` 与独立知识面板），见 `docs/15-Security Knowledge RAG 实现文档.md`。生成确定性验收报告：

```bash
make knowledge-rag
```

结果写入 `artifacts/knowledge_rag_report.json`。
