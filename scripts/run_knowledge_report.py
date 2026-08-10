"""Run a deterministic Security Knowledge RAG smoke and write an auditable report.

The script builds the knowledge index in a temporary SQLite database (never
touches the demo runtime), runs a fixed set of retrieval queries, and asserts
that each query surfaces the expected reference document at the top. Results
are written to ``artifacts/knowledge_rag_report.json``.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from app.db.base import Base
from app.db.session import create_business_engine
from app.knowledge.service import KnowledgeService

# Deterministic query -> expected top reference (doc_id prefix match).
EXPECTATIONS: dict[str, str] = {
    "凭据泄露 处置 手册": "kno-playbook-leak-response",
    "CI Action 篡改 供应链": "kno-ci-action-mutation",
    "资源劫持 GPU 高成本": "kno-attack-t1496",
    "旧密钥 冻结 轮换": "kno-playbook-freeze-old-key",
    "恢复 验证 断言": "kno-playbook-verify-recovery",
    "access key 泄露 云凭据": "kno-cloud-access-key",
}


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    knowledge_dir = root / "data" / "knowledge"
    artifact_path = root / "artifacts" / "knowledge_rag_report.json"
    started = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="yudun_knowledge_") as temp:
        engine = create_business_engine(f"sqlite:///{Path(temp) / 'knowledge.db'}")
        Base.metadata.create_all(engine)
        service = KnowledgeService(engine, knowledge_dir)

        status = service.status()
        queries: list[dict[str, object]] = []
        passed = True
        for query, expected in EXPECTATIONS.items():
            result = service.search(query, limit=5)
            top = result.hits[0].doc_id if result.hits else None
            ok = top == expected
            passed = passed and ok
            queries.append(
                {
                    "query": query,
                    "expected_doc_id": expected,
                    "top_doc_id": top,
                    "score": result.hits[0].score if result.hits else None,
                    "total": result.total,
                    "mode": result.mode,
                    "elapsed_ms": result.elapsed_ms,
                    "pass": ok,
                }
            )

    report = {
        "report": "security_knowledge_rag",
        "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "status": "PASS" if passed else "FAIL",
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "index": {
            "mode": status.mode,
            "fts_available": status.fts_available,
            "document_count": status.document_count,
            "imported_count": status.imported_count,
            "categories": status.categories,
            "knowledge_dir": str(knowledge_dir),
        },
        "queries": queries,
        "conclusion": (
            "Security Knowledge RAG returns deterministic reference material; "
            "hits are citations only and never become facts or authorization."
        ),
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
