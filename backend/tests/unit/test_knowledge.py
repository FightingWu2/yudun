"""Unit tests for the Security Knowledge RAG feature.

Covers the dependency-free retrieval math (tokenizer / ranking / loader) and
the ORM-backed ``KnowledgeService`` (FTS5 + TF-IDF hybrid search, reload,
status). Integration of knowledge citations into ``AgentRuntime`` is covered
in ``backend/tests/integration/test_knowledge_agent.py``.
"""

from pathlib import Path

import pytest
from app.db.base import Base
from app.db.session import create_business_engine
from app.knowledge.builtin import BUILTIN_DOCUMENTS
from app.knowledge.loader import load_all, load_builtin, load_imported
from app.knowledge.ranking import (
    SearchableDocument,
    build_tfidf_index,
    fts_match_expression,
    make_snippet,
    score_tfidf,
)
from app.knowledge.schemas import KnowledgeDocument
from app.knowledge.service import KnowledgeService
from app.knowledge.tokenize import tokenize


def _make_service(tmp_path: Path) -> KnowledgeService:
    engine = create_business_engine(f"sqlite:///{tmp_path / 'knowledge.db'}")
    Base.metadata.create_all(engine)
    return KnowledgeService(engine, tmp_path / "knowledge")


# --------------------------------------------------------------- tokenizer


def test_tokenize_splits_cjk_into_bigrams() -> None:
    terms = tokenize("供应链投毒与凭据泄露检测")
    assert "供应链" not in terms  # bigrams, not whole words
    assert "供应" in terms and "链投" in terms
    assert "凭据" in terms and "泄露" in terms


def test_tokenize_lowercases_latin_and_drops_stopwords() -> None:
    terms = tokenize("The API Credential was Exposed")
    assert "api" in terms and "credential" in terms and "exposed" in terms
    assert "the" not in terms and "was" not in terms


# ------------------------------------------------------------------ loader


def test_builtin_knowledge_loads_with_kno_prefix() -> None:
    documents = load_builtin()
    assert len(documents) == len(BUILTIN_DOCUMENTS) == 21
    assert all(str(item["doc_id"]).startswith("kno-") for item in documents)
    categories = {item["category"] for item in documents}
    assert "ATTACK_TECHNIQUE" in categories and "RESPONSE_PLAYBOOK" in categories


def test_imported_markdown_document_loads(tmp_path: Path) -> None:
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    (knowledge_dir / "extra-playbook.md").write_text(
        "---\n"
        "id: kno-extra-playbook\n"
        "title: 额外处置手册\n"
        "category: RESPONSE_PLAYBOOK\n"
        "type: playbook\n"
        "tags: 处置, 手册\n"
        "---\n"
        "正文内容用于检索测试。\n",
        encoding="utf-8",
    )
    imported = load_imported(knowledge_dir)
    assert len(imported) == 1
    assert imported[0]["doc_id"] == "kno-extra-playbook"
    assert "正文内容" in imported[0]["content"]


def test_load_all_includes_builtin_and_imported(tmp_path: Path) -> None:
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    (knowledge_dir / "extra.md").write_text(
        "---\nid: kno-extra\ncategory: REFERENCE\ntype: note\n---\n内容。\n",
        encoding="utf-8",
    )
    documents = load_all(knowledge_dir)
    assert len(documents) == len(BUILTIN_DOCUMENTS) + 1
    assert any(item["doc_id"] == "kno-extra" for item in documents)


# ---------------------------------------------------------------- schemas


def test_knowledge_document_schema_rejects_bad_doc_id() -> None:
    with pytest.raises(Exception):
        KnowledgeDocument.model_validate(
            {
                "doc_id": "doc-invalid-prefix",
                "category": "REFERENCE",
                "doc_type": "note",
                "title": "t",
                "content": "c",
            }
        )


def test_knowledge_document_schema_accepts_builtin_entries() -> None:
    for item in BUILTIN_DOCUMENTS:
        document = KnowledgeDocument.model_validate(item)
        assert document.doc_id.startswith("kno-")


# --------------------------------------------------------------- ranking


def test_fts_match_expression_is_quoted_and_safe() -> None:
    expression = fts_match_expression('CI "action" AND mutation OR ("DROP TABLE')
    assert '"DROP TABLE"' not in expression
    assert expression.startswith('"')  # first term is quoted


def test_tfidf_ranks_relevant_document_first() -> None:
    documents = [
        SearchableDocument("kno-a", "API 凭据泄露", "密钥泄露导致云 API 滥用", ("凭据",)),
        SearchableDocument("kno-b", "Webshell 检测", "检测后门与命令执行", ("webshell",)),
    ]
    index = build_tfidf_index(documents)
    hits = score_tfidf("凭据 泄露 云 API", index)
    assert hits[0].doc_id == "kno-a"


def test_make_snippet_windows_around_first_match() -> None:
    snippet = make_snippet("前面内容凭据泄露在后面", ["凭据", "泄露"])
    assert "凭据" in snippet
    assert snippet.startswith("…") or len(snippet) < 160


# ---------------------------------------------------------------- service


def test_service_indexes_documents_and_reports_status(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    status = service.status()
    assert status.document_count == len(BUILTIN_DOCUMENTS)
    assert status.imported_count == 0
    assert status.mode in {"FTS5+TFIDF", "TFIDF_ONLY"}


def test_service_hybrid_search_returns_ranked_hits(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    result = service.search("凭据泄露 处置 手册", limit=3)
    assert result.total > 0
    assert result.mode == service.status().mode
    first = result.hits[0]
    assert first.score > 0
    assert first.snippet
    assert first.doc_id.startswith("kno-")
    # The leak-response playbook should outrank unrelated entries.
    assert any(hit.doc_id == "kno-playbook-leak-response" for hit in result.hits)


def test_service_hybrid_search_unknown_term_is_empty(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    result = service.search("zzzqwx nonexistentterm", limit=3)
    assert result.total == 0
    assert result.hits == []


def test_service_reload_picks_up_new_import(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    before = service.status().document_count
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir(exist_ok=True)
    (knowledge_dir / "late-arrival.md").write_text(
        "---\n"
        "id: kno-late-arrival\n"
        "title: 后期导入条目\n"
        "category: REFERENCE\n"
        "type: note\n"
        "---\n"
        "后期导入的知识内容。\n",
        encoding="utf-8",
    )
    reloaded = service.reload()
    assert reloaded.document_count == before + 1
    assert service.get("kno-late-arrival") is not None


def test_service_documents_are_json_serializable(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    documents = service.list_documents()
    assert len(documents) == service.status().document_count
    for item in documents:
        assert item["doc_id"].startswith("kno-")
        assert "content" in item
