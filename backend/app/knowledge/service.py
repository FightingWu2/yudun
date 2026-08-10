"""KnowledgeService: owns the Security Knowledge index and hybrid retrieval.

The index is rebuilt on every ``reset`` (business.db is recreated), so the
service keeps documents in memory and mirrors them into a SQLite FTS5 virtual
table inside business.db for candidate recall. TF-IDF ranking (from
``app.knowledge.ranking``) re-ranks the candidates. When FTS5 is unavailable
the service transparently falls back to TF-IDF-only ranking.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from app.knowledge.builtin import BUILTIN_DOCUMENT_IDS
from app.knowledge.loader import load_all
from app.knowledge.ranking import (
    RankedHit,
    SearchableDocument,
    TfidfIndex,
    build_tfidf_index,
    fts_match_expression,
    make_snippet,
    score_tfidf,
)
from app.knowledge.schemas import (
    KnowledgeDocument,
    KnowledgeHit,
    KnowledgeIndexStatus,
    KnowledgeReloadResult,
    KnowledgeSearchResult,
)


class KnowledgeService:
    """Deterministic security-knowledge search service."""

    def __init__(self, engine: Engine, knowledge_dir: Path) -> None:
        self._engine = engine
        self._knowledge_dir = knowledge_dir
        self._documents: dict[str, KnowledgeDocument] = {}
        self._imported_count = 0
        self._searchable: list[SearchableDocument] = []
        self._tfidf: TfidfIndex | None = None
        self._fts_available: bool | None = None
        self._mode = "PENDING"
        self.ensure_indexed()

    # ------------------------------------------------------------- lifecycle

    def ensure_indexed(self) -> None:
        loaded = load_all(self._knowledge_dir)
        self._documents = {}
        self._imported_count = 0
        for raw in loaded:
            document = KnowledgeDocument.model_validate(raw)
            self._documents[document.doc_id] = document
            if document.doc_id not in BUILTIN_DOCUMENT_IDS:
                self._imported_count += 1
        self._searchable = [
            SearchableDocument(
                doc_id=document.doc_id,
                title=document.title,
                content=document.content,
                tags=tuple(document.tags),
            )
            for document in self._documents.values()
        ]
        self._tfidf = build_tfidf_index(self._searchable)
        self._sync_fts()

    def reload(self) -> KnowledgeReloadResult:
        self.ensure_indexed()
        return KnowledgeReloadResult(
            mode=self._mode,
            fts_available=bool(self._fts_available),
            document_count=len(self._documents),
            imported_count=self._imported_count,
        )

    # ----------------------------------------------------------------- FTS5

    def _detect_fts(self) -> bool:
        connection = self._engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x)")
            cursor.execute("DROP TABLE IF EXISTS _fts_probe")
            connection.commit()
            return True
        except Exception:  # pragma: no cover - depends on sqlite build
            return False
        finally:
            connection.close()

    def _sync_fts(self) -> None:
        if not self._detect_fts():
            self._fts_available = False
            self._mode = "TFIDF_ONLY"
            return
        self._fts_available = True
        connection = self._engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.execute("DROP TABLE IF EXISTS knowledge_fts")
            cursor.execute(
                "CREATE VIRTUAL TABLE knowledge_fts USING fts5("
                "doc_id UNINDEXED, title, content, tags, tokenize='unicode61')"
            )
            for document in self._documents.values():
                cursor.execute(
                    "INSERT INTO knowledge_fts(doc_id, title, content, tags) VALUES (?,?,?,?)",
                    (
                        document.doc_id,
                        document.title,
                        document.content,
                        " ".join(document.tags),
                    ),
                )
            connection.commit()
        finally:
            connection.close()
        self._mode = "FTS5+TFIDF"

    def _recall(self, query: str) -> set[str]:
        """Return candidate doc_ids via FTS5, falling back to a full scan."""
        if self._fts_available:
            expression = fts_match_expression(query)
            if expression != '""':
                connection = self._engine.raw_connection()
                try:
                    rows = connection.execute(
                        "SELECT doc_id FROM knowledge_fts WHERE knowledge_fts MATCH ?",
                        (expression,),
                    ).fetchall()
                finally:
                    connection.close()
                ids = {row[0] for row in rows}
                if ids:
                    return ids
        return set(self._documents)

    # ------------------------------------------------------------- queries

    def search(self, query: str, limit: int = 8) -> KnowledgeSearchResult:
        started = time.perf_counter()
        normalized = (query or "").strip()
        if not normalized:
            return KnowledgeSearchResult(
                query=query,
                limit=limit,
                total=0,
                elapsed_ms=0.0,
                mode=self._mode,
            )
        candidates = self._recall(normalized)
        index = self._tfidf
        ranked: list[RankedHit] = (
            score_tfidf(normalized, index, candidates) if index is not None else []
        )
        hits: list[KnowledgeHit] = []
        for hit in ranked[:limit]:
            document = self._documents[hit.doc_id]
            hits.append(
                KnowledgeHit(
                    doc_id=document.doc_id,
                    title=document.title,
                    category=document.category,
                    doc_type=document.doc_type,
                    score=hit.score,
                    matched_terms=hit.matched_terms,
                    snippet=make_snippet(document.content, hit.matched_terms),
                    source=document.source,
                    version=document.version,
                )
            )
        return KnowledgeSearchResult(
            query=normalized,
            limit=limit,
            total=len(ranked),
            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            mode=self._mode,
            hits=hits,
        )

    def list_documents(self) -> list[dict[str, Any]]:
        return [document.model_dump(mode="json") for document in self._documents.values()]

    def get(self, doc_id: str) -> KnowledgeDocument | None:
        return self._documents.get(doc_id)

    def status(self) -> KnowledgeIndexStatus:
        categories: dict[str, int] = Counter(
            document.category.value for document in self._documents.values()
        )
        return KnowledgeIndexStatus(
            mode=self._mode,
            fts_available=bool(self._fts_available),
            document_count=len(self._documents),
            imported_count=self._imported_count,
            categories=dict(sorted(categories.items())),
            knowledge_dir=str(self._knowledge_dir),
        )
