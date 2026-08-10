"""Security Knowledge RAG: built-in + imported knowledge base with hybrid
FTS5 + TF-IDF retrieval.

Design constraints (see docs/15-Security Knowledge RAG 实现文档.md):

* Retrieval results are *reference material only* — they never become
  ``ConfirmedFact`` or an authorization basis on their own.
* The pipeline is deterministic and offline: the index is rebuilt from
  ``data/knowledge/`` + built-in entries on every reset, so replays are
  reproducible.
"""

# Sub-modules are imported directly (e.g. ``from app.knowledge.service import
# KnowledgeService``) so the retrieval math (tokenize/ranking/loader) stays
# importable without the ORM/Pydantic stack — this keeps it unit-testable in
# minimal environments.
