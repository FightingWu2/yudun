"""Pydantic schemas for the Security Knowledge RAG feature."""

from enum import StrEnum

from pydantic import Field, field_validator

from app.schemas.base import NonEmptyStr, StrictSchema


class KnowledgeCategory(StrEnum):
    ATTACK_TECHNIQUE = "ATTACK_TECHNIQUE"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    CI_SUPPLY_CHAIN = "CI_SUPPLY_CHAIN"
    DETECTION_RULE = "DETECTION_RULE"
    RESPONSE_PLAYBOOK = "RESPONSE_PLAYBOOK"
    CLOUD_ABUSE = "CLOUD_ABUSE"
    REFERENCE = "REFERENCE"


class KnowledgeDocument(StrictSchema):
    """A single indexed knowledge entry.

    ``doc_id`` uses a readable ``kno-`` slug (like ``rule_id``/``scenario_id``)
    rather than a runtime ULID so built-in and imported documents can be
    referenced deterministically across replays.
    """

    doc_id: NonEmptyStr
    category: KnowledgeCategory
    doc_type: str = "reference"
    title: NonEmptyStr
    tags: list[str] = Field(default_factory=list)
    content: NonEmptyStr
    source: str = "BUILTIN"
    version: str = "1.0"

    @field_validator("doc_id")
    @classmethod
    def validate_doc_id(cls, value: str) -> str:
        if not value.startswith("kno-"):
            raise ValueError("knowledge doc_id must use kno- prefix")
        return value

    @field_validator("doc_type")
    @classmethod
    def validate_doc_type(cls, value: str) -> str:
        allowed = {"reference", "playbook", "rule", "note"}
        if value not in allowed:
            raise ValueError("unsupported knowledge doc_type")
        return value


class KnowledgeHit(StrictSchema):
    """A ranked retrieval hit returned to callers."""

    doc_id: str
    title: NonEmptyStr
    category: KnowledgeCategory
    doc_type: str
    score: float = Field(ge=0.0, le=1.0)
    matched_terms: list[str] = Field(default_factory=list)
    snippet: NonEmptyStr
    source: str = "BUILTIN"
    version: str = "1.0"


class KnowledgeSearchResult(StrictSchema):
    """Container returned by the knowledge search endpoint."""

    query: str
    limit: int
    total: int
    elapsed_ms: float
    mode: str
    hits: list[KnowledgeHit] = Field(default_factory=list)


class KnowledgeIndexStatus(StrictSchema):
    """Status describing the current knowledge index."""

    mode: str
    fts_available: bool
    document_count: int
    imported_count: int
    categories: dict[str, int] = Field(default_factory=dict)
    knowledge_dir: str


class KnowledgeReloadResult(StrictSchema):
    """Result of an index reload."""

    reloaded: bool = True
    mode: str
    fts_available: bool
    document_count: int
    imported_count: int
