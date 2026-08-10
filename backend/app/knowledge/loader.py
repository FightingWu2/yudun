"""Knowledge-document loading: built-in entries plus imported files.

Imported documents live under ``<project>/data/knowledge/`` and may be:

* ``*.md`` — optional ``---`` frontmatter (``key: value`` lines) followed by
  the markdown body. The document id is derived from the filename.
* ``*.json`` — either a single object or an array of objects matching the
  ``KnowledgeDocument`` schema.

The module is dependency-free so loading can be unit-tested without the ORM.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.knowledge.builtin import BUILTIN_DOCUMENTS

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# Category/doc_type aliases accepted in frontmatter.
_CATEGORIES = {
    "ATTACK_TECHNIQUE",
    "CLOUD_CREDENTIAL",
    "CI_SUPPLY_CHAIN",
    "DETECTION_RULE",
    "RESPONSE_PLAYBOOK",
    "CLOUD_ABUSE",
    "REFERENCE",
}
_DOC_TYPES = {"reference", "playbook", "rule", "note"}


def load_builtin() -> list[dict[str, Any]]:
    """Return a deep copy of the built-in knowledge documents."""
    return [dict(item) for item in BUILTIN_DOCUMENTS]


def _slugify(name: str) -> str:
    slug = re.sub(r"[^0-9a-zA-Z一-鿿]+", "-", name).strip("-").lower()
    return slug or "document"


def _safe_doc_id(raw: str) -> str:
    slug = _slugify(raw)
    if slug.startswith("kno-"):
        return slug
    return f"kno-{slug}"


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    match = _FRONTMATTER_RE.match(text)
    if match is None:
        return {}, text
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        meta[key.strip().lower()] = value.strip()
    return meta, text[match.end() :]


def _normalize_tags(raw: str) -> list[str]:
    return [tag.strip() for tag in re.split(r"[,\s;]+", raw) if tag.strip()]


def _load_markdown(path: Path) -> dict[str, Any]:
    meta, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
    category = meta.get("category", "REFERENCE").upper()
    doc_type = meta.get("type", "note").lower()
    if category not in _CATEGORIES:
        category = "REFERENCE"
    if doc_type not in _DOC_TYPES:
        doc_type = "note"
    return {
        "doc_id": _safe_doc_id(meta.get("id", path.stem)),
        "category": category,
        "doc_type": doc_type,
        "title": meta.get("title", path.stem),
        "tags": _normalize_tags(meta.get("tags", "")),
        "content": body.strip() or path.stem,
        "source": meta.get("source", "IMPORTED_MARKDOWN"),
        "version": meta.get("version", "1.0"),
    }


def _load_json_document(raw: dict[str, Any]) -> dict[str, Any]:
    if "content" not in raw:
        raise ValueError("knowledge json entry requires a content field")
    category = str(raw.get("category", "REFERENCE")).upper()
    doc_type = str(raw.get("doc_type", "note")).lower()
    if category not in _CATEGORIES:
        category = "REFERENCE"
    if doc_type not in _DOC_TYPES:
        doc_type = "note"
    tags = raw.get("tags")
    if isinstance(tags, str):
        tags = _normalize_tags(tags)
    return {
        "doc_id": _safe_doc_id(str(raw.get("doc_id") or raw.get("title") or "document")),
        "category": category,
        "doc_type": doc_type,
        "title": str(raw.get("title", raw.get("doc_id", "Untitled"))),
        "tags": [str(tag) for tag in (tags if isinstance(tags, list) else [])],
        "content": str(raw["content"]),
        "source": str(raw.get("source", "IMPORTED_JSON")),
        "version": str(raw.get("version", "1.0")),
    }


def load_imported(knowledge_dir: Path) -> list[dict[str, Any]]:
    """Load all imported documents under ``knowledge_dir``."""
    if not knowledge_dir.is_dir():
        return []
    documents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(knowledge_dir.iterdir()):
        if path.is_dir() or path.name.startswith("."):
            continue
        try:
            if path.suffix.lower() == ".md":
                item = _load_markdown(path)
            elif path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else [data]
                if not isinstance(data, list):
                    items = [data]
                raw_items = [entry for entry in items if isinstance(entry, dict)]
                if not raw_items:
                    continue
                for entry in raw_items:
                    item = _load_json_document(entry)
                    if item["doc_id"] not in seen:
                        seen.add(item["doc_id"])
                        documents.append(item)
                continue
            else:
                continue
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"failed to import knowledge file {path.name}: {exc}") from exc
        if item["doc_id"] not in seen:
            seen.add(item["doc_id"])
            documents.append(item)
    return documents


def load_all(knowledge_dir: Path) -> list[dict[str, Any]]:
    """Built-in entries followed by imported entries; imported wins on id clash."""
    documents = load_builtin()
    seen = {item["doc_id"] for item in documents}
    for item in load_imported(knowledge_dir):
        if item["doc_id"] in seen:
            documents = [entry for entry in documents if entry["doc_id"] != item["doc_id"]]
        documents.append(item)
        seen.add(item["doc_id"])
    return documents
