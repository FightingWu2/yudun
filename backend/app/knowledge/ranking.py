"""Pure-standard-library TF-IDF ranking and FTS5 MATCH expression builder.

The hybrid retrieval flow is:

1. *Candidate recall* — a SQLite FTS5 ``MATCH`` (or, when FTS5 is
   unavailable, a plain inverted-index scan) narrows the candidate set.
2. *Ranking* — TF-IDF weighted scoring re-ranks the candidates.

Only this module and ``tokenize`` implement the retrieval math, so the whole
algorithm can be unit-tested without the project's ORM/Pydantic stack.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from app.knowledge.tokenize import term_frequencies, tokenize

# Tokens acceptable inside a double-quoted FTS5 phrase: latin runs and CJK.
_FTS_TOKEN = re.compile(r"[a-z0-9_\-\.]+|[㐀-鿿]{2}")


def fts_match_expression(query: str) -> str:
    """Build a safe, quoted FTS5 MATCH expression from a plain-text query.

    Every term is wrapped in double quotes so user input cannot inject FTS5
    query operators. A bare CJK char is dropped (bigrams carry the signal).
    """
    terms: list[str] = []
    for match in _FTS_TOKEN.findall((query or "").lower()):
        term = match.strip()
        if not term or (len(term) == 1 and ord(term) > 0x2E80):
            continue
        if term not in terms:
            terms.append(term)
    if not terms:
        return '""'
    return " OR ".join(f'"{term}"' for term in terms)


@dataclass(frozen=True)
class SearchableDocument:
    """Minimal document shape used by the ranker (ORM-free)."""

    doc_id: str
    title: str
    content: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class TfidfIndex:
    df: dict[str, int]
    postings: dict[str, dict[str, int]]
    doc_lengths: dict[str, int]
    n_docs: int


@dataclass
class RankedHit:
    """A single ranked retrieval hit."""

    doc_id: str
    score: float
    matched_terms: list[str] = field(default_factory=list)
    snippet: str = ""


def build_tfidf_index(documents: Iterable[SearchableDocument]) -> TfidfIndex:
    """Build document-frequency and postings data for TF-IDF scoring."""
    docs = list(documents)
    df: dict[str, int] = defaultdict(int)
    postings: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    doc_lengths: dict[str, int] = {}
    for doc in docs:
        tokens = tokenize(f"{doc.title} {doc.content} {' '.join(doc.tags)}")
        if not tokens:
            continue
        doc_lengths[doc.doc_id] = len(tokens)
        for term, count in term_frequencies(tokens).items():
            if postings[term].get(doc.doc_id, 0) == 0:
                df[term] += 1
            postings[term][doc.doc_id] += count
    return TfidfIndex(
        df=dict(df),
        postings={term: dict(docs_map) for term, docs_map in postings.items()},
        doc_lengths=doc_lengths,
        n_docs=len(docs),
    )


def score_tfidf(
    query: str,
    index: TfidfIndex,
    candidates: Iterable[str] | None = None,
) -> list[RankedHit]:
    """Rank documents by weighted TF-IDF similarity against a query.

    ``candidates`` optionally pre-filters the doc set (e.g. the FTS5 recall
    set). When omitted, all indexed documents are scored.
    """
    query_terms = [term for term in tokenize(query) if term in index.postings]
    if not query_terms:
        return []
    query_tf = term_frequencies(query_terms)
    n_docs = max(index.n_docs, 1)
    allowed = None if candidates is None else set(candidates)

    scores: dict[str, float] = defaultdict(float)
    matched: dict[str, set[str]] = defaultdict(set)
    for term, count in query_tf.items():
        idf = math.log(1.0 + n_docs / max(index.df.get(term, 1), 1))
        for doc_id, doc_tf in index.postings.get(term, {}).items():
            if allowed is not None and doc_id not in allowed:
                continue
            doc_len = max(index.doc_lengths.get(doc_id, 1), 1)
            # Sublinear term weight + length normalisation keeps the score a
            # similarity-like number instead of a raw count.
            weight = count * idf * (1.0 + math.log(doc_tf)) / math.sqrt(doc_len)
            scores[doc_id] += weight
            matched[doc_id].add(term)

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    max_score = ranked[0][1] if ranked else 0.0
    hits: list[RankedHit] = []
    for doc_id, raw in ranked:
        score = raw / max_score if max_score else 0.0
        hits.append(
            RankedHit(
                doc_id=doc_id,
                score=round(score, 4),
                matched_terms=sorted(matched.get(doc_id, set())),
            )
        )
    return hits


def make_snippet(content: str, matched_terms: list[str], window: int = 160) -> str:
    """Return a compact window around the first matched term in ``content``."""
    if not matched_terms or not content:
        return content[:window] + ("…" if len(content) > window else "")
    position = len(content)
    lowered = content.lower()
    for term in matched_terms:
        found = lowered.find(term.lower())
        if found >= 0:
            position = min(position, found)
    start = max(0, position - window // 4)
    end = min(len(content), start + window)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(content) else ""
    return f"{prefix}{content[start:end]}{suffix}"
