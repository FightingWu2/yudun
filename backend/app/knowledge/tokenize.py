"""Pure-standard-library text tokenizer shared by FTS5 and TF-IDF.

English words are lowercased word runs; CJK text is segmented into
overlapping bigrams so SQLite FTS5 (unicode61 tokenizer) and the TF-IDF
ranker operate in the same term space. Keeping this module dependency-free
means the retrieval algorithm can be unit-tested without the project's
SQLAlchemy/Pydantic stack.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

_LATIN = re.compile(r"[a-z0-9][a-z0-9_\-\.]{0,63}", re.IGNORECASE)
_CJK = re.compile(r"[一-鿿㐀-䶿]+")

# Small, deliberately conservative stop-word list. Security-specific terms are
# intentionally NOT removed (e.g. "key", "secret") because they carry signal.
_STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "to",
    "in",
    "on",
    "for",
    "with",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "at",
    "by",
    "from",
    "as",
    "it",
    "its",
    "this",
    "that",
    "these",
    "those",
    "which",
    "who",
    "whom",
    "not",
    "no",
    "but",
    "if",
    "then",
    "else",
    "when",
    "where",
    "why",
    "how",
    "all",
    "any",
    "each",
    "every",
    "some",
    "such",
    "only",
    "own",
    "same",
    "too",
    "very",
    "can",
    "will",
    "just",
    "should",
    "about",
    "into",
    "over",
    "after",
    "before",
    "between",
    "under",
    "again",
    "further",
    "once",
    # Minimal CJK function words.
    "这里",
    "我们",
    "他们",
    "你们",
    "以及",
    "可以",
    "需要",
    "进行",
    "相关",
    "一个",
    "这个",
    "那个",
    "已经",
    "通过",
    "对于",
    "由于",
    "但是",
    "如果",
    "并且",
    "其中",
    "以及",
    "包括",
    "用于",
}


def tokenize(text: str) -> list[str]:
    """Return a normalized term list for a piece of text."""
    tokens: list[str] = []
    normalized = unicodedata.normalize("NFKC", text or "")
    for part in _LATIN.findall(normalized):
        token = part.lower()
        if token not in _STOPWORDS:
            tokens.append(token)
    for cjk in _CJK.findall(normalized):
        if len(cjk) == 1:
            if cjk not in _STOPWORDS:
                tokens.append(cjk)
            continue
        for index in range(len(cjk) - 1):
            bigram = cjk[index : index + 2]
            if bigram not in _STOPWORDS:
                tokens.append(bigram)
    return tokens


def term_frequencies(tokens: list[str]) -> Counter[str]:
    """Return a term-frequency counter over a token list."""
    return Counter(tokens)


def unique_terms(text: str) -> list[str]:
    """Return the sorted unique terms for a text (used for FTS MATCH)."""
    return sorted({token for token in tokenize(text)})
