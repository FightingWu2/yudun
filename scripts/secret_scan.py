#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "backend" / "app",
    ROOT / "frontend" / "src",
    ROOT / "frontend" / "dist",
    ROOT / "artifacts",
    ROOT / ".runtime",
]
SKIP_FILES = {ROOT / "backend" / "app" / "core" / "redaction.py"}
SCAN_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".css", ".html", ".json", ".md", ".db", ".log"}
PATTERNS = [
    re.compile(r"(?i)authorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)(?<![A-Z_])(?:api[-_]?key|password|secret|token|credential)\s*[=:]\s*"
        r"['\"](?!\[REDACTED\]|plain-|fixture)[^'\"]{8,}['\"]"
    ),
]


def main() -> int:
    findings: list[str] = []
    for scan_root in SCAN_ROOTS:
        for path in scan_root.rglob("*"):
            if not path.is_file() or path in SKIP_FILES or path.suffix not in SCAN_SUFFIXES:
                continue
            text = path.read_bytes().decode("utf-8", errors="ignore")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if any(pattern.search(line) for pattern in PATTERNS):
                    findings.append(f"{path.relative_to(ROOT)}:{line_number}")
    if findings:
        print("Potential plaintext secrets found:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(
        "Secret scan passed: no plaintext credential patterns in source, bundle, "
        "runtime database, logs, or test artifacts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
