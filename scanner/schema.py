#!/usr/bin/env python3
"""
scanner/schema.py

Canonical finding schema emitted by all scanner adapters.
Downstream consumers (PaC ingest, GitHub Actions reporter) are adapter-agnostic.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    rule_id: str                    # e.g. "raw-sql-injection", "hardcoded-secret"
    title: str
    description: str                # AST tool message
    severity: str                   # critical | high | medium | low | info
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str               # extracted context window (30 lines)
    language: str
    category: str                   # injection | secrets | crypto | access-control | xss | ssrf
    cwe_ids: list[str] = field(default_factory=list)   # e.g. ["CWE-89"]
    owasp_ids: list[str] = field(default_factory=list) # e.g. ["A03:2021"]

    # Claude triage fields — populated after triage pass
    triage_status: str = "PENDING"  # PENDING | TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW | ERROR
    triage_reasoning: str = ""
    triage_confidence: str = ""     # high | medium | low

    # Metadata
    scanner: str = "semgrep"
    scan_id: str = ""
    commit_sha: str = ""
    repo: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    def is_confirmed(self) -> bool:
        return self.triage_status == "TRUE_POSITIVE"


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CATEGORY_MAP = {
    # Semgrep rule id prefixes → category
    "sql":        "injection",
    "sqli":       "injection",
    "cmd":        "injection",
    "ssrf":       "ssrf",
    "xss":        "xss",
    "secret":     "secrets",
    "hardcoded":  "secrets",
    "crypto":     "crypto",
    "tls":        "crypto",
    "auth":       "access-control",
    "authz":      "access-control",
    "jwt":        "access-control",
    "path":       "injection",
    "xxe":        "injection",
    "deserial":   "injection",
}


def infer_category(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    for prefix, category in CATEGORY_MAP.items():
        if prefix in rule_lower:
            return category
    return "other"
