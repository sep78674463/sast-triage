#!/usr/bin/env python3
"""
scanner/adapters/semgrep.py

Runs Semgrep against a target directory using a rule pack and returns
a list of Finding objects (pre-triage, triage_status=PENDING).
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from scanner.schema import Finding, infer_category

# Default rule pack — community registry aliases
DEFAULT_RULES = [
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/java",
    "p/go",
    "p/secrets",
    "p/owasp-top-ten",
]

SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}


def run(
    target_dir: str,
    rules: list[str] | None = None,
    custom_rule_files: list[str] | None = None,
    languages: list[str] | None = None,
    context_window: int = 15,
    commit_sha: str = "",
    repo: str = "",
) -> list[Finding]:
    """
    Run Semgrep and return a list of pre-triage Finding objects.

    Args:
        target_dir: Path to source directory to scan.
        rules: Semgrep registry rule packs (default: DEFAULT_RULES).
        custom_rule_files: Paths to local .yaml rule files (merged with rules).
        languages: Optional language filter (e.g. ["python", "javascript"]).
        context_window: Lines of context to extract around each finding.
        commit_sha: Git SHA of scanned commit (stored in Finding metadata).
        repo: Repository name (stored in Finding metadata).
    """
    configs = _build_configs(rules, custom_rule_files)
    cmd = ["semgrep"] + configs + [target_dir, "--json", "--quiet"]

    if languages:
        for lang in languages:
            cmd += ["--include", f"*.{_lang_extension(lang)}"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[semgrep] failed to parse output: {result.stderr[:500]}")
        return []

    findings = []
    for match in raw.get("results", []):
        file_path = match.get("path", "")
        line_start = match.get("start", {}).get("line", 0)
        line_end = match.get("end", {}).get("line", line_start)
        rule_id = match.get("check_id", "unknown")
        message = match.get("extra", {}).get("message", "")
        raw_severity = match.get("extra", {}).get("severity", "WARNING")
        metadata = match.get("extra", {}).get("metadata", {})

        snippet = _extract_context(file_path, line_start, context_window)
        language = _detect_language(file_path)

        findings.append(Finding(
            rule_id=rule_id,
            title=_rule_id_to_title(rule_id),
            description=message,
            severity=SEVERITY_MAP.get(raw_severity, "medium"),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet,
            language=language,
            category=infer_category(rule_id),
            cwe_ids=_listify(metadata.get("cwe")),
            owasp_ids=_listify(metadata.get("owasp")),
            scanner="semgrep",
            commit_sha=commit_sha,
            repo=repo,
        ))

    return findings


def _build_configs(rules: list[str] | None, custom_files: list[str] | None) -> list[str]:
    configs = []
    for r in (rules or DEFAULT_RULES):
        configs += ["--config", r]
    for f in (custom_files or []):
        configs += ["--config", f]
    return configs


def _extract_context(filepath: str, line_num: int, window: int) -> str:
    if not os.path.exists(filepath):
        return ""
    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()
    start = max(0, line_num - window - 1)
    end = min(len(lines), line_num + window)
    numbered = [f"{start + i + 1:4}: {line}" for i, line in enumerate(lines[start:end])]
    return f"--- {filepath} (lines {start+1}–{end}) ---\n" + "".join(numbered)


def _detect_language(filepath: str) -> str:
    ext = Path(filepath).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
        ".cs": "csharp", ".cpp": "cpp", ".c": "c",
    }.get(ext, "unknown")


def _lang_extension(lang: str) -> str:
    return {
        "python": "py", "javascript": "js", "typescript": "ts",
        "java": "java", "go": "go",
    }.get(lang.lower(), lang)


def _rule_id_to_title(rule_id: str) -> str:
    return rule_id.split(".")[-1].replace("-", " ").replace("_", " ").title()


def _listify(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]
