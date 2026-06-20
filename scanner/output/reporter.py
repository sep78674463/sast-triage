#!/usr/bin/env python3
"""
scanner/output/reporter.py

Formats triage results for terminal output, JSON export, and GitHub Actions
SARIF format (accepted natively by GitHub Code Scanning).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from scanner.schema import Finding, SEVERITY_RANK


def print_summary(findings: list[Finding]) -> None:
    total = len(findings)
    tp = sum(1 for f in findings if f.triage_status == "TRUE_POSITIVE")
    fp = sum(1 for f in findings if f.triage_status == "FALSE_POSITIVE")
    nr = sum(1 for f in findings if f.triage_status == "NEEDS_REVIEW")
    err = sum(1 for f in findings if f.triage_status == "ERROR")

    print("\n" + "=" * 60)
    print(f"  SAST Triage Summary")
    print("=" * 60)
    print(f"  Total findings (pre-triage):  {total}")
    print(f"  TRUE_POSITIVE (confirmed):    {tp}")
    print(f"  FALSE_POSITIVE (suppressed):  {fp}")
    print(f"  NEEDS_REVIEW (manual):        {nr}")
    print(f"  ERROR (triage failed):        {err}")
    if total > 0:
        suppression_rate = round(fp / total * 100)
        print(f"  False-positive suppression:   {suppression_rate}%")
    print("=" * 60)

    confirmed = [f for f in findings if f.triage_status == "TRUE_POSITIVE"]
    confirmed.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)

    if confirmed:
        print("\n  Confirmed vulnerabilities (highest severity first):\n")
        for f in confirmed:
            print(f"  [{f.severity.upper()}] {f.rule_id}")
            print(f"    {f.file_path}:{f.line_start}")
            print(f"    {f.triage_reasoning}")
            print()


def write_json(findings: list[Finding], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total": len(findings),
                "confirmed": sum(1 for f in findings if f.triage_status == "TRUE_POSITIVE"),
                "findings": [f.to_dict() for f in findings],
            },
            f,
            indent=2,
        )
    print(f"[reporter] JSON written to {output_path}")


def write_sarif(findings: list[Finding], output_path: str, repo_root: str = ".") -> None:
    """
    Emit SARIF 2.1.0 — accepted by GitHub Code Scanning and VS Code.
    Only TRUE_POSITIVE findings are included.
    """
    SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}

    rules = {}
    results = []

    for f in findings:
        if f.triage_status != "TRUE_POSITIVE":
            continue

        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
                "properties": {
                    "tags": f.cwe_ids + f.owasp_ids,
                    "precision": "high",
                    "problem.severity": f.severity,
                },
            }

        rel_path = os.path.relpath(f.file_path, repo_root)
        results.append({
            "ruleId": f.rule_id,
            "message": {"text": f"{f.triage_reasoning} ({f.description})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_start, "endLine": f.line_end},
                }
            }],
            "properties": {"confidence": f.triage_confidence},
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sast-triage",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/SEPCyber/sast-triage",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"[reporter] SARIF written to {output_path}")
