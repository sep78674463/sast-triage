#!/usr/bin/env python3
"""
scanner/run.py

CLI orchestrator for the hybrid SAST triage pipeline.

Usage:
  python3 -m scanner.run --target ./src
  python3 -m scanner.run --target ./src --languages python javascript
  python3 -m scanner.run --target ./src --rules p/python p/secrets --dry-run
  python3 -m scanner.run --target ./src --specialist   # use category-specialized agents
  python3 -m scanner.run --target ./src --output-json outputs/findings.json
  python3 -m scanner.run --target ./src --output-sarif outputs/results.sarif
"""

import argparse
import os
import sys

from scanner.adapters import semgrep
from scanner.agents import triage as generic_triage
from scanner.agents.specialized import triage_with_specialist, SPECIALIST_CATEGORIES
from scanner.output.reporter import print_summary, write_json, write_sarif
from scanner.schema import Finding


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Hybrid SAST: Semgrep + Claude triage")
    p.add_argument("--target", default="./src", help="Directory to scan")
    p.add_argument("--rules", nargs="+", help="Semgrep rule packs (default: p/python p/secrets p/owasp-top-ten)")
    p.add_argument("--custom-rules", nargs="+", help="Local Semgrep YAML rule files")
    p.add_argument("--languages", nargs="+", help="Language filter (python javascript java go)")
    p.add_argument("--dry-run", action="store_true", help="Run Semgrep only; skip Claude triage")
    p.add_argument("--specialist", action="store_true", help="Use category-specialized Claude agents")
    p.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low", "info"],
                   help="Minimum severity to triage (default: medium)")
    p.add_argument("--output-json", help="Write full results to JSON file")
    p.add_argument("--output-sarif", help="Write confirmed findings to SARIF file")
    p.add_argument("--commit-sha", default=os.getenv("GITHUB_SHA", ""), help="Git commit SHA")
    p.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""), help="Repository name")
    return p.parse_args()


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def main() -> int:
    args = parse_args()

    # ── 1. Semgrep scan ──────────────────────────────────────────────────────
    print(f"[*] Scanning {args.target} with Semgrep...")
    findings = semgrep.run(
        target_dir=args.target,
        rules=args.rules,
        custom_rule_files=args.custom_rules,
        languages=args.languages,
        commit_sha=args.commit_sha,
        repo=args.repo,
    )
    print(f"[*] Semgrep: {len(findings)} finding(s) before triage")

    if not findings:
        print("[*] No findings. Done.")
        return 0

    # ── 2. Severity filter ───────────────────────────────────────────────────
    min_rank = SEVERITY_RANK[args.severity]
    to_triage = [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= min_rank]
    skipped = len(findings) - len(to_triage)
    if skipped:
        print(f"[*] Skipping {skipped} finding(s) below --severity {args.severity}")

    # ── 3. Dry run ───────────────────────────────────────────────────────────
    if args.dry_run:
        print("[*] --dry-run: skipping Claude triage")
        for f in to_triage:
            f.triage_status = "PENDING"
        _finalize(findings, args)
        return 0

    # ── 4. Claude triage ─────────────────────────────────────────────────────
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY not set — cannot triage. Use --dry-run to skip.", file=sys.stderr)
        return 1

    print(f"[*] Triaging {len(to_triage)} finding(s) with Claude ({_model()})...")

    if args.specialist:
        triaged = []
        for f in to_triage:
            if f.category in SPECIALIST_CATEGORIES:
                triaged.append(triage_with_specialist(f))
            else:
                triaged.append(generic_triage.triage_finding(f))
    else:
        triaged = generic_triage.triage_batch(to_triage)

    # Merge any below-threshold findings back (untriaged)
    all_findings = triaged + [f for f in findings if SEVERITY_RANK.get(f.severity, 0) < min_rank]

    _finalize(all_findings, args)
    confirmed = sum(1 for f in all_findings if f.triage_status == "TRUE_POSITIVE")
    return 1 if confirmed > 0 else 0


def _finalize(findings: list[Finding], args: argparse.Namespace) -> None:
    print_summary(findings)
    if args.output_json:
        write_json(findings, args.output_json)
    if args.output_sarif:
        write_sarif(findings, args.output_sarif, repo_root=args.target)


def _model() -> str:
    return os.getenv("CLAUDE_MODEL", "claude-opus-4-8")


if __name__ == "__main__":
    sys.exit(main())
