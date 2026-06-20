#!/usr/bin/env python3
"""
scanner/agents/triage.py

Claude triage agent — takes a pre-triage Finding and determines whether it is
a TRUE_POSITIVE or FALSE_POSITIVE by acting as an adversarial code auditor.

Architecture:
  - One API call per finding (stateless; no conversation history needed)
  - temperature=0.0 for deterministic decisions
  - Structured JSON output enforced via system prompt
  - Batching with configurable concurrency to respect rate limits
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import anthropic

from scanner.schema import Finding

MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-4-8")
MAX_TOKENS = 800
MAX_WORKERS = int(os.getenv("TRIAGE_CONCURRENCY", "5"))
RETRY_SLEEP = float(os.getenv("TRIAGE_RETRY_SLEEP", "2.0"))

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client


SYSTEM_PROMPT = """You are an expert application security auditor specializing in eliminating false positives.

Your job: given a code snippet flagged by a static analysis tool, determine whether an attacker can realistically exploit the reported vulnerability.

Act as an attacker. Attempt to construct a concrete exploit path. If you cannot find one — because the data is sanitized, statically defined, gated behind auth, or otherwise safe — classify it as FALSE_POSITIVE.

Respond ONLY with valid JSON. No markdown, no prose outside the JSON object.

Required format:
{
  "status": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "confidence": "high" | "medium" | "low",
  "reasoning": "One to three sentences explaining your decision."
}

Use NEEDS_REVIEW when the snippet alone is insufficient to make a determination (e.g. sanitization happens in an imported function you cannot see)."""


def _build_prompt(finding: Finding) -> str:
    return f"""Static analysis tool flagged: "{finding.description}"
Rule: {finding.rule_id}
Category: {finding.category}
Severity: {finding.severity}
CWEs: {', '.join(finding.cwe_ids) or 'unknown'}

{finding.code_snippet}

Can an attacker exploit this? Respond in JSON only."""


def triage_finding(finding: Finding) -> Finding:
    """Triage a single finding. Mutates and returns the finding."""
    prompt = _build_prompt(finding)

    for attempt in range(3):
        try:
            response = _get_client().messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                temperature=0.0,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            result = json.loads(raw)
            finding.triage_status = result.get("status", "ERROR")
            finding.triage_reasoning = result.get("reasoning", "")
            finding.triage_confidence = result.get("confidence", "")
            return finding

        except json.JSONDecodeError:
            finding.triage_status = "ERROR"
            finding.triage_reasoning = f"Model returned non-JSON: {raw[:200]}"
            return finding

        except anthropic.RateLimitError:
            if attempt < 2:
                time.sleep(RETRY_SLEEP * (attempt + 1))
            else:
                finding.triage_status = "ERROR"
                finding.triage_reasoning = "Rate limit exceeded after retries."
                return finding

        except Exception as e:
            finding.triage_status = "ERROR"
            finding.triage_reasoning = str(e)
            return finding

    return finding


def triage_batch(findings: list[Finding], show_progress: bool = True) -> list[Finding]:
    """
    Triage a list of findings concurrently.
    Returns all findings with triage_status populated.
    """
    if not findings:
        return findings

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_finding = {executor.submit(triage_finding, f): f for f in findings}
        for i, future in enumerate(as_completed(future_to_finding), 1):
            result = future.result()
            results.append(result)
            if show_progress:
                status_icon = {"TRUE_POSITIVE": "🔴", "FALSE_POSITIVE": "✅", "NEEDS_REVIEW": "🟡", "ERROR": "⚠️"}.get(result.triage_status, "?")
                print(f"  [{i}/{len(findings)}] {status_icon} {result.triage_status} — {result.file_path}:{result.line_start} ({result.rule_id})")

    return results
