#!/usr/bin/env python3
"""
scanner/agents/specialized.py

Specialized triage agents for specific vulnerability categories.
Each agent uses a narrowly-scoped system prompt tuned to its domain,
producing higher accuracy than the generic triage agent for that class.

Usage: the orchestrator routes findings to the appropriate agent by category.
"""

import json
import os

import anthropic

from scanner.schema import Finding

MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-4-8")
MAX_TOKENS = 800

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        _client = anthropic.Anthropic(api_key=key)
    return _client


_SYSTEM_PROMPTS = {
    "injection": """You are an injection vulnerability specialist (SQL, Command, SSRF, XXE, Path Traversal).
Trace the data flow from source (user-controlled input) to sink (dangerous execution point).
Look for: parameterized queries, prepared statements, ORM escaping, allow-lists, type coercion.
If any sanitizer sits between source and sink, classify FALSE_POSITIVE.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}""",

    "secrets": """You are a secrets and credential detection specialist.
Determine whether the flagged value is: (a) a real hardcoded secret, (b) a placeholder/example, (c) an environment variable reference, or (d) a test fixture.
Patterns like "YOUR_KEY_HERE", "changeme", "example", "test", or values read from os.getenv() are FALSE_POSITIVE.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}""",

    "crypto": """You are a cryptography auditor.
Evaluate: key lengths, algorithm choices (MD5/SHA1 = weak, AES-256/SHA-256 = acceptable), IV/nonce reuse, ECB mode, hardcoded keys, use of deprecated libraries.
Consider context: if MD5 is used for a non-security purpose (e.g. cache key, ETag), it may be a FALSE_POSITIVE.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}""",

    "access-control": """You are an access control and authentication specialist (IDOR, broken auth, JWT flaws, privilege escalation, missing authz checks).
Determine if the flagged code is on a path reachable by unauthenticated or unauthorized users.
Look for: middleware decorators, role checks, framework auth guards, JWT validation.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}""",

    "xss": """You are an XSS and output encoding specialist.
Trace user-controlled data to HTML/JS rendering sinks.
Look for: template auto-escaping (Django, Jinja2, React JSX), explicit encode/escape calls, Content-Security-Policy headers.
If auto-escaping is active and no raw/safe bypass is present, classify FALSE_POSITIVE.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}""",
}

_DEFAULT_SYSTEM = """You are an application security auditor. Determine if the flagged code is a TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_REVIEW.
Respond ONLY in JSON: {"status": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": "high"|"medium"|"low", "reasoning": "..."}"""


def triage_with_specialist(finding: Finding) -> Finding:
    """Route finding to the appropriate specialist agent and return triaged finding."""
    system = _SYSTEM_PROMPTS.get(finding.category, _DEFAULT_SYSTEM)
    prompt = f"""Rule: {finding.rule_id}
Description: {finding.description}
CWEs: {', '.join(finding.cwe_ids) or 'unknown'}

{finding.code_snippet}"""

    try:
        response = _get_client().messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        result = json.loads(response.content[0].text.strip())
        finding.triage_status = result.get("status", "ERROR")
        finding.triage_reasoning = result.get("reasoning", "")
        finding.triage_confidence = result.get("confidence", "")
    except Exception as e:
        finding.triage_status = "ERROR"
        finding.triage_reasoning = str(e)

    return finding


SPECIALIST_CATEGORIES = set(_SYSTEM_PROMPTS.keys())
