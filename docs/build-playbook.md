# sast-triage Build Playbook

A session-by-session record of how this project was designed and built using Claude as a collaborator. Captures the prompts, decisions, and design reasoning so the work is reproducible and auditable.

---

## Table of Contents

1. [Concept and Architecture Decision](#phase-1-concept-and-architecture-decision)
2. [Initial Scaffold — Semgrep + Claude Pipeline](#phase-2-initial-scaffold)
3. [Debugging and End-to-End Verification](#phase-3-debugging-and-verification)
4. [PaC Dashboard Integration](#phase-4-pac-dashboard-integration)

---

## Phase 1: Concept and Architecture Decision {#phase-1-concept-and-architecture-decision}

**Date:** 2026-06-20

### Context

During development of the PaC GRC platform, a Google AI exchange was shared describing how SAST tools work and proposing a hybrid architecture combining Semgrep (deterministic AST parsing) with Claude (contextual triage) to eliminate false positives.

### Prompt sequence

> "This session is being continued... [shared Google AI exchange on SAST + LLM hybrid pipeline]"

> "I'm thinking this security vulnerability scanner should live in a separate repo and it should be a separate POC — what do you think about that strategy?"

> "yes — can you create a new repo or shall I?"

### Response summary

The assistant recommended a separate repo on three grounds:

1. **Different audiences and deployment models** — SAST is a dev-time tool targeting engineering teams via CI/CD; PaC is an operational GRC platform targeting CISOs and compliance teams. They have different cadences and dependency footprints.
2. **Clean dependency separation** — Semgrep, Tree-sitter, and AST parsing libraries have no overlap with Neo4j, OSCAL, or FedRAMP.
3. **Independent pitchability** — a standalone scanner POC is easier to demonstrate without the GRC context.

**The one integration point preserved:** scanner findings should flow into PaC via `ingest/vuln/adapters/semgrep.py` (forthcoming). The scanner is a producer; PaC is the downstream compliance consumer. Same pattern as Nessus.

### Key Design Decisions

| Decision | Rationale |
|---|---|
| Separate repo, not a PaC subdirectory | Different audiences, dependencies, and deployment models |
| Semgrep-first, Claude-second | Semgrep filters 99% of secure code for free; Claude only sees flagged snippets |
| Adversarial triage framing | Claude prompted as an attacker trying to *prove* exploitability — suppresses creative hallucination |
| Adapter pattern for scanners | Same `Finding` dataclass regardless of source; downstream reporter is scanner-agnostic |
| Category-specialized agents | Narrower system prompts (injection / secrets / crypto / access-control / xss) produce higher accuracy than a single generic agent |
| SARIF output | GitHub Code Scanning native format — confirmed findings surface as PR annotations without extra tooling |

---

## Phase 2: Initial Scaffold {#phase-2-initial-scaffold}

**Date:** 2026-06-20  
**Commit:** `298a454 feat: initial scaffold — hybrid Semgrep + Claude SAST triage pipeline`

### Prompt sequence

> "yes — can you create a new repo or shall I?" → user created the repo → "the repo is created"

### Artifacts produced

| File | Purpose |
|---|---|
| `scanner/schema.py` | `Finding` dataclass — canonical output schema; `SEVERITY_RANK` and `CATEGORY_MAP` for routing |
| `scanner/adapters/semgrep.py` | Semgrep runner — builds config args, runs subprocess, extracts 30-line context windows, returns `Finding` list |
| `scanner/agents/triage.py` | Generic adversarial Claude triage agent — batched with `ThreadPoolExecutor`; 3-attempt retry on rate limits |
| `scanner/agents/specialized.py` | 5 domain-specific agents with tighter system prompts: injection, secrets, crypto, access-control, xss |
| `scanner/output/reporter.py` | Terminal summary with suppression rate; JSON export (full audit trail); SARIF 2.1.0 export (GitHub Code Scanning) |
| `scanner/run.py` | CLI orchestrator — `--target`, `--dry-run`, `--specialist`, `--severity`, `--output-json`, `--output-sarif` |
| `scanner/rules/python-injection.yaml` | Custom Semgrep rules: SQL injection via `%`, `.format()`, f-strings; `subprocess shell=True`; `os.system()`; path traversal |
| `scanner/rules/secrets.yaml` | Custom Semgrep rules: hardcoded passwords, AWS key pattern, PEM private key material |
| `scanner/rules/crypto.yaml` | Custom Semgrep rules: MD5, SHA-1, AES-ECB, weak PRNG |
| `.github/workflows/sast.yml` | GitHub Actions workflow — runs on every PR; uploads SARIF to GitHub Code Scanning; saves findings as artifact |
| `tests/fixtures/vulnerable.py` | Test fixture with 4 deliberate vulnerabilities for end-to-end pipeline testing |
| `requirements.txt` | `anthropic>=0.30.0`, `semgrep>=1.70.0` |
| `.semgrepignore` | Excludes `node_modules/`, `__pycache__/`, `outputs/` — scans everything else |

### Architecture

```
[Source Code]
     │
     ▼
[Semgrep AST scan]  ←── custom YAML rules + registry packs
     │
     │  Finding objects (pre-triage)
     ▼
[Severity filter]   ←── --severity flag (default: medium)
     │
     ▼
[Claude triage]     ←── generic agent OR specialist by category
     │
     │  TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
     ▼
[Reporter]          ←── terminal summary + JSON + SARIF
```

---

## Phase 3: Debugging and End-to-End Verification {#phase-3-debugging-and-verification}

**Date:** 2026-06-20  
**Commits:** `bf225cd`, `fee2481`, `a47a9ac`, `149aad1`

### Bugs encountered and fixed

#### Bug 1 — Semgrep rule YAML syntax (commit `bf225cd`)
**Symptom:** 0 findings on known-vulnerable fixture.  
**Cause:** The SQL injection pattern `cursor.execute($SQL % ...)` used Semgrep metavariable syntax that didn't match the fixture's string formatting style.  
**Fix:** Rewrote rules using `"..." % ...` pattern form and tested each rule individually with `semgrep --config rule.yaml file.py` before integrating.

#### Bug 2 — Wrong git context in subprocess (commit `bf225cd`)
**Symptom:** Semgrep reported "Scanning 0 files" when called via subprocess.  
**Cause:** `subprocess.run()` inherited the calling process's working directory (PaC repo), so Semgrep's `git ls-files` returned nothing for sast-triage files.  
**Fix:** Added `cwd=abs_target` to the subprocess call so Semgrep uses the correct git context.

#### Bug 3 — Relative config paths breaking with `cwd` (commit `fee2481`)
**Symptom:** Still 0 findings after Bug 2 fix — config files not found.  
**Cause:** Custom rule file paths like `scanner/rules/python-injection.yaml` were passed as relative paths, but with `cwd=tests/fixtures` they resolved to `tests/fixtures/scanner/rules/...` which doesn't exist.  
**Fix:** `os.path.abspath()` applied to all custom rule file paths before building the subprocess command. Target path also resolved to absolute; subprocess passes `"."` as the scan target.

#### Bug 4 — Registry packs failing silently (commit `bf225cd`)
**Symptom:** 0 findings when default rules (`p/python`, `p/secrets`) combined with custom rules.  
**Cause:** Registry packs require a Semgrep login/network call. In offline or unauthenticated environments they fail silently, returning 0 results.  
**Fix:** Default registry packs are now skipped when custom rule files are provided. Registry packs remain available via explicit `--rules` flag.

#### Bug 5 — `temperature` deprecated for `claude-opus-4-8` (commit `a47a9ac`)
**Symptom:** All triage calls returned ERROR with `"'temperature' is deprecated for this model"`.  
**Cause:** `claude-opus-4-8` does not accept the `temperature` parameter.  
**Fix:** Removed `temperature=0.0` from all `client.messages.create()` calls in both `triage.py` and `specialized.py`.

#### Bug 6 — API key not available to subprocess spawned by Flask
**Symptom:** Triage errors with "Could not resolve authentication method" when run from dashboard.  
**Cause:** Flask server started without `ANTHROPIC_API_KEY` in its environment; the key was in `~/.zshrc` but not loaded before the server started.  
**Fix:** Documented startup procedure: `source ~/.zshrc && python3 pac_api.py`. The key is passed through `os.environ` to the scanner subprocess.

### Verification

```bash
# Dry run — Semgrep only, confirms 2 findings in fixture
python3 -m scanner.run \
  --target tests/fixtures \
  --custom-rules scanner/rules/python-injection.yaml \
               scanner/rules/secrets.yaml \
               scanner/rules/crypto.yaml \
  --dry-run --severity low

# Full run with Claude triage
python3 -m scanner.run \
  --target tests/fixtures \
  --custom-rules scanner/rules/python-injection.yaml \
               scanner/rules/secrets.yaml \
               scanner/rules/crypto.yaml \
  --specialist

# Expected result:
#   TRUE_POSITIVE:   1  (SQL injection — raw-sql-string-format, line 10)
#   FALSE_POSITIVE:  1  (MD5 weak hash — correctly suppressed as non-security cache key)
#   Suppression:    50%
```

### Claude's triage reasoning (SQL injection, confirmed TRUE_POSITIVE)

> *"The username parameter flows directly into cursor.execute() via Python's '%s' % username string formatting operator at line 10. There is no sanitization, escaping, or allow-list validation between the source (function argument username) and the sink (cursor.execute). This is a textbook CWE-89 SQL injection. The correct fix is to use a parameterized query: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))."*

### Claude's triage reasoning (MD5, confirmed FALSE_POSITIVE)

> *"MD5 is used here to generate a cache key from data, not for any security-sensitive purpose such as password hashing or integrity verification. An attacker cannot exploit weak collision resistance in a caching context. This is a FALSE_POSITIVE."*

---

## Phase 4: PaC Dashboard Integration {#phase-4-pac-dashboard-integration}

**Date:** 2026-06-20

### Prompt sequence

> "Can we add a command to run the scan to this page: http://localhost:8000/"

> "yes" [to fix rule ID display and typo]

### What was built

Added a **SAST Triage** card to the PaC dashboard (`pac_api.py`) with:
- One-click **Run SAST Scan →** button
- Inline display of confirmed vulnerabilities with severity, rule ID, file path, and Claude's reasoning
- Status line: confirmed count + suppression count, color-coded (green = clean, red = vulnerabilities found)
- "Last run" timestamp

Added `/sast/run` POST endpoint to `pac_api.py`:
- Spawns `python3 -m scanner.run` as a subprocess with `PYTHONPATH` and `ANTHROPIC_API_KEY` passed through
- Parses `outputs/sast-latest.json` for results
- Returns JSON: `{confirmed, suppressed, needs_review, errors, total, summary, ran_at}`
- 120-second timeout

### Key fixes during integration

| Issue | Fix |
|---|---|
| Rule ID showing full dotted path (`Users.susanphillips.sast-triage.scanner.rules.raw-sql-string-format`) | `.split('.')[-1]` in the summary formatter |
| Typo "vulnerabilityy" in status message | Fixed ternary: `'vulnerabilities' : 'vulnerability'` |
| Neo4j connection error on digest variants | `NEO4J_BOLT=bolt://localhost:7687` env var — default was `bolt://neo4j:7687` (Docker hostname) |

### Startup procedure (required after this phase)

```bash
# Kill any existing server, load env vars, start fresh
lsof -ti :8000 | xargs kill -9
source ~/.zshrc   # loads ANTHROPIC_API_KEY and NEO4J_BOLT
cd ~/Applications/PaC
python3 pac_api.py
```

---

## Design Principles

1. **Semgrep filters, Claude decides.** Running an LLM on raw source is expensive and noisy. Semgrep handles structural matching in milliseconds for free; Claude only sees the flagged snippets.

2. **Adversarial inversion.** Claude is not asked "is this a bug?" — it's asked "can an attacker exploit this?" That inversion suppresses hallucination and forces logical code evaluation.

3. **Narrow agents, cleaner signal.** The `--specialist` flag routes each finding to a domain-specific agent (injection / secrets / crypto / access-control / xss) with a tighter system prompt. Narrower context = fewer false triage decisions.

4. **Full audit trail.** Every finding — including FALSE_POSITIVE decisions and reasoning — is written to JSON. This is the compliance evidence that the AI triage layer is operating correctly.

5. **SARIF for CI.** Confirmed findings are emitted as SARIF 2.1.0, accepted natively by GitHub Code Scanning. No additional tooling needed to surface findings as PR annotations.

6. **Producer/consumer separation.** sast-triage produces findings. PaC consumes them. The interface is a JSON file (or future `ingest/vuln/adapters/semgrep.py` adapter). Neither repo depends on the other's internals.
