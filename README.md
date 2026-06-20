# sast-triage

Hybrid static application security testing (SAST) pipeline that combines deterministic AST analysis with Claude AI triage to eliminate false positives.

```
[Source Code] ──► [Semgrep AST] ──► [Findings] ──► [Claude Triage] ──► [Confirmed Vulns Only]
```

**The problem:** Commercial SAST tools are tuned for recall over precision — they flag everything that *might* be vulnerable. Teams waste hours manually reviewing false positives.

**The solution:** Run a fast, free AST scan to find structural matches, then route each flagged snippet to Claude acting as an adversarial auditor. Claude attempts to construct a concrete exploit. If it can't, the finding is suppressed.

## What's Inside

| File | Purpose |
|---|---|
| `scanner/schema.py` | `Finding` dataclass — canonical output from all adapters |
| `scanner/adapters/semgrep.py` | Semgrep adapter — runs scan, extracts context windows, returns `Finding` list |
| `scanner/agents/triage.py` | Generic Claude triage agent — adversarial verification, batched with concurrency |
| `scanner/agents/specialized.py` | Category-specialized agents (injection / secrets / crypto / access-control / xss) |
| `scanner/output/reporter.py` | Terminal summary, JSON export, SARIF export (GitHub Code Scanning) |
| `scanner/run.py` | CLI orchestrator |
| `scanner/rules/` | Custom Semgrep YAML rules (Python injection, secrets, crypto) |
| `.github/workflows/sast.yml` | GitHub Actions workflow — runs on every PR, uploads SARIF |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set API key (get one at https://console.anthropic.com → API Keys)
export ANTHROPIC_API_KEY="your-key-here"

# Scan with the bundled custom rules (no Semgrep login required)
python3 -m scanner.run --target ./src \
  --custom-rules scanner/rules/python-injection.yaml \
               scanner/rules/secrets.yaml \
               scanner/rules/crypto.yaml

# Dry run (Semgrep only, no Claude)
python3 -m scanner.run --target ./src --custom-rules scanner/rules/python-injection.yaml --dry-run

# Use category-specialized agents (higher accuracy)
python3 -m scanner.run --target ./src \
  --custom-rules scanner/rules/python-injection.yaml \
               scanner/rules/secrets.yaml \
               scanner/rules/crypto.yaml \
  --specialist

# Use Semgrep registry packs (requires `semgrep login`)
python3 -m scanner.run --target ./src --rules p/python p/secrets p/owasp-top-ten

# Export results
python3 -m scanner.run --target ./src \
  --custom-rules scanner/rules/python-injection.yaml \
  --output-json outputs/findings.json \
  --output-sarif outputs/results.sarif
```

> **Note on Semgrep registry packs** (`p/python`, `p/owasp-top-ten`, etc.): these require a free Semgrep account and `semgrep login`. The bundled `scanner/rules/` custom rules work offline with no login required. When `--custom-rules` is provided and `--rules` is not, registry packs are skipped automatically.

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--target` | `./src` | Directory to scan |
| `--rules` | `p/python p/secrets p/owasp-top-ten` | Semgrep registry rule packs |
| `--custom-rules` | — | Local Semgrep YAML rule files |
| `--languages` | all | Language filter (`python javascript java go`) |
| `--dry-run` | false | Run Semgrep only; skip Claude triage |
| `--specialist` | false | Route findings to category-specialized Claude agents |
| `--severity` | `medium` | Minimum severity to triage |
| `--output-json` | — | Write full results to JSON |
| `--output-sarif` | — | Write confirmed findings to SARIF (GitHub Code Scanning) |

## Architecture

### Why Semgrep first?

Running an LLM across an entire codebase is expensive and slow. Semgrep filters 99% of secure code in milliseconds for free, passing Claude only the specific lines that match a structural vulnerability pattern. This makes the pipeline fast enough to run on every PR.

### Why adversarial framing?

Claude is prompted to act as an attacker trying to *prove* the bug is exploitable — not to find bugs. If Claude can't construct a concrete exploit vector given the surrounding context (sanitizers, auth guards, static values), it classifies the finding as FALSE_POSITIVE. This inversion is what drives the suppression rate.

### Specialized agents

The `--specialist` flag routes each finding to a domain-specific agent with a tighter system prompt:

| Agent | Category | What it checks |
|---|---|---|
| Injection | `injection` | Source → sink taint path; parameterized query usage |
| Secrets | `secrets` | Real credential vs. placeholder/env var reference |
| Crypto | `crypto` | Key lengths, weak algorithms, ECB mode, PRNG quality |
| Access Control | `access-control` | Middleware guards, role checks, JWT validation |
| XSS | `xss` | Template auto-escaping, raw/safe bypasses |

### Output formats

- **Terminal:** human-readable summary with suppression rate and confirmed findings
- **JSON:** full audit trail including FALSE_POSITIVE reasoning (for compliance evidence)
- **SARIF:** GitHub Code Scanning format — only TRUE_POSITIVE findings; surfaces as PR annotations

## GitHub Actions

### Adding the API key secret

1. Go to your repository on GitHub
2. **Settings → Secrets and variables → Actions → New repository secret**
3. Name: `ANTHROPIC_API_KEY`, Value: your Anthropic API key
4. Click **Add secret**

The workflow will then have access to the key on every PR and push.

### What the workflow does

Once the secret is set, push to trigger it. The workflow runs on every PR:
1. Semgrep scans the repo
2. Claude triages findings at `--severity medium` and above
3. SARIF is uploaded to GitHub Code Scanning (appears as PR annotations)
4. Full JSON findings saved as a build artifact for 30 days

## Connecting to PaC

The PaC GRC platform (`localhost:8000`) includes a **SAST Triage** card on its dashboard that runs this scanner with one click and displays confirmed vulnerabilities inline. The `/sast/run` endpoint in `pac_api.py` spawns the scanner as a subprocess and returns results as JSON.

Confirmed findings can also be ingested into PaC's Neo4j graph via the `ingest/vuln/adapters/semgrep.py` adapter (forthcoming), linking SAST findings to asset nodes, NIST controls, and POA&M items.

**PaC startup (required for dashboard integration):**
```bash
source ~/.zshrc   # loads ANTHROPIC_API_KEY and NEO4J_BOLT
cd ~/Applications/PaC && python3 pac_api.py
```

## Build Playbook

Session-by-session record of how this project was designed and built, including architecture decisions, bugs encountered, and fixes applied: [`docs/build-playbook.md`](docs/build-playbook.md).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | required | Claude API key |
| `CLAUDE_MODEL` | `claude-opus-4-8` | Model to use for triage |
| `TRIAGE_CONCURRENCY` | `5` | Parallel Claude API calls |
| `TRIAGE_RETRY_SLEEP` | `2.0` | Seconds between rate-limit retries |
