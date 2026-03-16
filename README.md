# vantyr

[![npm version](https://img.shields.io/npm/v/@gianmarcomaz/vantyr?style=flat-square&color=black&label=vantyr)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
[![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![zero telemetry](https://img.shields.io/badge/telemetry-zero-black?style=flat-square)](https://github.com/gianmarcomaz/vantyr)

Zero-telemetry static security scanner and trust-certification CLI for MCP (Model Context Protocol) server implementations. Runs 6 context-aware analyzers against any GitHub repository or local AI configuration files, returning a weighted **Trust Score (0–100)**, a per-category scorecard, and actionable remediation guidance — entirely offline.

Research indicates 37% of published agent skills contain security flaws and 43% of tested MCP servers allow command injection. vantyr requires no account, no cloud service, and no internet connection beyond fetching the repository you ask it to scan.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [CLI Flags](#3-cli-flags)
4. [How It Works](#4-how-it-works)
5. [Security Analyzers](#5-security-analyzers)
6. [Scoring Model](#6-scoring-model)
7. [Trust Labels and Exit Codes](#7-trust-labels-and-exit-codes)
8. [Suppressing False Positives](#8-suppressing-false-positives)
9. [Output Formats](#9-output-formats)
10. [CI/CD Integration](#10-cicd-integration)
11. [GitHub Action](#11-github-action)
12. [Local Scan Mode](#12-local-scan-mode)
13. [Supported Languages and File Types](#13-supported-languages-and-file-types)
14. [Constraints and Limitations](#14-constraints-and-limitations)
15. [Out of Scope](#15-out-of-scope)
16. [Certified by Vantyr](#16-certified-by-vantyr)
17. [License](#17-license)

---

## 1. Installation

| Method | Command |
|---|---|
| Zero-install (recommended) | `npx -p @gianmarcomaz/vantyr@latest vantyr scan <url>` |
| Global install | `npm install -g @gianmarcomaz/vantyr` |

The `-p` flag is required for scoped packages — it tells npx which package to install before invoking the `vantyr` command. Always pin `@latest` to ensure you run the most recent version without a local install.

Requires Node.js >= 18.

---

## 2. Quick Start

```bash
# Zero-install — works on any machine with Node.js, no prior setup required
npx -p @gianmarcomaz/vantyr@latest vantyr scan https://github.com/lharries/whatsapp-mcp

# Scan a private repository
npx -p @gianmarcomaz/vantyr@latest vantyr scan https://github.com/owner/repo --token <github-pat>

# Scan local MCP configuration files
npx -p @gianmarcomaz/vantyr@latest vantyr scan --local

# Machine-readable output for pipelines
npx -p @gianmarcomaz/vantyr@latest vantyr scan https://github.com/owner/repo --json
```

If you installed globally (`npm install -g @gianmarcomaz/vantyr`), replace the npx prefix with just `vantyr scan ...`.

GitHub limits unauthenticated requests to 60/hour. A Personal Access Token raises this to 5,000/hour and unlocks private repo access. Generate one at [github.com/settings/tokens](https://github.com/settings/tokens) with read-only `Contents` scope.

---

## 3. CLI Flags

```
vantyr scan [url] [options]
```

| Flag | Description |
|---|---|
| `[url]` | GitHub repository URL. `.git` suffixes and `/tree/...` or `/blob/...` paths are stripped automatically. |
| `--token <pat>` | GitHub PAT for private repositories and higher rate limits. |
| `--local` | Scan local MCP config files instead of a GitHub repository. |
| `--json` | Emit structured JSON to stdout; suppress all other output. Mutually exclusive with `--sarif`. |
| `--sarif` | Emit SARIF 2.1.0 to stdout for GitHub Code Scanning. Mutually exclusive with `--json`. |
| `--verbose` | List every scanned file path before results. Terminal mode only. |

---

## 4. How It Works

vantyr is a pure static analyzer. It does not execute code or require a running MCP environment.

| Step | Description |
|---|---|
| 1. File acquisition | Fetches up to 100 files (≤ 100 KB each) via the GitHub Contents API. Skips `node_modules`, `dist`, `.git`, `vendor`, `__pycache__`, and similar generated directories. |
| 2. Six analyzers | Each analyzer runs independently and returns findings with `category`, `severity`, `file`, `line`, `snippet`, `message`, and `remediation`. |
| 3. Suppression | Findings whose flagged line (or the line immediately above) contains `// vantyr-ignore` or `# vantyr-ignore` are removed before scoring. |
| 4. Trust Score | Each category starts at 100; findings deduct points by severity. A weighted average produces the final score. A **hard cap of 75** applies when any HIGH or CRITICAL finding is present. |
| 5. Output | Results render to terminal, or serialize to JSON or SARIF depending on active flags. |

---

## 5. Security Analyzers

Each category starts at 100. Expand a section to see full detection logic, severity tables, and edge-case handling.

<details>
<summary><strong>NE — Network Exposure &nbsp;|&nbsp; weight: 15%</strong></summary>

Detects wildcard interface bindings and unencrypted external communication.

**Wildcard bindings detected:**

| Language | Pattern |
|---|---|
| JS/TS | `.listen('0.0.0.0')`, `.listen('::')`, `host: '0.0.0.0'`, `host: ''` (empty resolves to all interfaces) |
| Python | `.bind(('0.0.0.0', ...))`, `.bind(('::', ...))` |
| Go | `net.Listen(...)` containing `0.0.0.0` |
| All | `INADDR_ANY` |

Safe bindings (`127.0.0.1`, `localhost`, `::1`) on the same line suppress the finding.

**Unencrypted communication:**

| Pattern | Severity |
|---|---|
| Plain `http://` to external host | HIGH |
| Plain `ws://` to external host | HIGH |
| Dynamically constructed `http://`/`ws://` via template literal | MEDIUM |
| `host` set from `process.env` or config object | MEDIUM |

**Context-aware severity for wildcard bindings:**

| Context | Severity |
|---|---|
| No authentication detected in file or directory | CRITICAL |
| Webhook or bot file (Slack Bolt, Twilio, WhatsApp, etc.) | MEDIUM |
| Authentication middleware detected | LOW |

Auth detection covers 30+ patterns: `jwt.verify`, `passport.`, `@requires_auth`, `BasicAuth`, `BearerAuth`, `OAuth`, `signing_secret`, `req.headers.authorization`, `['Authorization']`, `['X-API-Key']`, and framework patterns from FastAPI, Flask, Next.js, Clerk, Supabase, and Firebase.

Skips test files, CLI/build paths (`cmd/`, `scripts/`, `bin/`), and comment lines.

</details>

<details>
<summary><strong>CI — Command Injection &nbsp;|&nbsp; weight: 20%</strong></summary>

Detects shell execution calls that could allow RCE via LLM-controlled input.

**Tracked functions by language:**

| Language | Function | Shell-based |
|---|---|---|
| JS/TS | `exec`, `execSync`, `eval`, `new Function()`, `vm.runIn*Context()` | Yes |
| JS/TS | `execFile`, `execFileSync`, `spawn`, `spawnSync` | No |
| Python | `os.system()`, `os.popen()`, `commands.getoutput()`, `exec()`, `eval()` | Yes |
| Python | `subprocess.run/Popen/call/check_output/check_call` | Conditional (`shell=True`) |
| Go | `exec.Command()` | No — args passed directly to OS, no shell |

**Import alias bypass detection:** Per-file scan for `import subprocess as sp`, `from subprocess import run`, `const cp = require('child_process')`, and `import * as cp from 'child_process'`. Dynamic regex patterns are generated for each alias found, preventing alias-based bypasses.

**Severity decision (ordered):**

| Priority | Condition | Severity |
|---|---|---|
| 1 | Test file | Skipped |
| 2 | Import/require declaration | Skipped |
| 3 | Go `exec.Command` with literal binary | Skipped |
| 4 | Go `exec.Command` with dynamic binary | HIGH |
| 5 | Install-time script, literal arg | LOW |
| 6 | Install-time script, dynamic arg | MEDIUM |
| 7 | CLI tool path, literal arg | LOW |
| 8 | CLI tool path, dynamic arg | MEDIUM |
| 9 | Production, literal arg | LOW |
| 10 | Production, shell metacharacters in literal (`&`, `\|`, `;`, `<`, `>`) | CRITICAL |
| 11 | Production, dynamic arg, shell-based function | CRITICAL |
| 12 | Production, dynamic arg, non-shell function | HIGH |

Locally-defined string constants (`const CMD = 'git status'`) used as arguments are treated as literals, not dynamic values.

</details>

<details>
<summary><strong>CL — Credential Leaks &nbsp;|&nbsp; weight: 25%</strong></summary>

Detects hardcoded secrets in source code. Highest-weighted category.

**10 secret patterns:**

| Pattern | Detection Rule | Default Severity |
|---|---|---|
| Generic API Key | `api_key`/`token`/`secret`/`password` assigned a 20+ char value | HIGH |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | CRITICAL |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub OAuth Token | `gho_[A-Za-z0-9]{36}` | CRITICAL |
| JWT String | `eyJ...` three-part base64url token | CRITICAL |
| JWT/Bearer Assignment | `jwt`/`bearer` variable assigned 10+ char string | HIGH |
| Database URL | `mongodb://user:pass@`, `postgres://user:pass@`, `mysql://`, `redis://` | CRITICAL |
| Private Key Header | `-----BEGIN [RSA/EC/DSA/OPENSSH] PRIVATE KEY-----` | CRITICAL |
| Slack Token | `xox[bpors]-...` | HIGH |
| Stripe Live Key | `sk_live_[A-Za-z0-9]{24,}` | CRITICAL |

Stripe test keys (`sk_test_...`) are INFO — they do not grant live payment access.

**False positive mitigation (applied before reporting):**

- Placeholder values (`YOUR_API_KEY`, `xxx`, `changeme`, `<token>`, `dummy`, `sample`, etc.) downgrade severity to INFO.
- Test file paths (`test`, `spec`, `mock`, `fixture`, `example`, `template`) reduce severity by one level.
- `process.env['VAR']` and `os.environ['VAR']` lookups are skipped entirely.

**Project-level checks:**

- No `.gitignore` present: LOW
- `.gitignore` missing `.env`, `*.key`, or `*.pem`: LOW
- Committed `.env` files (`.env`, `.env.local`, `.env.production`, `.env.development`): HIGH

</details>

<details>
<summary><strong>TP — Tool Poisoning &nbsp;|&nbsp; weight: 15%</strong></summary>

Detects prompt injection payloads in MCP tool descriptions. Files without a recognized tool registration pattern are skipped entirely. Duplicate descriptions extracted by overlapping patterns are deduplicated before analysis.

**Injection patterns:**

| Pattern | Severity |
|---|---|
| `ignore previous/above/all`, `disregard previous/all/earlier` | CRITICAL |
| `you are now [persona]` (excludes benign status words: `connected`, `ready`, `running`, `active`, etc.) | CRITICAL |
| `system prompt`, `instructions override`, `forget everything/all/previous` | CRITICAL |
| Zero-width or direction-override Unicode (U+200B, U+200C, U+200D, U+202E, U+FEFF) | CRITICAL |
| HTML comments `<!-- ... -->` | CRITICAL |
| `you must always`, `you should never` (behavioral mandates) | HIGH |
| HTML or XML tags in description | MEDIUM |
| Description length exceeds 1,000 characters | MEDIUM |
| Base64-encoded string (40+ characters) in description | MEDIUM |
| Cross-tool invocation instructions | INFO |

**Tool name shadowing (HIGH):** Names matching `read_file`, `write_file`, `execute_command`, `run_script`, `sudo`, `eval`, `system`, `fetch_url`, `http_get`, `fs_read`, or `fs_write` are flagged — these shadow well-known system primitives and may mislead the LLM.

</details>

<details>
<summary><strong>SC — Spec Compliance &nbsp;|&nbsp; weight: 10%</strong></summary>

Validates MCP protocol conformance across JS/TS, Python, and Go SDKs. Violations indicate an incomplete implementation likely to behave unpredictably with MCP clients.

| Check | Fail Condition | Severity |
|---|---|---|
| Server name/version | Not declared in server initialization | MEDIUM |
| Capabilities | No `capabilities:` / `setCapabilities()` / `ServerCapabilities` | LOW |
| MCP SDK | No `@modelcontextprotocol/sdk`, `mcp-python`, `mcp-go`, or `protocolVersion` | MEDIUM |
| Tool definitions | No tool registration pattern found | MEDIUM |
| Input schema | Tool definitions present but no `inputSchema`/`parameters` | MEDIUM |
| Schema type | Input schema missing top-level `"type": "object"` | MEDIUM |
| Error handling | No try/catch, `if err != nil`, or error handler | MEDIUM |
| Silent errors | Empty catch block or bare `except Exception: pass` | LOW |
| JSON-RPC errors | No `JsonRpcError`, `McpError`, or error code pattern | LOW |
| HTTP transport auth | HTTP transport without authentication middleware | HIGH |
| README | No `README.md` found | LOW |
| Empty descriptions | `description: ''` detected | LOW |

</details>

<details>
<summary><strong>IV — Input Validation &nbsp;|&nbsp; weight: 15%</strong></summary>

Detects tool input flowing unsanitized into dangerous sinks. Shell execution patterns are excluded to avoid overlap with CI.

**Tracked input variable names:** `args`, `params`, `input`, `validatedArgs`, `toolInput`, `userInput`, `llmInput`, `request`, `body`, `payload`, `data`, `parsed`, `toolArgs`, `callArgs`, `handlerArgs`

**Dangerous sinks:**
- **File:** `readFile`, `readFileSync`, `writeFile`, `writeFileSync`, `createReadStream`, `createWriteStream`, `appendFile`, Python `open()`, template literals containing `args.*`
- **Network:** `fetch`, `axios`, `got`, `request`, `http.get`, `https.get`, `urllib.request`, template literals containing `args.*`
- **SQL:** Template literals or string concatenation in `.query()` or `execute()` calls

**15-line upstream context window — severity by existing protection:**

| File sink context | Severity |
|---|---|
| `path.resolve()` + `.startsWith(allowedDir)` | SAFE |
| `path.resolve()` without `.startsWith()` | MEDIUM |
| `path.join()` without `.startsWith()` | MEDIUM |
| Type validation (Zod/Joi) only | MEDIUM |
| No validation | HIGH |

| Network sink context | Severity |
|---|---|
| `new URL()` + allowlist check | SAFE |
| Allowlist check only | SAFE |
| `new URL()` without allowlist | MEDIUM |
| No validation | HIGH |

| SQL sink context | Severity |
|---|---|
| Type validation present | HIGH (type checks do not prevent SQL injection) |
| No validation | CRITICAL |

**Additional checks:**
- Dynamic dispatch `handlerMap[args.action](...)`: HIGH
- `args[someVar]` in tool handler without type validation: MEDIUM
- `...args` spread in tool handler without type validation: LOW
- No `inputSchema` anywhere in codebase: HIGH (project-level finding)

</details>

---

## 6. Scoring Model

**Per-finding deductions (applied independently to each category):**

| Severity | Deduction |
|---|---|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -5 |
| LOW | -3 |
| INFO | 0 |

Deductions stack and the floor is 0. Four CRITICAL findings in one category score `max(0, 100 - 100) = 0`.

**Weighted average (OWASP-aligned):**

| Category | Code | Weight | OWASP Reference |
|---|---|---|---|
| Credential Leaks | CL | 25% | MCP01 — highest impact |
| Command Injection | CI | 20% | MCP05 — RCE via LLM input |
| Network Exposure | NE | 15% | MCP07 — unauthorized access |
| Input Validation | IV | 15% | SSRF, path traversal, SQLi |
| Tool Poisoning | TP | 15% | MCP03 — prompt injection |
| Spec Compliance | SC | 10% | Protocol hygiene |

```
TrustScore = round(CL×0.25 + CI×0.20 + NE×0.15 + IV×0.15 + TP×0.15 + SC×0.10)
```

**Circuit Breaker:** **Any HIGH or CRITICAL finding hard-caps the Trust Score at 75**, making `CERTIFIED` impossible regardless of other category scores. Resolving all HIGH and CRITICAL findings removes the cap. The `scoreCapped: true` flag is set in JSON and SARIF output when the cap is active.

A category is considered passing if its score is 80 or above.

---

## 7. Trust Labels and Exit Codes

| Score | Label | Exit Code | Meaning |
|---|---|---|---|
| 80–100 | CERTIFIED | 0 | No HIGH or CRITICAL findings. All major checks pass. |
| 50–79 | WARNING | 0 | Issues present. Resolve before production deployment. |
| 0–49 | FAILED | 1 | Serious vulnerabilities present. CI/CD pipeline fails. |

A score of exactly 75 (from the circuit breaker) always produces WARNING, never CERTIFIED.

---

## 8. Suppressing False Positives

Place `// vantyr-ignore` (JS/TS/Go) or `# vantyr-ignore` (Python/YAML) on the flagged line or the line immediately above it.

```javascript
// vantyr-ignore
const host = "0.0.0.0"; // intentional — service runs behind a corporate VPN
```

```python
cmd = build_deploy_command()  # vantyr-ignore
os.system(cmd)
```

Suppression applies to exactly one finding at one location. It does not suppress other findings in the same file or category. Suppression is applied after all analyzers complete — it does not affect how analyzers run.

Project-level findings (no line number, file reported as `project`) cannot be suppressed with inline comments. Fix the underlying issue instead.

---

## 9. Output Formats

### Terminal (default)

Color-coded scorecard with per-category breakdown, a remediation list sorted by severity, and a summary line. Add `--verbose` to list every scanned file path.

```
Vantyr — Trust Score: 61/100  WARNING

  Network Exposure      — 100/100
  Command Injection     — 100/100
  Credential Leaks      —  70/100  (2 findings)
  Tool Poisoning        — 100/100
  Spec Compliance       —  85/100  (1 finding)
  Input Validation      — 100/100

Remediations:

  [HIGH] [Credential Leaks] Line 12 in config.js
    Generic API Key detected.
    Remove hardcoded credentials and use environment variables instead.

Scanned: https://github.com/owner/repo
Checks: 6 | Critical: 0 | High: 1 | Medium: 1 | Low: 0 | Pass: 4/6
```

### JSON (`--json`)

Structured output for pipelines and dashboards. All terminal output is suppressed.

```bash
vantyr scan https://github.com/owner/repo --json | jq '.trustScore'
```

```json
{
  "source": "https://github.com/owner/repo",
  "trustScore": 61,
  "label": "WARNING",
  "scoreCapped": false,
  "categories": {
    "CL": { "score": 70, "passed": false, "findingCount": 2, "findings": [] }
  },
  "stats": { "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0 },
  "passCount": 5,
  "totalFindings": 3,
  "findings": [
    { "category": "CL", "severity": "high", "file": "src/config.js", "line": 12,
      "snippet": "...", "message": "...", "remediation": "..." }
  ]
}
```

### SARIF (`--sarif`)

SARIF 2.1.0 output for GitHub Code Scanning. Severity mapping: `CRITICAL/HIGH` → `error`, `MEDIUM` → `warning`, `LOW/INFO` → `note`. Each result includes `ruleId`, `physicalLocation`, `trustScore`, and `scoreCapped` in its property bag.

---

## 10. CI/CD Integration

**Basic exit code gate:**

```yaml
- run: npx @gianmarcomaz/vantyr scan ${{ github.event.repository.html_url }}
```

Fails the step (exit code 1) when Trust Score < 50.

**GitHub Code Scanning with inline PR annotations:**

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run vantyr
        run: npx @gianmarcomaz/vantyr scan ${{ github.event.repository.html_url }} --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

**Private repository scanning:**

```yaml
- run: npx @gianmarcomaz/vantyr scan ${{ github.event.repository.html_url }} --token ${{ secrets.VANTYR_TOKEN }}
```

**Custom score threshold:**

```bash
SCORE=$(npx @gianmarcomaz/vantyr scan https://github.com/owner/repo --json | jq '.trustScore')
[ "$SCORE" -lt 80 ] && echo "Score $SCORE is below CERTIFIED threshold" && exit 1
```

---

## 11. GitHub Action

The Vantyr GitHub Action wraps the CLI scanner to provide native GitHub integration: SARIF upload to the Security tab, a PR comment with the Trust Score and category breakdown, and a configurable pass/fail status check.

**Add to your repository at `.github/workflows/vantyr.yml`:**

```yaml
name: MCP Security Scan
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  vantyr-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Vantyr MCP Security Scan
        uses: gianmarcomaz/vantyr@v1
        with:
          threshold: 70
```

**Action inputs:**

| Input | Default | Description |
|---|---|---|
| `target` | Current repo | GitHub URL to scan. Defaults to the repository running the workflow. |
| `threshold` | `70` | Minimum Trust Score to pass the status check. Set to `0` to never fail. |
| `post-comment` | `true` | Post a PR comment with score and findings. Comment is updated on re-push, never duplicated. |
| `upload-sarif` | `true` | Upload `vantyr-results.sarif` to GitHub Code Scanning for inline PR annotations. |
| `token` | `GITHUB_TOKEN` | GitHub token for API access. The built-in `GITHUB_TOKEN` is used automatically. |

**What the Action does on each PR push:**

1. Fetches the repository source and runs all 6 analyzers
2. Writes `vantyr-results.sarif` — picked up by the `upload-sarif` step to populate the Security tab with per-file, per-line annotations
3. Posts (or updates) a PR comment with the Trust Score, category scorecard, findings summary, and a badge snippet to copy
4. Exits with code 1 if the Trust Score is below `threshold`, which blocks merge on protected branches

**Scanning an external repository:**

```yaml
- uses: gianmarcomaz/vantyr@v1
  with:
    target: https://github.com/some-org/their-mcp-server
    threshold: 80
    post-comment: false
```

---

## 12. Local Scan Mode

`vantyr scan --local` reads MCP configuration and AI rules files from standard paths on your machine. No GitHub URL required.

| File | Platform |
|---|---|
| `~/.cursor/mcp.json` | All |
| `~/.codeium/windsurf/mcp_config.json` | All |
| `~/Library/Application Support/Claude/claude_desktop_config.json` | macOS |
| `%APPDATA%\Claude\claude_desktop_config.json` | Windows |
| `.vscode/mcp.json`, `.cursor/mcp.json` | Project-level |
| `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `copilot-instructions.md` | Project-level |

Local mode scans the configuration files themselves. It does not follow `command` entries in MCP configuration to scan the referenced server source code on disk. To scan a referenced server, pass its GitHub URL as a separate scan.

---

## 13. Supported Languages and File Types

| Type | Extensions |
|---|---|
| Source code (all six analyzers) | `.js` `.jsx` `.mjs` `.cjs` `.ts` `.tsx` `.py` `.go` `.rs` |
| Configuration files (credential + structural checks) | `.json` `.yaml` `.yml` `.toml` `.md` `.sh` `.bash` `.zsh` `.env` |
| Always skipped | Binaries, images, compiled artifacts, files > 100 KB |

---

## 14. Constraints and Limitations

| Constraint | Detail |
|---|---|
| File cap | 100 files per scan. Large repositories show a warning; unanalyzed files may inflate the score. |
| File size cap | Files > 100 KB skipped. Minified and bundled files are not meaningful static analysis targets. |
| Static analysis only | Runtime vulnerabilities (race conditions, insecure deserialization, timing attacks) are not detectable. |
| 15-line context window | IV's upstream validation check is limited to 15 lines. Checks placed further above a sink are not detected. |
| Single-file alias detection | CI alias detection is per-file. Cross-file aliases (defined in one file, used in another) are not caught. |
| No interprocedural analysis | IV does not track data flow across function call boundaries. |
| Pattern-based tool detection | TP only analyzes files matching known SDK registration patterns. Custom frameworks may not be detected. |

---

## 15. Out of Scope

| Vulnerability class | Recommended alternative |
|---|---|
| Dependency CVEs | `npm audit`, `pip-audit`, `govulncheck`, Dependabot |
| Runtime misconfigurations | Penetration testing, runtime security monitoring |
| Output sanitization / secondary injection | Semantic taint analysis, manual review |
| Authentication correctness | Auth-specific static analyzers, code review |
| Business logic vulnerabilities | Manual security review, threat modeling |
| Infrastructure security | Cloud security posture management (CSPM) tools |

---

## 16. Certified by Vantyr

If your MCP server scores **80 or above** (CERTIFIED), add the badge to your `README.md`:

[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)

```markdown
[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
```

With your score included (replace `92` with your actual score):

[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED%20%E2%80%94%2092%2F100-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)

```markdown
[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED%20%E2%80%94%2092%2F100-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
```

To verify a badge claim, anyone can run:

```bash
npx -p @gianmarcomaz/vantyr@latest vantyr scan https://github.com/owner/repo
```

---

## 17. License

MIT
