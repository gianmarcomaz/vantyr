# vantyr

[![npm version](https://img.shields.io/npm/v/@gianmarcomaz/vantyr?style=flat-square&color=black&label=vantyr)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
[![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![zero telemetry](https://img.shields.io/badge/telemetry-zero-black?style=flat-square)](https://github.com/gianmarcomaz/vantyr)

Zero-telemetry, developer-first static security scanner and trust-certification CLI for Model Context Protocol (MCP) server implementations.

As the MCP ecosystem grows, security has become a critical bottleneck. Research indicates that nearly 37% of published agent skills contain security flaws, and up to 43% of tested MCP servers allow command injection. `vantyr` addresses this by providing a fully local, 100% offline vulnerability scanner that requires no account, no cloud service, and no internet connection beyond fetching the repository you ask it to scan.

`vantyr` performs static analysis on MCP server source code — either from a GitHub repository or from your local AI configuration files — and produces a weighted **Trust Score (0–100)** with a `CERTIFIED / WARNING / FAILED` label, per-finding remediation guidance, and machine-readable output for CI/CD integration.

All analysis is performed locally. No source code, findings, or metadata leave your machine. The only outbound network call is to the GitHub API when you explicitly pass a repository URL.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [All Commands and Flags](#3-all-commands-and-flags)
4. [How It Works — Architecture Overview](#4-how-it-works--architecture-overview)
5. [The Six Security Analyzers](#5-the-six-security-analyzers)
   - 5.1 [Network Exposure (NE)](#51-network-exposure-ne)
   - 5.2 [Command Injection (CI)](#52-command-injection-ci)
   - 5.3 [Credential Leaks (CL)](#53-credential-leaks-cl)
   - 5.4 [Tool Poisoning (TP)](#54-tool-poisoning-tp)
   - 5.5 [Spec Compliance (SC)](#55-spec-compliance-sc)
   - 5.6 [Input Validation (IV)](#56-input-validation-iv)
6. [Scoring Model](#6-scoring-model)
7. [Trust Labels and Exit Codes](#7-trust-labels-and-exit-codes)
8. [Suppressing False Positives](#8-suppressing-false-positives)
9. [Output Formats](#9-output-formats)
   - 9.1 [Terminal](#91-terminal)
   - 9.2 [JSON](#92-json)
   - 9.3 [SARIF (GitHub Code Scanning)](#93-sarif-github-code-scanning)
10. [CI/CD Integration](#10-cicd-integration)
11. [Local Scan Mode](#11-local-scan-mode)
12. [Supported Languages and File Types](#12-supported-languages-and-file-types)
13. [Technical Constraints and Limitations](#13-technical-constraints-and-limitations)
14. [What vantyr Does Not Cover](#14-what-vantyr-does-not-cover)
15. [Certified by Vantyr — Badge for Your Repository](#15-certified-by-vantyr--badge-for-your-repository)
16. [License](#16-license)

---

## 1. Installation

**Global install (recommended):**

```bash
npm install -g @gianmarcomaz/vantyr
```

After a global install, the `vantyr` command is available system-wide:

```bash
vantyr scan https://github.com/owner/repo
```

**Zero-install (npx):**

```bash
npx -p @gianmarcomaz/vantyr vantyr scan https://github.com/owner/repo
```

The `-p` flag is required for scoped packages — it tells npx which package to install before running the `vantyr` command.

Requires Node.js version 18 or higher.

---

## 2. Quick Start

**Zero-install trial with npx:**

```bash
npx -p @gianmarcomaz/vantyr vantyr scan https://github.com/owner/repo
```

**Or install once globally and use anywhere:**

```bash
npm install -g @gianmarcomaz/vantyr
vantyr scan https://github.com/owner/repo
```

**Scan a private repository or avoid rate limits:**

```bash
vantyr scan https://github.com/owner/repo --token <github-pat>
```

GitHub limits unauthenticated API requests to 60 per hour. Passing a Personal Access Token increases this to 5,000 per hour and enables access to private repositories. Generate a token at [github.com/settings/tokens](https://github.com/settings/tokens) — a fine-grained token with read-only `Contents` permission on the target repository is sufficient.

**Scan your local MCP configuration files:**

```bash
vantyr scan --local
```

**Output results as JSON for pipeline consumption:**

```bash
vantyr scan https://github.com/owner/repo --json
```

---

## 3. All Commands and Flags

The CLI exposes a single command: `scan`.

```
vantyr scan [url] [options]
```

| Flag | Type | Description |
|---|---|---|
| `[url]` | Positional argument | GitHub repository URL to scan. Accepts `.git` suffixes and `/tree/...` or `/blob/...` paths — these are stripped automatically. |
| `--token <pat>` | String | GitHub Personal Access Token. Required for private repositories. Increases the API rate limit from 60 to 5,000 requests per hour for authenticated users. |
| `--local` | Boolean | Scan local MCP configuration and AI rules files instead of a GitHub repository. The `[url]` argument is ignored when this flag is set. |
| `--json` | Boolean | Emit structured JSON to stdout and suppress all other output. Intended for programmatic consumption in pipelines. Mutually exclusive with `--sarif`. |
| `--sarif` | Boolean | Emit a SARIF 2.1.0 document to stdout. Intended for the GitHub `upload-sarif` action to populate the Security tab. Mutually exclusive with `--json`. |
| `--verbose` | Boolean | Print the path of every scanned file before showing results. Only active in terminal mode (ignored with `--json` or `--sarif`). |

---

## 4. How It Works — Architecture Overview

`vantyr` is a pure static analyzer. It does not execute any code, make requests to the scanned server, or require a running MCP environment.

The scan pipeline runs in the following sequence:

**Step 1 — File acquisition.** For GitHub scans, the GitHub Contents API is used to recursively fetch the repository file tree. Files are fetched up to a limit of 100 files per scan (configurable future work). Files larger than 100 KB are skipped. Directories excluded from scanning: `node_modules`, `dist`, `build`, `out`, `.git`, `vendor`, `__pycache__`, `.venv`, `coverage`, and `.nyc_output`. For local scans, files are read directly from disk from a set of well-known paths.

**Step 2 — Suppression pre-processing.** Not applicable at this stage. Suppression is applied after analysis (see Step 5).

**Step 3 — Six parallel analyzers.** Each of the six security analyzers receives the complete file list and returns an array of findings. Analyzers are independent — they share no state and do not communicate with each other. Each finding carries: `category`, `severity`, `file`, `line`, `snippet`, `message`, and `remediation`.

**Step 4 — Suppression post-processing.** After all analyzers complete, findings are filtered. Any finding whose flagged line, or the line immediately above it, contains a `// vantyr-ignore` or `# vantyr-ignore` comment is removed from the results before scoring.

**Step 5 — Trust Score calculation.** The filtered findings are grouped by category. Each category starts at 100 and deducts points per finding based on severity. A weighted average across the six categories produces the final Trust Score. A hard cap is applied if any HIGH or CRITICAL severity findings are present.

**Step 6 — Output rendering.** Results are rendered to the terminal, or serialized as JSON or SARIF depending on the active output flags.

---

## 5. The Six Security Analyzers

### 5.1 Network Exposure (NE)

**Purpose:** Identify MCP server deployments that are reachable by unauthorized network clients due to wildcard interface bindings or unencrypted external communication.

**What it checks:**

*Wildcard bindings.* The analyzer looks for server socket bindings on all network interfaces:

- JavaScript/TypeScript: `.listen('0.0.0.0')`, `.listen('::')`, `host: '0.0.0.0'`, `host: '::'`, `host: ''` (empty string, which resolves to all interfaces)
- Python: `.bind(('0.0.0.0', ...))`, `.bind(('::', ...))`
- Go: `net.Listen(...)` with `0.0.0.0`
- All languages: `INADDR_ANY`

Explicitly safe bindings (`127.0.0.1`, `localhost`, `::1`) on the same line suppress the finding.

*Unencrypted external communication.*

- Plain `http://` URLs referencing external hosts (not localhost/127.0.0.1/::1): severity HIGH
- Plain `ws://` WebSocket connections to external hosts: severity HIGH
- Dynamically constructed `http://` or `ws://` URLs using template literals: severity MEDIUM

*Host from environment or config.*

- `host: process.env.HOST` or similar dynamic host bindings: severity MEDIUM (may be safe or unsafe depending on deployment defaults)

**Context-awareness:**

The analyzer is not a naive pattern matcher. For every wildcard binding detected, it examines the same file and all files in the same directory for authentication context before assigning severity:

- Binding with NO authentication detected anywhere in the file or sibling files: severity CRITICAL
- Binding in a file identified as a webhook or bot receiver (by filename pattern or SDK import, e.g., Slack Bolt, Twilio): severity MEDIUM — webhook platforms use platform-side signature verification
- Binding WITH authentication middleware detected (JWT, OAuth, API key checking, `passport.js`, `flask_login`, `req.headers.authorization`, etc.): severity LOW

Authentication is detected by scanning for 30+ patterns including: `jwt.verify`, `passport.`, `@requires_auth`, `BasicAuth`, `BearerAuth`, `OAuth`, `signing_secret`, `hmac.`, `req.headers.authorization`, `['Authorization']`, `['X-API-Key']`, and framework-specific middleware patterns from FastAPI, Flask, Next.js, Clerk, Supabase, Firebase, and others.

**What it explicitly skips:**

- Test files (`__tests__/`, `*.test.js`, `*.spec.py`, `testdata/`, etc.)
- CLI and build tooling paths (`cmd/`, `cli/`, `scripts/`, `tools/`, `bin/`, `hack/`)
- Comment lines

---

### 5.2 Command Injection (CI)

**Purpose:** Detect shell execution calls that could allow an attacker (or a compromised LLM) to run arbitrary commands on the host system.

**What it checks:**

*JavaScript/TypeScript dangerous functions:*

| Function | Shell-based | Notes |
|---|---|---|
| `exec()`, `execSync()` | Yes | Passes command string through `/bin/sh` |
| `execFile()`, `execFileSync()` | No | Spawns directly, no shell |
| `spawn()`, `spawnSync()` | No | Spawns directly, no shell |
| `eval()` | Yes | Dynamic code execution |
| `new Function()` | Yes | Dynamic code execution |
| `vm.runInNewContext()`, `vm.runInThisContext()` | Yes | VM sandbox bypass |

*Python dangerous functions:*

| Function | Shell-based | Notes |
|---|---|---|
| `os.system()` | Yes | Always passes through shell |
| `os.popen()` | Yes | Always passes through shell |
| `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_output()`, `subprocess.check_call()` | Conditional | Shell-based only when `shell=True` is present on the same line |
| `commands.getoutput()` | Yes | Legacy, always shell-based |
| `exec()`, `eval()` | Yes | Dynamic code execution |

*Go:*

| Function | Shell-based | Notes |
|---|---|---|
| `exec.Command()` | No | Go does NOT use a shell — args are passed directly to the OS |

*Import aliases.* The analyzer performs per-file alias detection before scanning. If a file contains `import subprocess as sp`, it generates a dynamic pattern for `sp.run(...)`, `sp.Popen(...)`, etc. Similarly for `from subprocess import run`, `const cp = require('child_process')`, and `import * as cp from 'child_process'`. This prevents alias-based bypasses.

**Severity assignment per call site:**

For each dangerous function call found, severity is determined by the following ordered logic:

1. **Test files** — skipped entirely (not production code)
2. **Import/require declarations** — skipped (not actual calls)
3. **Go `exec.Command` with literal binary** — skipped (literal first argument, no shell, low risk)
4. **Go `exec.Command` with dynamic binary** — HIGH (CLI tool context) or MEDIUM (CLI tool context)
5. **Go `exec.Command` with spread args** — MEDIUM (binary is fixed, args are dynamic but no shell)
6. **Install-time scripts** (`preinstall.js`, `postinstall.js`, `setup.sh`, etc.) — LOW if argument is literal or local constant, MEDIUM if dynamic
7. **CLI tools** (`cmd/`, `cli/`, `scripts/`, `bin/`) — LOW if argument is literal, MEDIUM if dynamic
8. **Production code, literal argument** — LOW (command is fixed, not dynamic)
9. **Production code, shell metacharacters in literal** (`&`, `|`, `;`, `<`, `>`) — CRITICAL (explicit dangerous command in source)
10. **Production code, dynamic argument, shell-based function** — CRITICAL
11. **Production code, dynamic argument, non-shell function** — HIGH

A locally-defined constant (`const CMD = 'git status'`) used as the argument is treated as a literal, not as a dynamic argument. The analyzer tracks all `const/let/var = 'string literal'` assignments per file to detect this.

The analyzer also checks whether Python `subprocess` calls include `shell=True` on the same line, and upgrades severity accordingly.

---

### 5.3 Credential Leaks (CL)

**Purpose:** Detect secrets, tokens, and credentials committed to source code.

**The 10 secret patterns:**

| Pattern Name | Detection Rule | Severity |
|---|---|---|
| Generic API Key | Assignment of a 20+ character alphanumeric value to a variable named `api_key`, `token`, `secret`, `password`, `passwd`, or `pwd` | HIGH |
| AWS Access Key | String matching `AKIA[0-9A-Z]{16}` | CRITICAL |
| GitHub Token | String matching `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| GitHub OAuth Token | String matching `gho_[A-Za-z0-9]{36}` | CRITICAL |
| JWT String | Three-part dot-separated base64url token matching `eyJ...` header | CRITICAL |
| JWT/Bearer Assignment | Assignment of a 10+ character string to a variable named `jwt` or `bearer` | HIGH |
| Database URL with Password | Connection string matching `mongodb://user:pass@`, `postgres://user:pass@`, `mysql://user:pass@`, `redis://user:pass@` | CRITICAL |
| Private Key Header | PEM header `-----BEGIN [RSA/EC/DSA/OPENSSH] PRIVATE KEY-----` | CRITICAL |
| Slack Token | String matching `xox[bpors]-...` Slack token format | HIGH |
| Stripe Live Key | String matching `sk_live_[A-Za-z0-9]{24,}` | CRITICAL |

*Stripe test keys* (`sk_test_...`) are reported at INFO severity — they grant no access to live payment data.

**False positive mitigation:**

The analyzer applies two layers of false positive reduction before reporting a match:

1. **Placeholder detection.** If the matched string contains any of the following values, severity is downgraded to INFO: `YOUR_API_KEY`, `your_api_key`, `xxx`, `changeme`, `CHANGEME`, `<token>`, `<api_key>`, `TODO`, `FIXME`, `replace_me`, `placeholder`, `example`, `test_key`, `dummy`, `sample`.

2. **Test file detection.** Matches in files whose path contains `test`, `spec`, `mock`, `example`, `sample`, `template`, or `fixture` have their severity reduced by one level (CRITICAL becomes HIGH, HIGH becomes MEDIUM, etc.).

3. **Environment variable lookups.** Lines containing `process.env['VAR_NAME']` or `os.environ['VAR_NAME']` are skipped — these are lookups, not assignments of actual values.

**Project-level checks:**

Beyond line-by-line scanning, the analyzer checks two project-level conditions:

- If no `.gitignore` file is present: LOW finding ("secrets may be accidentally committed")
- If `.gitignore` exists but does not cover `.env`, `*.key`, or `*.pem`: LOW finding

Committed `.env` files (`.env`, `.env.local`, `.env.production`, `.env.development`) are flagged as HIGH regardless of their content.

---

### 5.4 Tool Poisoning (TP)

**Purpose:** Detect prompt injection payloads embedded in MCP tool descriptions. Tool descriptions are read by the LLM to decide when and how to use tools. Malicious content in descriptions can redirect the model's behavior without the user's knowledge.

**How it works:**

The analyzer first identifies files that contain tool definitions by scanning for SDK-specific patterns: `server.tool(`, `.addTool(`, `.add_tool(`, `tools: [`, `@server.tool`, `@mcp.tool`, `mcp.NewTool(`, `.AddTool(`, `RegisterTool`. Files without any tool definition pattern are skipped entirely.

For each file with tool definitions, description text is extracted using four patterns: `description: 'value'`, `description = 'value'`, Python triple-quoted docstrings (`"""..."""`), and Python single-quoted docstrings (`'''...'''`). Duplicate descriptions (produced by overlapping extraction patterns) are deduplicated before analysis.

**Injection pattern detection (applied to description text):**

| Pattern | Severity | What it catches |
|---|---|---|
| `ignore previous`, `ignore above`, `ignore all` | CRITICAL | Instruction override |
| `disregard previous`, `disregard all`, `disregard earlier` | CRITICAL | Instruction override |
| `you are now [persona]` | CRITICAL | Identity override — the negative lookahead excludes benign status phrases: `connected`, `logged`, `subscribed`, `available`, `ready`, `enabled`, `configured`, `running`, `serving`, `listening`, `active`, `online`, `offline`, `authenticated`, `authorized`, `processing`, `complete`, `done`, `finished`, `started`, `stopped` |
| `system prompt` | CRITICAL | Reference to system prompt |
| `instructions override` | CRITICAL | Explicit override language |
| `forget everything`, `forget all`, `forget previous` | CRITICAL | Memory reset attempt |
| Zero-width or direction-override Unicode characters (U+200B, U+200C, U+200D, U+202E, U+FEFF) | CRITICAL | Hidden instructions invisible to human reviewers |
| HTML comments `<!-- ... -->` | CRITICAL | Instructions hidden from users but visible to LLMs |
| `you must always`, `you should never` (behavioral mandates) | HIGH | Behavioral override (reduced from CRITICAL — legitimate verbose descriptions occasionally match this pattern) |
| HTML or XML tags in description | MEDIUM | Could hide content |
| `before using this tool, ...` | INFO | Cross-tool instruction |
| `first call / also execute / also run` | INFO | Cross-tool invocation instruction |

**Structural checks:**

- Descriptions longer than 1,000 characters: MEDIUM — unusually long descriptions are harder to audit and may hide injected instructions among legitimate content
- Base64-encoded strings (40+ characters matching the base64 alphabet) anywhere in a description: MEDIUM — encoded content is invisible to casual readers

**Tool name shadowing:**

Tool names are checked against a list of common system or sensitive names: `read_file`, `write_file`, `execute_command`, `run_script`, `get_user_info`, `sudo`, `eval`, `system`, `fetch_url`, `http_get`, `fs_read`, `fs_write`. A tool with one of these names shadows a well-known capability and may confuse the LLM into believing it is interacting with a trusted system primitive. Severity: HIGH.

---

### 5.5 Spec Compliance (SC)

**Purpose:** Validate conformance with the MCP specification and protocol hygiene. Spec violations do not always represent security vulnerabilities, but they indicate an immature or incomplete implementation that may behave unpredictably with MCP clients.

**Check 1 — Server metadata.**

Scans the full codebase for server name and version declarations using patterns for JS/TS (`createServer`, `McpServer`, `Server`), Python, and Go (`mcp.NewServer`, `NewServer`). If name or version is absent: MEDIUM finding.

Checks for explicit capabilities declarations (`capabilities:`, `setCapabilities()`, `ServerCapabilities`, Go's `WithCapabilities`). If absent: LOW finding.

**Check 2 — MCP SDK or protocol declaration.**

Looks for official SDK imports: `@modelcontextprotocol/sdk`, `mcp-python`, `mcp-sdk`, `mcp-go`, or a `protocolVersion` declaration. If absent: MEDIUM finding.

**Check 3 — Tool definitions and input schemas.**

Detects tool definitions using five independent patterns to avoid false negatives:

1. Direct SDK call: `server.tool(`, `.addTool(`, `.registerTools(`, `@server.tool`, `@mcp.tool`
2. Variable-then-register pattern: `const myTool = { name: ... }` followed by `addTool(myTool)`
3. Array of tools: `tools: [` or `const tools = [`
4. Object matching MCP tool shape: object with `name`, `description`, and `inputSchema` properties
5. Tool definition files: filenames matching `tools.ts`, `toolDefinitions.ts`, `tool-defs.ts`, `mcpTools.py`, etc.
6. Go SDK: `mcp.NewTool(`, `.AddTool(`, `RegisterTool`

If no tool definition pattern is found: MEDIUM finding.

If tool definitions are found but no `inputSchema` / `input_schema` / `parameters:` declaration exists anywhere: MEDIUM finding.

If an input schema exists but lacks a top-level `"type": "object"` declaration: MEDIUM finding.

**Check 4 — Error handling.**

Scans for try/catch blocks, Go `if err != nil` patterns, or error handler registrations (`.on('error')`, `ErrorHandler`). If none are found: MEDIUM finding.

If error handling exists but empty catch blocks or bare `except Exception: pass` are detected: LOW finding (silent errors).

Checks for JSON-RPC error response patterns: `JsonRpcError`, `McpError`, error objects with a `code` field, Go's `fmt.Errorf`/`errors.Is`/`errors.As`. If none: LOW finding.

**Check 5 — Transport security.**

If an HTTP transport is detected (`SSEServerTransport`, `HttpServerTransport`, `express`, `fastify`, `http.createServer`, `http.ListenAndServe`), the analyzer checks for authentication middleware anywhere in the codebase. If HTTP transport is present without any authentication pattern: HIGH finding.

**Check 6 — Documentation.**

If no `README.md` file is found in the repository: LOW finding.

If empty tool descriptions (`description: ''` or `description: ""`) are detected: LOW finding.

---

### 5.6 Input Validation (IV)

**Purpose:** Detect tool input flowing unsanitized into dangerous operations. An MCP server that passes LLM-supplied values directly to file operations, network requests, or database queries is vulnerable to path traversal, SSRF, and SQL injection respectively.

**Dangerous sinks:**

The analyzer tracks tool input variables (identified by common names: `args`, `params`, `input`, `validatedArgs`, `toolInput`, `userInput`, `llmInput`, `request`, `body`, `payload`, `data`, `parsed`, `toolArgs`, `callArgs`, `handlerArgs`) flowing into the following sink categories:

*File operations (path traversal risk):*

- `readFile(args.*)`, `readFileSync(args.*)`, `writeFile(args.*)`, `writeFileSync(args.*)`, `createReadStream(args.*)`, `createWriteStream(args.*)`, `appendFile(args.*)`
- Python `open(args.*)`
- Template literals: `` fs.method(`...${args.path}`) ``

*Network requests (SSRF risk):*

- `fetch(args.url)`, `axios.get(args.url)`, `axios.post(args.url)`, `got(args.url)`, `request(args.url)`, `http.get(args.url)`, `https.get(args.url)`, `urllib.request(args.url)`
- Template literals: `` fetch(`https://api.example.com/${args.path}`) ``

*SQL injection:*

- Template literals in query calls: `` .query(`SELECT ... ${args.name}`) ``
- String concatenation in queries: `.query('SELECT ... ' + args.name)`
- Template literals in execute calls: `` execute(`...${args.value}`) ``

**Context window analysis (15 lines upstream):**

Rather than simply flagging every sink call, the analyzer examines the 15 lines of code immediately above each sink call to detect existing security controls. Severity is adjusted accordingly:

| File operation context | Severity |
|---|---|
| `path.resolve()` AND `.startsWith(allowedDir)` both present | SAFE — not flagged |
| `path.resolve()` present but `.startsWith()` absent | MEDIUM — path is resolved but not confined |
| `path.join()` present but `.startsWith()` absent | MEDIUM — join does not prevent traversal |
| Type validation present (Zod, Joi, etc.) but no path containment | MEDIUM |
| No validation at all | HIGH |

| Network request context | Severity |
|---|---|
| `new URL()` AND allowlist check (`indexOf`, `includes`, `===`) both present | SAFE — not flagged |
| Allowlist check present without URL parsing | SAFE |
| `new URL()` present but no allowlist check | MEDIUM |
| Hardcoded base URL in template literal | LOW |
| Type validation only | MEDIUM |
| No validation at all | HIGH |

| SQL context | Severity |
|---|---|
| Type validation present | HIGH (type validation does not prevent SQL injection) |
| No validation at all | CRITICAL |

**Dynamic dispatch detection:**

The pattern `handlerMap[args.action](...)` — using a tool input value to select and call a function — is flagged as HIGH regardless of context. This pattern allows arbitrary function invocation if the dispatch table is not strictly controlled.

**Dynamic property access and spread:**

- `args[someVar]` in a tool handler context without type validation: MEDIUM
- `...args` spread inside a tool handler without type validation: LOW

**Project-level check:**

If no `inputSchema` / `input_schema` / `InputSchema` declaration is found anywhere in the codebase: HIGH finding. A server that declares no input schemas accepts arbitrary input without any structural constraints.

**What IV explicitly does not overlap with CI:**

The IV analyzer does not scan for `exec`, `spawn`, `os.system`, or similar shell execution patterns — those are the exclusive domain of the CI analyzer. This prevents double-counting the same line in both categories.

---

## 6. Scoring Model

**Per-category scoring.**

Every category starts at 100. For each finding in that category, a fixed deduction is subtracted:

| Severity | Deduction |
|---|---|
| CRITICAL | 25 points |
| HIGH | 15 points |
| MEDIUM | 5 points |
| LOW | 3 points |
| INFO | 0 points |

Deductions are cumulative and the floor is 0. A category with two CRITICAL findings scores `100 - 25 - 25 = 50`. A category with four CRITICAL findings scores `max(0, 100 - 100) = 0`.

**Weighted average.**

The six category scores are combined into a single Trust Score using a weighted average. Weights are aligned with the OWASP Top 10 for LLM Applications — categories that map to higher-ranked OWASP risks carry higher weight:

| Category | Code | Weight | OWASP Reference |
|---|---|---|---|
| Credential Leaks | CL | 25% | MCP01 — most damaging, most common |
| Command Injection | CI | 20% | MCP05 — RCE via LLM input |
| Network Exposure | NE | 15% | MCP07 — unauthorized access |
| Input Validation | IV | 15% | SSRF, path traversal, SQL injection |
| Tool Poisoning | TP | 15% | MCP03 — prompt injection |
| Spec Compliance | SC | 10% | Protocol hygiene |

The formula is:

```
TrustScore = round(
  CL_score * 0.25 +
  CI_score * 0.20 +
  NE_score * 0.15 +
  IV_score * 0.15 +
  TP_score * 0.15 +
  SC_score * 0.10
)
```

**Circuit Breaker — hard cap for HIGH and CRITICAL findings.**

If any finding in the scan has severity HIGH or CRITICAL, the Trust Score is capped at a maximum of 75, regardless of the weighted calculation. This circuit breaker ensures that a repository with high-severity security issues cannot achieve `CERTIFIED` status even if the other five categories are clean. Resolving all HIGH and CRITICAL findings removes the cap and allows the full calculated score to apply.

When the cap is applied, a warning is displayed in terminal output, and the `scoreCapped: true` flag is set in JSON and SARIF output.

**Pass count.**

A category is considered "passing" if its score is 80 or above. The pass count (0–6) is reported alongside the Trust Score.

---

## 7. Trust Labels and Exit Codes

| Score Range | Label | Meaning |
|---|---|---|
| 80 – 100 | CERTIFIED | All categories pass or have only low-severity findings. No HIGH or CRITICAL findings exist. |
| 50 – 79 | WARNING | Security issues are present that should be resolved before production deployment. |
| 0 – 49 | FAILED | Serious vulnerabilities are present. The process exits with code 1. |

Note: A score of exactly 75 from the hard cap mechanism always produces a WARNING label, not CERTIFIED.

**Exit codes:**

- `0` — Trust Score is 50 or above
- `1` — Trust Score is below 50, or a fatal error occurred

This enables `vantyr` to function as a CI gate: a failing scan fails the pipeline.

---

## 8. Suppressing False Positives

If a finding is a confirmed false positive, it can be suppressed using an inline comment. Place the suppression comment either on the same line as the flagged code or on the line immediately above it.

**JavaScript/TypeScript/Go:**

```js
// vantyr-ignore
const host = "0.0.0.0";
```

```js
const host = "0.0.0.0"; // vantyr-ignore
```

**Python/YAML:**

```python
cmd = build_deploy_command()  # vantyr-ignore
os.system(cmd)
```

**Scope of suppression:**

- The suppression applies to exactly one finding on the flagged line or the line below the comment.
- It does not suppress other findings in the same file or the same category.
- Suppression is applied as a post-processing step after all six analyzers complete. It does not affect how analyzers run — it only removes the finding from the results before scoring.

**What cannot be suppressed:**

Project-level findings have no line number (file is reported as "project"). These cannot be suppressed with inline comments. Examples: "No MCP tool definitions found", "No input schemas defined", "No README.md". These require fixing the underlying issue.

---

## 9. Output Formats

### 9.1 Terminal

Default mode. Color-coded output showing:

- The Trust Score and label
- A per-category breakdown with scores and finding counts
- A warning if the score was capped
- A remediation list for every finding, sorted by severity

Example:

```
MCP Certify -- Trust Score: 61/100  WARNING

  Network Exposure      -- 100/100
  Command Injection     -- 100/100
  Credential Leaks      --  70/100  (2 findings)
  Tool Poisoning        -- 100/100
  Spec Compliance       --  85/100  (1 finding)
  Input Validation      -- 100/100

-------------------------------------------------

Remediations:

[HIGH] [Credential Leaks] Line 12 in config.js
  Generic API Key detected.
  Remove hardcoded credentials and use environment variables instead.

[MEDIUM] [Spec Compliance] In project
  No explicit capabilities declaration found.
  Declare server capabilities to inform clients what features are supported.

-------------------------------------------------
Scanned: https://github.com/owner/repo
Checks: 6 | Critical: 0 | High: 1 | Medium: 1 | Low: 0 | Pass: 4/6
```

Use `--verbose` to also list every scanned file path before this output.

### 9.2 JSON

Activated by `--json`. All other console output is suppressed. The full JSON document is written to stdout.

```jsonc
{
  "source": "https://github.com/owner/repo",
  "trustScore": 61,
  "label": "WARNING",
  "scoreCapped": false,
  "categories": {
    "NE": { "score": 100, "passed": true, "findingCount": 0, "findings": [] },
    "CI": { "score": 100, "passed": true, "findingCount": 0, "findings": [] },
    "CL": { "score": 70,  "passed": false, "findingCount": 2, "findings": [...] },
    "TP": { "score": 100, "passed": true, "findingCount": 0, "findings": [] },
    "SC": { "score": 85,  "passed": true, "findingCount": 1, "findings": [...] },
    "IV": { "score": 100, "passed": true, "findingCount": 0, "findings": [] }
  },
  "stats": {
    "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0
  },
  "passCount": 5,
  "totalFindings": 3,
  "findings": [
    {
      "category": "CL",
      "severity": "high",
      "file": "src/config.js",
      "line": 12,
      "snippet": "const API_KEY = 'AbCd1234...'",
      "message": "Generic API Key detected.",
      "remediation": "Remove hardcoded credentials and use environment variables instead."
    }
  ]
}
```

If `--local` is used and no config files are found, the JSON output is:

```json
{
  "source": "Local Configuration & Rules",
  "trustScore": null,
  "label": "NO_FILES",
  "message": "No local MCP configuration or rules files found.",
  "findings": []
}
```

### 9.3 SARIF (GitHub Code Scanning)

Activated by `--sarif`. Emits a SARIF 2.1.0 document to stdout, suitable for upload to GitHub's Security tab via the `upload-sarif` action.

The document contains six SARIF rules (one per category) with descriptions, `helpUri` links to OWASP MCP Top 10, and severity tags.

SARIF severity mapping:

| vantyr severity | SARIF level |
|---|---|
| CRITICAL, HIGH | `error` |
| MEDIUM | `warning` |
| LOW, INFO | `note` |

Each SARIF result includes:
- `ruleId` (e.g., `MCP-CL`, `MCP-CI`)
- `level`
- `message.text` combining the finding message and remediation
- `physicalLocation` with file URI and line number (when available)
- `properties.trustScore` and `properties.scoreCapped`

---

## 10. CI/CD Integration

**Basic pipeline gate:**

```yaml
- name: MCP Security Scan
  run: npx vantyr scan ${{ github.event.repository.html_url }}
```

The step fails (exit code 1) when Trust Score is below 50.

**GitHub Code Scanning with SARIF:**

Upload results directly to the Security tab for inline PR annotations:

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
        run: npx vantyr scan ${{ github.event.repository.html_url }} --sarif > results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

**JSON output for custom dashboards or policy checks:**

```bash
# Fail the build if Trust Score is below 80 (stricter than the default 50 gate)
SCORE=$(npx vantyr scan https://github.com/owner/repo --json | jq '.trustScore')
if [ "$SCORE" -lt 80 ]; then
  echo "Score $SCORE is below CERTIFIED threshold"
  exit 1
fi
```

**Scanning private repositories in CI:**

Store the GitHub PAT as a repository secret and pass it via the `--token` flag:

```yaml
- name: Run vantyr
  run: npx vantyr scan ${{ github.event.repository.html_url }} --token ${{ secrets.MCPCERTIFY_TOKEN }} --json
```

---

## 11. Local Scan Mode

`vantyr scan --local` reads MCP configuration and AI rules files from standard locations on your machine. It does not require a GitHub URL.

**Files scanned:**

| Path | Platform | Purpose |
|---|---|---|
| `~/.cursor/mcp.json` | All | Cursor global MCP configuration |
| `~/.codeium/windsurf/mcp_config.json` | All | Windsurf MCP configuration |
| `~/Library/Application Support/Claude/claude_desktop_config.json` | macOS | Claude Desktop configuration |
| `%APPDATA%\Claude\claude_desktop_config.json` | Windows | Claude Desktop configuration |
| `.vscode/mcp.json` | All (project) | VSCode project MCP config |
| `.cursor/mcp.json` | All (project) | Cursor project MCP config |
| `.cursorrules` | All (project) | Cursor AI instructions file |
| `.windsurfrules` | All (project) | Windsurf AI instructions file |
| `CLAUDE.md` | All (project) | Claude project instructions |
| `copilot-instructions.md` | All (project) | GitHub Copilot instructions |

**What is checked in local mode:**

The same six analyzers run on the discovered files. In practice, the most relevant findings in local mode are:

- **Credential Leaks (CL):** Hardcoded API keys or tokens in JSON configuration files, environment variable values inadvertently pasted into config
- **Tool Poisoning (TP):** Prompt injection payloads embedded in `.cursorrules`, `CLAUDE.md`, or other AI rules files
- **Spec Compliance (SC):** Missing schemas, missing documentation in project-level config

**What local mode does not do:**

Local mode scans the configuration files themselves. It does not dynamically trace the `command` entries in MCP configuration (e.g., the `npx` package path or local binary path defined in `claude_desktop_config.json`) and scan the underlying server source code on your local disk. To scan a referenced MCP server's implementation, pass its GitHub URL explicitly as a separate scan.

---

## 12. Supported Languages and File Types

**Source code files (full analysis — all six analyzers):**

- JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`)
- TypeScript (`.ts`, `.tsx`)
- Python (`.py`)
- Go (`.go`)
- Rust (`.rs`)

**Configuration and data files (credential and structural checks):**

- JSON (`.json`)
- YAML (`.yaml`, `.yml`)
- TOML (`.toml`)
- Markdown (`.md`)
- Shell scripts (`.sh`, `.bash`, `.zsh`)
- Environment files (`.env`, `.env.*`)

**Skipped always:**

Binary files, image files, compiled artifacts, and files larger than 100 KB are excluded regardless of extension.

---

## 13. Technical Constraints and Limitations

**File cap.** Up to 100 files per scan. For repositories exceeding this limit, vantyr scans the first 100 eligible files returned by the GitHub API and displays a warning. The remaining files are not analyzed. This may result in an artificially high Trust Score for large codebases.

**File size cap.** Files larger than 100 KB are skipped. Large generated files or bundled artifacts often hit this limit. This is intentional — minified or bundled files are not meaningful targets for static analysis.

**Static analysis only.** vantyr does not execute any code. It cannot detect vulnerabilities that only manifest at runtime, such as insecure deserialization, race conditions, timing attacks, or vulnerabilities introduced by runtime configuration.

**15-line context window.** The IV analyzer's upstream context window is fixed at 15 lines. A validation check placed more than 15 lines above a sink call will not be detected, and the finding will report a higher severity than it deserves. Consider this when reviewing medium-severity IV findings.

**Single-file alias detection.** Import alias detection in the CI analyzer operates per-file. Cross-file aliases (e.g., an alias defined in `utils.py` and used in `handler.py`) are not detected.

**Pattern-based tool definition detection.** The TP analyzer only analyzes files that contain at least one recognized tool registration pattern. MCP tools registered via unconventional or custom frameworks may not be detected.

**No interprocedural analysis.** The IV analyzer does not track data flow across function boundaries. If tool input is passed as an argument to a helper function that then calls a dangerous sink, the finding will not be reported.

---

## 14. What vantyr Does Not Cover

The following vulnerability classes are explicitly out of scope for the current version:

- **Dependency vulnerabilities.** vantyr does not audit `package.json`, `requirements.txt`, `go.mod`, or other dependency manifests for known CVEs. Use `npm audit`, `pip-audit`, `govulncheck`, or Dependabot for this.

- **Runtime security misconfigurations.** TLS certificate validation, DNS rebinding protections, rate limiting, and other server-side runtime controls cannot be assessed through source code analysis alone.

- **Output sanitization.** Responses returned by tools to the LLM are not analyzed. A tool that returns attacker-controlled content without sanitization could enable secondary prompt injection, but detecting this requires semantic understanding of data flow that static analysis cannot reliably provide.

- **Authentication correctness.** The NE and SC analyzers detect the *presence* of authentication patterns. They do not verify that the authentication implementation is correct (e.g., JWT signature verification, token expiry checks, scope validation).

- **Business logic vulnerabilities.** Access control at the tool level (e.g., a tool that performs destructive operations without confirming intent), excessive capability grants, and missing confirmation dialogs for sensitive actions are not analyzed.

- **Infrastructure security.** Container configurations, Kubernetes manifests, cloud IAM policies, and firewall rules are outside the scope of source code analysis.

---

## 15. Certified by Vantyr — Badge for Your Repository

If your MCP server scores **80 or above** (CERTIFIED), you can add the official badge to your own `README.md` to signal to users that your server has passed the vantyr security audit.

**Copy this into your README:**

```markdown
[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
```

It renders as:

[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)

**With your score included:**

```markdown
[![Certified by Vantyr](https://img.shields.io/badge/Vantyr-CERTIFIED%20%E2%80%94%2092%2F100-brightgreen?style=flat-square&logo=checkmarx&logoColor=white)](https://www.npmjs.com/package/@gianmarcomaz/vantyr)
```

Replace `92` with your actual Trust Score. To verify a badge claim, anyone can run:

```bash
npx @gianmarcomaz/vantyr scan https://github.com/owner/repo
```

---

## 16. License

MIT
