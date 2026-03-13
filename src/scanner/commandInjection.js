/**
 * Command Injection Analyzer
 * Scans for dangerous code execution patterns that could allow RCE via LLM input.
 *
 * Context-aware:
 *   - Test files are excluded (not production code)
 *   - Install-time scripts (preinstall, postinstall, setup) get reduced severity
 *   - CLI tools (cmd/, cli/, scripts/) are treated as lower risk
 *   - Go's exec.Command() is NOT shell execution (args are explicit, no shell)
 *   - Import/require statements are NOT findings (only actual calls matter)
 */

/* ════════════════════════════════════════════════════
   Test‑file & CLI‑tool detection
   ════════════════════════════════════════════════════ */

/** Matches test file paths across JS/TS/Go/Python */
const TEST_FILE_RE =
    /(?:[\\/](?:__tests__|tests?|spec|__mocks__|mock|fixture|e2e|testdata|testutil)[\\/]|[\\/](?:.*_test|.*\.test|.*\.spec)\.[a-z]+$)/i;

/** Matches CLI‑tool / build‑script paths */
const CLI_TOOL_RE =
    /(?:^|[\\/])(?:cmd|cli|scripts|tools|bin|hack|contrib)[\\/]/i;

/** Install-time script filenames — run at setup, not at runtime */
const INSTALL_TIME_FILENAMES = new Set([
    "preinstall.js", "postinstall.js", "preinstall.ts", "postinstall.ts",
    "setup.js", "setup.ts", "setup.sh", "setup.bat",
    "install.js", "install.sh",
]);

/**
 * Check if a file is an install-time script.
 * Matches by filename or by being referenced in package.json scripts.
 */
function isInstallTimeFile(filePath, allFiles) {
    // Check filename
    const basename = filePath.replace(/^.*[\\/]/, "").toLowerCase();
    if (INSTALL_TIME_FILENAMES.has(basename)) return true;

    // Check if referenced in package.json install scripts
    const pkgFile = allFiles.find((f) => /[\\/]?package\.json$/.test(f.path));
    if (pkgFile) {
        try {
            const pkg = JSON.parse(pkgFile.content);
            const installScripts = [
                pkg.scripts?.preinstall,
                pkg.scripts?.postinstall,
                pkg.scripts?.prepare,
            ].filter(Boolean);
            // Check if this file is referenced in any install script
            if (installScripts.some((s) => s.includes(basename))) return true;
        } catch { /* invalid json */ }
    }
    return false;
}

/* ════════════════════════════════════════════════════
   Dangerous function patterns
   ════════════════════════════════════════════════════ */

const DANGEROUS_FUNCTIONS = [
    // JavaScript / TypeScript — these use a shell by default
    { regex: /(?:^|[^a-zA-Z0-9_.])exec\s*\(|child_process\.exec\s*\(/, lang: "js", shellBased: true },
    { regex: /(?:^|[^a-zA-Z0-9_.])execSync\s*\(|child_process\.execSync\s*\(/, lang: "js", shellBased: true },
    { regex: /(?:^|[^a-zA-Z0-9_.])execFile\s*\(|child_process\.execFile\s*\(/, lang: "js", shellBased: false },
    { regex: /(?:^|[^a-zA-Z0-9_.])execFileSync\s*\(|child_process\.execFileSync\s*\(/, lang: "js", shellBased: false },
    { regex: /(?:^|[^a-zA-Z0-9_.])spawn\s*\(|child_process\.spawn\s*\(/, lang: "js", shellBased: false },
    { regex: /(?:^|[^a-zA-Z0-9_.])spawnSync\s*\(|child_process\.spawnSync\s*\(/, lang: "js", shellBased: false },
    { regex: /(?:^|[^a-zA-Z0-9_.])eval\s*\(/, lang: "js", shellBased: true },
    { regex: /new\s+Function\s*\(/, lang: "js", shellBased: true },
    { regex: /vm\.runIn(?:New|This)?Context\s*\(/, lang: "js", shellBased: true },
    // Python — os.system uses shell; subprocess can go either way
    { regex: /os\.system\s*\(/, lang: "py", shellBased: true },
    { regex: /subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(/, lang: "py", shellBased: false }, // Will check for shell=True dynamically
    { regex: /(?:^|[^a-zA-Z0-9_.])exec\s*\(/, lang: "py", shellBased: true },
    { regex: /(?:^|[^a-zA-Z0-9_.])eval\s*\(/, lang: "py", shellBased: true },
    { regex: /os\.popen\s*\(/, lang: "py", shellBased: true },
    { regex: /commands\.getoutput\s*\(/, lang: "py", shellBased: true },
    // Go — exec.Command runs directly, NO shell involved
    { regex: /exec\.Command\s*\(/, lang: "go", shellBased: false },
];

// Heuristic: check if the first argument is a string literal (safer) or variable
const LITERAL_ARG = /\(\s*['"`][^'"`${}]*['"`]\s*[,)]/;
const TEMPLATE_LITERAL = /\(\s*`[^`]*\$\{/;

/** Import/require statements — NOT a finding, just a declaration */
const IMPORT_RE = /^\s*(?:import\s+|const\s+.*=\s*require\s*\(|from\s+['"]|require\s*\(\s*['"])/;

/**
 * Scan for locally-defined constants assigned string literals.
 * If a variable is const X = 'literal' and then used in exec(X),
 * that's effectively a literal — LOW not CRITICAL.
 */
function findLocalConstants(lines) {
    const constants = new Set();
    for (const line of lines) {
        const match = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*['"`][^'"`${}]*['"`]/);
        if (match) constants.add(match[1]);
    }
    return constants;
}

/** Check if the first arg passed to a function call is a known constant */
function isArgLocalConstant(line, constants) {
    // Covers JS/TS, Python, and Go dangerous function names so that a call
    // like os.system(CMD) where CMD is a const string is correctly rated low,
    // not critical.
    const match = line.match(
        /(?:(?:child_process\.)?(?:exec(?:Sync|File|FileSync)?|spawn(?:Sync)?|eval)|os\.(?:system|popen)|commands\.getoutput|subprocess\.(?:run|Popen|call|check_output|check_call)|exec\.Command)\s*\(\s*(\w+)\s*[,)]/
    );
    if (match && constants.has(match[1])) return true;
    return false;
}

/* ════════════════════════════════════════════════════
   Import-alias bypass detection
   ════════════════════════════════════════════════════ */

/** Escape a string for safe use inside a RegExp constructor. */
function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Detect per-file import aliases that would bypass the static DANGEROUS_FUNCTIONS
 * patterns, then return equivalent pattern objects in the same shape.
 *
 * Covers:
 *   Python: import subprocess as sp  →  sp.run/Popen/call/check_output/check_call
 *   Python: from subprocess import run/Popen/…  →  bare run/Popen/…
 *   Python: import os as o  →  o.system / o.popen
 *   Python: from os import system/popen  →  bare system/popen
 *   JS/TS:  const cp = require('child_process')  →  cp.exec/execSync/spawn/…
 *   JS/TS:  import * as cp from 'child_process'  →  cp.exec/execSync/spawn/…
 *
 * @param {string} content  Full file text
 * @param {string} filePath File path (used to determine language)
 * @returns {Array}         Extra pattern objects shaped like DANGEROUS_FUNCTIONS entries
 */
function detectImportAliases(content, filePath) {
    const extra = [];
    const isPy = /\.py$/.test(filePath);
    const isJs = /\.[jt]sx?$/.test(filePath);

    if (isPy) {
        // import subprocess as <alias>
        const spAlias = content.match(/\bimport\s+subprocess\s+as\s+(\w+)/);
        if (spAlias) {
            const a = escapeRegex(spAlias[1]);
            extra.push({
                regex: new RegExp(`(?:^|[^a-zA-Z0-9_.])${a}\\.(?:run|Popen|call|check_output|check_call)\\s*\\(`),
                lang: 'py', shellBased: false,
            });
        }

        // from subprocess import run, Popen, call, …
        const spFrom = content.match(/\bfrom\s+subprocess\s+import\s+([\w,\s]+)/);
        if (spFrom) {
            for (const name of spFrom[1].split(',').map(s => s.trim())) {
                if (/^(?:run|Popen|call|check_output|check_call)$/.test(name)) {
                    const n = escapeRegex(name);
                    extra.push({
                        regex: new RegExp(`(?:^|[^a-zA-Z0-9_.])${n}\\s*\\(`),
                        lang: 'py', shellBased: false,
                    });
                }
            }
        }

        // import os as <alias>
        const osAlias = content.match(/\bimport\s+os\s+as\s+(\w+)/);
        if (osAlias) {
            const a = escapeRegex(osAlias[1]);
            extra.push({
                regex: new RegExp(`(?:^|[^a-zA-Z0-9_.])${a}\\.(?:system|popen)\\s*\\(`),
                lang: 'py', shellBased: true,
            });
        }

        // from os import system / popen
        const osFrom = content.match(/\bfrom\s+os\s+import\s+([\w,\s]+)/);
        if (osFrom) {
            for (const name of osFrom[1].split(',').map(s => s.trim())) {
                if (/^(?:system|popen)$/.test(name)) {
                    const n = escapeRegex(name);
                    extra.push({
                        regex: new RegExp(`(?:^|[^a-zA-Z0-9_.])${n}\\s*\\(`),
                        lang: 'py', shellBased: true,
                    });
                }
            }
        }
    }

    if (isJs) {
        const CP_METHODS = '(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)';

        // const cp = require('child_process')
        const reqAlias = content.match(/(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)/);
        // import * as cp from 'child_process'
        const importAlias = content.match(/import\s+\*\s+as\s+(\w+)\s+from\s+['"]child_process['"]/);

        const alias = reqAlias?.[1] ?? importAlias?.[1];
        if (alias && alias !== 'child_process') {
            const a = escapeRegex(alias);
            extra.push({
                regex: new RegExp(`(?:^|[^a-zA-Z0-9_.])${a}\\.${CP_METHODS}\\s*\\(`),
                lang: 'js', shellBased: true,
            });
        }
    }

    return extra;
}

/* ════════════════════════════════════════════════════
   Go-specific helpers
   ════════════════════════════════════════════════════ */

/**
 * Go's exec.Command(name, args...) executes directly without a shell.
 * Only the first argument (the binary) being dynamic is a real concern.
 * If the first arg is a literal string, the command itself is fixed.
 */
const GO_EXEC_LITERAL_BINARY = /exec\.Command\s*\(\s*"[^"]+"/;
const GO_EXEC_ARGS_SPREAD = /exec\.Command\s*\(\s*\w+\s*,\s*\w+\s*\.\.\.\s*\)/;

function isGoExecSafe(line) {
    // First arg is a literal string → binary is fixed, much safer
    if (GO_EXEC_LITERAL_BINARY.test(line)) return true;
    return false;
}

function isGoExecFirstArgDynamic(line) {
    // exec.Command(someVar, ...) or exec.Command(parts[0], parts[1:]...)
    if (/exec\.Command\s*\(\s*[a-zA-Z_]\w*(?:\s*[,)])|\[\d+\]/.test(line) && !GO_EXEC_LITERAL_BINARY.test(line)) {
        return true;
    }
    return false;
}

/* ════════════════════════════════════════════════════
   Main Analyzer
   ════════════════════════════════════════════════════ */

/**
 * @param {Array<{path: string, content: string}>} files
 * @returns {{ score: number, status: string, findings: Array }}
 */
function analyzeCommandInjection(files) {
    const findings = [];

    for (const file of files) {
        const lines = file.content.split("\n");
        const isTestFile = TEST_FILE_RE.test(file.path);
        const isCliTool = CLI_TOOL_RE.test(file.path);
        const isGoFile = /\.go$/.test(file.path);
        const isInstallTime = isInstallTimeFile(file.path, files);
        const localConstants = findLocalConstants(lines);

        // Merge static patterns with any alias-specific patterns found in this file
        const aliasPatterns = detectImportAliases(file.content, file.path);
        const effectivePatterns = aliasPatterns.length > 0
            ? [...DANGEROUS_FUNCTIONS, ...aliasPatterns]
            : DANGEROUS_FUNCTIONS;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Skip comments
            const trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

            // ── SKIP: Import/require statements are NOT findings ──
            if (IMPORT_RE.test(trimmed)) continue;

            for (const pattern of effectivePatterns) {
                if (!pattern.regex.test(line)) continue;

                /* ── Context 1: Test files → skip entirely ── */
                if (isTestFile) {
                    // Don't even report test-file findings — they are not prod code
                    break;
                }

                /* ── Context 2: Go exec.Command — NOT shell execution ── */
                if (isGoFile && pattern.lang === "go") {
                    if (isGoExecSafe(line)) {
                        // Literal binary name + explicit args → benign
                        // Don't flag at all — Go's exec.Command with literal is safe
                        break;
                    }

                    if (isGoExecFirstArgDynamic(line)) {
                        // Dynamic binary name — the real risk in Go
                        const severity = isCliTool ? "medium" : "high";
                        findings.push({
                            severity,
                            file: file.path,
                            line: i + 1,
                            snippet: trimmed,
                            message: isCliTool
                                ? "CLI tool uses dynamic command name in exec.Command. Verify user input is validated."
                                : "Dynamic command name in exec.Command — the executed binary is determined at runtime.",
                            remediation:
                                "Use an allowlist of permitted binaries. Validate the command name before passing to exec.Command().",
                        });
                        break;
                    }

                    // Go exec.Command with args spread (e.g., exec.Command("docker", args...))
                    // The binary is literal but args are dynamic — lower risk than shell
                    if (GO_EXEC_ARGS_SPREAD.test(line)) {
                        findings.push({
                            severity: isCliTool ? "low" : "medium",
                            file: file.path,
                            line: i + 1,
                            snippet: trimmed,
                            message: "exec.Command with spread args — binary is fixed but arguments come from a variable.",
                            remediation:
                                "Validate argument values before passing to exec.Command. Go's exec.Command does NOT use a shell, so injection risk is limited to argument manipulation.",
                        });
                        break;
                    }
                }

                /* ── Context 3: Install-time scripts → reduced severity ── */
                if (isInstallTime) {
                    const isLiteral = LITERAL_ARG.test(line) && !TEMPLATE_LITERAL.test(line);
                    const isConst = isArgLocalConstant(line, localConstants);
                    if (isLiteral || isConst) {
                        findings.push({
                            severity: "low",
                            file: file.path,
                            line: i + 1,
                            snippet: trimmed,
                            message: "Install-time script — runs at setup only, not at runtime. Verify this never receives dynamic input.",
                            remediation:
                                "If this command is only for project setup, this is acceptable. Ensure it never receives user or LLM input.",
                        });
                    } else {
                        findings.push({
                            severity: "medium",
                            file: file.path,
                            line: i + 1,
                            snippet: trimmed,
                            message: "Install-time script uses dynamic argument — verify input source.",
                            remediation:
                                "Install scripts should only use hardcoded commands. Dynamic arguments may indicate supply-chain risk.",
                        });
                    }
                    break;
                }

                /* ── Context 4: CLI tools → downgrade severity ── */
                if (isCliTool) {
                    const isLiteral = LITERAL_ARG.test(line) && !TEMPLATE_LITERAL.test(line);
                    findings.push({
                        severity: isLiteral ? "low" : "medium",
                        file: file.path,
                        line: i + 1,
                        snippet: trimmed,
                        message: isLiteral
                            ? "CLI utility uses shell command with literal argument."
                            : "CLI utility uses shell command with dynamic argument — verify input is validated.",
                        remediation:
                            "CLI tools should validate and sanitize all user input before passing to shell commands.",
                    });
                    break;
                }

                /* ── Context 5: Regular production code ── */
                const isLiteral = LITERAL_ARG.test(line) && !TEMPLATE_LITERAL.test(line);
                const isConst = isArgLocalConstant(line, localConstants);

                // Check for shell metacharacters inside literal strings (e.g. exec("rm -rf / && something"))
                let hasDangerousMetachars = false;
                if (isLiteral) {
                    const argMatch = line.match(/\(\s*['"`]([^'"`${}]*)['"`]/);
                    if (argMatch && /[&|;<>$`\n]|>\s*&/.test(argMatch[1])) {
                        hasDangerousMetachars = true;
                    }
                }

                // Check for Python shell=True
                const isPythonShellTrue = pattern.lang === "py" && /shell\s*=\s*True/i.test(line);
                const isShellBased = pattern.shellBased || isPythonShellTrue || hasDangerousMetachars;

                if ((isLiteral || isConst) && !hasDangerousMetachars) {
                    findings.push({
                        severity: "low",
                        file: file.path,
                        line: i + 1,
                        snippet: trimmed,
                        message: isConst
                            ? "Shell command uses a locally-defined constant. Verify it is never reassigned from external input."
                            : "Shell command with literal argument. Verify this is intentional.",
                        remediation:
                            "If this command is intentional and never receives LLM input, consider documenting why it's needed.",
                    });
                } else {
                    findings.push({
                        severity: isShellBased ? "critical" : "high",
                        file: file.path,
                        line: i + 1,
                        snippet: trimmed,
                        message: hasDangerousMetachars
                            ? "Shell metacharacters detected in literal command string — explicit command injection or risky behavior."
                            : isShellBased
                                ? "Potential command injection — shell command with variable/dynamic argument."
                                : "Command execution with dynamic argument — verify input is not from LLM.",
                        remediation:
                            "Avoid passing LLM-provided input directly to shell commands. Use allowlists for permitted commands and validate/sanitize all input parameters.",
                    });
                }

                break; // Only flag once per line
            }
        }
    }

    return findings.map(f => ({ ...f, category: 'CI' }));
}

export { analyzeCommandInjection };
