/**
 * Input Validation Analyzer
 *
 * Distinguishes between Type Validation (Zod, Joi, basic schemas) and
 * Security Validation (path containment, URL allowlists, parameterized queries).
 * 
 * Skips Command Injection patterns to avoid double-counting with the CI module.
 */

const TYPE_VALIDATION_RE = /z\.(?:string|number|boolean|object|array|enum)|Joi\.(?:string|number)|joi|yup|superstruct|valibot|inputSchema|input_schema|"type"\s*:\s*"string"/i;

// Common variable names that represent direct MCP / LLM tool input.
// Used in "direct-call" sink patterns (bare identifier, no property access).
// Kept intentionally specific to avoid flagging readFile(config) or fetch(url)
// where those variables come from application config rather than tool input.
// Property-access patterns (ending in [\.\[]) keep the broader [a-zA-Z0-9_]+
// because args.path / input.url etc. are structurally tool-input shaped.
const MCP_INPUT_NAMES = '(?:args|params|input|validatedArgs|toolInput|userInput|llmInput|req(?:uest)?|body|payload|data|parsed|toolArgs|callArgs|handlerArgs)';

const DANGEROUS_SINKS = [
    // ── Path traversal ──
    {
        // Direct-call: restrict to known MCP input variable names to avoid FP on
        // readFile(config), readFile(filename), readFile(p), etc.
        regex: new RegExp(`(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|appendFile|appendFileSync)\\s*\\(\\s*${MCP_INPUT_NAMES}\\b`),
        name: "File operation with tool input",
        type: "file"
    },
    {
        // Property-access: keep broad identifier — args.path, input.file, etc.
        regex: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(\s*(?:args|params|input|validatedArgs|[a-zA-Z0-9_]+)\s*[\.\[]/,
        name: "File operation with tool input property",
        type: "file"
    },
    {
        // Python open(): restrict to MCP input names — open(filepath) is too common
        regex: new RegExp(`open\\s*\\(\\s*${MCP_INPUT_NAMES}\\b`),
        name: "Python open() with tool input",
        type: "file"
    },
    {
        regex: /fs\.\w+\s*\(\s*`[^`]*\$\{.*(?:args|params|input)/,
        name: "File path built from template literal with tool input",
        type: "file"
    },
    // ── SSRF ──
    {
        // Direct-call: restrict to known MCP input names — fetch(url) is extremely
        // common in non-tool-handler code and generates many FPs otherwise.
        regex: new RegExp(`(?:fetch|axios\\.get|axios\\.post|axios|got|request|http\\.get|https\\.get|urllib\\.request)\\s*\\(\\s*${MCP_INPUT_NAMES}\\b`),
        name: "HTTP request with tool input URL",
        type: "network"
    },
    {
        // Property-access: keep broad — fetch(args.url), axios(input.endpoint), etc.
        regex: /(?:fetch|axios|got|request|http\.get|https\.get)\s*\(\s*(?:args|params|input|validatedArgs|[a-zA-Z0-9_]+)\s*[\.\[]/,
        name: "HTTP request with tool input property",
        type: "network"
    },
    {
        regex: /(?:fetch|axios|got|request)\s*\(\s*`([^`]+)?\$\{.*(?:args|params|input)/,
        name: "URL built from template literal with tool input",
        type: "network"
    },
    // ── SQL injection ──
    {
        regex: /\.query\s*\(\s*`[^`]*\$\{.*(?:args|params|input)/,
        name: "SQL query with interpolated tool input",
        type: "sql"
    },
    {
        regex: /\.query\s*\(\s*['"][^'"]*['"]\s*\+\s*(?:args|params|input)/,
        name: "SQL query with concatenated tool input",
        type: "sql"
    },
    {
        regex: /(?:execute|exec|run)\s*\(\s*`[^`]*\$\{.*(?:args|params|input)/,
        name: "Database execution with interpolated tool input",
        type: "sql"
    },
];

const DISPATCH_PATTERNS = [
    {
        regex: /\w+\s*\[\s*(?:args|params|input)\s*\.\s*\w+\s*\]\s*\(/,
        name: "Dynamic dispatch from user input",
        severity: "high",
        remediation: "Do not use user-supplied values to dynamically select and invoke functions. Use an explicit allowlist map instead.",
    },
];

const DYNAMIC_ACCESS_REGEX = /args\s*\[\s*\w+\s*\]/;
const SPREAD_REGEX = /\.\.\.(?:args|params|input)\b/;
const TEST_FILE_RE = /(?:[\\/](?:__tests__|tests?|spec|__mocks__|mock|fixture)[\\/]|\.(?:test|spec)\.[jt]sx?$)/i;
const SAFE_VARIABLE_RE = /\b(?:redact|mask|sanitiz|log|debug|print|censor|hide|obfuscat|display|format|stringify|output|response|result|reply)\w*\s*\[/i;
const CONFIG_SOURCE_RE = /\b(?:config|settings|env|process\.env|os\.environ|serverConfig|appConfig|options|defaults|constants)\b/i;
const RESPONSE_BUILD_RE = /\b(?:response|result|output|reply|data|body|payload|ret|res)\s*\[/i;

function isDynamicAccessSafe(line, filePath) {
    if (TEST_FILE_RE.test(filePath)) return true;
    if (SAFE_VARIABLE_RE.test(line)) return true;
    if (CONFIG_SOURCE_RE.test(line) && !/exec|spawn|eval|system/i.test(line)) return true;
    if (RESPONSE_BUILD_RE.test(line)) return true;
    if (/args\s*\[\s*\d+\s*\]/.test(line) && !/exec|spawn|eval|system/i.test(line)) return true;
    return false;
}

function isSpreadSafe(line, filePath) {
    if (TEST_FILE_RE.test(filePath)) return true;
    if (!/exec|spawn|eval|system/i.test(line)) {
        if (/(?:vi|jest)\.fn|mock/i.test(line)) return true;
        if (/console\.|log\(|print\(/i.test(line)) return true;
    }
    return false;
}

function analyzeInputValidation(files) {
    const findings = [];
    let hasInputSchema = false;

    for (const file of files) {
        const content = file.content;
        if (!/\.(?:js|ts|jsx|tsx|py|go|rs)$/.test(file.path)) continue;

        if (/inputSchema|input_schema|parameters\s*[:=]\s*\{|InputSchema|mcp\.Property|WithDescription|Required\s*[:=]/.test(content)) {
            hasInputSchema = true;
        }

        // Test files are not production code — skip sink scanning entirely.
        // The inputSchema check above still runs so test fixtures that define
        // schemas contribute to the global hasInputSchema flag correctly.
        if (TEST_FILE_RE.test(file.path)) continue;

        const lines = content.split("\n");
        const hasTypeValidation = TYPE_VALIDATION_RE.test(content);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            /* ── Pass 1 & 2 combined: Find sinks and check context ── */
            for (const sink of DANGEROUS_SINKS) {
                const match = line.match(sink.regex);
                if (match) {
                    const blockContext = Math.max(0, i - 15);
                    const contextUpstream = lines.slice(blockContext, i + 1).join("\n");
                    
                    if (sink.type === "file") {
                        const hasResolve = /path\.resolve|os\.path\.realpath/.test(contextUpstream);
                        const hasStartsWith = /\.startsWith|indexOf|includes/.test(contextUpstream);
                        const hasJoin = /path\.join|os\.path\.join/.test(contextUpstream);
                        
                        // We also need to be careful not to flag static requires
                        if (/fs\.readFile\s*\(\s*['"]/.test(line)) continue;
                        
                        if (hasResolve && hasStartsWith) {
                            // SAFE
                        } else if (hasResolve && !hasStartsWith) {
                            findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "Path is resolved but not confined.", remediation: "Add .startsWith(allowedBaseDir) to prevent path traversal." });
                        } else if (hasJoin && !hasStartsWith) {
                            findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "path.join doesn't prevent traversal.", remediation: "Use path.resolve() and .startsWith(allowedBaseDir)." });
                        } else if (hasTypeValidation) {
                            findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `Tool input passes type check but has no path traversal protection before being passed to file operation.`, remediation: "Add path.resolve() + startsWith(allowedBaseDir) to confine file access to an allowed directory." });
                        } else {
                            findings.push({ severity: "high", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `Unsanitized file path from tool input — path traversal risk.`, remediation: "Add path.resolve() + startsWith(allowedBaseDir) to confine file access to an allowed directory." });
                        }
                    } else if (sink.type === "network") {
                        const hasNewURL = /new\s+URL/.test(contextUpstream);
                        const hasAllowlist = /allowlist|whitelist|includes|indexOf|==|===/.test(contextUpstream);
                        
                        if (hasNewURL && hasAllowlist) {
                            // SAFE
                        } else if (hasAllowlist && !hasNewURL) {
                            // Also basically safe if we do string matching
                            // SAFE
                        } else if (hasNewURL && !hasAllowlist) {
                            findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "URL is parsed but not validated.", remediation: "Validate URL protocol and hostname against an allowlist." });
                        } else if (match[1] && /^https?:\/\//.test(match[1])) {
                            // Hardcoded base URL in template string
                            findings.push({ severity: "low", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "Base URL is hardcoded, but dynamic path should be validated.", remediation: "Ensure the path segment doesn't allow traversal out of the base URL's API space." });
                        } else if (hasTypeValidation) {
                            findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `Tool input passes type check but has no SSRF protection before being passed to network request.`, remediation: "Validate URL protocol (https only) and hostname against an allowlist. Block requests to internal IP ranges." });
                        } else {
                            findings.push({ severity: "high", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `Unsanitized URL from tool input — SSRF risk.`, remediation: "Validate URL protocol (https only) and hostname against an allowlist." });
                        }
                    } else if (sink.type === "sql") {
                        if (hasTypeValidation) {
                            findings.push({ severity: "high", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `Tool input passes type check but is vulnerable to SQL injection.`, remediation: "Use parameterized queries (e.g. $1, ?) instead of string interpolation for database operations." });
                        } else {
                            findings.push({ severity: "critical", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `SQL injection risk from tool input.`, remediation: "Use parameterized queries (e.g. $1, ?) instead of string interpolation for database operations." });
                        }
                    }
                    
                    break; // one sink finding per line
                }
            }

            /* ── Dynamic dispatch ── */
            for (const dp of DISPATCH_PATTERNS) {
                if (dp.regex.test(line)) {
                    findings.push({ severity: dp.severity, file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: `${dp.name} — could allow arbitrary function invocation.`, remediation: dp.remediation });
                }
            }

            /* ── Dynamic property access — non-sinks ── */
            if (DYNAMIC_ACCESS_REGEX.test(line)) {
                if (!isDynamicAccessSafe(line, file.path)) {
                    const isToolHandler = /server\.tool|\.addTool|@server\.tool|@mcp\.tool|tool_handler|ToolHandler/.test(content);
                    if (isToolHandler && !hasTypeValidation) {
                        findings.push({ severity: "medium", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "Dynamic property access on args in tool handler — validate inputs before use.", remediation: "Validate all tool inputs using a schema validation library like Zod." });
                    }
                }
            }

            /* ── Spread patterns ── */
            if (SPREAD_REGEX.test(line)) {
                if (!isSpreadSafe(line, file.path)) {
                    const isToolHandler = /server\.tool|\.addTool|@server\.tool|@mcp\.tool|tool_handler|ToolHandler/.test(content);
                    if (isToolHandler && !hasTypeValidation) {
                        findings.push({ severity: "low", file: file.path, line: i + 1, snippet: line.trim().slice(0, 200), message: "Spreading args in tool handler — verify all spread targets are safe.", remediation: "Validate all tool inputs before spreading." });
                    }
                }
            }
        }
    }

    if (!hasInputSchema) {
        findings.push({
            severity: "high",
            file: "project",
            line: null,
            snippet: "",
            message: "No inputSchema definitions found. The server accepts arbitrary input without constraints.",
            remediation: "Declare an inputSchema for all tools. Use JSON Schema to constrain inputs, specifying types, required fields, and enum values.",
        });
    }

    // Filter out potential duplicate findings that are overly broad (like if multiple sinks triggered on same line)
    // We already have deduplication at the terminal level, but we can do a quick unique filter here too if needed.
    
    return findings.map(f => ({ ...f, category: 'IV' }));
}

export { analyzeInputValidation };
