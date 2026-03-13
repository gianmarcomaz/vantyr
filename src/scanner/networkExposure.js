/**
 * Network Exposure Analyzer
 *
 * Two-step analysis:
 *   1. Detect 0.0.0.0 / :: / INADDR_ANY bindings (same patterns as before)
 *   2. For each hit, check the SAME file + nearby files for authentication
 *      middleware, webhook/bot indicators, or signing verification.
 *
 * Context-aware:
 *   - Test files are excluded (not production code)
 *   - CLI/build tools are excluded
 *
 * Severity assignment:
 *   - 0.0.0.0 with NO auth detected      → critical
 *   - 0.0.0.0 in a webhook/bot file      → medium
 *   - 0.0.0.0 WITH auth detected         → low
 *   - 127.0.0.1 / localhost / ::1         → pass (no finding)
 */

/* ════════════════════════════════════════════════════
   Detection Patterns — same as original, DO NOT REMOVE
   ════════════════════════════════════════════════════ */

const CRITICAL_PATTERNS = [
    // JavaScript/TypeScript
    { regex: /\.listen\s*\([^)]*['"]0\.0\.0\.0['"]/, lang: "js" },
    { regex: /\.listen\s*\([^)]*['"]::['"]/, lang: "js" },
    { regex: /host\s*[:=]\s*['"]0\.0\.0\.0['"]/, lang: "any" },
    { regex: /host\s*[:=]\s*['"]::['"]/, lang: "any" },
    { regex: /host\s*[:=]\s*['"]["']/, lang: "any" }, // empty string = 0.0.0.0
    // Python
    { regex: /\.bind\s*\(\s*\(\s*['"]0\.0\.0\.0['"]/, lang: "py" },
    { regex: /\.bind\s*\(\s*\(\s*['"]::['"]/, lang: "py" },
    // Go
    { regex: /net\.Listen\s*\([^)]*['"]0\.0\.0\.0/, lang: "go" },
    { regex: /INADDR_ANY/, lang: "any" },
];

const SAFE_PATTERNS = [
    /['"]127\.0\.0\.1['"]/,
    /['"]localhost['"]/,
    /['"]::1['"]/,
];

const WARNING_PATTERNS = [
    { regex: /host\s*[:=]\s*(?:process\.env|os\.environ|os\.Getenv)/, message: "Host from environment variable" },
    { regex: /host\s*[:=]\s*(?:config|settings|options)\./, message: "Host from config (verify default)" },
];

const URL_PATTERNS = [
    {
        regex: /['"`]http:\/\/(?!(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0))[^'"`${}]+['"`]/i,
        severity: "high",
        message: "Unencrypted HTTP communication with external host detected.",
        remediation: "Use HTTPS for all external API communication to prevent man-in-the-middle attacks.",
    },
    {
        regex: /['"`]ws:\/\/(?!(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0))[^'"`${}]+['"`]/i,
        severity: "high",
        message: "Unencrypted WebSocket (ws://) communication with external host detected.",
        remediation: "Use secure WebSockets (wss://) for all external ongoing connections.",
    },
    {
        regex: /['"`](?:http|ws):\/\/\$\{/i,
        severity: "medium",
        message: "Dynamic unencrypted URL detected (http/ws).",
        remediation: "Ensure the dynamically constructed URL uses HTTPS/WSS if connecting to external hosts.",
    },
];

/* ════════════════════════════════════════════════════
   Authentication & Webhook Indicator Patterns
   ════════════════════════════════════════════════════ */

const AUTH_PATTERNS = [
    // Python decorators & middleware
    /@requires_auth/i,
    /@authenticate/i,
    /verify_signature/i,
    /verify_slack_signature/i,
    /signing_secret/i,
    /hmac\./i,
    /token_required/i,
    /api_key_required/i,
    /BasicAuth|BearerAuth/i,
    /OAuth/,

    // Python auth libraries
    /from\s+(?:fastapi\.security|starlette\.authentication|flask_login|flask_httpauth)/,
    /Depends\s*\(\s*\w*[Aa]uth/,

    // JS/TS auth middleware & libraries
    /passport\./,
    /jwt\.verify/i,
    /express-jwt/,
    /next-auth/i,
    /clerk/i,
    /supabase\.auth/i,
    /firebase.*auth/i,
    /req\.headers\s*\[\s*['"]authorization['"]\s*\]/i,
    /req\.headers\.authorization/i,
    /apiKey|api_key/i,
    /bearerToken|bearer_token/i,

    // General auth header checks
    /['"]Authorization['"]/,
    /['"]X-API-Key['"]/i,
    /['"]Bearer\s/i,

    // Middleware with "auth" in the name
    /middleware.*auth/i,
    /auth.*middleware/i,
    /use\s*\(\s*\w*[Aa]uth/,
];

const WEBHOOK_FILE_INDICATORS = [
    // Filename patterns
    /webhook/i,
    /bot\./i,
    /callback/i,
    /_bot\b/i,
    /slack_bot|slackbot/i,
    /whatsapp/i,
    /telegram/i,
    /discord_bot|discordbot/i,
];

const WEBHOOK_CONTENT_INDICATORS = [
    /import\s+.*slack_sdk/,
    /from\s+slack_sdk/,
    /require\s*\(\s*['"]@slack\/bolt['"]\)/,
    /require\s*\(\s*['"]twilio['"]\)/,
    /from\s+twilio/,
    /whatsapp/i,
    /SlackRequestHandler|SlackEventAdapter/i,
    /verify_slack_request|verify_slack_signature/i,
    /TwilioClient/i,
];

/* ════════════════════════════════════════════════════
   Helpers
   ════════════════════════════════════════════════════ */

/**
 * Check if a file (by content) contains authentication patterns.
 */
function fileHasAuth(content) {
    return AUTH_PATTERNS.some((re) => re.test(content));
}

/**
 * Check if a file is a webhook/bot receiver (by path OR content).
 */
function fileIsWebhook(filePath, content) {
    const pathMatch = WEBHOOK_FILE_INDICATORS.some((re) => re.test(filePath));
    const contentMatch = WEBHOOK_CONTENT_INDICATORS.some((re) => re.test(content));
    return pathMatch || contentMatch;
}

/**
 * Build a directory→files lookup for checking "nearby" files in the same dir.
 */
function buildDirIndex(files) {
    const index = {};
    for (const file of files) {
        const dir = file.path.replace(/[/\\][^/\\]+$/, "") || ".";
        if (!index[dir]) index[dir] = [];
        index[dir].push(file);
    }
    return index;
}

/**
 * Check if ANY file in the same directory has auth patterns.
 */
function dirHasAuth(filePath, dirIndex) {
    const dir = filePath.replace(/[/\\][^/\\]+$/, "") || ".";
    const siblings = dirIndex[dir] || [];
    return siblings.some((f) => fileHasAuth(f.content));
}

/** Test file paths — not production code */
const TEST_FILE_RE =
    /(?:[\\/](?:__tests__|tests?|spec|__mocks__|mock|fixture|e2e|testdata|testutil)[\\/]|[\\/](?:.*_test|.*\.test|.*\.spec)\.[a-z]+$)/i;

/** CLI-tool / build-script / dev-tooling paths */
const CLI_TOOL_RE =
    /(?:^|[\\/])(?:cmd|cli|scripts|tools|bin|hack|contrib)[\\/]/i;

/* ════════════════════════════════════════════════════
   Main Analyzer
   ════════════════════════════════════════════════════ */

/**
 * @param {Array<{path: string, content: string}>} files
 * @returns {{ score: number, status: string, findings: Array }}
 */
function analyzeNetworkExposure(files) {
    const findings = [];
    const dirIndex = buildDirIndex(files);

    for (const file of files) {
        const lines = file.content.split("\n");
        const isTestFile = TEST_FILE_RE.test(file.path);
        const isCliTool = CLI_TOOL_RE.test(file.path);

        // Skip test files and CLI tools entirely — not production server code
        if (isTestFile || isCliTool) continue;

        const thisFileHasAuth = fileHasAuth(file.content);
        const thisFileIsWebhook = fileIsWebhook(file.path, file.content);
        const nearbyAuth = dirHasAuth(file.path, dirIndex);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();

            // Skip comments and documentation examples
            if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("<!--")) continue;
            // Skip common documentation keywords
            if (/example|documentation|placeholder/i.test(line)) continue;

            /* ── Step 1: detect 0.0.0.0 binding ── */
            for (const pattern of CRITICAL_PATTERNS) {
                if (!pattern.regex.test(line)) continue;
                // Skip if safe pattern on same line
                if (SAFE_PATTERNS.some((sp) => sp.test(line))) continue;

                /* ── Step 2: contextual severity ── */
                if (thisFileIsWebhook) {
                    findings.push({
                        severity: "medium",
                        file: file.path,
                        line: i + 1,
                        snippet: line.trim(),
                        message:
                            "Webhook receiver binds to all network interfaces. Verify that incoming requests are validated using platform signing secrets (e.g., Slack signing secret, WhatsApp verification token).",
                        remediation:
                            "Validate webhook signatures on every incoming request to prevent unauthorized access.",
                    });
                } else if (thisFileHasAuth || nearbyAuth) {
                    findings.push({
                        severity: "low",
                        file: file.path,
                        line: i + 1,
                        snippet: line.trim(),
                        message:
                            "Server binds to all network interfaces. Authentication middleware detected — verify it covers all MCP endpoints.",
                        remediation:
                            "Ensure authentication is enforced on all tool execution endpoints, not just some routes.",
                    });
                } else {
                    findings.push({
                        severity: "critical",
                        file: file.path,
                        line: i + 1,
                        snippet: line.trim(),
                        message:
                            "Server binds to all network interfaces with no authentication detected. Anyone who can reach this port can execute MCP operations without authorization.",
                        remediation:
                            "Either bind to 127.0.0.1 for local-only access, or add authentication middleware (API key validation, OAuth, or request signing) to protect network-exposed endpoints.",
                    });
                }
            }

            /* ── Warning patterns (env/config host) ── */
            for (const pattern of WARNING_PATTERNS) {
                if (pattern.regex.test(line)) {
                    findings.push({
                        severity: "medium",
                        file: file.path,
                        line: i + 1,
                        snippet: line.trim(),
                        message: pattern.message + " — could be safe or unsafe depending on deployment.",
                        remediation:
                            "Ensure the default value for the host binding is 127.0.0.1 or localhost. Document the expected deployment configuration.",
                    });
                }
            }

            /* ── Unencrypted external URL patterns ── */
            for (const pattern of URL_PATTERNS) {
                if (pattern.regex.test(line)) {
                    findings.push({
                        severity: pattern.severity,
                        file: file.path,
                        line: i + 1,
                        snippet: line.trim().slice(0, 150),
                        message: pattern.message,
                        remediation: pattern.remediation,
                    });
                }
            }

        }
    }

    // Return raw findings with category tagged
    return findings.map(f => ({ ...f, category: 'NE' }));
}

export { analyzeNetworkExposure };
