/**
 * Spec Compliance Analyzer
 * Validates MCP server protocol conformance.
 *
 * Supports patterns from JS/TS, Python, and Go MCP SDKs.
 */

/**
 * @param {Array<{path: string, content: string}>} files
 * @returns {Array}
 */
function analyzeSpecCompliance(files) {
    const findings = [];

    const allContent = files.map((f) => f.content).join("\n");
    const allPaths = files.map((f) => f.path);

    // ─── CHECK 1: Server manifest/metadata ───
    const hasServerName =
        /server[_-]?name/i.test(allContent) ||
        /(?:createServer|McpServer|Server|mcp\.NewServer|NewServer)\s*\(\s*\{[\s\S]{0,100}?name\s*:/i.test(allContent) ||
        /name\s*=\s*['"][a-zA-Z0-9_-]+[-_]mcp[-_]/i.test(allContent);
    const hasVersion =
        /server[_-]?version|mcp[_-]?version/i.test(allContent) ||
        /(?:createServer|McpServer|Server|mcp\.NewServer|NewServer)\s*\(\s*\{[\s\S]{0,100}?version\s*:/i.test(allContent);
    const hasCapabilities =
        /capabilities\s*[:=]/.test(allContent) ||
        /setCapabilities/.test(allContent) ||
        /WithCapabilities|ServerCapabilities|Capabilities\s*\{/.test(allContent);  // Go

    if (!(hasServerName && hasVersion)) {
        findings.push({
            severity: "medium",
            file: "project",
            line: null,
            snippet: "",
            message: `Server ${!hasServerName ? "name" : "version"} not found in source code.`,
            remediation: "Declare server name and version in your MCP server configuration.",
        });
    }
    if (!hasCapabilities) {
        findings.push({
            severity: "low",
            file: "project",
            line: null,
            snippet: "",
            message: "No explicit capabilities declaration found.",
            remediation: "Declare server capabilities to inform clients what features are supported.",
        });
    }

    const hasProtocolSupport = /@modelcontextprotocol\/sdk|mcp[_-]python|mcp[_-]sdk|github\.com\/mark3b\/mcp|mcp-go|protocolVersion/i.test(allContent);
    if (!hasProtocolSupport) {
        findings.push({
            severity: "medium",
            file: "project",
            line: null,
            snippet: "",
            message: "No MCP SDK or protocol version declaration found.",
            remediation: "Use an official MCP SDK or explicitly declare protocol compatibility.",
        });
    }

    // ─── CHECK 2: Tool definitions structure ───

    // Pattern 1: Direct SDK calls (JS/TS/Python)
    const hasDirectSDKCall =
        /server\.tool\s*\(/.test(allContent) ||
        /\.addTool\s*\(/.test(allContent) ||
        /\.registerTools?\s*\(/.test(allContent) ||
        /@server\.tool/.test(allContent) ||
        /@mcp\.tool/.test(allContent);

    // Pattern 2: Variable-then-register
    const hasVarThenRegister =
        /(?:const|let|var)\s+\w+\s*=\s*\{[^}]*name\s*:/.test(allContent) &&
        /(?:addTool|registerTool|server\.tool)/.test(allContent);

    // Pattern 3: Array of tools
    const hasToolArray =
        /tools\s*[:=]\s*\[/.test(allContent) ||
        /(?:const|let|var)\s+tools\s*=\s*\[/.test(allContent);

    // Pattern 4: Object matching MCP tool shape (name + description + inputSchema)
    const hasToolShapeObject =
        /name\s*[:=]\s*['"][\w-]+['"]/.test(allContent) &&
        /description\s*[:=]\s*['"][^'"]{3,}['"]/.test(allContent) &&
        /inputSchema|input_schema|InputSchema/.test(allContent);

    // Pattern 5: Tool definition files (tools.ts, toolDefinitions.ts, etc.)
    const hasToolDefFile = allPaths.some((p) =>
        /[\/\\](?:tools|toolDefinitions|tool[_-]?defs|mcpTools)\.(?:ts|js|py)$/i.test(p)
    );

    // Go SDK patterns
    const hasGoToolDef =
        /mcp\.NewTool\s*\(/.test(allContent) ||
        /\.AddTool\s*\(/.test(allContent) ||
        /AddTools?\s*\(/.test(allContent) ||
        /RegisterTool/.test(allContent);

    const hasToolDef = hasDirectSDKCall || hasVarThenRegister || hasToolArray ||
                       hasToolShapeObject || hasToolDefFile || hasGoToolDef;

    const hasInputSchema =
        /inputSchema|input_schema|parameters\s*[:=]\s*\{/.test(allContent) ||
        /InputSchema|mcp\.Property|WithDescription|Required\s*[:=]/.test(allContent);
    const hasSchemaType =
        /"type"\s*:\s*"object"/.test(allContent) || /type\s*[:=]\s*['"]object['"]/.test(allContent);
    const hasProperties =
        /"properties"\s*:/.test(allContent) || /properties\s*[:=]/.test(allContent);

    if (hasToolDef) {
        if (hasInputSchema) {
            if (!hasSchemaType && !/InputSchema/.test(allContent)) {
                findings.push({
                    severity: "medium",
                    file: "project",
                    line: null,
                    snippet: "",
                    message: "Tool input schema lacks a top-level 'type' field.",
                    remediation: "Ensure the root of the inputSchema is an explicitly typed 'object'.",
                });
            }
        } else {
            findings.push({
                severity: "medium",
                file: "project",
                line: null,
                snippet: "",
                message: "Tool definitions found but no input schemas detected.",
                remediation: "Define inputSchema with JSON Schema for each tool to enable input validation.",
            });
        }
    } else {
        findings.push({
            severity: "medium",
            file: "project",
            line: null,
            snippet: "",
            message: "No MCP tool definitions found.",
            remediation: "Define tools using the MCP SDK's server.tool() or equivalent method.",
        });
    }

    // ─── CHECK 3: Error handling ───
    const hasJsonRpcError =
        /error\s*[:=]\s*\{.*code/s.test(allContent) ||
        /JsonRpcError|McpError/.test(allContent) ||
        /fmt\.Errorf|errors\.Is|errors\.As|errors\.New/.test(allContent);  // Go
    const hasTryCatch =
        /try\s*\{[\s\S]*catch/m.test(allContent) ||
        /if\s+err\s*!=\s*nil/.test(allContent);  // Go error handling
    const hasErrorHandler =
        /\.on\s*\(\s*['"]error['"]|onerror|error_handler|catch_exceptions/.test(allContent) ||
        /ErrorHandler|HandleError/.test(allContent);  // Go

    if (hasTryCatch || hasErrorHandler) {
        const hasSilentErrors = /catch\s*\([^)]*\)\s*\{\s*\}|except\s+Exception[^:]*:\s*pass/.test(allContent);
        if (hasSilentErrors) {
            findings.push({
                severity: "low",
                file: "project",
                line: null,
                snippet: "",
                message: "Silent error handling detected (empty catch block).",
                remediation: "Properly handle and return errors to the language model.",
            });
        }
    } else {
        findings.push({
            severity: "medium",
            file: "project",
            line: null,
            snippet: "",
            message: "No error handling patterns detected in tool handlers.",
            remediation: "Wrap tool handlers in try/catch blocks and return proper JSON-RPC error responses.",
        });
    }
    if (!hasJsonRpcError) {
        findings.push({
            severity: "low",
            file: "project",
            line: null,
            snippet: "",
            message: "No JSON-RPC error response patterns found.",
            remediation: "Return MCP-compliant error objects with error codes and messages.",
        });
    }

    // ─── CHECK 4: Transport implementation ───
    const hasStdio =
        /stdio|StdioServerTransport|stdin|stdout/.test(allContent) ||
        /CommandTransport|StdioTransport/.test(allContent);  // Go
    const hasHttp =
        /SSEServerTransport|HttpServerTransport|express|fastify|http\.createServer/.test(allContent) ||
        /SSEHandler|StreamableHTTP|http\.ListenAndServe/.test(allContent);  // Go

    if (hasHttp) {
        const hasAuth = /auth|authenticate|middleware|bearer|authorization/i.test(allContent);
        if (!hasAuth) {
            findings.push({
                severity: "high",
                file: "project",
                line: null,
                snippet: "",
                message: "HTTP transport without authentication middleware detected.",
                remediation: "Add authentication middleware to protect your HTTP-based MCP server.",
            });
        }
    }

    // ─── CHECK 5: Documentation ───
    const hasReadme = allPaths.some((p) => /readme\.md$/i.test(p));
    const hasToolDescriptions = /description\s*[:=]\s*['"][^'"]{5,}['"]/.test(allContent);

    if (!hasReadme) {
        findings.push({
            severity: "low",
            file: "project",
            line: null,
            snippet: "",
            message: "No README.md file found.",
            remediation: "Create a README with setup instructions, tool documentation, and usage examples.",
        });
    }

    const hasEmptyToolDescriptions = /description\s*[:=]\s*['"]["']/i.test(allContent);
    if (hasEmptyToolDescriptions) {
        findings.push({
            severity: "low",
            file: "project",
            line: null,
            snippet: "",
            message: "Empty tool descriptions detected.",
            remediation: "Provide meaningful descriptions for all tools. LLMs rely on these descriptions to know when and how to use the tool.",
        });
    }

    return findings.map(f => ({ ...f, category: 'SC' }));
}

export { analyzeSpecCompliance };
