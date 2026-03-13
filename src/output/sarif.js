/**
 * SARIF 2.1.0 output formatter for vantyr.
 *
 * SARIF (Static Analysis Results Interchange Format) is the standard consumed
 * by GitHub Code Scanning. Uploading this file as a GitHub Actions artifact
 * (upload-sarif action) produces inline PR annotations and populates the repo's
 * "Security → Code scanning" tab automatically.
 *
 * Severity mapping:
 *   critical / high  → level "error"   (blocks PR merge in strict configurations)
 *   medium           → level "warning"
 *   low / info       → level "note"
 */

const SARIF_SCHEMA =
    'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

// One rule per analyzer category — each rule appears in the "Rules" panel of
// GitHub Code Scanning and links to the relevant OWASP MCP guidance.
const RULES = [
    {
        id: 'MCP-NE',
        name: 'NetworkExposure',
        shortDescription: { text: 'Network Exposure' },
        fullDescription: {
            text: 'Detects wildcard network bindings (0.0.0.0, ::, INADDR_ANY) and unencrypted external HTTP/WebSocket communication that expose MCP endpoints to unauthorized access.',
        },
        helpUri: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        properties: { tags: ['security', 'network', 'mcp'] },
    },
    {
        id: 'MCP-CI',
        name: 'CommandInjection',
        shortDescription: { text: 'Command Injection' },
        fullDescription: {
            text: 'Detects shell execution functions (exec, spawn, os.system, subprocess, eval) that could allow remote code execution when driven by LLM-controlled input. Maps to OWASP MCP05.',
        },
        helpUri: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        properties: { tags: ['security', 'injection', 'rce', 'mcp'] },
    },
    {
        id: 'MCP-CL',
        name: 'CredentialLeaks',
        shortDescription: { text: 'Credential Leaks' },
        fullDescription: {
            text: 'Detects hardcoded secrets, API keys, tokens, private keys, and database URLs with embedded passwords committed to source control. Maps to OWASP MCP01.',
        },
        helpUri: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        properties: { tags: ['security', 'secrets', 'credentials', 'mcp'] },
    },
    {
        id: 'MCP-TP',
        name: 'ToolPoisoning',
        shortDescription: { text: 'Tool Poisoning / Prompt Injection' },
        fullDescription: {
            text: 'Detects prompt injection payloads embedded in MCP tool descriptions: instruction overrides, identity hijacks, zero-width Unicode characters, HTML comments, and shadowed tool names. Maps to OWASP MCP03.',
        },
        helpUri: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        properties: { tags: ['security', 'prompt-injection', 'mcp'] },
    },
    {
        id: 'MCP-SC',
        name: 'SpecCompliance',
        shortDescription: { text: 'MCP Spec Compliance' },
        fullDescription: {
            text: 'Validates MCP protocol conformance: server metadata, tool schema declarations, error handling, transport security, and documentation completeness.',
        },
        helpUri: 'https://modelcontextprotocol.io/specification',
        properties: { tags: ['compliance', 'protocol', 'mcp'] },
    },
    {
        id: 'MCP-IV',
        name: 'InputValidation',
        shortDescription: { text: 'Input Validation' },
        fullDescription: {
            text: 'Detects unsanitized tool input flowing into dangerous sinks: file operations (path traversal), network requests (SSRF), SQL queries (injection), and dynamic function dispatch.',
        },
        helpUri: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
        properties: { tags: ['security', 'input-validation', 'ssrf', 'sqli', 'mcp'] },
    },
];

/** Map a finding category code to its SARIF rule ID. */
const CATEGORY_TO_RULE_ID = {
    NE: 'MCP-NE',
    CI: 'MCP-CI',
    CL: 'MCP-CL',
    TP: 'MCP-TP',
    SC: 'MCP-SC',
    IV: 'MCP-IV',
};

/** Map vantyr severity levels to SARIF result levels. */
function toSarifLevel(severity) {
    switch (severity) {
        case 'critical':
        case 'high':
            return 'error';
        case 'medium':
            return 'warning';
        case 'low':
        case 'info':
        default:
            return 'note';
    }
}

/**
 * Build a SARIF 2.1.0 document from vantyr scan results.
 *
 * @param {string} sourceUrl  - The scanned GitHub URL or "Local Configuration & Rules"
 * @param {{ scoreData: object|null, noFiles?: boolean }} results
 * @returns {object}          - A plain object ready for JSON.stringify()
 */
export function formatSarifResult(sourceUrl, { scoreData, noFiles = false }) {
    if (noFiles || !scoreData) {
        return {
            $schema: SARIF_SCHEMA,
            version: '2.1.0',
            runs: [
                {
                    tool: {
                        driver: { name: 'vantyr', version: '1.0.0', rules: RULES },
                    },
                    results: [],
                    properties: {
                        trustScore: null,
                        label: 'NO_FILES',
                        source: sourceUrl,
                        message: 'No local MCP configuration or rules files found.',
                    },
                },
            ],
        };
    }

    const { categories, trustScore, scoreCapped } = scoreData;

    // Flatten all findings across every category
    const allFindings = Object.entries(categories).flatMap(([key, cat]) =>
        cat.findings.map(f => ({ ...f, category: key }))
    );

    const sarifResults = allFindings.map(finding => {
        const ruleId = CATEGORY_TO_RULE_ID[finding.category] || finding.category;
        const level = toSarifLevel(finding.severity);

        const result = {
            ruleId,
            level,
            message: {
                text: finding.remediation
                    ? `${finding.message} — ${finding.remediation}`
                    : finding.message,
            },
        };

        // Attach a physical location when we have a file and line number.
        // Project-level findings (file === "project", no line) get a
        // repository-root location so GitHub still displays them.
        if (finding.file && finding.file !== 'project' && finding.line) {
            result.locations = [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: finding.file,
                            uriBaseId: '%SRCROOT%',
                        },
                        region: {
                            startLine: finding.line,
                        },
                    },
                },
            ];
        } else {
            result.locations = [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: '.',
                            uriBaseId: '%SRCROOT%',
                        },
                    },
                },
            ];
        }

        // Attach a code snippet when available
        if (finding.snippet) {
            result.locations[0].physicalLocation.region = {
                ...(result.locations[0].physicalLocation.region || {}),
                snippet: { text: finding.snippet },
            };
        }

        // Embed Trust Score context as a property bag on each result
        result.properties = {
            severity: finding.severity,
            trustScore,
            scoreCapped: scoreCapped || false,
        };

        return result;
    });

    return {
        $schema: SARIF_SCHEMA,
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'vantyr',
                        version: '1.0.0',
                        informationUri: 'https://github.com/gianmarcomaz/vantyr',
                        rules: RULES,
                    },
                },
                // Encode the scanned source as a conversion provenance note
                conversion: {
                    tool: {
                        driver: {
                            name: 'vantyr',
                            version: '1.0.0',
                        },
                    },
                    invocation: {
                        commandLine: `vantyr scan ${sourceUrl}`,
                        executionSuccessful: true,
                    },
                },
                results: sarifResults,
                // Surface the Trust Score as a run-level property visible in dashboards
                properties: {
                    trustScore,
                    label: trustScore >= 80 ? 'CERTIFIED' : trustScore >= 50 ? 'WARNING' : 'FAILED',
                    scoreCapped: scoreCapped || false,
                    source: sourceUrl,
                },
            },
        ],
    };
}
