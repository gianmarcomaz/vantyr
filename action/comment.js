import { getBadgeUrl } from './badge.js';

/** HTML marker used to identify and update existing Vantyr comments. */
export const COMMENT_MARKER = '<!-- vantyr-scan -->';

const CATEGORY_META = {
    CL: { name: 'Credential Leaks', weight: '25%', owasp: 'MCP01' },
    CI: { name: 'Command Injection', weight: '20%', owasp: 'MCP05' },
    NE: { name: 'Network Exposure', weight: '15%', owasp: 'MCP07' },
    IV: { name: 'Input Validation', weight: '15%', owasp: 'SSRF' },
    TP: { name: 'Tool Poisoning', weight: '15%', owasp: 'MCP03' },
    SC: { name: 'Spec Compliance', weight: '10%', owasp: 'Protocol' },
};

/**
 * Build the full PR comment markdown string from a JSON scan result.
 *
 * @param {object} result - Output from formatJsonResult()
 * @param {number} threshold - Configured pass threshold
 * @returns {string} Markdown string ready to POST to the GitHub API
 */
export function buildComment(result, threshold) {
    const { trustScore, label, scoreCapped, categories, stats, findings } = result;

    const passed = trustScore >= threshold;
    const verdict = passed ? '✅ PASSED' : '❌ FAILED';
    const labelEmoji = label === 'CERTIFIED' ? '🟢' : label === 'WARNING' ? '🟡' : '🔴';

    // Category scorecard table
    const categoryRows = Object.entries(CATEGORY_META)
        .map(([code, meta]) => {
            const cat = categories[code];
            const score = cat ? cat.score : 100;
            const icon = score >= 80 ? '🟢' : score >= 50 ? '🟡' : '🔴';
            return `| ${icon} ${meta.name} | ${score}/100 | ${meta.weight} | ${meta.owasp} |`;
        })
        .join('\n');

    // High/Critical findings table (only shown when relevant)
    const severeFindings = findings.filter(
        f => f.severity === 'critical' || f.severity === 'high'
    );

    let findingsSection = '';
    if (severeFindings.length > 0) {
        const rows = severeFindings
            .slice(0, 10) // cap to keep comment readable
            .map(f => {
                const sev = f.severity === 'critical' ? '🔴 CRITICAL' : '🟠 HIGH';
                const file = f.file && f.file !== 'project' ? `\`${f.file}\`` : '_(project-level)_';
                const line = f.line ? f.line : '—';
                const msg = f.message.replace(/\|/g, '\\|').slice(0, 80);
                return `| ${sev} | ${file} | ${line} | ${msg} |`;
            })
            .join('\n');

        const overflow = severeFindings.length > 10
            ? `\n_...and ${severeFindings.length - 10} more. Run the scan locally for the full list._`
            : '';

        findingsSection = `
### High & Critical Findings

| Severity | File | Line | Description |
|----------|------|------|-------------|
${rows}${overflow}`;
    }

    // Score capped warning
    const cappedWarning = scoreCapped
        ? '\n> ⚠️ **Score capped at 75** — circuit breaker active. Resolve all HIGH and CRITICAL findings to unlock full scoring.\n'
        : '';

    // Badge snippet
    const badgeUrl = getBadgeUrl(trustScore);
    const badgeSnippet = `\`![Vantyr Trust Score](${badgeUrl})\``;

    return `${COMMENT_MARKER}
## Vantyr MCP Security Scan

### ${labelEmoji} Trust Score: **${trustScore}/100** — ${verdict}
${cappedWarning}
| Category | Score | Weight | OWASP |
|----------|-------|--------|-------|
${categoryRows}

### Findings Summary
- 🔴 Critical: **${stats.critical}**
- 🟠 High: **${stats.high}**
- 🟡 Medium: **${stats.medium}**
- 🔵 Low: **${stats.low}**
${findingsSection}

---
📛 **Add this badge to your README:**
${badgeSnippet}

> Threshold: ${threshold}/100 &nbsp;|&nbsp; [Vantyr](https://github.com/gianmarcomaz/vantyr) — Zero-telemetry MCP security scanner`;
}

/**
 * Build a minimal error comment when the scan itself fails.
 *
 * @param {string} errorMessage
 * @returns {string}
 */
export function buildErrorComment(errorMessage) {
    return `${COMMENT_MARKER}
## Vantyr MCP Security Scan

❌ **Scan failed**

\`\`\`
${errorMessage}
\`\`\`

> [Vantyr](https://github.com/gianmarcomaz/vantyr) — Zero-telemetry MCP security scanner`;
}
