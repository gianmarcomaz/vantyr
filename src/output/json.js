/**
 * JSON output formatter for vantyr.
 * Produces a stable, machine-readable structure suitable for CI/CD pipelines,
 * dashboards, or downstream tooling.
 */

const CATEGORY_NAMES = {
    NE: 'Network Exposure',
    CI: 'Command Injection',
    CL: 'Credential Leaks',
    TP: 'Tool Poisoning',
    SC: 'Spec Compliance',
    IV: 'Input Validation',
};

/**
 * @param {string} sourceUrl
 * @param {{ scoreData: object }} results
 * @returns {object}
 */
export function formatJsonResult(sourceUrl, { scoreData }) {
    const { trustScore, categories, totalFindings, stats, passCount, scoreCapped } = scoreData;

    let label = 'CERTIFIED';
    if (trustScore < 50) label = 'FAILED';
    else if (trustScore < 80) label = 'WARNING';

    // Flatten all findings into a single array with category metadata attached
    const allFindings = Object.entries(categories).flatMap(([key, cat]) =>
        cat.findings.map(f => ({
            category: key,
            categoryName: CATEGORY_NAMES[key] || key,
            severity: f.severity,
            file: f.file || null,
            line: f.line || null,
            snippet: f.snippet || '',
            message: f.message || '',
            remediation: f.remediation || '',
        }))
    );

    return {
        source: sourceUrl,
        trustScore,
        label,
        scoreCapped: scoreCapped || false,
        categories: Object.fromEntries(
            Object.entries(categories).map(([key, cat]) => [
                key,
                {
                    name: CATEGORY_NAMES[key] || key,
                    score: cat.score,
                    passed: cat.score >= 80,
                    findingCount: cat.findings.length,
                    findings: cat.findings,
                },
            ])
        ),
        stats,
        passCount,
        totalFindings,
        findings: allFindings,
    };
}
