import { analyzeNetworkExposure } from "./networkExposure.js";
import { analyzeCommandInjection } from "./commandInjection.js";
import { analyzeCredentialLeaks } from "./credentialLeaks.js";
import { analyzeToolPoisoning } from "./toolPoisoning.js";
import { analyzeSpecCompliance } from "./specCompliance.js";
import { analyzeInputValidation } from "./inputValidation.js";

// Matches any of the supported ignore-comment forms:
//   // vantyr-ignore
//   # vantyr-ignore
const IGNORE_RE = /vantyr-ignore/i;

/**
 * Filter out findings whose source line (or the line immediately above it)
 * carries a vantyr-ignore comment. Project-level findings (no line number)
 * are never suppressed this way.
 *
 * Supported comment styles:
 *   // vantyr-ignore        (JS / TS / Go)
 *   # vantyr-ignore         (Python / YAML / shell)
 *
 * The comment can appear on the flagged line itself or on the line above —
 * either placement is conventional and both are honoured.
 */
function suppressIgnoredFindings(findings, files) {
    const fileLines = new Map();
    for (const file of files) {
        fileLines.set(file.path, file.content.split('\n'));
    }

    return findings.filter(finding => {
        if (!finding.file || finding.line == null) return true;

        const lines = fileLines.get(finding.file);
        if (!lines) return true;

        const idx = finding.line - 1; // findings use 1-based line numbers
        if (lines[idx] && IGNORE_RE.test(lines[idx])) return false;
        if (idx > 0 && lines[idx - 1] && IGNORE_RE.test(lines[idx - 1])) return false;

        return true;
    });
}

/**
 * Runs all 6 security checks against a list of files and returns a flat
 * findings array with any vantyr-ignore suppressions applied.
 * @param {Array<{path: string, content: string}>} files
 * @returns {Array}
 */
export function runAllChecks(files) {
    const allFindings = [
        ...analyzeNetworkExposure(files),
        ...analyzeCommandInjection(files),
        ...analyzeCredentialLeaks(files),
        ...analyzeToolPoisoning(files),
        ...analyzeSpecCompliance(files),
        ...analyzeInputValidation(files),
    ];

    return suppressIgnoredFindings(allFindings, files);
}
