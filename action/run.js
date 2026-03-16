/**
 * Vantyr GitHub Action — main run script.
 *
 * Executed by action.yml as: node ${{ github.action_path }}/run.js
 *
 * Steps:
 *   A. Resolve the scan target URL
 *   B. Fetch files and run the Vantyr scan pipeline (same functions as the CLI)
 *   C. Write vantyr-results.sarif for the upload-sarif step
 *   D. Post (or update) a PR comment if running on a pull_request event
 *   E. Evaluate threshold and exit with code 1 if the score is too low
 */

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import https from 'https';

// ── Resolve paths relative to this file so the action works regardless of cwd ──
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import from the existing Vantyr source tree
import { fetchRepoFiles } from '../src/fetcher/github.js';
import { runAllChecks } from '../src/scanner/index.js';
import { calculateTrustScore } from '../src/scoring/trustScore.js';
import { formatJsonResult } from '../src/output/json.js';
import { formatSarifResult } from '../src/output/sarif.js';
import { buildComment, buildErrorComment, COMMENT_MARKER } from './comment.js';

// ── Environment variables injected by action.yml ─────────────────────────────
const INPUT_TARGET       = process.env.INPUT_TARGET       || '';
const INPUT_THRESHOLD    = parseInt(process.env.INPUT_THRESHOLD || '70', 10);
const INPUT_POST_COMMENT = process.env.INPUT_POST_COMMENT !== 'false';
const INPUT_UPLOAD_SARIF = process.env.INPUT_UPLOAD_SARIF !== 'false';
const INPUT_TOKEN        = process.env.INPUT_TOKEN || process.env.GITHUB_TOKEN || '';
const GITHUB_REPOSITORY  = process.env.GITHUB_REPOSITORY || '';
const GITHUB_EVENT_NAME  = process.env.GITHUB_EVENT_NAME || '';
const GITHUB_EVENT_PATH  = process.env.GITHUB_EVENT_PATH || '';

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(msg) {
    console.log(`[vantyr] ${msg}`);
}

function fail(msg) {
    console.error(`[vantyr] ERROR: ${msg}`);
    process.exit(1);
}

/**
 * Make a GitHub REST API request using Node's built-in https module.
 * Returns the parsed JSON response body.
 */
function githubApiRequest(method, path, body, token) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const options = {
            hostname: 'api.github.com',
            port: 443,
            path,
            method,
            headers: {
                'User-Agent': 'vantyr-action/1.0',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
            },
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, body: data ? JSON.parse(data) : {} });
                } catch {
                    resolve({ status: res.statusCode, body: data });
                }
            });
        });

        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

/**
 * Find an existing Vantyr comment on a PR (identified by the COMMENT_MARKER).
 * Returns the comment id if found, otherwise null.
 */
async function findExistingComment(owner, repo, prNumber, token) {
    let page = 1;
    while (true) {
        const { status, body } = await githubApiRequest(
            'GET',
            `/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`,
            null,
            token
        );
        if (status !== 200 || !Array.isArray(body) || body.length === 0) break;
        const match = body.find(c => c.body && c.body.includes(COMMENT_MARKER));
        if (match) return match.id;
        if (body.length < 100) break;
        page++;
    }
    return null;
}

/**
 * Create or update the Vantyr PR comment.
 */
async function upsertComment(owner, repo, prNumber, markdown, token) {
    const existingId = await findExistingComment(owner, repo, prNumber, token);

    if (existingId) {
        const { status } = await githubApiRequest(
            'PATCH',
            `/repos/${owner}/${repo}/issues/comments/${existingId}`,
            { body: markdown },
            token
        );
        if (status === 200) {
            log(`Updated existing PR comment (id: ${existingId}).`);
        } else {
            log(`Warning: failed to update comment (HTTP ${status}).`);
        }
    } else {
        const { status } = await githubApiRequest(
            'POST',
            `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
            { body: markdown },
            token
        );
        if (status === 201) {
            log('Posted new PR comment.');
        } else {
            log(`Warning: failed to post comment (HTTP ${status}).`);
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    // ── A. Resolve scan target ────────────────────────────────────────────────
    let targetUrl = INPUT_TARGET.trim();
    if (!targetUrl) {
        if (!GITHUB_REPOSITORY) fail('No target URL provided and GITHUB_REPOSITORY is not set.');
        targetUrl = `https://github.com/${GITHUB_REPOSITORY}`;
    }

    // Strip .git suffix and trailing /tree/... paths (mirrors cli.js behaviour)
    targetUrl = targetUrl.replace(/\.git$/, '').replace(/\/(tree|blob)\/.*$/, '').replace(/\/$/, '');

    const REPO_URL_RE = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)$/;
    const match = targetUrl.match(REPO_URL_RE);
    if (!match) fail(`Invalid GitHub URL: ${targetUrl}`);

    const [, owner, repo] = match;
    log(`Scanning ${owner}/${repo} (threshold: ${INPUT_THRESHOLD}/100)...`);

    // ── B. Run the scan pipeline ──────────────────────────────────────────────
    let jsonResult;
    let sarifResult;
    let scanError = null;

    try {
        const { files, capped, totalFound } = await fetchRepoFiles(owner, repo, INPUT_TOKEN);

        if (files.length === 0) {
            throw new Error('No scannable source files found in the repository.');
        }

        if (capped) {
            log(`Large repository: ${totalFound} eligible files found, only the first 100 were scanned.`);
        }

        log(`Fetched ${files.length} files. Running analyzers...`);

        const findings  = runAllChecks(files);
        const scoreData = calculateTrustScore(findings);

        jsonResult  = formatJsonResult(targetUrl, { scoreData });
        sarifResult = formatSarifResult(targetUrl, { scoreData });

        log(`Scan complete. Trust Score: ${scoreData.trustScore}/100 (${jsonResult.label})`);
    } catch (err) {
        scanError = err.message || String(err);
        console.error(`[vantyr] Scan failed: ${scanError}`);
    }

    // ── C. Write SARIF file ───────────────────────────────────────────────────
    if (INPUT_UPLOAD_SARIF) {
        const sarifPath = join(process.cwd(), 'vantyr-results.sarif');
        const sarifDoc = sarifResult
            ? sarifResult
            : formatSarifResult(targetUrl, { scoreData: null, noFiles: true });
        writeFileSync(sarifPath, JSON.stringify(sarifDoc, null, 2), 'utf8');
        log(`SARIF written to ${sarifPath}`);
    }

    // ── D. Post PR comment ────────────────────────────────────────────────────
    const isPr = GITHUB_EVENT_NAME === 'pull_request' || GITHUB_EVENT_NAME === 'pull_request_target';

    if (INPUT_POST_COMMENT && isPr) {
        let prNumber = null;
        try {
            const event = JSON.parse(readFileSync(GITHUB_EVENT_PATH, 'utf8'));
            prNumber = event?.pull_request?.number ?? event?.number ?? null;
        } catch {
            log('Warning: could not parse GitHub event payload to find PR number.');
        }

        if (prNumber && INPUT_TOKEN) {
            const markdown = scanError
                ? buildErrorComment(scanError)
                : buildComment(jsonResult, INPUT_THRESHOLD);

            try {
                await upsertComment(owner, repo, prNumber, markdown, INPUT_TOKEN);
            } catch (err) {
                log(`Warning: could not post PR comment — ${err.message}`);
            }
        } else if (!INPUT_TOKEN) {
            log('Warning: no token available; skipping PR comment.');
        }
    }

    // ── E. Threshold check and exit code ──────────────────────────────────────
    if (scanError) {
        console.error('[vantyr] Exiting with code 1 due to scan error.');
        process.exit(1);
    }

    const score = jsonResult.trustScore;
    if (score >= INPUT_THRESHOLD) {
        log(`Trust Score ${score}/100 — PASSED (threshold: ${INPUT_THRESHOLD})`);
    } else {
        console.error(`[vantyr] Trust Score ${score}/100 — FAILED (threshold: ${INPUT_THRESHOLD})`);
        process.exit(1);
    }
}

main();
