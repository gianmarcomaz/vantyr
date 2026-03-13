import { Command } from 'commander';
import { fetchRepoFiles } from './fetcher/github.js';
import { discoverLocalFiles } from './config/localScanner.js';
import { runAllChecks } from './scanner/index.js';
import { calculateTrustScore } from './scoring/trustScore.js';
import { printTerminalResult } from './output/terminal.js';
import { formatJsonResult } from './output/json.js';
import { formatSarifResult } from './output/sarif.js';
import chalk from 'chalk';

export async function run() {
    const program = new Command();

    program
        .name('vantyr')
        .description('MCP security scanner — Trust Score for AI dev environments. 100% local, zero telemetry.')
        .version('1.0.0');

    program.command('scan')
        .argument('[url]', 'GitHub repository URL to scan')
        .option('-l, --local', 'Discover local MCP configs and rules files')
        .option('-t, --token <pat>', 'GitHub Personal Access Token for higher rate limits')
        .option('-j, --json', 'Output results as JSON (suppresses all other output, for CI/CD pipelines)')
        .option('-s, --sarif', 'Output results as SARIF 2.1.0 (for GitHub Code Scanning / upload-sarif action)')
        .option('-v, --verbose', 'List every file that was scanned before showing results')
        .action(async (url, options) => {
            // --json and --sarif both emit structured data to stdout, so all
            // progress/status console.log calls must be silenced for those modes.
            const silent = !!(options.json || options.sarif);
            const log = (msg) => { if (!silent) console.log(msg); };
            const logErr = (msg) => {
                if (silent) {
                    console.log(JSON.stringify({ error: msg }));
                } else {
                    console.error(chalk.red(msg));
                }
            };

            try {
                let files = [];
                let sourceUrl = '';

                if (options.local) {
                    log(chalk.dim('\nDiscovering local MCP config and rules files...'));
                    files = discoverLocalFiles();
                    sourceUrl = 'Local Configuration & Rules';

                    if (files.length === 0) {
                        if (options.sarif) {
                            const empty = formatSarifResult(sourceUrl, { scoreData: null, noFiles: true });
                            console.log(JSON.stringify(empty, null, 2));
                        } else if (options.json) {
                            console.log(JSON.stringify({
                                source: sourceUrl,
                                trustScore: null,
                                label: 'NO_FILES',
                                message: 'No local MCP configuration or rules files found. Looked in common locations like ~/.cursor/mcp.json, claude_desktop_config.json, etc.',
                                findings: []
                            }, null, 2));
                        } else {
                            log(chalk.yellow('\nNo local MCP configuration or rules files found.'));
                            log(chalk.dim('Looked in common locations like ~/.cursor/mcp.json, claude_desktop_config.json, etc.'));
                        }
                        return;
                    }
                    log(chalk.green(`Found ${files.length} local configuration/rules files.`));
                    if (options.verbose) {
                        log('');
                        log(chalk.dim('Files:'));
                        for (const f of files) {
                            log(chalk.dim(`  ${f.path}`));
                        }
                    }
                    log('');
                } else {
                    if (!url) {
                        throw new Error('Missing GitHub URL argument. Usage: vantyr scan <github-url>');
                    }

                    // Accept URLs with .git suffix or trailing paths (e.g. copied from browser)
                    const normalizedUrl = url.replace(/\.git$/, '').replace(/\/(tree|blob)\/.*$/, '').replace(/\/$/, '');
                    const REPO_URL_REGEX = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)$/;
                    const match = normalizedUrl.match(REPO_URL_REGEX);

                    if (!match) {
                        throw new Error('Invalid GitHub URL. Please use the format: https://github.com/owner/repo');
                    }

                    const [, owner, repo] = match;
                    sourceUrl = normalizedUrl;

                    log(chalk.dim(`\nFetching repository files from GitHub (${owner}/${repo})...`));
                    const fetchResult = await fetchRepoFiles(owner, repo, options.token);
                    files = fetchResult.files;

                    if (files.length === 0) {
                        throw new Error('No scannable source files found in the repository. The repository may be empty or contain only unsupported file types.');
                    }
                    log(chalk.green(`Fetched ${files.length} files successfully.`));
                    if (fetchResult.capped) {
                        log(chalk.yellow(`   ⚠ Large repository: ${fetchResult.totalFound} eligible files found but only the first 100 were scanned. Results may not reflect the full codebase. Consider reviewing skipped files manually.`));
                    }
                    if (options.verbose) {
                        log('');
                        log(chalk.dim(`Files scanned (${files.length}):`));
                        for (const f of files) {
                            log(chalk.dim(`  ${f.path}`));
                        }
                    }
                    log('');
                }

                // Run analyzers
                const checks = runAllChecks(files);

                // Calculate Trust Score
                const scoreData = calculateTrustScore(checks);

                // Output — mutually exclusive structured formats, terminal is default
                if (options.sarif) {
                    const result = formatSarifResult(sourceUrl, { scoreData });
                    console.log(JSON.stringify(result, null, 2));
                } else if (options.json) {
                    const result = formatJsonResult(sourceUrl, { scoreData });
                    console.log(JSON.stringify(result, null, 2));
                } else {
                    printTerminalResult(sourceUrl, { scoreData, checks });
                }

                // Exit Code (using process.exitCode to allow async drain)
                if (scoreData.trustScore < 50) {
                    process.exitCode = 1;
                }

            } catch (err) {
                logErr(`\nError: ${err.message}\n`);
                process.exitCode = 1;
            }
        });

    // Parse arguments or show help
    if (process.argv.length < 3) {
        program.help();
        return;
    }

    await program.parseAsync(process.argv);
}
