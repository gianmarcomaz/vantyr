import chalk from 'chalk';

/**
 * Prints the results to the terminal matching the exact required format.
 * @param {string} sourceUrl - The GitHub URL or 'Local'
 * @param {Object} results - { scoreData, checks }
 */
export function printTerminalResult(sourceUrl, results) {
    const { trustScore, categories, totalFindings, stats, scoreCapped } = results.scoreData;

    console.log();
    let finalLabel = 'CERTIFIED';
    if (trustScore < 50) {
        finalLabel = 'FAILED';
    } else if (trustScore < 80) {
        finalLabel = 'WARNING';
    }

    // Print header
    console.log(`🔒 Vantyr — Trust Score: ${chalk.bold(trustScore)}/100  ${finalLabel}`);
    if (scoreCapped) {
        console.log(chalk.yellow('   ⚠ Score capped at 75: HIGH or CRITICAL findings present. Resolve all critical issues to achieve CERTIFIED.'));
    }
    console.log();

    const allFindings = [];
    
    const orderedChecks = [
        { name: "Network Exposure", key: "NE" },
        { name: "Command Injection", key: "CI" },
        { name: "Credential Leaks", key: "CL" },
        { name: "Tool Poisoning", key: "TP" },
        { name: "Spec Compliance", key: "SC" },
        { name: "Input Validation", key: "IV" },
    ];

    let passedChecks = 0;

    for (const check of orderedChecks) {
        const cat = categories[check.key];
        const pScore = cat.score;
        const findingCount = cat.findings.length;
        
        let icon = '✅';
        let colorChalk = chalk.green;
        
        if (pScore < 50) {
            icon = '❌';
            colorChalk = chalk.red;
        } else if (pScore < 80) {
            icon = '⚠️ ';
            colorChalk = chalk.yellow;
        } else {
            passedChecks++;
        }
        
        let findingText = '';
        if (findingCount > 0) {
            findingText = `  (${findingCount} finding${findingCount > 1 ? 's' : ''})`;
        }
        
        console.log(`${colorChalk(icon)} ${check.name.padEnd(20)} — ${colorChalk(`${pScore}/100`)}${findingText}`);
        
        allFindings.push(...cat.findings.map(f => ({ ...f, categoryName: check.name })));
    }

    console.log();
    console.log(chalk.dim('─────────────────────────────────────────────────'));
    console.log();

    if (allFindings.length > 0) {
        console.log('Remediations:');
        console.log();

        const seenRemediations = new Set();

        for (const finding of allFindings) {
            let isCrit = finding.severity === 'critical';
            let isHigh = finding.severity === 'high';
            let isMed = finding.severity === 'medium';
            let isLow = finding.severity === 'low';
            let isInfo = finding.severity === 'info';
            
            let icon = 'ℹ ';
            let headerColor = chalk.dim;
            
            if (isCrit || isHigh) {
                icon = '❌';
                headerColor = chalk.red;
            } else if (isMed) {
                icon = '⚠️ ';
                headerColor = chalk.yellow;
            }

            const badge = `[${finding.severity.toUpperCase()}]`;
            const categoryBadge = `[${finding.categoryName}]`;
            const filename = finding.file ? finding.file.split(/[\\/]/).pop() : 'project';
            
            let header = `${icon}  ${headerColor(badge)} ${chalk.cyan(categoryBadge)}`;
            if (finding.line) {
                header += ` Line ${finding.line} in ${filename}`;
            } else {
                header += ` In ${filename}`;
            }

            const messageStr = finding.message || '';
            const remStr = finding.remediation || '';
            
            // Deduplication logic
            const uniqKey = `${finding.severity}-${finding.categoryName}-${finding.file}-${finding.line}-${messageStr}-${remStr}`;
            if (seenRemediations.has(uniqKey)) {
                continue;
            }
            seenRemediations.add(uniqKey);

            console.log(`  ${header}`);
            console.log(`     ${messageStr}`);
            if (remStr && remStr !== messageStr) {
                console.log(`     → ${remStr}`);
            }
            console.log();
        }

        console.log(chalk.dim('─────────────────────────────────────────────────'));
    }

    console.log(`Scanned: ${sourceUrl}`);
    console.log(`Checks: 6 | Critical: ${stats.critical} | High: ${stats.high} | Medium: ${stats.medium} | Low: ${stats.low} | Pass: ${passedChecks}/6`);
    console.log();
}
