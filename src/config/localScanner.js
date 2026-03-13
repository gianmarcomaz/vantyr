import fs from 'fs';
import path from 'path';
import os from 'os';

/**
 * Discovers and reads local MCP configuration files and rule files.
 * @returns {Array<{path: string, content: string}>}
 */
export function discoverLocalFiles() {
    const homedir = os.homedir();
    const cwd = process.cwd();
    const isWindows = os.platform() === 'win32';
    const appData = process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming');

    // 1. MCP Config locations
    const configLocations = [
        path.join(homedir, '.cursor', 'mcp.json'),
        path.join(homedir, '.codeium', 'windsurf', 'mcp_config.json'),
        isWindows 
            ? path.join(appData, 'Claude', 'claude_desktop_config.json')
            : path.join(homedir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
        path.join(cwd, '.vscode', 'mcp.json'),
        path.join(cwd, '.cursor', 'mcp.json')
    ];

    // 2. Rules files in current directory
    const ruleFiles = [
        '.cursorrules',
        '.windsurfrules',
        '.clinerules',
        'CLAUDE.md',
        'copilot-instructions.md'
    ].map(f => path.join(cwd, f));

    const allPaths = [...configLocations, ...ruleFiles];
    const files = [];

    for (const filePath of allPaths) {
        try {
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf-8');
                files.push({ path: filePath, content });
            }
        } catch (err) {
            // Silently skip unreadable files
        }
    }

    return files;
}
