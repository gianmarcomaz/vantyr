const ALLOWED_EXTENSIONS = new Set([
    ".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rs",
    ".json", ".yaml", ".yml", ".toml", ".env", ".md",
]);

const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", "vendor",
    "__pycache__", ".next", ".nuxt", "coverage", ".venv",
]);

const MAX_FILE_SIZE = 100 * 1024; // 100KB

/**
 * Fetch the file tree and contents from a GitHub repository.
 * @param {string} owner - Repo owner
 * @param {string} repo - Repo name
 * @param {string} token - Optional GitHub personal access token
 * @returns {Promise<Array<{path: string, content: string}>>}
 */
export async function fetchRepoFiles(owner, repo, token) {
    // 1. Get the default branch
    const repoData = await githubGet(`/repos/${owner}/${repo}`, token);
    const branch = repoData.default_branch || "main";

    // 2. Get the recursive file tree
    const treeData = await githubGet(
        `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
        token
    );

    if (!treeData.tree || !Array.isArray(treeData.tree)) {
        throw new Error("Could not fetch repository file tree. Check that the repository exists and is accessible.");
    }

const REQUIRED_FILES = new Set([".gitignore", ".env", ".env.local"]);

    // 3. Filter files
    const filePaths = treeData.tree
        .filter((item) => {
            if (item.type !== "blob") return false;
            if (item.size && item.size > MAX_FILE_SIZE) return false;

            const filename = item.path.split("/").pop();
            const isRequired = REQUIRED_FILES.has(filename);

            // Check extension (if not explicitly required)
            if (!isRequired) {
                const ext = getExtension(item.path);
                if (!ALLOWED_EXTENSIONS.has(ext)) return false;
            }

            // Check for skipped directories
            const parts = item.path.split("/");
            for (const part of parts) {
                if (SKIP_DIRS.has(part)) return false;
            }

            return true;
        })
        .map((item) => item.path);

    // 4. Fetch file contents (max 100 files to stay within timeout)
    const FILE_LIMIT = 100;
    const capped = filePaths.length > FILE_LIMIT;
    const limitedPaths = filePaths.slice(0, FILE_LIMIT);
    const files = [];

    // Fetch in batches of 5 to respect rate limits
    for (let i = 0; i < limitedPaths.length; i += 5) {
        const batch = limitedPaths.slice(i, i + 5);
        const results = await Promise.all(
            batch.map(async (path) => {
                try {
                    const data = await githubGet(
                        `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`,
                        token
                    );
                    if (data.encoding === "base64" && data.content) {
                        const content = Buffer.from(data.content, "base64").toString("utf-8");
                        return { path, content };
                    }
                    return null;
                } catch (err) {
                    return null;
                }
            })
        );
        files.push(...results.filter(Boolean));
    }

    return { files, capped, totalFound: filePaths.length };
}

/**
 * Make a GET request to the GitHub API using native fetch.
 */
async function githubGet(path, token) {
    const headers = {
        "User-Agent": "MCP-Certify/1.0",
        "Accept": "application/vnd.github.v3+json",
    };
    
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const url = `https://api.github.com${path}`;
    
    try {
        const response = await fetch(url, { headers });

        if (!response.ok) {
            if (response.status === 404) {
                // Determine if it was a repo 404 or a file 404
                const isRepoPath = path.startsWith('/repos/') && !path.includes('/contents/') && !path.includes('/git/trees/');
                if (isRepoPath) {
                    const parts = path.split('/');
                    throw new Error(`Repository not found: ${parts[2]}/${parts[3]}. Check that the URL is correct and the repository is public.`);
                }
                throw new Error(`GitHub API error 404: Not Found (${path})`);
            }
            
            if (response.status === 403 || response.status === 429) {
                const limit = response.headers.get("x-ratelimit-limit");
                const remaining = response.headers.get("x-ratelimit-remaining");
                
                if (remaining === "0") {
                    throw new Error(`GitHub API rate limit exceeded (${limit} req/hr). Use the --token <github-pat> flag for authenticated access (5000 req/hr). Generate a token at: https://github.com/settings/tokens`);
                }
                
                const data = await response.json().catch(() => ({}));
                if (data.message?.toLowerCase().includes('private')) {
                    throw new Error('Repository is private or requires authentication. Use --token <github-pat> to access private repositories.');
                }
                
                throw new Error(`GitHub API error ${response.status}: ${data.message || 'Forbidden'}`);
            }
            
            const body = await response.text().catch(() => '');
            throw new Error(`GitHub API error ${response.status}: ${body.slice(0, 300) || response.statusText}`);
        }

        return response.json();
    } catch (err) {
        if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
            throw new Error('Could not connect to GitHub API. Check your internet connection.');
        }
        throw err;
    }
}

function getExtension(filePath) {
    const dot = filePath.lastIndexOf(".");
    return dot >= 0 ? filePath.slice(dot) : "";
}
