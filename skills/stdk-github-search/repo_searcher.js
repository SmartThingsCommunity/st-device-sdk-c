/**
 * STDK GitHub Repository Searcher
 * Provides search capabilities across STDK GitHub repositories
 */

const GITHUB_REPOS = {
    main: {
        name: 'st-device-sdk-c',
        url: 'https://github.com/SmartThingsCommunity/st-device-sdk-c',
        rawUrl: 'https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main',
        description: 'STDK core SDK source code'
    },
    ref: {
        name: 'st-device-sdk-c-ref',
        url: 'https://github.com/SmartThingsCommunity/st-device-sdk-c-ref',
        rawUrl: 'https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c-ref/main',
        description: 'STDK reference documents and guides'
    }
};

const KEY_DOCUMENT_PATHS = {
    'getting_started': '/doc/getting_started.md',
    'apis': '/doc/APIs.md',
    'porting_guide': '/doc/porting_guide.md',
    'commercialization': '/doc/Commercialization_Guide.md',
    'mobile_errors': '/doc/mobile_error_codes_guide.md',
    'stdk_config': '/doc/STDK_Config.md',
    'wifi_update': '/doc/WiFi_Update.md',
    'capability_attribute': '/doc/Capability_Attribute_Update.md',
    'key_generation': '/doc/STDK_Key_Generation.md',
    'qr_generation': '/doc/STDK_QR_Generation.md',
    'device_state': '/doc/Device_State_Diagram.md',
    'onboarding_flow': '/doc/onboarding_seq_flow.md'
};

const SOURCE_CODE_PATHS = {
    'iot_main': '/src/iot_main.c',
    'iot_api': '/src/iot_api.c',
    'iot_mqtt': '/src/mqtt/iot_mqtt_client.c',
    'iot_easysetup_ble': '/src/easysetup/iot_easysetup_ble.c',
    'iot_easysetup_http': '/src/easysetup/iot_easysetup_http.c',
    'iot_security': '/src/security/iot_security.c',
    'iot_capability': '/src/capability/iot_capability.c',
    'st_dev': '/src/include/st_dev.h',
    'iot_main_h': '/src/include/iot_main.h',
    'iot_error': '/src/include/iot_error.h'
};

const EXAMPLE_PATHS = {
    'esp32': '/example/esp32',
    'posix': '/example/posix',
    'raspberry_pi': '/example/raspberry'
};

/**
 * Fetch a file from GitHub repository
 * @param {string} repoKey - 'main' or 'ref'
 * @param {string} filePath - File path in repository
 * @returns {Promise<string>} File content
 */
async function fetchFromGitHub(repoKey, filePath) 
{
    const repo = GITHUB_REPOS[repoKey];
    if (!repo) {
        throw new Error(`Unknown repository: ${repoKey}. Use 'main' or 'ref'`);
    }

    const url = repo.rawUrl + filePath;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: File not found at ${filePath}`);
        }
        return await response.text();
    } catch (error) {
        console.error(`Error fetching from GitHub:`, error.message);
        throw error;
    }
}

/**
 * Search for a document
 * @param {string} docKey - Key from KEY_DOCUMENT_PATHS
 * @returns {Promise<string>} Document content
 */
async function findDocument(docKey) 
{
    const filePath = KEY_DOCUMENT_PATHS[docKey];
    if (!filePath) {
        throw new Error(`Unknown document: ${docKey}. Available: ${Object.keys(KEY_DOCUMENT_PATHS).join(', ')}`);
    }

    try {
        return await fetchFromGitHub('main', filePath);
    } catch (error) {
        throw new Error(`Cannot find document ${docKey}: ${error.message}`);
    }
}

/**
 * Search for source code file
 * @param {string} codeKey - Key from SOURCE_CODE_PATHS
 * @returns {Promise<string>} Source code content
 */
async function findSourceCode(codeKey) 
{
    const filePath = SOURCE_CODE_PATHS[codeKey];
    if (!filePath) {
        throw new Error(`Unknown source file: ${codeKey}. Available: ${Object.keys(SOURCE_CODE_PATHS).join(', ')}`);
    }

    try {
        return await fetchFromGitHub('main', filePath);
    } catch (error) {
        throw new Error(`Cannot find source code ${codeKey}: ${error.message}`);
    }
}

/**
 * Search across documentation
 * @param {string} searchTerm - Search term
 * @returns {Promise<string>} Search results
 */
async function searchDocumentation(searchTerm) 
{
    const results = {found: [], notFound: []};

    for (const [key, path] of Object.entries(KEY_DOCUMENT_PATHS)) {
        try {
            const content = await fetchFromGitHub('main', path);
            if (content.toLowerCase().includes(searchTerm.toLowerCase())) {
                results.found.push({document: key, path: path, preview: extractPreview(content, searchTerm, 100)});
            }
        } catch (error) {
            results.notFound.push({document: key, reason: error.message});
        }
    }

    return results;
}

/**
 * Extract preview of search result
 * @param {string} content - Document content
 * @param {string} searchTerm - Search term
 * @param {number} charCount - Characters to show
 * @returns {string} Preview snippet
 */
function extractPreview(content, searchTerm, charCount = 150) 
{
    const index = content.toLowerCase().indexOf(searchTerm.toLowerCase());
    if (index === -1) 
	return '';

    const start = Math.max(0, index - charCount);
    const end = Math.min(content.length, index + charCount);

    let preview = content.substring(start, end);
    if (start > 0) 
	preview = '...' + preview;
    if (end < content.length) 
	preview = preview + '...';

    return preview;
}

/**
 * Get repository information
 * @returns {object} Repository details
 */
function getRepositoryInfo() 
{
    return {
        repositories: GITHUB_REPOS,
        documents: Object.keys(KEY_DOCUMENT_PATHS),
        sourceFiles: Object.keys(SOURCE_CODE_PATHS),
        examples: Object.keys(EXAMPLE_PATHS)
    };
}

/**
 * Generate search guide
 * @returns {string} Formatted search guide
 */
function generateSearchGuide() 
{
    let guide = `# STDK GitHub Search Guide\n\n`;

    guide += `## Available Documents\n\n`;
    for (const [key, path] of Object.entries(KEY_DOCUMENT_PATHS)) {
        guide += `- **${key}**: \`${path}\`\n`;
    }
    guide += `\n## Available Source Files\n\n`;
    for (const [key, path] of Object.entries(SOURCE_CODE_PATHS)) {
        guide += `- **${key}**: \`${path}\`\n`;
    }

    guide += `\n## Example Locations\n\n`;
    for (const [key, path] of Object.entries(EXAMPLE_PATHS)) {
        guide += `- **${key}**: \`${path}\`\n`;
    }

    guide += `\n## Repositories\n\n`;
    guide += `- **Main**: ${GITHUB_REPOS.main.url}\n`;
    guide += `- **Reference**: ${GITHUB_REPOS.ref.url}\n`;

    return guide;
}

/**
 * Search for GitHub issues
 * @param {string} searchTerm - Search term
 * @returns {string} GitHub issue search URL
 */
function generateIssueSearchUrl(searchTerm) 
{
    return `https://github.com/SmartThingsCommunity/st-device-sdk-c/issues?q=${encodeURIComponent(searchTerm)}`;
}

/**
 * Get file path for direct GitHub access
 * @param {string} docKey - Document key
 * @returns {string} GitHub web URL
 */
function getGitHubWebUrl(docKey) 
{
    const filePath = KEY_DOCUMENT_PATHS[docKey] || SOURCE_CODE_PATHS[docKey];
    if (!filePath) {
        return null;
    }

    return `${GITHUB_REPOS.main.url}/blob/main${filePath}`;
}

// Export functions for skill to use
module.exports = {
    fetchFromGitHub,
    findDocument,
    findSourceCode,
    searchDocumentation,
    getRepositoryInfo,
    generateSearchGuide,
    generateIssueSearchUrl,
    getGitHubWebUrl,
    GITHUB_REPOS,
    KEY_DOCUMENT_PATHS,
    SOURCE_CODE_PATHS,
    EXAMPLE_PATHS
};
