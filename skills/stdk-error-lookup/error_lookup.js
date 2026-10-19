/**
 * STDK Error Code Lookup
 * Fetches error code definitions from GitHub and provides solutions
 */

const GITHUB_REPOS = {
    main: 'https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main'
};

const ERROR_SOURCES = {
    mobile: '/doc/mobile_error_codes_guide.md',
    internal: '/src/include/iot_main.h'
};

/**
 * Fetch error code documentation from GitHub
 * @param {string} errorType - 'mobile' or 'internal'
 * @returns {Promise<string>} Error code documentation content
 */
async function fetchErrorCodeDocument(errorType) 
{
    if (!ERROR_SOURCES[errorType]) {
        throw new Error(`Unknown error type: ${errorType}. Use 'mobile' or 'internal'`);
    }

    const url = GITHUB_REPOS.main + ERROR_SOURCES[errorType];

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: Failed to fetch ${url}`);
        }
        return await response.text();
    } catch (error) {
        console.error(`Error fetching error code document:`, error.message);
        throw error;
    }
}

/**
 * Determine error code type (mobile or internal)
 * @param {string} errorCode - Error code to check
 * @returns {string} 'mobile', 'internal', or 'unknown'
 */
function identifyErrorCodeType(errorCode) 
{
    // Mobile format: XX-XXX
    if (/^\d{2}-\d{3}$/.test(errorCode)) {
        return 'mobile';
    }

    // Internal format: NE01, CE01, EE01, etc.
    if (/^[A-Z]{2}\d{2}$/.test(errorCode)) {
        return 'internal';
    }

    return 'unknown';
}

/**
 * Extract error code information from mobile error codes document
 * @param {string} content - Document content
 * @param {string} mainCode - Main code (e.g., "81" from "81-001")
 * @returns {string} Error information or null if not found
 */
function extractMobileErrorInfo(content, mainCode) 
{
    // Look for section with main code
    const sectionRegex = new RegExp(`^#+\\s+${mainCode}\\s*[-\\s].*$`, 'mi');
    const match = content.match(sectionRegex);

    if (!match) {
        return null;
    }

    // Extract section content
    const sectionStart = content.indexOf(match[0]);
    const nextSection = content.indexOf('\n#', sectionStart + 1);
    const sectionEnd = nextSection === -1 ? content.length : nextSection;

    return content.substring(sectionStart, sectionEnd);
}

/**
 * Extract error code information from SDK internal error codes
 * @param {string} content - Header file content
 * @param {string} errorCode - Error code (e.g., "NE01")
 * @returns {object} Error information or null if not found
 */
function extractInternalErrorInfo(content, errorCode) 
{
    // Look for enum value or #define
    const patterns = 
	[new RegExp(`${errorCode}\\s*[=,]\\s*([^,\\n]+)`, 'i'), new RegExp(`#define\\s+.*${errorCode}.*`, 'i')];

    for (const pattern of patterns) {
        const match = content.match(pattern);
        if (match) {
            return {code: errorCode, definition: match[0], context: extractContext(content, match.index)};
        }
    }

    return null;
}

/**
 * Extract context around a match
 * @param {string} content - Document content
 * @param {number} index - Match index
 * @returns {string} Context with surrounding lines
 */
function extractContext(content, index) 
{
    const lines = content.split('\n');
    let currentPos = 0;
    let lineNum = 0;

    for (let i = 0; i < lines.length; i++) {
        if (currentPos + lines[i].length >= index) {
            lineNum = i;
            break;
        }
        currentPos += lines[i].length + 1;
    }

    const start = Math.max(0, lineNum - 2);
    const end = Math.min(lines.length, lineNum + 3);

    return lines.slice(start, end).join('\n');
}

/**
 * Look up error code
 * @param {string} errorCode - Error code to look up
 * @returns {Promise<string>} Error code information and solutions
 */
async function lookupErrorCode(errorCode) 
{
    const errorType = identifyErrorCodeType(errorCode);

    if (errorType === 'unknown') {
        return `
## Unknown Error Code Format: ${errorCode}

**Expected formats:**
- Mobile error codes: XX-XXX (e.g., 81-001, 04-100)
- SDK internal error codes: NNXX (e.g., NE01, CE01)

**Note:** Please verify the error code format and try again.
`;
    }

    try {
        const content = await fetchErrorCodeDocument(errorType);

        let errorInfo = null;
        let result = `## Error Code Lookup: ${errorCode}\n\n`;

        if (errorType === 'mobile') {
            const mainCode = errorCode.split('-')[0];
            errorInfo = extractMobileErrorInfo(content, mainCode);

            if (errorInfo) {
                result += `### Mobile Error Code ${errorCode}\n\n${errorInfo}`;
            } else {
                result += `**Error code ${errorCode} not found in mobile error codes guide.**\n\n`;
            }
        } else if (errorType === 'internal') {
            errorInfo = extractInternalErrorInfo(content, errorCode);

            if (errorInfo) {
                result += `### SDK Internal Error Code ${errorCode}\n\n`;
                result += `**Definition:**\n\`\`\`\n${errorInfo.definition}\n\`\`\`\n\n`;
                result += `**Context:**\n\`\`\`\n${errorInfo.context}\n\`\`\`\n\n`;
            } else {
                result += `**Error code ${errorCode} not found in SDK internal error codes.**\n\n`;
            }
        }

        if (!errorInfo) {
            result += `### Escalation Guide\n\n`;
            result += 
		`The requested error code **${errorCode}** was not found in the SmartThings Device SDK repository.\n\n`;
            result += `Please report this through the following channels:\n\n`;
            result += `- **GitHub Issues**: https://github.com/SmartThingsCommunity/st-device-sdk-c/issues\n`;
            result += `- **Email Support**: partners@smartthings.com\n`;
        }

        result += `\n### Source Documentation\n\n`;
        result += `- Repository: https://github.com/SmartThingsCommunity/st-device-sdk-c\n`;
        result += 
            `- Source: ${errorType === 'mobile' ? 'doc/mobile_error_codes_guide.md' : 'src/include/iot_main.h'}\n`;

        return result;
    } catch (error) {
        return `## Error Looking Up Error Code: ${errorCode}

**Error:** ${error.message}

Please try again or report the issue through:
- **GitHub Issues**: https://github.com/SmartThingsCommunity/st-device-sdk-c/issues
- **Email Support**: partners@smartthings.com
`;
    }
}

/**
 * Get error code category by main code
 * @param {string} mainCode - Main code (2 digits)
 * @returns {object} Category information
 */
function getErrorCodeCategory(mainCode) 
{
    const categories = {
        '04': {category: 'Connection', description: 'SoftAP / BLE connectivity issues', severity: 'Very High'},
        '07': {category: 'Mobile App', description: 'App internal status / content issues', severity: 'Medium'},
        '08': {category: 'BLE', description: 'BLE stack / MTU / GATT / Pairing', severity: 'Very High'},
        '15': {category: 'Registration', description: 'WiFi / Cloud connection issues', severity: 'Very High'},
        '38': {category: 'Device SDK', description: 'MQTT / STDK handler / key / scan', severity: 'High'},
        '81': {category: 'Identity', description: 'Device authentication / identification', severity: 'Critical'},
        '86': {category: 'Backend Service', description: 'Device registration service issues', severity: 'Critical'}
    };

    return categories[mainCode] || {category: 'Unknown', description: 'Unknown error category', severity: 'Unknown'};
}

// Export functions for skill to use
module.exports = {
    lookupErrorCode,
    identifyErrorCodeType,
    getErrorCodeCategory,
    fetchErrorCodeDocument,
    extractMobileErrorInfo,
    extractInternalErrorInfo
};
