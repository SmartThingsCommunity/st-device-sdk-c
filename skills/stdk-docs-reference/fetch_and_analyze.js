/**
 * STDK Documentation Fetcher and Analyzer
 * Fetches markdown files from GitHub and provides analyzed content
 */

const GITHUB_REPOS = {
    main: 'https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/master',
    ref: 'https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c-ref/master'
};

const DOCUMENT_PATHS = {
    // Main SDK repo - documentation
    'getting_started': '/doc/getting_started.md',
    'apis': '/doc/APIs.md',
    'device_state_diagram': '/doc/Device_State_Diagram.md',
    'onboarding_seq_flow': '/doc/onboarding_seq_flow.md',
    'porting_guide': '/doc/porting_guide.md',
    'capability_attribute': '/doc/Capability_Attribute_Update.md',
    'wifi_update': '/doc/WiFi_Update.md',
    'stdk_config': '/doc/STDK_Config.md',
    'key_generation': '/doc/STDK_Key_Generation.md',
    'qr_generation': '/doc/STDK_QR_Generation.md',
    'commercialization': '/doc/Commercialization_Guide.md',
    'mobile_errors': '/doc/mobile_error_codes_guide.md',

    // Reference repo - additional docs
    'stdk_quickstart': '/README.md',
    'ref_readme': '/README.md'
};

/**
 * Fetch a document from GitHub
 * @param {string} docKey - Key from DOCUMENT_PATHS
 * @param {string} repo - 'main' or 'ref' repository
 * @returns {Promise<string>} Document content
 */
async function fetchDocument(docKey, repo = 'main') 
{
    const path = DOCUMENT_PATHS[docKey];
    if (!path) {
        throw new Error(`Unknown document: ${docKey}. Available: ${Object.keys(DOCUMENT_PATHS).join(', ')}`);
    }

    const url = GITHUB_REPOS[repo] + path;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: Failed to fetch ${url}`);
        }
        return await response.text();
    } catch (error) {
        console.error(`Error fetching document from GitHub:`, error.message);
        throw error;
    }
}

/**
 * Extract specific sections from markdown content
 * @param {string} content - Markdown content
 * @param {string} sectionTitle - Section title to extract
 * @returns {string} Section content
 */
function extractSection(content, sectionTitle) 
{
    const lines = content.split('\n');
    const sectionRegex = new RegExp(`^#+\\s+${sectionTitle}\\s*$`, 'i');

    let startIdx = -1;
    let endIdx = lines.length;

    // Find section start
    for (let i = 0; i < lines.length; i++) {
        if (sectionRegex.test(lines[i])) {
            startIdx = i;
            break;
        }
    }

    if (startIdx === -1) {
        return `Section "${sectionTitle}" not found`;
    }

    // Find section end (next heading of same or higher level)
    const startLevel = lines[startIdx].match(/^#+/)[0].length;
    for (let i = startIdx + 1; i < lines.length; i++) {
        const match = lines[i].match(/^#+/);
        if (match && match[0].length <= startLevel) {
            endIdx = i;
            break;
        }
    }

    return lines.slice(startIdx, endIdx).join('\n');
}

/**
 * Analyze security architecture from key generation and QR docs
 * @returns {Promise<string>} Comprehensive security analysis
 */
async function analyzeSecurityMechanism() 
{
    try {
        const keyGenDoc = await fetchDocument('key_generation', 'main');
        const qrDoc = await fetchDocument('qr_generation', 'main');

        const keyGenSection = extractSection(keyGenDoc, 'ED25519');
        const qrSection = extractSection(qrDoc, 'QR Code');

        return `## Security Mechanism Analysis

### ED25519 Key Generation and Distribution
${keyGenSection}

### QR Code Generation and Usage
${qrSection}

### Integrated Security Flow
- Key Generation: ED25519 public/private key pair creation during development
- Distribution: Public key encoding in QR code embedded in device
- Verification: Ownership confirmation through QR code scanning during onboarding
`;
    } catch (error) {
        return `Error analyzing security: ${error.message}`;
    }
}

/**
 * Get complete onboarding flow explanation
 * @returns {Promise<string>} Complete onboarding documentation
 */
async function getOnboardingFlow() 
{
    try {
        const onboardingDoc = await fetchDocument('onboarding_seq_flow', 'main');
        const apiDoc = await fetchDocument('apis', 'main');

        const onboardingPhases = extractSection(onboardingDoc, 'Phase');
        const apiFlow = extractSection(apiDoc, 'Onboarding');

        return `## Complete Onboarding Process

${onboardingDoc}

### API Integration
${apiFlow}
`;
    } catch (error) {
        return `Error fetching onboarding flow: ${error.message}`;
    }
}

/**
 * Get device configuration requirements
 * @returns {Promise<string>} Configuration documentation
 */
async function getDeviceConfiguration() 
{
    try {
        const configDoc = await fetchDocument('stdk_config', 'main');
        const keyGenDoc = await fetchDocument('key_generation', 'main');

        return `## Device Configuration Complete Guide

${configDoc}

### Key Generation and Configuration
${keyGenDoc}
`;
    } catch (error) {
        return `Error fetching configuration: ${error.message}`;
    }
}

/**
 * Get ESP32 specific documentation
 * @returns {Promise<string>} ESP32-related documentation
 */
async function getESP32Guide() 
{
    try {
        // Main SDK includes ESP32 porting guide
        const portingDoc = await fetchDocument('porting_guide', 'main');
        const gettingStarted = await fetchDocument('getting_started', 'main');

        const esp32Section = extractSection(portingDoc, 'ESP32');
        const setupSection = extractSection(gettingStarted, 'Setup');

        return `## ESP32 Development Guide

### Porting Guide (ESP32)
${esp32Section}

### Getting Started - Environment Setup
${setupSection}
`;
    } catch (error) {
        return `Error fetching ESP32 guide: ${error.message}`;
    }
}

/**
 * Analyze error codes
 * @param {string} errorCode - Error code to look up
 * @returns {Promise<string>} Error explanation and solution
 */
async function analyzeErrorCode(errorCode) 
{
    try {
        const errorsDoc = await fetchDocument('mobile_errors', 'main');
        const errorSection = extractSection(errorsDoc, errorCode);

        return `## Error Code: ${errorCode}\n${errorSection}`;
    } catch (error) {
        return `Error looking up error code: ${error.message}`;
    }
}

// Export functions for skill to use
module.exports = {
    fetchDocument,
    extractSection,
    analyzeSecurityMechanism,
    getOnboardingFlow,
    getDeviceConfiguration,
    getESP32Guide,
    analyzeErrorCode,
    DOCUMENT_PATHS
};
