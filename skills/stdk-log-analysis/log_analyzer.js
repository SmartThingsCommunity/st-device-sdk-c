/**
 * STDK Log Analysis
 * Comprehensive analysis of STDK log files with error extraction and flow reconstruction
 */

const GITHUB_REPO = 'https://github.com/SmartThingsCommunity/st-device-sdk-c';

/**
 * STDK Log Tags and their modules
 */
const LOG_TAGS = {
    'iot_main': {module: 'Core', description: 'Main state machine, connection management'},
    'iot_api': {module: 'API', description: 'External API calls'},
    'iot_capability': {module: 'Capability', description: 'Capability processing'},
    'iot_easysetup': {module: 'EasySetup', description: 'Onboarding process'},
    'iot_mqtt': {module: 'MQTT', description: 'Cloud communication'},
    'iot_security': {module: 'Security', description: 'Security/encryption'},
    'iot_nv_data': {module: 'NV Data', description: 'Storage management'},
    'iot_util': {module: 'Utility', description: 'Utility functions'},
    'iot_bsp': {module: 'BSP', description: 'Hardware abstraction'}
};

const LOG_LEVELS = {
    '[I]': 'Info',
    '[D]': 'Debug',
    '[W]': 'Warning',
    '[E]': 'Error',
    '[T]': 'Trace'
};

const ERROR_CODE_PATTERNS = {
    internal: /\b(NE\d{2}|CE\d{2}|EE\d{2})\b/g,
    mobile: /\b\d{2}-\d{3}\b/g
};

/**
 * Parse log file content
 * @param {string} logContent - Raw log file content
 * @returns {object} Parsed log structure
 */
function parseLogFile(logContent) 
{
    const lines = logContent.split('\n');
    const parsed = {
        totalLines: lines.length,
        errors: [],
        warnings: [],
        events: [],
        errorCodes: new Set(),
        tags: new Set(),
        timeRange: {start: null, end: null}
    };

    for (const line of lines) {
        // Extract log level
        const levelMatch = line.match(/(\[.\])/);
        const level = levelMatch ? levelMatch[1] : null;

        // Extract timestamp if present
        const timeMatch = line.match(/(\d{2}:\d{2}:\d{2}\.\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
        const timestamp = timeMatch ? timeMatch[1] : null;

        // Extract tag
        const tagMatch = line.match(/(iot_\w+|[\w_]+):/);
        const tag = tagMatch ? tagMatch[1] : null;

        // Classify by level
        if (level === '[E]'){
            parsed.errors.push({timestamp, tag, line});
        } else if (level === '[W]') {
            parsed.warnings.push({timestamp, tag, line});
        }

        // Track key events
        if (line.match(/connect|CONNECT|mqtt|MQTT|onboard|Onboard|state|STATE/i)) {
            parsed.events.push({timestamp, line});
        }

        // Extract error codes
        const internalCodes = line.match(ERROR_CODE_PATTERNS.internal);
        const mobileCodes = line.match(ERROR_CODE_PATTERNS.mobile);
        if (internalCodes) 
	    internalCodes.forEach(code => parsed.errorCodes.add(code));
        if (mobileCodes) 
	    mobileCodes.forEach(code => parsed.errorCodes.add(code));

        // Track tags
        if (tag) 
	    parsed.tags.add(tag);

        // Update time range
        if (timestamp) {
            if (!parsed.timeRange.start) 
		parsed.timeRange.start = timestamp;
            parsed.timeRange.end = timestamp;
        }
    }

    return parsed;
}

/**
 * Extract errors and warnings with context
 * @param {string} logContent - Raw log content
 * @param {number} contextLines - Lines before/after error
 * @returns {object} Error and warning extraction
 */
function extractErrorsWithContext(logContent, contextLines = 3) 
{
    const lines = logContent.split('\n');
    const result = {errors: [], warnings: []};

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for error line
        if (line.match(/\[E\]|ERROR|error|FAIL|fail|Exception/)) {
            const start = Math.max(0, i - contextLines);
            const end = Math.min(lines.length, i + contextLines + 1);
            const context = lines.slice(start, end).join('\n');

            result.errors.push({lineNumber: i + 1, errorLine: line, context, errorCodes: extractErrorCodes(line)});
        }

        // Check for warning line
        if (line.match(/\[W\]|WARNING|warning/)) {
            const start = Math.max(0, i - contextLines);
            const end = Math.min(lines.length, i + contextLines + 1);
            const context = lines.slice(start, end).join('\n');

            result.warnings.push({lineNumber: i + 1, warningLine: line, context});
        }
    }

    return result;
}

/**
 * Extract error codes from a line
 * @param {string} line - Log line
 * @returns {array} Found error codes
 */
function extractErrorCodes(line) 
{
    const codes = [];
    const internalMatches = line.match(ERROR_CODE_PATTERNS.internal);
    const mobileMatches = line.match(ERROR_CODE_PATTERNS.mobile);

    if (internalMatches) 
	codes.push(...internalMatches);
    if (mobileMatches) 
	codes.push(...mobileMatches);

    return [...new Set(codes)];
}

/**
 * Reconstruct operation flow from logs
 * @param {string} logContent - Raw log content
 * @returns {object} Operation flow timeline
 */
function reconstructOperationFlow(logContent) 
{
    const lines = logContent.split('\n');
    const flow = {initialization: [], onboarding: [], connection: [], operation: [], errors: []};

    let currentPhase = null;

    for (const line of lines) {
        // Detect initialization phase
        if (line.match(/init|boot|startup|setup|config/i)) {
            flow.initialization.push(line);
            currentPhase = 'initialization';
        }

        // Detect onboarding phase
        if (line.match(/onboard|easysetup|provision|cmd:/i)) {
            flow.onboarding.push(line);
            currentPhase = 'onboarding';
        }

        // Detect connection phase
        if (line.match(/connect|wifi|mqtt|tls|certificate|auth/i) && !line.match(/disconnect/i)) {
            flow.connection.push(line);
            currentPhase = 'connection';
        }

        // Detect operation phase
        if (line.match(/capability|attribute|publish|subscribe|command/i)) {
            flow.operation.push(line);
            currentPhase = 'operation';
        }

        // Track errors
        if (line.match(/\[E\]|ERROR|error|FAIL|fail/)) {
            flow.errors.push({timestamp: extractTimestamp(line), line});
        }
    }

    return flow;
}

/**
 * Extract timestamp from log line
 * @param {string} line - Log line
 * @returns {string|null} Timestamp or null
 */
function extractTimestamp(line) 
{
    const match = line.match(/(\d{2}:\d{2}:\d{2}\.\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
    return match ? match[1] : null;
}

/**
 * Analyze EasySetup commands (cmd:X format)
 * @param {string} logContent - Raw log content
 * @returns {array} Detected cmd: commands in order
 */
function analyzeEasySetupCommands(logContent) 
{
    const cmdPattern = /cmd:(\d+)/g;
    const commands = [];
    let match;

    const cmdDescriptions = {
        0: 'Device info query',
        1: 'Key exchange (ECDH)',
        2: 'Confirmation info',
        3: 'Ownership confirmation',
        4: 'WiFi scan (optional)',
        5: 'WiFi provisioning',
        6: 'Setup complete',
        7: 'Log system info',
        8: 'Create log dump',
        9: 'Get log dump'
    };

    while ((match = cmdPattern.exec(logContent)) !== null) {
        const cmdNum = match[1];
        commands.push({cmd: cmdNum, description: cmdDescriptions[cmdNum] || 'Unknown', position: match.index});
    }

    return commands;
}

/**
 * Identify critical issues
 * @param {string} logContent - Raw log content
 * @returns {array} Critical issues found
 */
function identifyCriticalIssues(logContent) 
{
    const issues = [];

    // Check for connection failures
    if (logContent.match(/MQTT.*fail|connection.*fail|TLS.*fail/i)) {
        issues.push({
            severity: 'CRITICAL',
            type: 'MQTT/TLS Connection Failure',
            description: 'Device cannot establish cloud connection',
            sourceFiles: ['src/mqtt/iot_mqtt_client.c', 'src/security/iot_security.c']
        });
    }

    // Check for authentication failures
    if (logContent.match(/auth.*fail|certificate|key.*error/i)) {
        issues.push({
            severity: 'CRITICAL',
            type: 'Authentication Failure',
            description: 'Device authentication or key validation failed',
            sourceFiles: ['src/security/iot_security.c', 'src/include/iot_main.h']
        });
    }

    // Check for WiFi connection failures
    if (logContent.match(/wifi.*fail|AP.*fail|ASSOC.*fail|STA.*fail/i)) {
        issues.push({
            severity: 'CRITICAL',
            type: 'WiFi Connection Failure',
            description: 'Device cannot connect to WiFi AP',
            sourceFiles: ['src/port/net/iot_bsp_wifi.c', 'src/easysetup/iot_easysetup_http.c']
        });
    }

    // Check for attribute/capability errors
    if (logContent.match(/ConstraintViolationError|UnprocessableEntityError|NotValidValue/)) {
        issues.push({
            severity: 'MAJOR',
            type: 'Attribute/Capability Error',
            description: 'Invalid component or attribute in device profile',
            sourceFiles: ['src/capability/iot_capability.c', 'src/iot_api.c']
        });
    }

    // Check for onboarding failures
    if (logContent.match(/onboard.*fail|easysetup.*fail|cmd.*timeout/i)) {
        issues.push({
            severity: 'CRITICAL',
            type: 'Onboarding Failure',
            description: 'Device onboarding process failed',
            sourceFiles: ['src/easysetup/iot_easysetup_ble.c', 'src/easysetup/iot_easysetup_http.c']
        });
    }

    return issues;
}

/**
 * Generate analysis report
 * @param {string} logContent - Raw log content
 * @returns {string} Formatted analysis report
 */
async function generateAnalysisReport(logContent) 
{
    const parsed = parseLogFile(logContent);
    const errorsWithContext = extractErrorsWithContext(logContent);
    const flow = reconstructOperationFlow(logContent);
    const easySetupCmds = analyzeEasySetupCommands(logContent);
    const criticalIssues = identifyCriticalIssues(logContent);

    let report = `# STDK Log Analysis Report\n\n`;

    // Executive Summary
    report += `## Executive Summary\n\n`;
    report += `**Status**: ${criticalIssues.length > 0 ? '❌ Critical Issues Found' : '✅ No Critical Issues'}\n`;
    report += `**Total Lines**: ${parsed.totalLines}\n`;
    report += `**Errors**: ${parsed.errors.length}\n`;
    report += `**Warnings**: ${parsed.warnings.length}\n`;
    report += `**Time Range**: ${parsed.timeRange.start} to ${parsed.timeRange.end}\n\n`;

    // Error Codes Found
    if (parsed.errorCodes.size > 0) {
        report += `## Error Codes Found\n\n`;
        Array.from(parsed.errorCodes).forEach(code => {
            report += `- ${code}\n`;
        });
        report += `\nFor details on these error codes, use stdk-error-lookup skill.\n\n`;
    }

    // EasySetup Command Sequence
    if (easySetupCmds.length > 0) {
        report += `## EasySetup Command Sequence\n\n`;
        easySetupCmds.forEach((cmd, index) => {
            report += `${index + 1}. cmd:${cmd.cmd} - ${cmd.description}\n`;
        });
        report += `\nExpected normal sequence: cmd:0 → cmd:1 → cmd:2 → cmd:3 → cmd:5 → cmd:6\n\n`;
    }

    // Critical Issues
    if (criticalIssues.length > 0) {
        report += `## Critical Issues\n\n`;
        criticalIssues.forEach((issue, index) => {
            report += `### ${index + 1}. ${issue.type}\n`;
            report += `**Severity**: ${issue.severity}\n`;
            report += `**Description**: ${issue.description}\n`;
            report += `**Source Files**:\n`;
            issue.sourceFiles.forEach(file => {
                report += `- ${GITHUB_REPO}/blob/master/${file}\n`;
            });
            report += `\n`;
        });
    }

    // Error Details
    if (errorsWithContext.errors.length > 0) {
        report += `## Error Details\n\n`;
        errorsWithContext.errors.slice(0, 10).forEach((error, index) => {
            report += `### Error ${index + 1} (Line ${error.lineNumber})\n`;
            report += `\`\`\`\n${error.errorLine}\n\`\`\`\n`;
            if (error.errorCodes.length > 0) {
                report += `**Error Codes**: ${error.errorCodes.join(', ')}\n`;
            }
            report += `\n`;
        });
    }

    // Operation Flow
    report += `## Operation Flow\n\n`;
    report += `**Initialization**: ${flow.initialization.length} events\n`;
    report += `**Onboarding**: ${flow.onboarding.length} events\n`;
    report += `**Connection**: ${flow.connection.length} events\n`;
    report += `**Operation**: ${flow.operation.length} events\n\n`;

    // Tags Used
    report += `## Modules Detected\n\n`;
    Array.from(parsed.tags).filter(tag => LOG_TAGS[tag]).forEach(tag => {
        const tagInfo = LOG_TAGS[tag];
        report += `- **${tagInfo.module}** (${tag}): ${tagInfo.description}\n`;
    });

    report += `\n## Additional Resources\n\n`;
    report += `- **Repository**: ${GITHUB_REPO}\n`;
    report += `- **Error Code Lookup**: Use stdk-error-lookup skill for error code details\n`;
    report += `- **Source Code**: Explore ${GITHUB_REPO}/tree/master/src for implementation details\n`;

    return report;
}

// Export functions for skill to use
module.exports = {
    parseLogFile,
    extractErrorsWithContext,
    reconstructOperationFlow,
    analyzeEasySetupCommands,
    identifyCriticalIssues,
    generateAnalysisReport,
    LOG_TAGS,
    LOG_LEVELS,
    ERROR_CODE_PATTERNS
};
