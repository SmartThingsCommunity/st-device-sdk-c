---
name: stdk-log-analysis
description: Comprehensive SmartThings Device SDK (STDK) log analysis with automatic error extraction, operation flow reconstruction, and issue diagnosis. Identifies problems, provides root cause analysis, and recommends solutions with GitHub source code references.
---

# STDK Log Analysis

Comprehensive analysis of SmartThings Device SDK (STDK) log files to identify operation flows, extract errors, and diagnose issues with GitHub source code references.

## When to Use

- When users share device log files for analysis
- When analyzing onboarding failures from device logs
- When investigating MQTT connection problems
- When troubleshooting attribute/capability transmission errors
- When diagnosing API call failures
- When understanding device state transitions and operation flow

## Supported Log Types

1. **Device Logs**
   - STDK SDK output logs
   - Format: `[I][D][W][E] tag: message`
   - Example: `[E] iot_main: MQTT connection failed`

2. **Mobile App Logs**
   - SmartThings mobile app logs
   - Android logcat / iOS system logs

3. **Network Capture Logs**
   - BLE/BTSnoop logs
   - Analyzable with `tools/btsnoop_parser.py` from GitHub repository

## STDK Log Identification

### Major Log Tags

| Tag | Module | Description |
|-----|--------|-------------|
| `iot_main` | Core | Main state machine, connection management |
| `iot_api` | API | External API calls |
| `iot_capability` | Capability | Capability processing |
| `iot_easysetup` | EasySetup | Onboarding process |
| `iot_mqtt` | MQTT | Cloud communication |
| `iot_security` | Security | Security/encryption |
| `iot_nv_data` | NV Data | Storage management |
| `iot_util` | Utility | Utility functions |
| `iot_bsp` | BSP | Hardware abstraction |

### Log Levels

- `[I]` Info: General information
- `[D]` Debug: Debugging information
- `[W]` Warning: Warnings
- `[E]` Error: Errors
- `[T]` Trace: Detailed tracing

### Major Error Patterns

```
[E] iot_main: NE01    # SoftAP setup failed
[E] iot_main: NE02    # SoftAP connection failed
[E] iot_main: CE01    # MQTT connection failed
[E] iot_main: CE20    # MQTT authentication failed
[E] iot_easysetup:    # Onboarding related errors
[E] iot_security:     # Security related errors
```

## Automatic Analysis Procedure

This skill performs comprehensive automated analysis on STDK log files:

### Phase 1: Log File Parsing & Extraction

Automatically extract:

1. **Log Structure Analysis**
   - File size and line count
   - Log timestamp range
   - Device firmware version
   - Serial number, MAC address

2. **Error/Warning Extraction**
   - All lines containing `ERROR|error|FAIL|fail|Exception|exception`
   - All lines with `[E]` (Error level)
   - All lines with `[W]` (Warning level)
   - Error/warning context (3 lines before/after)

3. **Key Events Extraction**
   - STDK initialization: `[I] iot_` or similar STDK tags
   - Connection attempts: `connect|CONNECT|mqtt|MQTT`
   - Device state changes: `status|STATE|state|DEVICE_STATUS`
   - Capability/attribute transmission: `publish|attribute|capability`
   - Authentication/security: `TLS|authenticate|auth|key|Key`

### Phase 2: Operation Flow Reconstruction

Automatically track and visualize:

1. **Boot & Initialization**
   - System startup logs
   - Module initialization sequence
   - Configuration loading

2. **Onboarding Flow** (if present in logs)
   - BLE/SoftAP startup
   - Mobile app connection
   - Credential exchange
   - WiFi AP connection
   - Cloud registration
   - Device state transitions (cmd: sequence)

3. **Connection Flow** (if present in logs)
   - WiFi association
   - DHCP/IP address assignment
   - DNS resolution
   - TLS/Certificate handling
   - MQTT connection
   - MQTT authentication
   - Topic subscription
   - Initial attribute publishing

4. **Runtime Operation** (if present in logs)
   - Capability command reception
   - Attribute publishing
   - MQTT message exchanges
   - Error/recovery sequences

### Phase 3: Issue Identification & Diagnosis

Automatically identify:

1. **Critical Errors**
   - Error code classification (NE**, CE**, EE**)
   - Error message extraction
   - Error context and sequence
   - Last successful operation before error

2. **Warning Analysis**
   - Driver warnings
   - Retry attempts
   - Timeout warnings
   - Resource warnings

3. **API Error Analysis**
   - ConstraintViolationError
   - UnprocessableEntityError
   - NotValidValue errors
   - Component/attribute mismatch
   - Data type mismatch

4. **Attribute/Capability Errors** (New)
   - Invalid component names (e.g., "statusLed" instead of "main")
   - Data type mismatches (object vs. array vs. string)
   - Malformed JSON payloads
   - Cloud rejection reasons
   - Capability attribute structure errors

5. **Connection State Analysis**
   - Normal flow vs. abnormal flow
   - Connection drops and timing
   - Reconnection behavior
   - State machine progression

### Phase 4: Root Cause Analysis & Solutions

For each identified issue:

1. **Root Cause**
   - What actually failed
   - When it failed (timestamp)
   - Last successful state before failure

2. **Impact Assessment**
   - Does it affect functionality?
   - Is it blocking or non-blocking?
   - Can device still operate?

3. **Source Code Reference**
   - Related source files
   - Function names
   - Error code meanings

4. **Recommended Solutions**
   - Immediate actions
   - Verification steps
   - Prevention measures

### Phase 5: Comprehensive Report

Provide structured output:

1. **Executive Summary**
   - Overall status (✅ Normal / ⚠️ With Warnings / ❌ Critical Issues)
   - Key findings
   - Critical issues requiring immediate fix

2. **Log Overview**
   - Time range analyzed
   - Device info (SN, MAC, FW)
   - Log statistics (total lines, errors, warnings)

3. **Operation Flow Timeline**
   - Chronological flow of major events
   - Device state progression
   - Connection status changes

4. **Issues Found** (organized by severity)
   - **🔴 Critical** - Blocks device operation
   - **🟠 Major** - Causes functional issues
   - **🟡 Warning** - Non-blocking but should fix
   - **🟢 Info** - Non-critical notes

5. **Issue Details** (for each issue)
   - What: Error description
   - When: Timestamp
   - Where: Affected component
   - Why: Root cause analysis
   - How to fix: Recommended solution
   - Code reference: Source files/functions

6. **Success Metrics**
   - What is working correctly
   - What has been verified as normal
   - Positive indicators

7. **Next Steps**
   - Priority action items
   - Verification checklist
   - Code changes needed (if any)

## Analysis Examples

### Example 1: AP Connection Failure

**Log Pattern:**
```
[I] iot_main: Connecting to AP "MyWiFi"
[E] iot_main: NE11-3: STA connection failed
[E] iot_main: WiFi ASSOC failed
```

**Automated Analysis Output:**
```
🔴 CRITICAL: WiFi Association Failure
├─ When: timestamp
├─ Component: Network (WiFi STA mode)
├─ Error Code: NE11-3
├─ Message: STA connection failed, ASSOC failure
├─ Root Cause: AP handshake failure (possible causes)
│  ├─ Incorrect WiFi password
│  ├─ AP not supporting 2.4GHz
│  ├─ Hidden SSID not properly handled
│  └─ WPA/Security mismatch
├─ Source: src/port/net/iot_bsp_wifi.c
├─ Impact: Device cannot connect to home AP, onboarding blocked
└─ Solution:
   1. Verify WiFi SSID and password match AP
   2. Check if AP supports 2.4GHz band
   3. Verify AP security type (WPA2/WPA3)
   4. Try without special characters in password
```

### Example 2: MQTT Connection Failure

**Log Pattern:**
```
[D] iot_mqtt: Connecting to broker...
[E] iot_security: TLS handshake failed
[E] iot_mqtt: CE01: MQTT connection failed
```

**Automated Analysis Output:**
```
🔴 CRITICAL: MQTT Connection Failure (TLS Handshake)
├─ When: timestamp
├─ Component: Cloud (MQTT/Security)
├─ Error Code: CE01
├─ Message: TLS handshake failed, MQTT connection failed
├─ Root Cause: TLS Certificate validation error
│  ├─ Device time out of sync with server
│  ├─ CA root certificate expired or invalid
│  ├─ Network firewall blocking port 8883
│  └─ Device certificate missing or invalid
├─ Source: src/mqtt/iot_mqtt_client.c, src/security/iot_security.c
├─ Impact: Device cannot reach SmartThings Cloud
└─ Solution:
   1. Check device system time (should be within ±5 minutes of NTP)
   2. Verify CA root certificate is loaded
   3. Check network connectivity to mqtt-regional*.api.smartthings.com:8883
   4. Verify device private key is correctly embedded
   5. Check firewall/network policies allow MQTT port
```

### Example 3: Attribute Publishing Error (New)

**Log Pattern:**
```
[06:46:28.988] ERROR payload: {
  "error": {
    "code": "ConstraintViolationError",
    "message": "The request is malformed.",
    "details": [{
      "code": "NotValidValue",
      "target": "deviceEvents[0].component",
      "message": "statusLed is not a valid value."
    }]
  }
}
```

**Automated Analysis Output:**
```
🟠 MAJOR: Invalid Component Name in Attribute
├─ When: timestamp
├─ Component: Capability/API
├─ Error Type: ConstraintViolationError (NotValidValue)
├─ Message: Component "statusLed" is not a valid value
├─ Root Cause: Device publishing attribute with undefined component
│  ├─ Component "statusLed" not defined in Device Profile
│  ├─ Should use "main" component instead
│  └─ Mismatch between device code and Developer Console configuration
├─ Source: Device capability handler, API payload generation
├─ Impact: Attribute transmission fails, device status not updated in app
└─ Solution:
   1. Check Device Profile in Developer Console
   2. Find correct component name (likely "main")
   3. Update device code to use correct component name
   4. Verify: st_cap_send_attr(cap_handle, "main", ...)
   5. Redeploy firmware and test again
```

### Example 4: Data Type Mismatch Error (New)

**Log Pattern:**
```
[06:46:28.997] ERROR payload: {
  "error": {
    "code": "ConstraintViolationError",
    "details": [{
      "code": "UnprocessableEntityError",
      "target": "deviceEvents[0].value",
      "message": "deviceEvents[0].value: object found, array expected"
    }]
  }
}
```

**Automated Analysis Output:**
```
🟠 MAJOR: Attribute Data Type Mismatch
├─ When: timestamp
├─ Component: Capability/API
├─ Error Type: ConstraintViolationError (UnprocessableEntityError)
├─ Message: Attribute value is object, but array expected
├─ Root Cause: Device sending wrong data type for attribute
│  ├─ Sending: Object/JSON structure {...}
│  ├─ Expected: String/Integer/Array format
│  └─ Attribute definition mismatch
├─ Source: Device attribute creation, IOT_EVENT value assignment
├─ Impact: Attribute update rejected by cloud, attribute not synchronized
└─ Solution:
   1. Check attribute definition in Device Profile
   2. Verify value type matches definition
   3. Update device code:
      // ❌ Wrong: iot_cap_val_t value with type=OBJECT
      // ✅ Correct: iot_cap_val_t value with type=STRING
      value.type = IOT_CAP_VAL_TYPE_STRING;
      value.string = "on";  // or "off"
   4. Rebuild and redeploy firmware
```

## EasySetup Command (cmd) Information

### SoftAP/HTTP Onboarding Commands

EasySetup commands displayed as `cmd:X` format in logs:

| cmd | Enum Name | Description | Required |
|-----|-----------|-------------|----------|
| **0** | `IOT_EASYSETUP_STEP_DEVICEINFO` | Device info query (protocol version, firmware, serial) | ✅ Required |
| **1** | `IOT_EASYSETUP_STEP_KEYINFO` | Key exchange (ECDH, master secret generation) | ✅ Required |
| **2** | `IOT_EASYSETUP_STEP_CONFIRMINFO` | Ownership confirmation info (OTM method) | ✅ Required |
| **3** | `IOT_EASYSETUP_STEP_CONFIRM` | Ownership confirmation (button/PIN/QR) | ✅ Required |
| **4** | `IOT_EASYSETUP_STEP_WIFISCANINFO` | WiFi AP scan results | ⚠️ Optional |
| **5** | `IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO` | WiFi credentials received | ✅ Required |
| **6** | `IOT_EASYSETUP_STEP_SETUPCOMPLETE` | Onboarding complete confirmation | ✅ Required |
| **7** | `IOT_EASYSETUP_STEP_LOG_SYSTEMINFO` | Log system info query | ❌ Diagnostic |
| **8** | `IOT_EASYSETUP_STEP_LOG_CREATE_DUMP` | Log dump creation | ❌ Diagnostic |
| **9** | `IOT_EASYSETUP_STEP_LOG_GET_DUMP` | Log dump retrieval | ❌ Diagnostic |

### BLE Onboarding Commands

| cmd | Enum Name | Description |
|-----|-----------|-------------|
| **0** | `IOT_EASYSETUP_BLE_STEP_DEVICEINFO` | Device info |
| **1** | `IOT_EASYSETUP_BLE_STEP_KEYINFO` | Key exchange |
| **2** | `IOT_EASYSETUP_BLE_STEP_CONFIRMINFO` | Confirmation info |
| **3** | `IOT_EASYSETUP_BLE_STEP_CONFIRM` | Ownership confirmation |
| **4** | `IOT_EASYSETUP_BLE_STEP_WIFISCANINFO` | WiFi scan |
| **5** | `IOT_EASYSETUP_BLE_STEP_WIFIPROVIONINGINFO` | WiFi provisioning |
| **6** | `IOT_EASYSETUP_BLE_STEP_TNCAGREEMENTS` | TNC agreement |
| **7** | `IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE` | Setup complete |
| **8** | `IOT_EASYSETUP_BLE_STEP_LOG_SYSTEMINFO` | Log system info |
| **9** | `IOT_EASYSETUP_BLE_STEP_LOG_GET_DUMP` | Log dump |
| **10** | `IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_CONNECTION_INFO` | Offline diagnostic connection info |
| **11** | `IOT_EASYSETUP_BLE_STEP_OFFLINE_DIAGNOSTICS_RECOVERY` | Offline diagnostic recovery |
| **12** | `IOT_EASYSETUP_BLE_STEP_SETUPCOMPLETE_RESPONSE` | Setup complete response |

### Normal Onboarding Sequence

```
[SoftAP/HTTP]
cmd:0 → cmd:1 → cmd:2 → cmd:3 → cmd:4(optional) → cmd:5 → cmd:6

[BLE]
cmd:0 → cmd:1 → cmd:2 → cmd:3 → cmd:4(optional) → cmd:5 → cmd:6 → cmd:7
```

### Connection Drop Analysis

When connection drops in logs, check the last cmd:

- **Dropped at cmd 0-1**: Initial connection/security issue
- **Dropped at cmd 2-3**: Ownership confirmation issue (OTM)
- **Dropped at cmd 4-5**: WiFi connection issue
- **Dropped at cmd 6**: Completion stage issue
- **Dropped at cmd 7-9**: Disconnection after diagnostic command (app may have performed diagnostics after error)

## Attribute/Capability Error Reference

### Common API Errors in Logs

| Error Code | Error Type | Meaning | Fix |
|-----------|-----------|---------|-----|
| `ConstraintViolationError: NotValidValue` | Invalid Component | Component name not defined in Device Profile | Use correct component name from Device Profile (usually "main") |
| `ConstraintViolationError: UnprocessableEntityError` | Wrong Data Type | Attribute value type doesn't match definition | Change value type: STRING/INTEGER instead of OBJECT |
| `ConstraintViolationError: NotValidValue` | Invalid Attribute | Attribute name not defined in Capability | Use correct attribute name from Capability definition |
| `BadRequestError` | Malformed Payload | JSON structure is invalid | Verify JSON format, check character encoding |
| `AuthenticationError` | Auth Failure | Device authentication failed | Check device key, serial number, or time sync |

### How to Find Root Cause

**When you see an error in logs:**

1. **Extract the full error message**
   - Look for `error.code` field
   - Look for `details[].message` field
   - Get the `target` field to know what failed

2. **Identify the problem type**
   - If target is `deviceEvents[X].component` → Wrong component name
   - If target is `deviceEvents[X].attribute` → Wrong attribute name
   - If target is `deviceEvents[X].value` → Wrong data type

3. **Check Device Profile**
   - Go to Developer Console
   - Find Device Profile
   - Check Components section (e.g., is "statusLed" defined?)
   - Check Capabilities for correct attribute names and types

4. **Update device code**
   - Fix component name to match Device Profile
   - Fix attribute value type to match Capability definition
   - Rebuild and redeploy

## Reference Files

### STDK Source Code

- `src/iot_main.c` - Main logic and state machine
- `src/iot_api.c` - API implementation  
- `src/easysetup/iot_easysetup_ble.c` - BLE onboarding
- `src/easysetup/iot_easysetup_http.c` - HTTP/SoftAP onboarding
- `src/mqtt/iot_mqtt_client.c` - MQTT client
- `src/mqtt/iot_mqtt_message.c` - MQTT message formatting
- `src/security/iot_security.c` - TLS and certificate handling
- `src/capability/iot_capability.c` - Capability attribute handling
- `src/include/iot_main.h` - Error code definitions
- `src/include/iot_error.h` - Error code enum
- `src/port/` - Platform-specific implementations

### Documentation

- `doc/mobile_error_codes_guide.md` - Mobile app error code meanings
- `doc/APIs.md` - Complete API reference
- `doc/Device_State_Diagram.md` - Device state machine
- `doc/onboarding_seq_flow.md` - Onboarding sequence diagram
- `tools/btsnoop_parser.py` - BLE log parser

## Expected Log Tags by Module

| Module | Expected Log Tags | Common Log Patterns |
|--------|------------------|-------------------|
| **Initialization** | `[sys]`, `[config]`, `module init` | "module [X] init", "initializing" |
| **WiFi** | `[WiFi]`, `[atbm_log]`, `[wlan]` | "connecting to AP", "associated", "DHCP" |
| **Onboarding** | `[App]`, `[device_metadata]`, `[AGENT]` | "onboarding_config", "device_info", "Serial number" |
| **STDK Core** | `[DevSDK]`, `iot_`, `st_` | "MQTT", "connect", "status", "capability" |
| **Cloud** | `[FOTA]`, `publish`, `subscribe` | "MQTT connected", "event", "attribute" |
| **Audio/Video** | `[VIDEO]`, `[AUDIO]`, `[AV_API]` | "stream", "encoding", "frame" |
| **Watchdog** | `[WatchdogClient]`, `[AGENT]` | "heartbeat", "keepalive" |

## Analysis Workflow Summary

```
User shares log file
        ↓
[Phase 1: Parse] Extract errors, warnings, events
        ↓
[Phase 2: Reconstruct] Build operation flow timeline
        ↓
[Phase 3: Identify] Classify issues by severity
        ↓
[Phase 4: Diagnose] Analyze root cause
        ↓
[Phase 5: Report] Provide actionable recommendations
        ↓
User receives comprehensive analysis with solutions
```