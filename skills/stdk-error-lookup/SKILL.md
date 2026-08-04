---
name: stdk-error-lookup
description: Look up SmartThings Device SDK (STDK) error codes and provide solutions. Fetches live error code definitions from GitHub. Supports mobile error codes (81-001, 04-100) and SDK internal error codes (NE01, CE01).
---

# STDK Error Code Lookup

Look up SmartThings Device SDK (STDK) error codes and provide solutions with real-time GitHub documentation.

## When to Use

- When users ask about mobile error codes like "81-001" or "04-100"
- When users ask about SDK internal error codes (NE01, CE01, EE01, etc.)
- When troubleshooting onboarding/connection failures
- When analyzing error messages in device logs

## Error Code Sources

All error code information is retrieved from official GitHub repositories in real-time. No hardcoded data is used.

**Primary Repository**: https://github.com/SmartThingsCommunity/st-device-sdk-c

Source files accessed:
- **Mobile Error Codes**: `doc/mobile_error_codes_guide.md`
  - Raw URL: `https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/doc/mobile_error_codes_guide.md`
- **SDK Internal Error Codes**: `src/include/iot_main.h` (iot_st_ecode_t definitions)
  - Raw URL: `https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/src/include/iot_main.h`

## Error Code Formats

### 1. Mobile Error Codes (User-facing Format)
```
MAIN(2-digit) - SUB(3-digit)
Examples: 81-001, 04-100, 15-200, 08-050
```

### 2. SDK Internal Error Codes (Development/Log Format)
```
NE01, NE02, NE11, CE01, CE11, CE20, EE01, EE10, etc.
```

## MAIN Code Categories

| MAIN | Category | Description | Severity |
|------|----------|-------------|----------|
| **04** | Connection | SoftAP / BLE connectivity issues | Very High |
| **07** | Mobile App | App internal status / content issues | Medium |
| **08** | BLE | BLE stack / MTU / GATT / Pairing | Very High |
| **15** | Registration | WiFi / Cloud connection issues | Very High |
| **38** | Device SDK | MQTT / STDK handler / key / scan | High |
| **81** | Identity | Device authentication / identification | Critical |
| **86** | Backend Service | Device registration service issues | Critical |

## Error Code Lookup Procedure

### Step 1: Identify Error Code Format
- Mobile error code format `XX-XXX` → Fetch from `mobile_error_codes_guide.md`
- SDK internal error code format `NE/CE/EE + number` → Fetch from `iot_main.h`

### Step 2: Fetch from GitHub Repository
The skill automatically fetches relevant documentation from GitHub:

```
Mobile codes: https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/doc/mobile_error_codes_guide.md
Internal codes: https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/src/include/iot_main.h
```

### Step 3: Parse and Provide Answer
- Extract error code definition from GitHub
- Provide description and meaning
- List root causes and developer checklist
- Reference source code locations when applicable

### Step 4: Error Code Not Found — Escalation Guide
If error code cannot be found in GitHub repository:

"The requested error code **[ERROR_CODE]** was not found in the SmartThings Device SDK repository. Please report this through the following channels:"

- **GitHub Issues**: https://github.com/SmartThingsCommunity/st-device-sdk-c/issues
- **Email Support**: partners@smartthings.com

## Important Rules

1. **ALWAYS fetch from GitHub** — Real-time documentation retrieval, never use hardcoded data
2. **Provide complete context** — Include error meaning, root causes, and solutions
3. **Reference source files** — Point to GitHub file locations for deeper investigation
4. **Escalate when needed** — Use escalation guide for unknown error codes
5. **Cross-reference** — Link related error codes and state machine information from official docs
