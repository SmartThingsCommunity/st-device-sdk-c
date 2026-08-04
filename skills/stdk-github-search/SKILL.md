---
name: stdk-github-search
description: Search SmartThings Device SDK (STDK) GitHub repositories for issues, documents, and source code. Provides multiple search methods and repository structure information.
---

# STDK GitHub Search

Search for information across SmartThings Device SDK (STDK) GitHub repositories with multiple methods.

## When to Use

- When users need to find specific documentation or source code
- When searching for related GitHub issues or discussions
- When checking latest SDK documentation or examples
- When looking for platform-specific implementation references
- When investigating error codes or troubleshooting guides

## Repository Information

### Two Main Repositories

| Repository | URL | Purpose |
|------------|-----|---------|
| **st-device-sdk-c** | https://github.com/SmartThingsCommunity/st-device-sdk-c | Core SDK source code, documentation, examples |
| **st-device-sdk-c-ref** | https://github.com/SmartThingsCommunity/st-device-sdk-c-ref | Reference documents, additional guides, examples |

## Search Methods

### 1. Direct File Fetch (Recommended)

The skill fetches files directly from GitHub raw content URLs:

```
Documents: https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/doc/{filename}.md
Source Code: https://raw.githubusercontent.com/SmartThingsCommunity/st-device-sdk-c/main/src/{path}/{filename}.c
```

### 2. Using GitHub CLI (gh)

#### View File Contents
```bash
# View files in st-device-sdk-c repository
gh api repos/SmartThingsCommunity/st-device-sdk-c/contents/doc/getting_started.md --jq '.content' | base64 -d

# View directory structure
gh api repos/SmartThingsCommunity/st-device-sdk-c/contents/doc --jq '.[].name'
```

### 3. Download Repository as ZIP

#### PowerShell Download
```powershell
# Download st-device-sdk-c
Invoke-WebRequest -Uri "https://github.com/SmartThingsCommunity/st-device-sdk-c/archive/refs/heads/main.zip" -OutFile "st-device-sdk-c.zip"
Expand-Archive -Path "st-device-sdk-c.zip" -DestinationPath "."
Rename-Item "st-device-sdk-c-main" "st-device-sdk-c"
```

#### Bash Download
```bash
curl -L -o st-device-sdk-c.zip https://github.com/SmartThingsCommunity/st-device-sdk-c/archive/refs/heads/main.zip
unzip st-device-sdk-c.zip
mv st-device-sdk-c-main st-device-sdk-c
```

### 4. Clone Repository

```bash
# Clone st-device-sdk-c
git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git

# Clone st-device-sdk-c-ref
git clone https://github.com/SmartThingsCommunity/st-device-sdk-c-ref.git
```

### 5. GitHub Web Search

```
Direct browser search:
https://github.com/SmartThingsCommunity/st-device-sdk-c/search?q=search_term
```

## Repository Structure

### st-device-sdk-c — Core SDK

#### Documentation (`doc/`)
| File | Purpose |
|------|---------|
| `getting_started.md` | SDK setup and first steps |
| `APIs.md` | Complete API reference |
| `porting_guide.md` | Platform porting guide |
| `Commercialization_Guide.md` | Product deployment guide |
| `mobile_error_codes_guide.md` | Mobile app error code reference |
| `STDK_Config.md` | Configuration and setup files |
| `WiFi_Update.md` | WiFi credential transmission |
| `Device_State_Diagram.md` | Device lifecycle states |
| `onboarding_seq_flow.md` | Onboarding sequence flows |
| `Capability_Attribute_Update.md` | Capability implementation |
| `STDK_Key_Generation.md` | ED25519 key generation |
| `STDK_QR_Generation.md` | QR code generation |

#### Source Code (`src/`)
| Path | Purpose |
|------|---------|
| `include/` | Public header files |
| `iot_main.c` | Main state machine |
| `iot_api.c` | API implementation |
| `easysetup/` | Onboarding module |
| `mqtt/` | Cloud communication |
| `security/` | TLS and certificates |
| `capability/` | Capability handling |
| `port/` | Platform abstraction layer |

#### Examples (`example/`)
| Path | Platform |
|------|----------|
| `esp32/` | ESP32 reference implementation |
| `posix/` | Linux/POSIX PoC |
| `raspberry/` | Raspberry Pi integration |

#### Tools (`tools/`)
| Tool | Purpose |
|------|---------|
| `keygen/` | ED25519 key pair generation |
| `qrgen/` | QR code generation |
| `manual_onboarding/` | Manual onboarding utility |

### st-device-sdk-c-ref — Reference Materials

| Path | Content |
|------|---------|
| `doc/` | Additional reference documentation |
| `example/` | Extended example implementations |

## Search Strategy by Question Type

### 1. Getting Started / Product Development
1. **st-device-sdk-c/doc/getting_started.md** — Setup and workflow
2. **st-device-sdk-c/example/** — Reference implementations
3. **st-device-sdk-c-ref/doc/** — Additional guides

### 2. API Usage and Reference
1. **st-device-sdk-c/doc/APIs.md** — Complete API documentation
2. **st-device-sdk-c/src/include/** — Header files with function signatures
3. **st-device-sdk-c/example/** — API usage examples

### 3. Platform Porting (ESP32, Linux, etc.)
1. **st-device-sdk-c/doc/porting_guide.md** — Porting instructions
2. **st-device-sdk-c/src/port/** — Platform-specific implementations
3. **st-device-sdk-c/example/esp32/** — ESP32 reference code

### 4. Error Code and Troubleshooting
1. **st-device-sdk-c/doc/mobile_error_codes_guide.md** — User-facing error codes
2. **st-device-sdk-c/src/include/iot_main.h** — SDK internal error definitions
3. Use **stdk-error-lookup** skill for detailed error analysis

### 5. Security and Keys
1. **st-device-sdk-c/doc/STDK_Key_Generation.md** — Key generation process
2. **st-device-sdk-c/doc/STDK_QR_Generation.md** — QR code generation
3. **st-device-sdk-c/src/security/** — Security implementation

### 6. Onboarding Process
1. **st-device-sdk-c/doc/onboarding_seq_flow.md** — Sequence diagrams
2. **st-device-sdk-c/src/easysetup/** — Onboarding implementation
3. **st-device-sdk-c/example/** — Onboarding examples

### 7. Cloud Communication
1. **st-device-sdk-c/doc/APIs.md** — Cloud API reference
2. **st-device-sdk-c/src/mqtt/** — MQTT implementation
3. **st-device-sdk-c/src/capability/** — Capability messaging

## Key Header Files

| Header | Location | Purpose |
|--------|----------|---------|
| `st_dev.h` | `src/include/` | Main SDK API |
| `iot_main.h` | `src/include/` | Core definitions and error codes |
| `iot_error.h` | `src/include/` | Error type definitions |
| `iot_capability.h` | `src/include/` | Capability API |

## Search with GitHub CLI

```bash
# List open issues
gh issue list --repo SmartThingsCommunity/st-device-sdk-c --state open --limit 20

# Search issues by keyword
gh issue list --repo SmartThingsCommunity/st-device-sdk-c --search "onboarding"

# View specific file
gh api repos/SmartThingsCommunity/st-device-sdk-c/contents/doc/getting_started.md --jq '.content' | base64 -d
```

## Integration with Other Skills

- **stdk-docs-reference** — Fetch and analyze documentation comprehensively
- **stdk-error-lookup** — Look up specific error codes and solutions
- **stdk-log-analysis** — Analyze device logs and identify issues