---
name: stdk-docs-reference
description: Comprehensive SmartThings Device SDK (STDK) reference with detailed documentation analysis, code examples, and sequence diagrams. Fetches live documentation from official GitHub repositories. Provides complete guides for development, APIs, onboarding, porting, and commercialization.
---

# STDK Documentation Reference Skill

This skill provides comprehensive SmartThings Device SDK (STDK) documentation and guidance by fetching live content from official GitHub repositories in real-time.

## When to Use

- When users need detailed SDK usage and development guides
- When explaining STDK onboarding process with sequence flows
- When users need complete API reference with examples
- When porting guides or commercialization guides are needed
- When implementing specific features (WiFi Update, Capability, etc.)
- When understanding device state transitions and lifecycle
- When analyzing error codes and troubleshooting

## Skill Capabilities

### 1. GitHub-Based Documentation Retrieval
This skill fetches and analyzes documentation from:
- **Main SDK Repository**: https://github.com/SmartThingsCommunity/st-device-sdk-c
- **Reference Documentation**: https://github.com/SmartThingsCommunity/st-device-sdk-c-ref
- **Documentation Files**: README.md, docs/*.md, getting_started.md, APIs.md, etc.

### 2. Document Analysis & Synthesis
- Fetches raw markdown files from GitHub
- Analyzes and synthesizes information across multiple documents
- Provides complete, accurate information from official sources
- Code examples from real SDK implementation

### 3. Real-time Information
- Always accesses the latest documentation from GitHub
- Ensures information is current and accurate
- References official GitHub repositories as authoritative source

### 4. Detailed Explanations
Provides:
- Step-by-step API call sequences with code examples
- Data structure definitions with field-by-field details
- Security architecture and authentication flows
- Onboarding sequence flows with message exchanges
- Configuration file structures and requirements

## How This Skill Works

When you ask about STDK topics, this skill will:

1. **Fetch relevant documentation** from GitHub repositories (st-device-sdk-c and st-device-sdk-c-ref)
2. **Analyze the actual content** of markdown files
3. **Synthesize information** across multiple documents to answer your question
4. **Provide code examples** from the SDK repository
5. **Explain data structures** with specific field details from official docs
6. **Reference source files** with direct links to GitHub

## GitHub Source Documentation

### Available Documents from st-device-sdk-c
- `getting_started.md` - SDK Getting Started guide
- `APIs.md` - Complete API reference documentation
- `Device_State_Diagram.md` - 7 device lifecycle states and transitions
- `onboarding_seq_flow.md` - Onboarding 5-phase sequence flows
- `porting_guide.md` - Porting guide for various platforms (ESP32, Linux, Raspberry Pi)
- `Capability_Attribute_Update.md` - Capability and attribute updates
- `WiFi_Update.md` - WiFi information transmission methods
- `STDK_Config.md` - Configuration files and structures
- `STDK_Key_Generation.md` - **ED25519 key generation and distribution**
- `STDK_QR_Generation.md` - **QR code generation and encoding**
- `Commercialization_Guide.md` - Commercialization and deployment
- `mobile_error_codes_guide.md` - Mobile app error codes

### Available Documents from st-device-sdk-c-ref
- Additional reference materials and examples

## Knowledge Areas (GitHub-Based)

### Onboarding Process
- 5-phase detailed explanation (Device ↔ Mobile App ↔ Cloud)
- 7 device states and state transitions
- 4 ownership validation types (JUSTWORKS, BUTTON, PIN, QR)
- ED25519 key-based security mechanisms
- TLS authentication and MQTT communication
- Secure WiFi information transmission

### Security Mechanisms (Accurate Implementation)
- **ED25519 Key Generation** - Public/private key creation, storage locations
- **QR Code Distribution** - Exact data encoded in QR codes
- **device_info.json** - Required fields and their purposes
- **onboarding_config.json** - Onboarding configuration structure
- Ownership validation mechanisms

### API Reference
- Connection APIs: st_conn_init, st_conn_start, st_conn_cleanup
- Capability APIs: st_cap_handle_init, st_cap_cmd_set_cb, st_cap_send_attr
- Callback specifications: st_status_cb, st_cap_cmd_cb, st_cap_noti_cb
- Complete data structure definitions

### Platform-Specific Development Guides
- ESP32 porting and development
- Linux/POSIX PoC development
- Raspberry Pi + BlueZ integration
- Environment setup and build instructions

## Sample Questions This Skill Can Accurately Answer

- "How are ED25519 public keys distributed, and what exactly is encoded in QR codes?"
- "What is the exact structure of device_info.json and onboarding_config.json?"
- "Explain the 5-phase onboarding process with detailed message exchanges between Device ↔ Mobile App ↔ Cloud"
- "What is the API call sequence from st_conn_init to st_conn_start, and what does each function do?"
- "Explain all 7 device states in the Device State Diagram"
- "How does the security mechanism (key exchange, TLS, MQTT) work during onboarding?"
- "What environment setup is needed to start STDK development on ESP32?"
- "What capabilities are needed to create an air conditioner device, and what are their commands and attributes?"
- "How do I implement device control features (temperature setting, mode changes) using Capability API?"
- "What causes mobile app error code '81-001' and how do I fix it?"

## Technical Details Covered

### Security Architecture
- ED25519 public/private key generation
- Device serial number and identification
- TLS certificate generation and validation
- MQTT authentication with private keys
- Ownership validation through multiple mechanisms

### Communication Protocols
- BLE (Bluetooth Low Energy) for initial discovery
- WiFi information transmission during onboarding
- MQTT for Cloud communication
- Message format and encoding

### Configuration Management
- device_info.json structure and variations
- onboarding_config.json with all required fields
- Ownership validation type configuration
- Capability and component mapping

## Skill Output Quality

This skill provides:
- ✅ Complete documentation synthesis (not just references)
- ✅ Real code examples from actual SDK implementations
- ✅ Sequence diagram analysis with detailed flows
- ✅ Step-by-step explanations with code snippets
- ✅ Data structure details with field descriptions and requirements
- ✅ Error handling strategies and edge cases
- ✅ Security mechanism explanations from official sources
- ✅ Practical implementation guidance for all platforms
- ✅ Always up-to-date with latest GitHub documentation

## How to Use This Skill Effectively

### Question Writing Tips
1. **Be specific and precise**: Ask "How are ED25519 keys distributed?" rather than vague questions
2. **Request multi-document synthesis**: "Explain the complete onboarding process" triggers aggregation across multiple documents
3. **Request code examples explicitly**: Ask "Show me STDK API usage examples" to get practical code
4. **Look up error codes directly**: Ask about mobile app or SDK error codes for solutions

### How the Skill Works
- Fetches live documentation from **st-device-sdk-c** and **st-device-sdk-c-ref** GitHub repositories in real-time
- Retrieves and analyzes .md files matching your query topic
- Synthesizes information across multiple documents to provide accurate, comprehensive answers
- Always provides information based on the latest official documentation
- Enables reference to original sources via GitHub links