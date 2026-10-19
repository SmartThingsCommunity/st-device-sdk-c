# st-device-sdk-dev-support

An Android support tool for SmartThings Device SDK developers. It allows testing and debugging of the BLE onboarding process for SmartThings Direct Connected Devices.

## Key Features

### 1. Samsung BLE Device Scanning
- Samsung device filtering (Company ID: 0x0075)
- SmartThings device identification:
  - Version: 0x42
  - Service ID: 0x0C
  - Samsung Connect Packet Version: 0x83
  - OCF Info: 0x05 (Onboarding Ready) or 0x03 (Onboarded)
  - Feature: 0x59
- Device information parsing: MNID, SETUPID, BLE MAC Address, Serial Number

### 2. BLE GATT Communication
- Service UUID: 0xFD1D
- Characteristic UUID: BE940F0E-AE2D-4F8E-A4C7-300280E60E09
- MTU negotiation (up to 512 bytes)
- Segmented Data transmission/reception

### 3. Onboarding Command Support
| Command | Code | Description |
|---------|------|-------------|
| DeviceInfo | 0x01 | Request device information |
| KeyInfo | 0x02 | ECDH key exchange |
| ConfirmInfo | 0x03 | OTM (Ownership Transfer Method) confirmation |
| WifiScanInfo | 0x05 | WiFi AP scan |
| WifiProvisioningInfo | 0x06 | Send WiFi credentials |
| SetupComplete | 0x08 | Onboarding complete |

### 4. Security Features
- **ECDH Key Exchange**: Ed25519 → X25519 conversion
- **Shared Secret Generation**: X25519 Agreement + SHA-256
- **AES-256-CBC Encryption/Decryption**: KeyInfo, ConfirmInfo, WifiScanInfo, WifiProvisioningInfo

### 5. WiFi Provisioning
- Display WiFi AP scan results
- Enter and save WiFi password
- Hidden SSID support

## Requirements

### Hardware
- Android 6.0 (API 23) or higher
- Device with BLE 4.0 or higher support

### Permissions
- `BLUETOOTH_SCAN` (Android 12+)
- `BLUETOOTH_CONNECT` (Android 12+)
- `ACCESS_FINE_LOCATION`

## How to Use

### 1. Device Scanning
1. Launch the app and click the "Scan" button
2. SmartThings devices are automatically detected
3. Filter options: All / Onboarding Ready / Onboarded

### 2. Load device_info.json
1. Click the "Select device_info.json" button
2. Select the `device_info.json` file
3. Extract publicKey, privateKey, serialNumber from the file

### 3. Onboarding Process
1. Select a scanned device → GATT connection
2. Send DeviceInfo → Receive device information
3. Send KeyInfo → Generate Shared Secret
4. Send ConfirmInfo → Select OTM
5. Send WifiScanInfo → View WiFi list
6. Send WifiProvisioningInfo → Send WiFi credentials
7. Send SetupComplete → Onboarding complete

## Project Structure

```
st-device-sdk-dev-support/
├── app/
│   ├── src/main/
│   │   ├── java/com/example/ble_scanner/
│   │   │   ├── MainActivity.kt          # BLE scan, device list
│   │   │   ├── GattDetailActivity.kt    # GATT communication, onboarding
│   │   │   ├── BleDevice.kt             # Device data model
│   │   │   ├── DeviceAdapter.kt         # Device list adapter
│   │   │   └── WifiListAdapter.kt       # WiFi list adapter
│   │   └── res/
│   │       ├── layout/                  # UI layouts
│   │       └── values/                  # String, color resources
│   └── build.gradle
├── build.gradle
└── settings.gradle
```

## Build Instructions

### Android Studio
1. Open the project in Android Studio
2. Sync Project with Gradle Files
3. Run > Run 'app'

### Command Line
```bash
./gradlew assembleDebug
```

## Dependencies

- AndroidX AppCompat
- AndroidX Core
- AndroidX CardView
- AndroidX RecyclerView
- BouncyCastle (Cryptography)

## Related Documentation

- [SmartThings Device SDK](https://developer.smartthings.com/sdk/)
- [SmartThings Developer Workspace](https://developer.smartthings.com/workspace/)
- [st-device-sdk-c Repository](../)

## License

Apache License 2.0