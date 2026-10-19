# SmartThings Device SDK Emulator (Android)

An emulator that allows you to run SmartThings Device SDK (C) code as an Android app.

## Features

- **Device Provisioning**: Device registration and initial setup
- **Capability Control**: Change capability states such as switch, temperature, humidity, etc.
- **MQTT Communication**: MQTT connection with SmartThings cloud
- **EasySetup**: BLE/Wi-Fi onboarding support
- **Log Viewer**: Real-time SDK log monitoring
- **File Selection**: Load device information JSON files

## Project Structure

```
app/src/main/
├── java/com/samsung/devicesdk/emulator/
│   ├── MainActivity.kt        # Main activity
│   ├── STDeviceSDK.kt         # SDK JNI wrapper
│   └── STDeviceService.kt     # Background service
├── cpp/
│   ├── CMakeLists.txt         # NDK build configuration
│   ├── jni/
│   │   └── st_device_sdk_jni.c  # JNI interface
│   └── port/android/         # Android port implementation
│       ├── iot_bsp_debug_android.c
│       ├── iot_bsp_fs_android.c
│       ├── iot_bsp_nv_data_android.c
│       ├── iot_bsp_random_android.c
│       ├── iot_bsp_system_android.c
│       ├── iot_bsp_wifi_android.c
│       ├── iot_crypto_util_android.c
│       ├── iot_net_util_android.c
│       └── iot_os_util_android.c
├── res/layout/
│   └── activity_main.xml     # Main layout
└── AndroidManifest.xml
```

## Build Instructions

### 1. Copy SDK Sources

```batch
copy_sdk_sources.bat
```

This batch file copies C sources from `st-device-sdk-c-ref/iot-core` to `app/src/main/cpp/`.

### 2. Open in Android Studio

1. Launch Android Studio
2. **File → Open** → Select `st-device-sdk-emulator` folder
3. Gradle sync will run automatically
4. **Build → Make Project** (Ctrl+F9)

### 3. JDK Configuration

Set Android Studio's Gradle JDK to **JDK 17**:
- **File → Settings → Build → Gradle → Gradle JDK**
- Select JDK 17 (or install via "Download JDK" if not available)

> **Note**: AGP 8.2.0 + Gradle 8.2 supports up to JDK 17. To use JDK 21,
> you need to upgrade Gradle to 8.5 or higher.

### 4. NDK Installation

Install NDK from SDK Manager:
- **Tools → SDK Manager → SDK Tools → NDK (Side by side)**
- NDK 25.x or 26.x recommended

### 5. Run

- Connect Android device via USB (or use emulator)
- **Run → Run 'app'** (Shift+F10)
- Minimum API level: 26 (Android 8.0)

## Architecture

```
┌─────────────────────────────────┐
│      Android App (Kotlin)       │
│  MainActivity / STDeviceSDK     │
├─────────────────────────────────┤
│         JNI Interface           │
│    st_device_sdk_jni.c          │
├─────────────────────────────────┤
│    SmartThings Device SDK (C)   │
│  iot_main / iot_capability /    │
│  iot_easysetup / iot_mqtt /     │
│  iot_security / iot_nv_data     │
├─────────────────────────────────┤
│      Android Port Layer         │
│  BSP / OS / Net / Crypto        │
└─────────────────────────────────┘
```

## Key JNI APIs

| Java Method | C Function | Description |
|------------|--------|------|
| `initialize(context)` | `Java_..._initialize` | Initialize SDK |
| `createDevice(config)` | `Java_..._createDevice` | Create device |
| `startEasySetup()` | `Java_..._startEasySetup` | Start EasySetup |
| `sendCapability(attr)` | `Java_..._sendCapability` | Send capability |
| `getDeviceStatus()` | `Java_..._getDeviceStatus` | Get device status |
| `destroyDevice()` | `Java_..._destroyDevice` | Destroy device |

## License

Apache License 2.0