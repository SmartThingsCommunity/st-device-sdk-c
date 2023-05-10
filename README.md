# SmartThings SDK for Direct Connected Devices for C

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings SDK for Direct Connected Devices for C is the IoT core device library that allow device applications to securely connect to the SmartThings Cloud.
To facilitate the development of device application in your original chipset SDK that installed before, we provide this core device library as a separate repository.
You may simply link it to develop a device application in your existing development environment.

We also provide examples so that so that you can refer to how this core device library can be linked in existing original chipset SDKs and device applications can be developed.

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## Main features

This core device library provides the following features :

- Customized MQTT in order to reduce memory consumption and enhance stability
- Easy and efficient APIs
  - Connection APIs : You can do onboarding & MQTT connection by just calling only a few these APIs.
  - Capability APIs : More than hundred different capabilities can be implemented as only a few APIs.

## How to get started?

This core device library includes platform-dependent parts that should be built in a specific toolchain or SDK. That is, if you do NOT use the pre-porting environment, you must first port them to the appropriate environment.

After porting, you can use this library completely under the specific environment. For more information on detailed workflow below, please refer to the [Getting Started](./doc/getting_started.md). Maybe, we think it's more helpful to you

- Register a Device on Developer Workspace
- Develop a Device Application

## Porting SmartThings SDK for Direct Connected Devices for C

This core device library has platform-dependent directories. In current SDK version, those that must be ported are present in `src/port/bsp`, `src/port/net` and `src/port/os`.
By default, we have already provided several implementations based on some operating systems(e.g. FreeRTOS, LINUX) and chipsets(e.g. ESPRESSIF, REALTEK, Raspberry Pi). These porting examples in those directories make it easier for you to port to additional chipsets and operating systems.

For instructions on how to port this SDK, please see the [Porting Guide](./doc/porting_guide.md).

## Building SmartThings SDK for Direct Connected Devices for C

This core device library should be built according to the chipset development environment to be applied. If this environment is not ready yet, you can build it in the POSIX environment based on Ubuntu as shown below.

But, unlike the resource limited MCU devices, you can NOT check the onboarding process in the POSIX environment because it does not support a SoftAP function by default. Therefore, as a starting point of this SDK, we strongly recommend that you build one of the MCU device examples provided in `example` directory to use all features without limitations.

### Prerequisites

Basically, you can build this core device library through `cmake` in the Ubuntu.

- `sudo apt-get install libssl-dev libpthread-stubs0-dev`

### Build

1. Clone the source code.

   - Download the source code via `git clone`.

     ```sh
     $ git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git
     ```

2. Build a POSIX example application.

   - Go to a example directory and then build.

     ```sh
     $ cd st-device-sdk-c/example/posix
     $ cmake -B build
     $ cd build
     $ make
     ```

## Learn more

For more information, please review the following documents:

- [Getting Started](./doc/getting_started.md) : It covers the overall workflow and detailed steps for starters to work with SDK.
- [API References](./doc/APIs.md) : It provide all API reference that SDK offers.
- [Commercialization Guide](./doc/Commercialization_Guide) : It provides guide for ones who consider commercializing their IoT products with SDK.
- [Capabilities Reference](https://developer.smartthings.com/docs/devices/capabilities/capabilities) : This page serves as a reference for the supported capabilities.
- [Developer Workspace](https://smartthings.developer.samsung.com/workspace/) : It provides functions related to device information registration and device integration in the SmartThings cloud.

## License

This library is licensed under the [Apache License Ver2.0](LICENSE).
