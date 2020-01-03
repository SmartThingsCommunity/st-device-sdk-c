# SmartThings Device SDK

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings Device SDK(for short STDK) is the IoT core device library that allow device applications to securely connect to the SmartThings Cloud. To facilitate the development of device application in your  original chipset SDK that installed before, we provide this core device library as a separate repository. You may simply link it to develop a device application in your existing development environment.

We also provide the additional Reference repository so that you can refer to how this core device library can be linked in existing original chipset SDKs and device applications can be developed.

- [Reference](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) : There are sample device applications under the `apps` directory.

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## Main features

This core device library provides the following features :

- Customized MQTT  in order to reduce memory consumption and enhance stability
- More easy and efficient APIs
  - Connection APIs : You can do onboarding & MQTT connection by just calling only a few these APIs.
  - [Capability](https://smartthings.developer.samsung.com/docs/api-ref/capabilities.html) APIs : More than hundred different capabilities can be implemented as only a few APIs.

## How to get started?

This core device library includes platform-dependent parts that should be built in a specific toolchain or SDK. That is, if you do NOT use the pre-porting environment, you must first port them to the appropriate environment.

After porting, you can use this library completely under the specific environment. Therefore, it is better to refer to one of the pre-supplied example device applications in the [Reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref). Maybe, we think it's more helpful to you.

And, to know how a device information is registered to the SmartThings Cloud via [Developer Workspace](https://smartthings.developer.samsung.com/workspace/), please visit also the [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md).

## Porting STDK

This core device library has platform-dependent directories. In current SDK version, those that must be ported are present in `src/port/bsp`, `src/port/net` and `src/port/os`. By default, we provide several implementations such as POSIX, ESPRESSIF, REALTEK.

These porting examples in those directories make it easier for you to port to different chipsets and operating systems. Please refer to the [Porting Guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/master/doc/porting_guide.md) for instructions on porting this SDK.

As of now, this release can be cross-compiled via several ported chipset SDK's environments. More information can be found [here](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref).

## Building STDK

This core device library should be built according to the chipset development environment to be applied. If this environment is not ready yet, you can build it in the POSIX environment as shown below. But, unlike the resource limited MCU devices, you can NOT check the onboarding process in the POSIX environment because it does not support a SoftAP function by default. Therefore, as a starting point, we strongly recommend that you build one of the MCU device examples provided in the [Reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) to use all features without limitations.

### Prerequisites

Basically, you can build this core device library through `make` in the Ubuntu.

- `sudo apt-get install libssl-dev libpthread-stubs0-dev`

### Build

1. Clone the source code.

   - Download the source code via `git clone`.

     ```sh
     $ cd ~
     $ git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git
     $ cd st-device-sdk-c
     ```

2. Build the core device library.

   - This build process moves the core device library to `~/st-device-sdk-c/output/` location.

     ```sh
     $ cd ~/st-device-sdk-c/
     $ make
     ```

3. Build a POSIX example application.

   - Go to a example directory and then build.

     ```sh
     $ cd ~/st-device-sdk-c/example
     $ make
     ```

## Learn more

For more information, please review the following documents:

- [SmartThings Direct-connected devices](https://smartthings.developer.samsung.com/docs/devices/direct-connected-devices/overview.html) : It covers the overall workflow and detailed steps for connecting devices to the SmartThings Cloud directly.
- [Capabilities Reference](https://smartthings.developer.samsung.com/docs/api-ref/capabilities.html) : This page serves as a reference for the supported capabilities.
- [Developer Workspace](https://smartthings.developer.samsung.com/workspace/) : It provides functions related to device information registration and device integration in the SmartThings cloud.
- [STDK Code Lab](https://developer.samsung.com/codelab/smartThings/device/overview) : The code lab data of the 2019 Samsung Developer Conference. It includes a demo video and a tutorial.

## License

This library is licensed under the [Apache License Ver2.0](LICENSE).
