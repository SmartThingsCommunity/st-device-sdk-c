# SmartThings Device SDK

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings Device SDK is the IoT core device library that allow device applications to securely connect to the SmartThings Cloud. To facilitate the development of device application in your  original chipset SDK that installed before, we provide this core device library as a separate repository. You may simply link it to develop a device application in your existing development environment.

We also provide the additional Reference repository so that you can refer to how this core device library can be linked in existing original chipset SDKs and device applications can be developed.

- [Reference](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) : There are sample device applications under the `apps` directory.

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## Announcements

Good news! We have launched the new commercial program for MQTT devices. You will be able to submit for certification into the SmartThings mobile app later this month. To prepare for submission, please perform the necessary steps with your current integrations:

 - Update to the latest SmartThings Device SDK
   - Please use SmartThings Device SDK v1.3.3 or later
 - Downlaod the updated onboarding_config.json for your devices.
 - Re-register any test devices you have registered previously.
 - Update to the latest SmartThings mobile app to test your device
   - Please use SmartThings mobile application v1.7.51 (for Android), v1.6.51 (for iOS) or later

## Main features

This core device library provides the following features :

- Customized MQTT  in order to reduce memory consumption and enhance stability
- Easy and efficient APIs
  - Connection APIs : You can do onboarding & MQTT connection by just calling only a few these APIs.
  - [Capability](https://smartthings.developer.samsung.com/docs/api-ref/capabilities.html) APIs : More than hundred different capabilities can be implemented as only a few APIs.

## How to get started?

This core device library includes platform-dependent parts that should be built in a specific toolchain or SDK. That is, if you do NOT use the pre-porting environment, you must first port them to the appropriate environment.

After porting, you can use this library completely under the specific environment. Therefore, it is better to refer to one of the pre-supplied example device applications in the [Reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref). For more information on detailed workflow below, please refer to the [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md). Maybe, we think it's more helpful to you

- Setup Environment
- Register a Device
- Develop a Device Application

## Porting SmartThings Device SDK

This core device library has platform-dependent directories. In current SDK version, those that must be ported are present in `src/port/bsp`, `src/port/net` and `src/port/os`. By default, we have already provided several implementations based on some operating systems(e.g. FreeRTOS) and chipsets(e.g. ESPRESSIF, REALTEK). These porting examples in those directories make it easier for you to port to additional chipsets and operating systems. As of now, this release can also be cross-compiled directly through several chipset SDK environments that have already been ported in the [Reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref).

For instructions on how to port this SDK, please see the [Porting Guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/master/doc/porting_guide.md).

## Building SmartThings Device SDK

This core device library should be built according to the chipset development environment to be applied. If this environment is not ready yet, you can build it in the POSIX environment based on Ubuntu as shown below.

But, unlike the resource limited MCU devices, you can NOT check the onboarding process in the POSIX environment because it does not support a SoftAP function by default. Therefore, as a starting point of this SDK, we strongly recommend that you build one of the MCU device examples provided in the [Reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) to use all features without limitations.

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
- [SmartThings Device SDK Code Lab](https://developer.samsung.com/codelab/smartthings/smartthings-device-sdk/overview.html) : The code lab data of the 2019 Samsung Developer Conference. It includes a demo video and a tutorial.

## License

This library is licensed under the [Apache License Ver2.0](LICENSE).
