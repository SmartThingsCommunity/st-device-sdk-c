# SmartThings Device SDK

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings Device SDK(for short STDK) is the core device library that allow device applications to securely connect to the SmartThings Cloud. To facilitate the development of device application in an original chipset SDK, we also provide the [reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) for example device applications as well as this IoT core device library. If you want to use the core device library in your original chipset SDK that installed before, you may simply link it to develop a device application in your existing development environment.

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## Main features

This core device library provides the following features :

- Customized MQTT  in order to reduce memory consumption and enhance stability
- More easy and efficient APIs
  - Connection APIs : You can do onboarding & MQTT connection by just calling only a few these APIs.
  - [Capability](https://smartthings.developer.samsung.com/docs/api-ref/capabilities.html) APIs : More than hundred different capabilities can be implemented as only a few APIs.

## How to get started?

This core device library includes platform-dependent parts that should be built in a specific toolchain or SDK. That is, if you do NOT use the pre-porting environment, you must first port them to the appropriate environment.

After porting, you can use this library completely under the specific environment. Therefore, it is better to refer to one of the pre-supplied example device application in the [reference repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref). Maybe, we think it's more helpful to you.

And, to know how a device information is registered to the SmartThings Cloud via Developer Workspace, please visit also the [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md).

## Porting STDK

The SmartThings Device SDK has platform-dependent directories. In current SDK version, those that must be ported are present in `src/port/bsp` and `src/port/os`. By default, we provide several implementations such as POSIX, ESPRESSIF, REALTEK.

These porting examples in those directories make it easier for you to port to different chipsets and operating systems. Please refer to the [Porting Guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/master/doc/porting_guide.md) for instructions on porting this SDK.

As of now, this release can be cross-compiled via several ported chipset SDK's environments. More information can be found [here](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref)

## Build STDK

The SmartThings Device SDK itself basically supports POSIX build.

### Prerequisites

- `make` build on Ubuntu environment.
- `sudo apt-get install libssl-dev libpthread-stubs0-dev`

### Build

1. Clone the source code.

   - Download the source code via `git clone`.

     ```sh
     cd ~
     git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git
     cd st-device-sdk-c
     ```

2. Build the core device library.

   - This build process moves the core device library to `~/st-device-sdk-c/output/` location.

     ```sh
     cd ~/st-device-sdk-c/
     make
     ```

3. Build a POSIX example application.

   - Go to a example directory and then build.

     ```sh
     cd ~/st-device-sdk-c/example
     make
     ```

## License

This library is licensed under the [Apache License Ver2.0](LICENSE).
