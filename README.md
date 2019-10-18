# SmartThings Device SDK

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings Device SDK is the core device library that allow device applications to securely connect to the SmartThings Cloud Server. To facilitate the development of device application in an original chipset SDK, we also provide this [reference git repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) for example device applications as well as the core device library. 

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## Main features

This core library provides the following features :

- Customized MQTT  in order to reduce memory consumption and enhance stability
- More easy and efficient APIs
  - Connection APIs : You can do onboarding & MQTT connection by just calling an API.
  - Capability APIs : More than hundred different capabilities can be implemented as 8 APIs.

## How to get started?

This core device library itself supports only POSIX build because it includes platform-dependent parts that should be built in a specific toolchain or SDK. Therefore, if you use a specific vendor's existing SDK, we recommend that you build this git from the [reference git repository](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref) that has a sample device application. 

And, to know how a device information is registered to the SmartThings Cloud Server via Developer Workspace, please visit also the [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/doc/getting_started.md).

## Porting the SDK

Please refer to the [Porting Guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/doc/porting_guide.md) for instructions on porting this SDK.

Like other SDKs, the SmartThings Device SDK has platform-dependent and platform-independent directories. In current SDK version, the platform-dependent directories that must be ported are present in `src/port/bsp` and `src/port/os`.

This SmartThings Device SDK builds with a cross-platform build tool. **As of now, this release builds on Linux and several ported environments of chipset SDKs .**



## Build a POSIX sample

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

2. Build a core library.

   - This build process moves the core library to `~/st-device-sdk-c/output/` location.

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