# SmartThings SDK for Direct Connected Devices for C

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

The SmartThings SDK for Direct Connected Devices for C is the IoT core device library that allow device applications to securely connect to the SmartThings Cloud.
To facilitate the development of device application in your original chipset SDK that installed before, we provide this core device library as a separate repository.
You may simply link it to develop a device application in your existing development environment.

We also provide examples so that so that you can refer to how this core device library can be linked in existing original chipset SDKs and device applications can be developed.

It is distributed in source form and written in C99 for the purpose of portability to most platforms.

## SmartThings SDK version 2.0 Release

With the release of SmartThings SDK version 2.0, we decided to no longer support softAP-based ST app connections. 
If you want to use softAP-based SmartThings SDK, you should use SmartThings SDK version 1.X. 
The currently provided softAP-based SmartThings SDK can be used, but new feature upgrades are no longer planned to be supported for softAP-base SmartThings SDK.

Because softAP-based devices have technical limitations in supporting the functions planned by SmartThings, we have released SmartThings SDK version 2.0, which provides BLE-based connection with SmartThings APP.
If the chipset to be used in the product supports BLE, it is recommended to use a BLE-based SmartThings SDK.

Using BLE is expected to not only support new SmartThings features, but also improve device search and connection stability with the SmartThings APP.

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

This core device library has platform-dependent directories. In current SDK version, those that must be ported are present in `src/port`.
By default, we have already provided several implementations based on some operating systems(e.g. FreeRTOS) and chipsets(e.g. ESPRESSIF). These porting examples in those directories make it easier for you to port to additional chipsets and operating systems.

For instructions on how to port this SDK, please see the [Porting Guide](./doc/porting_guide.md).

## Git Branch Guide

We are managing two git branch categories. One is `develop` branch. The other is `release/v{version}` branchs. In `devleop` branch, we are merging latest developing features actively. In `release/v{version}` branchs, we branch out from `devleop` branch and keep them stable updating bugfix and small amendment. If you want to use latest SDK features for test or POC, we recommand `devleop` branch as base. Or if you want to apply the SDK in real product and consider commercializing, we recommand `release/v{version}` branchs as base.

- `develop` branch : Latest devleoping features. Recommand for new feature test or POC.
- `release/v{version}` branchs : Tested and stable branchs. Recommand for Commercial product.

## Quick PoC development on Linux distribution

You can build and test the SDK on your Linux distribution environment without real target board. In this way, you can easily make PoC demo for your product and check your IoT device feasibility on SmartThings platform. Also in real product developing, building and testing on Linux environment can accelerate product development speed.

We provide `example/posix` example to demonstrate how to build and test the SDK on Linux distribution. But before running the example, you should acquire [Getting Started](./doc/getting_started.md) to be familiar with the SDK development process and register your test device profile on [Developer Workspace](https://developer.smartthings.com/workspace/). And this example skips onboarding(registering) process, so before test, you should register your device on the cloud manually with [manual onboarding tool](./tools/manual_onboarding/README.md) provided in `tools/manual_onboarding` folder.

## Learn more

For more information, please review the following documents:

- [Getting Started](./doc/getting_started.md) : It covers the overall workflow and detailed steps for starters to work with SDK.
- [API References](./doc/APIs.md) : It provide all API reference that SDK offers.
- [Commercialization Guide](./doc/Commercialization_Guide) : It provides guide for ones who consider commercializing their IoT products with SDK.
- [Capabilities Reference](https://developer.smartthings.com/docs/devices/capabilities/capabilities-reference) : This page serves as a reference for the supported capabilities.
- [Developer Workspace](https://developer.smartthings.com/workspace/) : It provides functions related to device information registration and device integration in the SmartThings cloud.

## Commercialization

For commercialization, refer to the following [link](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/doc/Commercialization_Guide).

If you have any issue, or want to commercialize your IoT devices using this SDK, please use the following contact point.
- Commercializatioin : partners@smartthings.com
- Technical inquiry : open new issue on Github

## License

This library is licensed under the [Apache License Ver2.0](LICENSE).
