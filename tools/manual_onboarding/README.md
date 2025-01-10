# Manual Onboarding Script Tool

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

## Summary

This script tool provides way to register a device manually on SmartThings platform instead of a real device onboarding process.
So, you can build fast prototype SmartThings IoT application using the SDK on your desktop environment without real device board.

## Remark

This tool is provided to aim to help fast PoC bring-up and development. After checking functional feasibility, you need to test it on real device from onboarding process.

## Prerequisites

* User PAT (Personal Access Token) with devices, deviceprofiles, location scope. (Refer [How To Generate PAT](https://developer.smartthings.com/docs/getting-started/authorization-and-permissions))
* Registered Device Profile and Test Devices identity (Please read [How To Register a Device on Developer Workspace](../../doc/getting_started.md#register-a-device-on-developer-workspace))

## Usage

```sh
stdk-onboarding.py
```

### Example

1. Enter your PAT. If you don't have it, please generate one with devices, deviceprofiles, locatio scope. (Refer [How To Generate PAT](https://developer.smartthings.com/docs/getting-started/authorization-and-permissions))

![enter PAT](./res/manual_onboarding_enter_PAT.png)

2. Choose location and room to register a device on your SmartThings App.

![choose location and room](./res/manual_onboarding_choose_location_room.png)

3. Choose device profile of the device. (You can find your device profile name on Developer Workspace. Click the _Device Profile_ under _Develop_ tab on your Project. Please refer [Getting Started](../../doc/getting_started.md#register-a-device-on-developer-workspace) document.)

![choose device profile](./res/manual_onboarding_choose_device_profile.png)

![device profile on DevWS](./res/DevWS_device_profile.png)

4. Enter serial number for the device. You should enter registered serial number on your developer Workspace. (You can find registered device serial number in _Test Devices_ under _Test_ tab. Please refer [Getting Started](../../doc/getting_started.md#register-a-device-on-developer-workspace) document.)

![enter serial number](./res/manual_onboarding_enter_serial.png)

![serial on DevWS](./res/DevWS_device_serial.png)

5. Enter device label to show on SmartThings App. If you skip, default device label is device profile name.

![enter label](./res/manual_onboarding_enter_label.png)

6. Review registration info before proceeding.

![review info](./res/manual_onboarding_review_register_info.png)

7. Result of registration. You can get device id for registered device on SmartThings platform.

![review info](./res/manual_onboarding_register_result.png)

### Result

On SmartThings App

![sign in](./res/manual_onboarding_result.png)
