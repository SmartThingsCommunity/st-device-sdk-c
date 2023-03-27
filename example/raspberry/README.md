# _Raspberry Pi switch example_

## Build environment

1. Raspberry Pi 4 Model B

2. Raspberry Pi OS(32-bit) Released : 2023-02-21

3. apt-get install git cmake libglib2.0-dev

## How to build example

1. Stop Network Manager service. (systemctl stop NetworkManager)
(Because we manipulate wlan0 with wpa_supplicant, need to stop other network interference)

2. Run 'git submodule update --init --recursive' on the SDK to download all modules.

3. Move to example/raspberry directory, run cmake and build example.

4. To test your registered devices on DevWS, replace onboarding_config.json and device.json with yours before build. (Refer [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md))

5. Excute example with root right and test (sudo ./example)

Please refer [Getting Started](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/master/doc/getting_started.md) guide for integration test.
