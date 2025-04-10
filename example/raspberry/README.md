# _Raspberry Pi switch example_

## Build environment

1. Raspberry Pi 4 Model B

2. Raspberry Pi OS(32-bit) Released : 2023-02-21

3. apt-get install git cmake libglib2.0-dev

4. Stop Network Manager service. (systemctl stop NetworkManager)
(Because we manipulate wlan0 with wpa_supplicant, need to stop other network interference)

5. Run `git submodule update --init --recursive` on the SDK to download all modules.

   ```sh
   $ cd st-device-sdk-c/
   $ git submodule update --init --recursive
   ```

## How to build example

1. Move to example/raspberry directory, run cmake and build example.

   ```sh
   $ cd st-device-sdk-c/example/raspberry
   $ cmake -B build
   $ cd build
   $ make
   ```

2. To test your registered devices on DevWS, replace onboarding_config.json and device.json with yours before build. (Refer [Getting Started](../..//doc/getting_started.md))

3. Excute example with root right and test (sudo ./example)

    ```sh
    $ sudo ./example
    ```

Please refer [Getting Started](../../doc/getting_started.md) guide for testing example with ST app.
