# _Raspberry Pi switch example_

## Build environment

1. Raspberry Pi 4 Model B

2. Raspberry Pi OS (64-bit) - Debian ver: 13 (Trixie), Kernel ver: 6.12.47+rpt-rpi-v8

3. sudo apt install git cmake libglib2.0-dev

4. Stop Network Manager service. (systemctl stop NetworkManager)
(Because we manipulate wlan0 with wpa_supplicant, need to stop other network interference)

5. Download all dependent submodules

   ```sh
   $ cd st-device-sdk-c/
   $ git submodule update --init --recursive
   ```

## Configure RPi BLE stack

Prevent pairing popups and to stop reverse service discovery

1. Edit `/etc/bluetooth/main.conf` file to disable `ReverseServiceDiscovery` flag
    ```sh
    - #ReverseServiceDiscovery = true
    + ReverseServiceDiscovery = false
    ```

## How to build and run example

1. Move to `st-device-sdk-c` example directory, run cmake and build example.

   ```sh
   $ cd st-device-sdk-c/example/raspberry
   $ cmake -B build
   $ cd build
   $ make
   ```

2. To test your registered devices on DevWS, replace `onboarding_config.json` and `device_info.json` with yours before build. (Refer [Getting Started](../..//doc/getting_started.md))

3. Execute example with root rights and test

    ```sh
    $ sudo ./example
    ```

Please refer [Getting Started](../../doc/getting_started.md) guide for testing example with ST app.
