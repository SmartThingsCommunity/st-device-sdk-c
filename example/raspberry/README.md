# _Raspberry Pi switch example_

## Build environment

1. Raspberry Pi 4 Model B

2. Raspberry Pi OS (64-bit) - Debian ver: 12 (bookworm), Kernel ver: 6.6.74+rpt-rpi-v8

3. apt-get install git cmake libglib2.0-dev

4. Stop Network Manager service. (systemctl stop NetworkManager)
(Because we manipulate wlan0 with wpa_supplicant, need to stop other network interference)

5. Download all dependent submodules

   ```sh
   $ cd st-device-sdk-c/
   $ git submodule update --init --recursive
   ```

## Update RPi BLE stack

I. Custom scan response:

The BlueZ BLE stack package needs to be updated to add custom data in ble scan response packet

> **_NOTE:_**
> The following steps have been verified on RPi with Bluez v5.66

1. Get the bluez source code

    ```sh
    $ apt-get source bluez
    ```

2. Move to bluez `patches` directory (eg: bluez-5.66) and copy bluez patches from `st-device-sdk-c` repo

    ```sh
    $ cd bluez-xxx/debian/patches
    $ cp <st-device-sdk-c dir path>/example/raspberry/patches/bluez/*.patch .
    ```

3. In the same bluez `patches` folder, update `series` file to mention names of the 3 bluez patches

    ```sh
    0001-add-manufacturer-data-for-scan-response.patch
    0002-add-documentation-for-property-ManufacturerDataSR.patch
    0003-add-manufacturer-data-at-the-end.patch
    ```

4. Move to bluez main directory and rebuild bluez package

    ```sh
    $ cd bluez-xxx/
    $ debuild -us -uc -b
    ```

> **_NOTE:_**
> If there are build errors:\
> a. For build error that mentions installation of dependencies
> ```sh
> $ sudo apt install flex bison libdw-dev libudw-dev
> ```
> b. For other build errors, try with '-d' option
> ```sh
> $ sudo debuild -us -uc -b -d
> ```

5. Install the updated bluez package (eg: bluez_5.66-1+deb12u2_armhf.deb)

    ```sh
    $ sudo dpkg -i ../bluez_xxx-deb12u2-xxx.deb
    ```

6. Restart Bluetooth service

    ```sh
    $ sudo systemctl restart bluetooth.service
    ```

II. Prevent pairing popups:

Configure BlueZ to prevent pairing popups and to stop reverse service discovery

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
