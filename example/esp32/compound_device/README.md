# _ESP32 compound example_

## Summary

This example demonstrate compound device which has 1 main device and 2 child devices. Before running, you need a permission from us to register a device as compound. Please contact partners@smartthings.com if you are interested in developing compound IoT device.

## Build environment

1. Setup ESP32 build environment (Linux/Windows/macOS) according to [ESP Guide](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/index.html).

> **_NOTE:_**  
> This example is tested under ESP-IDF SDK v5.0. Please choose v5.0 when setting up toolchain.  
> This example is verified with ESP32-DevKitC  
> You can also configure other esp32 series as long as they support BLE and Wifi functionality.

2. Acquire SmartThings Device SDK workflow reading [Getting Started](../../doc/getting_started.md) Document.

## How to build example

1. Replace `onboarding_config.json` and `device.json` files under `main` folder with your registered ones on DevWS (see [Getting Started Update Device Information](../..//doc/getting_started.md#update-device-information))

    1-1. You need 2 more device profiles for each child device. Please create 2 more projects on DevWS.

    1-2. For serial numbers for child devices, it doesn't have to be registered on DevWS. Instread, it should be unique under same mnId. We recommend child device serial number derived from main device serial number(For example, if main device serial number is `STDKabcd`, child device serial number can be `STDKabcd-child1`, `STDKabcd-child2` etc.)

    ```c
    // main.c example
    // Create 2 more projects on DevWS for child devices and fill below info.
    // Serial numbers for child devices doesn't have to be registered on DevWS.
    // We recommand serial number naming like 'main device serial number' + '-child' + 'child number'
    st_child_dev_reg_info child_register_info_1 = {
      .mnid = "MNID",
      .serial_number = "first_child_sn",
      .vid = "VID",
      .device_type_id = "TYPE",
      .dip_id = "DIP_UUID",
      .dip_major_version = 0,
      .dip_minor_version = 1
    };

    st_child_dev_reg_info child_register_info_2 = {
      .mnid = "MNID",
      .serial_number = "second_child_sn",
      .vid = "VID",
      .device_type_id = "TYPE",
      .dip_id = "DIP_UUID",
      .dip_major_version = 0,
      .dip_minor_version = 1
    };
    ```

2. Build this example.

   ```sh
   $ cd st-device-sdk-c/example/esp32
   $ idf.py build
   ```
> **_NOTE:_**  
> The build should be exectued after ESP environment variables set(`PATH`, `IDF_PATH` etc.). You can refer [Start a ESP Project on Windows](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/windows-setup.html#get-started-windows-first-steps) or [Start a ESP Project on Linux and macOS](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/linux-macos-setup.html#get-started-linux-macos-first-steps).

> **_NOTE:_** The example default `sdkconfig` file is configured for esp32. To change other esp32 series, you should reconfigure `sdkconfig` file for your testing target.  
For example, we provide some other esp32 series sdkconfig like `sdkconfig.esp32c3`, `sdkconfig.esp32s3`. You can overwrite `sdkconfig` with above file and build.  
>You may need to run fullclean to remove previous target board build configuration before building different target.
>```sh
>$ idf.py fullclean
>```

3. Flash the image on target board and monitor.

    ```sh
    $ idf.py -p PORT flash
    $ idf.py -p PORT monitor
    ```
> **_NOTE:_**  
> To check PORT number on your computer, please check [Connect Your Device on Windows](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/windows-setup.html#connect-your-device) or [Connect your Device on Linux and macOS](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/linux-macos-setup.html#connect-your-device)

Please refer [Getting Started Test](../../doc/getting_started.md#test) guide for testing example with ST app.
