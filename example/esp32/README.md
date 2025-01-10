# _ESP32 switch example_

## Build environment

1. Setup ESP32 build environment (Linux/Windows/macOS) according to [ESP Guide](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/index.html).

> **_NOTE:_**  
> This example is tested under ESP-IDF SDK v5.0. Please choose v5.0 when setting up toolchain.  
> You can also setup other esp32 series like ESP32-S series, ESP32-C series according to above setup guide.

2. Acquire SmartThings Device SDK workflow reading [Getting Started](../../doc/getting_started.md) Document.

## How to build example

1. Replace `onboarding_config.json` and `device.json` files under `main` folder with your registered ones on DevWS (see [Getting Started Update Device Information](../..//doc/getting_started.md#update-device-information))

2. Build this example.

   ```sh
   $ cd st-device-sdk-c/example/esp32
   $ idf.py build
   ```
> **_NOTE:_**  
> The build should be exectued after ESP environment variables set(`PATH`, `IDF_PATH` etc.). You can refer [Start a ESP Project on Windows](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/windows-setup.html#get-started-windows-first-steps) or [Start a ESP Project on Linux and macOS](https://docs.espressif.com/projects/esp-idf/en/v5.0.7/esp32/get-started/linux-macos-setup.html#get-started-linux-macos-first-steps).

> **_NOTE:_** The example default target board is esp32. To run the example on other esp32 series, change `CONFIG_IDF_TARGET` in `sdkconfig` file with desired target board before build.  
> For example, to run the example on esp32s3 board, change `CONFIG_IDF_TARGET` in `sdkconfig` file like below.
>```vim
>... (Skip) ...
>CONFIG_IDF_TARGET="esp32s3"
>... (Skip) ...
>```
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
