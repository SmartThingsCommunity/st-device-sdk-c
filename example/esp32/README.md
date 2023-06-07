# _ESP32 switch example_

## Build environment

1. Download ESP IDF v5.0 SDK version from [espressif github](https://github.com/espressif/esp-idf) (checkout release/5.0 branch)

   ```sh
   $ mkdir -p ~/esp
   $ cd ~/esp
   $ git clone -b release/v5.0 --recursive https://github.com/espressif/esp-idf.git
   ```

2. Setup ESP32 build environment according to [guide](https://docs.espressif.com/projects/esp-idf/en/release-v5.0/esp32/get-started/index.html)

3. Acquire SmartThings Device SDK workflow reading [Getting Started](../../doc/getting_started.md) Document

## How to build example

1. Build this example and flash image on esp32 board. (Please refer [espressif guide](https://docs.espressif.com/projects/esp-idf/en/release-v5.0/esp32/get-started/linux-macos-setup.html#build-the-project))

   ```sh
   $ cd st-device-sdk-c/example/esp32
   $ idf.py build
   $ idf.py flash
   ```
2. Run and monitor esp32. (Please refer [espressif guide](https://docs.espressif.com/projects/esp-idf/en/release-v5.0/esp32/get-started/linux-macos-setup.html#monitor-the-output))

    ```sh
    $ idf.py monitor
    ```

3. To test your registered devices on DevWS, replace onboarding_config.json and device.json under `main` folder with yours before build. (Refer [Getting Started](../..//doc/getting_started.md#update-device-information))


Please refer [Getting Started](../../doc/getting_started.md#test) guide for testing example with ST app.
