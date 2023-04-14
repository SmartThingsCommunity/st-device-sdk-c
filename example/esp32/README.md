# _ESP32 switch example_

## Build environment

1. Download ESP IDF v4.3.1 SDK version(git commit : 2e74914051d14ec2290fc751a8486fb51d73a31e)

2. Setup ESP32 build environment [guide](https://docs.espressif.com/projects/esp-idf/en/release-v4.3/esp32/get-started/index.html)

## How to build example

1. To test your registered devices on DevWS, replace onboarding_config.json and device.json with yours before build. (Refer [Getting Started](../..//doc/getting_started.md))

2. Build this example and flash image on esp32 board.

   ```sh
   $ cd st-device-sdk-c/example/esp32
   $ idf.py build
   $ idf.py flash
   ```
3. Run and monitor esp32

    ```sh
    $ idf.py monitor
    ```

Please refer [Getting Started](../../doc/getting_started.md) guide for testing example with ST app.
