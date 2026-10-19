# _POSIX switch example_

## Summary

This example is providing simple IoT switch device application running on POSIX system. To run the example on POSIX system, you first register device profile on Console according to [Getting Started](../../doc/getting_started.md). And for easy test purpose, this example skips onboarding(registering) process. So you should register your device on the cloud ahead manually according to [manual onboarding tool guide](../../tools/manual_onboarding/README.md).

## Build environment

1. Linux distribution. (tested on Ubuntu 18.04, 20.04)

2. apt-get install git cmake libglib2.0-dev

3. Run `git submodule update --init --recursive` on the SDK to download all modules.

   ```sh
   $ cd st-device-sdk-c/
   $ git submodule update --init --recursive
   ```

## How to build example

1. Put your registered device info in config struct. (in `main.c`)

    ```c
    // Below is config example.
    // You should replace with your device information.
    st_device_config_t dev_config = {
    // You should replace your deviceId and server url.
    // You can get deviceId and server url after registering your device with the manual registering tool.
    .device_id = "12345678-1234-1234-1234-123456789012",
    .server_url = "ssl://mqtt-regional-apnortheast2.api.smartthings.com:8883",

    // You should replace your device identity info.
    // You can get your device identity info from device_info.json.
    .id_method = ST_IDENTITY_METHOD_MANUAL_ED25519,
    .identity = {
        .ed25519 = {
            .sn = "STDKEXAMPLE",
            .pubkey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=",
            .prikey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=",
        },
    },

    // You should replace your onboarding config info.
    // You can get the info from onboarding_config.json.
    .mnId = "ABCD",
    .dip_id = "12345678-1234-1234-1234-123456789012",
    .dip_major_version = 0,
    .dip_minor_version = 1,
    };
    ```
    You can get `device_id`, `server_url` info from manual onboarding registration result. (See [manual onboarding tool guide](../../tools/manual_onboarding/README.md) for details).
    ```sh
    /////// Registration Result ////////
    Device ID : d6f97986-3195-4936-ac91-91c214ce73a2
    Server URL : ssl://mqtt-regional-apnortheast2.api.smartthings.com:8883
    ///////////////////////////////////
    ```

    You can get `identity` from device_info.json. (See [Getting Started](../../doc/getting_started.md#register-test-devices) for details.)
    ```json
     {
       "deviceInfo": {
         "firmwareVersion": "firmwareVersion_here",
         "privateKey": "privateKey_here",
         "publicKey": "publicKey_here",
         "serialNumber": "serialNumber_here"
       }
     }
    ```

    You can get `onboarding config` from onboarding_config.json. (See [Getting Started](../../doc/getting_started.md#download-onboarding_configjson) for details)
    ```json
    {
        "onboardingConfig": {
            "deviceOnboardingId": "NAME",
            "mnId": "MNID",
            "setupId": "999",
            "vid": "VID",
            "deviceTypeId": "TYPE",
            "ownershipValidationTypes": [
                "JUSTWORKS",
                "BUTTON",
                "PIN",
                "QR"
            ],
            "identityType": "ED25519",
            "deviceIntegrationProfileKey": {
                "id": "DIP_UUID",
                "majorVersion": 0,
                "minorVersion": 1
            }
        }
    }
    ```

2. Move to example/posix directory, run cmake and build example.

    ```sh
    $ cd st-device-sdk-c/example/posix
    $ cmake -B build
    $ cd build
    $ make
    ```

3. Excute example.

    ```sh
    $ ./example
    ```

4. Test with SmartThings App on mobile.
