# _POSIX switch example_

## Summary

This example is providing simple IoT switch device application running on POSIX system. To run the example on POSIX system, you first register device profile on Developer Workspace according to [Getting Started](../../doc/getting_started.md). And for easy test purpose, this example skips onboarding(registering) process. So you should register your device on the cloud ahead manually according to [manual onboarding tool guide](../../tools/manual_onboarding/README.md).

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
    // You should replace your deviceId and server type.
    // You can get deviceId and server type after registering your device with the manual registering tool.
    .device_id = "12345678-1234-1234-1234-123456789012",
    .server_type = SERVER_TYPE_AP_NORTH_EAST2,

    // You should replace your device identity info.
    // You can get your device identity info from device_info.json created after using keygen tool.
    .id_method = ST_IDENTITY_METHOD_MANUAL_ED25519,
    .identity = {
        .ed25519 = {
            .sn = "STDKEXAMPLE",
            .pubkey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=",
            .prikey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=",
        },
    },

    // You should replace your mnId.
    // You can check your mnid from onboarding_config.json or Developer Workspace.
    .mnId = "ABCD",
    };
    ```
    You can get `device_id`, `server_type`, `mnId` info from manual onboarding registration result. (See [manual onboarding tool guide](../../tools/manual_onboarding/README.md) for details).
    ```sh
    /////// Registration Result ////////
    Device ID : d6f97986-3195-4936-ac91-91c214ce73a2
    mnId : fkOP
    Server Type : AP_NORTH EAST2
    ///////////////////////////////////
    ```

    You can get `identity` from device_info.json. (See [keygen tool guide](../../tools/keygen/README.md) for details.)
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
