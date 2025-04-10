# How to create secure key for SmartThings Device SDK

### Introduction
SmartThings Device SDK allows users to pair their devices with the SmartThings App through a process called device onboarding.
During device onboarding, the device and user information shall be protected. To support, a key for encryption is required.
SmartThings Device SDK provides Key generation tool at `st-device-sdk-c/tools/keygen/` to help the developer.
But, if the developer has own key generation tool, they can use thiers

### How to use SmartThings Device SDK key generation tool
This example shows how to create ED25519 key pair with SDK tools. You can get device_info.json file as a result from tools/keygen/output_{ serialNumber}
Prefix 'STDK' means serial number for the developer.

```sh
$ cd {SDK_ROOT}/tools/keygen/
$ python3 stdk-keygen.py --firmware switch_example_001
Use following serial number and public key
for the identity of your device in Developer Workspace.

Serial Number:
STDK**E90W***uCX

Public Key:
nFN5x***uQusQ****ZHoBSFaAoP9***kNdLnjDJRew=
```

Products shall have unique serial number.

Manufacturer shall use the serial number in the result depending on their policy for the commercialization.

The created serial number shall use safe characters in URLs.
|                      | Characters                                                                                           |
| :------------------- | :---------------------------------------------------------------------------------------------------|
| Safe characters       | Alphanumeric [0-9a-zA-Z], special characters $-_.+!*'(),                                            |

SmartThings Device SDK also provides the bulk generation.
This tool can be installed by following the [guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/tools/keygen/README.md) 
Key Generation tool offers several options
| Option               | Description                                                                                         |
| :------------------- | :---------------------------------------------------------------------------------------------------|
| -h, --help           |show this help message and exit                                                                      |
| --mnid MNID          |[I] can set your MNID as prefix of Serial Number                                                     |
| --firmware version   |[I] firmware version for device_info.json                                                            |
| --input csv          |[C] input csv file that has a list of serial numbers                                                 |
| --output csv         |[C] output batch csv file                                                                            |
| --nv {esp, esp-encrypt} |generate nv image for choiced chipset                                                                |
| --qr                 |generate QR code image. --path is required                                                           |
| --path PATH          |input the path located onboarding_config.json (Or copy onboarding_config.json to the current folder) |
  
ex) If the manufacturer uses two options, --input <CSV file> abd --qr, they can get the sercure key and QR, together.
