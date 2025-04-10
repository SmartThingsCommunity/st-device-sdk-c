# How to create QR code for SmartThings Device SDK

### Introduction
SmartThings Device SDK allows users to pair their devices with the SmartThings App through a process called device onboarding.
This "device onboarding" process involves confirming whether this device is owned by the user through the user's operation.
STDK provides four methods for this. These four methods are Just Works, Button Confirm, Pin Code Confirm, and QR Code Confirm.
When registering an onboarding profile in Developer Workspace, the developer can select methods may be used to check whether the device to be paired with the SmartThings App is owned by the user during onboarding.
Using QR code is not only used for user verification, but also helps user to onboarding user's device quickly and accurately. 
In the "Add device" menu of the SmartThings App, the onboarding process starts by only scanning QR provided through the "Scan QR code".

### Information included in QR code
The QR code includes the following three pieces of information, and the manufacturer can generate the QR code with the information of each device and provide it to the user.
1. mnId - ID granted to the company. The developer can check this value in Develpoer Workspace or onboarding_profile.json.
2. setupId - A unique identification number in MNID (a.k.a Onboarding ID). The developer can check this value in Developer Workspace or onboarding_profile.json.
(A unique three-digit number that helps identifing this device onboarding)
3. SerialNumber - A UTF-8 URL encoded unique string assigned to each device. Developer shall use the serial number registered in Developer Workspace. Used serial number shall use safe characters in URLs.

|                      | Characters                                                                                           |
| :------------------- | :---------------------------------------------------------------------------------------------------|
| Safe characters       | Alphanumeric [0-9a-zA-Z], special characters $-_.+!*'(),                                            |

### How to create QR code
The final QR code format is as follows. m is for mnid, s is for setupId and r is for serial number.
```
https://qr.samsungiots.com/?m=<mnId>&s=<setupId>&r=<SerialNumber>
```
To create QR code, SmartThings Device SDK provides QR generation tool at `st-device-sdk-c/tools/qrgen/`.

This tool can be installed by following the [guide](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/tools/qrgen/README.md) 

QR Generation tool offers options

| Option               | Description                                                                                         |
| :------------------- | :---------------------------------------------------------------------------------------------------|
| -h, --help           | show this help message and exit                                                                     |
| --folder FOLDER      | Folder containing onboarding_config.json and device_info.json (if not supplied uses current folder) |
