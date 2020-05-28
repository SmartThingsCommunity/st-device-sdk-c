# How to create QR code for SmartThings Device SDK

### Introduction
SmartThings Device SDK allows users to pair their devices with the SmartThings App through a process called device onboarding.
This "device onboarding" process involves confirming whether this device is owned by the user through the user's operation.
STDK provides four methods for this. These four methods are Just Works, Button Confirm, Pin Code Confirm, and QR Code Confirm.
When registering an onboarding profile in Developer Workspace, the developer can select methods will be used to check whether the device to be paired with the SmartThings App is owned by the user during onboarding.
Using QR code is not only used for user verification, but also helps user to onboarding user's device quickly and accurately. 
In the "Add device" menu of the SmartThings App, the onboarding process starts by only scanning QR provided through the "Scan QR code".

### Information included in QR code
The QR code includes the following three pieces of information, and the manufacturer can generate the QR code with the information of each device and provide it to the user.
1. mnid - ID granted to the company. The developer can check this value in Develpoer Workspace or onboarding_profile.json.
2. setupId - A unique identification number in MNID (a.k.a Onboarding ID). The developer can check this value in Developer Workspace or onboarding_profile.json.
(A unique three-digit number that helps identifing this device onboarding)
3. Serial number - A UTF-8 URL encoded unique string assigned to each device. Developer must use the serial number registered in Developer Workspace.

### How to create QR code
The final QR code format is as follows. m is for mnid, s is for setupId and r is for serial number.
```
https://qr.samsungiots.com/?m=****&s=***&r=****************
```
