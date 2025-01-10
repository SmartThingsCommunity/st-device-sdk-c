# Ed25519 Key Pair generation tools for Individual and Commercial

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

## Summary

This repository provides a tools to generate key pair and batch file for Developer Workspace.
Ed25519 is a signature algorithm with EdDSA over curve25519.

## Remark

This utility is limited to generate key pairs for test devices.
Each manufacturer should use their own method to meet security requirements for commercial devices.  

For example
 * The operation of key management facility must be conducted in a secure manner.
 * If device key pair is generated outside device and later injected, the generated private key must only be maintained outside the device in encrypted form and should be deleted after successful injection.
 * The generated key pairs must be globally uniquely identified independently based on its identifiers.

Please refer security guideline document which is available at `Publish` menu of Developer Workspace.

## Requirement

* The length of serial number should be between 8 and 30.
* The generated private key must only be maintained outside the device in encrypted form and should be deleted after successful injection to device.
* The generated key pairs must be globally uniquely identified independently based on its identifiers.
* The key management facility must provide a way to check the validity of each key pair for known compromised devices.

## Prerequisites

Install pynacl python package
```sh
pip install pynacl --user
```

## Usage

```sh
stdk-keygen.py [-h] [--mnid MNID] [--firmware version] [--input csv] [--output csv] [--nv {esp}] [--qr] [--path PATH]
```

### Individual

Example
```sh
$ python stdk-keygen.py
Use following serial number and public key
for the identity of your device in Developer Workspace.

Serial Number:
STDKod********63

Public Key:
GbZr************************************PDw=
```
Output files
```sh
$ tree output_STDKod********63/
output_STDKod********63/
├── device_info.json
├── device.pubkey.b64
└── device.seckey.b64
```
You can add your *MNID* in serial number and set firmware version in device_info.json.
```sh
$ python stdk-keygen.py --mnid TEST --firmware V20200804
Use following serial number and public key
for the identity of your device in Developer Workspace.

Serial Number:
STDKTEST****7KXw

Public Key:
Fqj6************************************hp0=

$ cat output_STDKTEST****7KXw/device_info.json
{
	"deviceInfo": {
		"firmwareVersion": "V20200804",
		"privateKey": "H/Jy************************************1p4=",
		"publicKey": "Fqj6************************************hp0=",
		"serialNumber": "STDKTEST****7KXw"
	}
}
```

You can generate QR code which could be helpful to add your device in ST app.
```sh
$ python stdk-keygen.py --qr --path [location of onboarding_config.json]
Use following serial number and public key
for the identity of your device in Developer Workspace.

Serial Number:
STDKTEST****7KXw

Public Key:
Fqj6************************************hp0=

File:	output_STDKTEST****7KXw/qr-STDKTEST****7KXw.png 
QR url:	https://qr.samsungiots.com/?m=****&s=***&r=STDKTEST****7KXw

$ tree output_STDKTEST****7KXw/
output_STDKTEST****7KXw/
├── device_info.json
├── device.pubkey.b64
├── device.seckey.b64
└── qr-STDKTEST****7KXw.png

```

Copy the Serial Number and Public Key after running the command. You will need to upload these values to the SmartThings Cloud via [Developer Workspace](https://smartthings.developer.samsung.com/workspace/projects) during the next phase.

If you create a device identity with a command with an option like above,  You can get the ready-to-use `device_info.json` file directly.

### Commercial

Example
```sh
$ python stdk-keygen.py --input sn.csv
Loading sn.csv...
Batch file has been saved: output_bulk/2020****_193746/DI_Batch_2020****_193746.csv
```
Output files
output csv file (DI_Batch_20200722_193746.csv in below example)
serial number named sub directory which contains key pair
```sh
$ tree output_bulk/
output_bulk/
└── 20200722_193746
    ├── DI_Batch_20200722_193746.csv
    ├── TEST12345678
    │   ├── device.pubkey.b64
    │   └── device.seckey.b64
    ├── TEST23456789
    │   ├── device.pubkey.b64
    │   └── device.seckey.b64
    └── TEST34567890
        ├── device.pubkey.b64
        └── device.seckey.b64
```
You can generate QR code for commercial
```sh
$ python stdk-keygen.py --input sn.csv --qr --path [location of onboarding_config.json]
Loading sn.csv...
...
Batch file has been saved: output_bulk/2020****_193746/DI_Batch_2020****_193746.csv
```
Output files
output csv file (DI_Batch_20200722_193746.csv in below example)
serial number named sub directory which contains key pair and QR code image
```sh
$ tree output_bulk/
output_bulk/
└── 20200722_193746
    ├── DI_Batch_20200722_193746.csv
    ├── TEST12345678
    │   ├── device.pubkey.b64
    │   └── device.seckey.b64
    │   └── qr-TEST12345678.png
    ├── TEST23456789
    │   ├── device.pubkey.b64
    │   └── device.seckey.b64
    │   └── qr-TEST23456789.png
    └── TEST34567890
        ├── device.pubkey.b64
        └── device.seckey.b64
        └── qr-TEST34567890.png
```
Change the output batch file location
```sh
python stdk-keygen.py --input sn.csv --output output/batch.csv
```
Generate NV image (for ESP chipset)
```sh
python stdk-keygen.py --input sn.csv --nv esp
```
* Please find a stnv image to flash with stnv-${SN}.img
* Make sure the IDF_PATH has been exported as following
```sh
export IDF_PATH=.../st-device-sdk-c-ref/bsp/esp32
or
export IDF_PATH=.../st-device-sdk-c-ref/bsp/esp8266
```

#### csv format
* Input csv file
has 'serial number' list
**header**
sn
**example**
    ```bash
    sn
    TEST12345678
    TEST23456789
    TEST34567890
    ...
    ```
* Output csv file
**header**
sn,keyType,keyCrv,pubkey
**example**
    ```bash
    sn,keyType,keyCrv,pubkey
    TEST12345678,ECPUBKEY,ED25519,JSHp***********************************02Y0=
    TEST23456789,ECPUBKEY,ED25519,AYzF***********************************zl8k=
    TEST34567890,ECPUBKEY,ED25519,5rfr***********************************8wQo=
    ...
    ```
