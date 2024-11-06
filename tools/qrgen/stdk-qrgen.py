#!/usr/bin/env python3

import argparse
import json
import os

import qrcode

__version__ = "1.0.1"
onboardingFile = "onboarding_config.json"
deviceInfoFile = "device_info.json"


def safeOpenJSONFile(file):
    with open(file) as f:
        try:
            return json.load(f)
        except:
            raise TypeError("Unable to parse %s" % (file))


def safeReadJSON(key, data, file):
    if not key in data:
        raise KeyError("%s not found in %s" % (key, file))
    elif data[key] is None or data[key] == "":
        raise ValueError("%s value is empty in %s" % (key, file))
    else:
        return data[key]


def main():
    parser = argparse.ArgumentParser(
        description="%s v%s - SmartThings Device QR geeration tool" %
        (os.path.basename(__file__), __version__))

    parser.add_argument(
        '--folder',
        default=os.getcwd(),
        help="Folder containing %s and %s (if not supplied uses current folder)"
        % (onboardingFile, deviceInfoFile))

    args = parser.parse_args()

    try:
        file = os.path.join(args.folder, onboardingFile)
        data = safeOpenJSONFile(file)
        safeReadJSON("onboardingConfig", data, file)
        mnid = safeReadJSON("mnId", data["onboardingConfig"], file)
        onboardingId = safeReadJSON("setupId", data["onboardingConfig"], file)

        file = os.path.join(args.folder, deviceInfoFile)
        data = safeOpenJSONFile(file)
        serialNumber = safeReadJSON("serialNumber", data["deviceInfo"], file)

        qrUrl = "https://qr.samsungiots.com/?m=%s&s=%s&r=%s" % (
            mnid, onboardingId, serialNumber)
        imgFP = serialNumber + '.png'
        img = qrcode.make(qrUrl)
        img.save(imgFP)
        print("File:\t%s \nQR url:\t%s" % (imgFP, qrUrl))
    except Exception as e:
        print("ERROR: " + str(e))


if __name__ == "__main__":
    main()
