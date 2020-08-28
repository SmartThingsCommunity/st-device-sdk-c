#!/usr/bin/env python3

import qrcode
import json
import argparse
import os
from pathlib import Path

__version__ = "1.0.0"
onboardingFile = "onboarding_config.json"
deviceInfoFile = "device_info.json"


def safeOpenJSONFile(file):
    if (not os.path.isfile(file)):
        print("ERROR: file does not exist %s" % (file))
    else:
        try:
            return json.load(open(file))
        except:
            print("ERROR: Unable to parse %s" % (file))
    quit()


def safeReadJSON(key, data, file):
    if not key in data:
        print("ERROR: %s not found in %s" % (key, file))
    elif data[key] is None or data[key] == "":
        print("ERROR: %s value is empty in %s" % (key, file))
    else:
        return data[key]
    quit()


def main():
    parser = argparse.ArgumentParser(
        description="%s v%s - SmartThings Device QR geeration tool" %
        (os.path.basename(__file__), __version__))

    parser.add_argument(
        '--folder',
        type=Path,
        default=os.getcwd(),
        help="Folder containing %s and %s (if not supplied uses current folder)"
        % (onboardingFile, deviceInfoFile))

    args = parser.parse_args()

    file = os.path.join(args.folder, onboardingFile)
    data = safeOpenJSONFile(file)
    safeReadJSON("onboardingConfig", data, file)
    mnid = safeReadJSON("mnId", data["onboardingConfig"], file)
    onboardingId = safeReadJSON("setupId", data["onboardingConfig"], file)

    file = os.path.join(args.folder, deviceInfoFile)
    data = safeOpenJSONFile(file)
    serialNumber = safeReadJSON("serialNumber", data["deviceInfo"], file)

    qrUrl = "https://qr.samsungiots.com/?m=%s&s=%s&r=%s" % (mnid, onboardingId,
                                                            serialNumber)
    print("QR url: " + qrUrl)
    img = qrcode.make(qrUrl)
    img.save(serialNumber + '.png')


if __name__ == "__main__":
    main()