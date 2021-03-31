#!/usr/bin/env python3

import os
import sys
import argparse
import base64
import binascii
import csv
import random
import string

from datetime import datetime
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

import json
from pathlib import Path
import pkgutil
try:
    import qrcode
except ImportError:
    print("-----------------------------NOTICE----------------------------------")
    print("qrcode module failed to import. QR code generation will not execute.")
    print("If you want to make QR code, please install qrcode module first.")
    print("---------------------------------------------------------------------")
    pass

__version__ = "1.4.0"
ROOT_PATH = "output"

onboardingFile = "onboarding_config.json"

def safeOpenJSONFile(file):
    try:
        open(file)
    except FileNotFoundError:
        print("%s is Not Found" % (onboardingFile))
        print("To make QR code, %s downloaded from Developer Workspace is necessary" % (onboardingFile))
        print("Please input --path argument with the path located %s in your computer." % (onboardingFile))
    else:
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

class Ed25519Key():
    def __init__(self, sn):
        if not isinstance(sn, str):
            raise TypeError("SerialNumber is not a string")

        self._sn = sn

    def generate(self):
        # Generate Ed25519 keypair
        seckey = SigningKey.generate()
        pubkey = seckey.verify_key

        self._seckey_hex = seckey.encode()
        self._pubkey_hex = pubkey.encode()

        self._seckey_hex_b64 = base64.b64encode(self._seckey_hex)
        self._pubkey_hex_b64 = base64.b64encode(self._pubkey_hex)

    def get_pubkey_b64(self):
        return self._pubkey_hex_b64

    def get_seckey_b64(self):
        return self._seckey_hex_b64

    def _do_save(self, sub_path, fname, key_hex_b64):
        path = os.path.join(sub_path, fname)

        if os.path.exists(path):
            raise TypeError("WARNING: '%s' is already generated" % path)

        if not os.path.isdir(sub_path):
            os.makedirs(sub_path, exist_ok=True)

        with open(path, "wb") as fp:
            fp.write(key_hex_b64)

    def savetofile(self, sub_path):
        self._do_save(sub_path, "device.seckey.b64", self._seckey_hex_b64)
        self._do_save(sub_path, "device.pubkey.b64", self._pubkey_hex_b64)

    def dump(self):
        print("Dump Ed25519 keypair,")
        print("seckey      :", binascii.hexlify(self._seckey_hex))
        print("pubkey      :", binascii.hexlify(self._pubkey_hex))
        print("seckey(b64) :", self._seckey_hex_b64)
        print("pubkey(b64) :", self._pubkey_hex_b64)

class Batch():
    def __init__(self, time, output):
        if not isinstance(time, str):
            raise TypeError("time is not a string")

        self._time = time
        self._batch_output = output

    def generate_csv(self, sub_path, items):
        if self._batch_output is None:
            batch_file = "DI_Batch_" + self._time + ".csv"
            path = os.path.join(sub_path, batch_file)
        else:
            path = self._batch_output

        if os.path.exists(path):
            raise TypeError("WARNING: '%s' is already registered" % path)

        dir = os.path.dirname(path)

        if os.path.isdir(dir):
            os.makedirs(dir, exist_ok=True)

        with open(path, 'w', newline='') as csvfile:
            fieldnames = ['sn', 'keyType', 'keyCrv', 'pubkey']
            write = csv.DictWriter(csvfile, fieldnames=fieldnames)
            write.writeheader()
            write.writerows(items)

        print("Batch file has been saved: " + path)

class Formatter():
    def __init__(self, sn, pubkey_b64, seckey_b64, firmware_version):
        self._sn = sn
        self._pubkey_b64 = pubkey_b64
        self._seckey_b64 = seckey_b64
        if firmware_version is None:
            self._firmware_version = "firmwareVersion_here"
        else:
            self._firmware_version = firmware_version

    def print_to_console(self):
        print("Use following serial number and public key")
        print("for the identity of your device in Developer Workspace.\n")
        print("Serial Number:")
        print(self._sn)
        print("")
        print("Public Key:")
        print(self._pubkey_b64)
        print("")

    def generate_device_info_json(self, sub_path):
        path = os.path.join(sub_path, "device_info.json")

        with open(path, "w") as device_info:
            device_info.write('{\n')
            device_info.write('\t"deviceInfo": {\n')
            device_info.write('\t\t"firmwareVersion": "' + self._firmware_version + '",\n')
            device_info.write('\t\t"privateKey": "' + self._seckey_b64 + '",\n')
            device_info.write('\t\t"publicKey": "' + self._pubkey_b64 + '",\n')
            device_info.write('\t\t"serialNumber": "' + self._sn + '"\n')
            device_info.write('\t}\n')
            device_info.write('}\n')

class Nv():
    def prepare_repo(self, sub_path, sn):
        csv_file = "stnv.csv"
        image_file = "stnv-" + sn + ".bin"

        repo_dir = os.path.join(sub_path, "stnv")

        if not os.path.isdir(repo_dir):
            os.makedirs(repo_dir, exist_ok=True)

        self._csvfile = os.path.join(repo_dir, csv_file)
        self._imagefile = os.path.join(repo_dir, image_file)
        self._sn = sn

    def generate_csv(self, pubkey_b64, seckey_b64):
        with open(self._csvfile, 'w', newline='') as csvfile:
            fieldnames = ['key', 'type', 'encoding', 'value']
            write = csv.DictWriter(csvfile, fieldnames=fieldnames)
            write.writeheader()
            write.writerow({'key':'stdk', 'type':'namespace'})
            write.writerow({'key':'PKType', 'type':'data', 'encoding':'string', 'value':'ED25519'})
            write.writerow({'key':'PublicKey', 'type':'data', 'encoding':'string', 'value':pubkey_b64.decode('utf-8')})
            write.writerow({'key':'PrivateKey', 'type':'data', 'encoding':'string', 'value':seckey_b64.decode('utf-8')})
            write.writerow({'key':'SerialNum', 'type':'data', 'encoding':'string', 'value':self._sn})

    def generate_image(self):
        esp_tools_dir = os.environ.get('IDF_PATH')
        if (esp_tools_dir is None) or (esp_tools_dir == ""):
            raise TypeError("ERROR: set IDF_PATH for stnv image")
        else:
            nv_gen_tools = os.path.join(esp_tools_dir, "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py")

        cmd = "python " + nv_gen_tools
        cmd += " generate"
        cmd += " " + self._csvfile
        cmd += " " + self._imagefile
        cmd += " 0x4000"
        if "esp32" in esp_tools_dir:
            cmd += " --version 1"
        cmd += " > /dev/null"
        result = os.system(cmd)
        if result != 0:
            raise TypeError("failed to generate NV images")

def get_random(mnid, length):
    random_string = ''
    pool = string.ascii_letters + string.digits
    if mnid is None:
        length += 4
    elif len(mnid) != 4:
        raise TypeError("ERROR: MNID length is not 4")
    else:
        random_string = mnid

    random_string += ''.join(random.choice(pool) for i in range(length))
    return random_string

class Qr():
    def prepare_repo(self, sub_path, args, mnid, onboardingId, sn):
        image_file = "qr-" + sn + ".png"

        if args.input is None:
            self._imagefile = os.path.join(sub_path, image_file)
        else:
            repo_dir = os.path.join(sub_path, sn)
            if not os.path.isdir(repo_dir):
                os.makedirs(repo_dir, exist_ok=True)
            self._imagefile = os.path.join(repo_dir, image_file)

        qrUrl = "https://qr.samsungiots.com/?m=%s&s=%s&r=%s" % (
                mnid, onboardingId, sn)
        self._qrurl = qrUrl

    def generate_image(self):
            imgFP = self._imagefile
            img = qrcode.make(self._qrurl)
            img.save(imgFP)
            print("File:\t%s \nQR url:\t%s" % (imgFP, self._qrurl))

def individual(args, qrcode_imported):
    root_path = ROOT_PATH
    sn = 'STDK' + get_random(args.mnid, 8)
    sub_path = root_path + "_" + sn

    edkey = Ed25519Key(sn)
    edkey.generate()
    edkey.savetofile(sub_path)
    pubkey_b64 = edkey.get_pubkey_b64().decode("utf-8")

    formatter = Formatter(sn, edkey.get_pubkey_b64().decode('utf-8'), edkey.get_seckey_b64().decode('utf-8'), args.firmware)
    formatter.print_to_console()
    formatter.generate_device_info_json(sub_path)

    if args.nv == 'esp':
        # Generate NV image file
        nv = Nv()
        nv.prepare_repo(sub_path, sn)
        nv.generate_csv(edkey.get_pubkey_b64(), edkey.get_seckey_b64())
        nv.generate_image()
    if args.qr is True and qrcode_imported is not None:
        #Generate QRcode imagea
        file = os.path.join(args.path, onboardingFile)
        data = safeOpenJSONFile(file)
        if data is not None:
            safeReadJSON("onboardingConfig", data, file)
            mnid = safeReadJSON("mnId", data["onboardingConfig"], file)
            onboardingId = safeReadJSON("setupId", data["onboardingConfig"], file)
            qr = Qr()
            qr.prepare_repo(sub_path, args, mnid, onboardingId, sn)
            qr.generate_image()

def bulk(args, qrcode_imported):
    root_path = ROOT_PATH + "_bulk"
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_path = os.path.join(root_path, time)
    batch_items = []

    if not os.path.exists(args.input):
        raise TypeError("not found '%s'" % args.input)

    print("Loading " + args.input + "...")

    if args.qr is True and qrcode_imported is not None:
        file = os.path.join(args.path, onboardingFile)
        data = safeOpenJSONFile(file)
        if data is not None:
            safeReadJSON("onboardingConfig", data, file)
            mnid = safeReadJSON("mnId", data["onboardingConfig"], file)
            onboardingId = safeReadJSON("setupId", data["onboardingConfig"], file)

    with open(args.input, newline='') as csvinput:
        reader = csv.DictReader(csvinput)
        for row in reader:
            # Generate csv rows in 'csv_items' for batch csv file
            batch_item = dict()
            sn = row['sn']
            edkey = Ed25519Key(sn)
            edkey.generate()
            edkey.savetofile(os.path.join(sub_path, sn))
            batch_item['sn'] = sn
            batch_item['keyType'] = 'ECPUBKEY'
            batch_item['keyCrv'] = 'ED25519'
            batch_item['pubkey'] = edkey.get_pubkey_b64().decode("utf-8")
            batch_items.append(batch_item)
            #print(csv_item.items())

            if args.nv == 'esp':
                # Generate NV image file
                nv = Nv()
                nv.prepare_repo(os.path.join(sub_path, sn), sn)
                nv.generate_csv(edkey.get_pubkey_b64(), edkey.get_seckey_b64())
                nv.generate_image()

            if args.qr is True and qrcode_imported is not None and data is not None:
                #Generate QRcode image
                qr = Qr()
                qr.prepare_repo(sub_path, args, mnid, onboardingId, sn)
                qr.generate_image()

    batch = Batch(time, args.output)
    batch.generate_csv(sub_path, batch_items)

def version(args):
    print(__version__)

def main():
    parser = argparse.ArgumentParser(description="%s v%s - SmartThings Device SDK keygen tools" %(__file__, __version__))
    parser.add_argument(
        '--mnid',
        help="[I] can set your MNID as prefix of Serial Number")

    parser.add_argument(
        '--firmware',
	metavar='version',
        help="[I] firmware version for device_info.json")

    parser.add_argument(
        '--input',
	metavar='csv',
        help="[C] input csv file that has a list of serial numbers")

    parser.add_argument(
        '--output',
	metavar='csv',
        help="[C] output batch csv file")

    parser.add_argument(
        '--nv',
        choices=['esp'],
        help="generate nv image for choiced chipset")

    parser.add_argument(
        '--qr',
        action='store_true',
        default=False,
        help="generate QR code image. --path is required")

    parser.add_argument(
        '--path',
        default=os.getcwd(),
        help="input the path located %s (Or copy %s to the current folder)"
        % (onboardingFile, onboardingFile))

    args = parser.parse_args()

    qrcode_imported = pkgutil.find_loader('qrcode')

    if args.input is None:
        individual(args, qrcode_imported)
    else:
        bulk(args, qrcode_imported)

if __name__ == "__main__":
    main()
