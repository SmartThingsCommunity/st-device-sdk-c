#!/usr/bin/env python3

import requests
import json
import uuid
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

server_type_url = {"AP_NORTH_EAST2" : "mqtt-regional-apnortheast2.api.smartthings.com",
        "US_EAST1" : "mqtt-regional-useast1.api.smartthings.com",
        "EU_WEST1" : "mqtt-regional-euwest1.api.smartthings.com"}

smartthings_api_url = {"smartthings" : "https://api.smartthings.com",
        "dossier" : "https://dossier-global.api.smartthings.com",
        "greatgate" : "https://greatgate-http.api.smartthings.com",
        }
user_PAT= ""

def chooseFromList(candidates):
    for i in range(len(candidates)):
        print(f"{i+1}. {candidates[i]}")
    while True:
        try:
            chosen = int(input(f"{bcolors.BOLD}Choose from lists (1 ~ {len(candidates)}) : {bcolors.ENDC}"))
        except ValueError:
            print('That\'s not a number!')
        else:
            if 1 <= chosen <= len(candidates):
                break
            else:
                print('Out of range. Try again')
    return chosen

def requestSmartThingsAPI(operation, resource, ST_api_server="smartthings", payload=None):
    ST_API_headers = {"Authorization": "Bearer " + user_PAT}
    if operation == "Get":
        response = requests.get(smartthings_api_url[ST_api_server] + "/" + resource, headers=ST_API_headers)
    elif operation == "POST":
        response = requests.post(smartthings_api_url[ST_api_server] + "/" + resource, headers=ST_API_headers, json=payload)
    else:
        print("Not supporting request operation {" + operation + "}")
        return
    if not response.ok:
        print("Failed to request. " + response.reason)
        print(response.text)
        return
    return response

print("")
print("This tool is provided to register a device manually on SmartThings platform.")
print("Before proceeding, you need to generate your PAT token with proper scope and register a device profile and a device info on DevWS.")
print("Please refer Getting Started document for more details.")
print("")

# 1. Get user PAT token
user_PAT = input(bcolors.BOLD + "1. Enter Your PAT(Personal Access Token)" + bcolors.ENDC + "\n(For more information, please visit https://developer.smartthings.com/docs/getting-started/authorization-and-permissions. The PAT should include devices, deviceprofiles, locations scopes.)\n: ")
print("")

# 2. Get user choice for Location & Room to install device.
response = requestSmartThingsAPI("Get", "locations")
if not response:
    exit(1)
location_lists = response.json()["items"]
print(bcolors.BOLD + "2 - 1. Choose location to register a device on your SmartThings App : " + bcolors.ENDC)
chosen_location = location_lists[chooseFromList([i["name"] for i in location_lists]) - 1]
print("")

response = requestSmartThingsAPI("Get", "locations/" + chosen_location["locationId"] + "/rooms")
if not response:
    exit(1)
room_lists = response.json()["items"]
print(bcolors.BOLD + "2 -2. Choose room to register a device on your SmartThings App : " + bcolors.ENDC)
chosen_room = room_lists[chooseFromList([i["name"] for i in room_lists]) - 1]
print("")

# 3. Get user choice for device profile of device.
response = requestSmartThingsAPI("Get", "deviceintegrationprofiles", ST_api_server="dossier")
if not response:
    exit(1)
dip_lists = response.json()["items"]
print(bcolors.BOLD + "3. Choose device profile of the device : " + bcolors.ENDC)
chosen_dip = dip_lists[chooseFromList([i["name"] for i in dip_lists]) - 1]
response = requestSmartThingsAPI("Get", "deviceprofiles/" + chosen_dip["deviceProfileId"])
if not response:
    exit(1)
chosen_dp = response.json()
print("")

# 4. Get user choice for the device to register.
serial = input(bcolors.BOLD + "4. Enter serial number for the device: " + bcolors.ENDC)
print("")
# 5. (Optional) Get device label to show on SmartThings App from user.
label = input(bcolors.BOLD + "5. (Optional) Enter device label to show on SmartThings App : " + bcolors.ENDC)
print("")

print("Location : " + chosen_location["name"])
print("Room : " + chosen_room["name"])
print("Device Profile : " + chosen_dip["name"])
print("Device Serial : " + serial)
if label:
    print("(Option) Device Label : " + label)
ready = input(bcolors.BOLD + "Are you proceeding registration with above data(yes)? " + bcolors.ENDC)
print("")

if ready == "Yes" or ready == "yes":
    reg_msg = {
            "lookupId" : str(uuid.uuid4()),
            "serialNumber" : serial,
            "deviceTypeId" : chosen_dp["metadata"]["deviceTypeId"],
            "mnId" : chosen_dp["metadata"]["mnId"],
            "locationId" : chosen_location["locationId"],
            "roomId" : chosen_room["roomId"],
            "type" : "MQTT",
            "deviceIntegrationProfileKey" : chosen_dip["key"]
            }
    if label:
        reg_msg["label"] = label
    response = requestSmartThingsAPI("POST", "devices", ST_api_server="greatgate", payload=reg_msg)
    if not response:
        exit(1)
    print("/////// Registration Result ////////")
    print("Device ID : " + response.json()["deviceId"])
    print("mnId : " + response.json()["metadata"]["mnId"])
    response = requestSmartThingsAPI("Get", "mqtt/broker/" + chosen_location["locationId"], ST_api_server="greatgate")
    if response:
        for i in server_type_url:
            if re.search(server_type_url[i], response.json()["url"]):
                print("Server Type : " + i)
                break
    print("////////////////////////////////////")
else:
    print(bcolors.BOLD + "Cancel!" + bcolors.ENDC)
print("")
