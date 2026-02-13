#!/usr/bin/env python3

import requests
import json
import uuid
import re
import ssl
import time
import base64
import threading
from paho.mqtt import client as mqtt_client
from packaging.version import Version, parse
from cryptography.hazmat.primitives.asymmetric import ed25519
from urllib.parse import urlparse

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
        "greatgate" : "https://greatgate-http.api.smartthings.com",
        }

user_PAT= ""
IOT_SUB_TOPIC_REGISTRATION_NOTIFY = "/v1/registrations/notification/"
IOT_PUB_TOPIC_REGISTRATION = "/v1/registrations"
mqtt_sign_up_connection_request_status = "CONNECT_FAIL"
device_id = None
gg_server_url=""

serialhash = str(uuid.uuid4())

lookup_id = str(uuid.uuid4())

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
        print("Payload : " + json.dumps(payload))
        print(ST_api_server)
        response = requests.post(smartthings_api_url[ST_api_server] + "/" + resource, headers=ST_API_headers, json=payload)
    else:
        print("Not supporting request operation {" + operation + "}")
        return
    if not response.ok:
        print("Failed to request. " + response.reason)
        print(response.text)
        return
    return response

# --- Helper function ---
def to_bytes(s):
    return s.encode('utf-8')

def timer_expired():
    print("60 seconds are up! Timeout")

def deviceProvisioningAPI():
    reg_msg = {
            "serialHash" : serialhash,
            "provisioningTs" : int(time.time()*1000),
            "lookupId" : lookup_id,
            "locationId" : chosen_location["locationId"],
            "roomId" : chosen_room["roomId"]
    }

    print(f"{bcolors.OKCYAN}Sending provisioning request to greatgate 'devices/provisioning/' API...{bcolors.ENDC}")
    provionDataResponse = requestSmartThingsAPI("POST", "devices/provisioning/", ST_api_server="greatgate", payload=reg_msg)
    if not provionDataResponse:
        print(f"{bcolors.FAIL}Provisioning request failed.{bcolors.ENDC}")
        return 0

    print(f"{bcolors.OKGREEN}Provisioning api response: {provionDataResponse.json()}{bcolors.ENDC}")
    return 1

def subscribe_topic(client, topic_name, client_ID):
    IOT_SUB_TOPIC = f"{topic_name}{client_ID}"
    print(f"Subscribing to topic: '{IOT_SUB_TOPIC}'")
    res, mid = client.subscribe(IOT_SUB_TOPIC)
    if res == mqtt_client.MQTT_ERR_SUCCESS:
        print(f"Subscription successful with Message ID: {mid}")
    else:
        print(f"Failed to subscribe, return code {res}\n")

def publish_topic(client):
    # Publish a message to the registration topic
    payload = {
        "lookupId" : lookup_id,
        "serialHash" : serialhash,
        "mnId" : given_mnId,
        "vid": given_vid,
        "deviceTypeId": given_deviceTypeId,
        "deviceIntegrationProfileKey" : {
            "id" : dip_id,
            "majorVersion" : dip_version.major,
            "minorVersion" : dip_version.minor
        },
            "type": "MQTT"
    }
    if label: # optional
        payload["label"] = label

    try:
        message = json.dumps(payload)
        result, mid = client.publish(IOT_PUB_TOPIC_REGISTRATION, message, qos=1)
        print(f"Published registration to '{IOT_PUB_TOPIC_REGISTRATION}': {message}")
    except Exception as e:
        print(f"Publish error: {e}")

def on_message(client, userdata, msg):
    global mqtt_sign_up_connection_request_status
    global device_id
    print(f"\n{bcolors.OKCYAN}Message received on topic: '{msg.topic}'{bcolors.ENDC}")
    try:
        payload_str = msg.payload.decode("utf-8")
        cleaned_payload_str = payload_str.rstrip('\x00')
        payload_json = json.loads(cleaned_payload_str)
        print(f"Cleaned Payload: {cleaned_payload_str}")

        if 'deviceId' in payload_json:
            device_id = payload_json['deviceId']
            print(f"{bcolors.OKGREEN}Successfully registered device!")
            print(f"  Device ID: {device_id}{bcolors.ENDC}")

        elif 'event' in payload_json:
            event = payload_json['event']
            if event == "connect.success":
                print(f"{bcolors.OKGREEN}Event: connect.success: {event}{bcolors.ENDC}")
                mqtt_sign_up_connection_request_status = event
            elif event == "connect.fail":
                print(f"{bcolors.FAIL}Event: connect.fail: {event}{bcolors.ENDC}")
                mqtt_sign_up_connection_request_status = event
            elif event == "connect.timeout":
                print(f"{bcolors.FAIL}Event: connect.timeout: {event}{bcolors.ENDC}")
                mqtt_sign_up_connection_request_status = event

        else:
            print(f"{bcolors.WARNING}Received a message, but it's not a recognized registration response.{bcolors.ENDC}")
            print(f" Full Payload: {json.dumps(payload_json, indent=2)}")

    except json.JSONDecodeError:
        print(f"{bcolors.FAIL}Error: Failed to decode message payload as JSON.{bcolors.ENDC}")
        print(f"  Raw Payload (bytes): {msg.payload}")
        print(f"  Payload Length: {len(msg.payload)}")
        if msg.payload:
            print(f"  Raw Payload (decoded as UTF-8, ignoring errors): {msg.payload.decode('utf-8', errors='ignore')}")
            print(f"  Raw Payload (Hex): {msg.payload.hex()}")
        else:
            print("  Payload is empty.")
    except Exception as e:
        print(f"{bcolors.FAIL}An error occurred while processing the message: {e}{bcolors.ENDC}")
    print("-" * 20)


def connect_mqtt_broker(client_ID: str, jwt_token: str, timer):
    def on_connect(client, userdata, flags, rc, properties=None):
        print(f"Connection returned with result code {rc}")
        if rc == 0:
            print(f"{bcolors.OKGREEN}Connected to MQTT Broker successfully!{bcolors.ENDC}")

            # Subscribe to the registration notification topic
            subscribe_topic(client, IOT_SUB_TOPIC_REGISTRATION_NOTIFY, client_ID)

        else:
            print(f"{bcolors.FAIL}Failed to connect, return code {rc}{bcolors.ENDC}")
            # Common MQTT return codes:
            # 1: Connection refused - incorrect protocol version
            # 2: Connection refused - invalid client identifier
            # 3: Connection refused - server unavailable
            # 4: Connection refused - bad username or password
            # 5: Connection refused - not authorised
            if rc == 4 or rc == 5:
                print(f"{bcolors.FAIL}Error: Bad username/password or not authorized. Please check your PAT token.{bcolors.ENDC}")

    client = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, client_ID)
    client.on_connect = on_connect
    client.on_message = on_message # Assign the message callbaack

    # Configure TLS
    try:
        client.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLSv1_2, ciphers=None)
    except FileNotFoundError:
        print(f"{bcolors.WARNING}Warning: System CA certificates not found. TLS might fail.{bcolors.ENDC}")
        print("Ensure your system has CA certificates installed (e.g., ca-certificates package).")

        return None

    # Set username and password for MQTT
    # For SmartThings Mqtt connect, the username is often the serialNumber
    # and the password is the JWT Token.
    print(f"Attempting MQTT connection with username: '{client_ID}' and provided JWT token.")
    client.username_pw_set(username=client_ID, password=jwt_token)

    global gg_server_url
    response = requestSmartThingsAPI("Get", "mqtt/broker/" + chosen_location["locationId"], ST_api_server="greatgate")
    if response:
        gg_server_url = urlparse(response.json()["url"]).hostname
    else:
        print(f"{bcolors.FAIL}Failed to get broekr url{bcolors.ENDC}")
        return None

    broker_address = gg_server_url
    broker_port = 8883
    keepalive = 120

    print(f"Connecting to MQTT broker at {broker_address}:{broker_port}...")
    try:
        client.connect(broker_address, broker_port, keepalive)
    except (ConnectionRefusedError, OSError) as e:
        print(f"{bcolors.FAIL}Failed to connect to broker: {e}{bcolors.ENDC}")
        print("Check network connectivity and broker address/port.")
        return None

    # Start a background thread to handle the network loop
    client.loop_start()

    timer.start()
    while timer.is_alive():
        print(f"Waiting for connect.success event...: {mqtt_sign_up_connection_request_status}")
        time.sleep(1)
        if mqtt_sign_up_connection_request_status == "connect.success":
            break

    if mqtt_sign_up_connection_request_status == "connect.success":
        print(f"{bcolors.OKGREEN}Received connect.success event. Proceeding with registration.{bcolors.ENDC}")
        publish_topic(client)
    else:
        print(f"{bcolors.FAIL}Did not receive connect.success event within timeout period. Exiting.{bcolors.ENDC}")

    return client

print("")
print("This tool is provided to register a device manually on SmartThings platform.")
print("Before proceeding, you need to generate your PAT token with proper scope and register a device profile and a device info on DevWS.")
print("Please refer Getting Started document for more details.")
print("")

# 1. Get user PAT token
user_PAT = input(bcolors.BOLD + "1. Enter Your PAT(Personal Access Token)" + bcolors.ENDC + "\n(For more information, please visit https://developer.smartthings.com/docs/getting-started/authorization-and-permissions. The PAT should include devices, deviceprofiles, locations scopes.)\n: ")
print("")

if not user_PAT:
    print(f"{bcolors.FAIL}PAT token is required. Exiting.{bcolors.ENDC}")
    exit(1)

# 2. Get user choice for Location & Room to install device.
print(f"{bcolors.BOLD}2 - 1. Choose location to register a device on your SmartThings App : {bcolors.ENDC}")
response = requestSmartThingsAPI("Get", "locations")
if not response:
    exit(1)
location_lists = response.json()["items"]
if not location_lists:
    print(f"{bcolors.FAIL}No locations found in your SmartThings account. Please create a location first.{bcolors.ENDC}")
    exit(1)

chosen_location = location_lists[chooseFromList([i["name"] for i in location_lists]) - 1]
print(f"  Selected Location: {chosen_location['name']} (ID: {chosen_location['locationId']})")
print("")

print(f"{bcolors.BOLD}2 - 2. Choose room to register a device on your SmartThings App : {bcolors.ENDC}")
response = requestSmartThingsAPI("Get", "locations/" + chosen_location["locationId"] + "/rooms")
if not response:
    exit(1)
room_lists = response.json()["items"]
if not room_lists:
    print(f"{bcolors.WARNING}No rooms found for location '{chosen_location['name']}'. The device will be registered to the location itself.{bcolors.ENDC}")
    # Create a default room structure if no rooms exist, as roomId might be required by some API calls.
    chosen_room = {"roomId": chosen_location["locationId"], "name": chosen_location["name"]} # Use locationId as a fallback
else:
    chosen_room = room_lists[chooseFromList([i["name"] for i in room_lists]) - 1]
    print(f"  Selected Room: {chosen_room['name']} (ID: {chosen_room['roomId']})")
print("")

# 3. Get device profile information.
print(bcolors.BOLD + "3. Get installing device profile information.(Please refer onboarding_config.json)" + bcolors.ENDC)
given_mnId = input(bcolors.BOLD + "3 - 1. Enter mnId for the device: " + bcolors.ENDC)
given_vid = input(bcolors.BOLD + "3 - 2. Enter vid for the device: " + bcolors.ENDC)
given_deviceTypeId = input(bcolors.BOLD + "3 - 3. Enter deviceTypeId for the device: " + bcolors.ENDC)
dip_id = input(bcolors.BOLD + "3 - 4. Enter deviceIntegrationProfileKey id for the device: " + bcolors.ENDC)
dip_version = input(bcolors.BOLD + "3 - 5. Enter deviceIntegrationProfileKey Version {major.minor}: " + bcolors.ENDC)
dip_version = parse(dip_version)
print("")

# 4. Get device identity infor for the device.
print(bcolors.BOLD + "4. Get installing device identity information.(Please refer device_info.json)" + bcolors.ENDC)
serial = input(bcolors.BOLD + "4 - 1. Enter serial number for the device: " + bcolors.ENDC)
serial_number = serial
private_key = input(bcolors.BOLD + "4 - 2. Enter private key for the device: " + bcolors.ENDC)
print("")

# 5. (Optional) Get device label to show on SmartThings App from user.
label = input(bcolors.BOLD + "5. (Optional) Enter device label to show on SmartThings App : " + bcolors.ENDC)
print("")

print(f"{bcolors.OKBLUE}--- Summary ---{bcolors.ENDC}")
print(f"Location : {chosen_location['name']} ({chosen_location['locationId']})")
print(f"Room     : {chosen_room['name']} ({chosen_room['roomId']})")
print(f"Device Profile ID/Version : {dip_id}/{str(dip_version.major)}.{str(dip_version.minor)}")
print(f"Device Serial : {serial}")
print(f"Device mnID : {given_mnId}")
print(f"Device vID : {given_vid}")
print(f"Device deviceTypeId : {given_deviceTypeId}")
if label:
    print(f"Device Label : {label}")
print("-" * 20)
ready = input(bcolors.BOLD + "Are you proceeding registration with above data(yes)? " + bcolors.ENDC)
print("")

if not (ready == "Yes" or ready == "yes"):
    print(bcolors.BOLD + "Cancel!" + bcolors.ENDC)
    exit(1)

# --- JWT token construction ---
header_data = {"alg": "EdDSA", "kty": "OKP", "typ": "JWT", "crv": "Ed25519", "ver": "0.0.1", "kid": serial_number}

payload_data = {
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600, # 1 hour expiry
    "sub": serial_number,
    "mnId": given_mnId,
    "dipId": dip_id,
    "jti": str(uuid.uuid4())
}

header_json = json.dumps(header_data, separators=(',', ':'))
payload_json = json.dumps(payload_data, separators=(',', ':'))

header_b64url = base64.urlsafe_b64encode(to_bytes(header_json)).decode('utf-8').rstrip('=')
payload_b64url = base64.urlsafe_b64encode(to_bytes(payload_json)).decode('utf-8').rstrip('=')

signing_input = f"{header_b64url}.{payload_b64url}"

signing_input_bytes = to_bytes(signing_input)

private_key_b64 = private_key
decoded_private_key_bytes = base64.urlsafe_b64decode(private_key_b64)
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(decoded_private_key_bytes)
# Sign the data
signature_bytes = private_key.sign(signing_input_bytes)

encoded_signature = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')

encoded_jwt = f"{signing_input}.{encoded_signature}"
# --- End JWT Construction ---

# --- send device provisioning request to greatgate ---
deviceProvisioningAPI()

# create timer for 60 seconds timeout for connect success event. If not received, exit.
timer = threading.Timer(60, timer_expired)

# call connect mqtt broker with jwt token and serial number
client = connect_mqtt_broker(serial, encoded_jwt, timer)

while device_id == None:
    time.sleep(1)

if device_id != None:
    print("")
    print("/////// Registration Result ////////")
    print("Device ID : " + device_id)
    print("mnId : " + given_mnId)
    for i in server_type_url:
        if re.search(server_type_url[i], gg_server_url):
            print("Server Type : " + i)
            break
    print("////////////////////////////////////")

timer.cancel()
exit(0)
