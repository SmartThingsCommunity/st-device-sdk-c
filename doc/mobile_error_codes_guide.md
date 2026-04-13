# Mobile Error Code Guide for STDK Device Developers
- Target: This guide for developers of SmartThings Device SDK (STDK)
- Purpose  
  - When an **Onboarding Error Code** occurs in the SmartThings app  
    → Organized so that STDK device developers can quickly see **what to check first**
- Note: The meaning of each error code describes why it was treated as a failure from the **mobile phone’s point of view**.  
  This document describes what STDK device developers should check for each error code.
- **04-xxx / 08-xxx / 15-xxx / 38-xxx **  
  → **Almost always check device/firmware side first**  
  → Collect and analyze device logs
- **07-xxx**  
  → **Mainly app/contents/permissions**  
  → On the device side, only **ID/model/identifier values + repro conditions**,  
    then report to SmartThings with app logs + screenshots
- **81-xxx / 86-xxx** 
  → **Mainly cloud/network**
  → Check the network available on mobile and device,
    then report to SmartThings with app logs + STDK log

---
## Summary Guide Dedicated to STDK Device Developers
## 1. Error Code Format
- External format: `MAIN(2 digits) - SUB(3 digits)`
  - e.g.) `04-200`, `07-003`, `08-001`, `15-100`
---
## 2. Role Summary by MAIN Code
 MAIN | Meaning                                 | Priority / Responsibility for STDK Device Dev |
------|-----------------------------------------|-----------------------------------------------|
 **04** | Connection (SoftAP / BLE)     | **Very high – wireless/connection logic**     |
 **07** | Mobile internal status / Contents     | **App/contents-centric issue** → Device: check ID/model/repro info, then report |
 **08** | BLE (Bond/MTU/GATT/Property)         | **Very high – BLE stack/provisioning**        |
 **15** | Registration (Wi-Fi / Cloud)         | **Very high – AP/Cloud connection**           |
 **38** | Device SDK (MQTT D2D)       | **Core STDK – SDK handler/key/scan**          |
 **81** | Identity       | **Cloud – Device authentication**          |
 **86** | Device backend service       | **Cloud – Device registration**          |
---
## 3. MAIN 04 – Connection (SoftAP / BLE)
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-----------------------------------------------------|
 **04-100** | Connection between mobile and Wifi device failed (Soft AP connection fail) | Whether SoftAP interface is up, SSID/security/channel, DHCP behavior, SoftAP on-time (timeout), concurrent connection limit/reset behavior |
 **04-110** | Home AP connection fail | When trying to connect to Home AP in STA mode: attempt/result, cause of WPA handshake failure, 2.4 GHz support, handling of hidden SSID/special characters, AP password parsing |
 **04-150** | Disconnect with Wifi device unexpectedly | During SoftAP / local HTTP / provisioning: whether device reset/watchdog occurred, Wi-Fi driver crash, power instability, lack of keepalive |
 **04-151** | Disconnect with Ble device unexpectedly | BLE disconnect reason code, last GATT operation and processing time, bonding state, whether device entered sleep during onboarding, memory/stack shortage or reset |
 **04-160** | Disconnect SoftAP by iOS System interrupt | SoftAP disconnected by iOS (e.g. OS popup) → On device side, check SoftAP re-advertising/recovery strategy (auto restart, retry after timeout) |
 **04-161** | SoftAP connection unstable | SoftAP link is up but D2D commands not working → Check HTTP/protocol server thread under SoftAP, session/timeout, watchdog logs |
 **04-200** | BLE GATT connection fail | BLE advertising state (on/off), connection parameters, GATT DB definition, pairing/bond issues, whether it disconnects immediately after connection |
 **04-202** | Device not found with previously detected information | Consistency of advertising payload (identifier) between discovery time and connection time, advertising interval, discovery-mode entry/hold time, button/LED UX |
 **04-203** | Ble Gatt connection fail (mismatch pairing information between Thing and Mobile) | After Thing (device) reset, bond info not properly cleared causing pairing mismatch → Check bond wipe logic on factory reset/ownership reset |
---
## 4. MAIN 07 – Mobile internal status / Contents  
> Most cases are **app/contents on cloud** issues.  
> Instead of solving by device firmware, it is important to **collect identifiers/model/repro info/app logs** and report.

- Common device-side information to check
  - Whether `modelCode` exposed by device, QR/claim payload, `mnid/setupid` mapping values are **identical to spec/registration info**
  - Whether it is **reproducible repeatedly on the same account and same device**

 Code | Description | Meaning | What STDK Device Developers Should Check |
------|------------------------|-------------------|-----------------------|
 **07-001** | Not enough internal storage to download setup contents | Phone storage is insufficient | Guide user to free storage on the device (phone) and retry |
 **07-003** | No Contents data of requested mnid and setupid is registered in Server | No contents on server for the `mnid/setupid` combination | Check `mnid/setupid` values used by device → report with app logs and these values |
 **07-008** | No matching catalog Apps or Product Data with mnid/setupid or modelCode | Catalog/Product data does not match `mnid/setupid/modelCode` | Check whether device IDs such as model code, QR payload match spec → report with all 3 values (`mnid/setupid/modelCode`) |
 **07-999** | internal state error | SmartThings app internal error | **Must collect app logs and report to ST** (cannot be solved by device changes) |
---
## 5. MAIN 08 – BLE (Bond / MTU / GATT / Property)
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-------------------------------------------|
 **08-001** | BLE Bonding failure | Logs for pairing start/success/failure steps, IO capability, bond store/delete logic, max number of bonds, whether storage area is full/corrupted |
 **08-002** | BLE MTU Request failure | Whether MTU negotiation is supported, requested/allowed MTU size, memory shortage or crash at specific MTU |
 **08-003** | BLE Service discovery failure | GATT service/characteristic UUID/permissions (READ/WRITE/INDICATE), whether disconnect occurs during service discovery |
 **08-202** | device property read failure after onboarding | GATT read failure after registration – sleep, reconnection policy, service availability, connection stability |
 **08-203** | device property write failure after onboarding | Write failure in operational state – error code/return handling, state rollback, concurrent access |
---
## 6. MAIN 15 – Registration (Wi-Fi / Cloud)
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-------------------------------------------|
 **15-100** | Enrollee fail to connection access point (Device can’t connect to AP) | SSID/security/WPA handshake result, 2.4 GHz support, DHCP success/failure, captive portal environment, password parsing issues (UTF-8/special characters) |
 **15-200** | Device sign up error to cloud | Logs of first sign-up API call, TLS handshake (time/certificate issues), registration token/claim handling result, HTTP status code |
 **15-201** | Device sign up error to cloud with user inputted AP information | When using AP info input by user – whether AP connection succeeded, status of sign-up request/response |
 **15-300** | Device sign in error to cloud (health online check fail) | Whether MQTT/HTTPS connect succeeds, keepalive, reconnect/backoff, health-ping response status |
 **15-500** | Cloud connection status check failure after Wi-Fi update | Whether device reports “resource published / online / capability ready” state to cloud in time, MQTT `wifiInformation ` capability |
---
## 7. MAIN 38 – Device SDK (MQTT D2D)
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-------------------------------------------|
 **38-001** | Get property from device fail | Whether SDK `GET` handler properly receives request/creates response/sends it, value range/format validation, exceptions/timeouts |
 **38-002** | Set property to device fail | Input value validation, state-apply logic, error-code return/rollback on failure, idempotency |
 **38-531** | Device can’t scan nearby Wi-Fi | Wi-Fi scan API call/response, conflicts when SoftAP/STA/BLE are used simultaneously, driver error code when result is zero APs |
---
## 8. MAIN 81 - Identity
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-------------------------------------------|
 **81-001** | No device data in server or no matching data in response | Check if the serial number matching the device is registered in Developer Console. If the issue persists, change the device's serial number, register it in the Developer Console, and verify again. |
---
## 9. MAIN 86 – Device backend service
 Code  | Description | What STDK Device Developers Should Check |
-------|------------------------|-------------------------------------------|
 **86-001** | Failed to get Broker url | Check the network connected with the mobile is available |
 **86-002** | Failed to get device id using claim Id | Check the network status on mobile and device and the availability of port 8883/8884 (MQTT). Avoid guest network / VLAN / enterprise 802.1X networks. If the issue persists, reset device and retry |
