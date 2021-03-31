# HISTORY

## 1.5.11 :  Changes until v1.5.11

New Improvements or features:

 - Create new attribute extended option API : st_cap_create_attr_with_option() & struct iot_cap_attr_option_t
 - Added new net interface to use external private key for X509 supporting
 - Added external private callback & new security key type for X509 supporting

Enhancements or amendments:

 - Change MISC NV storing workflow by the best effort
 - Upgrade QR code generating tool for user-friendly

Bug fixed:

 - port/os/posix : Fixed missing mem-free at iot_mutex_destory case
 - port/os/tizenrt : Added mem-free routine for mutex handling & thread handling case

## 1.5.9 :  Changes until v1.5.9

Enhancements or amendments:

 - Update deps/mbedtls version to mbedtls-2.16.0
 - Added iot_bsp_wifi_init() related error-handling codes for st_conn_init()

## 1.5.7 :  Changes until v1.5.7

Enhancements or amendments:

 - Check MQTT connection status before send event
 - Check malloc failure before using it for POSIX
 - Change accept-socket close condition
 - Update event bits size for mico os queue

Bug fixed:

 - Fix socket leak issue during easysetup process

## 1.5.5 :  Changes until v1.5.5

New Improvements or features:

 - Update STDK D2D protocol (v1.1.0) : to support the wifi scanlist refresh during D2D

Enhancements or amendments:

 - Added to check NULL for malloc for the posix os porting layer

## 1.5.3 :  Changes until v1.5.3

New Improvements or features:

 - Add new functions
  * iot_os_thread_get_current_handle() : to check current thread handle for iot_conn_start/start_ex/cleanup
  * st_cap_create_attr_with_id() : to support 'commandId' added attribute creating

Enhancements or amendments:

 - Update & change easysetup module
  * use macro for end-of-http-heaer & HTTP_CONN_H handle as pointer type, declare internal functions as static
  * replace 'es_http_init()', add more abstraction for receiving http packet for httpd
 - Push attributes evnets directly in MQTT queue
  * remove all unused codes related to pub_queue handling in iot-core
 - Change 'wifi bssid' value saving to NV mechanism
 - Adjust delay timing for easysetup/httpd complete
 - Change mqtt disconnection timing to prevent unwanted self-reconnecting
 - Update & modify TCs for iot_easysetup_http.c, iot_capability.c, iot_dump_log.c
 - Update parameter for nvs_partition_gen.py
 - Update & change logfile module
  * modify argument of iot_os_eventgroup_wait_bits & move declation code to inside of switch statement
 - Return FS_NOT_FOUND when the bsp-layer returns FS_NO_FILE in security-layer
  * update doxygen to have IOT_ERROR_FS_NO_FILE return value for bsp-layer
 - Added some JSON/CBOR encoding codes to set OS information

Bug fixed:

 - Update some static analysis related issues
  * add Null checking condition
  * use 'memcpy' instead of 'strcpy'
  * fix wrong print error cases & add type casting on log printing
  * fix prevent for division by zero case in security module
  * fix uninitialized variable usage in OS/POSIX case
 - Fix some potential memory leak cases on easysetup module
  * fix wrong buffer length calculation in easysetup
  * fix iot_security_cipher_init/deinit() related memory leak cases
  * remove encrypt_buf's outside allcation to prevent memory leak
  * fix cloud data proving error case

## 1.4.4 :  Changes until v1.4.4

New Improvements or features:

 - Add qr-code generator for individual and bulk

Enhancements or amendments:

 - Support JSON Array type agument for command-event handling
 - Add & Update wifi bssid information handling & saving routine
  * Add 'read_len' parameter to update length of the actual read data on iot_nv_data layer
  * Add string type member variable for mac address in struct iot_wifi_prov_data
 - Update es_msg_parser for post message handling, to have more stability
 - Add & update TCs : TC_FUNC_iot_easysetup_http_parser.c, es_msg_parser(), _es_wifiprovisioninginfo_handler()
 - Change st_info_get() usage for IOT_INFO_TYPE_IOT_PROVISIONED
  * Support its calling on the user-cb condition
  * Add new internal iot_nv_prov_data_exist() function
 - Modify docs : remove STDK_APIs.pdf, add hyper link in APIs.md
 - Add invalidate chunk variable checking on iot_MQTT read, write functions to avoid reuse it
 - Update Static Code Analysis tool checked items
  * Use safety 'snprintf' func. instead of 'sprintf'
  * Modify & remove unreachable & meaningless condition check codes
  * Prevent buffer overflow vulnerability case
  * Prevent 'copying string without null termination' case
  * Prevent memory-leak & add null checking for some exceptional cases

Bug fixed:

 - Remove unused variable, goto label and deprecated header including to prevent build-warning

## 1.4.2 :  Changes until v1.4.2

New Improvements or features:

 - Add protocol version to distinguish each protocol Easysetup process, Server connection & Developer Workspace
  * STDK_D2D_PROTOCOL_VERSION : 1.0.0 (for Easysetup process)
  * STDK_D2S_PROTOCOL_VERSION : 1.0.0  (for Server connection)
  * STDK_DWS_PROTOCOL_VERSION : 1.0.0 (for Developer Workspace)
 - Add QR generation tools : stdk-qrgen.py
 - Add new internal API to change iot-state timeout value : iot_state_timeout_change()

Enhancements or amendments:

 - Remove unreachable or unused codes in iot_api.c & stdk-qrgen.py
 - Update iot_capability TC & iot_noti_sub_cb_rate_limit_reached_SUCCESS()
 - Update capability helper files for fanOscillationMode, mediaPlayback and ovenOperationState
 - Docs & internal comments update

Bug fixed:

 - Fix memleak on iot_security_base64_decode_urlsafe()

## 1.4.0 :  Changes until v1.4.0

New Improvements or features:

 - Supporting ESP32S2 chip BSP : Added new port-layer files for ESP32S2
 - Support EMW3080 chipset from MXCHIP : Added new port-layer files for EMW3080

Enhancements or amendments:

 - Add new internal _iot_command_peek() func. to prevent unwnated interference
 - Add & update TC for
  * TC_STATIC_iot_mqtt_registration_client_callback_SUCCESS()
  * TC_STATIC_iot_parse_sequence_num_SUCCESS/FAILURE()
  * TC_st_conn_ownership_confirm_SUCCESS()
  * Some TC naming convention
 - Logging enhancements
  * Add 'log_time' member into struct iot_dump_state
  * Add mqtt connection success/try counts flags
  * Change some general case log from WARN to DEBUG
 - Add DEPRECATED indicator for deprecated functions in iot_capability
 - Add 'rate_limit_timeout' for delayed connection when the server send 'RATE_LIMIT' event
 - Delete unused global variable & functions

Bug fixed:

 - Fix comapatibility issue with AP which configured to 11n only on ESP8266
 - Fix stdk-keygen.py tool for nv parameter handling

## 1.3.6 :  Changes until v1.3.6

New Improvements or features:

 - Support to use predefined config to cmake build
 - Adding a firmwareUpdate helper file
 - Add ST_CAP_CREATE_ATTR_xxx macros to help creating attr events
 - Implement notifying send fail event to app.

Enhancements or amendments:

 - Refactoring internal _iot_parse_noti_data function to make it straight
 - Add & update TC for
  * TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_SCAN
  * TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_OFF
  * TC_STATIC_esp_wifiscaninfo_handler_success
  * __wrap_iot_bsp_wifi_set_mode mock
 - Change d2d time info to be optional supporting
 - Refine fs and system codes for emw3166
  * Refine codes for build warning
  * Do not stop sntp in time_synced_cb to avoid crash issue
 - Change event sequence number external variable to st context's variable
 - Merge the same error handling code to reduce duplication of code iot_os_util_posix.c

## 1.3.3 :  Changes until v1.3.3

New Improvements or features:

 - Change server's root certificate to increase the validity until Jan 15 12:00:00 2038 GMT
 - Change keygen-tool from linux based binary to python based source-code
  * For detailed information, please refer to tools/keygen/READ.md
 - Introduce new user-level APIs to control iot-core
  * st_conn_start_ex() : To start st_conn_start() at the specific points. It supports only IOT_STATUS_PROVISIONING & IOT_STATUS_CONNECTING cases
  * st_info_get() : To get iot-core's information. There are two types of information IOT_INFO_TYPE_IOT_STATUS_AND_STAT & IOT_INFO_TYPE_IOT_PROVISIONED
 - Update Web-Token making APIs for server side DI V2 interface
 - Support EMW3166 chipset from MXCHIP
 - Change st_conn_cleanup() API usage by block & sync mechanism
 - Update self-registration process for DIP updating
 - Implement some json2cbor transfer handling interanl function.

Enhancements or amendments:

 - Replace & modify iot_create_all_log_dump with st_create_log_dump
 - Increase confirm timeout from 10s to 100s
 - Optimize the code to reduce the number of computations of length
 - Call thread yield to avoid MQTT ack pending busy waiting loop
 - Change IOT_USR_INTERACT_BIT_XX events-bit usage & remove resource cleanup routine on WAIT_USR_INTERACT()
 - Adjust easysetup resource deinit & free sequence to prevent unwanted disconnection event it 'es_http' task
 - Add inline dummy functions : iot_log_read_flash()/iot_log_write_flash()/iot_log_erase_sector()
 - Add internal ctx validation checking routine in iot_main.c
 - Add forcely JUSTWORKS confirmation bit adding logic to skip user-confirmation during D2D process
 - Add optional device_info values into registration payload : firmware_version, model_number, marketing_name, manufacturer_name/code, os_name/version and stdk_version
 - Skip error check for second wifi scan mode requesting : The second wifi scan mode supporting is optional

Bug fixed:

 - Change PROVISIONING/DONE iot_status reporting timing to fix PROVISIONING/FAIL reporting after PROVISIONING/DONE
 - Add iot_cmd_lock mutex to prevent unwanted reentrant during recovery processing
 - Fix building error about security helper on POSIX
 - Remove 'Ack pending work' on the queue handled immediately to prevent unwanted task running
 - Fix NV layer written length bug to make mismatch of data length between the written & the read by adding null terminated
 - Send MQTT CONNECT packet only once during connection. (no duplication)

## 1.1.18 :  Changes until v1.1.18

New Improvements or features:

 - Added SIGN_UP/IN iot_stat_lv to report things's sign-up/in status
 - Added virtual device in hardware
 - D2D protocol version update to ver.1.0.0
  * It depends on Mobile's SmartThings Apps (will be update)
 - Implement enhanced MQTT functionalities
  * Add MQTT Publish Async function.
  * Implement common MQTT packet complete wait sub-functions
  * Implement MQTT event callback functions & Change callback mechanism
 - Added security-system-manager to manage the key and certificate
  * Added ecdh/pubkey sub/module system

Enhancements or amendments:

 - Added retry MQTT connect concept when critical rejects happen instead of clean
 - Change its usage by sync-operation for IOT_WIFI_MODE_SCAN
 - Update & fixed boilerplate for easysetup & doxygen for bsp
 - Changes for 'logdump' & 'dumpstate' related usage
 - Move sw backed fs encryption into bsp
 - Updated & changed NV regarding security system
 - Updated & changed Easysetup related security system (for ecdh, cipher, certificate get..)
 - Updated new iot_os_eventgroup_xxx APIs usage (limit number of bits)
 - Fixed & changed webtoken related security system (pk_info, jwt/cwt, error messages,..)
 - Migrate pk/hash/base64 functions for security system

Bug fixed:

 - TC build error fixed to match MACRO with latest header
 - MQTT chunk memory handling bug fixed by chunk onwer.
 - To clear easysetup event group bit on easysetup deinit
 - Throw away all pub_queue instead of reset to prevent memory-leak (on iot_main)

## 1.1.16 :  Changes until v1.1.16

New Improvements

 - Applyed new onboarding flow for the new SmartThings Apps (New version will be release at the end of Jun.)
  * Support backward compatibility only for STDK. If you use the latest STDK, you can use old & new mobile's SmartThings Apps.
    But if you want to use the new SmartThings Apps, you have to use the latest STDK (v1.1.16)
 - Added ESP32's NVS encryption configuration - CONFIG_FLASH_ENCRYPTION_ENABLED
  * ref. : https://docs.espressif.com/projects/esp-idf/en/v3.3.2/security/flash-encryption.html#
 - Intruduce 'security backend' interface to support H/W secure storage such as eSE (embedded Secure Element)
  * Added cipher module in crypto sub system & helper functions for base64, sha256 and ed25519 to curve25519 converting.
 - Added new api to get certificate from rodata area.
 - Intruduce iot_log_dump for STDK internal logging system
  * Added new IOT_DUMP() macro & dump_log_id_t enums for case based logging
  * Added IOT_DUMP() macro in each src files to remain each case

Enhancements

 - Update iot_os_eventgroup related usage for set_bits/clear_bits/wait_for_all_bits.
 - Update MQTT related operation & functionality
  * Change MQTT operation mechanism based on queue
  * Implement MQTT operation cycle function & MQTT packet event user callback process based on chunk
  * Implement MQTT packet handling functions based on chunk
 - Added some device information items to display in IOT analytics board
 - Update iot-core connection working flow for several external st_conn_start() API usage
  * Added new st_lamp_conn_retry sample in apps/esp8266 of ref.
  * Added 'st_conn_lock' mutex to restrict st_conn_start() usage
 - Enforce http packet parser & find "Content-Length" header with case-insensitive for easysetup process
 - Seperate easysetup d2d by the protocol type for supporting new onboarding flow
 - Update guide & Doc. for os/bsp information, how to create QR code for STDK
 - Added clean socket mechanism to remove es_tcp_task() when es_http_deinit() called

Bug fixed:

 - Add more validation condition check for mutex lock to guard code
 - Calculating remaining timeout workaround for freertos version diff
 - Fix wrong condition check on httpd
 - Set NULL while loading missing optional values
 - Potential bug fixed for st_conn_start() re-using scenarios without H/W reset
 - Fix read length condition check issue on port/bsp/rtlxxx

## 1.1.14 :  Changes until v1.1.14

New Improvements or features:

 - Introduce new security system to support Security Level 3 & added TC for security
 - Add dump log function & dump log id list for group id based logging
 - Implement MQTT write/read stream functions based on chunk queue.

Enhancements or amendments:

 - Changed nv definition name for certificate : NV port layer definition & naming changed
 - Change to return the read size : FS port layer - iot_bsp_fs_read/write() function changed
 - Refactoring iot_log_file part for RAM-only supporting
 - Do not turn off the wifi if network access failed : only for ESP related WIFI/BSP parts
 - Added & updated Unit TC case for iot_os_xxx/iot_capability/iot_api/iot_mqtt_client/iot_main

Bug fixed:

 - Fixed wrong input length checking for 'bsp/esp32/fs'
 - fixed wrong json length calculation for 'example'

## 1.1.12 :  Changes until v1.1.12

New Improvements or features:

 - Introduce new internal APIs to handle iot_misc_info data
 - Implement NV(flash) based logging feature - STDK_IOT_CORE_LOG_FILE

Enhancements or amendments:

 - Update TC for iot-core, bsp, mqtt related internal codes
 - Increase registration process timeout until 15 min.
 - Support BOOLEAN data type in Capability handling API
 - Added Wi-Fi auth type to support various BSP
 - Add log handler for tls

Bug fixed:

 - Fixed status updating fail during recovery
 - Fixed some typo errors at the comments
 - Fixed build error for POSIX
 - Remove useless sleep for wifi disconnection on bsp/tizenrt
 - Changed to use timer during tls_read and tls_write on mbedtls net-interface

## 1.1.10 :  Changes until v1.1.10

New Improvements or features:

 - Added initial 'device-integration-profile-key' parsing codes on iot-main
 - To set UTC time from the mobile for SNTP
 - Use static iot_root_ca.c (do not make it on building process)
 - Set & add the timeout period & function(default) for mbed TLS handshake process
 - Add more JSON wrapper functions and use them in iot_capability.c
 - Embed cmocka-1.1.5 internally for unit test

Enhancements or amendments:

 - Update & change DIP handling codes for CBOR based operation
 - Refactoring wifi auth mode decision on easysetup process
 - TC update & add some checking codes for parameter hardness on iot_tuil, iot_capability, iot_easysetup
 - Update wifi related logic for scan-process & thread cancellation codes
 - Support commands number and order information in cmd data structure
 - Easysetup: code clean up & refactoring decode and decrypt part
 - Update D2D process : to change the request uri to create the dump, to skip the error status update for D2D cmd
 - Refactor iot_main : command status management, use unsigend value for bitwise operation

Bug fixed:

 - Fix wifi connection failed issue by auto-reconnecting on RTL
 - Changed main event-msg handling to prevent memory-leak condition
 - Code cleanup & fixed : iot_api.c, iot_nv_data.c, iot_net

## 1.1.0 :  Changes for version 1.1.0

 * Need to use over the Mobile's SmartThings Apps v1.7.43 (for Android)

New Improvements or features:

 - Supports TizenRT based target - port TizenRT wrapper
 - The port number changed for httpd during easy-setup
 - Added new IOT_STAT_LV_CONN to notify it to user
 - Added implementation of iot_bsp_wifi_get_mac()
 - Supports rtl8720c bsp based target
 - Supports mbedTLS usage in posix solution (instead of openssl, you can use mbedTLS for posix)
 - Added rtl8721csm porting layer
 - Update keygen tool - v2.1

Enhancements or amendments:

 - Don't send MQTT ping during there is outstanding packet
 - Only support for dynamic buffer allocation in MQTT layer
 - Add a contributing guideline
 - Check the uuid validation
 - Change lookup_id removing timing
 - Increase the maximum number of sacn results
 - Make iot_mqtt.h layer to import external MQTT solution
 - Separate internal network interface layer
 - Some function naming changed for httpd_init/deinit
 - Internal network function related code cleanup
 - Change auth mode to verify the certifcate

Bug fixed:

 - Fix rtl-chipset not support web security type connection issue
 - Added easy-setup resources checking flag & deleting routine to avoid memory leaking
 - Fix rtl-chipset based "RTW API: Join bss timeout" issue
 - Fix wi-fi memory leak
 - Internal network related build error fix

## 1.0.0 : Initial public release.
