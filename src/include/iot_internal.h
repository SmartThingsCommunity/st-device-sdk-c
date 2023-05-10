/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef _IOT_INTERNAL_H_
#define _IOT_INTERNAL_H_

#include "iot_capability.h"
#include "iot_serialize.h"
#include "iot_bsp_wifi.h"

#define IOT_TASK_NAME "iot-task"
#define IOT_TASK_STACK_SIZE (1024*5)
#define IOT_TASK_PRIORITY (4)
#define IOT_QUEUE_LENGTH (10)

#define IOT_TOPIC_SIZE (100)
#define IOT_PAYLOAD_SIZE (1024)

#define IOT_SUB_TOPIC_REGISTRATION_PREFIX	"/v1/registrations/notification"
#define IOT_SUB_TOPIC_REGISTRATION_PREFIX_SIZE	strlen(IOT_SUB_TOPIC_REGISTRATION_PREFIX)
#define IOT_SUB_TOPIC_COMMAND_PREFIX		"/v1/commands"
#define IOT_SUB_TOPIC_COMMAND_PREFIX_SIZE		strlen(IOT_SUB_TOPIC_COMMAND_PREFIX)
#define IOT_SUB_TOPIC_NOTIFICATION_PREFIX	"/v1/notifications"
#define IOT_SUB_TOPIC_NOTIFICATION_PREFIX_SIZE	strlen(IOT_SUB_TOPIC_NOTIFICATION_PREFIX)

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
#define IOT_PUB_TOPIC_REGISTRATION	"/v1/registrations/cbor"
#define IOT_SUB_TOPIC_REGISTRATION	"/v1/registrations/notification/%s/cbor"

#define IOT_PUB_TOPIC_EVENT		"/v1/deviceEvents/%s/cbor"
#define IOT_SUB_TOPIC_COMMAND		"/v1/commands/%s/cbor"
#define IOT_SUB_TOPIC_NOTIFICATION	"/v1/notifications/%s/cbor"
#define IOT_PUB_TOPIC_HEALTH		"/v1/health/cbor"
#define IOT_PUB_TOPIC_DEVICES_UPDATE		"/v1/devices/update/cbor"
#define IOT_PUB_TOPIC_GET_PREFERENCES		"/v1/devices/preferences/get/cbor"
#else
#define IOT_PUB_TOPIC_REGISTRATION	"/v1/registrations"
#define IOT_SUB_TOPIC_REGISTRATION	"/v1/registrations/notification/%s"

#define IOT_PUB_TOPIC_EVENT		"/v1/deviceEvents/%s"
#define IOT_SUB_TOPIC_COMMAND		"/v1/commands/%s"
#define IOT_SUB_TOPIC_NOTIFICATION	"/v1/notifications/%s"
#define IOT_PUB_TOPIC_HEALTH		"/v1/health"
#define IOT_PUB_TOPIC_DEVICES_UPDATE		"/v1/devices/update"
#define IOT_PUB_TOPIC_GET_PREFERENCES		"/v1/devices/preferences/get"
#endif

#define IOT_PUB_TOPIC_DELETE	"/v1/devices/delete"

/* MQTT Pre-defined constant */
#define IOT_DEFAULT_TIMEOUT 		12000	/* milli-seconds */
#define IOT_MQTT_KEEPALIVE_INTERVAL	120		/* seconds */

/**
 * @brief Contains a enumeration values for types of iot_misc_info.
 */
typedef enum {
	IOT_MISC_INFO_DIP = 0,	/**< @brief For Device Integration Profile information */
	IOT_MISC_INFO_LOCATION,	/**< @brief for Device's location ID */
	IOT_MISC_PREV_ERR,      /**< @brief for err code for help contents of app */
} iot_misc_info_t;

/* Core */
/**
 * @brief	send command to iot main task
 * @details	this function sends specific command to iot-task via queue
 * @param[in]	ctx					iot-core context
 * @param[in]	cmd_type			actual specific command type
 * @param[in]	param				additional parameter for each command
 * @param[in]	param_size			additional parameter's size
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_MEM_ALLOC		memory allocation failed
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_command_send(struct iot_context *ctx,
	enum iot_command_type cmd_type, const void *param, int param_size);

/**
 * @brief	send wifi control request
 * @details	this function sends wifi control command using iot_command_send internally
 * @param[in]	ctx					iot-core context
 * @param[in]	wifi_mode			actual wifi control mode
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_MEM_ALLOC		memory allocation failed
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_wifi_ctrl_request(struct iot_context *ctx,
		iot_wifi_mode_t wifi_mode);

/**
 * @brief   send ble control request
 * @details this function sends ble control command using iot_command_send internally
 * @param[in]   ctx                 iot-core context
 * @retval  IOT_ERROR_NONE          success.
 * @retval  IOT_ERROR_MEM_ALLOC     memory allocation failed
 * @retval  IOT_ERROR_BAD_REQ       queue send error
 */
iot_error_t iot_ble_ctrl_request(struct iot_context *ctx);

/**
 * @brief	update iot state
 * @details	this function tries to update iot-state using iot_command_send internally
 * @param[in]	ctx					iot-core context
 * @param[in]	new_state			new iot-state to update
 * @param[in]	opt				optional parameter for each new_state
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_MEM_ALLOC		memory allocation failed
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_state_update(struct iot_context *ctx,
	iot_state_t new_state, int opt);

/**
 * @brief	change iot_state timeout value
 * @details	this function tries to change iot-state-timeout value using iot_command_send internally
 * @param[in]	ctx					iot-core context
 * @param[in]	target_state		target iot-state for changing timeout
 * @param[in]	new_timeout_ms		new timeout value for target iot-state
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_INVALID_ARGS	unsupported or invalid params
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_state_timeout_change(struct iot_context *ctx,
	iot_state_t target_state, unsigned int new_timeout_ms);

/**
 * @brief	send easysetup cgi payload manipulation request
 * @details	easysetup cgi payload manipulation should be done at iot-task. This function sends payload to iot-task via queue
 * @param[in]	ctx				iot-core context
 * @param[in]	step			indicates which uri(command) is dealing with
 * @param[in]	payload			payload data - mostly json data
 * @retval	IOT_ERROR_NONE		success.
 * @retval	IOT_ERROR_BAD_REQ	queue send error
 */
iot_error_t iot_easysetup_request(struct iot_context *ctx,
	enum iot_easysetup_step step, const void *payload);

/**
 * @brief	load "onboarding_config.json" from application source directory
 * @details	"onboarding_config.json" can be downloaded from SmartThings Developer Workspace <br>
 * 		This function parses downloaded "onboarding_config.json" to be used for EasySetup
 * @param[in]	onboarding_config		start pointer of json data
 * @param[in]	onboarding_config_len	json data length
 * @param[out]	devconf		"onboarding_config.json" will be parsed and mapped to this internal structure
 * @retval	IOT_ERROR_NONE                      success.
 * @retval	IOT_ERROR_UNINITIALIZED             invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC                 memory allocation failure.
 * @retval	IOT_ERROR_CRYPTO_SHA256             sha256 error.
 * @retval	IOT_ERROR_CRYPTO_BASE64             base64 error.
 * @retval	IOT_ERROR_CRYPTO_BASE64_URLSAFE     base64 urlsafe error.
 * @par example
 * @code
 {
    "onboardingConfig": {
        "deviceOnboardingID": "NAME", // max. 13 character. this will be prefix of soft-ap ssid.
        "mnId": "MNID", // mnId for developer and/or manufacturer. "MNID" shouldn't be used.
        "setupId": "999", // 3-digit Device onboarding ID for this device.
        "vid": "VID", // VID(Vendor ID) for this profile.
        "deviceTypeId": "TYPE", // Device type which is selected from Developer Workspace.
        "ownershipValidationType": [ "JUSTWORKS", "BUTTON", "PIN", "QR" ],
            // "JUSTWORKS" for confirming without user interaction.
            // "BUTTON" for confirming by pressing builtin button.
            // "PIN" for confirming by matching 8-digit number PIN
            // "QR" for confirming by scanning a QR code by SmartThings app.
        "identityType": "ED25519 or CERTIFICATE" // ED25519 or X.509 CERTIFICATE
     }
 }
 * @endcode
 */
iot_error_t iot_api_onboarding_config_load(unsigned char *onboarding_config,
		unsigned int onboarding_config_len, struct iot_devconf_prov_data *devconf);

/**
 * @brief	load "device_info.json" from application source directory
 * @details	"device_info.json" should be updated by application developer <br>
 * 		This function parses downloaded "device_info.json" to be used for EasySetup<br>
 * 		Only firmwareVersion will be parsed by this api. others are handled by another api
 *
 * @param[in]	device_info			start pointer of json data
 * @param[in]	device_info_len		json data length
 * @param[out]	info		"device_info.json" will be parsed and mapped to this internal structure
 * @retval	IOT_ERROR_NONE              success.
 * @retval	IOT_ERROR_UNINITIALIZED     invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC         memory allocation failure.
 * @par example
 * @code
{
	"deviceInfo": {
		"firmwareVersion": "FwVer0011A",
    ...
	}
}
 * @endcode
 */
iot_error_t iot_api_device_info_load(unsigned char *device_info,
		unsigned int device_info_len, struct iot_device_info *info);

/**
 * @brief	free onboarding config memory
 * @details	this function frees the loaded onboarding configuration
 * @param[in]	devconf		loaded onboarding configuration
 */
void iot_api_onboarding_config_mem_free(struct iot_devconf_prov_data *devconf);

/**
 * @brief	free device info memory
 * @details	this function frees the loaded device's information
 * @param[in]	info		loaded device's information
 */
void iot_api_device_info_mem_free(struct iot_device_info *info);

/**
 * @brief	free prov data memory
 * @details	this function frees the loaded provisioning data
 * @param[in]	prov		loaded provisioning data
 */
void iot_api_prov_data_mem_free(struct iot_device_prov_data *prov);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
/**
 * @brief	Extract required data from "device_info.json" which is located in application source directory
 * @details	"device_info.json" should be updated by application developer <br>
 * 		This function parses downloaded "device_info.json" to be used for EasySetup
 * @param[in]	device_nv_info		starting pointer of json data
 * @param[in]	device_nv_info_len	json data length
 * @param[in]	object				object name for searching json data.
 * @param[out]	nv_data		"device_info.json" will be parsed by "object" and mapped to this pointer
 * @retval	IOT_ERROR_NONE              success.
 * @retval	IOT_ERROR_UNINITIALIZED     invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC         memory allocation failure.
 * @par example
 * @code
   {
	"nvProfile": {
		"privateKey": "privateKey", // Client (= Device) Private key
		"publicKey": "publicKey", // Client (= Device) Public key
		"serialNumber": "serialNumber" // Device Serial Number
	}
   }
 * @endcode
 */
iot_error_t iot_api_read_device_identity(unsigned char *device_nv_info,
      unsigned int device_nv_info_len, const char *object, char **nv_data);
#endif

/**
 * @brief	device cleanup
 * @details	this function triggers clean-up process. All registered data will be removed
 * @param[in]	ctx	iot-core context
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_device_cleanup(struct iot_context *ctx);

/**
 * @brief	easy setup connect
 * @details	this function tries to connect server for registration or communication process
 * @param[in]	ctx		iot-core context
 * @param[in]	conn_type	set connection type. registration or communication with server
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type);

/**
 * @brief	easy setup disconnect
 * @details	this function tries to disconnect server for registration or communication process
 * @param[in]	ctx		iot-core context
 * @param[in]	conn_type	set connection type. registration or communication with server
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type);

/**
 * @brief	callback for mqtt command msg
 * @details	this function is used to handle command message from server
 * @param[in]	cap_handle_list		allocated capability handle list
 * @param[in]	payload			received raw message from server
 */
void iot_cap_sub_cb(iot_cap_handle_list_t *cap_handle_list, char *payload);

/**
 * @brief	callback for mqtt command msg(version2)
 * @details	this function is used to handle command message from server
 * @param[in]	ctx		iot-core context
 * @param[in]	payload			received raw message from server
 */
void iot_cap_commands_cb(struct iot_context *ctx, char *payload);

/**
 * @brief	callback for mqtt noti msg
 * @details	this function is used to handle notification message from server
 * @param[in]	ctx		iot-core context
 * @param[in]	payload		received raw message from server
 */
void iot_noti_sub_cb(struct iot_context *ctx, char *payload);

/**
 * @brief	call init callback
 * @details	this function is used to call all allocated capability callbacks when target is connected
 * @param[in]	cap_handle_list		allocated capability handle list
 */
void iot_cap_call_init_cb(iot_cap_handle_list_t *cap_handle_list);

/* For universal purpose */
/**
 * @brief	get time data by sec
 * @details	this function tries to get time value in second by string
 * @param[out]	buf		buffer point to contain second based string value
 * @param[in]	buf_len		size of allocated buffer for string
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_time_in_sec(char *buf, size_t buf_len);

/**
 * @brief	get time date in second by long
 * @details	this function tries to get time value in second by long
 * @param[out]	sec		point to contain second based long value
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_time_in_sec_by_long(long *sec);


/**
 * @brief	get time data in msec
 * @details	this function tries to get time value in millisecond by string
 * @param[out]	buf		buffer point to contain millisecond based string value
 * @param[in]	buf_len		size of allocated buffer for string
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_time_in_ms(char *buf, size_t buf_len);

/**
 * @brief	load each type value from iot_misc_info data
 * @details	this function tries to load each type value in iot_misc_info data
 * @param[in]	type	type of iot_misc_info to load its value
 * @param[out]	out_data	A pointer to data structure to load <br>
 * 		each type of iot_misc_info value from iot_misc_info data
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_misc_info_load(iot_misc_info_t type, void *out_data);

/**
 * @brief	store each type value to iot_misc_info data
 * @details	this function tries to store each type value in iot_misc_info data
 * @param[in]	type	type of iot_misc_info to load its value
 * @param[in]	in_data		A pointer to data structure to store <br>
 * 		each type of iot_misc_info value to iot_misc_info data
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_misc_info_store(iot_misc_info_t type, const void *in_data);

/**
 * @brief	get random_id string based on uuid style
 * @details	this function tries to get new generated random_id string
 * @param[in]	str	allocated memory pointer for random_id string
 * @param[in]	max_sz	max size of allocated memory pointer
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_random_id_str(char *str, size_t max_sz);

/**
 * @brief	get last happended device error code for SmartThings App
 * @details	this function tries to get last happended device error code
 * @param[in]	ctx			iot-core context
 * @param[out]	st_ecode	A pointer to load iot_st_ecode data structure
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_st_ecode(struct iot_context *ctx, struct iot_st_ecode *st_ecode);

/**
 * @brief	set new happened device error code for SmartThings App
 * @details	this function tries to set new happened device error code
 * @param[in]	ctx			iot-core context
 * @param[in]	ecode	    help contents error type
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_set_st_ecode(struct iot_context *ctx, iot_st_ecode_t ecode);


/**
 * @brief	set device error code for SmartThings App from internal connection error
 * @details	this function converts device error code from iot_error_t type connection error.
 *          this function calls iot_set_st_ecode() internally.
 *          iot_bsp_wifi_set_mode() should return proper iot_error_t value to send help contents error code
 * @param[in]	ctx			iot-core context
 * @param[in]	conn_error	    iot_error_t type connection error (-610 ~ -6xx)
 * @retval	IOT_ERROR_NONE                  success.
 *          IOT_ERROR_INVALID_ARGS          not supported error code and/or null context
 */
iot_error_t iot_set_st_ecode_from_conn_error(struct iot_context *ctx, iot_error_t conn_error);

/**
 * @brief	device internal clean-up function
 * @details	This function cleans-up all DATA including provisioning & registered data
 * @param[in]	ctx			iot-core context
 * @param[in]	reboot		boolean set true for auto-reboot of system, else false.
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_cleanup(struct iot_context *ctx, bool reboot);

#endif /* _IOT_INTERNAL_H_ */

