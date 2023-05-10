/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_EASY_SETUP_H_
#define _IOT_EASY_SETUP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "iot_error.h"
#include "iot_main.h"

enum ownership_validation_feature {
	OVF_BIT_JUSTWORKS = 0,
	OVF_BIT_QR,
	OVF_BIT_BUTTON,
	OVF_BIT_PIN,
	OVF_BIT_SERIAL_NUMBER,
	OVF_BIT_MAX_FEATURE = OVF_BIT_SERIAL_NUMBER,

};

#define IOT_OVF_TYPE_JUSTWORKS		(1u << (unsigned)OVF_BIT_JUSTWORKS)
#define IOT_OVF_TYPE_BUTTON		(1u << (unsigned)OVF_BIT_BUTTON)
#define IOT_OVF_TYPE_PIN		(1u << (unsigned)OVF_BIT_PIN)
#define IOT_OVF_TYPE_QR			(1u << (unsigned)OVF_BIT_QR)

#define IOT_ES_URI_POST_KEYINFO			"/keyinfo"
#define IOT_ES_URI_POST_CONFIRMINFO		"/confirminfo"
#define IOT_ES_URI_POST_CONFIRM			"/confirm"
#define IOT_ES_URI_POST_WIFIPROVISIONINGINFO	"/wifiprovisioninginfo"
#define IOT_ES_URI_POST_SETUPCOMPLETE		"/setupcomplete"
#define IOT_ES_URI_POST_LOGS			"/logs/dump"

#define IOT_ES_URI_GET_DEVICEINFO		"/deviceinfo"
#define IOT_ES_URI_GET_WIFISCANINFO		"/wifiscaninfo"
#define IOT_ES_URI_GET_POST_RESPONSE		"/post_response"
#define IOT_ES_URI_GET_LOGS_SYSTEMINFO		"/logs/systeminfo"
#define IOT_ES_URI_GET_LOGS_DUMP		"/logs/dump"

#define IOT_ES_DUMP(LEVEL, ERR, arg)	IOT_DUMP(LEVEL, ERR, __LINE__, arg)

/* Client Common */
#define IOT_ERROR_EASYSETUP_400_BASE			IOT_ERROR_EASYSETUP_CLIENT
#define IOT_ERROR_EASYSETUP_INVALID_CMD		(IOT_ERROR_EASYSETUP_400_BASE - 1)
#define IOT_ERROR_EASYSETUP_INVALID_REQUEST		(IOT_ERROR_EASYSETUP_400_BASE - 2)
#define IOT_ERROR_EASYSETUP_INVALID_SEQUENCE		(IOT_ERROR_EASYSETUP_400_BASE - 3)
#define IOT_ERROR_EASYSETUP_NOT_SUPPORTED		(IOT_ERROR_EASYSETUP_400_BASE - 4)
#define IOT_ERROR_EASYSETUP_BASE64_DECODE_ERROR	(IOT_ERROR_EASYSETUP_400_BASE - 5)
#define IOT_ERROR_EASYSETUP_AES256_DECRYPTION_ERROR	(IOT_ERROR_EASYSETUP_400_BASE - 6)
#define IOT_ERROR_EASYSETUP_CIPHER_ERROR		(IOT_ERROR_EASYSETUP_400_BASE - 7)
#define IOT_ERROR_EASYSETUP_CIPHER_ALIGN_ERROR		(IOT_ERROR_EASYSETUP_400_BASE - 8)
#define IOT_ERROR_EASYSETUP_CIPHER_PARAMS_ERROR		(IOT_ERROR_EASYSETUP_400_BASE - 9)

/* Key Info */
#define IOT_ERROR_EASYSETUP_RAND_DECODE_ERROR		(IOT_ERROR_EASYSETUP_400_BASE - 11)
#define IOT_ERROR_EASYSETUP_INVALID_TIME		(IOT_ERROR_EASYSETUP_400_BASE - 12)

/* Otm */
#define IOT_ERROR_EASYSETUP_INVALID_QR			(IOT_ERROR_EASYSETUP_400_BASE - 21)
#define IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER		(IOT_ERROR_EASYSETUP_400_BASE - 22)
#define IOT_ERROR_EASYSETUP_INVALID_PIN			(IOT_ERROR_EASYSETUP_400_BASE - 23)
#define IOT_ERROR_EASYSETUP_PIN_NOT_MATCHED		(IOT_ERROR_EASYSETUP_400_BASE - 24)

/* Wifi provisioning */
#define IOT_ERROR_EASYSETUP_INVALID_MAC			(IOT_ERROR_EASYSETUP_400_BASE - 31)
#define IOT_ERROR_EASYSETUP_INVALID_BROKER_URL			(IOT_ERROR_EASYSETUP_400_BASE - 32)

/* Server Common */
#define IOT_ERROR_EASYSETUP_500_BASE			IOT_ERROR_EASYSETUP_SERVER
#define IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 1)
#define IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 2)
#define IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 3)
#define IOT_ERROR_EASYSETUP_BASE64_ENCODE_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 4)
#define IOT_ERROR_EASYSETUP_AES256_ENCRYPTION_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 5)
#define IOT_ERROR_EASYSETUP_FAILED_CREATE_LOG	(IOT_ERROR_EASYSETUP_500_BASE - 6)
#define IOT_ERROR_EASYSETUP_QUEUE_SEND_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 7)
#define IOT_ERROR_EASYSETUP_QUEUE_RECV_ERROR	(IOT_ERROR_EASYSETUP_500_BASE - 8)

/* Key Info */
#define IOT_ERROR_EASYSETUP_SHARED_KEY_INIT_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 11)
#define IOT_ERROR_EASYSETUP_SHARED_KEY_CREATION_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 12)
#define IOT_ERROR_EASYSETUP_SHARED_KEY_PARAMS_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 13)
#define IOT_ERROR_EASYSETUP_BLE_ECDH_SETUP_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 14)
#define IOT_ERROR_EASYSETUP_SHARED_SIGNATURE_CREATION_FAIL	(IOT_ERROR_EASYSETUP_500_BASE - 15)
#define IOT_ERROR_EASYSETUP_SHARED_DATA_CREATION_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 16)

/* Otm */
#define IOT_ERROR_EASYSETUP_CONFIRM_NOT_SUPPORT		(IOT_ERROR_EASYSETUP_500_BASE - 21)
#define IOT_ERROR_EASYSETUP_CONFIRM_TIMEOUT		(IOT_ERROR_EASYSETUP_500_BASE - 22)
#define IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND		(IOT_ERROR_EASYSETUP_500_BASE - 23)
#define IOT_ERROR_EASYSETUP_CONFIRM_DENIED		(IOT_ERROR_EASYSETUP_500_BASE - 24)
#define IOT_ERROR_EASYSETUP_PIN_NOT_FOUND		(IOT_ERROR_EASYSETUP_500_BASE - 25)

/* Wifi provisioning */
#define IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND			(IOT_ERROR_EASYSETUP_500_BASE - 31)
#define IOT_ERROR_EASYSETUP_WIFI_DATA_WRITE_FAIL			(IOT_ERROR_EASYSETUP_500_BASE - 32)
#define IOT_ERROR_EASYSETUP_WIFI_DATA_READ_FAIL			(IOT_ERROR_EASYSETUP_500_BASE - 33)
#define IOT_ERROR_EASYSETUP_CLOUD_DATA_WRITE_FAIL			(IOT_ERROR_EASYSETUP_500_BASE - 34)
#define IOT_ERROR_EASYSETUP_LOOKUPID_GENERATE_FAIL			(IOT_ERROR_EASYSETUP_500_BASE - 35)
#define IOT_ERROR_EASYSETUP_WIFI_NOT_DISCOVERED			(IOT_ERROR_EASYSETUP_500_BASE - 36)
#define IOT_ERROR_EASYSETUP_WIFI_INVALID_PASSWORD			(IOT_ERROR_EASYSETUP_500_BASE - 37)
#define IOT_ERROR_EASYSETUP_WIFI_INVALID_SSID			(IOT_ERROR_EASYSETUP_500_BASE - 38)
#define IOT_ERROR_EASYSETUP_WIFI_INVALID_BSSID			(IOT_ERROR_EASYSETUP_500_BASE - 39)
#define IOT_ERROR_EASYSETUP_SERIAL_NUMBER_GET_FAIL			(IOT_ERROR_EASYSETUP_500_BASE - 40)

/* Registration */
#define IOT_ERROR_EASYSETUP_REGISTER_FAILED_REGISTRATION			(IOT_ERROR_EASYSETUP_500_BASE - 41)

/* Certificate */
#define IOT_ERROR_EASYSETUP_CETIFICATE_FAILED_GET_CERTIFICATE			(IOT_ERROR_EASYSETUP_500_BASE - 51)

/* HTTP */
#define IOT_ERROR_EASYSETUP_HTTP_RECV_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 61)
#define IOT_ERROR_EASYSETUP_HTTP_SEND_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 62)
#define IOT_ERROR_EASYSETUP_HTTP_PARSE_FAIL		(IOT_ERROR_EASYSETUP_500_BASE - 63)
#define IOT_ERROR_EASYSETUP_HTTP_PEER_CONN_CLOSED		(IOT_ERROR_EASYSETUP_500_BASE - 64)

/**
 * @brief	easysetup cgi request handler
 * @details	This function runs from iot-task by executing actual cgi payload manipulation.<br>
 * 		result will be transferred to httpd task (tiT) as easysetup response queue parameter.
 * @param[in]	ctx		iot_context handle
 * @param[in]	request		easysetup payload as input
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE		success
 */
iot_error_t iot_easysetup_request_handler(struct iot_context *ctx, struct iot_easysetup_payload request);

/**
 * @brief	Create E4 type SSID
 * @details	This function create E4 type soft-ap SSID for this device
 * @param[in]	devconf		things static information
 * @param[out]	ssid		created ssid
 * @param[in]	ssid_len	ssid buffer length including null termination
 * @return	iot_state_t
 * @retval	IOT_ERROR_NONE	success
 */
iot_error_t iot_easysetup_create_ssid(struct iot_devconf_prov_data *devconf, char *ssid, size_t ssid_len);

/**
 * @brief   Create BLE Advertise Packet
 * @details This function create BLE advertise packet for this device
 * @param[in]   ctx     iot_context
 * @return  iot_state_t
 * @retval  IOT_ERROR_NONE  success
 */
iot_error_t iot_easysetup_create_ble_advertise_packet(struct iot_context *ctx);

/**
 * @brief	Start easysetup device-to-device sequence
 * @details	This function makes wifi mode as soft-ap and starts httpd
 * @param[in]	ctx	iot_context handle
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE		success
 * @retval	IOT_ERROR_UNINITIALIZED	error
 */
iot_error_t iot_easysetup_init(struct iot_context *ctx);


/**
 * @brief	Stop easysetup device-to-device sequence
 * @details	This function stops httpd working
 * @param[in]	ctx	iot_context handle
 * @return	void
 */
void iot_easysetup_deinit(struct iot_context *ctx);

/**
 * @brief	Query stopping eayssetup device-to-device sequence
 * @details	This function queries stopping easysetup device-to-device sequence
 * @return	bool
 * @retval	true	easysetup deinit is in progress
 * @retval	false	easysetup deinit isn't in progress
 */
bool is_es_http_deinit_processing(void);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_EASY_SETUP_H_ */
