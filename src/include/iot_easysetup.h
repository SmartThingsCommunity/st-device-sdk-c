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
	OVF_BIT_MAX_FEATURE,
};

#define IOT_OVF_TYPE_JUSTWORKS		(1 << OVF_BIT_JUSTWORKS)
#define IOT_OVF_TYPE_BUTTON		(1 << OVF_BIT_BUTTON)
#define IOT_OVF_TYPE_PIN		(1 << OVF_BIT_PIN)
#define IOT_OVF_TYPE_QR			(1 << OVF_BIT_QR)

#define IOT_ES_URI_POST_KEYINFO			"keyinfo"
#define IOT_ES_URI_POST_CONFIRMINFO		"confirminfo"
#define IOT_ES_URI_POST_CONFIRM			"confirm"
#define IOT_ES_URI_POST_WIFIPROVISIONINGINFO	"wifiprovisioninginfo"
#define IOT_ES_URI_POST_SETUPCOMPLETE	"setupcomplete"
#define IOT_ES_URI_POST_LOGS	"logs"

#define IOT_ES_URI_GET_DEVICEINFO		"/deviceinfo"
#define IOT_ES_URI_GET_WIFISCANINFO		"/wifiscaninfo"
#define IOT_ES_URI_GET_POST_RESPONSE		"/post_response"
#define IOT_ES_URI_GET_LOGS_SYSTEMINFO		"/logs/systeminfo"
#define IOT_ES_URI_GET_LOGS_DUMP		"/logs/dump"

#define IOT_ERROR_EASYSETUP_INVALID_REQUEST		(IOT_ERROR_EASYSETUP_BASE - 1)
#define IOT_ERROR_EASYSETUP_INVALID_SEQUENCE		(IOT_ERROR_EASYSETUP_BASE - 2)
#define IOT_ERROR_EASYSETUP_NOT_SUPPORTED		(IOT_ERROR_EASYSETUP_BASE - 3)
#define IOT_ERROR_EASYSETUP_INVALID_PIN			(IOT_ERROR_EASYSETUP_BASE - 4)
#define IOT_ERROR_EASYSETUP_INVALID_QR			(IOT_ERROR_EASYSETUP_BASE - 5)
#define IOT_ERROR_EASYSETUP_INVALID_BROKER_URL		(IOT_ERROR_EASYSETUP_BASE - 6)
#define IOT_ERROR_EASYSETUP_INVALID_PAYLOAD		(IOT_ERROR_EASYSETUP_BASE - 7)

#define IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR	(IOT_ERROR_EASYSETUP_BASE - 50)
#define IOT_ERROR_EASYSETUP_WIFI_SCANLIST_NOT_FOUND	(IOT_ERROR_EASYSETUP_BASE - 51)
#define IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND		(IOT_ERROR_EASYSETUP_BASE - 52)
#define IOT_ERROR_EASYSETUP_CONFIRM_TIMEOUT		(IOT_ERROR_EASYSETUP_BASE - 53)
#define IOT_ERROR_EASYSETUP_CONFIRM_DENIED		(IOT_ERROR_EASYSETUP_BASE - 54)
#define IOT_ERROR_EASYSETUP_SHARED_KEY_CREATION_FAIL	(IOT_ERROR_EASYSETUP_BASE - 55)
#define IOT_ERROR_EASYSETUP_RPK_NOT_FOUND		(IOT_ERROR_EASYSETUP_BASE - 56)
#define IOT_ERROR_EASYSETUP_CERTIFICATE_NOT_FOUND	(IOT_ERROR_EASYSETUP_BASE - 57)
#define IOT_ERROR_EASYSETUP_PIN_NOT_FOUND		(IOT_ERROR_EASYSETUP_BASE - 58)
#define IOT_ERROR_EASYSETUP_SPUB_DECODE_ERROR		(IOT_ERROR_EASYSETUP_BASE - 59)
#define IOT_ERROR_EASYSETUP_RAND_DECODE_ERROR		(IOT_ERROR_EASYSETUP_BASE - 60)
#define IOT_ERROR_EASYSETUP_INTERNAL_WARNING		(IOT_ERROR_EASYSETUP_BASE - 97)
#define IOT_ERROR_EASYSETUP_INTERNAL_CRITICAL_ERROR	(IOT_ERROR_EASYSETUP_BASE - 98)

#define IOT_ERROR_EASYSETUP_400_BASE			IOT_ERROR_EASYSETUP_INVALID_REQUEST
#define IOT_ERROR_EASYSETUP_500_BASE			IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR
#define IOT_ERROR_EASYSETUP_MAX				(IOT_ERROR_EASYSETUP_BASE - 99)

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
 * @brief	Start eayssetup device-to-device sequence
 * @details	This function makes wifi mode as soft-ap and starts httpd
 * @param[in]	ctx	iot_context handle
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE		success
 * @retval	IOT_ERROR_UNINITIALIZED	error
 */
iot_error_t iot_easysetup_init(struct iot_context *ctx);


/**
 * @brief	Stop eayssetup device-to-device sequence
 * @details	This function stops httpd working
 * @param[in]	ctx	iot_context handle
 * @return	void
 */
void iot_easysetup_deinit(struct iot_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_EASY_SETUP_H_ */
