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

#ifndef _IOT_ERROR_H_
#define _IOT_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name iot_error_t
 * @brief internal error codes.
 */
typedef enum iot_error_t {
	/* common error */
	IOT_ERROR_NONE = 0,
	IOT_ERROR_BAD_REQ = -1,
	IOT_ERROR_INVALID_ARGS = -2,
	IOT_ERROR_WRITE_FAIL = -3,
	IOT_ERROR_READ_FAIL = -4,
	IOT_ERROR_UNINITIALIZED = -5,
	IOT_ERROR_MEM_ALLOC = -6,
	IOT_ERROR_TIMEOUT = -7,
	IOT_ERROR_DUPLICATED_CMD = -8,

	/* registration error */
	IOT_ERROR_REG_UPDATED = -10,

	IOT_ERROR_NOT_IMPLEMENTED = -11,
	IOT_ERROR_INIT_FAIL = -12,
	IOT_ERROR_DEINIT_FAIL = -13,
	IOT_ERROR_NV_DATA_ERROR = -14,
	IOT_ERROR_NV_DATA_NOT_EXIST = -15,
	IOT_ERROR_FS_OPEN_FAIL = -16,
	IOT_ERROR_FS_READ_FAIL = -17,
	IOT_ERROR_FS_WRITE_FAIL = -18,
	IOT_ERROR_FS_REMOVE_FAIL = -19,
	IOT_ERROR_FS_CLOSE_FAIL = -20,
	IOT_ERROR_FS_NO_FILE = -21,
	IOT_ERROR_FS_ENCRYPT_INIT = -22,
	IOT_ERROR_FS_ENCRYPT_FAIL = -23,
	IOT_ERROR_FS_DECRYPT_FAIL = -24,
	IOT_ERROR_UUID_FAIL = -25,
	IOT_ERROR_CBOR_PARSE = -26,
	IOT_ERROR_CBOR_TO_JSON = -27,
	IOT_ERROR_WEBTOKEN_FAIL = -28,

	/* mqtt error */
	IOT_ERROR_MQTT_NETCONN_FAIL = -200,
	IOT_ERROR_MQTT_CONNECT_FAIL = -201,
	IOT_ERROR_MQTT_SERVER_UNAVAIL = -202,
	IOT_ERROR_MQTT_PUBLISH_FAIL = -203,
	IOT_ERROR_MQTT_REJECT_CONNECT = -204,
	IOT_ERROR_MQTT_CONNECT_TIMEOUT = -205,

	IOT_ERROR_NET_INVALID_INTERFACE = -300,
	IOT_ERROR_NET_CONNECT = -301,
	IOT_ERROR_NET_SNTP = -302,

	/* easy setup error */
	IOT_ERROR_EASYSETUP_CLIENT = -400,
	IOT_ERROR_EASYSETUP_SERVER = -500,

	/* connectivity error */
	IOT_ERROR_CONN_CONNECT_FAIL = -600,
	IOT_ERROR_CONN_OPERATE_FAIL = -601,
	IOT_ERROR_CONN_SOFTAP_CONF_FAIL = -610,
	IOT_ERROR_CONN_SOFTAP_CONN_FAIL = -611,
	IOT_ERROR_CONN_SOFTAP_DHCP_FAIL = -612,
	IOT_ERROR_CONN_SOFTAP_AUTH_FAIL = -613,
	IOT_ERROR_CONN_STA_CONF_FAIL = -620,
	IOT_ERROR_CONN_STA_CONN_FAIL = -621,
	IOT_ERROR_CONN_STA_DHCP_FAIL = -622,
	IOT_ERROR_CONN_STA_AP_NOT_FOUND = -623,
	IOT_ERROR_CONN_STA_ASSOC_FAIL = -624,
	IOT_ERROR_CONN_STA_AUTH_FAIL = -625,
	IOT_ERROR_CONN_STA_NO_INTERNET = -626,
	IOT_ERROR_CONN_DNS_QUERY_FAIL = -630,

	IOT_ERROR_CRYPTO_BASE = -1000,
	IOT_ERROR_SECURITY_BASE = -1000,

	IOT_ERROR_PROV_FAIL = -2998,
	IOT_ERROR_CONNECT_FAIL = -2999,
} iot_error_t;

#ifdef __cplusplus
}
#endif

#endif /* _IOT_ERROR_H_ */
