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

	/* mqtt error */
	IOT_ERROR_MQTT_NETCONN_FAIL = -200,
	IOT_ERROR_MQTT_CONNECT_FAIL = -201,
	IOT_ERROR_MQTT_SERVER_UNAVAIL = -202,
	IOT_ERROR_MQTT_PUBLISH_FAIL = -203,
	IOT_ERROR_MQTT_REJECT_CONNECT = -204,

	IOT_ERROR_NET_INVALID_INTERFACE = -300,
	IOT_ERROR_NET_CONNECT = -301,

	IOT_ERROR_CRYPTO_BASE = -1000,
	IOT_ERROR_JWT_BASE = -2000,

	/* easy setup error */
	IOT_ERROR_PROV_FAIL = -2998,
	IOT_ERROR_CONNECT_FAIL = -2999,
	IOT_ERROR_EASYSETUP_BASE = -3000,
} iot_error_t;

#ifdef __cplusplus
}
#endif

#endif /* _IOT_ERROR_H_ */
