/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_DUMP_LOG_H_
#define _IOT_DUMP_LOG_H_

#include "iot_main.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IOT_DUMP_MAGIC_NUMBER (0x57D1C109)
#define IOT_DUMP_LOG_MSG_LINE_LENGTH 16
#define IOT_DUMP_BUFFER_SIZE 48

struct iot_dump_header {
    int magic_number;
    int log_version;
    int dump_state_size;
    int dummy;
};

struct iot_dump_state {
    int stdk_version_code;
    int clock_time;
    int sequence_number;
    int dip_version;
    char os_name[16];
    char os_version[16];
    char bsp_name[16];
    char bsp_version[16];
    char firmware_version[16];
    char model_number[16];
    char manufacturer_name[16];
    char dip_id[16];
    char device_id[8];
    unsigned int mqtt_connection_success_count;
    unsigned int mqtt_connection_try_count;

    long log_time;
};

#define IOT_DUMP_LOG_VERSION 0

typedef enum {
	IOT_DUMP_MAIN_BASE = 0x0000,	/* arg1: line-number, arg2: iot_error_t or specific */
	IOT_DUMP_MAIN_COMMAND = 0x0001,	/* arg1: cmd_type or err, arg2: curr_state */
	IOT_DUMP_MAIN_STATE =0x0002,	/* arg1: iot_state_t, arg2: final iot_error_t */
	IOT_DUMP_MQTT_BASE = 0x0100,
	IOT_DUMP_MQTT_CREATE_SUCCESS = 0x0101,	/* arg1: command_timeout_ms */
	IOT_DUMP_MQTT_CREATE_FAIL = 0x0102, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_DESTROY = 0x0103,
	IOT_DUMP_MQTT_PING_FAIL = 0x0104, /* arg1: error code */
	IOT_DUMP_MQTT_CONNECT_NETWORK_FAIL = 0x0105,
	IOT_DUMP_MQTT_CONNECT_RESULT = 0x0106, /* arg1: return code(rc), arg2: keepalive interval */
	IOT_DUMP_MQTT_SEND_FAIL = 0x0107, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_CYCLE_FAIL = 0x0108, /* arg1: return code(rc), arg2: received packet type */
	IOT_DUMP_MQTT_DISCONNECT = 0x0109, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_PUBLISH = 0x010A, /* arg1: return code(rc), arg2: packet id */
	IOT_DUMP_MQTT_UNSUBSCRIBE = 0x010B, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_SUBSCRIBE = 0x010C, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_WRITE_STREAM_FAIL = 0x010D, /* arg1: error code */
	IOT_DUMP_MQTT_READ_STREAM_FAIL = 0x010E, /* arg1: error code */
	IOT_DUMP_CAPABILITY_BASE = 0x0200,
	IOT_DUMP_CAPABILITY_COMMANDS_RECEIVED = 0x0201,
	IOT_DUMP_CAPABILITY_PROCESS_COMMAND = 0x0202,
	IOT_DUMP_CAPABILITY_COMMAND_SUCCEED = 0x0203,
	IOT_DUMP_CAPABILITY_NOTI_RECEIVED = 0x0204,
	IOT_DUMP_CAPABILITY_DEVICE_DELETED_RECEIVED = 0x0205,
	IOT_DUMP_CAPABILITY_EXPIRED_JWT_RECEIVED = 0x0206,
	IOT_DUMP_CAPABILITY_RATE_LIMIT_RECEIVED = 0x0207,
	IOT_DUMP_CAPABILITY_QUOTA_LIMIT_RECEIVED = 0x0208,
	IOT_DUMP_CAPABILITY_SEND_EVENT_NO_DATA_ERROR = 0x0209,
	IOT_DUMP_CAPABILITY_SEND_EVENT_NO_CONNECT_ERROR = 0x020A,
	IOT_DUMP_CAPABILITY_SEND_EVENT_QUEUE_FAIL_ERROR = 0x020B,
	IOT_DUMP_CAPABILITY_SEND_EVENT_SUCCESS = 0x020C,
	IOT_DUMP_SECURITY_BASE = 0x0300,
	IOT_DUMP_SECURITY_INIT = 0x0301,
	IOT_DUMP_SECURITY_DEINIT = 0x0302,
	IOT_DUMP_SECURITY_CONTEXT_NULL = 0x0303,
	IOT_DUMP_SECURITY_BE_CONTEXT_NULL = 0x0304,
	IOT_DUMP_SECURITY_BE_FUNC_NULL = 0x0305,
	IOT_DUMP_SECURITY_BE_FUNCS_ENTRY_NULL = 0x0306,
	IOT_DUMP_SECURITY_BE_EXTERNAL_NULL = 0x0307,
	IOT_DUMP_SECURITY_NOT_IMPLEMENTED = 0x0308,
	IOT_DUMP_SECURITY_PK_INIT = 0x0310,
	IOT_DUMP_SECURITY_PK_DEINIT = 0x0311,
	IOT_DUMP_SECURITY_PK_SIGN = 0x0312,
	IOT_DUMP_SECURITY_PK_VERIFY = 0x0313,
	IOT_DUMP_SECURITY_PK_PARSEKEY = 0x0314,
	IOT_DUMP_SECURITY_PK_KEY_LEN = 0x0315,
	IOT_DUMP_SECURITY_PK_KEY_TYPE = 0x0316,
	IOT_DUMP_SECURITY_PK_PARAMS_NULL = 0x0317,
	IOT_DUMP_SECURITY_PK_INVALID_PUBKEY = 0x0318,
	IOT_DUMP_SECURITY_PK_INVALID_SECKEY = 0x0319,
	IOT_DUMP_SECURITY_CIPHER_INIT = 0x0320,
	IOT_DUMP_SECURITY_CIPHER_DEINIT = 0x0321,
	IOT_DUMP_SECURITY_CIPHER_AES_ENCRYPT = 0x0322,
	IOT_DUMP_SECURITY_CIPHER_AES_DECRYPT = 0x0323,
	IOT_DUMP_SECURITY_CIPHER_SET_PARAMS = 0x0324,
	IOT_DUMP_SECURITY_CIPHER_PARAMS_NULL = 0x0325,
	IOT_DUMP_SECURITY_CIPHER_INVALID_MODE = 0x0326,
	IOT_DUMP_SECURITY_CIPHER_INVALID_ALGO = 0x0327,
	IOT_DUMP_SECURITY_CIPHER_INVALID_KEY = 0x0328,
	IOT_DUMP_SECURITY_CIPHER_INVALID_IV = 0x0329,
	IOT_DUMP_SECURITY_CIPHER_KEY_LEN = 0x032A,
	IOT_DUMP_SECURITY_CIPHER_IV_LEN = 0x032B,
	IOT_DUMP_SECURITY_CIPHER_BUF_OVERFLOW = 0x032C,
	IOT_DUMP_SECURITY_CIPHER_LIBRARY = 0x032D,
	IOT_DUMP_SECURITY_ECDH_INIT = 0x0330,
	IOT_DUMP_SECURITY_ECDH_DEINIT = 0x0331,
	IOT_DUMP_SECURITY_ECDH_SET_PARAMS = 0x0332,
	IOT_DUMP_SECURITY_ECDH_SHARED_SECRET = 0x0333,
	IOT_DUMP_SECURITY_ECDH_PARAMS_NULL = 0x0334,
	IOT_DUMP_SECURITY_ECDH_LIBRARY = 0x0335,
	IOT_DUMP_SECURITY_ECDH_INVALID_PUBKEY = 0x0336,
	IOT_DUMP_SECURITY_ECDH_INVALID_SECKEY = 0x0337,
	IOT_DUMP_SECURITY_KEY_INVALID_ID = 0x0340,
	IOT_DUMP_SECURITY_KEY_CONVERT = 0x0341,
	IOT_DUMP_SECURITY_KEY_NO_PERMISSION = 0x0342,
	IOT_DUMP_SECURITY_KEY_NOT_FOUND = 0x0343,
	IOT_DUMP_SECURITY_MANAGER_INIT = 0x0350,
	IOT_DUMP_SECURITY_MANAGER_DEINIT = 0x0351,
	IOT_DUMP_SECURITY_MANAGER_KEY_GET = 0x0352,
	IOT_DUMP_SECURITY_MANAGER_KEY_SET = 0x0353,
	IOT_DUMP_SECURITY_MANAGER_CERT_GET = 0x0354,
	IOT_DUMP_SECURITY_MANAGER_CERT_SET = 0x0355,
	IOT_DUMP_SECURITY_MANAGER_SN_GET = 0x0356,
	IOT_DUMP_SECURITY_MANAGER_KEY_GENERATE = 0x0357,
	IOT_DUMP_SECURITY_MANAGER_KEY_REMOVE = 0x0358,
	IOT_DUMP_SECURITY_CERT_INVALID_ID = 0x0359,
	IOT_DUMP_SECURITY_STORAGE_INIT = 0x0360,
	IOT_DUMP_SECURITY_STORAGE_DEINIT = 0x0361,
	IOT_DUMP_SECURITY_STORAGE_READ = 0x0362,
	IOT_DUMP_SECURITY_STORAGE_WRITE = 0x0363,
	IOT_DUMP_SECURITY_STORAGE_REMOVE = 0x0364,
	IOT_DUMP_SECURITY_STORAGE_PARAMS_NULL = 0x0365,
	IOT_DUMP_SECURITY_STORAGE_INVALID_ID = 0x0366,
	IOT_DUMP_SECURITY_FS_OPEN = 0x0370,
	IOT_DUMP_SECURITY_FS_READ = 0x0371,
	IOT_DUMP_SECURITY_FS_WRITE = 0x0372,
	IOT_DUMP_SECURITY_FS_CLOSE = 0x0373,
	IOT_DUMP_SECURITY_FS_REMOVE = 0x0374,
	IOT_DUMP_SECURITY_FS_BUFFER = 0x0375,
	IOT_DUMP_SECURITY_FS_ENCRYPT = 0x0376,
	IOT_DUMP_SECURITY_FS_DECRYPT = 0x0377,
	IOT_DUMP_SECURITY_FS_NOT_FOUND = 0x0378,
	IOT_DUMP_SECURITY_FS_INVALID_ARGS = 0x0379,
	IOT_DUMP_SECURITY_FS_INVALID_TARGET = 0x037A,
	IOT_DUMP_SECURITY_FS_UNKNOWN_TARGET = 0x037B,
	IOT_DUMP_SECURITY_BSP_FN_LOAD_NULL = 0x0380,
	IOT_DUMP_SECURITY_BSP_FN_STORE_NULL = 0x0381,
	IOT_DUMP_SECURITY_BSP_FN_REMOVE_NULL = 0x0382,
	IOT_DUMP_SECURITY_SHA256 = 0x0390,
	IOT_DUMP_SECURITY_BASE64_ENCODE = 0x03A0,
	IOT_DUMP_SECURITY_BASE64_DECODE = 0x03A1,
	IOT_DUMP_SECURITY_BASE64_URL_ENCODE = 0x03A2,
	IOT_DUMP_SECURITY_BASE64_URL_DECODE = 0x03A3,
	IOT_DUMP_SECURITY_MEM_ALLOC = 0x03F0,
	IOT_DUMP_SECURITY_INVALID_ARGS = 0x03F1,
	IOT_DUMP_UTIL_BASE = 0x0400,
	/* Client Common */
	IOT_DUMP_EASYSETUP_400_BASE = 0x0500, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_INVALID_CMD = 0x0501, /* arg1: line number, arg2: cmd number */
	IOT_DUMP_EASYSETUP_INVALID_REQUEST = 0x0502, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_INVALID_SEQUENCE = 0x0503, /* arg1: line number, arg2: cmd number */
	IOT_DUMP_EASYSETUP_NOT_SUPPORTED = 0x0504, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR = 0x0505, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_AES256_DECRYPTION_ERROR = 0x0506, /* arg1: line number, arg2: err number */
	/* Key Info */
	IOT_DUMP_EASYSETUP_RAND_DECODE_ERROR = 0x0511, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_INVALID_TIME = 0x0512, /* arg1: line number, arg2: err number */
	/* Otm */
	IOT_DUMP_EASYSETUP_INVALID_QR = 0x0521, /* arg1: line number, arg2: 0 for qr, 1 for serial number */
	IOT_DUMP_EASYSETUP_INVALID_SERIAL_NUMBER = 0x0522, /* arg1: line number, arg2: 0 for qr, 1 for serial number */
	IOT_DUMP_EASYSETUP_INVALID_PIN = 0x0523, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_PIN_NOT_MATCHED = 0x0524, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_OTMTYPE_JUSTWORK = 0x0525, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_OTMTYPE_QR = 0x0526, /* arg1: line number, arg2: 0 for qr, 1 for serial number */
	IOT_DUMP_EASYSETUP_OTMTYPE_BUTTON = 0x0527, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_OTMTYPE_PIN = 0x0528, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_OTMTYPE_NOT_SUPPORTED = 0x0529, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_REPORTED_OTMTYPE = 0x052A, /* arg1: line number, arg2: return value */
	/* Wifi provisioning */
	IOT_DUMP_EASYSETUP_INVALID_MAC = 0x0531, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_INVALID_BROKER_URL = 0x0532, /* arg1: line number, arg2: err number */
	/* Server Common */
	IOT_DUMP_EASYSETUP_500_BASE = 0x0540, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR = 0x0541, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR = 0x0542, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR = 0x0543, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_BASE64_ENCODE_ERROR = 0x0544, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_AES256_ENCRYPTION_ERROR = 0x0545, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_FAILED_CREATE_LOG = 0x0546, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_WAIT_RESPONSE = 0x0547, /* arg1: line number, arg2: cmd number */
	IOT_DUMP_EASYSETUP_CMD_SUCCESS = 0x0548, /* arg1: line number, arg2: cmd number */
	IOT_DUMP_EASYSETUP_CMD_FAIL = 0x0549, /* arg1: line number, arg2: cmd number */
	IOT_DUMP_EASYSETUP_INIT = 0x054A, /* arg1: line number, arg2: 0 for start, 1 for end */
	IOT_DUMP_EASYSETUP_DEINIT = 0x054B, /* arg1: line number, arg2: 0 for start, 1 for end */
	IOT_DUMP_EASYSETUP_CIPHER_ERROR = 0x054C, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_CIPHER_ALIGN_ERROR = 0x054D, /* arg1: line number, arg2: cipher type */
	IOT_DUMP_EASYSETUP_CIPHER_PARAMS_ERROR = 0x054E, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_QUEUE_FAIL = 0x054C, /* arg1: line number, arg2: 0 for recv, 1 for send */
	/* Key Info */
	IOT_DUMP_EASYSETUP_SHARED_KEY_INIT_FAIL = 0x0551, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SHARED_KEY_CREATION_FAIL = 0x0552, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_MASTER_SECRET_GENERATION_SUCCESS = 0x0553, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_SHARED_KEY_PARAMS_FAIL = 0x0554, /* arg1: line number, arg2: err number */
	/* Otm */
	IOT_DUMP_EASYSETUP_CONFIRM_NOT_SUPPORT = 0x0561, /* arg1: line number, arg2: return value */
	IOT_DUMP_EASYSETUP_CONFIRM_TIMEOUT = 0x0562, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_SERIAL_NOT_FOUND = 0x0563, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_CONFIRM_DENIED = 0x0564, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_PIN_NOT_FOUND = 0x0565, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM = 0x0566, /* arg1: line number, arg2: 0 */
	/* Wifi provisioning */
	IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND = 0x0571, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_WIFI_DATA_WRITE_FAIL = 0x0572, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_WIFI_DATA_READ_FAIL = 0x0573, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_CLOUD_DATA_WRITE_FAIL = 0x0574, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_LOOKUPID_GENERATE_FAIL = 0x0575, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_WIFI_NOT_DISCOVERED = 0x0576, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_WIFI_INVALID_PASSWORD = 0x0577, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_WIFI_INVALID_SSID = 0x0578, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_WIFI_INVALID_BSSID = 0x0579, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_SERIAL_NUMBER_GET_FAIL = 0x057A, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_PROVISIONING_SUCCESS = 0x057B, /* arg1: line number, arg2: 0 */
	/* Registration */
	IOT_DUMP_EASYSETUP_REGISTER_FAILED_REGISTRATION  = 0x0581, /* arg1: line number, arg2: 0 */
	/* Certificate */
	IOT_DUMP_EASYSETUP_CETIFICATE_FAILED_GET_CERTIFICATE = 0x0589, /* arg1: line number, arg2: 0 */
	/* tcp */
	IOT_DUMP_EASYSETUP_TCP_INIT = 0x0591, /* arg1: line number, arg2: 0 for start, 1 for end */
	IOT_DUMP_EASYSETUP_TCP_DEINIT = 0x0592, /* arg1: line number, arg2: 0 for start, 1 for end */
	IOT_DUMP_EASYSETUP_SOCKET_CREATE_FAIL = 0x0593, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SOCKET_BIND_FAIL = 0x0594, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SOCKET_LISTEN_FAIL = 0x0595, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SOCKET_ACCEPT_FAIL = 0x0596, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL = 0x0597, /* arg1: line number, arg2: err number */
	IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE = 0x0598, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL = 0x0599, /* arg1: line number, arg2: return value */
	IOT_DUMP_EASYSETUP_SOCKET_SHUTDOWN = 0x059A, /* arg1: line number, arg2: return value */
	/* Logging */
	IOT_DUMP_EASYSETUP_CREATE_LOGDUMP_FAIL = 0x05A1, /* arg1: line number, arg2: 0 */
	IOT_DUMP_EASYSETUP_CREATE_SUMODUMP_FAIL = 0x05A2, /* arg1: line number, arg2: 0 */
	IOT_DUMP_NV_DATA_BASE = 0x600,
	IOT_DUMP_NV_DATA_READ_FAIL = 0x601, /* arg1: enum iot_nvd_t, arg2: line number */
	IOT_DUMP_NV_DATA_WRITE_FAIL = 0x602, /* arg1: enum iot_nvd_t, arg2: line number */
	IOT_DUMP_NV_DATA_ERASE_FAIL = 0x603, /* arg1: enum iot_nvd_t, arg2: line number */
	IOT_DUMP_NV_DATA_NOT_EXIST = 0x604, /* arg1: enum iot_nvd_t, arg2: line number */
	IOT_DUMP_BSP_WIFI_BASE = 0x0700,
	IOT_DUMP_BSP_WIFI_INIT_SUCCESS = 0x0701,
	IOT_DUMP_BSP_WIFI_INIT_FAIL = 0x0702, /* arg1: return code(rc), arg2: line number */
	IOT_DUMP_BSP_WIFI_SETMODE = 0x0703, /* arg1: configuration mode(conf->mode) */
	IOT_DUMP_BSP_WIFI_SETMODE_FAIL = 0x0704, /* arg1: configuration mode(conf->mode),  arg2: return code(rc) */
	IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS = 0x0705,
	IOT_DUMP_BSP_WIFI_CONNECT_FAIL = 0x0706, /* arg1: connect timeout, arg2: error code*/
	IOT_DUMP_BSP_WIFI_SNTP_SUCCESS = 0x0707, /* arg1: current time,  arg2: retry count */
	IOT_DUMP_BSP_WIFI_SNTP_FAIL = 0x0708, /* arg1: retry count,  arg2: max retry */
	IOT_DUMP_BSP_WIFI_TIMEOUT = 0x0709, /* arg1: wifi mode, arg2: line number*/
	IOT_DUMP_BSP_WIFI_ERROR = 0x070A, /* arg1: wifi mode, arg2: line number*/
	IOT_DUMP_BSP_WIFI_EVENT_AUTH = 0x070B, /* arg1: rssi*/
	IOT_DUMP_BSP_WIFI_EVENT_DEAUTH = 0x070C, /* arg1: deauth reason*/

	IOT_DUMP_BSP_BASE = 0x1000,

	IOT_DUMP_EXAMPLE_BASE = 0xff00,
	IOT_DUMP_EXAMPLE_HELLO_WORLD = 0xff01,
	IOT_DUMP_EXAMPLE_COMMENT = 0xff02, /* decoder copies comment to output */
} dump_log_id_t;

#ifdef __cplusplus
}
#endif

#endif /* _IOT_DUMP_LOG_H_ */
