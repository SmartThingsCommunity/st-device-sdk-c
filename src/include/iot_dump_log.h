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

#define IOT_DUMP_MODE_NEED_BASE64 (1<<0)
#define IOT_DUMP_MODE_NEED_DUMP_STATE (1<<1)

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
    int dummy;
    char os_name[16];
    char os_version[16];
    char bsp_name[16];
    char bsp_version[16];
    char firmware_version[16];
    char model_number[16];
    char manufacturer_name[16];
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
	IOT_DUMP_MQTT_PING_FAIL = 0x0104,
	IOT_DUMP_MQTT_CONNECT_NETWORK_FAIL = 0x0105,
	IOT_DUMP_MQTT_CONNECT_RESULT = 0x0106, /* arg1: return code(rc), arg2: keepalive interval */
	IOT_DUMP_MQTT_SEND_FAIL = 0x0107, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_CYCLE_FAIL = 0x0108, /* arg1: return code(rc), arg2: received packet type */
	IOT_DUMP_MQTT_DISCONNECT = 0x0109, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_PUBLISH = 0x010A, /* arg1: return code(rc), arg2: packet id */
	IOT_DUMP_MQTT_UNSUBSCRIBE = 0x010B, /* arg1: return code(rc) */
	IOT_DUMP_MQTT_SUBSCRIBE = 0x010C, /* arg1: return code(rc) */
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
	IOT_DUMP_CRYPYO_BASE = 0x0300,
	IOT_DUMP_UTIL_BASE = 0x0400,
	/* Client Common */
	IOT_DUMP_EASYSETUP_400_BASE = 0x0500,
	IOT_DUMP_EASYSETUP_INVALID_CMD = 0x0501,
	IOT_DUMP_EASYSETUP_INVALID_REQUEST = 0x0502,
	IOT_DUMP_EASYSETUP_INVALID_SEQUENCE = 0x0503,
	IOT_DUMP_EASYSETUP_NOT_SUPPORTED = 0x0504,
	IOT_DUMP_EASYSETUP_BASE64_DECODE_ERROR = 0x0505,
	IOT_DUMP_EASYSETUP_AES256_DECRYPTION_ERROR = 0x0506,
	/* Key Info */
	IOT_DUMP_EASYSETUP_RAND_DECODE_ERROR = 0x0511,
	IOT_DUMP_EASYSETUP_INVALID_TIME = 0x0512,
	/* Otm */
	IOT_DUMP_EASYSETUP_INVALID_QR = 0x0521,
	IOT_DUMP_EASYSETUP_INVALID_SERIAL_NUMBER = 0x0522,
	IOT_DUMP_EASYSETUP_INVALID_PIN = 0x0523,
	IOT_DUMP_EASYSETUP_PIN_NOT_MATCHED = 0x0524,
	IOT_DUMP_EASYSETUP_OTMTYPE_JUSTWORK = 0x0525,
	IOT_DUMP_EASYSETUP_OTMTYPE_QR = 0x0526,
	IOT_DUMP_EASYSETUP_OTMTYPE_BUTTON = 0x0527,
	IOT_DUMP_EASYSETUP_OTMTYPE_PIN = 0x0528,
	IOT_DUMP_EASYSETUP_OTMTYPE_NOT_SUPPORTED = 0x0529,
	IOT_DUMP_EASYSETUP_REPORTED_OTMTYPE = 0x052A,
	/* Wifi provisioning */
	IOT_DUMP_EASYSETUP_INVALID_MAC = 0x0531,
	IOT_DUMP_EASYSETUP_INVALID_BROKER_URL = 0x0532,
	/* Server Common */
	IOT_DUMP_EASYSETUP_500_BASE = 0x0540,
	IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR = 0x0541,
	IOT_DUMP_EASYSETUP_JSON_CREATE_ERROR = 0x0542,
	IOT_DUMP_EASYSETUP_MEM_ALLOC_ERROR = 0x0543,
	IOT_DUMP_EASYSETUP_BASE64_ENCODE_ERROR = 0x0544,
	IOT_DUMP_EASYSETUP_AES256_ENCRYPTION_ERROR = 0x0545,
	IOT_DUMP_EASYSETUP_FAILED_CREATE_LOG = 0x0546,
	IOT_DUMP_EASYSETUP_WAIT_RESPONSE = 0x0547,
	IOT_DUMP_EASYSETUP_CMD_SUCCESS = 0x0548,
	IOT_DUMP_EASYSETUP_CMD_FAIL = 0x0549,
	IOT_DUMP_EASYSETUP_INIT = 0x054A,
	IOT_DUMP_EASYSETUP_DEINIT = 0x054B,
	IOT_DUMP_EASYSETUP_CIPHER_ERROR = 0x054C,
	IOT_DUMP_EASYSETUP_CIPHER_ALIGN_ERROR = 0x054D,
	IOT_DUMP_EASYSETUP_CIPHER_PARAMS_ERROR = 0x054E,
	IOT_DUMP_EASYSETUP_QUEUE_FAIL = 0x054C, /* arg1: line number, arg2: 0 for recv, 1 for send */
	/* Key Info */
	IOT_DUMP_EASYSETUP_SHARED_KEY_INIT_FAIL = 0x0551,
	IOT_DUMP_EASYSETUP_SHARED_KEY_CREATION_FAIL = 0x0552,
	IOT_DUMP_EASYSETUP_MASTER_SECRET_GENERATION_SUCCESS = 0x0553,
	IOT_DUMP_EASYSETUP_SHARED_KEY_PARAMS_FAIL = 0x0554,
	/* Otm */
	IOT_DUMP_EASYSETUP_CONFIRM_NOT_SUPPORT = 0x0561,
	IOT_DUMP_EASYSETUP_CONFIRM_TIMEOUT = 0x0562,
	IOT_DUMP_EASYSETUP_SERIAL_NOT_FOUND = 0x0563,
	IOT_DUMP_EASYSETUP_CONFIRM_DENIED = 0x0564,
	IOT_DUMP_EASYSETUP_PIN_NOT_FOUND = 0x0565,
	IOT_DUMP_EASYSETUP_GET_OWNER_CONFIRM = 0x0566,
	/* Wifi provisioning */
	IOT_DUMP_EASYSETUP_WIFI_SCAN_NOT_FOUND = 0x0571,
	IOT_DUMP_EASYSETUP_WIFI_DATA_WRITE_FAIL = 0x0572,
	IOT_DUMP_EASYSETUP_WIFI_DATA_READ_FAIL = 0x0573,
	IOT_DUMP_EASYSETUP_CLOUD_DATA_WRITE_FAIL = 0x0574,
	IOT_DUMP_EASYSETUP_LOOKUPID_GENERATE_FAIL = 0x0575,
	IOT_DUMP_EASYSETUP_WIFI_NOT_DISCOVERED = 0x0576,
	IOT_DUMP_EASYSETUP_WIFI_INVALID_PASSWORD = 0x0577,
	IOT_DUMP_EASYSETUP_WIFI_INVALID_SSID = 0x0578,
	IOT_DUMP_EASYSETUP_WIFI_INVALID_BSSID = 0x0579,
	IOT_DUMP_EASYSETUP_PROVISIONING_SUCCESS = 0x057A,
	/* Registration */
	IOT_DUMP_EASYSETUP_REGISTER_FAILED_REGISTRATION  = 0x0581,
	/* Certificate */
	IOT_DUMP_EASYSETUP_CETIFICATE_FAILED_GET_CERTIFICATE = 0x0589,
	/* tcp */
	IOT_DUMP_EASYSETUP_TCP_INIT = 0x0591,
	IOT_DUMP_EASYSETUP_TCP_DEINIT = 0x0592,
	IOT_DUMP_EASYSETUP_SOCKET_CREATE_FAIL = 0x0593,
	IOT_DUMP_EASYSETUP_SOCKET_BIND_FAIL = 0x0594,
	IOT_DUMP_EASYSETUP_SOCKET_LISTEN_FAIL = 0x0595,
	IOT_DUMP_EASYSETUP_SOCKET_ACCEPT_FAIL = 0x0596,
	IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL = 0x0597,
	IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE = 0x0598,
	IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL = 0x0599,
	IOT_DUMP_EASYSETUP_SOCKET_SHUTDOWN = 0x059A,
	/* Logging */
	IOT_DUMP_EASYSETUP_CREATE_LOGDUMP_FAIL = 0x05A1,
	IOT_DUMP_EASYSETUP_CREATE_SUMODUMP_FAIL = 0x05A2,
	IOT_DUMP_NV_DATA_BASE = 0x600,
	IOT_DUMP_NV_DATA_READ_FAIL = 0x601,
	IOT_DUMP_NV_DATA_WRITE_FAIL = 0x602,
	IOT_DUMP_NV_DATA_ERASE_FAIL = 0x603,
	IOT_DUMP_NV_DATA_NOT_EXIST = 0x604,
	IOT_DUMP_BSP_WIFI_BASE = 0x0700,
	IOT_DUMP_BSP_WIFI_INIT_SUCCESS = 0x0701,
	IOT_DUMP_BSP_WIFI_INIT_FAIL = 0x0702, /* arg1: return code(rc), arg2: line number */
	IOT_DUMP_BSP_WIFI_SETMODE = 0x0703, /* arg1: configuration mode(conf->mode) */
	IOT_DUMP_BSP_WIFI_SETMODE_FAIL = 0x0704, /* arg1: configuration mode(conf->mode),  arg2: return code(rc) */
	IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS = 0x0705,
	IOT_DUMP_BSP_WIFI_CONNECT_FAIL = 0x0706, /* arg1: connect timeout, arg2: line number*/
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

/**
 * @brief create all_log_dump
 * @param[in] iot_ctx - iot_core context
 * @param[out] log_dump_output - a pointer of not allocated pointer for log dump buffer.
 *         it will allocated in this function
 * @param[in] max_log_dump_size - maximum size of log dump.
 * @param[out] allocated_size - allocated memory size of log_dump_output
 * @param[in] log_mode - log mode generated by OR operation of following values
 *    IOT_DUMP_MODE_NEED_BASE64 : make log encoded to base64
 *    IOT_DUMP_MODE_NEED_DUMP_STATE : add dump state in log
 * @retval IOT_ERROR_NONE success
 *
 * @warning must free log_dump_output after using it.
 */
iot_error_t iot_dump_create_all_log_dump(struct iot_context *iot_ctx, char **log_dump_output, size_t max_log_dump_size, size_t *allocated_size, int log_mode);

#endif /* _IOT_DUMP_LOG_H_ */
