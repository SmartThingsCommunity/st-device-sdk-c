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

#ifdef __cplusplus
extern "C" {
#endif

#define DUMP_LOG_VERSION 0

typedef enum {
	IOT_DUMP_MAIN_BASE = 0x0000,
	IOT_DUMP_MAIN_COMMAND = 0x0001,
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
	IOT_DUMP_EASYSETUP_BASE = 0x0500,

	IOT_DUMP_BSP_BASE = 0x1000,

	IOT_DUMP_EXAMPLE_BASE = 0xff00,
	IOT_DUMP_EXAMPLE_HELLO_WORLD = 0xff01,
	IOT_DUMP_EXAMPLE_COMMENT = 0xff02, /* decoder copies comment to output */
}dump_log_id_t;

#endif /* _IOT_DUMP_LOG_H_ */
