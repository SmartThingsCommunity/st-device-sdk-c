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
	IOT_DUMP_MQTT_BASE = 0x0100,
	IOT_DUMP_CAPABILITY_BASE = 0x0200,
	IOT_DUMP_CRYPYO_BASE = 0x0300,
	IOT_DUMP_UTIL_BASE = 0x0400,
	IOT_DUMP_EASYSETUP_BASE = 0x0500,

	IOT_DUMP_BSP_BASE = 0x1000,

	IOT_DUMP_EXAMPLE_BASE = 0xff00,
	IOT_DUMP_EXAMPLE_HELLO_WORLD = 0xff01,
	IOT_DUMP_EXAMPLE_COMMENT = 0xff02, /* decoder copies comment to output */
}dump_log_id_t;

#endif /* _IOT_DUMP_LOG_H_ */
