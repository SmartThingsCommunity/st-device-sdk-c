/* ***************************************************************************
 *
 * Copyright 2020-2021 Samsung Electronics All Rights Reserved.
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

#include <string.h>
#include "easysetup_ble.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "easysetup_ble.h"
#include "iot_bsp_ble.h"

#define RX_BUFFER_MAX    512

static bool deinit_processing;
static char rx_buffer[RX_BUFFER_MAX];
static iot_os_thread es_ble_task_handle = NULL;
static uint32_t g_check_process = 0;
static uint32_t g_write_callback_len = 0;
static uint8_t g_write_cmd_num = 0;

extern struct iot_context *context;

static bool is_es_ble_deinit_processing(void)
{
	return deinit_processing;
}
void es_ble_deinit_processing_set(bool flag)
{
	deinit_processing = flag;
}

void es_msg_dispatch(iot_security_buffer_t *buf, uint8_t buf_count, uint8_t cmd_num)
{
	g_check_process = 1;
	g_write_cmd_num = cmd_num;
	g_write_callback_len = buf[0].len;
	memcpy(rx_buffer,buf[0].p,buf[0].len);
	if (buf_count > 1) {
		// Not actually used
		// If there is a use case, need to be changed rx_buffer
		// to iot_security_buffer array data structure
		IOT_ERROR("Received data is too large.");
	}
}

static int _es_process_accepted_connection(void *handle)
{
	iot_error_t err = IOT_ERROR_NONE;
	size_t len;
	int cmd;

	while (1) {
		iot_os_delay(10);
		if (g_check_process) {
			len = g_write_callback_len;
			g_check_process = 0;
			IOT_INFO("ble event reported");
			break;
		}
	}

	cmd = g_write_cmd_num - 1;

	rx_buffer[len] = 0;

	iot_easysetup_ble_msg_handler(cmd, rx_buffer, g_write_callback_len);

	return err;
}

static void _es_ble_task(void *pvParameters)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	iot_err = iot_easysetup_create_ble_advertise_packet(context);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't create ble advertise packet for easysetup.(%d)", iot_err);
		goto exit_task;
	}

	iot_bsp_ble_init(es_msg_assemble);

	while (!is_es_ble_deinit_processing()) {
		_es_process_accepted_connection(NULL);
	}

exit_task:
	/*set es_ble_task_handle to null, prevent duplicate delete in es_ble_deinit*/
	es_ble_task_handle = NULL;
	iot_os_thread_delete(NULL);
}


void es_ble_init()
{
	IOT_INFO("ble init!!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 0);
	iot_os_thread_create(_es_ble_task, "es_ble_task", (1024 * 4), NULL, 5, (iot_os_thread * const)(&es_ble_task_handle));
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 1);
}

void es_ble_deinit(void)
{
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 0);

	es_ble_deinit_processing_set(true);

	if (es_ble_task_handle) {
		iot_os_thread_delete(es_ble_task_handle);
		es_ble_task_handle = NULL;
	}

	es_ble_deinit_processing_set(false);

	iot_bsp_ble_deinit();
	IOT_INFO("ble deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}

