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
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "easysetup_ble.h"
#include "iot_bsp_ble.h"

#define RX_BUFFER_MAX    512

static uint8_t *tx_buffer = NULL;
static iot_os_thread es_ble_task_handle = NULL;
static bool deinit_processing;

extern struct iot_context *context;

bool msg_assemble(uint8_t *buf, uint32_t len);

bool is_es_ble_deinit_processing(void)
{
	return deinit_processing;
}
void es_ble_deinit_processing_set(bool flag)
{
	deinit_processing = flag;
}
static uint32_t g_write_callback_len = 0;
static uint8_t g_write_cmd_num = 0;
static uint32_t g_check_process = 0;

static char rx_buffer[RX_BUFFER_MAX];

void msg_dispatch(uint8_t *buf, uint32_t len, uint8_t cmd_num)
{
    g_check_process = 1;
    g_write_callback_len = len;
    memcpy(rx_buffer,buf,len);
    g_write_cmd_num = cmd_num;
}

static int process_accepted_connection(void *handle)
{
	iot_error_t err = IOT_ERROR_NONE;
	size_t content_len = 0;
	size_t len;
	char *payload;
	int type, cmd;
    int i;
    
	while (1)
	{
		size_t tx_buffer_len = 0;

        while (1) {
			iot_os_delay(10);
			if (g_check_process) {
				len = g_write_callback_len;
				g_check_process = 0;
				break;
			}
		}
		content_len = 0;

		err = es_msg_parser(rx_buffer, len, g_write_cmd_num, &payload, &cmd, &type, &content_len);

		if(err != IOT_ERROR_NONE) {
			type = D2D_ERROR;
        }

		rx_buffer[len]=0;
		ble_msg_handler(cmd, &tx_buffer, type, rx_buffer);

		if (!tx_buffer) {
			IOT_ERROR("tx_buffer is NULL");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
			return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}

		tx_buffer_len = strlen((char *)tx_buffer);

		tx_buffer[tx_buffer_len] = 0;

		iot_send_indication(tx_buffer, tx_buffer_len);
		
		free(tx_buffer);
		tx_buffer = NULL;
	}
}

static void es_ble_task(void *pvParameters)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	iot_err = iot_easysetup_create_ble_advertise_packet(context);
	if (iot_err != IOT_ERROR_NONE) {
	    IOT_ERROR("Can't create ble advertise packet for easysetup.(%d)", iot_err);
		return;
	}

	iot_bsp_ble_init(msg_assemble);

	while (!is_es_ble_deinit_processing()) {
	    process_accepted_connection(NULL);
	}

	/*set es_ble_task_handle to null, prevent duplicate delete in es_ble_deinit*/
	es_ble_task_handle = NULL;
	iot_os_thread_delete(NULL);
}


void es_ble_init()
{
	IOT_INFO("ble init!!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 0);
	iot_os_thread_create(es_ble_task, "es_ble_task", (1024 * 4), NULL, 5, (iot_os_thread * const)(&es_ble_task_handle));
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

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	es_ble_deinit_processing_set(false);
	IOT_INFO("ble deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}

