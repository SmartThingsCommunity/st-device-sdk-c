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

#include <string.h>

#ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_USE_SOCKET_API
#include "iot_easysetup_http_socket.h"
#endif
#include "../easysetup_http.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"

#define RX_BUFFER_MAX    1024

static char *tx_buffer = NULL;
static iot_os_thread es_tcp_task_handle = NULL;
static HTTP_CONN_H es_http_conn_handle;
static bool deinit_processing;

static void process_accepted_connection(HTTP_CONN_H handle)
{
	char rx_buffer[RX_BUFFER_MAX];
	iot_error_t err = IOT_ERROR_NONE;
	size_t content_len = 0;
	char *payload;
	int i, type, cmd;
	ssize_t len;

	http_try_configure_connection(handle);

	while (1)
	{
		size_t received_len = 0;
		size_t tx_buffer_len = 0;
		ssize_t http_request_header_len = -1;

		// start to process one http request
		memset(rx_buffer, '\0', sizeof(rx_buffer));
		content_len = 0;
        
		// ensure complete http request header before es_msg_parser
		do {
			len = http_recv_data(handle, rx_buffer, sizeof(rx_buffer), received_len);
			if (len < 0) {
				if (!deinit_processing) {
					IOT_ERROR("recv failed: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
				}
				return;
			}
			else if (len == 0) {
				IOT_ERROR("Connection closed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
				return;
			}
			else {
				received_len += len;
			}

			// \r\n\r\n  header end
			for (i = 0; i < received_len; i++) {
				if (i < received_len - 3) {
					if ((rx_buffer[i] == '\r') && (rx_buffer[i + 1] == '\n') && (rx_buffer[i + 2] == '\r')
						&& (rx_buffer[i + 3] == '\n')) {
						http_request_header_len = i + 4;
					}
				}
			} 
		} while (http_request_header_len < 0);

		err = es_msg_parser(rx_buffer, sizeof(rx_buffer), &payload, &cmd, &type, &content_len);

		if ((err == IOT_ERROR_NONE) && (type == D2D_POST)
				&& payload && (content_len > strlen((char *)payload)))
		{
			do {
				len = http_recv_data(handle, rx_buffer, sizeof(rx_buffer), received_len);
				if (len < 0) {
					IOT_ERROR("recv failed: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
					return;
				}
				else if (len == 0) {
					IOT_ERROR("Connection closed");
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
					return;
				}
				else {
					received_len += len;
				}
			} while (received_len < (http_request_header_len + content_len));

			payload = rx_buffer + http_request_header_len;
		}

		if(err == IOT_ERROR_INVALID_ARGS)
			http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
		else
			http_msg_handler(cmd, &tx_buffer, type, payload);

		if (!tx_buffer) {
			IOT_ERROR("tx_buffer is NULL");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
			return;
		}

		tx_buffer_len = strlen((char *)tx_buffer);
		tx_buffer[tx_buffer_len] = 0;

		len = http_send_data(handle, tx_buffer, tx_buffer_len);
		free(tx_buffer);
		tx_buffer = NULL;
		if (len < 0) {
			IOT_ERROR("Error is occurred during sending: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL, errno);
			return;
		}
	}
}

static void es_tcp_task(void *pvParameters)
{
	iot_error_t err;

	while (!deinit_processing) {
		err = http_initialize_connection(&es_http_conn_handle);
		if (err != IOT_ERROR_NONE) {
			break;
		}

		while (1) {
			err = http_accept_connection(&es_http_conn_handle);
			if (err != IOT_ERROR_NONE) {
				if (!deinit_processing) {
					IOT_ERROR("Unable to accept connection: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_ACCEPT_FAIL, errno);
					IOT_ERROR("accept failed %d", err);
				}
				break;
			}

			process_accepted_connection(es_http_conn_handle);

			if (!deinit_processing && !is_http_conn_handle_initialized(es_http_conn_handle))
			{
				http_cleanup_accepted_connection(&es_http_conn_handle);
			}
		}

		//sock resources should be clean
		if (!deinit_processing) {
			http_cleanup_all_connection(&es_http_conn_handle);
		}
	}

	if (!deinit_processing) {
		http_cleanup_all_connection(&es_http_conn_handle);
	}

	/*set es_tcp_task_handle to null, prevent duplicate delete in es_tcp_deinit*/
	es_tcp_task_handle = NULL;
	iot_os_thread_delete(NULL);
}



void es_http_init(void)
{
	IOT_INFO("http tcp init!!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 0);
	iot_os_thread_create(es_tcp_task, "es_tcp_task", (1024 * 4), NULL, 5, (iot_os_thread * const)(&es_tcp_task_handle));
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 1);
}

void es_http_deinit(void)
{
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 0);

	deinit_processing = true;
	//sock resources should be clean
	http_cleanup_all_connection(&es_http_conn_handle);

	if (es_tcp_task_handle) {
		iot_os_thread_delete(es_tcp_task_handle);
		es_tcp_task_handle = NULL;
	}

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	deinit_processing = false;
	IOT_INFO("http tcp deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}

