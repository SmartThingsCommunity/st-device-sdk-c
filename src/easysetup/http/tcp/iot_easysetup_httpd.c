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
#include <sys/types.h>
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"
#include "../easysetup_http.h"
#include "port_net.h"

#define RX_BUFFER_MAX    1024

static char *tx_buffer = NULL;
static iot_os_thread es_tcp_task_handle = NULL;
static PORT_NET_CONTEXT es_http_conn_handle = NULL;
static bool deinit_processing;

static bool is_es_http_deinit_processing(void)
{
	return deinit_processing;
}
static void es_http_deinit_processing_set(bool flag)
{
	deinit_processing = flag;
}

static iot_error_t http_packet_read(PORT_NET_CONTEXT handle, char *rx_buffer, size_t rx_buffer_size, size_t *received_len,
							 size_t *http_header_len)
{
	ssize_t len;
	size_t existing_len;
	int header_position = -1;
	int i;

	if (handle == NULL || rx_buffer == NULL || received_len == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}
	existing_len = *received_len;
	// ensure complete http request header before es_msg_parser
	do {
		len = port_net_read(handle, rx_buffer + existing_len, rx_buffer_size - existing_len - 1);
		if (len < 0) {
			if (!is_es_http_deinit_processing()) {
				IOT_ERROR("recv failed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, 0);
			}
			return IOT_ERROR_EASYSETUP_HTTP_RECV_FAIL;
		}
		else if (len == 0) {
			IOT_WARN("peer connection closed");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_WARN, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
			return IOT_ERROR_EASYSETUP_HTTP_PEER_CONN_CLOSED;
		}
		else {
			existing_len += len;
		}

		// \r\n\r\n  header end
		for (i = 0; i < existing_len; i++) {
			if (i < existing_len - 3) {
				if ((rx_buffer[i] == '\r') && (rx_buffer[i + 1] == '\n') && (rx_buffer[i + 2] == '\r')
					&& (rx_buffer[i + 3] == '\n')) {
					header_position = i + 4;
					break;
				}
			}
		}
	} while (header_position < 0);

	*received_len = existing_len;
	*http_header_len = header_position;

	return IOT_ERROR_NONE;
}

static iot_error_t http_packet_read_remaining(PORT_NET_CONTEXT handle, char *rx_buffer, size_t rx_buffer_size, size_t offset,
									   size_t expected_len)
{
	ssize_t len;
	size_t total_recv_len = offset;

	if (handle == NULL || rx_buffer == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}
	do {
		len = port_net_read(handle, rx_buffer + offset, rx_buffer_size - offset - 1);
		if (len < 0) {
			IOT_ERROR("recv failed");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, 0);
			return IOT_ERROR_EASYSETUP_HTTP_RECV_FAIL;
		}
		else if (len == 0) {
			IOT_ERROR("peer connection closed");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
			return IOT_ERROR_EASYSETUP_HTTP_PEER_CONN_CLOSED;
		}
		else {
			total_recv_len += len;
		}
	} while (total_recv_len < expected_len);

	return IOT_ERROR_NONE;
}

static int process_accepted_connection(PORT_NET_CONTEXT handle)
{
	char rx_buffer[RX_BUFFER_MAX];
	iot_error_t err = IOT_ERROR_NONE;
	size_t content_len = 0;
	char *payload;
	int type, cmd;
	ssize_t len;

	while (1)
	{
		size_t received_len = 0;
		size_t tx_buffer_len = 0;
		size_t http_request_header_len = 0;

		// start to process one http request
		memset(rx_buffer, '\0', sizeof(rx_buffer));

		err = http_packet_read(handle, rx_buffer, sizeof(rx_buffer), &received_len, &http_request_header_len);
		if (err != IOT_ERROR_NONE) {
			if (!is_es_http_deinit_processing() && err != IOT_ERROR_EASYSETUP_HTTP_PEER_CONN_CLOSED) {
				IOT_ERROR("failed to read http packet %d", err);
			}
			return err;
		}

		content_len = 0;
		err = es_msg_parser(rx_buffer, sizeof(rx_buffer), &payload, &cmd, &type, &content_len);

		if ((err == IOT_ERROR_NONE) && (type == D2D_POST)
				&& payload && (content_len > strlen((char *)payload)))
		{
			iot_error_t ret;
			ret = http_packet_read_remaining(handle, rx_buffer, sizeof(rx_buffer), received_len, http_request_header_len + content_len);
			if (ret != IOT_ERROR_NONE) {
				IOT_ERROR("failed to read remaining http packet %d", ret);
				return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
			}
			payload = rx_buffer + http_request_header_len;
		}

		if(err != IOT_ERROR_NONE) {
			http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
		}
		else {
			http_msg_handler(cmd, &tx_buffer, type, payload);
		}

		if (!tx_buffer) {
			IOT_ERROR("tx_buffer is NULL");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
			return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}

		tx_buffer_len = strlen((char *)tx_buffer);
		tx_buffer[tx_buffer_len] = 0;

		len = port_net_write(handle, tx_buffer, tx_buffer_len);
		free(tx_buffer);
		tx_buffer = NULL;
		if (len < 0) {
			IOT_ERROR("Error is occurred during sending");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL, 0);
			return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		}
	}
}

static void es_tcp_task(void *pvParameters)
{
	while (!is_es_http_deinit_processing()) {
		IOT_INFO("Listening http conneciton");
		if (es_http_conn_handle) {
			port_net_free(es_http_conn_handle);
			es_http_conn_handle = NULL;
		}
		es_http_conn_handle = port_net_listen("8888", NULL);
		if (es_http_conn_handle) {
			process_accepted_connection(es_http_conn_handle);
		}
	}

	if (es_http_conn_handle) {
		port_net_free(es_http_conn_handle);
		es_http_conn_handle = NULL;
	}

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	/*set es_tcp_task_handle to null, prevent duplicate delete in es_tcp_deinit*/
	es_tcp_task_handle = NULL;
	iot_os_thread_delete(NULL);
}



void es_http_init(void)
{
	IOT_INFO("http tcp init!!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 0);
	if (es_tcp_task_handle) {
		IOT_ERROR("Previous tcp thread still working!");
		return;
	}
	es_http_deinit_processing_set(false);
	iot_os_thread_create(es_tcp_task, "es_tcp_task", (1024 * 4), NULL, 5, (iot_os_thread * const)(&es_tcp_task_handle));
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 1);
}

void es_http_deinit(void)
{
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 0);
	es_http_deinit_processing_set(true);
	IOT_INFO("http tcp deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}
