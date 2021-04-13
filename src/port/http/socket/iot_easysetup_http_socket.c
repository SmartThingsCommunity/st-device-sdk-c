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
#include "iot_easysetup_http_impl.h"
#include "iot_easysetup.h"

#define HTTP_PORT 8888

bool is_http_conn_handle_initialized(HTTP_CONN_H *handle)
{
	if ((handle == NULL) || (handle->accept_sock == CONN_HANDLE_UNINITIALIZED) ||
			(handle->listen_sock == CONN_HANDLE_UNINITIALIZED)) {
		return false;
	}
	return true;
}

void http_cleanup_all_connection(HTTP_CONN_H *handle)
{
	if (handle == NULL) {
		return;
	}

	if (handle->listen_sock != CONN_HANDLE_UNINITIALIZED) {
		IOT_INFO("close listen socket");
		close(handle->listen_sock);
		handle->listen_sock = CONN_HANDLE_UNINITIALIZED;
	}

	// if http deinit before ST app reset tcp connection, we need close it here
	if (handle->accept_sock != CONN_HANDLE_UNINITIALIZED) {
		IOT_INFO("close accept socket");
		close(handle->accept_sock);
		handle->accept_sock = CONN_HANDLE_UNINITIALIZED;
	}
}

void http_cleanup_accepted_connection(HTTP_CONN_H *handle)
{
	if (handle == NULL) {
		return;
	}
	if (handle->accept_sock != CONN_HANDLE_UNINITIALIZED) {
		IOT_INFO("close accept socket");
		close(handle->accept_sock);
		handle->accept_sock = CONN_HANDLE_UNINITIALIZED;
	}
}

ssize_t http_packet_send(HTTP_CONN_H *handle, char *tx_buffer, size_t tx_buffer_len)
{
	int len;

	if (handle == NULL || is_http_conn_handle_initialized(handle) == false) {
		return -1;
	}
	if (tx_buffer == NULL) {
		return -1;
	}

	len = send(handle->accept_sock, tx_buffer, tx_buffer_len, 0);
	return len;
}

iot_error_t http_packet_read(HTTP_CONN_H *handle, char *rx_buffer, size_t rx_buffer_size, size_t *received_len,
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
		len = recv(handle->accept_sock, rx_buffer + existing_len, rx_buffer_size - existing_len - 1, 0);
		if (len < 0) {
			if (!is_es_http_deinit_processing()) {
				IOT_ERROR("recv failed: errno %d", errno);
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
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

iot_error_t http_packet_read_remaining(HTTP_CONN_H *handle, char *rx_buffer, size_t rx_buffer_size, size_t offset,
									   size_t expected_len)
{
	ssize_t len;
	size_t total_recv_len = offset;

	if (handle == NULL || rx_buffer == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}
	do {
		len = recv(handle->accept_sock, rx_buffer + offset, rx_buffer_size - offset - 1, 0);
		if (len < 0) {
			IOT_ERROR("recv failed: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
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

void http_try_configure_connection(HTTP_CONN_H *handle)
{
	int ret;

	if (handle == NULL || is_http_conn_handle_initialized(handle) == false) {
		return;
	}
	// set tcp keepalive related opts
	// if ST app WiFi disconnect coincidentally during easysetup,
	// we need short time tcp keepalive here.
	int keep_alive = 1;
	ret = setsockopt(handle->accept_sock, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
	if (ret < 0) {
		IOT_INFO("socket set keep-alive failed %d", errno);
	}

	int idle = 10;
	ret = setsockopt(handle->accept_sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));
	if (ret < 0) {
		IOT_INFO("socket set keep-idle failed %d", errno);
	}

	int interval = 5;
	ret = setsockopt(handle->accept_sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
	if (ret < 0) {
		IOT_INFO("socket set keep-interval failed %d", errno);
	}

	int maxpkt = 3;
	ret = setsockopt(handle->accept_sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int));
	if (ret < 0) {
		IOT_INFO("socket set keep-count failed %d", errno);
	}

	// HTTP response as tcp payload is sent once, and mostly less than MTU.
	// There is no need for tcp packet coalesced.
	// To enhance throughput, disable TCP Nagle's algorithm here.
	int no_delay = 1;
	ret = setsockopt(handle->accept_sock, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(int));
	if (ret < 0) {
		IOT_INFO("socket set no-delay failed %d", errno);
	}
}

iot_error_t http_initialize_connection(HTTP_CONN_H *handle)
{
	int addr_family, ip_protocol, ret;
	int opt = 1;
	struct sockaddr_in destAddr;
	destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(HTTP_PORT);
	addr_family = AF_INET;
	ip_protocol = IPPROTO_IP;
	int listen_sock;

	if (handle == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	handle->listen_sock = CONN_HANDLE_UNINITIALIZED;
	handle->accept_sock = CONN_HANDLE_UNINITIALIZED;

	listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
	if (listen_sock < 0) {
		IOT_ERROR("Unable to create socket: errno %d", errno);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CREATE_FAIL, errno);
		return IOT_ERROR_CONNECT_FAIL;
	}

	ret = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret != 0) {
		IOT_INFO("reuse socket isn't supported");
	}

	ret = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
	if (ret != 0) {
		IOT_ERROR("Socket unable to bind: errno %d", errno);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_BIND_FAIL, errno);
		close(listen_sock);
		return IOT_ERROR_CONNECT_FAIL;
	}

	ret = listen(listen_sock, 1);
	if (ret != 0) {
		IOT_ERROR("Error occurred during listen: errno %d", errno);
		IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_LISTEN_FAIL, errno);
		close(listen_sock);
		return IOT_ERROR_CONNECT_FAIL;
	}

	handle->listen_sock = listen_sock;

	return IOT_ERROR_NONE;
}

iot_error_t http_accept_connection(HTTP_CONN_H *handle)
{
	struct sockaddr_in source_addr;
	uint addr_len;
	int sock;

	if (handle == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}
	addr_len = sizeof(source_addr);

	sock = accept(handle->listen_sock, (struct sockaddr *)&source_addr, &addr_len);
	if (sock < 0) {
		return IOT_ERROR_CONNECT_FAIL;
	}
	handle->accept_sock = sock;
	return IOT_ERROR_NONE;
}