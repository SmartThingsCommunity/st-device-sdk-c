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
#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif
#include "../easysetup_http.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"

#define PORT 8888
#define RX_BUFFER_MAX    1024

static char *tx_buffer = NULL;

static iot_os_thread es_tcp_task_handle = NULL;

static int listen_sock = -1;
static int accept_sock = -1;
static int deinit_processing = 0;

static void _clear_sockets(void)
{
	if (listen_sock != -1) {
		IOT_INFO("close listen socket");
		close(listen_sock);
		listen_sock = -1;
	}

	// if http deinit before ST app reset tcp connection, we need close it here
	if (accept_sock != -1) {
		IOT_INFO("close accept socket");
		close(accept_sock);
		accept_sock = -1;
	}
}

static int _process_accept_socket(int sock)
{
	char rx_buffer[RX_BUFFER_MAX];
	int rx_buffer_len = 0;
	int http_request_header_len = 0;
	iot_error_t err = IOT_ERROR_NONE;
	size_t content_len = 0;

	char *payload;
	int ret, len, type, cmd;

 	// set tcp keepalive related opts 
	// if ST app WiFi disconnect coincidentally during easysetup, 
	// we need short time tcp keepalive here.
	int keep_alive = 1;
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));

	int idle = 10;
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));

	int interval = 5;
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));

	int maxpkt = 3;
	setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int));


	// HTTP response as tcp payload is sent once, and mostly less than MTU.
	// There is no need for tcp packet coalesced.
	// To enhance throughput, disable TCP Nagle's algorithm here.
	int no_delay = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(int));

	while (1)
	{
		// start to process one http request
		http_request_header_len = -1;
		memset(rx_buffer, '\0', sizeof(rx_buffer));
		rx_buffer_len = 0;
		content_len = 0;
        
		// ensure complete http request header before es_msg_parser
		do {
			len = recv(sock, rx_buffer + rx_buffer_len, sizeof(rx_buffer) - rx_buffer_len - 1, 0);

			if (len < 0) {
				if (!deinit_processing) {
					IOT_ERROR("recv failed: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
				}
				return -1;
			}
			else if (len == 0) {
				IOT_ERROR("Connection closed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
				return -1;
			}
			else {
				rx_buffer_len += len;
			}

			// \r\n\r\n  header end
			for (int i = 0; i < rx_buffer_len; i++) {
				if (i < rx_buffer_len - 3) {
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
				len = recv(sock, rx_buffer + rx_buffer_len, sizeof(rx_buffer) - rx_buffer_len - 1, 0);

				if (len < 0) {
					IOT_ERROR("recv failed: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
					return -1;
				}
				else if (len == 0) {
					IOT_ERROR("Connection closed");
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
					return -1;
				}
				else {
					rx_buffer_len += len;
				}
			} while (rx_buffer_len < (http_request_header_len + content_len));

			payload = rx_buffer + http_request_header_len;
		}
        

		if(err == IOT_ERROR_INVALID_ARGS)
			http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
		else
			http_msg_handler(cmd, &tx_buffer, type, payload);

		if (!tx_buffer) {
			IOT_ERROR("tx_buffer is NULL");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
			return -1;
		}

		len = strlen((char *)tx_buffer);
		tx_buffer[len] = 0;

		ret = send(sock, tx_buffer, len, 0);
		free(tx_buffer);
		tx_buffer = NULL;
		if (ret < 0) {
			IOT_ERROR("Error is occurred during sending: errno %d", ret);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL, ret);
			return -1;
		}
	}

	return 0;
}

static void es_tcp_task(void *pvParameters)
{
	int addr_family, ip_protocol, ret;
	struct sockaddr_in sourceAddr;
	uint addrLen;

	while (!deinit_processing) {
		int opt = 1;
		struct sockaddr_in destAddr;
		destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		destAddr.sin_family = AF_INET;
		destAddr.sin_port = htons(PORT);
		addr_family = AF_INET;
		ip_protocol = IPPROTO_IP;

		listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
		if (listen_sock < 0) {
			IOT_ERROR("Unable to create socket: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CREATE_FAIL, errno);
			break;
		}

		ret = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		if (ret != 0) {
			IOT_INFO("reuse socket isn't supported");
		}

		ret = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
		if (ret != 0) {
			IOT_ERROR("Socket unable to bind: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_BIND_FAIL, errno);
			break;
		}

		ret = listen(listen_sock, 1);
		if (ret != 0) {
			IOT_ERROR("Error occurred during listen: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_LISTEN_FAIL, errno);
			break;
		}

		while (1) {
			addrLen = sizeof(sourceAddr);

			accept_sock = accept(listen_sock, (struct sockaddr *)&sourceAddr, &addrLen);
			if (accept_sock < 0) {
				if (!deinit_processing) {
					IOT_ERROR("Unable to accept connection: errno %d", errno);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_ACCEPT_FAIL, errno);
				}
				break;
			}

			_process_accept_socket(accept_sock);

			if (!deinit_processing && accept_sock != -1)
			{
				close(accept_sock);
				accept_sock = -1;
			}
		}

		//sock resources should be clean
		if (!deinit_processing) {
			_clear_sockets();
		}
	}

	if (!deinit_processing) {
		_clear_sockets();
	}

	/*set es_tcp_task_handle to null, prevent dulicate delete in es_tcp_deinit*/
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

	deinit_processing = 1;
	//sock resources should be clean
	_clear_sockets();

	if (es_tcp_task_handle) {
		iot_os_thread_delete(es_tcp_task_handle);
		es_tcp_task_handle = NULL;
	}

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	deinit_processing = 0;
	IOT_INFO("http tcp deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}

