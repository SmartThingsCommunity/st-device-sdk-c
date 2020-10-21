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

#ifndef ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_SOCKET_H
#define ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_SOCKET_H

#include <sys/socket.h>
#include <errno.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#include "iot_debug.h"

typedef struct {
	int listen_sock;
	int accept_sock;
} HTTP_CONN_H;

#define CONN_HANDLE_UNINITIALIZED	(-1)

iot_error_t http_initialize_connection(HTTP_CONN_H *handle);
iot_error_t http_accept_connection(HTTP_CONN_H *handle);
void http_try_configure_connection(HTTP_CONN_H handle);
int http_recv_data(HTTP_CONN_H handle, char *rx_buffer, size_t rx_buffer_size, size_t received_len);
int http_send_data(HTTP_CONN_H handle, char *tx_buffer, size_t tx_buffer_len);
bool is_http_conn_handle_initialized(HTTP_CONN_H handle);

void http_cleanup_all_connection(HTTP_CONN_H *handle);
void http_cleanup_accepted_connection(HTTP_CONN_H *handle);

#endif //ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_SOCKET_H
