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

#ifndef ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_H
#define ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_H

#include "iot_easysetup_http_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

iot_error_t http_initialize_connection(HTTP_CONN_H *handle);
iot_error_t http_accept_connection(HTTP_CONN_H *handle);
void http_try_configure_connection(HTTP_CONN_H *handle);
iot_error_t http_packet_read(HTTP_CONN_H *handle, char *rx_buffer, size_t rx_buffer_size,
							 size_t *received_len, size_t *http_header_len);
iot_error_t http_packet_read_remaining(HTTP_CONN_H *handle, char *rx_buffer,size_t rx_buffer_size,
									   size_t offset, size_t expected_len);
ssize_t http_packet_send(HTTP_CONN_H *handle, char *tx_buffer, size_t tx_buffer_len);
bool is_http_conn_handle_initialized(HTTP_CONN_H *handle);

void http_cleanup_all_connection(HTTP_CONN_H *handle);
void http_cleanup_accepted_connection(HTTP_CONN_H *handle);

#ifdef __cplusplus
}
#endif

#endif //ST_DEVICE_SDK_C_IOT_EASYSETUP_HTTP_H
