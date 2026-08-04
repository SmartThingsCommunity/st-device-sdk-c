/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#ifndef ST_DEVICE_SDK_C_TC_MOCK_FUNCTIONS_H
#define ST_DEVICE_SDK_C_TC_MOCK_FUNCTIONS_H

#include <stdbool.h>

#include "iot_error.h"

void set_mock_iot_os_malloc_failure_with_index(unsigned int index);
void set_mock_iot_os_malloc_failure();
void do_not_use_mock_iot_os_malloc_failure();
void set_mock_iot_os_realloc_failure(bool fail);
void set_mock_detect_memory_leak(bool detect);

void set_mock_iot_bsp_fs_open_failure(iot_error_t err);
void set_mock_iot_bsp_fs_read_failure(iot_error_t err);
void set_mock_iot_bsp_fs_write_failure(iot_error_t err);
void set_mock_iot_bsp_fs_close_failure(iot_error_t err);
void set_mock_iot_bsp_fs_remove_failure(iot_error_t err);
void set_mock_port_net_write_failure(int failure);
void set_mock_port_net_write_skip_buf_check(int skip);
void set_mock_port_net_write_skip_len_check(int skip);
void reset_mock_port_net_write_skip_flags(void);

void port_net_mock_reset_read_stream(unsigned char *read_stream, size_t size);
void port_net_mock_reset_socket_status(int status);

#endif  // ST_DEVICE_SDK_C_TC_MOCK_FUNCTIONS_H
