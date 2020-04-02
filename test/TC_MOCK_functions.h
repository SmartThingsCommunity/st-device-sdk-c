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

void set_mock_iot_os_malloc_failure_with_index(unsigned int index);
void set_mock_iot_os_malloc_failure();
void do_not_use_mock_iot_os_malloc_failure();
void set_mock_detect_memory_leak(bool detect);

void set_mock_net_read_buffer_pointer(unsigned int index, unsigned int offset, unsigned int count);
void reset_mock_net_read_buffer_pointer_index(void);

#endif //ST_DEVICE_SDK_C_TC_MOCK_FUNCTIONS_H
