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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <iot_error.h>
#include <iot_bsp_wifi.h>
#include <stdbool.h>

iot_error_t __wrap_iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
    unsigned char *mock_mac;
    if (wifi_mac == NULL) {
        return IOT_ERROR_INVALID_ARGS;
    }

    mock_mac = mock_ptr_type(unsigned char *);
    if (mock_mac != NULL) {
        memcpy(wifi_mac->addr, mock_mac, IOT_WIFI_MAX_BSSID_LEN);
    }
    return mock_type(iot_error_t);
}

static bool _use_mocked_malloc;
void set_mock_malloc_failure(bool use_mock)
{
    _use_mocked_malloc = use_mock;
}

void * __real_malloc(size_t size);
void *__wrap_malloc(size_t size)
{
    if (_use_mocked_malloc)
        return NULL;
    else
        return __real_malloc(size);
}