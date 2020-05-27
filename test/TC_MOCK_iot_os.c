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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


#define MAX_MOCKED_IOT_OS_MALLOC_IN_TC 10
static unsigned int _mock_malloc_failure_index;
static bool _mock_iot_os_malloc_failure_at[MAX_MOCKED_IOT_OS_MALLOC_IN_TC];
static bool _mock_iot_os_malloc_start;
static bool _mock_detect_memory_leak;

void set_mock_iot_os_malloc_failure_with_index(unsigned int index)
{
    assert_in_range(index, 0, MAX_MOCKED_IOT_OS_MALLOC_IN_TC - 1);
    _mock_iot_os_malloc_failure_at[index] = true;
    _mock_iot_os_malloc_start = true;
}

void set_mock_iot_os_malloc_failure()
{
    for (int i = 0; i < MAX_MOCKED_IOT_OS_MALLOC_IN_TC; i++) {
        _mock_iot_os_malloc_failure_at[i] = true;
    }
    _mock_iot_os_malloc_start = true;
}

void do_not_use_mock_iot_os_malloc_failure()
{
    for (int i = 0; i < MAX_MOCKED_IOT_OS_MALLOC_IN_TC; i++) {
        _mock_iot_os_malloc_failure_at[i] = false;
    }
    _mock_malloc_failure_index = 0;
    _mock_iot_os_malloc_start = false;
}

void *__wrap_iot_os_malloc(size_t size)
{
    if (_mock_iot_os_malloc_start && _mock_iot_os_malloc_failure_at[_mock_malloc_failure_index]) {
        if (++_mock_malloc_failure_index >= MAX_MOCKED_IOT_OS_MALLOC_IN_TC ) {
            _mock_malloc_failure_index = MAX_MOCKED_IOT_OS_MALLOC_IN_TC - 1;
        }
        return NULL;
    }
    else if (_mock_iot_os_malloc_start && !_mock_iot_os_malloc_failure_at[_mock_malloc_failure_index]){
        if (++_mock_malloc_failure_index >= MAX_MOCKED_IOT_OS_MALLOC_IN_TC ) {
            _mock_malloc_failure_index = MAX_MOCKED_IOT_OS_MALLOC_IN_TC - 1;
        }
        if (_mock_detect_memory_leak)
            return test_malloc(size);
        else
            return malloc(size);
    } else {
        if (_mock_detect_memory_leak)
            return test_malloc(size);
        else
            return malloc(size);
    }
}

void __wrap_iot_os_free(void* ptr)
{
    if (_mock_detect_memory_leak)
        return test_free(ptr);
    else
        return free(ptr);
}

void *__wrap_iot_os_realloc(void* ptr, size_t size)
{
    if (_mock_detect_memory_leak)
        return test_realloc(ptr, size);
    else
        return realloc(ptr, size);
}

void *__wrap_iot_os_strdup(const char *src)
{
    if (_mock_detect_memory_leak) {
        char *dest;
        size_t size = strlen(src) + 1;

        dest = test_malloc(size);
        if (dest) {
            memcpy(dest, src, size);
        }
        return dest;
    } else {
        return strdup(src);
    }
}

void set_mock_detect_memory_leak(bool detect)
{
    _mock_detect_memory_leak = detect;
}

void __wrap_iot_os_delay(unsigned int delay_ms)
{
    check_expected(delay_ms);
}