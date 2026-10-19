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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cmocka_custom.h"
#include "iot_os_util.h"

#define MAX_MOCKED_IOT_OS_MALLOC_IN_TC 10
static unsigned int _mock_malloc_failure_index;
static bool _mock_iot_os_malloc_failure_at[MAX_MOCKED_IOT_OS_MALLOC_IN_TC];
static bool _mock_iot_os_malloc_start;
static bool _mock_detect_memory_leak;
static bool _mock_iot_os_realloc_failure;
static bool _mock_iot_os_strdup_failure;

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
        if (++_mock_malloc_failure_index >= MAX_MOCKED_IOT_OS_MALLOC_IN_TC) {
            _mock_malloc_failure_index = MAX_MOCKED_IOT_OS_MALLOC_IN_TC - 1;
        }
        return NULL;
    } else if (_mock_iot_os_malloc_start && !_mock_iot_os_malloc_failure_at[_mock_malloc_failure_index]) {
        if (++_mock_malloc_failure_index >= MAX_MOCKED_IOT_OS_MALLOC_IN_TC) {
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

void __wrap_iot_os_free(void *ptr)
{
    if (_mock_detect_memory_leak)
        return test_free(ptr);
    else
        return free(ptr);
}

void set_mock_iot_os_realloc_failure(bool fail)
{
    _mock_iot_os_realloc_failure = fail;
}

void *__wrap_iot_os_realloc(void *ptr, size_t size)
{
    if (_mock_iot_os_realloc_failure) {
        return NULL;
    }
    if (_mock_detect_memory_leak)
        return test_realloc(ptr, size);
    else
        return realloc(ptr, size);
}

void set_mock_iot_os_strdup_failure(bool fail)
{
    _mock_iot_os_strdup_failure = fail;
}

void *__wrap_iot_os_strdup(const char *src)
{
    if (_mock_iot_os_strdup_failure) {
        return NULL;
    }
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
    struct timespec ts = {
        0,
    };

    ts.tv_sec = delay_ms / 1000;
    ts.tv_nsec = (delay_ms % 1000) * 1000000;

    nanosleep(&ts, NULL);
}

/* Fail-at-Nth-call injection for OS primitives that allocate with libc malloc
 * and therefore cannot be driven through the iot_os_malloc failure index. */
#define MOCK_NO_FAILURE (-1)

static int _mock_eventgroup_create_fail_at = MOCK_NO_FAILURE;
static int _mock_eventgroup_create_count;
static int _mock_mutex_init_fail_at = MOCK_NO_FAILURE;
static int _mock_mutex_init_count;
static int _mock_thread_create_fail_at = MOCK_NO_FAILURE;
static int _mock_thread_create_count;

void set_mock_iot_os_eventgroup_create_failure_at(int index)
{
    _mock_eventgroup_create_fail_at = index;
    _mock_eventgroup_create_count = 0;
}

void do_not_use_mock_iot_os_eventgroup_create_failure(void)
{
    _mock_eventgroup_create_fail_at = MOCK_NO_FAILURE;
    _mock_eventgroup_create_count = 0;
}

iot_os_eventgroup *__real_iot_os_eventgroup_create(void);

iot_os_eventgroup *__wrap_iot_os_eventgroup_create(void)
{
    if (_mock_eventgroup_create_fail_at == _mock_eventgroup_create_count++) {
        return NULL;
    }
    return __real_iot_os_eventgroup_create();
}

void set_mock_iot_os_mutex_init_failure_at(int index)
{
    _mock_mutex_init_fail_at = index;
    _mock_mutex_init_count = 0;
}

void do_not_use_mock_iot_os_mutex_init_failure(void)
{
    _mock_mutex_init_fail_at = MOCK_NO_FAILURE;
    _mock_mutex_init_count = 0;
}

int __real_iot_os_mutex_init(iot_os_mutex *mutex);

int __wrap_iot_os_mutex_init(iot_os_mutex *mutex)
{
    if (_mock_mutex_init_fail_at == _mock_mutex_init_count++) {
        return IOT_OS_FALSE;
    }
    return __real_iot_os_mutex_init(mutex);
}

void set_mock_iot_os_thread_create_failure_at(int index)
{
    _mock_thread_create_fail_at = index;
    _mock_thread_create_count = 0;
}

void do_not_use_mock_iot_os_thread_create_failure(void)
{
    _mock_thread_create_fail_at = MOCK_NO_FAILURE;
    _mock_thread_create_count = 0;
}

int __real_iot_os_thread_create(void *thread_function, const char *name, int stack_size, void *data, int priority,
                                iot_os_thread *thread_handle);

int __wrap_iot_os_thread_create(void *thread_function, const char *name, int stack_size, void *data, int priority,
                                iot_os_thread *thread_handle)
{
    if (_mock_thread_create_fail_at == _mock_thread_create_count++) {
        return IOT_OS_FALSE;
    }
    return __real_iot_os_thread_create(thread_function, name, stack_size, data, priority, thread_handle);
}
