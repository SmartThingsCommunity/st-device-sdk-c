/* ***************************************************************************
 *
 * Copyright (c) 2026 Samsung Electronics All Rights Reserved.
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
#include "TC_MOCK_iot_es.h"

#include "iot_internal.h"
#include "iot_main.h"

static int mock_es_connect_use_wrap = 0;
static iot_error_t mock_es_connect_result = IOT_ERROR_NONE;
static int mock_es_connect_call_count = 0;

static int mock_es_disconnect_use_wrap = 0;
static iot_error_t mock_es_disconnect_result = IOT_ERROR_NONE;
static int mock_es_disconnect_call_count = 0;

void tc_mock_es_set_connect_use_wrap(int use_wrap)
{
    mock_es_connect_use_wrap = use_wrap;
}

void tc_mock_es_set_connect_result(iot_error_t err)
{
    mock_es_connect_result = err;
}

int tc_mock_es_get_connect_call_count(void)
{
    return mock_es_connect_call_count;
}

void tc_mock_es_reset_connect(void)
{
    mock_es_connect_use_wrap = 0;
    mock_es_connect_result = IOT_ERROR_NONE;
    mock_es_connect_call_count = 0;
}

iot_error_t __real_iot_es_connect(struct iot_context *ctx, int conn_type);

iot_error_t __wrap_iot_es_connect(struct iot_context *ctx, int conn_type)
{
    mock_es_connect_call_count++;
    if (!mock_es_connect_use_wrap) {
        return __real_iot_es_connect(ctx, conn_type);
    }
    return mock_es_connect_result;
}

void tc_mock_es_set_disconnect_use_wrap(int use_wrap)
{
    mock_es_disconnect_use_wrap = use_wrap;
}

void tc_mock_es_set_disconnect_result(iot_error_t err)
{
    mock_es_disconnect_result = err;
}

int tc_mock_es_get_disconnect_call_count(void)
{
    return mock_es_disconnect_call_count;
}

void tc_mock_es_reset_disconnect(void)
{
    mock_es_disconnect_use_wrap = 0;
    mock_es_disconnect_result = IOT_ERROR_NONE;
    mock_es_disconnect_call_count = 0;
}

iot_error_t __real_iot_es_disconnect(struct iot_context *ctx, int conn_type);

iot_error_t __wrap_iot_es_disconnect(struct iot_context *ctx, int conn_type)
{
    mock_es_disconnect_call_count++;
    if (!mock_es_disconnect_use_wrap) {
        return __real_iot_es_disconnect(ctx, conn_type);
    }
    return mock_es_disconnect_result;
}
