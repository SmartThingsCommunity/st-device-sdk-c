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

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_UTIL_easysetup_common.h"
#include "cmocka_custom.h"
#include "iot_debug.h"
#include "iot_error.h"
#include "iot_internal.h"
#include "iot_main.h"
#include "iot_os_util.h"
#include "iot_util.h"

#define UNUSED(x) (void **)(x)

extern iot_error_t _iot_easysetup_con_timer_init(struct iot_context *ctx);

static struct iot_context *g_test_context = NULL;

int TC_iot_easysetup_ble_setup(void **state)
{
    iot_error_t err;

    // Use the common setup
    TC_iot_easysetup_common_setup(state);

    g_test_context = (struct iot_context *)*state;

    // Initialize BLE related fields
    g_test_context->es_ble_ready = false;
    g_test_context->ble_connected = false;
    g_test_context->cloud_con_timer = NULL;

    return 0;
}

int TC_iot_easysetup_ble_teardown(void **state)
{
    // Use the common teardown
    return TC_iot_easysetup_common_teardown(state);
}

/**
 * @brief Test _iot_easysetup_con_timer_init success case
 */
void TC_iot_easysetup_con_timer_init_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: cloud_con_timer is NULL
    ctx->cloud_con_timer = NULL;

    // When: _iot_easysetup_con_timer_init is called
    err = _iot_easysetup_con_timer_init(ctx);

    // Then: should return IOT_ERROR_NONE and timer should be created
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx->cloud_con_timer);
}

/**
 * @brief Test _iot_easysetup_con_timer_init with existing timer
 */
void TC_iot_easysetup_con_timer_init_with_existing_timer(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_error_t err;

    // Given: cloud_con_timer already exists
    ctx->cloud_con_timer = NULL;

    // First call to create a timer
    err = _iot_easysetup_con_timer_init(ctx);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx->cloud_con_timer);

    // When: _iot_easysetup_con_timer_init is called again
    err = _iot_easysetup_con_timer_init(ctx);

    // Then: should return IOT_ERROR_NONE and timer should be replaced
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx->cloud_con_timer);
}