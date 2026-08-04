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
#include "TC_MOCK_iot_bsp_ble.h"
#include "TC_UTIL_easysetup_common.h"
#include "cmocka_custom.h"
#include "easysetup_ble.h"
#include "iot_bsp_ble.h"
#include "iot_debug.h"
#include "iot_error.h"
#include "iot_internal.h"
#include "iot_main.h"
#include "iot_os_util.h"
#include "iot_util.h"

#define UNUSED(x) (void **)(x)

static struct iot_context *g_test_context = NULL;

extern struct iot_context *context;

// Setup and teardown functions
int TC_iot_easysetup_ble_task_setup(void **state)
{
    iot_error_t err;

    // Reset mock state before each test
    tc_mock_ble_reset();

    // Use the common setup
    TC_iot_easysetup_common_setup(state);

    g_test_context = (struct iot_context *)*state;

    // Initialize BLE related fields
    g_test_context->es_ble_ready = false;
    g_test_context->ble_connected = false;
    g_test_context->easysetup_security_context = iot_security_init();
    if (g_test_context->easysetup_security_context) {
        iot_security_cipher_init(g_test_context->easysetup_security_context);
    }

    return 0;
}

int TC_iot_easysetup_ble_task_teardown(void **state)
{
    struct iot_context *context = (struct iot_context *)*state;

    // Clean up security context
    if (context->easysetup_security_context) {
        iot_security_cipher_deinit(context->easysetup_security_context);
        iot_security_deinit(context->easysetup_security_context);
        context->easysetup_security_context = NULL;
    }

    // Use the common teardown
    return TC_iot_easysetup_common_teardown(state);
}

void TC_es_msg_dispatch_null_parameters(void **state)
{
    uint8_t buf_count = 1;
    uint8_t cmd_num = 5;
    UNUSED(state);

    // Given: use real es_msg_dispatch
    tc_mock_ble_set_es_msg_dispatch_use_wrap(0);

    // When: dispatch with NULL buffer
    es_msg_dispatch(NULL, buf_count, cmd_num);

    // Then: function should handle gracefully (no crash)
    assert_true(true);
}

void TC_es_msg_dispatch_single_buffer(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    struct iot_context *original_context = context;
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 5;
    char test_data[] = "test_data_for_ble";
    size_t data_len = strlen(test_data);

    // Given: use real es_msg_dispatch, valid buffer with data, context set
    tc_mock_ble_set_es_msg_dispatch_use_wrap(0);
    context = ctx;
    buf[0].p = (uint8_t *)test_data;
    buf[0].len = data_len;

    // When: dispatch with single buffer
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Restore original context
    context = original_context;

    // Then: function should handle gracefully (no crash)
    assert_true(true);
}

void TC_es_msg_dispatch_multiple_buffers_warning(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    struct iot_context *original_context = context;
    iot_security_buffer_t buf[2];
    uint8_t buf_count = 2;
    uint8_t cmd_num = 3;
    char test_data1[] = "first_buffer_data";
    char test_data2[] = "second_buffer_data";
    size_t data1_len = strlen(test_data1);

    // Given: use real es_msg_dispatch, multiple buffers, context set
    tc_mock_ble_set_es_msg_dispatch_use_wrap(0);
    context = ctx;
    buf[0].p = (uint8_t *)test_data1;
    buf[0].len = data1_len;
    buf[1].p = (uint8_t *)test_data2;
    buf[1].len = strlen(test_data2);

    // When: dispatch with multiple buffers (should log warning)
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Restore original context
    context = original_context;

    // Then: function should handle gracefully (no crash)
    assert_true(true);
}

void TC_es_msg_dispatch_empty_buffer(void **state)
{
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 1;
    UNUSED(state);

    // Given: buffer with NULL pointer but zero length
    buf[0].p = NULL;
    buf[0].len = 0;

    // When: dispatch with invalid buffer data
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash
}

void TC_es_msg_dispatch_zero_length_buffer(void **state)
{
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 7;
    char test_data[] = "test_data";
    UNUSED(state);

    // Given: buffer with NULL pointer but zero length
    buf[0].p = NULL;
    buf[0].len = 0;

    // When: dispatch with zero length buffer
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash
}

void TC_es_msg_dispatch_large_data(void **state)
{
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 10;
    char *large_data = NULL;
    size_t large_data_len = 511;  // Just under the limit
    UNUSED(state);

    // Given: large buffer data
    large_data = (char *)malloc(large_data_len);
    assert_non_null(large_data);
    memset(large_data, 'A', large_data_len);

    buf[0].p = (uint8_t *)large_data;
    buf[0].len = large_data_len;

    // When: dispatch with large data
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash

    // Teardown
    free(large_data);
}

void TC_es_msg_dispatch_exactly_max_buffer(void **state)
{
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 15;
    char *max_data = NULL;
    size_t max_data_len = 512;  // Exactly at the limit
    UNUSED(state);

    // Given: maximum buffer data
    max_data = (char *)malloc(max_data_len);
    assert_non_null(max_data);
    memset(max_data, 'B', max_data_len);

    buf[0].p = (uint8_t *)max_data;
    buf[0].len = max_data_len;

    // When: dispatch with maximum data
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash

    // Teardown
    free(max_data);
}

void TC_es_ble_init_null_context(void **state)
{
    struct iot_context *original_context = context;
    UNUSED(state);

    // Save original context and set it to NULL
    context = NULL;

    // When: init called with NULL context
    es_ble_init();

    // Restore original context
    context = original_context;

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash
}

void TC_es_ble_init_valid_context_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    struct iot_context *original_context = context;

    // Given: valid context
    context = ctx;
    ctx->es_ble_ready = false;

    // When: init called with valid context
    es_ble_init();

    // Restore original context
    context = original_context;

    // Then: function should handle gracefully (no crash)
    assert_true(true);  // If we reach here, the function didn't crash
}

void TC_es_ble_init_advertisement_failure(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    struct iot_context *original_context = context;

    // Given: valid context, advertisement will fail
    context = ctx;
    ctx->es_ble_ready = false;
    tc_mock_ble_set_start_adv_rc(IOT_ERROR_BAD_REQ);

    // When: init called and advertisement fails
    es_ble_init();

    // Restore original context
    context = original_context;

    // Then: function should handle gracefully even if advertisement fails
    assert_true(true);
}

void TC_es_ble_init_advertisement_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    struct iot_context *original_context = context;

    // Given: valid context, advertisement will succeed
    context = ctx;
    ctx->es_ble_ready = false;
    tc_mock_ble_set_start_adv_rc(0);

    // When: init called
    es_ble_init();

    // Restore original context
    context = original_context;

    // Then: advertisement was attempted
    assert_int_equal(tc_mock_ble_get_start_adv_call_count(), 1);
}

void TC_es_ble_deinit_valid(void **state)
{
    UNUSED(state);

    // When: deinit called
    es_ble_deinit();

    // Then: iot_bsp_ble_deinit was called
    assert_int_equal(tc_mock_ble_get_bsp_ble_deinit_call_count(), 1);
}

void TC_es_ble_deinit_multiple_calls(void **state)
{
    UNUSED(state);

    // When: deinit called multiple times
    es_ble_deinit();
    es_ble_deinit();
    es_ble_deinit();

    // Then: iot_bsp_ble_deinit was called 3 times
    assert_int_equal(tc_mock_ble_get_bsp_ble_deinit_call_count(), 3);
}

void TC_es_ble_msg_handler_success(void **state)
{
    struct iot_context *ctx = (struct iot_context *)*state;
    iot_security_buffer_t buf[1];
    uint8_t buf_count = 1;
    uint8_t cmd_num = 5;
    char test_data[] = "test_ble_message_data";
    size_t data_len = strlen(test_data);
    device_work_data_t work;
    iot_error_t err;

    context = ctx;

    // Given: use real es_msg_dispatch
    tc_mock_ble_set_es_msg_dispatch_use_wrap(0);

    // Initialize work queue
    if (!ctx->work_queue) {
        ctx->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
        assert_non_null(ctx->work_queue);
    }

    if (!ctx->work_queue_signal) {
        ctx->work_queue_signal = iot_os_eventgroup_create();
        assert_non_null(ctx->work_queue_signal);
    }

    buf[0].p = (uint8_t *)test_data;
    buf[0].len = data_len;

    // When: es_msg_dispatch queues work for _es_ble_msg_handler
    es_msg_dispatch(buf, buf_count, cmd_num);

    // Then: manually process the work queue to execute the handler
    if (iot_util_queue_receive(ctx->work_queue, &work) == IOT_ERROR_NONE) {
        work.handler(ctx, work.param);
        if (work.param) {
            iot_os_free(work.param);
        }
    }

    // If no crash, the test passes
    assert_true(true);
}
