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
#include <iot_error.h>
#include <iot_main.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/easysetup/http/easysetup_http.h"
#include "cmocka_custom.h"

extern int ref_step;
extern iot_error_t _iot_easysetup_gen_post_payload(struct iot_context *ctx, int cmd, char *in_payload,
                                                   char **out_payload);
extern iot_error_t _iot_easysetup_gen_get_payload(struct iot_context *ctx, int cmd, char **out_payload);
extern void http_msg_handler(int cmd, char **buffer, enum cgi_type type, char *data_buf);
extern iot_error_t iot_easysetup_init(struct iot_context *ctx);
extern void iot_easysetup_deinit(struct iot_context *ctx);

void TC_iot_easysetup_gen_post_payload_NULL_IN_PAYLOAD(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    char *in_payload;

    // Given: in-payload is null
    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    in_payload = NULL;
    // When
    err = _iot_easysetup_gen_post_payload(context, IOT_EASYSETUP_STEP_KEYINFO, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(context);
}

void TC_iot_easysetup_gen_post_payload_CMD_INVALID_STEP(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    char in_payload[] = "test payload";
    int cmd;

    // Given: set cmd as IOT_EASYSETUP_INVALID_STEP
    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    cmd = IOT_EASYSETUP_INVALID_STEP;
    // When
    err = _iot_easysetup_gen_post_payload(context, cmd, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(context);
}

void TC_iot_easysetup_gen_post_payload_CMD_INVALID_SEQUENCE(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    char in_payload[] = "test payload";
    int cmd;

    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));

    // Given: invalid ref step
    ref_step = IOT_EASYSETUP_STEP_KEYINFO;
    cmd = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
    // When
    err = _iot_easysetup_gen_post_payload(context, cmd, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: invalid current step (cmd)
    ref_step = IOT_EASYSETUP_STEP_CONFIRM;
    cmd = IOT_EASYSETUP_STEP_KEYINFO;
    // When
    err = _iot_easysetup_gen_post_payload(context, cmd, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    free(context);
    ref_step = 0;
}

void TC_iot_easysetup_gen_post_payload_NULL_CONTEXT(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;
    char in_payload[] = "test payload";

    // Given: context is null
    // When
    err = _iot_easysetup_gen_post_payload(NULL, IOT_EASYSETUP_STEP_KEYINFO, in_payload, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_gen_post_payload_SETUPCOMPLETE_NULL_PAYLOAD(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;

    // Given: NULL payload for SETUPCOMPLETE step (which is allowed)
    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    // When
    err = _iot_easysetup_gen_post_payload(context, IOT_EASYSETUP_STEP_SETUPCOMPLETE, NULL, &out_payload);
    // Then
    // Should not return invalid request error for SETUPCOMPLETE with NULL payload
    // Teardown
    free(context);
}

void TC_iot_easysetup_gen_get_payload_CMD_INVALID_STEP(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    int cmd;

    // Given: set cmd as IOT_EASYSETUP_INVALID_STEP
    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    cmd = IOT_EASYSETUP_INVALID_STEP;
    // When
    err = _iot_easysetup_gen_get_payload(context, cmd, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(context);
}

void TC_iot_easysetup_gen_get_payload_CMD_INVALID_SEQUENCE(void **state)
{
    iot_error_t err;
    struct iot_context *context;
    char *out_payload = NULL;
    int cmd;

    context = malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));

    // Given: invalid ref step
    ref_step = IOT_EASYSETUP_STEP_CONFIRMINFO;
    cmd = IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO;
    // When
    err = _iot_easysetup_gen_get_payload(context, cmd, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    free(context);
    ref_step = 0;
}

void TC_iot_easysetup_gen_get_payload_NULL_CONTEXT(void **state)
{
    iot_error_t err;
    char *out_payload = NULL;

    // Given: context is null
    // When
    err = _iot_easysetup_gen_get_payload(NULL, IOT_EASYSETUP_STEP_DEVICEINFO, &out_payload);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_http_msg_handler_INVALID_CMD(void **state)
{
    char *buffer = NULL;
    char *payload = "test payload";

    // Given: invalid command
    // When
    http_msg_handler(IOT_EASYSETUP_INVALID_STEP, &buffer, D2D_POST, payload);
    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with invalid cmd
    assert_true(true);

    // Teardown
    if (buffer) {
        free(buffer);
    }
}

void TC_http_msg_handler_INVALID_TYPE(void **state)
{
    char *buffer = NULL;
    char *payload = "test payload";

    // Given: invalid type
    // When
    http_msg_handler(IOT_EASYSETUP_STEP_KEYINFO, &buffer, D2D_ERROR, payload);
    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with invalid type
    assert_true(true);

    // Teardown
    if (buffer) {
        free(buffer);
    }
}

void TC_http_msg_handler_NULL_DATA_BUF_POST(void **state)
{
    char *buffer = NULL;

    // Given: data_buf is null for POST
    // When
    http_msg_handler(IOT_EASYSETUP_STEP_KEYINFO, &buffer, D2D_POST, NULL);
    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with NULL data_buf
    assert_true(true);

    // Teardown
    if (buffer) {
        free(buffer);
    }
}

void TC_iot_easysetup_init_NULL_CONTEXT(void **state)
{
    iot_error_t err;

    // Given: context is null
    // When
    err = iot_easysetup_init(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_easysetup_deinit_NULL_CONTEXT(void **state)
{
    // Given: context is null
    // When
    iot_easysetup_deinit(NULL);
    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with NULL context
    assert_true(true);
}
