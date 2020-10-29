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
#include <stdio.h>
#include <stdlib.h>
#include <iot_error.h>
#include <string.h>
#include <iot_main.h>

extern int ref_step;
extern iot_error_t _iot_easysetup_gen_post_payload(struct iot_context *ctx, int cmd, char *in_payload, char **out_payload);
extern iot_error_t _iot_easysetup_gen_get_payload(struct iot_context *ctx, int cmd, char **out_payload);

void TC_iot_easysetup_gen_post_payload_NULL_REQUEST_QUEUE(void **state)
{
	iot_error_t err;
	struct iot_context *context;
	char *out_payload = NULL;
	char in_payload[128] = {0, };

	// Given: easysetup_req_queue is null
	context = malloc(sizeof(struct iot_context));
	memset(context, '\0', sizeof(struct iot_context));
	snprintf(in_payload, sizeof(in_payload), "Temporal String");
	ref_step = IOT_EASYSETUP_STEP_KEYINFO;
	context->easysetup_req_queue = NULL;
	// When
	err = _iot_easysetup_gen_post_payload(context, IOT_EASYSETUP_STEP_KEYINFO, in_payload, &out_payload);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
	// Teardown
	free(context);
}

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

void TC_iot_easysetup_gen_get_payload_STATE_UPDATE_FAILURE(void **state)
{
	iot_error_t err;
	struct iot_context *context;
	char *out_payload = NULL;
	int cmd;

	context = malloc(sizeof(struct iot_context));
	memset(context, '\0', sizeof(struct iot_context));

	// Given: set cmd_queue as null to make iot_state_update() failed
	ref_step = IOT_EASYSETUP_STEP_DEVICEINFO;
	cmd = IOT_EASYSETUP_STEP_DEVICEINFO;
	context->cmd_queue = NULL;
	// When
	err = _iot_easysetup_gen_get_payload(context, cmd, &out_payload);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Teardown
	free(context);
	ref_step = 0;
}