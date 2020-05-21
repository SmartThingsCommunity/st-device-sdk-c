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
#include <iot_error.h>
#include <iot_nv_data.h>
#include "security/iot_security_common.h"
#include "security/backend/iot_security_be.h"

#include "TC_MOCK_functions.h"

void TC_iot_security_init_malloc_failure(void **state)
{
	iot_security_context_t *context;

	for (int i = 0; i < 2; i++) {
		do_not_use_mock_iot_os_malloc_failure();
		// Given: i-th malloc failure
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		context = iot_security_init();
		// Then
		assert_null(context);
	}

	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_init_success(void **state)
{
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

	// When
	context = iot_security_init();
	// Then
	assert_non_null(context);
	// Teardown
	iot_os_free(context->be_context);
	iot_os_free(context);

	set_mock_detect_memory_leak(false);
}

void TC_iot_security_deinit_null_parameters(void **state)
{
	iot_error_t err;

	// When: context is null
	err = iot_security_deinit(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

	// Given
	context = iot_security_init();
	assert_non_null(context);
	// When
	err = iot_security_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);
}

void TC_iot_security_check_context_is_valid_null_parameters(void **state)
{
	iot_error_t err;

	// When: context is null
	err = iot_security_check_context_is_valid(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_check_context_is_valid_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

	// Given
	context = iot_security_init();
	assert_non_null(context);
	// When
	err = iot_security_check_context_is_valid(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	// Teardown
	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);
}
