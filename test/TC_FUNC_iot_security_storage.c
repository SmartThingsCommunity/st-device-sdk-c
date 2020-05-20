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
#include <security/iot_security_storage.h>
#include "security/backend/iot_security_be.h"

#include "TC_MOCK_functions.h"

#define TEST_SECURITY_STORAGE_PRIVATE_KEY	"y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI="
#define TEST_SECURITY_STORAGE_PUBLIC_KEY	"Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw="

static const char *sample_id = "a3b94a19-4363-4b60-b01e-f3d505898407";

static char sample_device_info[] = {
		"{\n"
		"\t\"deviceInfo\": {\n"
		"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
		"\t\t\"privateKey\": \"" TEST_SECURITY_STORAGE_PRIVATE_KEY "\",\n"
		"\t\t\"publicKey\": \"" TEST_SECURITY_STORAGE_PUBLIC_KEY "\",\n"
		"\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
		"\t}\n"
		"}"
};

int TC_iot_security_storage_init_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = iot_security_init();
	assert_non_null(context);

	*state = context;

	return 0;
}

int TC_iot_security_storage_init_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	return 0;
}

int TC_iot_security_storage_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

	context = iot_security_init();
	assert_non_null(context);

	err = iot_security_storage_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	*state = context;

	return 0;
}

int TC_iot_security_storage_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_storage_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);

	return 0;
}

void TC_iot_security_storage_init_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: malloc failure
	do_not_use_mock_iot_os_malloc_failure();
	set_mock_iot_os_malloc_failure_with_index(0);
	// When
	err = iot_security_storage_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
	// Teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_storage_init_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_storage_init(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_storage_init_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_storage_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	// Teardown
	err = iot_security_storage_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_deinit_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_storage_deinit(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_storage_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	err = iot_security_storage_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = iot_security_storage_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

typedef iot_error_t (*storage_rw_func)(iot_security_context_t *, iot_security_storage_id_t storage_id, iot_security_buffer_t *);

static void TC_iot_security_storage_do_null_parameters(iot_security_context_t *context, storage_rw_func rw_func)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t buf = { 0 };

	assert_non_null(context);
	assert_non_null(rw_func);

	// When: context, buf null
	err = rw_func(NULL, storage_id, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: context null
	err = rw_func(NULL, storage_id, &buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: buf null
	err = rw_func(context, storage_id, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

static void TC_iot_security_storage_do_invalid_parameters(iot_security_context_t *context, storage_rw_func rw_func, char rw)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	assert_non_null(context);
	assert_non_null(rw_func);

	if (rw == 'W') {
		// When: buffer doesn't have data
		err = rw_func(context, storage_id, &buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);

		// Given: buffer len is zero
		buf.p = (unsigned char *)sample_id;
		buf.len = 0;
		// When
		err = rw_func(context, storage_id, &buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);

		// Given: buffer pointer is null
		buf.p = NULL;
		buf.len = strlen((char *)sample_id);
		// When
		err = rw_func(context, storage_id, &buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Given: storage id invalid
	storage_id = IOT_NVD_UNKNOWN;
	buf.p = (unsigned char *)sample;
	buf.len = strlen(sample);
	// When
	err = rw_func(context, storage_id, &buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_read_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t buf = { 0 };
	iot_security_buffer_t sample_buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: prepare sample file
	sample_buf.p = (unsigned char *)sample;
	sample_buf.len = strlen(sample);
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	assert_int_equal(err, IOT_ERROR_NONE);

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When: valid input
		err = iot_security_storage_read(context, storage_id, &buf);
		// Then
		assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
	}

	// Teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_storage_read_null_parameters(void **state)
{
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	TC_iot_security_storage_do_null_parameters(context, iot_security_storage_read);
}

void TC_iot_security_storage_read_invalid_parameters(void **state)
{
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	TC_iot_security_storage_do_invalid_parameters(context, iot_security_storage_read, 'R');
}

void TC_iot_security_storage_read_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: read without storage_init
	err = iot_security_storage_read(context, storage_id, &buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_read_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t buf = { 0 };
	iot_security_buffer_t sample_buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: prepare sample file
	sample_buf.p = (unsigned char *)sample;
	sample_buf.len = strlen(sample);
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = iot_security_storage_read(context, storage_id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(buf.p);
	assert_int_equal(buf.len, sample_buf.len);
	assert_memory_equal(buf.p, sample_buf.p, sample_buf.len);
	// Teardown
	iot_os_free(buf.p);
}

void TC_iot_security_storage_write_null_parameters(void **state)
{
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	TC_iot_security_storage_do_null_parameters(context, iot_security_storage_write);
}

void TC_iot_security_storage_write_invalid_parameters(void **state)
{
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	TC_iot_security_storage_do_invalid_parameters(context, iot_security_storage_write, 'W');
}

void TC_iot_security_storage_write_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t sample_buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: prepare data
	sample_buf.p = (unsigned char *)sample;
	sample_buf.len = strlen(sample);

	// Given: factory file
	storage_id = IOT_NVD_PUBLIC_KEY;
	// When
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);

	// Given: write without storage_init
	context = iot_security_init();
	assert_non_null(context);
	// When
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
	// Teardown
	iot_security_deinit(context);
}

void TC_iot_security_storage_write_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t sample_buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: prepare data
	sample_buf.p = (unsigned char *)sample;
	sample_buf.len = strlen(sample);
	// When
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_remove_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: context is null
	err = iot_security_storage_remove(NULL, storage_id);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_remove_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: storage id invalid
	storage_id = IOT_NVD_UNKNOWN;
	// When
	err = iot_security_storage_remove(context, storage_id);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_storage_remove_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: factory file
	storage_id = IOT_NVD_PUBLIC_KEY;
	// When
	err = iot_security_storage_remove(context, storage_id);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);

	// Given: remove without storage_init
	context = iot_security_init();
	assert_non_null(context);
	// When
	err = iot_security_storage_remove(context, storage_id);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
	// Teardown
	iot_security_deinit(context);
}

void TC_iot_security_storage_remove_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_storage_id_t storage_id = IOT_NVD_ROOM_ID;
	iot_security_buffer_t sample_buf = { 0 };
	const char *sample = "1c83f234-9a53-11ea-b2e2-8f936ceb1180";

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: prepare sample file
	sample_buf.p = (unsigned char *)sample;
	sample_buf.len = strlen(sample);
	err = iot_security_storage_write(context, storage_id, &sample_buf);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = iot_security_storage_remove(context, storage_id);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}