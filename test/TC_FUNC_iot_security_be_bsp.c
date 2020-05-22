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
#include <security/iot_security_storage.h>
#include <security/backend/iot_security_be.h>

#include "TC_MOCK_functions.h"

extern iot_security_storage_target_t _iot_security_be_bsp_fs_storage_id2target(iot_security_storage_id_t storage_id);
extern iot_error_t _iot_security_be_bsp_fs_storage_id2filename(iot_security_storage_id_t storage_id, char *filename, size_t filename_len);
extern iot_error_t _iot_security_be_bsp_fs_load(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf);
extern iot_error_t _iot_security_be_bsp_fs_store(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id, iot_security_buffer_t *input_buf);
extern iot_error_t _iot_security_be_bsp_fs_remove(iot_security_be_context_t *be_context, iot_security_storage_id_t storage_id);

void TC_STATIC_iot_security_be_bsp_fs_storage_id2target_invalid_parameters(void **state)
{
	iot_security_storage_id_t id;
	iot_security_storage_target_t target;

	// Given: invalid nv
	id = IOT_NVD_UNKNOWN;
	// When
	target = _iot_security_be_bsp_fs_storage_id2target(id);
	// Then
	assert_int_equal(target, IOT_SECURITY_STORAGE_TARGET_UNKNOWN);

	// Given: invalid nv
	id = IOT_NVD_MAX;
	// When
	target = _iot_security_be_bsp_fs_storage_id2target(id);
	// Then
	assert_int_equal(target, IOT_SECURITY_STORAGE_TARGET_UNKNOWN);
}

void TC_STATIC_iot_security_be_bsp_fs_storage_id2target_success(void **state)
{
	iot_security_storage_id_t id;
	iot_security_storage_target_t target;

	// Given
	id = IOT_NVD_ROOM_ID;
	// When
	target = _iot_security_be_bsp_fs_storage_id2target(id);
	// Then
	assert_int_equal(target, IOT_SECURITY_STORAGE_TARGET_NV);

	// Given
	id = IOT_NVD_PUBLIC_KEY;
	// When
	target = _iot_security_be_bsp_fs_storage_id2target(id);
	// Then
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	assert_int_equal(target, IOT_SECURITY_STORAGE_TARGET_FACTORY);
#else
	assert_int_equal(target, IOT_SECURITY_STORAGE_TARGET_DI);
#endif
}

void TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;
	char filename[IOT_SECURITY_STORAGE_FILENAME_MAX_LEN];

	// Given
	id = IOT_NVD_ROOM_ID;
	// When: filename is null
	err = _iot_security_be_bsp_fs_storage_id2filename(id, NULL, sizeof(filename));
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS);

	// Given
	id = IOT_NVD_ROOM_ID;
	// When: filename len is zero
	err = _iot_security_be_bsp_fs_storage_id2filename(id, filename, 0);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS);

	// Given
	id = IOT_NVD_ROOM_ID;
	// When: small filename len
	err = _iot_security_be_bsp_fs_storage_id2filename(id, filename, 2);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_BUFFER);

	// Given: invalid id
	id = IOT_NVD_UNKNOWN;
	// When
	err = _iot_security_be_bsp_fs_storage_id2filename(id, filename, sizeof(filename));
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_STORAGE_INVALID_ID);
}

void TC_STATIC_iot_security_be_bsp_fs_storage_id2filename_success(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;
	char filename[IOT_SECURITY_STORAGE_FILENAME_MAX_LEN];

	// Given: valid id
	id = IOT_NVD_ROOM_ID;
	// When
	err = _iot_security_be_bsp_fs_storage_id2filename(id, filename, sizeof(filename));
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_bsp_fs_load_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_be_context_t be_context;
	iot_security_storage_id_t id;
	iot_security_buffer_t buf;
	const char *room_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";

	// Given: prepare room id
	id = IOT_NVD_ROOM_ID;
	buf.p = (unsigned char *)room_id;
	buf.len = strlen(room_id) + 1;
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: malloc failure
	do_not_use_mock_iot_os_malloc_failure();
	set_mock_iot_os_malloc_failure_with_index(0);
	id = IOT_NVD_ROOM_ID;
	// When
	err = _iot_security_be_bsp_fs_load(&be_context, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
	// Teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_be_bsp_fs_load_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_be_context_t be_context;
	iot_security_storage_id_t id;
	iot_security_buffer_t buf;

	// When: context is null
	err = _iot_security_be_bsp_fs_load(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_BE_CONTEXT_NULL);

	// Given: invalid id
	id = IOT_NVD_UNKNOWN;
	// When
	err = _iot_security_be_bsp_fs_load(&be_context, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET);

	// Given: invalid id
	id = IOT_NVD_UNKNOWN;
	// When
	err = _iot_security_be_bsp_fs_load(&be_context, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET);

	// When: buffer is null
	err = _iot_security_be_bsp_fs_load(&be_context, id, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS																																																																																																																		);
}

void TC_iot_security_be_bsp_fs_load_success(void **state)
{
	iot_error_t err;
	iot_security_be_context_t be_context;
	iot_security_storage_id_t id;
	iot_security_buffer_t test_buf;
	iot_security_buffer_t load_buf;
	const char *room_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";

	// Given: prepare room id
	id = IOT_NVD_ROOM_ID;
	test_buf.p = (unsigned char *)room_id;
	test_buf.len = strlen(room_id) + 1;
	err = _iot_security_be_bsp_fs_store(&be_context, id, &test_buf);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = _iot_security_be_bsp_fs_load(&be_context, id, &load_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(load_buf.p);
	assert_int_equal(load_buf.len, test_buf.len);
	assert_memory_equal(load_buf.p, test_buf.p, test_buf.len);
	// Teardown
	iot_os_free(load_buf.p);
}

void TC_iot_security_be_bsp_fs_store_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;
	iot_security_buffer_t buf;
	unsigned char data[32];

	// When: buffer data is invalid
	err = _iot_security_be_bsp_fs_store(NULL, id, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS);

	// Given: buffer is null
	buf.p = NULL;
	buf.len = sizeof(data);
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS);

	// Given: buffer size is zero
	buf.p = data;
	buf.len = 0;
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_ARGS);

	buf.p = data;
	buf.len = sizeof(data);

	// Given: invalid nv
	id = IOT_NVD_UNKNOWN;
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET);

	// Given: factory nv
	id = IOT_NVD_PUBLIC_KEY;
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);
}

void TC_iot_security_be_bsp_fs_store_success(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;
	iot_security_buffer_t buf;
	const char *room_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";

	// Given: prepare room id
	id = IOT_NVD_ROOM_ID;
	buf.p = (unsigned char *)room_id;
	buf.len = strlen(room_id) + 1;
	// When
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_bsp_fs_remove_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;

	// Given: invalid nv
	id = IOT_NVD_UNKNOWN;
	// When
	err = _iot_security_be_bsp_fs_remove(NULL, id);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET);

	// Given: factory nv
	id = IOT_NVD_PUBLIC_KEY;
	// When
	err = _iot_security_be_bsp_fs_remove(NULL, id);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_FS_INVALID_TARGET);
}

void TC_iot_security_be_bsp_fs_remove_success(void **state)
{
	iot_error_t err;
	iot_security_storage_id_t id;
	iot_security_buffer_t buf;
	const char *room_id = "1cd8e3f2-0c88-4298-90e3-cd9b35a82140";

	// Given: prepare room id
	id = IOT_NVD_ROOM_ID;
	buf.p = (unsigned char *)room_id;
	buf.len = strlen(room_id) + 1;
	err = _iot_security_be_bsp_fs_store(NULL, id, &buf);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = _iot_security_be_bsp_fs_remove(NULL, id);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_bsp_init_null_parameters(void **state)
{
	iot_error_t err;

	// When: context is null
	err = iot_security_be_bsp_init(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_BE_CONTEXT_NULL);
}

void TC_iot_security_be_bsp_init_success(void **state)
{
	iot_error_t err;
	iot_security_be_context_t be_context;

	// When
	err = iot_security_be_bsp_init(&be_context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}