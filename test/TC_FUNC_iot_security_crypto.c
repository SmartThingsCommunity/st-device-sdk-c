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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <bsp/iot_bsp_random.h>
#include <security/iot_security_crypto.h>

#include "TC_MOCK_functions.h"

int TC_iot_security_cipher_init_setup(void **state)
{
	iot_security_context_t *context;

	context = iot_security_init();
	assert_non_null(context);

	*state = context;

	return 0;
}

int TC_iot_security_cipher_init_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	return 0;
}

int TC_iot_security_cipher_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	/*
	 * set_mock_detect_memory_leak are not available by set_params
	 */

	context = iot_security_init();
	assert_non_null(context);

	err = iot_security_cipher_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);


	*state = context;

	return 0;
}

int TC_iot_security_cipher_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_cipher_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	return 0;
}

void TC_iot_security_cipher_init_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_cipher_init(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_init_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	do_not_use_mock_iot_os_malloc_failure();

	// Given
	set_mock_iot_os_malloc_failure_with_index(0);
	// When
	err = iot_security_cipher_init(context);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_cipher_init_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_deinit_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_cipher_deinit(NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_get_align_size_failure(void **state)
{
	iot_security_key_type_t key_type;
	size_t data_size;
	size_t align_size;

	// Given: unknown key type
	key_type = IOT_SECURITY_KEY_TYPE_UNKNOWN;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, 0);

	// Given: invalid input size
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 0;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, 0);
}

void TC_iot_security_cipher_get_align_size_success(void **state)
{
	iot_security_key_type_t key_type;
	size_t data_size;
	size_t align_size;
	size_t expected_size;

	// Given
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 16;
	expected_size = 32;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, expected_size);

	// Given
	key_type = IOT_SECURITY_KEY_TYPE_AES256;
	data_size = 24;
	expected_size = 32;
	// When
	align_size = iot_security_cipher_get_align_size(key_type, data_size);
	// Then
	assert_int_equal(align_size, expected_size);
}

void TC_iot_security_cipher_set_params_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char buf[IOT_SECURITY_SECRET_LEN];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: key len is zero
	aes_params.key.p = buf;
	aes_params.key.len = 0;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: iv len is zero
	aes_params.iv.p = buf;
	aes_params.iv.len = 0;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_set_params_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_set_params(NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_set_params(NULL, &aes_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_set_params(context, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_set_params_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	unsigned char msg[128];
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: input data is all zero
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: input buf is null
	plain_buf.p = NULL;
	plain_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: input buf len is zero
	plain_buf.p = msg;
	plain_buf.len = 0;
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_aes_encrypt(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(NULL, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(context, NULL, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: valid input data
	plain_buf.p = msg;
	plain_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_encrypt_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	err = iot_security_cipher_set_params(context, &aes_params);
	assert_int_equal(err, IOT_ERROR_NONE);
	// Given: input data
	plain_buf.p = secret_buf;
	plain_buf.len = secret_len;

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_cipher_aes_encrypt_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: encrypt without pk_init
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	encrypt_buf.p = msg;
	encrypt_buf.len = sizeof(msg);

	// When: input data is all zero
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: output buf is null
	decrypt_buf.p = NULL;
	decrypt_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: output buf len is zero
	decrypt_buf.p = msg;
	decrypt_buf.len = 0;
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	unsigned char msg[128];

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When
	err = iot_security_cipher_aes_decrypt(NULL, NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_decrypt(NULL, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_decrypt(context, NULL, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: valid input data
	encrypt_buf.p = msg;
	encrypt_buf.len = sizeof(msg);
	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_decrypt_malloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	err = iot_security_cipher_set_params(context, &aes_params);
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: encrypted data
	plain_buf.p = secret_buf;
	plain_buf.len = secret_len;
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	assert_int_equal(err, IOT_ERROR_NONE);

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// When
		err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
	iot_os_free(encrypt_buf.p);
}

void TC_iot_security_cipher_aes_decrypt_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: decrypt without pk_init
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_cipher_aes_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cipher_params_t aes_params = { 0 };
	unsigned char secret_buf[IOT_SECURITY_SECRET_LEN];
	unsigned char iv_buf[IOT_SECURITY_IV_LEN];
	iot_security_buffer_t plain_buf = { 0 };
	iot_security_buffer_t encrypt_buf = { 0 };
	iot_security_buffer_t decrypt_buf = { 0 };
	size_t secret_len = sizeof(secret_buf);
	size_t iv_len = sizeof(iv_buf);
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// buffer for plain
	plain_buf.len = 256;
	plain_buf.p = (unsigned char *)iot_os_malloc(plain_buf.len);
	assert_non_null(plain_buf.p);
	for (i = 0; i < plain_buf.len; i++) {
		plain_buf.p[i] = (unsigned char)iot_bsp_random();
	}

	// Given: cipher algorithm and iv
	aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
	for (i = 0; i < iv_len; i++) {
		iv_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.iv.p = iv_buf;
	aes_params.iv.len = iv_len;
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE)
	for (i = 0; i < secret_len; i++) {
		secret_buf[i] = (unsigned char)iot_bsp_random();
	}
	aes_params.key.p = secret_buf;
	aes_params.key.len = secret_len;
#endif
	// When
	err = iot_security_cipher_set_params(context, &aes_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);

	// When
	err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(encrypt_buf.p);
	assert_int_not_equal(encrypt_buf.len, 0);

	// When
	err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(decrypt_buf.p);
	assert_int_not_equal(decrypt_buf.len, 0);
	assert_int_equal(decrypt_buf.len, plain_buf.len);
	assert_memory_equal(decrypt_buf.p, plain_buf.p, plain_buf.len);

	// Local teardown
	iot_os_free(decrypt_buf.p);
	iot_os_free(encrypt_buf.p);
	iot_os_free(plain_buf.p);
}