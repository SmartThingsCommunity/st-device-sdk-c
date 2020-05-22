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
#include <iot_main.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <root_ca.h>
#include <bsp/iot_bsp_random.h>
#include <security/iot_security_manager.h>

#include "TC_MOCK_functions.h"

#define TEST_SECURITY_MANAGER_PRIVATE_KEY	"yQMrFPkZ1wI62K1cEuhSL23wBR/nLr7s3YUZn+XAwb8="
#define TEST_SECURITY_MANAGER_PUBLIC_KEY	"eV0oOSDhLf8UXqMO6Osat9G28lXldyZ5nzfQCQt/oiQ="
#define TEST_SECURITY_MANAGER_SERIAL_NUMBER	"STDKtestc51ef86c"

static char sample_device_info[] = {
		"{\n"
		"\t\"deviceInfo\": {\n"
		"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
		"\t\t\"privateKey\": \"" TEST_SECURITY_MANAGER_PRIVATE_KEY "\",\n"
		"\t\t\"publicKey\": \"" TEST_SECURITY_MANAGER_PUBLIC_KEY "\",\n"
		"\t\t\"serialNumber\": \"" TEST_SECURITY_MANAGER_SERIAL_NUMBER "\"\n"
		"\t}\n"
		"}"
};


int TC_iot_security_manager_setup(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	set_mock_detect_memory_leak(true);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
	err = iot_nv_init(NULL, 0);
#endif
	assert_int_equal(err, IOT_ERROR_NONE);

	context = iot_security_init();
	assert_non_null(context);

	err = iot_security_manager_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	*state = context;

	return 0;
}

int TC_iot_security_manager_teardown(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	err = iot_security_manager_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(false);

	return 0;
}

void TC_iot_security_manager_init_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_manager_init(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_manager_init_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	// Given
	context = iot_security_init();
	assert_non_null(context);
	// When
	err = iot_security_manager_init(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_deinit_null_parameters(void **state)
{
	iot_error_t err;

	// When
	err = iot_security_manager_init(NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

void TC_iot_security_manager_deinit_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;

	// Given
	context = iot_security_init();
	assert_non_null(context);
	err = iot_security_manager_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);
	// When
	err = iot_security_manager_deinit(context);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	// Teardown
	err = iot_security_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_set_key_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_params_t key_params;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: all null
	err = iot_security_manager_set_key(NULL, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: context null
	err = iot_security_manager_set_key(NULL, &key_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: params null
	err = iot_security_manager_set_key(context, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_set_key_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_params_t key_params;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher init to set key
	err = iot_security_cipher_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: unknown key id
	key_params.key_id = IOT_SECURITY_KEY_ID_UNKNOWN;
	// When
	err = iot_security_manager_set_key(context, &key_params);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);

	// Given: not supported key id
	key_params.key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
	// When
	err = iot_security_manager_set_key(context, &key_params);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Teardown
	err = iot_security_cipher_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_set_key_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_id_t key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
	iot_security_key_params_t key_params = { 0 };
	iot_security_buffer_t key_buf = { 0 };
	iot_security_buffer_t verify_buf = { 0 };
	int i;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: cipher init to set key
	err = iot_security_cipher_init(context);
	assert_int_equal(err, IOT_ERROR_NONE);

	// Given: prepare key
	key_buf.len = IOT_SECURITY_SHA256_LEN;
	key_buf.p = (unsigned char *)iot_os_malloc(key_buf.len);
	for (i = 0; i < key_buf.len; i++) {
		key_buf.p[i] = (unsigned char)iot_bsp_random();
	}

	// Given
	key_params.key_id = key_id;
	key_params.params.cipher.key = key_buf;
	assert_non_null(key_buf.p);
	// When
	err = iot_security_manager_set_key(context, &key_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	err = iot_security_manager_get_key(context, key_id, &verify_buf);
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(verify_buf.p);
	assert_int_not_equal(verify_buf.len, 0);
	assert_memory_equal(verify_buf.p, key_buf.p, key_buf.len);

	// Teardown
	iot_os_free(verify_buf.p);
	err = iot_security_cipher_deinit(context);
	assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_get_key_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_id_t key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
	iot_security_buffer_t key_buf;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: all null
	err = iot_security_manager_get_key(NULL, 0, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: context null
	err = iot_security_manager_get_key(NULL, key_id, &key_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: key id zero
	err = iot_security_manager_get_key(context, 0, &key_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: params null
	err = iot_security_manager_get_key(context, key_id, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_get_key_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_id_t key_id;
	iot_security_buffer_t key_buf;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: unknown key id
	key_id = IOT_SECURITY_KEY_ID_UNKNOWN;
	// When
	err = iot_security_manager_get_key(context, key_id, &key_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);

	// Given: key id with no permission
	key_id = IOT_SECURITY_KEY_ID_DEVICE_PRIVATE;
	// When
	err = iot_security_manager_get_key(context, key_id, &key_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_KEY_NO_PERMISSION);
}

void TC_iot_security_manager_get_key_alloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_id_t key_id;
	iot_security_buffer_t key_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	for (int i = 0; i < 2; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// Given
		key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
		// When
		err = iot_security_manager_get_key(context, key_id, &key_buf);
		// Then
		assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_manager_get_key_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_key_id_t key_id;
	iot_security_buffer_t pubkey_buf = { 0 };
	char *pubkey_ref = (char *)TEST_SECURITY_MANAGER_PUBLIC_KEY;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
	// When
	err = iot_security_manager_get_key(context, key_id, &pubkey_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(pubkey_buf.p);
	assert_int_not_equal(pubkey_buf.len, 0);
	assert_memory_equal(pubkey_buf.p, pubkey_ref, strlen(pubkey_ref));
	// Teardown
	iot_os_free(pubkey_buf.p);
}

void TC_iot_security_manager_get_certificate_null_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cert_id_t cert_id = IOT_SECURITY_CERT_ID_DEVICE;
	iot_security_buffer_t cert_buf;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// When: all null
	err = iot_security_manager_get_certificate(NULL, 0, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: context null
	err = iot_security_manager_get_certificate(NULL, cert_id, &cert_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: cert id zero
	err = iot_security_manager_get_certificate(context, 0, &cert_buf);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: buf null
	err = iot_security_manager_get_certificate(context, cert_id, NULL);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_manager_get_certificate_invalid_parameters(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cert_id_t cert_id;
	iot_security_buffer_t cert_buf;

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given: unknown key id
	cert_id = IOT_SECURITY_CERT_ID_UNKNOWN;
	// When
	err = iot_security_manager_get_certificate(context, cert_id, &cert_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_SECURITY_CERT_INVALID_ID);
}

void TC_iot_security_manager_get_certificate_alloc_failure(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cert_id_t cert_id;
	iot_security_buffer_t key_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	for (int i = 0; i < 1; i++) {
		// Given: i-th malloc failure
		do_not_use_mock_iot_os_malloc_failure();
		set_mock_iot_os_malloc_failure_with_index(i);
		// Given
		cert_id = IOT_SECURITY_CERT_ID_MQTT_ROOT_CA;
		// When
		err = iot_security_manager_get_certificate(context, cert_id, &key_buf);
		// Then
		assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
	}

	// Local teardown
	do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_manager_get_certificate_success(void **state)
{
	iot_error_t err;
	iot_security_context_t *context;
	iot_security_cert_id_t cert_id;
	iot_security_buffer_t cert_buf = { 0 };

	context = (iot_security_context_t *)*state;
	assert_non_null(context);

	// Given
	cert_id = IOT_SECURITY_CERT_ID_MQTT_ROOT_CA;
	// When
	err = iot_security_manager_get_certificate(context, cert_id, &cert_buf);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(cert_buf.p);
	assert_int_not_equal(cert_buf.len, 0);
	assert_memory_equal(cert_buf.p, st_root_ca, st_root_ca_len);
	// Teardown
	iot_os_free(cert_buf.p);
}