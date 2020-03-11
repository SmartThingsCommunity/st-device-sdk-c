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
#include <iot_crypto.h>
#define UNUSED(x)   (void**)(x)

void TC_iot_crypto_pk_init_null_parameter(void **state)
{
	iot_error_t err;
	iot_crypto_pk_context_t context;
	UNUSED(state);

	// When: Null parameters
	err = iot_crypto_pk_init(NULL, NULL);
	// Then: Should return error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: Null info
	err = iot_crypto_pk_init(&context, NULL);
	// Then: Should return error
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_crypto_pk_init_ed25519(void **state)
{
	iot_error_t err;
	iot_crypto_pk_context_t context;
	iot_crypto_pk_info_t pk_info;
	UNUSED(state);

	//Given
	memset(&pk_info, '\0', sizeof(iot_crypto_pk_info_t));
	pk_info.type = IOT_CRYPTO_PK_ED25519;

	// When
	err = iot_crypto_pk_init(&context, &pk_info);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(context.info, &pk_info, sizeof(iot_crypto_pk_info_t));
}

void TC_iot_crypto_pk_init_invalid_type(void **state)
{
	iot_error_t err;
	iot_crypto_pk_context_t context;
	iot_crypto_pk_info_t pk_info;
	UNUSED(state);

	//Given
	memset(&pk_info, '\0', sizeof(iot_crypto_pk_info_t));
	pk_info.type = 0x77;

	// When
	err = iot_crypto_pk_init(&context, &pk_info);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_crypto_pk_free(void **state)
{
	iot_crypto_pk_context_t context;
	iot_crypto_pk_info_t pk_info;
	UNUSED(state);

	// Given: set pk_info
	context.info = &pk_info;
	// When
	iot_crypto_pk_free(&context);
	// Then
	assert_ptr_not_equal(context.info, &pk_info);
}
