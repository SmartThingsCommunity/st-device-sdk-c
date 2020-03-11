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
#include <iot_bsp_random.h>
#define UNUSED(x)   (void**)(x)

static unsigned char pubkey_b64[] = "tQdqhHSoMtruTdW0BAmDtmI7XzRKylfU1u5Lrz8lnm4=";
static unsigned char seckey_b64[] = "QhFRpFn66t49JHEV+UrtrkIxgSQJWvq+TRRRpVn67e4=";

void load_pubkey(iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	unsigned char *pubkey;
	unsigned char *seckey;
	size_t key_len = IOT_CRYPTO_ED25519_LEN;
	size_t olen;

	pubkey = (unsigned char *)malloc(key_len);
	assert_non_null(pubkey);

	seckey = (unsigned char *)malloc(key_len);
	assert_non_null(seckey);

	pk_info->type = IOT_CRYPTO_PK_ED25519;

	err = iot_crypto_base64_decode(pubkey_b64, strlen(pubkey_b64), pubkey, key_len, &olen);
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, key_len);
	pk_info->pubkey = pubkey;
	pk_info->pubkey_len = olen;

	err = iot_crypto_base64_decode(seckey_b64, strlen(seckey_b64), seckey, key_len, &olen);
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, key_len);
	pk_info->seckey = seckey;
	pk_info->seckey_len = olen;
}

int TC_iot_crypto_pk_setup(void **state)
{
	iot_error_t err;
	iot_crypto_pk_context_t *context;
	iot_crypto_pk_info_t *pk_info;

	context = (iot_crypto_pk_context_t *)malloc(sizeof(iot_crypto_pk_context_t));
	assert_non_null(context);
	memset(context, 0, sizeof(iot_crypto_pk_context_t));

	pk_info = (iot_crypto_pk_info_t *)malloc(sizeof(iot_crypto_pk_info_t));
	assert_non_null(pk_info);
	memset(pk_info, 0, sizeof(iot_crypto_pk_info_t));

	load_pubkey(pk_info);

	err = iot_crypto_pk_init(context, pk_info);
	assert_int_equal(err, IOT_ERROR_NONE);

	*state = context;

	return 0;
}

int TC_iot_crypto_pk_teardown(void **state)
{
	iot_crypto_pk_context_t *context;
	iot_crypto_pk_info_t *pk_info;

	context = (iot_crypto_pk_context_t *)*state;
	assert_non_null(context);

	pk_info = context->info;
	assert_non_null(pk_info);

	free(pk_info->pubkey);
	free(pk_info->seckey);
	free(pk_info);
	free(context);

	return 0;
}

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

void TC_iot_crypto_pk_ed25519_success(void **state)
{
	iot_error_t err;
	iot_crypto_pk_context_t *context;
	unsigned char *buf;
	unsigned char sig[IOT_CRYPTO_SIGNATURE_LEN];
	size_t buf_len;
	size_t sig_len;
	int i;

	context = (iot_crypto_pk_context_t *)*state;
	assert_non_null(context);
	// Given
	buf_len = 256;
	buf = (unsigned char *)malloc(buf_len);
	assert_non_null(buf);
	for (i = 0; i < buf_len; i++) {
		buf[i] = (unsigned char)(iot_bsp_random() & 0xff);
	}
	// When
	err = iot_crypto_pk_sign(context, buf, buf_len, sig, &sig_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	// TODO: need to check sig_len is equal to IOT_CRYPTO_SIGNATURE_LEN

	// When
	err = iot_crypto_pk_verify(context, buf, buf_len, sig, sig_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
}
