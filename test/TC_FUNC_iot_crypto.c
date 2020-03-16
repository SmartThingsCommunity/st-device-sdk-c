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

int TC_iot_crypto_cipher_aes_setup(void **state)
{
	iot_crypto_cipher_info_t *cipher_info;
	unsigned char *secret;
	unsigned char *iv;
	size_t secret_len = IOT_CRYPTO_SECRET_LEN;
	size_t iv_len = IOT_CRYPTO_IV_LEN;
	int i;

	cipher_info = (iot_crypto_cipher_info_t *)malloc(sizeof(iot_crypto_cipher_info_t ));
	assert_non_null(cipher_info);

	cipher_info->type = IOT_CRYPTO_CIPHER_AES256;
	cipher_info->mode = IOT_CRYPTO_CIPHER_ENCRYPT;

	secret = (unsigned char *)malloc(secret_len);
	assert_non_null(secret);
	for (i = 0; i < secret_len; i++) {
		secret[i] = (unsigned char)(iot_bsp_random() & 0xff);
	}
	cipher_info->key = secret;
	cipher_info->key_len = secret_len;

	iv = (unsigned char *)malloc(iv_len);
	assert_non_null(iv);
	for (i = 0; i < iv_len; i++) {
		iv[i] = (unsigned char)(iot_bsp_random() & 0xff);
	}
	cipher_info->iv = iv;
	cipher_info->iv_len = iv_len;

	*state = cipher_info;

	return 0;
}

int TC_iot_crypto_cipher_aes_teardown(void **state)
{
	iot_crypto_cipher_info_t *cipher_info;

	cipher_info = (iot_crypto_cipher_info_t *)*state;

	if (cipher_info) {
		if (cipher_info->key)
			free(cipher_info->key);
		if (cipher_info->iv)
			free(cipher_info->iv);
		free(cipher_info);
	}

	return 0;
}

void TC_iot_crypto_cipher_aes_null_parameter(void **state)
{
	iot_error_t err;
	iot_crypto_cipher_info_t *cipher_info;
	unsigned char buf[32];
	unsigned char out[32];
	size_t buf_len = sizeof(buf);
	size_t out_len = sizeof(buf);
	size_t olen;

	cipher_info = (iot_crypto_cipher_info_t *)*state;
	assert_non_null(cipher_info);

	err = iot_crypto_cipher_aes(NULL, NULL, 0, NULL, NULL, 0);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(NULL, buf, buf_len, out, &olen, out_len);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(cipher_info, NULL, buf_len, out, &olen, out_len);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(cipher_info, buf, 0, out, &olen, out_len);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(cipher_info, buf, buf_len, NULL, &olen, out_len);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(cipher_info, buf, buf_len, out, NULL, out_len);
	assert_int_not_equal(err, IOT_ERROR_NONE);

	err = iot_crypto_cipher_aes(cipher_info, buf, buf_len, out, &olen, 0);
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_crypto_cipher_aes_invalid_parameter(void **state)
{
	iot_error_t err;
	iot_crypto_cipher_info_t *cipher_info;
	unsigned char *plain;
	unsigned char *encrypt;
	unsigned char *decrypt;
	size_t plain_len = 256;
	size_t encrypt_len;
	size_t required_len;
	size_t olen;
	int i;

	cipher_info = (iot_crypto_cipher_info_t *)*state;
	assert_non_null(cipher_info);

	// buffer for plain
	plain = (unsigned char *)malloc(plain_len);
	assert_non_null(plain);
	for (i = 0; i < plain_len; i++) {
		plain[i] = (unsigned char)(iot_bsp_random() & 0xff);
	}
	// buffer for encryption
	required_len = iot_crypto_cipher_get_align_size(cipher_info->type, plain_len);
	encrypt = (unsigned char *)malloc(required_len);
	assert_non_null(encrypt);
	// buffer for decryption
	decrypt = (unsigned char *)malloc(required_len);
	assert_non_null(decrypt);

	// Given
	cipher_info->type = -1;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE);
	// Local teardown
	cipher_info->type = IOT_CRYPTO_CIPHER_AES256;

	// Given
	cipher_info->mode = -1;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_MODE);
	// Local teardown
	cipher_info->mode = IOT_CRYPTO_CIPHER_ENCRYPT;

	// Given
	cipher_info->key_len = 256;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_KEYLEN);
	// Local teardown
	cipher_info->key_len = IOT_CRYPTO_SECRET_LEN;

	// Given
	cipher_info->iv_len = 256;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_IVLEN);
	// Local teardown
	cipher_info->iv_len = IOT_CRYPTO_IV_LEN;

	// Given
	cipher_info->mode = IOT_CRYPTO_CIPHER_ENCRYPT;
	required_len = plain_len;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_OUTSIZE);

	// Given
	cipher_info->mode = IOT_CRYPTO_CIPHER_DECRYPT;
	encrypt_len = iot_crypto_cipher_get_align_size(cipher_info->type, plain_len);
	required_len = plain_len;
	// When
	err = iot_crypto_cipher_aes(cipher_info, encrypt, encrypt_len, decrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_CIPHER_OUTSIZE);

	free(decrypt);
	free(encrypt);
	free(plain);
}

void TC_iot_crypto_cipher_aes_success(void **state)
{
	iot_error_t err;
	iot_crypto_cipher_info_t *cipher_info;
	unsigned char *plain;
	unsigned char *encrypt;
	unsigned char *decrypt;
	size_t plain_len = 256;
	size_t encrypt_len;
	size_t required_len;
	size_t olen;
	int i;

	cipher_info = (iot_crypto_cipher_info_t *)*state;
	assert_non_null(cipher_info);

	// buffer for plain
	plain = (unsigned char *)malloc(plain_len);
	assert_non_null(plain);
	for (i = 0; i < plain_len; i++) {
		plain[i] = (unsigned char)(iot_bsp_random() & 0xff);
	}
	// buffer for encryption
	required_len = iot_crypto_cipher_get_align_size(cipher_info->type, plain_len);
	encrypt = (unsigned char *)malloc(required_len);
	assert_non_null(encrypt);
	// buffer for decryption
	decrypt = (unsigned char *)malloc(required_len);
	assert_non_null(decrypt);

	// Given
	cipher_info->mode = IOT_CRYPTO_CIPHER_ENCRYPT;
	// When
	err = iot_crypto_cipher_aes(cipher_info, plain, plain_len, encrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, required_len);
	encrypt_len = olen;

	// Given
	cipher_info->mode = IOT_CRYPTO_CIPHER_DECRYPT;
	// When
	err = iot_crypto_cipher_aes(cipher_info, encrypt, encrypt_len, decrypt, &olen, required_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, plain_len);
	assert_memory_equal(decrypt, plain, plain_len);

	free(decrypt);
	free(encrypt);
	free(plain);
}

static const unsigned char *sample = "ab~c123!?$*&()'-=@~abc";
static const unsigned char *sample_b64 = "YWJ+YzEyMyE/JComKCknLT1AfmFiYw==";
static const unsigned char *sample_b64url = "YWJ-YzEyMyE_JComKCknLT1AfmFiYw==";

typedef iot_error_t (*iot_crypto_base64_func)(const unsigned char *, size_t, unsigned char *, size_t, size_t *);

void TC_iot_crypto_base64_invalid_parameter(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char dst[256];
	size_t src_len;
	size_t dst_len;
	size_t out_len;
	int i;
	iot_crypto_base64_func base64_func_target;
	iot_crypto_base64_func base64_funcs[] = {
			iot_crypto_base64_encode,
			iot_crypto_base64_decode,
			iot_crypto_base64_encode_urlsafe,
			iot_crypto_base64_decode_urlsafe,
	};

	for (i = 0; i < (sizeof(base64_funcs) / sizeof(base64_funcs[0])); i++) {
		base64_func_target = base64_funcs[i];
		assert_non_null(base64_func_target);

		// Given
		src = (unsigned char *) sample;
		src_len = strlen(src);
		dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len);
		// When: src is null
		err = base64_func_target(NULL, src_len, dst, dst_len, &out_len);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);

		// When: dst is null
		err = base64_func_target(src, src_len, NULL, dst_len, &out_len);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);

		// When: out_len is null
		err = base64_func_target(src, src_len, dst, dst_len, NULL);
		// Then
		assert_int_not_equal(err, IOT_ERROR_NONE);
	}

	// Given
	src = (unsigned char *)sample;
	src_len = strlen(src);
	// When: small output buffer
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len) - 1;
	err = iot_crypto_base64_encode(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_BASE64);

	// Given
	src = (unsigned char *)sample_b64;
	src_len = strlen(src);
	// When: small output buffer
	dst_len = 8;
	err = iot_crypto_base64_decode(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_BASE64);

	// Given
	src = (unsigned char *)sample;
	src_len = strlen(src);
	// When: small output buffer
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len) - 1;
	err = iot_crypto_base64_encode_urlsafe(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_BASE64_URLSAFE);

	// Given: small output buffer
	src = (unsigned char *)sample_b64url;
	src_len = strlen(src);
	// When
	dst_len = 8;
	err = iot_crypto_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_CRYPTO_BASE64_URLSAFE);
}

void TC_iot_crypto_base64_failure(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char dst[256];
	unsigned char tmp[256] = {0x90, 0x13, 0x14, '='};
	size_t src_len;
	size_t dst_len;
	size_t out_len;

	// Given
	src = (unsigned char *)tmp;
	src_len = 4;
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len);
	// When
	err = iot_crypto_base64_decode(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	src = (unsigned char *)tmp;
	src_len = 4;
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len);
	// When
	err = iot_crypto_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_crypto_base64_encode_success(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char *dst;
	unsigned char *expected;
	size_t src_len;
	size_t dst_len;
	size_t out_len;

	// Given
	src = (unsigned char *)sample;
	src_len = strlen(src);
	expected = (unsigned char *)sample_b64;
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len);
	dst = (unsigned char *)malloc(dst_len);
	assert_non_null(dst);
	// When
	err = iot_crypto_base64_encode(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(dst, expected, out_len);

	// teardown
	free(dst);
}

void TC_iot_crypto_base64_decode_success(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char *dst;
	unsigned char *expected;
	size_t src_len;
	size_t dst_len;
	size_t out_len;

	// Given
	src = (unsigned char *)sample_b64;
	src_len = strlen(src);
	expected = (unsigned char *)sample;
	dst_len = src_len;
	dst = (unsigned char *)malloc(dst_len);
	assert_non_null(dst);
	// When
	err = iot_crypto_base64_decode(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(dst, expected, out_len);

	// teardown
	free(dst);
}

void TC_iot_crypto_base64_urlsafe_encode_success(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char *dst;
	unsigned char *expected;
	size_t src_len;
	size_t dst_len;
	size_t out_len;

	// Given
	src = (unsigned char *)sample;
	src_len = strlen(src);
	expected = (unsigned char *)sample_b64url;
	dst_len = IOT_CRYPTO_CAL_B64_LEN(src_len);
	dst = (unsigned char *)malloc(dst_len);
	assert_non_null(dst);
	// When
	err = iot_crypto_base64_encode_urlsafe(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(dst, expected, out_len);

	// teardown
	free(dst);
}

void TC_iot_crypto_base64_urlsafe_decode_success(void **state)
{
	iot_error_t err;
	unsigned char *src;
	unsigned char *dst;
	unsigned char *expected;
	size_t src_len;
	size_t dst_len;
	size_t out_len;

	// Given
	src = (unsigned char *)sample_b64url;
	src_len = strlen(src);
	expected = (unsigned char *)sample;
	dst_len = src_len;
	dst = (unsigned char *)malloc(dst_len);
	assert_non_null(dst);
	// When
	err = iot_crypto_base64_decode_urlsafe(src, src_len, dst, dst_len, &out_len);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(dst, expected, out_len);

	// teardown
	free(dst);
}