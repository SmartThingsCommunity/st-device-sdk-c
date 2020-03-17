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

void TC_iot_crypto_cipher_get_align_size(void **state)
{
	iot_crypto_cipher_type_t cipher_type;
	size_t len;
	size_t align_len;
	size_t expected_len;

	// Given: not supported cipher algorithm
	cipher_type = -1;
	// When
	align_len = iot_crypto_cipher_get_align_size(cipher_type, len);
	// Then
	assert_int_equal(align_len, 0);

	// Given: invalid input size
	cipher_type = IOT_CRYPTO_CIPHER_AES256;
	len = 0;
	// When
	align_len = iot_crypto_cipher_get_align_size(cipher_type, len);
	// Then
	assert_int_equal(align_len, 0);

	// Given
	cipher_type = IOT_CRYPTO_CIPHER_AES256;
	len = 16;
	expected_len = 32;
	// When
	align_len = iot_crypto_cipher_get_align_size(cipher_type, len);
	// Then
	assert_int_equal(align_len, expected_len);

	// Given
	cipher_type = IOT_CRYPTO_CIPHER_AES256;
	len = 24;
	expected_len = 32;
	// When
	align_len = iot_crypto_cipher_get_align_size(cipher_type, len);
	// Then
	assert_int_equal(align_len, expected_len);
}

static unsigned char things_seckey_ed25519[] = {
	0x18, 0xdc, 0xba, 0x03, 0xef, 0xa9, 0x26, 0x19,
	0x79, 0x24, 0xbd, 0x44, 0xae, 0x39, 0x3d, 0xe0,
	0xf1, 0x9f, 0x9e, 0x9c, 0xdc, 0x6f, 0xd1, 0xe9,
	0xef, 0x10, 0xdc, 0x94, 0x29, 0x7e, 0x61, 0x85
};

static unsigned char things_seckey_curve25519[] = {
	0x88, 0xcf, 0x25, 0xca, 0x07, 0x0f, 0xef, 0xf9,
	0x90, 0x0a, 0xba, 0x15, 0x89, 0xa4, 0x58, 0x6c,
	0x05, 0x6e, 0xac, 0x9f, 0x97, 0x18, 0x85, 0xc5,
	0xd1, 0x0e, 0xda, 0xcb, 0x7a, 0xb8, 0x5c, 0x54
};

static unsigned char cloud_pubkey_ed25519[] = {
	0x88, 0x8a, 0xe2, 0xc2, 0x92, 0x91, 0x92, 0x31,
	0x32, 0x42, 0x49, 0x84, 0xc3, 0x14, 0x0f, 0xce,
	0x09, 0xb4, 0x52, 0x88, 0x66, 0x4a, 0x28, 0x6c,
	0x72, 0xbf, 0xae, 0xce, 0x40, 0x6f, 0x63, 0x5d
};

static unsigned char cloud_pubkey_curve25519[] = {
	0x6e, 0xc7, 0x18, 0xce, 0x29, 0x4e, 0xcb, 0x76,
	0xb4, 0x50, 0xa9, 0x48, 0xce, 0x24, 0x87, 0x02,
	0xdc, 0xcf, 0x4f, 0xb2, 0x91, 0x12, 0x15, 0x67,
	0x21, 0xa0, 0x8d, 0xf8, 0x36, 0x13, 0xde, 0x25
};

static unsigned char ecdh_master_secret_expected[] = {
	0x6c, 0x61, 0xcc, 0x93, 0x50, 0xbf, 0x87, 0xe1,
	0x3c, 0x0d, 0xc8, 0x60, 0xbd, 0xfd, 0xfc, 0x58,
	0xab, 0xc7, 0x9f, 0xe7, 0x0f, 0x35, 0x3a, 0x33,
	0xd3, 0x11, 0xc4, 0x36, 0x1b, 0x32, 0x53, 0xe8
};

static unsigned char ecdh_hash_token[] = {
	0xd0, 0xdf, 0x40, 0xee, 0x8c, 0x54, 0x25, 0xba,
	0x46, 0x74, 0xf3, 0x4a, 0x33, 0x95, 0xde, 0xc6,
	0xec, 0xe9, 0xe1, 0xd6, 0x60, 0x50, 0x1e, 0xd5,
	0x16, 0xbe, 0xaf, 0xce, 0x1c, 0x24, 0x49, 0x4c
};

int TC_iot_crypto_ecdh_setup(void **state)
{
	iot_crypto_ecdh_params_t *ecdh_params;
	size_t ecdh_params_len = sizeof(iot_crypto_ecdh_params_t);
	ecdh_params = (iot_crypto_ecdh_params_t *)malloc(ecdh_params_len);
	assert_non_null(ecdh_params);

	ecdh_params->t_seckey = things_seckey_curve25519;
	ecdh_params->s_pubkey = cloud_pubkey_curve25519;
	ecdh_params->hash_token = ecdh_hash_token;
	ecdh_params->hash_token_len = sizeof(ecdh_hash_token);

	*state = ecdh_params;

	return 0;
}

int TC_iot_crypto_ecdh_teardown(void **state)
{
	iot_crypto_ecdh_params_t *ecdh_params;
	ecdh_params = (iot_crypto_ecdh_params_t *)*state;

	free(ecdh_params);

	return 0;
}

void TC_iot_crypto_ecdh_invalid_parameter(void **state)
{
	iot_error_t err;
	iot_crypto_ecdh_params_t *ecdh_params;
	unsigned char master[IOT_CRYPTO_SECRET_LEN];
	size_t master_len = sizeof(master);

	ecdh_params = (iot_crypto_ecdh_params_t *)*state;

	// When: master is null
	err = iot_crypto_ecdh_gen_master_secret(NULL, master_len, ecdh_params);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// When: mlen is zero
	err = iot_crypto_ecdh_gen_master_secret(master, 0, ecdh_params);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// When: params is null
	err = iot_crypto_ecdh_gen_master_secret(master, master_len, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: insufficient master buffer
	master_len = sizeof(master) - 1;
	// When
	err = iot_crypto_ecdh_gen_master_secret(master, master_len, ecdh_params);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_crypto_ecdh_success(void **state)
{
	iot_error_t err;
	iot_crypto_ecdh_params_t *ecdh_params;
	unsigned char master[IOT_CRYPTO_SECRET_LEN];
	size_t master_len = sizeof(master);

	// Given
	ecdh_params = (iot_crypto_ecdh_params_t *)*state;
	// When
	err = iot_crypto_ecdh_gen_master_secret(master, master_len, ecdh_params);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(master, ecdh_master_secret_expected, master_len);
}

int TC_iot_crypto_ed25519_keypair_setup(void **state)
{
	iot_crypto_ed25519_keypair_t *keypair;
	size_t keypair_len = sizeof(iot_crypto_ed25519_keypair_t);

	keypair = (iot_crypto_ed25519_keypair_t *)malloc(keypair_len);
	assert_non_null(keypair);

	iot_crypto_ed25519_init_keypair(keypair);

	*state = keypair;

	return 0;
}

int TC_iot_crypto_ed25519_keypair_teardown(void **state)
{
	iot_crypto_ed25519_keypair_t *keypair;

	keypair = (iot_crypto_ed25519_keypair_t *)*state;

	iot_crypto_ed25519_free_keypair(keypair);

	free(keypair);

	return 0;
}

void TC_iot_crypto_ed25519_keypair_invalid_parameter(void **state)
{
	iot_error_t err;
	iot_crypto_ed25519_keypair_t *keypair;
	unsigned char *tmpkey;

	keypair = (iot_crypto_ed25519_keypair_t *)*state;
	assert_non_null(keypair);

	// Given: pk is null
	// When
	err = iot_crypto_ed25519_convert_keypair(NULL);
	// then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: ed25519 pubkey is null
	tmpkey = keypair->sign.pubkey;
	keypair->sign.pubkey = NULL;
	// When
	err = iot_crypto_ed25519_convert_keypair(keypair);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
	// Local teardown
	keypair->sign.pubkey = tmpkey;

	// Given: ed25519 seckey is null
	tmpkey = keypair->sign.seckey;
	keypair->sign.seckey = NULL;
	// When
	err = iot_crypto_ed25519_convert_keypair(keypair);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
	// Local teardown
	keypair->sign.seckey = tmpkey;

	// Given: curve25519 pubkey is null
	tmpkey = keypair->curve.pubkey;
	keypair->curve.pubkey = NULL;
	// When
	err = iot_crypto_ed25519_convert_keypair(keypair);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
	// Local teardown
	keypair->curve.pubkey = tmpkey;

	// Given: curve25519 seckey is null
	tmpkey = keypair->curve.seckey;
	keypair->curve.seckey = NULL;
	// When
	err = iot_crypto_ed25519_convert_keypair(keypair);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
	// Local teardown
	keypair->curve.seckey = tmpkey;
}

void TC_iot_crypto_ed25519_keypair_success(void **state)
{
	iot_error_t err;
	iot_crypto_ed25519_keypair_t *keypair;
	unsigned char *pubkey_curve25519_expected = cloud_pubkey_curve25519;
	unsigned char *seckey_curve25519_expected = things_seckey_curve25519;

	keypair = (iot_crypto_ed25519_keypair_t *)*state;
	assert_non_null(keypair);

	// Given
	memcpy(keypair->sign.pubkey, cloud_pubkey_ed25519, sizeof(cloud_pubkey_ed25519));
	memcpy(keypair->sign.seckey, things_seckey_ed25519, sizeof(things_seckey_ed25519));
	// When
	err = iot_crypto_ed25519_convert_keypair(keypair);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(keypair->curve.pubkey, pubkey_curve25519_expected, IOT_CRYPTO_ED25519_LEN);
	assert_memory_equal(keypair->curve.seckey, seckey_curve25519_expected, IOT_CRYPTO_ED25519_LEN);
}

void TC_iot_crypto_ed25519_convert_invalid_parameter(void **state)
{
	iot_error_t err;
	unsigned char key_curve25519[IOT_CRYPTO_ED25519_LEN];

	// Given: ed25519 buffer is null
	// When
	err = iot_crypto_ed25519_convert_pubkey(cloud_pubkey_ed25519, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: curve25519 buffer is null
	// When
	err = iot_crypto_ed25519_convert_pubkey(NULL, key_curve25519);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: ed25519 buffer is null
	// When
	err = iot_crypto_ed25519_convert_seckey(things_seckey_ed25519, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// Given: curve25519 buffer is null
	// When
	err = iot_crypto_ed25519_convert_seckey(NULL, key_curve25519);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_crypto_ed25519_convert_success(void **state)
{
	iot_error_t err;
	unsigned char *key_ed25519;
	unsigned char key_curve25519[IOT_CRYPTO_ED25519_LEN];
	unsigned char *key_curve25519_expected;

	// Given: pubkey
	key_ed25519 = cloud_pubkey_ed25519;
	key_curve25519_expected = cloud_pubkey_curve25519;
	// When
	err = iot_crypto_ed25519_convert_pubkey(key_ed25519, key_curve25519);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(key_curve25519, key_curve25519_expected, IOT_CRYPTO_ED25519_LEN);

	// Given: seckey
	key_ed25519 = things_seckey_ed25519;
	key_curve25519_expected = things_seckey_curve25519;
	// When
	err = iot_crypto_ed25519_convert_seckey(key_ed25519, key_curve25519);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(key_curve25519, key_curve25519_expected, IOT_CRYPTO_ED25519_LEN);
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

static const size_t b64_encode_len_input[] = {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static const size_t b64_encode_len_required[] = {
	4, 4, 8, 8, 8, 12, 12, 12, 16, 16, 16, 20, 20, 20, 24,
	24, 24, 28, 28, 28, 32, 32, 32, 36, 36, 36, 40, 40, 40, 44
};

static const size_t b64_decode_len_input[] = {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static const size_t b64_decode_len_required[] = {
	3, 3, 3, 6, 6, 6, 6, 9, 9, 9, 9, 12, 12, 12, 12,
	15, 15, 15, 15, 18, 18, 18, 18, 21, 21, 21, 21, 24, 24, 24
};

void TC_iot_crypto_base64_buffer_size(void **state)
{
	const size_t *input;
	const size_t *expected;
	size_t required_len;
	int test_len;
	int i;

	// Given
	test_len = sizeof(b64_encode_len_input) / sizeof(b64_encode_len_input[0]);
	input = b64_encode_len_input;
	expected = b64_encode_len_required;
	for (i = 0; i < test_len; i++) {
		// When
		required_len = IOT_CRYPTO_CAL_B64_LEN(input[i]);
		// Then
		assert_int_equal(required_len, expected[i] + 1);
	}

	// Given
	test_len = sizeof(b64_decode_len_input) / sizeof(b64_decode_len_input[0]);
	input = b64_decode_len_input;
	expected = b64_decode_len_required;
	for (i = 0; i < test_len; i++) {
		// When
		required_len = IOT_CRYPTO_CAL_B64_DEC_LEN(input[i]);
		// Then
		assert_int_equal(required_len, expected[i] + 1);
	}
}