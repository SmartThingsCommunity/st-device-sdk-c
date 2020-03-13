/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"

#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/cipher.h"

static iot_error_t _iot_crypto_url_encode(char *buf, size_t buf_len)
{
	size_t i;

	if (!buf) {
		IOT_ERROR("encode buf is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!buf_len) {
		IOT_ERROR("encode length is zero");
		return IOT_ERROR_INVALID_ARGS;
	}

	for (i = 0; i < buf_len; i++) {
		switch (buf[i]) {
		case '+':
			buf[i] = '-';
			break;
		case '/':
			buf[i] = '_';
			break;
		default:
			break;
		}
	}

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_crypto_url_decode(char *buf, size_t buf_len)
{
	size_t i;

	if (!buf) {
		IOT_ERROR("decode buf is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!buf_len) {
		IOT_ERROR("decode length is zero");
		return IOT_ERROR_INVALID_ARGS;
	}

	for (i = 0; i < buf_len; i++) {
		switch (buf[i]) {
		case '-':
			buf[i] = '+';
			break;
		case '_':
			buf[i] = '/';
			break;
		default:
			break;
		}
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_base64_encode(const unsigned char *src, size_t src_len,
                                     unsigned char *dst, size_t dst_len,
                                     size_t *out_len)
{
	int ret;

	IOT_DEBUG("plain : %s (%d)", src, src_len);

	ret = mbedtls_base64_encode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("mbedtls_base64_encode = -0x%04X", -ret);
		return IOT_ERROR_CRYPTO_BASE64;
	}

	IOT_DEBUG("base64 : %s (%d)", dst, *out_len);

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_base64_decode(const unsigned char *src, size_t src_len,
                                     unsigned char *dst, size_t dst_len,
                                     size_t *out_len)
{
	int ret;

	IOT_DEBUG("base64 : %s (%d)", src, src_len);

	ret = mbedtls_base64_decode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("mbedtls_base64_decode = -0x%04X", -ret);
		return IOT_ERROR_CRYPTO_BASE64;
	}

	IOT_DEBUG("plain : %s (%d)", dst, *out_len);

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_base64_encode_urlsafe(unsigned char *src, size_t src_len,
                                             unsigned char *dst, size_t dst_len,
                                             size_t *out_len)
{
	int ret;

	IOT_DEBUG("plain : %s (%d)", src, src_len);

	ret = mbedtls_base64_encode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("mbedtls_base64_encode = -0x%04X", -ret);
		return IOT_ERROR_CRYPTO_BASE64_URLSAFE;
	}

	IOT_DEBUG("base64 : %s (%d)", dst, *out_len);

	ret = _iot_crypto_url_encode((char *)dst, *out_len);
	if (ret) {
		IOT_ERROR("_iot_crypto_url_encode = %d", ret);
		return IOT_ERROR_CRYPTO_BASE64_URLSAFE;
	}

	IOT_DEBUG("urlsafe: %s (%d)", dst, *out_len);

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_base64_decode_urlsafe(unsigned char *src, size_t src_len,
                                             unsigned char *dst, size_t dst_len,
                                             size_t *out_len)
{
	int ret;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char *src_dup = NULL;
	size_t pad_len;
	int i;

	IOT_DEBUG("urlsafe: %s (%d)", src, src_len);

	pad_len = IOT_CRYPTO_ALIGN_B64_LEN(src_len);
	src_dup = (unsigned char *)malloc(pad_len + 1);
	if (src_dup == NULL) {
		IOT_ERROR("malloc failed for align buffer");
		return IOT_ERROR_MEM_ALLOC;
	}

	memcpy(src_dup, src, src_len);
	/* consider '=' removed from tail */
	for (i = src_len; i < pad_len; i++) {
		src_dup[i] = '=';
	}
	src_dup[pad_len] = '\0';

	ret = _iot_crypto_url_decode((char *)src_dup, pad_len);
	if (ret) {
		IOT_ERROR("_iot_crypto_url_decode = %d", ret);
		err = IOT_ERROR_CRYPTO_BASE64_URLSAFE;
		goto exit;
	}

	IOT_DEBUG("base64 : %s (%d)", src_dup, pad_len);

	ret = mbedtls_base64_decode(dst, dst_len, out_len, src_dup, pad_len);
	if (ret) {
		IOT_ERROR("mbedtls_base64_decode = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_BASE64_URLSAFE;
		goto exit;
	}

	IOT_DEBUG("plain : %s (%d)", dst, *out_len);
exit:
	if (src_dup)
		free(src_dup);

	return err;
}

iot_error_t iot_crypto_sha256(unsigned char *src, size_t src_len, unsigned char *dst)
{
	int ret;

	IOT_DEBUG("src: %d@%p, dst: %p", src_len, src, dst);

	ret = mbedtls_sha256_ret(src, src_len, dst, 0);
	if (ret) {
		IOT_ERROR("mbedtls_sha256_ret = -0x%04X", -ret);
		return IOT_ERROR_CRYPTO_SHA256;
	}

	return IOT_ERROR_NONE;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
static iot_error_t _iot_crypto_pk_rsa_sign(iot_crypto_pk_context_t *ctx,
                                          unsigned char *input, size_t ilen,
                                          unsigned char *sig, size_t *slen)
{
	int ret;
	iot_error_t err = IOT_ERROR_NONE;
	mbedtls_pk_context pk;
	mbedtls_md_type_t md_alg;
	unsigned char *hash = NULL;
	size_t hash_len;

	IOT_DEBUG("input: %d@%p, key: %d@%p", ilen, input,
				ctx->info->seckey_len, ctx->info->seckey);

	mbedtls_pk_init(&pk);
	ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)ctx->info->seckey,
					ctx->info->seckey_len + 1, NULL, 0);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_CRYPTO_PK_PARSEKEY;
		goto exit;
	}

	md_alg = MBEDTLS_MD_SHA256;
	hash_len = IOT_CRYPTO_SHA256_LEN;
	hash = (unsigned char *)malloc(hash_len);

	err = iot_crypto_sha256(input, ilen, hash);
	if (err) {
		goto exit;
	}

	ret = mbedtls_pk_sign(&pk, md_alg, hash, hash_len, sig, slen, NULL, NULL);
	if (ret) {
		IOT_ERROR("mbedtls_pk_sign = -0x%04X\n", -ret);
		err = IOT_ERROR_CRYPTO_PK_SIGN;
		goto exit;
	}

	IOT_DEBUG("sig: %d@%p", *slen, sig);
exit:
	mbedtls_pk_free(&pk);

	if (hash) {
		free(hash);
	}

	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
static iot_error_t _iot_crypto_pk_rsa_verify(iot_crypto_pk_context_t *ctx,
                                          unsigned char *input, size_t ilen,
                                          unsigned char *sig, size_t slen)
{
	iot_error_t err = IOT_ERROR_NONE;
	mbedtls_pk_context pk;
	mbedtls_md_type_t md_alg;
	unsigned char *hash = NULL;
	size_t hash_len;
	int ret;

	IOT_DEBUG("input: %d@%p, key: %d@%p", ilen, input,
				ctx->info->seckey_len, ctx->info->seckey);

	mbedtls_pk_init(&pk);

	ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)ctx->info->seckey,
					ctx->info->seckey_len + 1, NULL, 0);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = 0x%04X\n", ret);
		err = IOT_ERROR_CRYPTO_PK_PARSEKEY;
		goto exit;
	}

	md_alg = MBEDTLS_MD_SHA256;
	hash_len = IOT_CRYPTO_SHA256_LEN;
	hash = (unsigned char *)malloc(hash_len);

	err = iot_crypto_sha256(input, ilen, hash);
	if (err) {
		goto exit;
	}

	IOT_DEBUG("hash: %d@%p", hash_len, hash);

	ret = mbedtls_pk_verify(&pk, md_alg, hash, hash_len, sig, slen);
	if (ret) {
		IOT_ERROR("mbedtls_pk_verify = 0x%04X\n", ret);
		err = IOT_ERROR_CRYPTO_PK_VERIFY;
		goto exit;
	}

	IOT_DEBUG("sign verify success");
exit:
	mbedtls_pk_free(&pk);

	if (hash) {
		free(hash);
	}

	return err;
}
#endif

const iot_crypto_pk_funcs_t iot_crypto_pk_rsa_funcs = {
	.name = "RSA",
	.sign = _iot_crypto_pk_rsa_sign,
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
	.verify = _iot_crypto_pk_rsa_verify,
#else
	.verify = NULL,
#endif
};
#endif

static iot_error_t _iot_crypto_swap_secret(unsigned char *key, size_t len)
{
	unsigned char *tmp;
	int i;

	tmp = (unsigned char *)malloc(len);
	if (tmp == NULL) {
		IOT_ERROR("malloc failed for swap");
		return IOT_ERROR_MEM_ALLOC;
	}

	for (i = 0; i < len; i++) {
		tmp[(len - 1) - i] = key[i];
	}

	memcpy(key, tmp, len);

	free((void *)tmp);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_crypto_ecdh_gen_premaster_secret(
		unsigned char **secret, size_t *olen,
		unsigned char *t_seckey, unsigned char *s_pubkey)
{
	iot_error_t err;
	mbedtls_ecdh_context ecdh;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_ecp_group_id ecp_grp_id = MBEDTLS_ECP_DP_CURVE25519;
	const char *pers = "iot_crypto_ecdh";
	size_t key_len = IOT_CRYPTO_ED25519_LEN;
	int ret;

	mbedtls_ecdh_init(&ecdh);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                            (const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	ret = mbedtls_ecp_group_load(&ecdh.grp, ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	err = _iot_crypto_swap_secret(t_seckey, key_len);
	if (err) {
		IOT_ERROR("_iot_crypto_swap_secret = %d", err);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&ecdh.d, t_seckey, key_len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	err = _iot_crypto_swap_secret(s_pubkey, key_len);
	if (err) {
		IOT_ERROR("_iot_crypto_swap_secret = %d", err);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&ecdh.Qp.X, s_pubkey, key_len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	ret = mbedtls_mpi_lset(&ecdh.Qp.Z, 1);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_lset = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&ecdh.grp, &ecdh.z,
		    &ecdh.Qp, &ecdh.d, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit; }

	*secret = (unsigned char *)malloc(key_len);
	if (*secret == NULL) {
		IOT_ERROR("malloc failed for secret");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&ecdh.z, *secret, key_len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit_secret;
	}

	err = _iot_crypto_swap_secret(*secret, key_len);
	if (err) {
		IOT_ERROR("_iot_crypto_swap_secret = %d", err);
		err = IOT_ERROR_CRYPTO_PK_ECDH;
		goto exit_secret;
	}

	*olen = key_len;

	err = IOT_ERROR_NONE;
	goto exit;

exit_secret:
	free((void *)*secret);
	*secret = NULL;
exit:
	mbedtls_ecdh_free(&ecdh);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return err;
}

iot_error_t iot_crypto_ecdh_gen_master_secret(unsigned char *master,
			size_t mlen, iot_crypto_ecdh_params_t *params)
{
	iot_error_t err;
	unsigned char *pmsecret = NULL;
	unsigned char *buf = NULL;
	size_t pmslen;
	size_t buf_len;

	if (!master) {
		IOT_ERROR("master buffer is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!params) {
		IOT_ERROR("params is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (mlen < IOT_CRYPTO_SECRET_LEN) {
		IOT_ERROR("master buffer is not enough");
		return IOT_ERROR_INVALID_ARGS;
	}

	err = _iot_crypto_ecdh_gen_premaster_secret(&pmsecret, &pmslen,
					params->t_seckey, params->s_pubkey);
	if (err) {
		goto exit;
	}

	buf_len = pmslen + params->hash_token_len;
	buf = (unsigned char *)malloc(buf_len);
	if (!buf) {
		IOT_ERROR("malloc failed for master secret");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	memcpy(buf, pmsecret, pmslen);
	memcpy(buf + pmslen, params->hash_token, params->hash_token_len);

	err = iot_crypto_sha256(buf, buf_len, master);
	if (err) {
		goto exit;
	}
exit:
	if (pmsecret)
		free(pmsecret);

	if (buf)
		free(buf);

	return err;
}

size_t iot_crypto_cipher_get_align_size(iot_crypto_cipher_type_t type,
			size_t size)
{
	const mbedtls_cipher_info_t *cipher_info;
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_type_t cipher_alg;
	unsigned int block_size;
	int ret;

	if (type == IOT_CRYPTO_CIPHER_AES256) {
		cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
	} else {
		IOT_ERROR("'%d' is not supported cipher algorithm", type);
		return 0;
	}

	cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
	if (!cipher_info) {
		IOT_ERROR("mbedtls_cipher_info_from_type returned null");
		return 0;
	}

	mbedtls_cipher_init(&cipher_ctx);

	ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		mbedtls_cipher_free(&cipher_ctx);
		return 0;
	}

	block_size = mbedtls_cipher_get_block_size(&cipher_ctx);

	size = size + (block_size - (size % block_size));

	mbedtls_cipher_free(&cipher_ctx);

	return size;
}

iot_error_t iot_crypto_cipher_aes(iot_crypto_cipher_info_t *info,
			unsigned char *input, size_t ilen,
			unsigned char *out, size_t *olen, size_t osize)
{
	iot_error_t err = IOT_ERROR_NONE;
	const mbedtls_cipher_info_t *cipher_info;
	mbedtls_cipher_type_t cipher_alg;
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_operation_t mode = MBEDTLS_ENCRYPT;
	int ret;

	if (!info) {
		IOT_ERROR("cipher info is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!input || !out || !olen) {
		IOT_ERROR("buffer is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if ((ilen == 0) || (osize == 0)) {
		IOT_ERROR("buffer length is zero");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("input: %d@%p", ilen, input);
	IOT_DEBUG("key:   %d@%p", info->key_len, info->key);
	IOT_DEBUG("iv:    %d@%p", info->iv_len, info->iv);

	if (info->type == IOT_CRYPTO_CIPHER_AES256) {
		cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
	} else {
		IOT_ERROR("'%d' is not a supported cipher algorithm", info->type);
		return IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE;
	}

	if (info->mode == IOT_CRYPTO_CIPHER_ENCRYPT) {
		mode = MBEDTLS_ENCRYPT;
	} else if (info->mode == IOT_CRYPTO_CIPHER_DECRYPT) {
		mode = MBEDTLS_DECRYPT;
	} else {
		IOT_ERROR("'%d' is invalid cipher mode", info->mode);
		return IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_MODE;
	}

	if (info->key_len != IOT_CRYPTO_SECRET_LEN) {
		IOT_ERROR("key length '%d' is wrong", info->key_len);
		return IOT_ERROR_CRYPTO_CIPHER_KEYLEN;
	}

	if (info->iv_len != IOT_CRYPTO_IV_LEN) {
		IOT_ERROR("iv length '%d' is wrong", info->iv_len);
		return IOT_ERROR_CRYPTO_CIPHER_IVLEN;
	}

	if (info->mode == IOT_CRYPTO_CIPHER_ENCRYPT) {
		if (osize < iot_crypto_cipher_get_align_size(info->type, ilen)) {
			IOT_ERROR("output buffer size is not sufficient");
			return IOT_ERROR_CRYPTO_CIPHER_OUTSIZE;
		}
	} else if (info->mode == IOT_CRYPTO_CIPHER_DECRYPT) {
		if (osize < ilen) {
			IOT_ERROR("output buffer size is not sufficient");
			return IOT_ERROR_CRYPTO_CIPHER_OUTSIZE;
		}
	}

	cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
	if (!cipher_info) {
		IOT_ERROR("mbedtls_cipher_info_from_type returned null");
		return IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE;
	}

	IOT_DEBUG("key len : %d, iv len : %d", cipher_info->key_bitlen / 8, cipher_info->iv_size);

	mbedtls_cipher_init(&cipher_ctx);

	ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_CIPHER;
		goto exit;
	}

	ret = mbedtls_cipher_setkey(&cipher_ctx, info->key, cipher_info->key_bitlen, mode);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_CIPHER;
		goto exit;
	}

	ret = mbedtls_cipher_crypt(&cipher_ctx, info->iv, info->iv_len,
			(const unsigned char *)input, ilen, out, olen);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_crypt = -0x%04X", -ret);
		err = IOT_ERROR_CRYPTO_CIPHER;
		goto exit;
	}

	IOT_DEBUG("out: (%d/%d)@%p", *olen, osize, out);
exit:
	mbedtls_cipher_free(&cipher_ctx);

	return err;
}
