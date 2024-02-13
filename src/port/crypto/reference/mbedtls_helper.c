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

#include "iot_debug.h"
#include "mbedtls_helper.h"

#include "mbedtls/version.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"

iot_error_t mbedtls_helper_sha512(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	int ret;

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_sha512(input, input_len, output, 0);
#else
	ret = mbedtls_sha512_ret(input, input_len, output, 0);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_sha512_ret = -0x%04X", -ret);
		return IOT_ERROR_SECURITY_SHA256;
	}

	return IOT_ERROR_NONE;
}

iot_error_t mbedtls_helper_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	int ret;

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_sha256(input, input_len, output, 0);
#else
	ret = mbedtls_sha256_ret(input, input_len, output, 0);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_sha256_ret = -0x%04X", -ret);
		return IOT_ERROR_SECURITY_SHA256;
	}

	return IOT_ERROR_NONE;
}

static iot_error_t _convert_seckey_to_raw(mbedtls_ecp_keypair *mbed_ecp_keypair, iot_security_buffer_t *key_buf)
{
	unsigned char raw[32];
	int ret;

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_mpi_write_binary(&mbed_ecp_keypair->MBEDTLS_PRIVATE(d), raw, sizeof(raw));
#else
	ret = mbedtls_mpi_write_binary(&mbed_ecp_keypair->d, raw, sizeof(raw));
#endif
	if (ret) {
		IOT_ERROR("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		return IOT_ERROR_SECURITY_MANAGER_KEY_GET;
	}

	/* remove ecp prefix */
	key_buf->len = sizeof(raw);
	key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
	if (!key_buf->p) {
		IOT_ERROR("failed to malloc for pubkey");
		key_buf->len = 0;
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	memcpy(key_buf->p, raw, key_buf->len);

	return IOT_ERROR_NONE;
}

static iot_error_t _convert_pubkey_to_raw(mbedtls_ecp_keypair *mbed_ecp_keypair, iot_security_buffer_t *key_buf)
{
	unsigned char raw[64 + 1];
	size_t olen;
	int ret;

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_ecp_point_write_binary(&mbed_ecp_keypair->MBEDTLS_PRIVATE(grp),
					     &mbed_ecp_keypair->MBEDTLS_PRIVATE(Q),
					     MBEDTLS_ECP_PF_UNCOMPRESSED,
					     &olen, raw, sizeof(raw));
#else
	ret = mbedtls_ecp_point_write_binary(&mbed_ecp_keypair->grp,
					     &mbed_ecp_keypair->Q,
					     MBEDTLS_ECP_PF_UNCOMPRESSED,
					     &olen, raw, sizeof(raw));
#endif
	if (ret) {
		IOT_ERROR("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		return IOT_ERROR_SECURITY_MANAGER_KEY_GET;
	}

	/* remove ecp prefix */
	key_buf->len = olen;
	key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
	if (!key_buf->p) {
		IOT_ERROR("failed to malloc for pubkey");
		key_buf->len = 0;
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	memcpy(key_buf->p, raw, key_buf->len);

	return IOT_ERROR_NONE;
}

iot_error_t mbedtls_helper_gen_secp256r1_keypair(iot_security_buffer_t *seckey_buf, iot_security_buffer_t *pubkey_buf)
{
	iot_error_t err = IOT_ERROR_SECURITY_MANAGER_KEY_GENERATE;
	int ret;

	mbedtls_ecp_keypair *mbed_ecp_keypair;
	const char *curve_name = "secp256r1";
	const mbedtls_ecp_curve_info *mbed_curve_info;

	mbedtls_ctr_drbg_context mbed_ctr_drbg;
	mbedtls_entropy_context mbed_entropy;
	mbedtls_ctr_drbg_init(&mbed_ctr_drbg);
	mbedtls_entropy_init(&mbed_entropy);
	const char *pers = "_iot_security_be_software_manager_generate_key";

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy, (const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		return err;
	}

	mbed_curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
	if (mbed_curve_info == NULL) {
		IOT_ERROR("mbedtls_ecp_curve_info_from_name = -0x%04X", -ret);
		goto exit;
	}

	mbed_ecp_keypair = (mbedtls_ecp_keypair *)iot_os_malloc(sizeof(mbedtls_ecp_keypair));
	if (!mbed_ecp_keypair) {
		IOT_ERROR("failed to malloc for ephemeral keypair");
		err = IOT_ERROR_SECURITY_MEM_ALLOC;
		goto exit;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	mbedtls_ecp_group_init(&mbed_ecp_keypair->MBEDTLS_PRIVATE(grp));
	mbedtls_mpi_init(&mbed_ecp_keypair->MBEDTLS_PRIVATE(d));
	mbedtls_ecp_point_init(&mbed_ecp_keypair->MBEDTLS_PRIVATE(Q));
#else
	mbedtls_ecp_group_init(&mbed_ecp_keypair->grp);
	mbedtls_mpi_init(&mbed_ecp_keypair->d);
	mbedtls_ecp_point_init(&mbed_ecp_keypair->Q);
#endif

	ret = mbedtls_ecp_gen_key(mbed_curve_info->grp_id, mbed_ecp_keypair, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_gen_key = -0x%04X", -ret);
		goto exit_keypair_buffer_free;
	}

	ret = _convert_pubkey_to_raw(mbed_ecp_keypair, pubkey_buf);
	if (ret) {
		IOT_ERROR("_convert_pubkey_to_raw = -0x%04X", -ret);
		goto exit_keypair_buffer_free;
	}

	ret = _convert_seckey_to_raw(mbed_ecp_keypair, seckey_buf);
	if (ret) {
		IOT_ERROR("_convert_seckey_to_raw = -0x%04X", -ret);
		pubkey_buf->len = 0;
		if (pubkey_buf->p) {
			iot_os_free(pubkey_buf->p);
			pubkey_buf->p = NULL;
		}
		goto exit_keypair_buffer_free;
	}

	err = IOT_ERROR_NONE;

exit_keypair_buffer_free:
	iot_os_free(mbed_ecp_keypair);
exit:
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

	return err;
}

iot_error_t mbedtls_helper_pk_sign_rsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
	int ret;

	if (!pk_params->seckey.p || (pk_params->seckey.len == 0)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		return IOT_ERROR_SECURITY_PK_INVALID_SECKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_pk_init(&mbed_pk_context);

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0, NULL, NULL);
#else
	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		goto exit;
	}

	sig_buf->len = 256U;
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		err = IOT_ERROR_SECURITY_MEM_ALLOC;
		goto exit;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, 256, &sig_buf->len, NULL, NULL);
#else
	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, &sig_buf->len, NULL, NULL);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_pk_sign = -0x%04X\n", -ret);
		iot_security_buffer_free(sig_buf);
		err = IOT_ERROR_SECURITY_PK_SIGN;
		goto exit;
	}

	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);

	err = IOT_ERROR_NONE;
exit:
	mbedtls_pk_free(&mbed_pk_context);

	return err;
}

static iot_error_t _pk_der_to_raw(iot_security_buffer_t *der_buf, iot_security_buffer_t *raw_buf)
{
	unsigned char *p;
	int len;

	if (!der_buf || !raw_buf) {
		IOT_ERROR("pk asn1 params is null");
		IOT_ERROR_DUMP_AND_RETURN(PK_PARAMS_NULL, 0);
	}

	p = der_buf->p;
	raw_buf->len = 0;

	// TAG : SEQUENCE
	if (*p++ != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
		IOT_ERROR("not found sequence tag");
		return -MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
	}

	len = *p++;

	// TAG : INTEGER for 's'
	if (*p++ != MBEDTLS_ASN1_INTEGER) {
		IOT_ERROR("not found integer tag");
		return -MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
	}

	len = *p++;

	if (*p == 0) {
		p++;
		len--;
	}

	memcpy(raw_buf->p + raw_buf->len, p, len);
	p += len;
	raw_buf->len += len;

	// TAG : INTEGER for 'r'
	if (*p++ != MBEDTLS_ASN1_INTEGER) {
		IOT_ERROR("not found integer tag");
		return -MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
	}

	len = *p++;

	if (*p == 0) {
		p++;
		len--;
	}

	memcpy(raw_buf->p + raw_buf->len, p, len);
	p += len;
	raw_buf->len += len;

	return 0;
}

iot_error_t mbedtls_helper_pk_sign_ecdsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
	iot_security_buffer_t raw_buf = { 0 };
	int ret;

	if (!pk_params->seckey.p || (pk_params->seckey.len == 0)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		return IOT_ERROR_SECURITY_PK_INVALID_SECKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_pk_init(&mbed_pk_context);

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0, NULL, NULL);
#else
	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		goto exit;
	}

	sig_buf->len = 1024U;
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		return IOT_ERROR_MEM_ALLOC;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, 1024, &sig_buf->len, NULL, NULL);
#else
	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, &sig_buf->len, NULL, NULL);
#endif
	if (ret) {
		IOT_ERROR("mbedtls_pk_sign = -0x%04X\n", -ret);
		iot_security_buffer_free(sig_buf);
		err = IOT_ERROR_SECURITY_PK_SIGN;
		goto exit;
	}

	raw_buf.p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!raw_buf.p) {
		IOT_ERROR("failed to malloc for raw buf");
		iot_security_buffer_free(sig_buf);
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	if (pk_params->pk_sign_type == IOT_SECURITY_PK_SIGN_TYPE_DER) {
		memcpy(raw_buf.p, sig_buf->p, sig_buf->len);
		raw_buf.len = sig_buf->len;
	}
	else {
		err = _pk_der_to_raw(sig_buf, &raw_buf);
		if (err) {
			IOT_ERROR("failed to convert from der to raw");
			iot_security_buffer_free(sig_buf);
			iot_security_buffer_free(&raw_buf);
			err = IOT_ERROR_SECURITY_PK_SIGN;
			goto exit;
		}
	}

	memset(sig_buf->p, 0, sig_buf->len);
	iot_os_free(sig_buf->p);
	sig_buf->p = raw_buf.p;
	sig_buf->len = raw_buf.len;

	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);

	err = IOT_ERROR_NONE;
exit:
	mbedtls_pk_free(&mbed_pk_context);

	return err;
}

iot_error_t mbedtls_helper_pk_verify_rsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	mbedtls_x509_crt mbed_x509_crt;
	mbedtls_md_type_t mbed_md_type;
	int ret;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		return IOT_ERROR_SECURITY_PK_INVALID_PUBKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_x509_crt_init(&mbed_x509_crt);

	ret = mbedtls_x509_crt_parse(&mbed_x509_crt, (const unsigned char *)pk_params->pubkey.p, pk_params->pubkey.len + 1);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		goto exit;
	}

	ret = mbedtls_pk_verify(&mbed_x509_crt.pk, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, sig_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_pk_verify = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_VERIFY;
		goto exit;
	}

	IOT_DEBUG("sign verify success");

	err = IOT_ERROR_NONE;
exit:
	mbedtls_x509_crt_free(&mbed_x509_crt);

	return err;
}

iot_error_t mbedtls_helper_pk_verify_ecdsa(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	mbedtls_x509_crt mbed_x509_crt;
	mbedtls_md_type_t mbed_md_type;
	int ret;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		return IOT_ERROR_SECURITY_PK_INVALID_PUBKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_x509_crt_init(&mbed_x509_crt);

	ret = mbedtls_x509_crt_parse(&mbed_x509_crt, (const unsigned char *)pk_params->pubkey.p, pk_params->pubkey.len + 1);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		goto exit;
	}

	ret = mbedtls_pk_verify(&mbed_x509_crt.pk, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, sig_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_pk_verify = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_VERIFY;
		goto exit;
	}

	IOT_DEBUG("sign verify success");

	err = IOT_ERROR_NONE;
exit:
	mbedtls_x509_crt_free(&mbed_x509_crt);

	return err;
}

static inline void _cipher_buffer_wipe(const iot_security_buffer_t *input_buf, size_t wiped_len)
{
	if (input_buf && (input_buf->len < wiped_len)) {
		int i;
		for (i = input_buf->len; i < wiped_len; i++) {
			input_buf->p[i] = 0;
		}
	}
}

static size_t _cipher_get_align_size(iot_security_key_type_t key_type, size_t data_size)
{
	const mbedtls_cipher_info_t *cipher_info;
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_type_t cipher_alg;
	unsigned int block_size;
	int ret;

	IOT_DEBUG("data size = %d, type = %d", (int)data_size, key_type);

	if (key_type == IOT_SECURITY_KEY_TYPE_AES256) {
		cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
	} else {
		IOT_ERROR("'%d' is not supported cipher algorithm", key_type);
		return 0;
	}

	if (!data_size) {
		IOT_ERROR("input size is zero");
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
	if (block_size == 0) {
		IOT_ERROR("mbedtls_cipher_get_block_size returned zero");
		mbedtls_cipher_free(&cipher_ctx);
		return 0;
	}

	data_size = data_size + (block_size - (data_size % block_size));

	mbedtls_cipher_free(&cipher_ctx);

	IOT_DEBUG("align size = %d", (int)data_size);

	return data_size;
}

static iot_error_t _cipher_aes_check_info(iot_security_cipher_params_t *cipher_params, const mbedtls_cipher_info_t *mbed_cipher_info)
{
#if MBEDTLS_VERSION_NUMBER > 0x03000000
	size_t mbed_cipher_key_bitlen, mbed_cipher_iv_size;
#endif
	if (!cipher_params || !mbed_cipher_info) {
		IOT_ERROR("parameters are null");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	mbed_cipher_key_bitlen = mbedtls_cipher_info_get_key_bitlen(mbed_cipher_info);
	mbed_cipher_iv_size = mbedtls_cipher_info_get_iv_size(mbed_cipher_info);
	if (cipher_params->key.len != (mbed_cipher_key_bitlen / 8)) {
		IOT_ERROR("key len mismatch, %d != %d", cipher_params->key.len, mbed_cipher_key_bitlen / 8);
		return IOT_ERROR_SECURITY_CIPHER_KEY_LEN;
	}

	if (cipher_params->iv.len != mbed_cipher_iv_size) {
		IOT_ERROR("iv len mismatch, %d != %d", cipher_params->iv.len, mbed_cipher_iv_size);
		return IOT_ERROR_SECURITY_CIPHER_IV_LEN;
	}
#else
	if (cipher_params->key.len != (mbed_cipher_info->key_bitlen / 8)) {
		IOT_ERROR("key len mismatch, %d != %d", cipher_params->key.len, (mbed_cipher_info->key_bitlen / 8));
		return IOT_ERROR_SECURITY_CIPHER_KEY_LEN;
	}

	if (cipher_params->iv.len != mbed_cipher_info->iv_size) {
		IOT_ERROR("iv len mismatch, %d != %d", cipher_params->iv.len, mbed_cipher_info->iv_size);
		return IOT_ERROR_SECURITY_CIPHER_IV_LEN;
	}
#endif

	return IOT_ERROR_NONE;
}

iot_error_t mbedtls_helper_cipher_aes(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf, bool is_encrypt)
{
	iot_error_t err;
	const mbedtls_cipher_info_t *mbed_cipher_info;
#if MBEDTLS_VERSION_NUMBER > 0x03000000
	size_t mbed_cipher_key_bitlen;
#endif
	mbedtls_cipher_type_t mbed_cipher_alg;
	mbedtls_cipher_context_t mbed_cipher_ctx;
	mbedtls_operation_t mbed_op_mode;
	size_t required_len;
	int ret;

	if (is_encrypt) {
		mbed_op_mode = MBEDTLS_ENCRYPT;
	} else {
		mbed_op_mode = MBEDTLS_DECRYPT;
	}

	mbed_cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;

	if (!cipher_params->key.p) {
		IOT_ERROR("key is invalid");
		return IOT_ERROR_SECURITY_CIPHER_INVALID_KEY;
	}

	if (!cipher_params->iv.p) {
		IOT_ERROR("iv is invalid");
		return IOT_ERROR_SECURITY_CIPHER_INVALID_IV;
	}

	IOT_DEBUG("input: %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("key:   %3d@%p", (int)cipher_params->key.len, cipher_params->key.p);
	IOT_DEBUG("iv:    %3d@%p", (int)cipher_params->iv.len, cipher_params->iv.p);

	mbed_cipher_info = mbedtls_cipher_info_from_type(mbed_cipher_alg);
	if (!mbed_cipher_info) {
		IOT_ERROR("mbedtls_cipher_info_from_type returned null");
		return IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO;
	}

	err = _cipher_aes_check_info(cipher_params, mbed_cipher_info);
	if (err) {
		return err;
	}

	mbedtls_cipher_init(&mbed_cipher_ctx);

	if (is_encrypt) {
		required_len = _cipher_get_align_size(cipher_params->type, input_buf->len);
	} else {
		required_len = input_buf->len;
	}

	output_buf->p = (unsigned char *)iot_os_malloc(required_len);
	if (!output_buf->p) {
		IOT_ERROR("failed to malloc for output buffer");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}
	memset(output_buf->p, 0, required_len);

	ret = mbedtls_cipher_setup(&mbed_cipher_ctx, mbed_cipher_info);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	mbed_cipher_key_bitlen = mbedtls_cipher_info_get_key_bitlen(mbed_cipher_info);
	ret = mbedtls_cipher_setkey(&mbed_cipher_ctx, cipher_params->key.p, mbed_cipher_key_bitlen, mbed_op_mode);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}

	ret = mbedtls_cipher_set_padding_mode(&mbed_cipher_ctx, MBEDTLS_PADDING_PKCS7);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_set_padding_mode = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_output_buf;
	}
#else
	ret = mbedtls_cipher_setkey(&mbed_cipher_ctx, cipher_params->key.p, mbed_cipher_info->key_bitlen, mbed_op_mode);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}
#endif

	ret = mbedtls_cipher_crypt(&mbed_cipher_ctx, cipher_params->iv.p, cipher_params->iv.len,
				   (const unsigned char *)input_buf->p, input_buf->len, output_buf->p, &output_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_crypt = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}

	if (output_buf->len > required_len) {
		IOT_ERROR("buffer overflow in cipher '%d' (%d > %d)", is_encrypt, (int)output_buf->len, (int)required_len);
		err = IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW;
		goto exit_free_output_buf;
	}

	_cipher_buffer_wipe(output_buf, required_len);

	IOT_DEBUG("key:   %3d@%p", (int)cipher_params->key.len, cipher_params->key.p);

	err = IOT_ERROR_NONE;
	goto exit;

exit_free_output_buf:
	iot_security_buffer_free(output_buf);
exit:
	mbedtls_cipher_free(&mbed_cipher_ctx);

	return err;
}

iot_error_t mbedtls_helper_ecdh_compute_shared_ecdsa(iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	mbedtls_ecdh_context mbed_ecdh;
	mbedtls_ctr_drbg_context mbed_ctr_drbg;
	mbedtls_entropy_context mbed_entropy;
	mbedtls_ecp_group_id mbed_ecp_grp_id = MBEDTLS_ECP_DP_SECP256R1;
	const char *pers = "iot_security_ecdh";
	iot_security_buffer_t pmsecret_buf = { 0 };
	size_t key_len;
	size_t secret_len;
	unsigned char public_buf[66];		/* length + tag + Q.X + Q.Y */
	int ret;

	if (!t_seckey_buf || !c_pubkey_buf || !output_buf) {
		IOT_ERROR("parameters is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	key_len = 64;
	secret_len = 32;

	if (t_seckey_buf->len > key_len) {
		IOT_ERROR("things seckey is too large");
		return IOT_ERROR_SECURITY_ECDH_INVALID_SECKEY;
	}

	// c_pubkey_buf include tag(1 byte) + key
	if (c_pubkey_buf->len > key_len + 1) {
		IOT_ERROR("cloud pubkey is too large");
		return IOT_ERROR_SECURITY_ECDH_INVALID_PUBKEY;
	}

	pmsecret_buf.len = secret_len;
	pmsecret_buf.p = (unsigned char *)iot_os_malloc(pmsecret_buf.len);
	if (!pmsecret_buf.p) {
		IOT_ERROR("malloc failed for pre master secret");
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	mbedtls_ecdh_init(&mbed_ecdh);
	mbedtls_ctr_drbg_init(&mbed_ctr_drbg);
	mbedtls_entropy_init(&mbed_entropy);

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy,
				    (const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	/*
	 * own key
	 */
	ret = mbedtls_ecp_group_load(&mbed_ecdh.MBEDTLS_PRIVATE(grp), mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.MBEDTLS_PRIVATE(d), t_seckey_buf->p, t_seckey_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	/*
	 * peer key
	 */
	public_buf[0] = c_pubkey_buf->len;
	memcpy(&public_buf[1], c_pubkey_buf->p, c_pubkey_buf->len);

	ret = mbedtls_ecdh_read_public(&mbed_ecdh, public_buf, sizeof(public_buf));
	if (ret) {
		printf("mbedtls_ecdh_read_public = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	/*
	 * ecdh
	 */

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.MBEDTLS_PRIVATE(grp),
			&mbed_ecdh.MBEDTLS_PRIVATE(z),
			&mbed_ecdh.MBEDTLS_PRIVATE(Qp),
			&mbed_ecdh.MBEDTLS_PRIVATE(d), mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.MBEDTLS_PRIVATE(z), pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}
#else
	/*
	 * own key
	 */
	ret = mbedtls_ecp_group_load(&mbed_ecdh.grp, mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.d, t_seckey_buf->p, t_seckey_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	/*
	 * peer key
	 */
	public_buf[0] = c_pubkey_buf->len;
	memcpy(&public_buf[1], c_pubkey_buf->p, c_pubkey_buf->len);

	ret = mbedtls_ecdh_read_public(&mbed_ecdh, public_buf, sizeof(public_buf));
	if (ret) {
		printf("mbedtls_ecdh_read_public = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	/*
	 * ecdh
	 */

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.grp, &mbed_ecdh.z, &mbed_ecdh.Qp, &mbed_ecdh.d, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.z, pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}
#endif

	output_buf->p = pmsecret_buf.p;
	output_buf->len = pmsecret_buf.len;
	err = IOT_ERROR_NONE;

exit:
	mbedtls_ecdh_free(&mbed_ecdh);
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

	return err;
}

static iot_error_t _swap_secret(iot_security_buffer_t *src, iot_security_buffer_t *dst)
{
	unsigned char *p;
	size_t len;
	int i;

	if (!src || !src->p || (src->len == 0) || !dst) {
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	len = src->len;
	p = (unsigned char *)iot_os_malloc(len);

	if (!p) {
		IOT_ERROR("failed to malloc for swap");
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	for (i = 0; i < len; i++) {
		p[(len - 1) - i] = src->p[i];
	}

	dst->p = p;
	dst->len = len;

	return IOT_ERROR_NONE;
}

iot_error_t mbedtls_helper_ecdh_compute_shared_ed25519(iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	mbedtls_ecdh_context mbed_ecdh;
	mbedtls_ctr_drbg_context mbed_ctr_drbg;
	mbedtls_entropy_context mbed_entropy;
	mbedtls_ecp_group_id mbed_ecp_grp_id = MBEDTLS_ECP_DP_CURVE25519;
	const char *pers = "iot_security_ecdh";
	iot_security_buffer_t pmsecret_buf = { 0 };
	iot_security_buffer_t swap_buf = { 0 };
	size_t key_len;
	size_t secret_len;
	int ret;

	if (!t_seckey_buf || !c_pubkey_buf || !output_buf) {
		IOT_ERROR("parameters is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	key_len = 32;
	secret_len = 32;

	if (t_seckey_buf->len > key_len) {
		IOT_ERROR("things seckey is too large");
		return IOT_ERROR_SECURITY_ECDH_INVALID_SECKEY;
	}

	if (c_pubkey_buf->len > key_len) {
		IOT_ERROR("cloud pubkey is too large");
		return IOT_ERROR_SECURITY_ECDH_INVALID_PUBKEY;
	}

	pmsecret_buf.len = secret_len;
	pmsecret_buf.p = (unsigned char *)iot_os_malloc(pmsecret_buf.len);
	if (!pmsecret_buf.p) {
		IOT_ERROR("malloc failed for pre master secret");
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	mbedtls_ecdh_init(&mbed_ecdh);
	mbedtls_ctr_drbg_init(&mbed_ctr_drbg);
	mbedtls_entropy_init(&mbed_entropy);

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy,
								(const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

#if MBEDTLS_VERSION_NUMBER > 0x03000000
	ret = mbedtls_ecp_group_load(&mbed_ecdh.MBEDTLS_PRIVATE(grp), mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	err = _swap_secret(t_seckey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.MBEDTLS_PRIVATE(d), swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		iot_security_buffer_free(&swap_buf);
		goto exit;
	}

	iot_security_buffer_free(&swap_buf);

	err = _swap_secret(c_pubkey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X), swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		iot_security_buffer_free(&swap_buf);
		goto exit;
	}

	iot_security_buffer_free(&swap_buf);

	ret = mbedtls_mpi_lset(&mbed_ecdh.MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_lset = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.MBEDTLS_PRIVATE(grp),
			&mbed_ecdh.MBEDTLS_PRIVATE(z),
			&mbed_ecdh.MBEDTLS_PRIVATE(Qp),
			&mbed_ecdh.MBEDTLS_PRIVATE(d), mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.MBEDTLS_PRIVATE(z), pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}
#else
	ret = mbedtls_ecp_group_load(&mbed_ecdh.grp, mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	err = _swap_secret(t_seckey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.d, swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		iot_security_buffer_free(&swap_buf);
		goto exit;
	}

	iot_security_buffer_free(&swap_buf);

	err = _swap_secret(c_pubkey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.Qp.X, swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		iot_security_buffer_free(&swap_buf);
		goto exit;
	}

	iot_security_buffer_free(&swap_buf);

	ret = mbedtls_mpi_lset(&mbed_ecdh.Qp.Z, 1);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_lset = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.grp, &mbed_ecdh.z, &mbed_ecdh.Qp, &mbed_ecdh.d, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.z, pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		goto exit;
	}
#endif

	err = _swap_secret(&pmsecret_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	output_buf->p = swap_buf.p;
	output_buf->len = swap_buf.len;
	err = IOT_ERROR_NONE;

exit:
	iot_security_buffer_free(&pmsecret_buf);
	mbedtls_ecdh_free(&mbed_ecdh);
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

	return err;
}

