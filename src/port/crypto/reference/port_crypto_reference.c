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
#include "port_crypto.h"

#include "mbedtls_helper.h"
#include "libsodium_helper.h"

iot_error_t port_crypto_sha512(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	return mbedtls_helper_sha512(input, input_len, output, output_len);
}

iot_error_t port_crypto_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	return mbedtls_helper_sha256(input, input_len, output, output_len);
}

iot_error_t port_crypto_generate_key(iot_security_key_id_t key_type, iot_security_buffer_t *seckey_buf, iot_security_buffer_t *pubkey_buf)
{
	iot_error_t err = IOT_ERROR_SECURITY_MANAGER_KEY_GENERATE;

	switch (key_type) {
	case IOT_SECURITY_KEY_TYPE_ECCP256:
		err = mbedtls_helper_gen_secp256r1_keypair(seckey_buf, pubkey_buf);
		break;
	default:
		IOT_ERROR("'%d' is not a supported for generating", key_type);
		break;
	}

	return err;
}

iot_error_t port_crypto_pk_sign(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!sig_buf) {
		IOT_ERROR("sig buffer is null");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	switch(pk_params->type)
	{
		case IOT_SECURITY_KEY_TYPE_ED25519 :
			return libsodium_helper_pk_sign_ed25519(pk_params, input_buf, sig_buf);
		case IOT_SECURITY_KEY_TYPE_RSA2048 :
			return mbedtls_helper_pk_sign_rsa(pk_params, input_buf, sig_buf);
		case IOT_SECURITY_KEY_TYPE_ECCP256 :
			return mbedtls_helper_pk_sign_ecdsa(pk_params, input_buf, sig_buf);
		default :
			IOT_ERROR("Not supported key type %d", pk_params->type);
			return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
	}

	return IOT_ERROR_NONE;
}

iot_error_t port_crypto_pk_verify(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!sig_buf || !sig_buf->p || (sig_buf->len == 0)) {
		IOT_ERROR("sig buffer is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	switch(pk_params->type)
	{
		case IOT_SECURITY_KEY_TYPE_ED25519 :
			return libsodium_helper_pk_verify_ed25519(pk_params, input_buf, sig_buf);
		case IOT_SECURITY_KEY_TYPE_RSA2048 :
			return mbedtls_helper_pk_verify_rsa(pk_params, input_buf, sig_buf);
		case IOT_SECURITY_KEY_TYPE_ECCP256 :
			return mbedtls_helper_pk_verify_ecdsa(pk_params, input_buf, sig_buf);
		default :
			IOT_ERROR("Not supported key type %d", pk_params->type);
			return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
	}

	return IOT_ERROR_NONE;
}

iot_error_t port_crypto_cipher_encrypt(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	switch (cipher_params->type) {
		case IOT_SECURITY_KEY_TYPE_AES256:
			err = mbedtls_helper_cipher_aes(cipher_params, input_buf, output_buf, true);
			break;
		default:
			IOT_ERROR("'%d' is not a supported cipher algorithm", cipher_params->type);
			err = IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO;
			break;
	}

	return err;
}

iot_error_t port_crypto_cipher_decrypt(iot_security_cipher_params_t *cipher_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	switch (cipher_params->type) {
		case IOT_SECURITY_KEY_TYPE_AES256:
			err = mbedtls_helper_cipher_aes(cipher_params, input_buf, output_buf, false);
			break;
		default:
			IOT_ERROR("'%d' is not a supported cipher algorithm", cipher_params->type);
			err = IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO;
			break;
	}

	return err;
}

iot_error_t port_crypto_compute_ecdh_shared(iot_security_key_type_t key_type, iot_security_buffer_t *t_seckey_buf, iot_security_buffer_t *c_pubkey_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	switch (key_type) {
	case IOT_SECURITY_KEY_TYPE_ECCP256:
		err = mbedtls_helper_ecdh_compute_shared_ecdsa(t_seckey_buf, c_pubkey_buf, output_buf);
		break;
	case IOT_SECURITY_KEY_TYPE_ED25519:
		err = mbedtls_helper_ecdh_compute_shared_ed25519(t_seckey_buf, c_pubkey_buf, output_buf);
		break;
	default:
		IOT_ERROR("'%d' is not a supported ecdh shared", key_type);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		break;
	}

	return err;
}
