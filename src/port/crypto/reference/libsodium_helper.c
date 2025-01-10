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
#include "libsodium_helper.h"

#include "sodium.h"

iot_error_t libsodium_helper_pk_sign_ed25519(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	unsigned char skpk[crypto_sign_SECRETKEYBYTES];
	unsigned long long olen;
	int ret;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len != crypto_sign_PUBLICKEYBYTES)) {
		IOT_ERROR("pubkey is invalid with %d@%p", (int)pk_params->pubkey.len, pk_params->pubkey.p);
		return IOT_ERROR_SECURITY_PK_INVALID_PUBKEY;
	}

	if (!pk_params->seckey.p || (pk_params->seckey.len != crypto_sign_PUBLICKEYBYTES)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		return IOT_ERROR_SECURITY_PK_INVALID_SECKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey.p);

	memcpy(skpk, pk_params->seckey.p, pk_params->seckey.len);
	memcpy(skpk + crypto_sign_PUBLICKEYBYTES, pk_params->pubkey.p, pk_params->pubkey.len);

	sig_buf->len = 64U;
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		memset(skpk, 0, sizeof(skpk));
		return IOT_ERROR_SECURITY_MEM_ALLOC;
	}

	ret = crypto_sign_detached(sig_buf->p, &olen, input_buf->p, input_buf->len, skpk);
	memset(skpk, 0, sizeof(skpk));
	if (ret) {
		IOT_ERROR("crypto_sign_detached = %d", ret);
		iot_security_buffer_free(sig_buf);
		return IOT_ERROR_SECURITY_PK_SIGN;
	}

	if ((size_t)olen != sig_buf->len) {
		IOT_ERROR("signature length mismatch (%d != %d)", (int)olen, (int)sig_buf->len);
		iot_security_buffer_free(sig_buf);
		return IOT_ERROR_SECURITY_PK_KEY_LEN;
	}

	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);

	return IOT_ERROR_NONE;
}

iot_error_t libsodium_helper_pk_verify_ed25519(iot_security_pk_params_t *pk_params, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	size_t key_len = crypto_sign_PUBLICKEYBYTES;
	int ret;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		return IOT_ERROR_SECURITY_PK_INVALID_PUBKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey);

	if (pk_params->pubkey.len != key_len) {
		IOT_ERROR("pubkey len '%d' is not '%d'", (int)pk_params->pubkey.len, (int)key_len);
		return IOT_ERROR_SECURITY_PK_KEY_LEN;
	}

	ret = crypto_sign_verify_detached(sig_buf->p, input_buf->p, input_buf->len, pk_params->pubkey.p);
	if (ret) {
		IOT_ERROR("crypto_sign_verify_detached = %d\n", ret);
		return IOT_ERROR_SECURITY_PK_VERIFY;
	}

	IOT_DEBUG("sign verify success");

	return IOT_ERROR_NONE;
}
