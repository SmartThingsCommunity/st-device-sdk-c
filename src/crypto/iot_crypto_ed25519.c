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

#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"

iot_error_t iot_crypto_ed25519_init_keypair(iot_crypto_ed25519_keypair_t *kp)
{
	size_t pklen = crypto_sign_publickeybytes();
	size_t sklen = crypto_sign_secretkeybytes();

	/* buffer for ed25519 */

	kp->sign.pubkey = (unsigned char *)malloc(pklen);
	if (!kp->sign.pubkey) {
		IOT_ERROR("malloc failed for pubkey");
		goto exit_sign_pk;
	}

	kp->sign.seckey = (unsigned char *)malloc(sklen);
	if (!kp->sign.seckey) {
		IOT_ERROR("malloc failed for seckey");
		goto exit_sign_sk;
	}

	/* buffer for curve25519 */

	kp->curve.pubkey = (unsigned char *)malloc(pklen);
	if (!kp->curve.pubkey) {
		IOT_ERROR("malloc failed for pubkey");
		goto exit_curve_pk;
	}

	kp->curve.seckey = (unsigned char *)malloc(sklen);
	if (!kp->curve.seckey) {
		IOT_ERROR("malloc failed for seckey");
		goto exit_curve_sk;
	}

	return IOT_ERROR_NONE;

exit_curve_sk:
	free((void *)kp->curve.pubkey);
	kp->curve.pubkey = NULL;
exit_curve_pk:
	free((void *)kp->sign.seckey);
	kp->sign.seckey = NULL;
exit_sign_sk:
	free((void *)kp->sign.pubkey);
	kp->sign.pubkey = NULL;
exit_sign_pk:
	return IOT_ERROR_MEM_ALLOC;
}

void iot_crypto_ed25519_free_keypair(iot_crypto_ed25519_keypair_t *kp)
{
	if (kp->sign.pubkey)
		free((void *)kp->sign.pubkey);
	if (kp->sign.seckey)
		free((void *)kp->sign.seckey);

	if (kp->curve.pubkey)
		free((void *)kp->curve.pubkey);
	if (kp->curve.seckey)
		free((void *)kp->curve.seckey);

	memset((void *)kp, 0, sizeof(iot_crypto_ed25519_keypair_t));
}

iot_error_t iot_crypto_ed25519_convert_keypair(iot_crypto_ed25519_keypair_t *kp)
{
	int ret;

	if (!kp) {
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!kp->curve.pubkey || !kp->sign.pubkey ||
	    !kp->curve.seckey || !kp->sign.seckey) {
		IOT_ERROR("iot_crypto_ed25519_init_keypair is needed");
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = crypto_sign_ed25519_pk_to_curve25519(kp->curve.pubkey, kp->sign.pubkey);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_pk_to_curve25519 = %d", ret);
		return IOT_ERROR_CRYPTO_ED_KEY_CONVERT;
	}

	ret = crypto_sign_ed25519_sk_to_curve25519(kp->curve.seckey, kp->sign.seckey);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_sk_to_curve25519 = %d", ret);
		return IOT_ERROR_CRYPTO_ED_KEY_CONVERT;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_ed25519_convert_pubkey(unsigned char *ed25519_key,
					unsigned char *curve25519_key)
{
	int ret;

	if (!ed25519_key || !curve25519_key) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = crypto_sign_ed25519_pk_to_curve25519(curve25519_key, ed25519_key);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_pk_to_curve25519 = %d", ret);
		return IOT_ERROR_CRYPTO_ED_KEY_CONVERT;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_crypto_ed25519_convert_seckey(unsigned char *ed25519_key,
					unsigned char *curve25519_key)
{
	int ret;

	if (!ed25519_key || !curve25519_key) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = crypto_sign_ed25519_sk_to_curve25519(curve25519_key, ed25519_key);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_sk_to_curve25519 = %d", ret);
		return IOT_ERROR_CRYPTO_ED_KEY_CONVERT;
	}

	return IOT_ERROR_NONE;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
static iot_error_t _iot_crypto_pk_ed25519_sign(iot_crypto_pk_context_t *ctx,
                                          unsigned char *input, size_t ilen,
                                          unsigned char *sig, size_t *slen)
{
	int ret;
	unsigned char skpk[crypto_sign_SECRETKEYBYTES];
	unsigned long long sig_len;

	IOT_DEBUG("input: %d@%p", ilen, input);
	IOT_DEBUG("seckey: %d@%p", ctx->info->seckey_len, ctx->info->seckey);
	IOT_DEBUG("pubkey: %d@%p", ctx->info->pubkey_len, ctx->info->pubkey);

	if (ctx->info->seckey_len != crypto_sign_PUBLICKEYBYTES) {
		IOT_ERROR("seckey len (%d) is not '%d'",
				ctx->info->seckey_len,
				crypto_sign_PUBLICKEYBYTES);
		return IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN;
	}

	if (ctx->info->pubkey_len != crypto_sign_PUBLICKEYBYTES) {
		IOT_ERROR("pubkey len (%d) is not '%d'",
				ctx->info->pubkey_len,
				crypto_sign_PUBLICKEYBYTES);
		return IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN;
	}

	memcpy(skpk, ctx->info->seckey, crypto_sign_PUBLICKEYBYTES);
	memcpy(skpk + crypto_sign_PUBLICKEYBYTES,
				ctx->info->pubkey, crypto_sign_PUBLICKEYBYTES);

	ret = crypto_sign_detached(sig, &sig_len, input, ilen, skpk);
	if (ret) {
		IOT_ERROR("crypto_sign_detached = %d", ret);
		return IOT_ERROR_CRYPTO_PK_SIGN;
	}

	*slen = (size_t)sig_len;

	IOT_DEBUG("sig: %d@%p", *slen, sig);

	return IOT_ERROR_NONE;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
static iot_error_t _iot_crypto_pk_ed25519_verify(iot_crypto_pk_context_t *ctx,
                                          unsigned char *input, size_t ilen,
                                          unsigned char *sig, size_t slen)
{
	int ret;

	IOT_DEBUG("input: %d@%p", ilen, input);
	IOT_DEBUG("sig: %d@%p", slen, sig);
	IOT_DEBUG("pubkey: %d@%p", ctx->info->pubkey_len, ctx->info->pubkey);

	if (ctx->info->pubkey_len != crypto_sign_PUBLICKEYBYTES) {
		IOT_ERROR("pubkey len (%d) is not '%d'\n",
				ctx->info->pubkey_len,
				crypto_sign_PUBLICKEYBYTES);
		return IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN;
	}

	ret = crypto_sign_verify_detached(sig, input, ilen, ctx->info->pubkey);
	if (ret) {
		IOT_ERROR("crypto_sign_verify_detached = %d\n", ret);
		return IOT_ERROR_CRYPTO_PK_VERIFY;
	}

	IOT_DEBUG("sign verify success");

	return IOT_ERROR_NONE;
}
#endif

const iot_crypto_pk_funcs_t iot_crypto_pk_ed25519_funcs = {
	.name = "ED25519",
	.sign = _iot_crypto_pk_ed25519_sign,
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
	.verify = _iot_crypto_pk_ed25519_verify,
#else
	.verify = NULL,
#endif
};
#endif
