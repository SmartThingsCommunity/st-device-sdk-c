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
#include "iot_crypto_internal.h"

iot_error_t iot_crypto_pk_init(iot_crypto_pk_context_t *ctx,
                               iot_crypto_pk_info_t *info)
{
	if (ctx == NULL) {
		IOT_ERROR("context is null");
		return IOT_ERROR_CRYPTO_PK_INVALID_CTX;
	}

	if (info == NULL) {
		IOT_ERROR("key info is null");
		return IOT_ERROR_CRYPTO_PK_INVALID_ARG;
	}

	ctx->info = info;

	switch (info->type) {
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
	case IOT_CRYPTO_PK_RSA:
		ctx->fn = &iot_crypto_pk_rsa_funcs;
		break;
#endif
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	case IOT_CRYPTO_PK_ED25519:
		ctx->fn = &iot_crypto_pk_ed25519_funcs;
		break;
#endif
	default:
		IOT_ERROR("not supported pk type (%d)", info->type);
		return IOT_ERROR_CRYPTO_PK_UNKNOWN_KEYTYPE;
	}

	return IOT_ERROR_NONE;
}

void iot_crypto_pk_free(iot_crypto_pk_context_t *ctx)
{
	memset(ctx, 0, sizeof(iot_crypto_pk_context_t));
}

iot_error_t iot_crypto_pk_sign(iot_crypto_pk_context_t *ctx,
                               unsigned char *input, size_t ilen,
                               unsigned char *sig, size_t *slen)
{
	iot_error_t err;

	if (ctx->fn->sign == NULL) {
		IOT_ERROR("%s sign is not supported", ctx->fn->name);
		return IOT_ERROR_CRYPTO_PK_NULL_FUNC;
	}

	err = ctx->fn->sign(ctx, input, ilen, sig, slen);
	if (err) {
		return err;
	}

	return err;
}

iot_error_t iot_crypto_pk_verify(iot_crypto_pk_context_t *ctx,
                                 unsigned char *input, size_t ilen,
                                 unsigned char *sig, size_t slen)
{
	iot_error_t err;

	if (ctx->fn->verify == NULL) {
		IOT_ERROR("%s verify is not supported", ctx->fn->name);
		return IOT_ERROR_CRYPTO_PK_NULL_FUNC;
	}

	err = ctx->fn->verify(ctx, input, ilen, sig, slen);
	if (err) {
		return err;
	}

	return err;
}
