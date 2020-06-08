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
#include "iot_internal.h"
#include "iot_nv_data.h"
#include "iot_debug.h"

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
static iot_error_t _iot_es_pk_load_rsa(iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	unsigned char *privkey;
	size_t privkey_len;

	err = iot_nv_get_private_key((char **)&privkey,
				(unsigned int *)&privkey_len);
	if (err) {
		IOT_ERROR("failed to load private key, ret = %d", err);
		return err;
	}

	pk_info->type = IOT_CRYPTO_PK_RSA;
	pk_info->seckey = privkey;
	pk_info->seckey_len = privkey_len;

	return IOT_ERROR_NONE;
}
#endif

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
static iot_error_t _iot_es_pk_load_ed25519(iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	unsigned char *seckey_b64 = NULL;
	unsigned char *pubkey_b64 = NULL;
	unsigned char *seckey = NULL;
	unsigned char *pubkey = NULL;
	size_t seckey_b64_len;
	size_t pubkey_b64_len;
	size_t seckey_len = IOT_SECURITY_ED25519_LEN;
	size_t pubkey_len = IOT_SECURITY_ED25519_LEN;

	err = iot_nv_get_private_key((char **)&seckey_b64, &seckey_b64_len);
	if (err) {
		IOT_ERROR("failed to load seckey, ret = %d", err);
		goto exit_failed;
	}

	seckey = (unsigned char *)iot_os_malloc(seckey_len);
	if (seckey == NULL) {
		IOT_ERROR("malloc failed for seckey");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_failed;
	}

	err = iot_crypto_base64_decode(seckey_b64, seckey_b64_len,
			seckey, seckey_len, &pk_info->seckey_len);
	if (err) {
		goto exit_failed;
	}

	err = iot_nv_get_public_key((char **)&pubkey_b64, &pubkey_b64_len);
	if (err) {
		IOT_ERROR("failed to load pukey, ret = %d", err);
		goto exit_failed;
	}

	pubkey = (unsigned char *)iot_os_malloc(pubkey_len);
	if (pubkey == NULL) {
		IOT_ERROR("malloc failed for pubkey");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_failed;
	}

	err = iot_crypto_base64_decode(pubkey_b64, pubkey_b64_len,
			pubkey, pubkey_len, &pk_info->pubkey_len);
	if (err) {
		goto exit_failed;
	}

	pk_info->type = IOT_CRYPTO_PK_ED25519;
	pk_info->seckey = seckey;
	pk_info->pubkey = pubkey;

	err = IOT_ERROR_NONE;
	goto exit;

exit_failed:
	if (seckey)
		iot_os_free((void *)seckey);
	if (pubkey)
		iot_os_free((void *)pubkey);
exit:
	if (seckey_b64)
		iot_os_free((void *)seckey_b64);
	if (pubkey_b64)
		iot_os_free((void *)pubkey_b64);

	return err;
}
#endif

void iot_es_crypto_init_pk(iot_crypto_pk_info_t *pk_info, iot_crypto_pk_type_t type)
{
	if (pk_info == NULL)
		return;

	memset(pk_info, 0, sizeof(iot_crypto_pk_info_t));
	pk_info->type = type;
}

iot_error_t iot_es_crypto_load_pk(iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;

	if (pk_info == NULL)
		return IOT_ERROR_INVALID_ARGS;

	switch(pk_info->type) {
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
	case IOT_CRYPTO_PK_RSA:
		err = _iot_es_pk_load_rsa(pk_info);
		break;
#endif
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	case IOT_CRYPTO_PK_ED25519:
		err = _iot_es_pk_load_ed25519(pk_info);
		break;
#endif
	default:
		IOT_ERROR("pk type (%d) is not supported", pk_info->type);
		err = IOT_ERROR_CRYPTO_PK_UNKNOWN_KEYTYPE;
		break;
	}

	return err;
}

void iot_es_crypto_free_pk(iot_crypto_pk_info_t *pk_info)
{
	if (pk_info == NULL)
		return;

	if (pk_info->pubkey)
		iot_os_free((void *)pk_info->pubkey);

	if (pk_info->seckey)
		iot_os_free((void *)pk_info->seckey);

	memset(pk_info, 0, sizeof(iot_crypto_pk_info_t));
}
