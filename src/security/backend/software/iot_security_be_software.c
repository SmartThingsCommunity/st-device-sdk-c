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

#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "security/iot_security_crypto.h"
#include "security/iot_security_storage.h"
#include "security/iot_security_util.h"
#include "security/backend/iot_security_be.h"
#include "port_crypto.h"

STATIC_FUNCTION
iot_error_t _iot_security_be_check_context_and_params_is_valid(iot_security_context_t *context, iot_security_sub_system_t sub_system)
{
	if (!context) {
		IOT_ERROR("context is null");
		IOT_ERROR_DUMP_AND_RETURN(CONTEXT_NULL, 0);
	}

	if (sub_system & IOT_SECURITY_SUB_PK) {
		if (!context->pk_params) {
			IOT_ERROR("pk params is null");
			IOT_ERROR_DUMP_AND_RETURN(PK_PARAMS_NULL, 0);
		}
	}

	if (sub_system & IOT_SECURITY_SUB_CIPHER) {
		if (!context->cipher_params) {
			IOT_ERROR("cipher params is null");
			IOT_ERROR_DUMP_AND_RETURN(CIPHER_PARAMS_NULL, 0);
		}
	}

	if (sub_system & IOT_SECURITY_SUB_ECDH) {
		if (!context->ecdh_params) {
			IOT_ERROR("ecdh params is null");
			IOT_ERROR_DUMP_AND_RETURN(ECDH_PARAMS_NULL, 0);
		}
	}

	if (sub_system & IOT_SECURITY_SUB_STORAGE) {
		if (!context->storage_params) {
			IOT_ERROR("storage params is null");
			IOT_ERROR_DUMP_AND_RETURN(STORAGE_PARAMS_NULL, 0);
		}
	}

	return IOT_ERROR_NONE;
}

typedef struct iot_security_be_key2storage_id_map {
	iot_security_key_id_t key_id;
	iot_security_storage_id_t storage_id;
} iot_security_be_key2storage_id_map_t;

static const iot_security_be_key2storage_id_map_t key2storage_id_map[] = {
	{ IOT_SECURITY_KEY_ID_DEVICE_PUBLIC, IOT_NVD_PUBLIC_KEY },
	{ IOT_SECURITY_KEY_ID_DEVICE_PRIVATE, IOT_NVD_PRIVATE_KEY },
	{ IOT_SECURITY_KEY_ID_SHARED_SECRET, IOT_NVD_UNKNOWN },
	{ IOT_SECURITY_KEY_ID_EPHEMERAL, IOT_NVD_UNKNOWN }
};

static inline iot_security_storage_id_t _iot_security_be_software_id_key2storage(iot_security_key_id_t key_id)
{
	iot_security_storage_id_t storage_id;
	const iot_security_be_key2storage_id_map_t *k2s_id_map_list = key2storage_id_map;
	int c2s_id_map_list_len = sizeof(key2storage_id_map) / sizeof(key2storage_id_map[0]);
	int i;

	IOT_DEBUG("key id = %d", key_id);

	for (i = 0; i < c2s_id_map_list_len; i++) {
		if (key_id == k2s_id_map_list[i].key_id) {
			storage_id = k2s_id_map_list[i].storage_id;
			IOT_DEBUG("storage id = %d", storage_id);
			return storage_id;
		}
	}

	IOT_ERROR("'%d' is not a supported key id", key_id);

	return IOT_NVD_UNKNOWN;
}

typedef struct iot_security_be_cert2storage_id_map {
	iot_security_cert_id_t cert_id;
	iot_security_storage_id_t storage_id;
} iot_security_be_cert2storage_id_map_t;

static const iot_security_be_cert2storage_id_map_t cert2storage_id_map[] = {
	{ IOT_SECURITY_CERT_ID_ROOT_CA, IOT_NVD_ROOT_CA_CERT },
	{ IOT_SECURITY_CERT_ID_SUB_CA,  IOT_NVD_SUB_CA_CERT },
	{ IOT_SECURITY_CERT_ID_DEVICE,  IOT_NVD_DEVICE_CERT },
};

static inline iot_security_storage_id_t _iot_security_be_software_id_cert2storage(iot_security_cert_id_t cert_id)
{
	iot_security_storage_id_t storage_id;
	const iot_security_be_cert2storage_id_map_t *c2s_id_map_list = cert2storage_id_map;
	int c2s_id_map_list_len = sizeof(cert2storage_id_map) / sizeof(cert2storage_id_map[0]);
	int i;

	IOT_DEBUG("cert id = %d", cert_id);

	for (i = 0; i < c2s_id_map_list_len; i++) {
		if (cert_id == c2s_id_map_list[i].cert_id) {
			storage_id = c2s_id_map_list[i].storage_id;
			IOT_DEBUG("storage id = %d", storage_id);
			return storage_id;
		}
	}

	IOT_ERROR("'%d' is not a supported cert id", cert_id);

	return IOT_NVD_UNKNOWN;
}

static const iot_security_storage_id_t no_exposed_storage_id_list[] = {
		IOT_NVD_PRIVATE_KEY,
};

STATIC_FUNCTION
iot_error_t _iot_security_be_software_id_check_permission(iot_security_storage_id_t id)
{
	int no_exposed_list_len = sizeof(no_exposed_storage_id_list) / sizeof(no_exposed_storage_id_list[0]);
	int i;

	for (i = 0; i < no_exposed_list_len; i++) {
		if (id == no_exposed_storage_id_list[i]) {
			IOT_ERROR("'%d' cannot be exposed to apps", id);
			IOT_ERROR_DUMP_AND_RETURN(KEY_NO_PERMISSION, id);
		}
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_bsp_fs_load(iot_security_context_t *context, iot_security_storage_id_t storage_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	const iot_security_be_bsp_funcs_t *bsp_fn;

	if (!context) {
		IOT_ERROR_DUMP_AND_RETURN(CONTEXT_NULL, 0);
	}

	if (!context->be_context) {
		IOT_ERROR_DUMP_AND_RETURN(BE_CONTEXT_NULL, 0);
	}

	bsp_fn = context->be_context->bsp_fn;

	if (!bsp_fn || !bsp_fn->bsp_fs_load) {
		IOT_ERROR_DUMP_AND_RETURN(BSP_FN_LOAD_NULL, 0);
	}

	err = bsp_fn->bsp_fs_load(context->be_context, storage_id, output_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
};

static iot_security_buffer_t ephemeral_seckey_buf = { 0 };
static iot_security_buffer_t ephemeral_pubkey_buf = { 0 };

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_load_ed25519_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;
	iot_security_buffer_t key_b64_buf = { 0 };
	iot_security_buffer_t key_buf = { 0 };
	size_t olen;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	storage_id = _iot_security_be_software_id_key2storage(key_id);
	if (storage_id == IOT_NVD_UNKNOWN) {
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &key_b64_buf);
	if (err) {
		return err;
	}

	key_buf.len = IOT_SECURITY_ED25519_LEN;
	key_buf.p = (unsigned char *) iot_os_malloc(key_buf.len);
	if (!key_buf.p) {
		IOT_ERROR("failed to malloc for key_buf");
		iot_security_buffer_free(&key_b64_buf);
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	/* remove null character for base64 decoding */
	if (strlen((char *)key_b64_buf.p) == (key_b64_buf.len - 1)) {
		key_b64_buf.len -= 1;
	}

	err = iot_security_base64_decode(key_b64_buf.p, key_b64_buf.len, key_buf.p, key_buf.len, &olen);
	if (err) {
		iot_security_buffer_free(&key_b64_buf);
		iot_security_buffer_free(&key_buf);
		return err;
	}

	if (olen != key_buf.len) {
		iot_security_buffer_free(&key_b64_buf);
		iot_security_buffer_free(&key_buf);
		IOT_ERROR_DUMP_AND_RETURN(PK_KEY_LEN, 0);
	}

	*output_buf = key_buf;

	IOT_DEBUG("key '%d' is loaded %d@%p", key_id, (int)output_buf->len, output_buf->p);

	iot_security_buffer_free(&key_b64_buf);

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_load_ed25519(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_buffer_t seckey = { 0 };
	iot_security_buffer_t pubkey = { 0 };

	err = _iot_security_be_software_pk_load_ed25519_key(context, IOT_SECURITY_KEY_ID_DEVICE_PRIVATE, &seckey);
	if (err) {
		return err;
	}

	err = _iot_security_be_software_pk_load_ed25519_key(context, IOT_SECURITY_KEY_ID_DEVICE_PUBLIC, &pubkey);
	if (err) {
		return err;
	}

	context->pk_params->type = IOT_SECURITY_KEY_TYPE_ED25519;
	context->pk_params->seckey = seckey;
	context->pk_params->pubkey = pubkey;

	return IOT_ERROR_NONE;
}
#endif

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_load_rsa(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;
	iot_security_buffer_t key_buf = { 0 };

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_software_id_key2storage(IOT_SECURITY_KEY_ID_DEVICE_PRIVATE);
	if (storage_id == IOT_NVD_UNKNOWN) {
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, storage_id);
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &key_buf);
	if (err) {
		return err;
	}

	context->pk_params->seckey = key_buf;

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
	storage_id = _iot_security_be_software_id_cert2storage(IOT_SECURITY_CERT_ID_DEVICE);
	if (storage_id == IOT_NVD_UNKNOWN) {
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, storage_id);
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &key_buf);
	if (err) {
		iot_security_buffer_free(&context->pk_params->seckey);
		return err;
	}

	context->pk_params->pubkey = key_buf;
#endif
	context->pk_params->type = IOT_SECURITY_KEY_TYPE_RSA2048;

	return err;
}
#endif

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_load_ecdsa(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;
	iot_security_buffer_t key_buf = { 0 };

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_software_id_key2storage(IOT_SECURITY_KEY_ID_DEVICE_PRIVATE);
	if (storage_id == IOT_NVD_UNKNOWN) {
		return IOT_ERROR_SECURITY_KEY_INVALID_ID;
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &key_buf);
	if (err) {
		return err;
	}

	context->pk_params->seckey = key_buf;

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
	storage_id = _iot_security_be_software_id_cert2storage(IOT_SECURITY_CERT_ID_DEVICE);
	if (storage_id == IOT_NVD_UNKNOWN) {
		return IOT_ERROR_SECURITY_KEY_INVALID_ID;
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &key_buf);
	if (err) {
		iot_security_buffer_free(&context->pk_params->seckey);
		return err;
	}

	context->pk_params->pubkey = key_buf;
#endif
	context->pk_params->type = IOT_SECURITY_KEY_TYPE_ECCP256;

	return err;
}
#endif

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_load_key(iot_security_context_t *context)
{
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	return _iot_security_be_software_pk_load_ed25519(context);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
	return _iot_security_be_software_pk_load_rsa(context);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
	return _iot_security_be_software_pk_load_ecdsa(context);
#else
	IOT_ERROR("not implemented");
	IOT_ERROR_DUMP_AND_RETURN(NOT_IMPLEMENTED, 0);
#endif
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_init(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		IOT_ERROR_DUMP_AND_RETURN(CONTEXT_NULL, 0);
	}

	err = _iot_security_be_software_pk_load_key(context);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_deinit(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	pk_params = context->pk_params;

	if (pk_params->pubkey.p) {
		iot_security_buffer_free(&pk_params->pubkey);
	}

	if (pk_params->seckey.p) {
		iot_security_buffer_free(&pk_params->seckey);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_get_key_type(iot_security_context_t *context, iot_security_key_type_t *key_type)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	*key_type = context->pk_params->type;

	IOT_DEBUG("type = %d", *key_type);

	return IOT_ERROR_NONE;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_set_sign_type(iot_security_context_t *context, iot_security_pk_sign_type_t pk_sign_type)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	context->pk_params->pk_sign_type = pk_sign_type;

	IOT_DEBUG("type = %d", pk_sign_type);

	return IOT_ERROR_NONE;
}
#endif

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	err = port_crypto_pk_sign(context->pk_params, input_buf, sig_buf);

	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_verify(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	err = port_crypto_pk_verify(context->pk_params, input_buf, sig_buf);

	return err;
}
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY */

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_deinit(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_cipher_params_t *cipher_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	cipher_params = context->cipher_params;

	if (cipher_params->key.p) {
		iot_security_buffer_free(&cipher_params->key);
	}

	if (cipher_params->iv.p) {
		iot_security_buffer_free(&cipher_params->iv);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_copy_params(iot_security_buffer_t *src, iot_security_buffer_t *dst)
{
	if (src->p) {
		if (src->len == 0) {
			IOT_ERROR("length of src is zero");
			IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
		}

		if (dst->p) {
			iot_security_buffer_free(dst);
		}

		dst->p = (unsigned char *)iot_os_malloc(src->len);
		if (!dst->p) {
			IOT_ERROR("failed to malloc for dst params");
			IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
		}

		memcpy(dst->p, src->p, src->len);
		dst->len = src->len;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_set_params(iot_security_context_t *context, iot_security_cipher_params_t *cipher_set_params)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	if (!cipher_set_params) {
		IOT_ERROR("cipher set params is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if ((cipher_set_params->type > IOT_SECURITY_KEY_TYPE_UNKNOWN) &&
		(cipher_set_params->type < IOT_SECURITY_KEY_TYPE_MAX)) {
		context->cipher_params->type = cipher_set_params->type;
	}

	err = _iot_security_be_software_cipher_copy_params(&cipher_set_params->key, &context->cipher_params->key);
	if (err) {
		return err;
	}

	err = _iot_security_be_software_cipher_copy_params(&cipher_set_params->iv, &context->cipher_params->iv);
	if (err) {
		return err;
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err = IOT_ERROR_NONE;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	err = port_crypto_cipher_encrypt(context->cipher_params, input_buf, output_buf);
	if (err) {
		IOT_ERROR("cipher encrypt error %d", err);
		return err;
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err = IOT_ERROR_NONE;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	err = port_crypto_cipher_decrypt(context->cipher_params, input_buf, output_buf);
	if (err) {
		IOT_ERROR("cipher decrypt error %d", err);
		return err;
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_manager_generate_key(iot_security_context_t *context, iot_security_key_id_t key_id)
{
	iot_error_t err = IOT_ERROR_SECURITY_MANAGER_KEY_GENERATE;

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key id is not for a ephemeral");
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	err = port_crypto_generate_key(IOT_SECURITY_KEY_TYPE_ECCP256, &ephemeral_seckey_buf, &ephemeral_pubkey_buf);
	if (err) {
		IOT_ERROR("key id is not for a ephemeral");
		return err;
	}

	err = IOT_ERROR_NONE;
	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_manager_remove_key(iot_security_context_t *context, iot_security_key_id_t key_id)
{
	iot_error_t err = IOT_ERROR_NONE;

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key id %d is not supported");
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	iot_security_buffer_free(&ephemeral_pubkey_buf);
	iot_security_buffer_free(&ephemeral_seckey_buf);

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_manager_set_key(iot_security_context_t *context, iot_security_key_params_t *key_params)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	if (!key_params) {
		IOT_ERROR("key params is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (key_params->key_id == IOT_SECURITY_KEY_ID_SHARED_SECRET) {
		iot_security_cipher_params_t *cipher_params = context->cipher_params;
		iot_security_cipher_params_t *cipher_set_params = &key_params->params.cipher;

		if (cipher_set_params->key.p && cipher_set_params->key.len) {
			cipher_params->key = cipher_set_params->key;
		}

		if (cipher_set_params->iv.p && cipher_set_params->iv.len) {
			cipher_params->iv = cipher_set_params->iv;
		}
	} else {
		IOT_ERROR("cannot set key for key index '%d'", key_params->key_id);
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_manager_get_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *key_buf)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_NONE);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_software_id_key2storage(key_id);

	err = _iot_security_be_software_id_check_permission(storage_id);
	if (err) {
		return err;
	}

	if (key_id == IOT_SECURITY_KEY_ID_SHARED_SECRET) {
		if (!context->cipher_params) {
			IOT_ERROR("cipher params is null");
			IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
		}

		if (!context->cipher_params->key.p || (context->cipher_params->key.len == 0)) {
			IOT_ERROR("shared secret not yet set");
			IOT_ERROR_DUMP_AND_RETURN(KEY_NOT_FOUND, 0);
		}

		key_buf->len = context->cipher_params->key.len;
		key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
		if (!key_buf->p) {
			IOT_ERROR("failed to malloc for getting key");
			key_buf->len = 0;
			IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
		}
		memcpy(key_buf->p, context->cipher_params->key.p, key_buf->len);
	} else if (key_id == IOT_SECURITY_KEY_ID_EPHEMERAL) {
		if (!ephemeral_pubkey_buf.p) {
			IOT_ERROR("ephemeral key pair is null");
			return IOT_ERROR_SECURITY_KEY_NOT_FOUND;
		}

		key_buf->len = ephemeral_pubkey_buf.len;
		key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
		if (!key_buf->p) {
			IOT_ERROR("failed to malloc for pubkey");
			key_buf->len = 0;
			IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
		}

		memcpy(key_buf->p, ephemeral_pubkey_buf.p, key_buf->len);
	} else {
		err = _iot_security_be_software_bsp_fs_load(context, storage_id, key_buf);
		if (err) {
			return err;
		}
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_manager_get_certificate(iot_security_context_t *context, iot_security_cert_id_t cert_id, iot_security_buffer_t *cert_buf)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_NONE);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_software_id_cert2storage(cert_id);
	if (storage_id == IOT_NVD_UNKNOWN) {
		IOT_ERROR_DUMP_AND_RETURN(CERT_INVALID_ID, cert_id);
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, cert_buf);
	if (err) {
		return err;
	}

	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
STATIC_FUNCTION
iot_error_t _iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key)
{
	iot_error_t ret;
    unsigned char h[64];

	if (!ed25519_key || !curve25519_key) {
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	ret = iot_security_sha512(ed25519_key, 32, h, 64);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_sk_to_curve25519 = %d", ret);
		return ret;
	}
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(curve25519_key, h, 32);
	memset(h, 0, 64);

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_load_ed25519(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;
	iot_security_ecdh_params_t *ecdh_params;
	iot_security_buffer_t seckey_b64_buf = { 0 };
	iot_security_buffer_t seckey_buf = { 0 };
	unsigned char *seckey_curve = NULL;
	size_t olen;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	storage_id = IOT_NVD_PRIVATE_KEY;

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, &seckey_b64_buf);
	if (err) {
		return err;
	}

	seckey_buf.len = IOT_SECURITY_ED25519_LEN;
	seckey_buf.p = (unsigned char *)iot_os_malloc(seckey_buf.len);
	if (!seckey_buf.p) {
		IOT_ERROR("failed to malloc for seckey_buf");
		err = IOT_ERROR_MEM_ALLOC;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_seckey_b64;
	}

	/* remove null character for base64 decoding */
	if (strlen((char *)seckey_b64_buf.p) == (seckey_b64_buf.len - 1)) {
		seckey_b64_buf.len -= 1;
	}

	err = iot_security_base64_decode(seckey_b64_buf.p, seckey_b64_buf.len, seckey_buf.p, seckey_buf.len, &olen);
	if (err) {
		goto exit_free_seckey;
	}

	if (olen != seckey_buf.len) {
		IOT_ERROR("seckey_len '%d' is not '%d'", (int)olen, (int)seckey_buf.len);
		err = IOT_ERROR_SECURITY_PK_KEY_LEN;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_seckey;
	}

	seckey_curve = (unsigned char *)iot_os_malloc(seckey_buf.len);
	if (!seckey_curve) {
		IOT_ERROR("failed to malloc for seckey_buf curve");
		err = IOT_ERROR_MEM_ALLOC;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_seckey;
	}

	err = _iot_security_ed25519_convert_seckey(seckey_buf.p, seckey_curve);
	if (err) {
		goto exit_free_seckey_curve;
	}

	ecdh_params = context->ecdh_params;

	ecdh_params->t_seckey.p = seckey_curve;
	ecdh_params->t_seckey.len = seckey_buf.len;

	err = IOT_ERROR_NONE;
	goto exit_free_seckey;

exit_free_seckey_curve:
	iot_os_free(seckey_curve);
exit_free_seckey:
	iot_security_buffer_free(&seckey_buf);
exit_free_seckey_b64:
	iot_security_buffer_free(&seckey_b64_buf);

	return err;
}
#endif

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_load(iot_security_context_t *context)
{
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	return _iot_security_be_software_ecdh_load_ed25519(context);
#else
	return IOT_ERROR_NONE;
#endif
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_init(iot_security_context_t *context)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	err = _iot_security_be_software_ecdh_load(context);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_deinit(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_ecdh_params_t *ecdh_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	ecdh_params = context->ecdh_params;

	if (ecdh_params->t_seckey.p) {
		iot_security_buffer_free(&ecdh_params->t_seckey);
	}

	if (ecdh_params->c_pubkey.p) {
		iot_security_buffer_free(&ecdh_params->c_pubkey);
	}

	if (ecdh_params->salt.p) {
		iot_security_buffer_free(&ecdh_params->salt);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_copy_params(iot_security_buffer_t *src, iot_security_buffer_t *dst)
{
	if (src->p) {
		if (src->len == 0) {
			IOT_ERROR("length of src is zero");
			IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
		}

		if (dst->p) {
			iot_security_buffer_free(dst);
		}

		dst->p = (unsigned char *)iot_os_malloc(src->len);
		if (!dst->p) {
			IOT_ERROR("failed to malloc for dst params");
			IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
		}

		memcpy(dst->p, src->p, src->len);
		dst->len = src->len;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_set_params(iot_security_context_t *context, iot_security_ecdh_params_t *ecdh_set_params)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	if (!ecdh_set_params) {
		IOT_ERROR("ecdh set params is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	context->ecdh_params->key_id = ecdh_set_params->key_id;

	err = _iot_security_be_software_ecdh_copy_params(&ecdh_set_params->t_seckey, &context->ecdh_params->t_seckey);
	if (err) {
		return err;
	}

	err = _iot_security_be_software_ecdh_copy_params(&ecdh_set_params->c_pubkey, &context->ecdh_params->c_pubkey);
	if (err) {
		return err;
	}

	err = _iot_security_be_software_ecdh_copy_params(&ecdh_set_params->salt, &context->ecdh_params->salt);
	if (err) {
		return err;
	}

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_compute_shared_secret(iot_security_context_t *context, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	iot_security_ecdh_params_t *ecdh_params;
	iot_security_buffer_t pmsecret_buf = { 0 };
	iot_security_buffer_t secret_buf = { 0 };
	iot_security_buffer_t shared_secret_buf = { 0 };

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	ecdh_params = context->ecdh_params;

	switch (ecdh_params->key_id) {
	case IOT_SECURITY_KEY_ID_EPHEMERAL:
#if defined(CONFIG_STDK_IOT_CORE_SECURITY_ONLY_UNITTEST)
		if (ecdh_params->t_seckey.p) {
			err = port_crypto_compute_ecdh_shared(IOT_SECURITY_KEY_TYPE_ECCP256, &ecdh_params->t_seckey, &ecdh_params->c_pubkey, &pmsecret_buf);
		} else
#endif
		{
			if (!ephemeral_seckey_buf.p) {
				IOT_ERROR("ephemeral key pair is null");
				err = IOT_ERROR_SECURITY_KEY_NOT_FOUND;
				goto exit;
			}

			err = port_crypto_compute_ecdh_shared(IOT_SECURITY_KEY_TYPE_ECCP256, &ephemeral_seckey_buf, &ecdh_params->c_pubkey, &pmsecret_buf);
			if (err) {
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
				goto exit;
			}
		}
		break;
	default:
		err = port_crypto_compute_ecdh_shared(IOT_SECURITY_KEY_TYPE_ED25519, &ecdh_params->t_seckey, &ecdh_params->c_pubkey, &pmsecret_buf);
		if (err) {
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
			goto exit;
		}
		break;
	}

	secret_buf.len = pmsecret_buf.len + ecdh_params->salt.len;
	secret_buf.p = (unsigned char *)iot_os_malloc(secret_buf.len);
	if (!secret_buf.p) {
		IOT_ERROR("failed to malloc for secret");
		err = IOT_ERROR_MEM_ALLOC;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_pmsecret;
	}

	memcpy(secret_buf.p, pmsecret_buf.p, pmsecret_buf.len);
	memcpy(secret_buf.p + pmsecret_buf.len, ecdh_params->salt.p, ecdh_params->salt.len);

	shared_secret_buf.len = IOT_SECURITY_SHA256_LEN;
	shared_secret_buf.p = (unsigned char *)iot_os_malloc(shared_secret_buf.len);
	if (!shared_secret_buf.p) {
		IOT_ERROR("failed to malloc for shared secret");
		err = IOT_ERROR_MEM_ALLOC;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_secret;
	}

	err = iot_security_sha256(secret_buf.p, secret_buf.len, shared_secret_buf.p, shared_secret_buf.len);
	if (err) {
		goto exit_free_shared_secret;
	}

	if (context->sub_system & IOT_SECURITY_SUB_CIPHER) {
		iot_security_key_params_t shared_key_params = { 0 };
		shared_key_params.key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
		shared_key_params.params.cipher.key = shared_secret_buf;
		err = _iot_security_be_software_manager_set_key(context, &shared_key_params);
		if (err) {
			goto exit_free_shared_secret;
		}
	}

	if (output_buf) {
		*output_buf = shared_secret_buf;
	}

	err = IOT_ERROR_NONE;
	goto exit_free_secret;

exit_free_shared_secret:
	iot_security_buffer_free(&shared_secret_buf);
exit_free_secret:
	iot_security_buffer_free(&secret_buf);
exit_free_pmsecret:
	iot_security_buffer_free(&pmsecret_buf);
exit:
	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_read(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	err = _iot_security_be_software_bsp_fs_load(context, storage_params->storage_id, data_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_write(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	if (!context->be_context->bsp_fn ||
		!context->be_context->bsp_fn->bsp_fs_store) {
		IOT_ERROR_DUMP_AND_RETURN(BSP_FN_STORE_NULL, 0);
	}

	err = context->be_context->bsp_fn->bsp_fs_store(context->be_context, storage_params->storage_id, data_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_storage_remove(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	if (!context->be_context->bsp_fn ||
		!context->be_context->bsp_fn->bsp_fs_remove) {
		IOT_ERROR_DUMP_AND_RETURN(BSP_FN_REMOVE_NULL, 0);
	}

	err = context->be_context->bsp_fn->bsp_fs_remove(context->be_context, storage_params->storage_id);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

const iot_security_be_funcs_t iot_security_be_software_funcs = {
	.pk_init = _iot_security_be_software_pk_init,
	.pk_deinit = _iot_security_be_software_pk_deinit,
	.pk_set_params = NULL,
	.pk_get_key_type = _iot_security_be_software_pk_get_key_type,
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
	.pk_set_sign_type = _iot_security_be_software_pk_set_sign_type,
#else
	.pk_set_sign_type = NULL,
#endif
	.pk_sign = _iot_security_be_software_pk_sign,
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
	.pk_verify = _iot_security_be_software_pk_verify,
#else
	.pk_verify = NULL,
#endif

	.cipher_init = NULL,
	.cipher_deinit = _iot_security_be_software_cipher_deinit,
	.cipher_set_params = _iot_security_be_software_cipher_set_params,
	.cipher_aes_encrypt = _iot_security_be_software_cipher_aes_encrypt,
	.cipher_aes_decrypt = _iot_security_be_software_cipher_aes_decrypt,

	.ecdh_init = _iot_security_be_software_ecdh_init,
	.ecdh_deinit = _iot_security_be_software_ecdh_deinit,
	.ecdh_set_params = _iot_security_be_software_ecdh_set_params,
	.ecdh_compute_shared_secret = _iot_security_be_software_ecdh_compute_shared_secret,

	.manager_init = NULL,
	.manager_deinit = NULL,
	.manager_generate_key = _iot_security_be_software_manager_generate_key,
	.manager_remove_key = _iot_security_be_software_manager_remove_key,
	.manager_set_key = _iot_security_be_software_manager_set_key,
	.manager_get_key = _iot_security_be_software_manager_get_key,
	.manager_get_certificate = _iot_security_be_software_manager_get_certificate,

	.storage_init = NULL,
	.storage_deinit = NULL,
	.storage_read = _iot_security_be_software_storage_read,
	.storage_write = _iot_security_be_software_storage_write,
	.storage_remove = _iot_security_be_software_storage_remove,
};

iot_security_be_context_t *iot_security_be_init(external_nv_callback external_nv_cb)
{
	iot_error_t err;
	iot_security_be_context_t *be_context;

	be_context = (iot_security_be_context_t *)iot_os_malloc(sizeof(iot_security_be_context_t));
	if (!be_context) {
		IOT_ERROR("failed to malloc for context");
		return NULL;
	}

	memset(be_context, 0, sizeof(iot_security_be_context_t));

	be_context->name = "software";
	be_context->fn = &iot_security_be_software_funcs;
	be_context->external_device_info_cb = external_nv_cb;

	err = iot_security_be_bsp_init(be_context);
	if (err) {
		IOT_ERROR("iot_security_be_bsp_init = %d", err);
		iot_os_free(be_context);
		return NULL;
	}

	IOT_DEBUG("security backend is '%s'", be_context->name);

	return be_context;
}

iot_error_t iot_security_be_deinit(iot_security_be_context_t *be_context)
{
	if (!be_context) {
		IOT_ERROR("backend context is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	memset(be_context, 0, sizeof(iot_security_be_context_t));

	iot_os_free(be_context);

	return IOT_ERROR_NONE;
}
