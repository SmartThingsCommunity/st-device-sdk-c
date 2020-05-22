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
#include "security/iot_security_manager.h"
#include "security/iot_security_storage.h"
#include "security/iot_security_helper.h"
#include "security/backend/iot_security_be.h"

STATIC_FUNCTION
iot_error_t _iot_security_be_check_context_and_params_is_valid(iot_security_context_t *context, iot_security_sub_system_t sub_system)
{
	if (!context) {
		IOT_ERROR("context is null");
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (sub_system & IOT_SECURITY_SUB_CIPHER) {
		if (!context->cipher_params) {
			IOT_ERROR("cipher params is null");
			return IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL;
		}
	}

	if (sub_system & IOT_SECURITY_SUB_STORAGE) {
		if (!context->storage_params) {
			IOT_ERROR("storage params is null");
			return IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL;
		}
	}

	return IOT_ERROR_NONE;
}

static inline void _iot_security_be_software_buffer_free(iot_security_buffer_t *buffer)
{
	if (buffer) {
		if (buffer->p && buffer->len) {
			memset(buffer->p, 0, buffer->len);
			iot_os_free(buffer->p);
		}
		memset(buffer, 0, sizeof(iot_security_buffer_t));
	}
}

static inline void _iot_security_be_software_buffer_wipe(const iot_security_buffer_t *input_buf, size_t wiped_len)
{
	if (input_buf && (input_buf->len < wiped_len)) {
		int i;
		for (i = input_buf->len; i < wiped_len; i++) {
			input_buf->p[i] = 0;
		}
	}
}

typedef struct iot_security_be_key2storage_id_map {
	iot_security_key_id_t key_id;
	iot_security_storage_id_t storage_id;
} iot_security_be_key2storage_id_map_t;

static const iot_security_be_key2storage_id_map_t key2storage_id_map[] = {
	{ IOT_SECURITY_KEY_ID_DEVICE_PUBLIC, IOT_NVD_PUBLIC_KEY },
	{ IOT_SECURITY_KEY_ID_DEVICE_PRIVATE, IOT_NVD_PRIVATE_KEY },
	{ IOT_SECURITY_KEY_ID_SHARED_SECRET, IOT_NVD_UNKNOWN }
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
			return IOT_ERROR_SECURITY_KEY_NO_PERMISSION;
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
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (!context->be_context) {
		return IOT_ERROR_SECURITY_BE_CONTEXT_NULL;
	}

	bsp_fn = context->be_context->bsp_fn;

	if (!bsp_fn || !bsp_fn->bsp_fs_load) {
		return IOT_ERROR_SECURITY_BSP_FN_LOAD_NULL;
	}

	err = bsp_fn->bsp_fs_load(context->be_context, storage_id, output_buf);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
};

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
		_iot_security_be_software_buffer_free(&cipher_params->key);
	}

	if (cipher_params->iv.p) {
		_iot_security_be_software_buffer_free(&cipher_params->iv);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_copy_params(iot_security_buffer_t *src, iot_security_buffer_t *dst)
{
	if (src->p) {
		if (src->len == 0) {
			IOT_ERROR("length of src is zero");
			return IOT_ERROR_INVALID_ARGS;
		}

		if (dst->p) {
			_iot_security_be_software_buffer_free(dst);
		}

		dst->p = (unsigned char *)iot_os_malloc(src->len);
		if (!dst->p) {
			IOT_ERROR("failed to malloc for dst params");
			return IOT_ERROR_MEM_ALLOC;
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
		return IOT_ERROR_INVALID_ARGS;
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
iot_error_t _iot_security_be_software_cipher_aes_check_info(iot_security_cipher_params_t *cipher_params, const mbedtls_cipher_info_t *mbed_cipher_info)
{
	if (!cipher_params || !mbed_cipher_info) {
		IOT_ERROR("parameters are null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (cipher_params->key.len != (mbed_cipher_info->key_bitlen / 8)) {
		IOT_ERROR("key len mismatch, %d != %d", cipher_params->iv.len, mbed_cipher_info->iv_size);
		return IOT_ERROR_SECURITY_CIPHER_KEY_LEN;
	}

	if (cipher_params->iv.len != mbed_cipher_info->iv_size) {
		IOT_ERROR("iv len mismatch, %d != %d", cipher_params->iv.len, mbed_cipher_info->iv_size);
		return IOT_ERROR_SECURITY_CIPHER_IV_LEN;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_aes(iot_security_context_t *context, iot_security_cipher_mode_t cipher_mode, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	iot_security_cipher_params_t *cipher_params;
	const mbedtls_cipher_info_t *mbed_cipher_info;
	mbedtls_cipher_type_t mbed_cipher_alg;
	mbedtls_cipher_context_t mbed_cipher_ctx;
	mbedtls_operation_t mbed_op_mode;
	size_t required_len;
	size_t expected_key_len;
	int ret;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (cipher_mode == IOT_SECURITY_CIPHER_ENCRYPT) {
		mbed_op_mode = MBEDTLS_ENCRYPT;
	} else if (cipher_mode == IOT_SECURITY_CIPHER_DECRYPT) {
		mbed_op_mode = MBEDTLS_DECRYPT;
	} else {
		IOT_ERROR("'%d' is not a supported cipher mode", cipher_mode);
		return IOT_ERROR_SECURITY_CIPHER_INVALID_MODE;
	}

	cipher_params = context->cipher_params;

	if (cipher_params->type == IOT_SECURITY_KEY_TYPE_AES256) {
		mbed_cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
		expected_key_len = IOT_SECURITY_SECRET_LEN;
	} else {
		IOT_ERROR("'%d' is not a supported cipher algorithm", cipher_params->type);
		return IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO;
	}

	if (!cipher_params->key.p || (cipher_params->key.len != expected_key_len)) {
		IOT_ERROR("key is invalid %d@%p", (int)cipher_params->key.len, cipher_params->key.p);
		return IOT_ERROR_SECURITY_CIPHER_INVALID_KEY;
	}

	if (!cipher_params->iv.p || (cipher_params->iv.len != IOT_SECURITY_IV_LEN)) {
		IOT_ERROR("iv is invalid %d@%p", (int)cipher_params->iv.len, cipher_params->iv.p);
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

	err = _iot_security_be_software_cipher_aes_check_info(cipher_params, mbed_cipher_info);
	if (err) {
		return err;
	}

	mbedtls_cipher_init(&mbed_cipher_ctx);

	if (cipher_mode == IOT_SECURITY_CIPHER_ENCRYPT) {
		required_len = iot_security_cipher_get_align_size(cipher_params->type, input_buf->len);
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

	ret = mbedtls_cipher_setkey(&mbed_cipher_ctx, cipher_params->key.p, mbed_cipher_info->key_bitlen, mbed_op_mode);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}

	ret = mbedtls_cipher_crypt(&mbed_cipher_ctx, cipher_params->iv.p, cipher_params->iv.len,
				   (const unsigned char *)input_buf->p, input_buf->len, output_buf->p, &output_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_crypt = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		goto exit_free_output_buf;
	}

	if (output_buf->len > required_len) {
		IOT_ERROR("buffer overflow in cipher '%d' (%d > %d)", cipher_mode, (int)output_buf->len, (int)required_len);
		err = IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW;
		goto exit_free_output_buf;
	}

	_iot_security_be_software_buffer_wipe(output_buf, required_len);

	IOT_DEBUG("key:   %3d@%p", (int)cipher_params->key.len, cipher_params->key.p);

	err = IOT_ERROR_NONE;
	goto exit;

exit_free_output_buf:
	_iot_security_be_software_buffer_free(output_buf);
exit:
	mbedtls_cipher_free(&mbed_cipher_ctx);

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_security_cipher_mode_t cipher_mode = IOT_SECURITY_CIPHER_ENCRYPT;
	return _iot_security_be_software_cipher_aes(context, cipher_mode, input_buf, output_buf);
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_security_cipher_mode_t cipher_mode = IOT_SECURITY_CIPHER_DECRYPT;
	return _iot_security_be_software_cipher_aes(context, cipher_mode, input_buf, output_buf);
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
		return IOT_ERROR_INVALID_ARGS;
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
		return IOT_ERROR_SECURITY_KEY_INVALID_ID;
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
			return IOT_ERROR_INVALID_ARGS;
		}

		if (!context->cipher_params->key.p || (context->cipher_params->key.len == 0)) {
			IOT_ERROR("shared secret not yet set");
			return IOT_ERROR_SECURITY_KEY_NOT_FOUND;
		}

		key_buf->len = context->cipher_params->key.len;
		key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
		if (!key_buf->p) {
			IOT_ERROR("failed to malloc for getting key");
			key_buf->len = 0;
			return IOT_ERROR_MEM_ALLOC;
		}
		memcpy(key_buf->p, context->cipher_params->key.p, key_buf->len);
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
		return IOT_ERROR_SECURITY_CERT_INVALID_ID;
	}

	err = _iot_security_be_software_bsp_fs_load(context, storage_id, cert_buf);
	if (err) {
		return err;
	}

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
		return IOT_ERROR_SECURITY_BSP_FN_STORE_NULL;
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
		return IOT_ERROR_SECURITY_BSP_FN_REMOVE_NULL;
	}

	err = context->be_context->bsp_fn->bsp_fs_remove(context->be_context, storage_params->storage_id);
	if (err) {
		if (err != IOT_ERROR_SECURITY_FS_NOT_FOUND) {
		}
		return err;
	}

	return IOT_ERROR_NONE;
}

const iot_security_be_funcs_t iot_security_be_software_funcs = {
	.cipher_init = NULL,
	.cipher_deinit = _iot_security_be_software_cipher_deinit,
	.cipher_set_params = _iot_security_be_software_cipher_set_params,
	.cipher_aes_encrypt = _iot_security_be_software_cipher_aes_encrypt,
	.cipher_aes_decrypt = _iot_security_be_software_cipher_aes_decrypt,

	.manager_init = NULL,
	.manager_deinit = NULL,
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
		return IOT_ERROR_INVALID_ARGS;
	}

	memset(be_context, 0, sizeof(iot_security_be_context_t));

	iot_os_free(be_context);

	return IOT_ERROR_NONE;
}
