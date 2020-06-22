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
#include "security/iot_security_ecdh.h"
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

	if (sub_system & IOT_SECURITY_SUB_PK) {
		if (!context->pk_params) {
			IOT_ERROR("pk params is null");
			return IOT_ERROR_SECURITY_PK_PARAMS_NULL;
		}
	}

	if (sub_system & IOT_SECURITY_SUB_CIPHER) {
		if (!context->cipher_params) {
			IOT_ERROR("cipher params is null");
			return IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL;
		}
	}

	if (sub_system & IOT_SECURITY_SUB_ECDH) {
		if (!context->ecdh_params) {
			IOT_ERROR("ecdh params is null");
			return IOT_ERROR_SECURITY_ECDH_PARAMS_NULL;
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

static inline void _iot_security_be_virtual_buffer_free(iot_security_buffer_t *buffer)
{
	if (buffer) {
		if (buffer->p && buffer->len) {
			memset(buffer->p, 0, buffer->len);
			iot_os_free(buffer->p);
		}
		memset(buffer, 0, sizeof(iot_security_buffer_t));
	}
}

static inline void _iot_security_be_virtual_buffer_wipe(const iot_security_buffer_t *input_buf, size_t wiped_len)
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
	{ IOT_SECURITY_KEY_ID_DEVICE_PUBLIC,  /* ToDo */ 0 },
	{ IOT_SECURITY_KEY_ID_DEVICE_PRIVATE, /* ToDo */ 0 },
	{ IOT_SECURITY_KEY_ID_SHARED_SECRET,  /* ToDo */ 0 }
};

static inline iot_security_storage_id_t _iot_security_be_virtual_id_key2storage(iot_security_key_id_t key_id)
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
	{ IOT_SECURITY_CERT_ID_ROOT_CA, /* ToDo */ 0 },
	{ IOT_SECURITY_CERT_ID_SUB_CA,  /* ToDo */ 0 },
	{ IOT_SECURITY_CERT_ID_DEVICE,  /* ToDo */ 0 },
};

static inline iot_security_storage_id_t _iot_security_be_virtual_id_cert2storage(iot_security_cert_id_t cert_id)
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
iot_error_t _iot_security_be_virtual_id_check_permission(iot_security_storage_id_t id)
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
iot_error_t _iot_security_be_virtual_pk_get_key_type(iot_security_context_t *context, iot_security_key_type_t *key_type)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	unsigned char skpk[crypto_sign_SECRETKEYBYTES];
	unsigned long long olen;
	size_t ed25519_len = IOT_SECURITY_ED25519_LEN;
	int ret;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!sig_buf) {
		IOT_ERROR("sig buffer is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_pk_verify(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	size_t key_len = IOT_SECURITY_ED25519_LEN;
	int ret;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!sig_buf || !sig_buf->p || (sig_buf->len == 0)) {
		IOT_ERROR("sig buffer is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_cipher_set_params(iot_security_context_t *context, iot_security_cipher_params_t *cipher_set_params)
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

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

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

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

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

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_manager_set_key(iot_security_context_t *context, iot_security_key_params_t *key_params)
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

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_manager_get_key(iot_security_context_t *context, iot_security_key_id_t key_id, iot_security_buffer_t *key_buf)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_NONE);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_virtual_id_key2storage(key_id);

	err = _iot_security_be_virtual_id_check_permission(storage_id);
	if (err) {
		return err;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_manager_get_certificate(iot_security_context_t *context, iot_security_cert_id_t cert_id, iot_security_buffer_t *cert_buf)
{
	iot_error_t err;
	iot_security_storage_id_t storage_id;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_NONE);
	if (err) {
		return err;
	}

	storage_id = _iot_security_be_virtual_id_cert2storage(cert_id);
	if (storage_id == IOT_NVD_UNKNOWN) {
		return IOT_ERROR_SECURITY_CERT_INVALID_ID;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_ecdh_set_params(iot_security_context_t *context, iot_security_ecdh_params_t *ecdh_set_params)
{
	iot_error_t err;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
	if (err) {
		return err;
	}

	if (!ecdh_set_params) {
		IOT_ERROR("ecdh set params is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	/*
	 * ToDo: call eSE
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_ecdh_compute_shared_secret(iot_security_context_t *context, iot_security_buffer_t *output_buf)
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

	/*
	 * ToDo: call eSE (fill the pmsecret_buf)
	 */

	secret_buf.len = pmsecret_buf.len + ecdh_params->salt.len;
	secret_buf.p = (unsigned char *)iot_os_malloc(secret_buf.len);
	if (!secret_buf.p) {
		IOT_ERROR("failed to malloc for secret");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_free_pmsecret;
	}

	memcpy(secret_buf.p, pmsecret_buf.p, pmsecret_buf.len);
	memcpy(secret_buf.p + pmsecret_buf.len, ecdh_params->salt.p, ecdh_params->salt.len);

	shared_secret_buf.len = IOT_SECURITY_SHA256_LEN;
	shared_secret_buf.p = (unsigned char *)iot_os_malloc(shared_secret_buf.len);
	if (!shared_secret_buf.p) {
		IOT_ERROR("failed to malloc for shared secret");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_free_secret;
	}

	err = iot_security_sha256(secret_buf.p, secret_buf.len, shared_secret_buf.p, shared_secret_buf.len);
	if (err) {
		goto exit_free_shared_secret;
	}

	if (output_buf) {
		*output_buf = shared_secret_buf;
	}

	err = IOT_ERROR_NONE;
	goto exit_free_secret;

exit_free_shared_secret:
	_iot_security_be_virtual_buffer_free(&shared_secret_buf);
exit_free_secret:
	_iot_security_be_virtual_buffer_free(&secret_buf);
exit_free_pmsecret:
	_iot_security_be_virtual_buffer_free(&pmsecret_buf);

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_storage_read(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	/*
	 * ToDo: call eSE (storage_params->storage_id)
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_storage_write(iot_security_context_t *context, iot_security_buffer_t *data_buf)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	/*
	 * ToDo: call eSE (storage_params->storage_id)
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_virtual_storage_remove(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_storage_params_t *storage_params;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
	if (err) {
		return err;
	}

	storage_params = context->storage_params;

	/*
	 * ToDo: call eSE (storage_params->storage_id)
	 */

	return IOT_ERROR_SECURITY_NOT_IMPLEMENTED;
}

const iot_security_be_funcs_t iot_security_be_virtual_funcs = {
	.pk_init = NULL,
	.pk_deinit = NULL,
	.pk_set_params = NULL,
	.pk_get_key_type = _iot_security_be_virtual_pk_get_key_type,
	.pk_sign = _iot_security_be_virtual_pk_sign,
	.pk_verify = _iot_security_be_virtual_pk_verify,

	.cipher_init = NULL,
	.cipher_deinit = NULL,
	.cipher_set_params = _iot_security_be_virtual_cipher_set_params,
	.cipher_aes_encrypt = _iot_security_be_virtual_cipher_aes_encrypt,
	.cipher_aes_decrypt = _iot_security_be_virtual_cipher_aes_decrypt,

	.ecdh_init = NULL,
	.ecdh_deinit = NULL,
	.ecdh_set_params = _iot_security_be_virtual_ecdh_set_params,
	.ecdh_compute_shared_secret = _iot_security_be_virtual_ecdh_compute_shared_secret,

	.manager_init = NULL,
	.manager_deinit = NULL,
	.manager_set_key = _iot_security_be_virtual_manager_set_key,
	.manager_get_key = _iot_security_be_virtual_manager_get_key,
	.manager_get_certificate = _iot_security_be_virtual_manager_get_certificate,

	.storage_init = NULL,
	.storage_deinit = NULL,
	.storage_read = _iot_security_be_virtual_storage_read,
	.storage_write = _iot_security_be_virtual_storage_write,
	.storage_remove = _iot_security_be_virtual_storage_remove,
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

	be_context->name = "virtual";
	be_context->fn = &iot_security_be_virtual_funcs;
	be_context->external_device_info_cb = external_nv_cb;

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
