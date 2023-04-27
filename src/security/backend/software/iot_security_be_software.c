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
#include "security/iot_security_helper.h"
#include "security/backend/iot_security_be.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pk.h"

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

static void *ephemeral_keypair;

STATIC_FUNCTION
iot_error_t _iot_security_be_software_get_seckey_with_secp256v1(iot_security_key_id_t key_id, iot_security_buffer_t *key_buf)
{
	mbedtls_ecp_keypair *mbed_ecp_keypair;
	unsigned char raw[IOT_SECURITY_EC_SECKEY_LEN];
	size_t olen;
	int ret;

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key is is not a ephemeral key");
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	if (!ephemeral_keypair) {
		IOT_ERROR("ephemeral key pair is null");
		IOT_ERROR_DUMP_AND_RETURN(KEY_NOT_FOUND, 0);
	}

	mbed_ecp_keypair = ephemeral_keypair;

	ret = mbedtls_mpi_write_binary(&mbed_ecp_keypair->d, raw, sizeof(raw));
	if (ret) {
		IOT_ERROR("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		printf("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		key_buf->len = 0;
		iot_os_free(key_buf->p);
		IOT_ERROR_DUMP_AND_RETURN(MANAGER_KEY_GET, -ret);
	}

	/* remove ecp prefix */
	key_buf->len = sizeof(raw);
	key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
	if (!key_buf->p) {
		IOT_ERROR("failed to malloc for pubkey");
		key_buf->len = 0;
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	memcpy(key_buf->p, raw, key_buf->len);

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_get_pubkey_with_secp256v1(iot_security_key_id_t key_id, iot_security_buffer_t *key_buf)
{
	mbedtls_ecp_keypair *mbed_ecp_keypair;
	unsigned char raw[IOT_SECURITY_EC_PUBKEY_LEN + 1];
	size_t olen;
	int ret;

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key is is not a ephemeral key");
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	if (!ephemeral_keypair) {
		IOT_ERROR("ephemeral key pair is null");
		IOT_ERROR_DUMP_AND_RETURN(KEY_NOT_FOUND, 0);
	}

	mbed_ecp_keypair = ephemeral_keypair;

	ret = mbedtls_ecp_point_write_binary(&mbed_ecp_keypair->grp,
					     &mbed_ecp_keypair->Q,
					     MBEDTLS_ECP_PF_UNCOMPRESSED,
					     &olen, raw, sizeof(raw));
	if (ret) {
		IOT_ERROR("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		printf("mbedtls_ecp_point_write_binary = -0x%04X", -ret);
		key_buf->len = 0;
		iot_os_free(key_buf->p);
		IOT_ERROR_DUMP_AND_RETURN(MANAGER_KEY_GET, -ret);
	}

	/* remove ecp prefix */
	key_buf->len = olen;
	key_buf->p = (unsigned char *)iot_os_malloc(key_buf->len);
	if (!key_buf->p) {
		IOT_ERROR("failed to malloc for pubkey");
		key_buf->len = 0;
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	memcpy(key_buf->p, raw, key_buf->len);

	return IOT_ERROR_NONE;
}

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
		_iot_security_be_software_buffer_free(&key_b64_buf);
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	/* remove null character for base64 decoding */
	if (strlen((char *)key_b64_buf.p) == (key_b64_buf.len - 1)) {
		key_b64_buf.len -= 1;
	}

	err = iot_security_base64_decode(key_b64_buf.p, key_b64_buf.len, key_buf.p, key_buf.len, &olen);
	if (err) {
		_iot_security_be_software_buffer_free(&key_b64_buf);
		_iot_security_be_software_buffer_free(&key_buf);
		return err;
	}

	if (olen != key_buf.len) {
		_iot_security_be_software_buffer_free(&key_b64_buf);
		_iot_security_be_software_buffer_free(&key_buf);
		IOT_ERROR_DUMP_AND_RETURN(PK_KEY_LEN, 0);
	}

	*output_buf = key_buf;

	IOT_DEBUG("key '%d' is loaded %d@%p", key_id, (int)output_buf->len, output_buf->p);

	_iot_security_be_software_buffer_free(&key_b64_buf);

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
		_iot_security_be_software_buffer_free(&context->pk_params->seckey);
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
		_iot_security_be_software_buffer_free(&context->pk_params->seckey);
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
		_iot_security_be_software_buffer_free(&pk_params->pubkey);
	}

	if (pk_params->seckey.p) {
		_iot_security_be_software_buffer_free(&pk_params->seckey);
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


#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_sign_ed25519(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
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
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!sig_buf) {
		IOT_ERROR("sig buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	pk_params = context->pk_params;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len != ed25519_len)) {
		IOT_ERROR("pubkey is invalid with %d@%p", (int)pk_params->pubkey.len, pk_params->pubkey.p);
		IOT_ERROR_DUMP_AND_RETURN(PK_INVALID_PUBKEY, 0);
	}

	if (!pk_params->seckey.p || (pk_params->seckey.len != ed25519_len)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		IOT_ERROR_DUMP_AND_RETURN(PK_INVALID_SECKEY, 0);
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey.p);

	memcpy(skpk, pk_params->seckey.p, pk_params->seckey.len);
	memcpy(skpk + ed25519_len, pk_params->pubkey.p, pk_params->pubkey.len);

	sig_buf->len = iot_security_pk_get_signature_len(pk_params->type);
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	ret = crypto_sign_detached(sig_buf->p, &olen, input_buf->p, input_buf->len, skpk);
	if (ret) {
		IOT_ERROR("crypto_sign_detached = %d", ret);
		_iot_security_be_software_buffer_free(sig_buf);
		IOT_ERROR_DUMP_AND_RETURN(PK_SIGN, ret);
	}

	if ((size_t)olen != sig_buf->len) {
		IOT_ERROR("signature length mismatch (%d != %d)", (int)olen, (int)sig_buf->len);
		_iot_security_be_software_buffer_free(sig_buf);
		IOT_ERROR_DUMP_AND_RETURN(PK_KEY_LEN, (int)sig_buf->len);
	}

	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);

	return IOT_ERROR_NONE;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_verify_ed25519(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
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
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!sig_buf || !sig_buf->p || (sig_buf->len == 0)) {
		IOT_ERROR("sig buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	pk_params = context->pk_params;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		IOT_ERROR_DUMP_AND_RETURN(PK_INVALID_PUBKEY, 0);
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey);

	if (pk_params->pubkey.len != key_len) {
		IOT_ERROR("pubkey len '%d' is not '%d'", (int)pk_params->pubkey.len, (int)key_len);
		IOT_ERROR_DUMP_AND_RETURN(PK_KEY_LEN, (int)pk_params->pubkey.len);
	}

	ret = crypto_sign_verify_detached(sig_buf->p, input_buf->p, input_buf->len, pk_params->pubkey.p);
	if (ret) {
		IOT_ERROR("crypto_sign_verify_detached = %d\n", ret);
		IOT_ERROR_DUMP_AND_RETURN(PK_VERIFY, ret);
	}

	IOT_DEBUG("sign verify success");

	return IOT_ERROR_NONE;
}
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY */
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519 */


#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_sign_rsa(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
	int ret;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!sig_buf) {
		IOT_ERROR("sig buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	pk_params = context->pk_params;

	if (!pk_params->seckey.p || (pk_params->seckey.len == 0)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		IOT_ERROR_DUMP_AND_RETURN(PK_INVALID_SECKEY, 0);
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_pk_init(&mbed_pk_context);

	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	sig_buf->len = iot_security_pk_get_signature_len(pk_params->type);
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, &sig_buf->len, NULL, NULL);
	if (ret) {
		IOT_ERROR("mbedtls_pk_sign = -0x%04X\n", -ret);
		_iot_security_be_software_buffer_free(sig_buf);
		err = IOT_ERROR_SECURITY_PK_SIGN;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	IOT_DEBUG("sig:    %3d@%p", (int)sig_buf->len, sig_buf->p);

	err = IOT_ERROR_NONE;
exit:
	mbedtls_pk_free(&mbed_pk_context);

	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
static iot_error_t _iot_security_be_software_pk_verify_rsa(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	mbedtls_x509_crt mbed_x509_crt;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
	int ret;

	err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!sig_buf || !sig_buf->p || (sig_buf->len == 0)) {
		IOT_ERROR("sig buffer is invalid");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	pk_params = context->pk_params;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		IOT_ERROR_DUMP_AND_RETURN(PK_INVALID_PUBKEY, 0);
	}

	IOT_DEBUG("input:  %3d@%p", (int)input->len, input->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig->len, sig->p);
	IOT_DEBUG("pubkey: %3d@%p", (int)pk_params->pubkey.len, pk_params->pubkey);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_x509_crt_init(&mbed_x509_crt);

	ret = mbedtls_x509_crt_parse(&mbed_x509_crt, (const unsigned char *)pk_params->pubkey.p, pk_params->pubkey.len + 1);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_pk_verify(&mbed_x509_crt.pk, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, sig_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_pk_verify = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_VERIFY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	IOT_DEBUG("sign verify success");

	err = IOT_ERROR_NONE;
exit:
	mbedtls_x509_crt_free(&mbed_x509_crt);

	return err;
}
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY */
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA */

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_der_to_raw(iot_security_buffer_t *der_buf, iot_security_buffer_t *raw_buf)
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

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_sign_ecdsa(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
	iot_security_buffer_t raw_buf = { 0 };
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

	pk_params = context->pk_params;

	if (!pk_params->seckey.p || (pk_params->seckey.len == 0)) {
		IOT_ERROR("seckey is invalid with %d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);
		return IOT_ERROR_SECURITY_PK_INVALID_SECKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("seckey: %3d@%p", (int)pk_params->seckey.len, pk_params->seckey.p);

	mbed_md_type = MBEDTLS_MD_SHA256;

	mbedtls_pk_init(&mbed_pk_context);

	ret = mbedtls_pk_parse_key(&mbed_pk_context, (const unsigned char *)pk_params->seckey.p, pk_params->seckey.len + 1, NULL, 0);
	if (ret) {
		IOT_ERROR("mbedtls_pk_parse_key = -0x%04X\n", -ret);
		err = IOT_ERROR_SECURITY_PK_PARSEKEY;
		goto exit;
	}

	sig_buf->len = iot_security_pk_get_signature_len(pk_params->type);
	sig_buf->p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!sig_buf->p) {
		IOT_ERROR("failed to malloc for sig");
		return IOT_ERROR_MEM_ALLOC;
	}

	ret = mbedtls_pk_sign(&mbed_pk_context, mbed_md_type, input_buf->p, input_buf->len, sig_buf->p, &sig_buf->len, NULL, NULL);
	if (ret) {
		IOT_ERROR("mbedtls_pk_sign = -0x%04X\n", -ret);
		_iot_security_be_software_buffer_free(sig_buf);
		err = IOT_ERROR_SECURITY_PK_SIGN;
		goto exit;
	}

	raw_buf.p = (unsigned char *)iot_os_malloc(sig_buf->len);
	if (!raw_buf.p) {
		IOT_ERROR("failed to malloc for raw buf");
		_iot_security_be_software_buffer_free(sig_buf);
		err = IOT_ERROR_MEM_ALLOC;
		goto exit;
	}

	if (pk_params->pk_sign_type == IOT_SECURITY_PK_SIGN_TYPE_DER) {
		memcpy(raw_buf.p, sig_buf->p, sig_buf->len);
		raw_buf.len = sig_buf->len;
	}
	else {
		err = _iot_security_be_software_pk_der_to_raw(sig_buf, &raw_buf);
		if (err) {
			IOT_ERROR("failed to convert from der to raw");
			_iot_security_be_software_buffer_free(sig_buf);
			_iot_security_be_software_buffer_free(&raw_buf);
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

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
static iot_error_t _iot_security_be_software_pk_verify_ecdsa(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
	iot_error_t err;
	iot_security_pk_params_t *pk_params;
	mbedtls_x509_crt mbed_x509_crt;
	mbedtls_pk_context mbed_pk_context;
	mbedtls_md_type_t mbed_md_type;
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

	pk_params = context->pk_params;

	if (!pk_params->pubkey.p || (pk_params->pubkey.len == 0)) {
		IOT_ERROR("pubkey is invalid");
		return IOT_ERROR_SECURITY_PK_INVALID_PUBKEY;
	}

	IOT_DEBUG("input:  %3d@%p", (int)input->len, input->p);
	IOT_DEBUG("sig:    %3d@%p", (int)sig->len, sig->p);
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
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY */
#endif /* CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA */

STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	return _iot_security_be_software_pk_sign_ed25519(context, input_buf, sig_buf);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
	return _iot_security_be_software_pk_sign_rsa(context, input_buf, sig_buf);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
	return _iot_security_be_software_pk_sign_ecdsa(context, input_buf, sig_buf);
#else
	IOT_ERROR("not implemented");
	IOT_ERROR_DUMP_AND_RETURN(NOT_IMPLEMENTED, 0);
#endif
}

#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_VERIFY)
STATIC_FUNCTION
iot_error_t _iot_security_be_software_pk_verify(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *sig_buf)
{
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
	return _iot_security_be_software_pk_verify_ed25519(context, input_buf, sig_buf);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
	return _iot_security_be_software_pk_verify_rsa(context, input_buf, sig_buf);
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ECDSA)
	return _iot_security_be_software_pk_verify_ecdsa(context, input_buf, sig_buf);
#else
	IOT_ERROR("not implemented");
	IOT_ERROR_DUMP_AND_RETURN(NOT_IMPLEMENTED, 0);
#endif
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
			IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
		}

		if (dst->p) {
			_iot_security_be_software_buffer_free(dst);
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
iot_error_t _iot_security_be_software_cipher_aes_check_info(iot_security_cipher_params_t *cipher_params, const mbedtls_cipher_info_t *mbed_cipher_info)
{
	if (!cipher_params || !mbed_cipher_info) {
		IOT_ERROR("parameters are null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (cipher_params->key.len != (mbed_cipher_info->key_bitlen / 8)) {
		IOT_ERROR("key len mismatch, %d != %d", cipher_params->key.len, (mbed_cipher_info->key_bitlen / 8));
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_KEY_LEN, (int)cipher_params->key.len);
	}

	if (cipher_params->iv.len != mbed_cipher_info->iv_size) {
		IOT_ERROR("iv len mismatch, %d != %d", cipher_params->iv.len, mbed_cipher_info->iv_size);
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_IV_LEN, (int)cipher_params->iv.len);
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
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (cipher_mode == IOT_SECURITY_CIPHER_ENCRYPT) {
		mbed_op_mode = MBEDTLS_ENCRYPT;
	} else if (cipher_mode == IOT_SECURITY_CIPHER_DECRYPT) {
		mbed_op_mode = MBEDTLS_DECRYPT;
	} else {
		IOT_ERROR("'%d' is not a supported cipher mode", cipher_mode);
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_INVALID_MODE, cipher_mode);
	}

	cipher_params = context->cipher_params;

	if (cipher_params->type == IOT_SECURITY_KEY_TYPE_AES256) {
		mbed_cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
		expected_key_len = IOT_SECURITY_SECRET_LEN;
	} else {
		IOT_ERROR("'%d' is not a supported cipher algorithm", cipher_params->type);
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_INVALID_ALGO, cipher_params->type);
	}

	if (!cipher_params->key.p || (cipher_params->key.len != expected_key_len)) {
		IOT_ERROR("key is invalid %d@%p", (int)cipher_params->key.len, cipher_params->key.p);
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_INVALID_KEY, (int)cipher_params->key.len);
	}

	if (!cipher_params->iv.p || (cipher_params->iv.len != IOT_SECURITY_IV_LEN)) {
		IOT_ERROR("iv is invalid %d@%p", (int)cipher_params->iv.len, cipher_params->iv.p);
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_INVALID_IV, (int)cipher_params->iv.len);
	}

	IOT_DEBUG("input: %3d@%p", (int)input_buf->len, input_buf->p);
	IOT_DEBUG("key:   %3d@%p", (int)cipher_params->key.len, cipher_params->key.p);
	IOT_DEBUG("iv:    %3d@%p", (int)cipher_params->iv.len, cipher_params->iv.p);

	mbed_cipher_info = mbedtls_cipher_info_from_type(mbed_cipher_alg);
	if (!mbed_cipher_info) {
		IOT_ERROR("mbedtls_cipher_info_from_type returned null");
		IOT_ERROR_DUMP_AND_RETURN(CIPHER_INVALID_ALGO, 0);
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
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	memset(output_buf->p, 0, required_len);

	ret = mbedtls_cipher_setup(&mbed_cipher_ctx, mbed_cipher_info);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_output_buf;
	}

	ret = mbedtls_cipher_setkey(&mbed_cipher_ctx, cipher_params->key.p, mbed_cipher_info->key_bitlen, mbed_op_mode);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_output_buf;
	}

	ret = mbedtls_cipher_crypt(&mbed_cipher_ctx, cipher_params->iv.p, cipher_params->iv.len,
				   (const unsigned char *)input_buf->p, input_buf->len, output_buf->p, &output_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_crypt = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_CIPHER_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit_free_output_buf;
	}

	if (output_buf->len > required_len) {
		IOT_ERROR("buffer overflow in cipher '%d' (%d > %d)", cipher_mode, (int)output_buf->len, (int)required_len);
		err = IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
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
iot_error_t _iot_security_be_software_manager_generate_key(iot_security_context_t *context, iot_security_key_id_t key_id)
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

	if (key_id != IOT_SECURITY_KEY_ID_EPHEMERAL) {
		IOT_ERROR("key id is not for a ephemeral");
		IOT_ERROR_DUMP_AND_RETURN(KEY_INVALID_ID, 0);
	}

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy, (const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, -ret);
		return err;
	}

	mbed_curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
	if (mbed_curve_info == NULL) {
		IOT_ERROR("mbedtls_ecp_curve_info_from_name = -0x%04X", -ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, -ret);
		goto exit;
	}

	mbed_ecp_keypair = (mbedtls_ecp_keypair *)iot_os_malloc(sizeof(mbedtls_ecp_keypair));
	if (!mbed_ecp_keypair) {
		IOT_ERROR("failed to malloc for ephemeral keypair");
		err = IOT_ERROR_SECURITY_MEM_ALLOC;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	mbedtls_ecp_group_init(&mbed_ecp_keypair->grp);
	mbedtls_mpi_init(&mbed_ecp_keypair->d);
	mbedtls_ecp_point_init(&mbed_ecp_keypair->Q);

	ret = mbedtls_ecp_gen_key(mbed_curve_info->grp_id, mbed_ecp_keypair, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_gen_key = -0x%04X", -ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, -ret);
		goto exit_keypair_buffer_free;
	}

	ephemeral_keypair = (void *)mbed_ecp_keypair;
	err = IOT_ERROR_NONE;
	goto exit;

exit_keypair_buffer_free:
	iot_os_free(ephemeral_keypair);
exit:
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

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

	if (ephemeral_keypair) {
		mbedtls_ecp_keypair_free((mbedtls_ecp_keypair *)ephemeral_keypair);
		iot_os_free(ephemeral_keypair);
	}

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
		err = _iot_security_be_software_get_pubkey_with_secp256v1(key_id, key_buf);
		if (err) {
			return err;
		}
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

	err = iot_security_ed25519_convert_seckey(seckey_buf.p, seckey_curve);
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
	_iot_security_be_software_buffer_free(&seckey_buf);
exit_free_seckey_b64:
	_iot_security_be_software_buffer_free(&seckey_b64_buf);

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
		_iot_security_be_software_buffer_free(&ecdh_params->t_seckey);
	}

	if (ecdh_params->c_pubkey.p) {
		_iot_security_be_software_buffer_free(&ecdh_params->c_pubkey);
	}

	if (ecdh_params->salt.p) {
		_iot_security_be_software_buffer_free(&ecdh_params->salt);
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_swap_secret(iot_security_buffer_t *src, iot_security_buffer_t *dst)
{
	unsigned char *p;
	size_t len;
	int i;

	if (!src || !src->p || (src->len == 0) || !dst) {
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	len = src->len;
	p = (unsigned char *)iot_os_malloc(len);

	if (!p) {
		IOT_ERROR("failed to malloc for swap");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	for (i = 0; i < len; i++) {
		p[(len - 1) - i] = src->p[i];
	}

	dst->p = p;
	dst->len = len;

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_compute_premaster_secret_ed25519(
			iot_security_buffer_t *t_seckey_buf,
			iot_security_buffer_t *c_pubkey_buf,
			iot_security_buffer_t *output_buf)
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
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	key_len = IOT_SECURITY_ED25519_LEN;
	secret_len = IOT_SECURITY_SECRET_LEN;

	if (t_seckey_buf->len > key_len) {
		IOT_ERROR("things seckey is too large");
		IOT_ERROR_DUMP_AND_RETURN(ECDH_INVALID_SECKEY, t_seckey_buf->len);
	}

	if (c_pubkey_buf->len > key_len) {
		IOT_ERROR("cloud pubkey is too large");
		IOT_ERROR_DUMP_AND_RETURN(ECDH_INVALID_PUBKEY, c_pubkey_buf->len);
	}

	pmsecret_buf.len = secret_len;
	pmsecret_buf.p = (unsigned char *)iot_os_malloc(pmsecret_buf.len);
	if (!pmsecret_buf.p) {
		IOT_ERROR("malloc failed for pre master secret");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	mbedtls_ecdh_init(&mbed_ecdh);
	mbedtls_ctr_drbg_init(&mbed_ctr_drbg);
	mbedtls_entropy_init(&mbed_entropy);

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy,
								(const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_ecp_group_load(&mbed_ecdh.grp, mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	err = _iot_security_be_software_swap_secret(t_seckey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.d, swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		_iot_security_be_software_buffer_free(&swap_buf);
		goto exit;
	}

	_iot_security_be_software_buffer_free(&swap_buf);

	err = _iot_security_be_software_swap_secret(c_pubkey_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.Qp.X, swap_buf.p, swap_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		_iot_security_be_software_buffer_free(&swap_buf);
		goto exit;
	}

	_iot_security_be_software_buffer_free(&swap_buf);

	ret = mbedtls_mpi_lset(&mbed_ecdh.Qp.Z, 1);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_lset = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.grp, &mbed_ecdh.z, &mbed_ecdh.Qp, &mbed_ecdh.d, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.z, pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	err = _iot_security_be_software_swap_secret(&pmsecret_buf, &swap_buf);
	if (err) {
		goto exit;
	}

	output_buf->p = swap_buf.p;
	output_buf->len = swap_buf.len;
	err = IOT_ERROR_NONE;

exit:
	_iot_security_be_software_buffer_free(&pmsecret_buf);
	mbedtls_ecdh_free(&mbed_ecdh);
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

	return err;
}

STATIC_FUNCTION
iot_error_t _iot_security_be_software_ecdh_compute_premaster_secret_ecdsa(
			iot_security_buffer_t *t_seckey_buf,
			iot_security_buffer_t *c_pubkey_buf,
			iot_security_buffer_t *output_buf)
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
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	key_len = IOT_SECURITY_EC_PUBKEY_LEN;
	secret_len = IOT_SECURITY_SECRET_LEN;

	if (t_seckey_buf->len > key_len) {
		IOT_ERROR("things seckey is too large");
		IOT_ERROR_DUMP_AND_RETURN(ECDH_INVALID_SECKEY, t_seckey_buf->len);
	}

	// c_pubkey_buf include tag(1 byte) + key
	if (c_pubkey_buf->len > key_len + 1) {
		IOT_ERROR("cloud pubkey is too large");
		IOT_ERROR_DUMP_AND_RETURN(ECDH_INVALID_PUBKEY, c_pubkey_buf->len);
	}

	pmsecret_buf.len = secret_len;
	pmsecret_buf.p = (unsigned char *)iot_os_malloc(pmsecret_buf.len);
	if (!pmsecret_buf.p) {
		IOT_ERROR("malloc failed for pre master secret");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	mbedtls_ecdh_init(&mbed_ecdh);
	mbedtls_ctr_drbg_init(&mbed_ctr_drbg);
	mbedtls_entropy_init(&mbed_entropy);

	ret = mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func, &mbed_entropy,
				    (const unsigned char *)pers, strlen(pers));
	if (ret) {
		IOT_ERROR("mbedtls_ctr_drbg_seed = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_ecp_group_load(&mbed_ecdh.grp, mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	/*
	 * own key
	 */
	ret = mbedtls_ecp_group_load(&mbed_ecdh.grp, mbed_ecp_grp_id);
	if (ret) {
		IOT_ERROR("mbedtls_ecp_group_load = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&mbed_ecdh.d, t_seckey_buf->p, t_seckey_buf->len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_read_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
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
		IOT_ERROR("mbedtls_ecdh_read_public = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	/*
	 * ecdh
	 */

	ret = mbedtls_ecdh_compute_shared(&mbed_ecdh.grp, &mbed_ecdh.z, &mbed_ecdh.Qp, &mbed_ecdh.d, mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
	if (ret) {
		IOT_ERROR("mbedtls_ecdh_compute_shared = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&mbed_ecdh.z, pmsecret_buf.p, pmsecret_buf.len);
	if (ret) {
		IOT_ERROR("mbedtls_mpi_write_binary = -0x%04X", -ret);
		err = IOT_ERROR_SECURITY_ECDH_LIBRARY;
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
		goto exit;
	}

	output_buf->p = pmsecret_buf.p;
	output_buf->len = pmsecret_buf.len;
	err = IOT_ERROR_NONE;

exit:
	mbedtls_ecdh_free(&mbed_ecdh);
	mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
	mbedtls_entropy_free(&mbed_entropy);

	return err;
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
			_iot_security_be_software_buffer_free(dst);
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
			err = _iot_security_be_software_ecdh_compute_premaster_secret_ecdsa(&ecdh_params->t_seckey, &ecdh_params->c_pubkey, &pmsecret_buf);
		} else
#endif
		{
			iot_security_buffer_t t_seckey_buf = { 0 };

			err = _iot_security_be_software_get_seckey_with_secp256v1(ecdh_params->key_id, &t_seckey_buf);
			if (err) {
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
				goto exit;
			}

			err = _iot_security_be_software_ecdh_compute_premaster_secret_ecdsa(&t_seckey_buf, &ecdh_params->c_pubkey, &pmsecret_buf);

			if (err) {
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, err, __LINE__, 0);
				_iot_security_be_software_buffer_free(&t_seckey_buf);
				goto exit;
			}

			_iot_security_be_software_buffer_free(&t_seckey_buf);
		}
		break;
	default:
		err = _iot_security_be_software_ecdh_compute_premaster_secret_ed25519(&ecdh_params->t_seckey, &ecdh_params->c_pubkey, &pmsecret_buf);
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
	_iot_security_be_software_buffer_free(&shared_secret_buf);
exit_free_secret:
	_iot_security_be_software_buffer_free(&secret_buf);
exit_free_pmsecret:
	_iot_security_be_software_buffer_free(&pmsecret_buf);
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
