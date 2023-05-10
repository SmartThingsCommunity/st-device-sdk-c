/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_ecdh.h>
#include <bsp/iot_bsp_random.h>
#include <security/iot_security_manager.h>
#include <iot_util.h>
#include <security/iot_security_helper.h>
#include "iot_debug.h"

#define ECDH_BLE_RANDOM_LEN		16
#define ECDH_BLE_DEBUG_LOG_ENABLE   0

static unsigned char own_ephemeral_pubkey_secp256r1_der_header[] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
	0x42, 0x00
};

iot_error_t iot_easysetup_ble_ecdh_init(iot_security_context_t **state)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_security_context_t *context = NULL;

	context = iot_security_init();
	if (context == NULL) {
		IOT_ERROR("context is NULL");
		err = IOT_ERROR_INIT_FAIL;
		goto out;
	}

	err = iot_security_pk_init(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security pk init fail");
        goto out;
    }

	err = iot_security_manager_init(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security manager init fail");
        goto out;
    }

	err = iot_security_cipher_init(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security cipher init fail");
        goto out;
    }

	*state = context;

out:
	return err;
}

iot_error_t iot_easysetup_ble_ecdh_teardown(void **state)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_security_context_t *context = NULL;

	context = (iot_security_context_t *)*state;
	if (context == NULL) {
		IOT_ERROR("context is NULL");
		err = IOT_ERROR_DEINIT_FAIL;
		goto out;
	}

	err = iot_security_manager_deinit(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security manager deinit fail");
        goto out;
    }

	err = iot_security_pk_deinit(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security pk deinit fail");
        goto out;
    }

	err = iot_security_deinit(context);
    if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Security pk deinit fail");
        goto out;
    }

out:
	return err;
}

iot_error_t iot_easysetup_ble_ecdh_compute_shared_signature(
            iot_security_context_t **state, unsigned char *sec_random,unsigned char **dev_cert,
            unsigned char **sub_cert, unsigned char **spub_key, size_t *spub_key_len,
            unsigned char **signature, size_t *signature_len)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cert_id_t cert_id;
    unsigned char random[ECDH_BLE_RANDOM_LEN * 2] = { 0 };
    unsigned char secret[IOT_SECURITY_SECRET_LEN] = { 0 };
    unsigned char iv[IOT_SECURITY_IV_LEN] = { 0 };
    iot_security_buffer_t cert_device_buf = { 0 };
    iot_security_buffer_t cert_sub_buf = { 0 };
    iot_security_buffer_t cert_blob_buf = { 0 };
    iot_security_buffer_t own_pubkey_buf = { 0 };
    iot_security_buffer_t own_pubkey_der_buf = { 0 };
    iot_security_buffer_t data_buf = { 0 };
    iot_security_buffer_t hash_buf = { 0 };
    iot_security_buffer_t sig_buf = { 0 };

	memcpy(&random[0], sec_random, (ECDH_BLE_RANDOM_LEN * 2));

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- random\n");
        iot_util_dump_mem("dump", random, (ECDH_BLE_RANDOM_LEN*2));
    }

    // <- certificates
    context = (iot_security_context_t *)*state;

    cert_id = IOT_SECURITY_CERT_ID_DEVICE;
    err = iot_security_manager_get_certificate(context, cert_id, &cert_device_buf);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to get the device certificate");
        goto out;
    }

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- leaf certificate\n");
        iot_util_dump_mem("dump", cert_device_buf.p, (int)cert_device_buf.len);
    }

    cert_id = IOT_SECURITY_CERT_ID_SUB_CA;
    err = iot_security_manager_get_certificate(context, cert_id, &cert_sub_buf);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to get the sub ca certificate");
        goto out;
    }

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- intermediate certificate\n");
        iot_util_dump_mem("dump", cert_sub_buf.p, (int)cert_sub_buf.len);
    }

	cert_blob_buf.len = cert_sub_buf.len + cert_device_buf.len;
	cert_blob_buf.p = (unsigned char *)iot_os_malloc(cert_blob_buf.len);
	memcpy(cert_blob_buf.p, cert_device_buf.p, cert_device_buf.len);
	memcpy(cert_blob_buf.p + cert_device_buf.len, cert_sub_buf.p, cert_sub_buf.len);

	*dev_cert = iot_os_malloc(cert_device_buf.len);
	*sub_cert = iot_os_malloc(cert_sub_buf.len);
	memcpy(*dev_cert, cert_device_buf.p, cert_device_buf.len);
	memcpy(*sub_cert, cert_sub_buf.p, cert_sub_buf.len);

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- certificate blob\n");
        iot_util_dump_mem("dump", cert_blob_buf.p, (int)cert_blob_buf.len);
    }

    // <- own public key
    err = iot_security_ecdh_init(context);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to init ecdh");
        goto out;
    }

    iot_security_ecdh_params_t ecdh_params = { 0 };

	ecdh_params.key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
	ecdh_params.salt.p = random;
	ecdh_params.salt.len = sizeof(random);

    err = iot_security_manager_generate_key(context, ecdh_params.key_id);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to generate ecdh key");
        goto out;
    }

    err = iot_security_manager_get_key(context, ecdh_params.key_id, &own_pubkey_buf);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to get ecdh pubkey");
        goto out;
    }

    own_pubkey_der_buf.len = own_pubkey_buf.len + sizeof(own_ephemeral_pubkey_secp256r1_der_header);

    if ((own_pubkey_der_buf.p = (unsigned char *)iot_os_malloc(own_pubkey_der_buf.len)) == NULL) {
        IOT_ERROR("failed to malloc for buf");
        err = IOT_ERROR_MEM_ALLOC;
        goto out;
    }
    memcpy(own_pubkey_der_buf.p, own_ephemeral_pubkey_secp256r1_der_header, sizeof(own_ephemeral_pubkey_secp256r1_der_header));
	memcpy(own_pubkey_der_buf.p + sizeof(own_ephemeral_pubkey_secp256r1_der_header), own_pubkey_buf.p, own_pubkey_buf.len);

    if ((*spub_key = iot_os_malloc(own_pubkey_der_buf.len)) == NULL) {
        IOT_ERROR("failed to malloc for buf");
        err = IOT_ERROR_MEM_ALLOC;
        goto out;
    }
    memcpy(*spub_key, own_pubkey_der_buf.p, own_pubkey_der_buf.len);
    *spub_key_len = own_pubkey_der_buf.len;

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- own ephemeral public key\n");
        iot_util_dump_mem("dump", own_pubkey_der_buf.p, own_pubkey_der_buf.len);
    }

    // <- signature
    data_buf.len = own_pubkey_der_buf.len + sizeof(random);
    if ((data_buf.p = (unsigned char *)iot_os_malloc(data_buf.len)) == NULL) {
        IOT_ERROR("failed to malloc for buf");
        err = IOT_ERROR_MEM_ALLOC;
        goto out;
    }

	memcpy(data_buf.p, own_pubkey_der_buf.p, own_pubkey_der_buf.len);
	memcpy(data_buf.p + own_pubkey_der_buf.len, random, sizeof(random));

	hash_buf.len = IOT_SECURITY_SHA256_LEN;
	hash_buf.p = (unsigned char *)iot_os_malloc(hash_buf.len);

    err = iot_security_sha256(data_buf.p, data_buf.len, hash_buf.p, hash_buf.len);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to make hashed data");
        goto out;
    }

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("-- hash\n");
        iot_util_dump_mem("dump", hash_buf.p, hash_buf.len);
    }

    err = iot_security_pk_set_sign_type(context, IOT_SECURITY_PK_SIGN_TYPE_DER);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to set sign type");
        goto out;
    }

    err = iot_security_pk_sign(context, &hash_buf, &sig_buf);
    if (err != IOT_ERROR_NONE) {
        IOT_ERROR("Fail to make signature");
        goto out;
    }

    if ((*signature = iot_os_malloc(sig_buf.len)) == NULL) {
        IOT_ERROR("failed to malloc for buf");
        err = IOT_ERROR_MEM_ALLOC;
        goto out;
    }
    memcpy(*signature, sig_buf.p, sig_buf.len);

    *signature_len = sig_buf.len;

    if (ECDH_BLE_DEBUG_LOG_ENABLE) {
        printf("<- signature\n");
        iot_util_dump_mem("dump", sig_buf.p, sig_buf.len);
    }

out:
    if (cert_device_buf.p) {
        iot_os_free(cert_device_buf.p);
    }
    if (cert_sub_buf.p) {
        iot_os_free(cert_sub_buf.p);
    }
    if (cert_blob_buf.p) {
        iot_os_free(cert_blob_buf.p);
    }
    if (data_buf.p) {
        iot_os_free(data_buf.p);
    }
    if (hash_buf.p) {
        iot_os_free(hash_buf.p);
    }
    if (sig_buf.p) {
        iot_os_free(sig_buf.p);
    }
    if (own_pubkey_der_buf.p) {
        iot_os_free(own_pubkey_der_buf.p);
    }
    if (own_pubkey_buf.p) {
        iot_os_free(own_pubkey_buf.p);
    }
    return err;
}
