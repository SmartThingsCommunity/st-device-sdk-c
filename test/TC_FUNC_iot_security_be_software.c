/* ***************************************************************************
 *
 * Copyright (c) 2026 Samsung Electronics All Rights Reserved.
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

#include <fcntl.h>
#include <iot_error.h>
#include <security/backend/iot_security_be.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_storage.h>
#include <security/iot_security_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"

extern iot_error_t _iot_security_be_check_context_and_params_is_valid(iot_security_context_t *context,
                                                                      iot_security_sub_system_t sub_system);
extern iot_error_t _iot_security_be_software_id_check_permission(iot_security_storage_id_t id);
extern iot_error_t _iot_security_be_software_bsp_fs_load(iot_security_context_t *context,
                                                         iot_security_storage_id_t storage_id,
                                                         iot_security_buffer_t *output_buf);
extern iot_error_t _iot_security_be_software_pk_init(iot_security_context_t *context);
extern iot_error_t _iot_security_be_software_pk_deinit(iot_security_context_t *context);
extern iot_error_t _iot_security_be_software_pk_get_key_type(iot_security_context_t *context,
                                                             iot_security_key_type_t *key_type);
extern iot_error_t _iot_security_be_software_pk_sign(iot_security_context_t *context, iot_security_buffer_t *input_buf,
                                                     iot_security_buffer_t *sig_buf);
extern iot_error_t _iot_security_be_software_pk_verify(iot_security_context_t *context,
                                                       iot_security_buffer_t *input_buf,
                                                       iot_security_buffer_t *sig_buf);
extern iot_error_t _iot_security_be_software_cipher_deinit(iot_security_context_t *context);
extern iot_error_t _iot_security_be_software_cipher_set_params(iot_security_context_t *context,
                                                               iot_security_cipher_params_t *cipher_set_params);
extern iot_error_t _iot_security_be_software_cipher_aes_encrypt(iot_security_context_t *context,
                                                                iot_security_buffer_t *input_buf,
                                                                iot_security_buffer_t *output_buf);
extern iot_error_t _iot_security_be_software_cipher_aes_decrypt(iot_security_context_t *context,
                                                                iot_security_buffer_t *input_buf,
                                                                iot_security_buffer_t *output_buf);
extern iot_error_t _iot_security_be_software_manager_generate_key(iot_security_context_t *context,
                                                                  iot_security_key_id_t key_id);
extern iot_error_t _iot_security_be_software_manager_remove_key(iot_security_context_t *context,
                                                                iot_security_key_id_t key_id);
extern iot_error_t _iot_security_be_software_manager_set_key(iot_security_context_t *context,
                                                             iot_security_key_params_t *key_params);
extern iot_error_t _iot_security_be_software_manager_get_key(iot_security_context_t *context,
                                                             iot_security_key_id_t key_id,
                                                             iot_security_buffer_t *key_buf);
extern iot_error_t _iot_security_be_software_manager_get_certificate(iot_security_context_t *context,
                                                                     iot_security_cert_id_t cert_id,
                                                                     iot_security_buffer_t *cert_buf);
extern iot_error_t _iot_security_be_software_ecdh_init(iot_security_context_t *context);
extern iot_error_t _iot_security_be_software_ecdh_deinit(iot_security_context_t *context);
extern iot_error_t _iot_security_be_software_ecdh_set_params(iot_security_context_t *context,
                                                             iot_security_ecdh_params_t *ecdh_set_params);
extern iot_error_t _iot_security_be_software_ecdh_compute_shared_secret(iot_security_context_t *context,
                                                                        iot_security_buffer_t *output_buf);
extern iot_error_t _iot_security_be_software_storage_read(iot_security_context_t *context,
                                                          iot_security_buffer_t *data_buf);
extern iot_error_t _iot_security_be_software_storage_write(iot_security_context_t *context,
                                                           iot_security_buffer_t *data_buf);
extern iot_error_t _iot_security_be_software_storage_remove(iot_security_context_t *context);
extern iot_error_t _iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key);
extern iot_error_t _iot_security_be_software_cipher_copy_params(iot_security_buffer_t *src, iot_security_buffer_t *dst);
extern iot_error_t _iot_security_be_software_ecdh_copy_params(iot_security_buffer_t *src, iot_security_buffer_t *dst);

extern const iot_security_be_funcs_t iot_security_be_software_funcs;

static iot_security_context_t *create_test_security_context(void)
{
    iot_security_context_t *context;

    context = (iot_security_context_t *)malloc(sizeof(iot_security_context_t));
    if (!context) {
        return NULL;
    }
    memset(context, 0, sizeof(iot_security_context_t));

    context->be_context = iot_security_be_init(NULL);
    if (!context->be_context) {
        free(context);
        return NULL;
    }

    context->pk_params = (iot_security_pk_params_t *)malloc(sizeof(iot_security_pk_params_t));
    if (!context->pk_params) {
        iot_security_be_deinit(context->be_context);
        free(context);
        return NULL;
    }
    memset(context->pk_params, 0, sizeof(iot_security_pk_params_t));

    context->cipher_params = (iot_security_cipher_params_t *)malloc(sizeof(iot_security_cipher_params_t));
    if (!context->cipher_params) {
        free(context->pk_params);
        iot_security_be_deinit(context->be_context);
        free(context);
        return NULL;
    }
    memset(context->cipher_params, 0, sizeof(iot_security_cipher_params_t));

    context->ecdh_params = (iot_security_ecdh_params_t *)malloc(sizeof(iot_security_ecdh_params_t));
    if (!context->ecdh_params) {
        free(context->cipher_params);
        free(context->pk_params);
        iot_security_be_deinit(context->be_context);
        free(context);
        return NULL;
    }
    memset(context->ecdh_params, 0, sizeof(iot_security_ecdh_params_t));

    context->storage_params = (iot_security_storage_params_t *)malloc(sizeof(iot_security_storage_params_t));
    if (!context->storage_params) {
        free(context->ecdh_params);
        free(context->cipher_params);
        free(context->pk_params);
        iot_security_be_deinit(context->be_context);
        free(context);
        return NULL;
    }
    memset(context->storage_params, 0, sizeof(iot_security_storage_params_t));

    return context;
}

static void free_test_security_context(iot_security_context_t *context)
{
    if (!context) {
        return;
    }
    if (context->storage_params) {
        free(context->storage_params);
    }
    if (context->ecdh_params) {
        free(context->ecdh_params);
    }
    if (context->cipher_params) {
        free(context->cipher_params);
    }
    if (context->pk_params) {
        free(context->pk_params);
    }
    if (context->be_context) {
        iot_security_be_deinit(context->be_context);
    }
    free(context);
}

void TC_iot_security_be_init_success(void **state)
{
    iot_security_be_context_t *be_context;

    // Given
    // When
    be_context = iot_security_be_init(NULL);
    // Then
    assert_non_null(be_context);
    assert_string_equal(be_context->name, "software");
    assert_non_null(be_context->fn);
    assert_non_null(be_context->bsp_fn);
    // Teardown
    iot_security_be_deinit(be_context);
}

void TC_iot_security_be_init_malloc_failure(void **state)
{
    iot_security_be_context_t *be_context;

    // Given
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    be_context = iot_security_be_init(NULL);
    // Then
    assert_null(be_context);
    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_be_init_bsp_init_failure(void **state)
{
    iot_security_be_context_t *be_context;

    // Given
    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    be_context = iot_security_be_init(NULL);
    // Then
    if (be_context) {
        iot_security_be_deinit(be_context);
    }
    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_security_be_init_with_callback(void **state)
{
    iot_security_be_context_t *be_context;

    // Given
    // When
    be_context = iot_security_be_init((external_nv_callback)0x12345678);
    // Then
    assert_non_null(be_context);
    // Teardown
    iot_security_be_deinit(be_context);
}

void TC_iot_security_be_init_consecutive_calls(void **state)
{
    iot_security_be_context_t *be_context1;
    iot_security_be_context_t *be_context2;

    // Given
    // When
    be_context1 = iot_security_be_init(NULL);
    be_context2 = iot_security_be_init(NULL);
    // Then
    assert_non_null(be_context1);
    assert_non_null(be_context2);
    assert_ptr_not_equal(be_context1, be_context2);
    // Teardown
    iot_security_be_deinit(be_context1);
    iot_security_be_deinit(be_context2);
}

void TC_iot_security_be_init_funcs_not_null(void **state)
{
    iot_security_be_context_t *be_context;

    // Given
    be_context = iot_security_be_init(NULL);
    // When
    // Then
    assert_non_null(be_context);
    assert_non_null(be_context->fn);
    assert_non_null(be_context->fn->pk_init);
    assert_non_null(be_context->fn->pk_deinit);
    assert_non_null(be_context->fn->pk_get_key_type);
    assert_non_null(be_context->fn->pk_sign);
    assert_non_null(be_context->fn->cipher_deinit);
    assert_non_null(be_context->fn->cipher_set_params);
    assert_non_null(be_context->fn->cipher_aes_encrypt);
    assert_non_null(be_context->fn->cipher_aes_decrypt);
    assert_non_null(be_context->fn->ecdh_init);
    assert_non_null(be_context->fn->ecdh_deinit);
    assert_non_null(be_context->fn->ecdh_set_params);
    assert_non_null(be_context->fn->ecdh_compute_shared_secret);
    assert_non_null(be_context->fn->manager_generate_key);
    assert_non_null(be_context->fn->manager_remove_key);
    assert_non_null(be_context->fn->manager_set_key);
    assert_non_null(be_context->fn->manager_get_key);
    assert_non_null(be_context->fn->manager_get_certificate);
    assert_non_null(be_context->fn->storage_read);
    assert_non_null(be_context->fn->storage_write);
    assert_non_null(be_context->fn->storage_remove);
    // Teardown
    iot_security_be_deinit(be_context);
}

void TC_iot_security_be_deinit_success(void **state)
{
    iot_security_be_context_t *be_context;
    iot_error_t err;

    // Given
    be_context = iot_security_be_init(NULL);
    // When
    err = iot_security_be_deinit(be_context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_deinit_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = iot_security_be_deinit(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_deinit_multiple_contexts(void **state)
{
    iot_security_be_context_t *be_contexts[3];
    iot_error_t err;
    int i;

    // Given
    for (i = 0; i < 3; i++) {
        be_contexts[i] = iot_security_be_init(NULL);
        assert_non_null(be_contexts[i]);
    }
    // When
    for (i = 0; i < 3; i++) {
        err = iot_security_be_deinit(be_contexts[i]);
        // Then
        assert_int_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_security_be_check_context_params_valid_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_NONE);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_check_context_params_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_check_context_and_params_is_valid(NULL, IOT_SECURITY_SUB_NONE);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_check_context_params_null_pk_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->pk_params);
    context->pk_params = NULL;
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->pk_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_check_context_params_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_CIPHER);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_check_context_params_null_ecdh_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->ecdh_params);
    context->ecdh_params = NULL;
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_ECDH);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->ecdh_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_check_context_params_null_storage_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->storage_params);
    context->storage_params = NULL;
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_STORAGE);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->storage_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_check_context_params_multiple_subs(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_check_context_and_params_is_valid(context, IOT_SECURITY_SUB_PK | IOT_SECURITY_SUB_CIPHER);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_id_check_permission_public_key(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_id_check_permission(IOT_NVD_PUBLIC_KEY);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_id_check_permission_private_key_denied(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_id_check_permission(IOT_NVD_PRIVATE_KEY);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_id_check_permission_unknown_id(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_id_check_permission(IOT_NVD_UNKNOWN);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_id_check_permission_device_cert(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_id_check_permission(IOT_NVD_DEVICE_CERT);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_id_check_permission_root_ca(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_id_check_permission(IOT_NVD_ROOT_CA_CERT);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_bsp_fs_load_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_bsp_fs_load(NULL, IOT_NVD_DEVICE_ID, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_bsp_fs_load_null_be_context(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_buffer_t output_buf = {0};

    // Given
    memset(&context, 0, sizeof(context));
    // When
    err = _iot_security_be_software_bsp_fs_load(&context, IOT_NVD_DEVICE_ID, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_bsp_fs_load_null_bsp_fn(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_buffer_t output_buf = {0};

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    context.be_context = &be_context;
    // When
    err = _iot_security_be_software_bsp_fs_load(&context, IOT_NVD_DEVICE_ID, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_bsp_fs_load_null_bsp_fs_load_fn(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_bsp_funcs_t bsp_fn;
    iot_security_buffer_t output_buf = {0};

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    memset(&bsp_fn, 0, sizeof(bsp_fn));
    be_context.bsp_fn = &bsp_fn;
    context.be_context = &be_context;
    // When
    err = _iot_security_be_software_bsp_fs_load(&context, IOT_NVD_DEVICE_ID, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_bsp_fs_load_invalid_storage_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_bsp_fs_load(context, IOT_NVD_UNKNOWN, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_deinit_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->pubkey.p = (unsigned char *)malloc(32);
    context->pk_params->pubkey.len = 32;
    context->pk_params->seckey.p = (unsigned char *)malloc(32);
    context->pk_params->seckey.len = 32;
    // When
    err = _iot_security_be_software_pk_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_deinit_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_pk_deinit(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_pk_deinit_null_pk_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->pk_params);
    context->pk_params = NULL;
    // When
    err = _iot_security_be_software_pk_deinit(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->pk_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_deinit_null_pubkey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->seckey.p = (unsigned char *)malloc(32);
    context->pk_params->seckey.len = 32;
    // When
    err = _iot_security_be_software_pk_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_deinit_null_seckey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->pubkey.p = (unsigned char *)malloc(32);
    context->pk_params->pubkey.len = 32;
    // When
    err = _iot_security_be_software_pk_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_deinit_both_null_keys(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_pk_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_get_key_type_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_type_t key_type;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->type = IOT_SECURITY_KEY_TYPE_ED25519;
    // When
    err = _iot_security_be_software_pk_get_key_type(context, &key_type);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(key_type, IOT_SECURITY_KEY_TYPE_ED25519);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_get_key_type_null_context(void **state)
{
    iot_error_t err;
    iot_security_key_type_t key_type;

    // Given
    // When
    err = _iot_security_be_software_pk_get_key_type(NULL, &key_type);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_pk_get_key_type_null_pk_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_type_t key_type;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->pk_params);
    context->pk_params = NULL;
    // When
    err = _iot_security_be_software_pk_get_key_type(context, &key_type);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->pk_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_get_key_type_rsa(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_type_t key_type;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->type = IOT_SECURITY_KEY_TYPE_RSA2048;
    // When
    err = _iot_security_be_software_pk_get_key_type(context, &key_type);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(key_type, IOT_SECURITY_KEY_TYPE_RSA2048);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_get_key_type_ecdsa(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_type_t key_type;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->pk_params->type = IOT_SECURITY_KEY_TYPE_ECCP256;
    // When
    err = _iot_security_be_software_pk_get_key_type(context, &key_type);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(key_type, IOT_SECURITY_KEY_TYPE_ECCP256);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_init_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_pk_init(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_pk_sign_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t sig_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_pk_sign(NULL, &input_buf, &sig_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_pk_sign_null_pk_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t sig_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->pk_params);
    context->pk_params = NULL;
    // When
    err = _iot_security_be_software_pk_sign(context, &input_buf, &sig_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->pk_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_pk_verify_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t sig_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_pk_verify(NULL, &input_buf, &sig_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_pk_verify_null_pk_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t sig_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->pk_params);
    context->pk_params = NULL;
    // When
    err = _iot_security_be_software_pk_verify(context, &input_buf, &sig_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->pk_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_deinit_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->cipher_params->key.p = (unsigned char *)malloc(16);
    context->cipher_params->key.len = 16;
    context->cipher_params->iv.p = (unsigned char *)malloc(16);
    context->cipher_params->iv.len = 16;
    // When
    err = _iot_security_be_software_cipher_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_deinit_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_cipher_deinit(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_deinit_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    // When
    err = _iot_security_be_software_cipher_deinit(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_deinit_null_key(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->cipher_params->iv.p = (unsigned char *)malloc(16);
    context->cipher_params->iv.len = 16;
    // When
    err = _iot_security_be_software_cipher_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_deinit_null_iv(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->cipher_params->key.p = (unsigned char *)malloc(16);
    context->cipher_params->key.len = 16;
    // When
    err = _iot_security_be_software_cipher_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_deinit_both_null(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_cipher_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_set_params_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_cipher_params_t cipher_set_params;
    unsigned char key_data[16] = {0};
    unsigned char iv_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    memset(&cipher_set_params, 0, sizeof(cipher_set_params));
    cipher_set_params.type = IOT_SECURITY_KEY_TYPE_AES256;
    cipher_set_params.key.p = key_data;
    cipher_set_params.key.len = 16;
    cipher_set_params.iv.p = iv_data;
    cipher_set_params.iv.len = 16;
    // When
    err = _iot_security_be_software_cipher_set_params(context, &cipher_set_params);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_set_params_null_context(void **state)
{
    iot_error_t err;
    iot_security_cipher_params_t cipher_set_params;

    // Given
    memset(&cipher_set_params, 0, sizeof(cipher_set_params));
    // When
    err = _iot_security_be_software_cipher_set_params(NULL, &cipher_set_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_set_params_null_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_cipher_set_params(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_set_params_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_cipher_params_t cipher_set_params;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    memset(&cipher_set_params, 0, sizeof(cipher_set_params));
    // When
    err = _iot_security_be_software_cipher_set_params(context, &cipher_set_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_set_params_zero_key_len(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_cipher_params_t cipher_set_params;
    unsigned char key_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    memset(&cipher_set_params, 0, sizeof(cipher_set_params));
    cipher_set_params.key.p = key_data;
    cipher_set_params.key.len = 0;
    // When
    err = _iot_security_be_software_cipher_set_params(context, &cipher_set_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_aes_encrypt_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t output_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_cipher_aes_encrypt(NULL, &input_buf, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_aes_encrypt_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t output_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    // When
    err = _iot_security_be_software_cipher_aes_encrypt(context, &input_buf, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_cipher_aes_decrypt_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t output_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_cipher_aes_decrypt(NULL, &input_buf, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_aes_decrypt_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t input_buf = {0};
    iot_security_buffer_t output_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    // When
    err = _iot_security_be_software_cipher_aes_decrypt(context, &input_buf, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_generate_key_invalid_key_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_generate_key(context, IOT_SECURITY_KEY_ID_DEVICE_PUBLIC);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_generate_key_shared_secret_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_generate_key(context, IOT_SECURITY_KEY_ID_SHARED_SECRET);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_generate_key_device_private_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_generate_key(context, IOT_SECURITY_KEY_ID_DEVICE_PRIVATE);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_generate_key_zero_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_generate_key(context, (iot_security_key_id_t)0);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_remove_key_invalid_key_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_remove_key(context, IOT_SECURITY_KEY_ID_DEVICE_PUBLIC);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_remove_key_shared_secret_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_remove_key(context, IOT_SECURITY_KEY_ID_SHARED_SECRET);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_remove_key_zero_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_remove_key(context, (iot_security_key_id_t)0);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_remove_key_ephemeral_no_generate(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_remove_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_set_key_null_context(void **state)
{
    iot_error_t err;
    iot_security_key_params_t key_params;

    // Given
    memset(&key_params, 0, sizeof(key_params));
    // When
    err = _iot_security_be_software_manager_set_key(NULL, &key_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_manager_set_key_null_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_set_key(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_set_key_null_cipher_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_params_t key_params;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->cipher_params);
    context->cipher_params = NULL;
    memset(&key_params, 0, sizeof(key_params));
    // When
    err = _iot_security_be_software_manager_set_key(context, &key_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->cipher_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_set_key_invalid_key_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_params_t key_params;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    memset(&key_params, 0, sizeof(key_params));
    key_params.key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
    // When
    err = _iot_security_be_software_manager_set_key(context, &key_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_set_key_shared_secret_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_key_params_t key_params;
    unsigned char key_data[16] = {0};
    unsigned char iv_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    memset(&key_params, 0, sizeof(key_params));
    key_params.key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    key_params.params.cipher.key.p = key_data;
    key_params.params.cipher.key.len = 16;
    key_params.params.cipher.iv.p = iv_data;
    key_params.params.cipher.iv.len = 16;
    // When
    err = _iot_security_be_software_manager_set_key(context, &key_params);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_get_key_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t key_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_manager_get_key(NULL, IOT_SECURITY_KEY_ID_SHARED_SECRET, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_manager_get_key_private_key_denied(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t key_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_get_key(context, IOT_SECURITY_KEY_ID_DEVICE_PRIVATE, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_get_key_shared_secret_not_set(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t key_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_get_key(context, IOT_SECURITY_KEY_ID_SHARED_SECRET, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_get_key_ephemeral_not_set(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t key_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_get_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_manager_get_certificate_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t cert_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_manager_get_certificate(NULL, IOT_SECURITY_CERT_ID_DEVICE, &cert_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_manager_get_certificate_invalid_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t cert_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_manager_get_certificate(context, (iot_security_cert_id_t)999, &cert_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_init_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_ecdh_init(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_init_null_ecdh_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->ecdh_params);
    context->ecdh_params = NULL;
    // When
    err = _iot_security_be_software_ecdh_init(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->ecdh_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_deinit_success(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->t_seckey.p = (unsigned char *)malloc(32);
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->c_pubkey.p = (unsigned char *)malloc(32);
    context->ecdh_params->c_pubkey.len = 32;
    context->ecdh_params->salt.p = (unsigned char *)malloc(16);
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_deinit_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_ecdh_deinit(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_deinit_null_ecdh_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->ecdh_params);
    context->ecdh_params = NULL;
    // When
    err = _iot_security_be_software_ecdh_deinit(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->ecdh_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_deinit_null_t_seckey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->c_pubkey.p = (unsigned char *)malloc(32);
    context->ecdh_params->c_pubkey.len = 32;
    // When
    err = _iot_security_be_software_ecdh_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_deinit_null_c_pubkey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->t_seckey.p = (unsigned char *)malloc(32);
    context->ecdh_params->t_seckey.len = 32;
    // When
    err = _iot_security_be_software_ecdh_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_deinit_null_salt(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->t_seckey.p = (unsigned char *)malloc(32);
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->c_pubkey.p = (unsigned char *)malloc(32);
    context->ecdh_params->c_pubkey.len = 32;
    // When
    err = _iot_security_be_software_ecdh_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_set_params_null_context(void **state)
{
    iot_error_t err;
    iot_security_ecdh_params_t ecdh_params;

    // Given
    memset(&ecdh_params, 0, sizeof(ecdh_params));
    // When
    err = _iot_security_be_software_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_set_params_null_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    // When
    err = _iot_security_be_software_ecdh_set_params(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_set_params_null_ecdh_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_ecdh_params_t ecdh_params;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->ecdh_params);
    context->ecdh_params = NULL;
    memset(&ecdh_params, 0, sizeof(ecdh_params));
    // When
    err = _iot_security_be_software_ecdh_set_params(context, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->ecdh_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_set_params_zero_len_seckey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_ecdh_params_t ecdh_params;
    unsigned char seckey_data[32] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    memset(&ecdh_params, 0, sizeof(ecdh_params));
    ecdh_params.t_seckey.p = seckey_data;
    ecdh_params.t_seckey.len = 0;
    // When
    err = _iot_security_be_software_ecdh_set_params(context, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(NULL, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_null_ecdh_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->ecdh_params);
    context->ecdh_params = NULL;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->ecdh_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_ephemeral_no_seckey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};
    unsigned char pubkey_data[32] = {0};
    unsigned char salt_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    context->ecdh_params->c_pubkey.p = pubkey_data;
    context->ecdh_params->c_pubkey.len = 32;
    context->ecdh_params->salt.p = salt_data;
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_ephemeral_with_seckey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};
    unsigned char seckey_data[32] = {0};
    unsigned char pubkey_data[32] = {0};
    unsigned char salt_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    context->ecdh_params->t_seckey.p = seckey_data;
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->c_pubkey.p = pubkey_data;
    context->ecdh_params->c_pubkey.len = 32;
    context->ecdh_params->salt.p = salt_data;
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    if (err == IOT_ERROR_NONE) {
        if (output_buf.p) {
            free(output_buf.p);
        }
    }
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_default_key_id(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};
    unsigned char seckey_data[32] = {0};
    unsigned char pubkey_data[32] = {0};
    unsigned char salt_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    context->ecdh_params->t_seckey.p = seckey_data;
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->c_pubkey.p = pubkey_data;
    context->ecdh_params->c_pubkey.len = 32;
    context->ecdh_params->salt.p = salt_data;
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    if (err == IOT_ERROR_NONE) {
        if (output_buf.p) {
            free(output_buf.p);
        }
    }
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_null_c_pubkey(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};
    unsigned char seckey_data[32] = {0};
    unsigned char salt_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->ecdh_params->key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    context->ecdh_params->t_seckey.p = seckey_data;
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->salt.p = salt_data;
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_ecdh_compute_shared_secret_with_cipher_subsystem(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t output_buf = {0};
    unsigned char seckey_data[32] = {0};
    unsigned char pubkey_data[32] = {0};
    unsigned char salt_data[16] = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    context->sub_system = IOT_SECURITY_SUB_ECDH | IOT_SECURITY_SUB_CIPHER;
    context->ecdh_params->key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    context->ecdh_params->t_seckey.p = seckey_data;
    context->ecdh_params->t_seckey.len = 32;
    context->ecdh_params->c_pubkey.p = pubkey_data;
    context->ecdh_params->c_pubkey.len = 32;
    context->ecdh_params->salt.p = salt_data;
    context->ecdh_params->salt.len = 16;
    // When
    err = _iot_security_be_software_ecdh_compute_shared_secret(context, &output_buf);
    // Then
    if (err == IOT_ERROR_NONE) {
        if (output_buf.p) {
            free(output_buf.p);
        }
    }
    // Teardown
    free_test_security_context(context);
}

void TC_iot_security_be_software_storage_read_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t data_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_storage_read(NULL, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_storage_read_null_storage_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t data_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->storage_params);
    context->storage_params = NULL;
    // When
    err = _iot_security_be_software_storage_read(context, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->storage_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_storage_write_null_context(void **state)
{
    iot_error_t err;
    iot_security_buffer_t data_buf = {0};

    // Given
    // When
    err = _iot_security_be_software_storage_write(NULL, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_storage_write_null_storage_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;
    iot_security_buffer_t data_buf = {0};

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->storage_params);
    context->storage_params = NULL;
    // When
    err = _iot_security_be_software_storage_write(context, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->storage_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_storage_write_null_bsp_fn(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_buffer_t data_buf = {0};

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    context.be_context = &be_context;
    context.storage_params = (iot_security_storage_params_t *)malloc(sizeof(iot_security_storage_params_t));
    memset(context.storage_params, 0, sizeof(iot_security_storage_params_t));
    // When
    err = _iot_security_be_software_storage_write(&context, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(context.storage_params);
}

void TC_iot_security_be_software_storage_write_null_bsp_store(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_bsp_funcs_t bsp_fn;
    iot_security_buffer_t data_buf = {0};

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    memset(&bsp_fn, 0, sizeof(bsp_fn));
    be_context.bsp_fn = &bsp_fn;
    context.be_context = &be_context;
    context.storage_params = (iot_security_storage_params_t *)malloc(sizeof(iot_security_storage_params_t));
    memset(context.storage_params, 0, sizeof(iot_security_storage_params_t));
    // When
    err = _iot_security_be_software_storage_write(&context, &data_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(context.storage_params);
}

void TC_iot_security_be_software_storage_remove_null_context(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_be_software_storage_remove(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_storage_remove_null_storage_params(void **state)
{
    iot_security_context_t *context;
    iot_error_t err;

    // Given
    context = create_test_security_context();
    assert_non_null(context);
    free(context->storage_params);
    context->storage_params = NULL;
    // When
    err = _iot_security_be_software_storage_remove(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    context->storage_params = NULL;
    free_test_security_context(context);
}

void TC_iot_security_be_software_storage_remove_null_bsp_fn(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_storage_params_t storage_params;

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    memset(&storage_params, 0, sizeof(storage_params));
    context.be_context = &be_context;
    context.storage_params = &storage_params;
    // When
    err = _iot_security_be_software_storage_remove(&context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_storage_remove_null_bsp_remove(void **state)
{
    iot_error_t err;
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_bsp_funcs_t bsp_fn;
    iot_security_storage_params_t storage_params;

    // Given
    memset(&context, 0, sizeof(context));
    memset(&be_context, 0, sizeof(be_context));
    memset(&bsp_fn, 0, sizeof(bsp_fn));
    memset(&storage_params, 0, sizeof(storage_params));
    be_context.bsp_fn = &bsp_fn;
    context.be_context = &be_context;
    context.storage_params = &storage_params;
    // When
    err = _iot_security_be_software_storage_remove(&context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_ed25519_convert_seckey_null_ed25519_key(void **state)
{
    iot_error_t err;
    unsigned char curve25519_key[32];

    // Given
    // When
    err = _iot_security_ed25519_convert_seckey(NULL, curve25519_key);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_ed25519_convert_seckey_null_curve25519_key(void **state)
{
    iot_error_t err;
    unsigned char ed25519_key[32];

    // Given
    // When
    err = _iot_security_ed25519_convert_seckey(ed25519_key, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_ed25519_convert_seckey_both_null(void **state)
{
    iot_error_t err;

    // Given
    // When
    err = _iot_security_ed25519_convert_seckey(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_copy_params_null_src(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src = {0};
    iot_security_buffer_t dst = {0};

    // Given
    // When
    err = _iot_security_be_software_cipher_copy_params(&src, &dst);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_copy_params_zero_len(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src;
    iot_security_buffer_t dst = {0};
    unsigned char data[16] = {0};

    // Given
    src.p = data;
    src.len = 0;
    // When
    err = _iot_security_be_software_cipher_copy_params(&src, &dst);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_cipher_copy_params_with_existing_dst(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src;
    iot_security_buffer_t dst = {0};
    unsigned char src_data[16] = {1, 2, 3};

    // Given
    src.p = src_data;
    src.len = 16;
    // When
    err = _iot_security_be_software_cipher_copy_params(&src, &dst);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    if (dst.p) {
        free(dst.p);
    }
}

void TC_iot_security_be_software_ecdh_copy_params_null_src(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src = {0};
    iot_security_buffer_t dst = {0};

    // Given
    // When
    err = _iot_security_be_software_ecdh_copy_params(&src, &dst);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_copy_params_zero_len(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src;
    iot_security_buffer_t dst = {0};
    unsigned char data[16] = {0};

    // Given
    src.p = data;
    src.len = 0;
    // When
    err = _iot_security_be_software_ecdh_copy_params(&src, &dst);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_security_be_software_ecdh_copy_params_with_existing_dst(void **state)
{
    iot_error_t err;
    iot_security_buffer_t src;
    iot_security_buffer_t dst = {0};
    unsigned char src_data[16] = {1, 2, 3};

    // Given
    src.p = src_data;
    src.len = 16;
    // When
    err = _iot_security_be_software_ecdh_copy_params(&src, &dst);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    if (dst.p) {
        free(dst.p);
    }
}
