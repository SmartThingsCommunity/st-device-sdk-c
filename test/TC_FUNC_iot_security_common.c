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

#include <iot_error.h>
#include <iot_nv_data.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_ecdh.h>
#include <security/iot_security_manager.h>
#include <security/iot_security_storage.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"
#include "security/backend/iot_security_be.h"
#include "security/iot_security_common.h"

TEST_SUITE("iot_security_common.c");

TEST(TC_iot_security_init_malloc_failure_neg)
{
    iot_security_context_t *context;

    for (int i = 0; i < 2; i++) {
        do_not_use_mock_iot_os_malloc_failure();
        // Given: i-th malloc failure
        set_mock_iot_os_malloc_failure_with_index(i);
        // When
        context = iot_security_init();
        // Then
        assert_null(context);
    }

    do_not_use_mock_iot_os_malloc_failure();
}

TEST(TC_iot_security_init_success_pos)
{
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

    // When
    context = iot_security_init();
    // Then
    assert_non_null(context);
    // Teardown
    iot_os_free(context->be_context);
    iot_os_free(context);

    set_mock_detect_memory_leak(false);
}

TEST(TC_iot_security_deinit_null_parameters_neg)
{
    iot_error_t err;

    // When: context is null
    err = iot_security_deinit(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_deinit_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

    // Given
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(false);
}

TEST(TC_iot_security_check_context_is_valid_null_parameters_neg)
{
    iot_error_t err;

    // When: context is null
    err = iot_security_check_context_is_valid(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_check_context_is_valid_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

    // Given
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_check_context_is_valid(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(false);
}

TEST(TC_iot_security_check_backend_funcs_entry_is_valid_failure_neg)
{
    iot_error_t err;
    iot_security_context_t context = {0};
    iot_security_be_context_t be_context = {0};

    // When: context is null
    err = iot_security_check_backend_funcs_entry_is_valid(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);

    // When: be context is null
    err = iot_security_check_backend_funcs_entry_is_valid(&context);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_CONTEXT_NULL);

    // Given: be funcs is null
    context.be_context = &be_context;
    // When
    err = iot_security_check_backend_funcs_entry_is_valid(&context);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_is_valid_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

    // Given
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_check_backend_funcs_entry_is_valid(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(false);
}

/*
 * Negative tests for iot_security_init() / iot_security_deinit()
 */

TEST(TC_iot_security_init_context_malloc_failure_neg)
{
    iot_security_context_t *context;

    do_not_use_mock_iot_os_malloc_failure();
    // Given: the malloc for the security context itself fails
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    context = iot_security_init();
    // Then
    assert_null(context);

    do_not_use_mock_iot_os_malloc_failure();
}

TEST(TC_iot_security_init_be_context_malloc_failure_neg)
{
    iot_security_context_t *context;

    do_not_use_mock_iot_os_malloc_failure();
    // Given: the malloc for the backend context fails
    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    context = iot_security_init();
    // Then
    assert_null(context);

    do_not_use_mock_iot_os_malloc_failure();
}

TEST(TC_iot_security_deinit_be_context_null_neg)
{
    iot_error_t err;
    iot_security_context_t context = {0};

    // Given: a context that never got a backend context attached
    // When
    err = iot_security_deinit(&context);
    // Then: the backend deinit rejects the null backend context
    assert_int_equal(err, IOT_ERROR_SECURITY_INVALID_ARGS);
}

TEST(TC_iot_security_deinit_sub_system_dangling_neg)
{
    iot_error_t err;
    iot_security_context_t context = {0};

    // Given: sub system flags are set but no backend context exists
    context.sub_system = IOT_SECURITY_SUB_PK | IOT_SECURITY_SUB_CIPHER | IOT_SECURITY_SUB_ECDH;
    // When
    err = iot_security_deinit(&context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // sub_system must stay untouched because deinit bailed out early
    assert_int_not_equal(context.sub_system, 0);
}

/*
 * iot_security_check_backend_funcs_entry_is_valid() is the common guard of
 * every security sub system.  The tests below drive that guard through each
 * public caller with a backend that has no function table.
 */

static iot_security_context_t *_no_funcs_context(iot_security_be_context_t *be_context)
{
    static iot_security_context_t context;

    memset(&context, 0, sizeof(context));
    memset(be_context, 0, sizeof(*be_context));
    context.be_context = be_context;

    return &context;
}

TEST(TC_iot_security_check_backend_funcs_entry_context_null_neg)
{
    // When
    iot_error_t err = iot_security_check_backend_funcs_entry_is_valid(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_be_context_null_neg)
{
    iot_security_context_t context = {0};

    // When: be_context is null
    iot_error_t err = iot_security_check_backend_funcs_entry_is_valid(&context);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_CONTEXT_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_funcs_null_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);

    // When: be_context->fn is null
    iot_error_t err = iot_security_check_backend_funcs_entry_is_valid(context);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_storage_read_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_buffer_t buf = {0};

    // When
    iot_error_t err = iot_security_storage_read(context, IOT_NVD_SERIAL_NUM, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_storage_write_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    unsigned char data[] = "payload";
    iot_security_buffer_t buf = {.p = data, .len = sizeof(data)};

    // When
    iot_error_t err = iot_security_storage_write(context, IOT_NVD_SERIAL_NUM, &buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_storage_remove_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);

    // When
    iot_error_t err = iot_security_storage_remove(context, IOT_NVD_SERIAL_NUM);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_ecdh_set_params_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_ecdh_params_t ecdh_params = {0};

    // When
    iot_error_t err = iot_security_ecdh_set_params(context, &ecdh_params);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_ecdh_compute_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_buffer_t secret_buf = {0};

    // When
    iot_error_t err = iot_security_ecdh_compute_shared_secret(context, &secret_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_pk_get_key_type_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_key_type_t key_type;

    // When
    iot_error_t err = iot_security_pk_get_key_type(context, &key_type);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_pk_sign_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    unsigned char data[] = "sign me";
    iot_security_buffer_t input_buf = {.p = data, .len = sizeof(data) - 1};
    iot_security_buffer_t sig_buf = {0};

    // When
    iot_error_t err = iot_security_pk_sign(context, &input_buf, &sig_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_pk_verify_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    unsigned char data[] = "verify me";
    iot_security_buffer_t input_buf = {.p = data, .len = sizeof(data) - 1};
    iot_security_buffer_t sig_buf = {.p = data, .len = sizeof(data) - 1};

    // When
    iot_error_t err = iot_security_pk_verify(context, &input_buf, &sig_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_cipher_set_params_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_cipher_params_t cipher_params = {0};

    // When
    iot_error_t err = iot_security_cipher_set_params(context, &cipher_params);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_cipher_encrypt_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    unsigned char data[] = "plain";
    iot_security_buffer_t input_buf = {.p = data, .len = sizeof(data) - 1};
    iot_security_buffer_t output_buf = {0};

    // When
    iot_error_t err = iot_security_cipher_aes_encrypt(context, &input_buf, &output_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_cipher_decrypt_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    unsigned char data[] = "cipher";
    iot_security_buffer_t input_buf = {.p = data, .len = sizeof(data) - 1};
    iot_security_buffer_t output_buf = {0};

    // When
    iot_error_t err = iot_security_cipher_aes_decrypt(context, &input_buf, &output_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_manager_generate_key_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);

    // When
    iot_error_t err = iot_security_manager_generate_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}

TEST(TC_iot_security_check_backend_funcs_entry_via_manager_get_key_neg)
{
    iot_security_be_context_t be_context;
    iot_security_context_t *context = _no_funcs_context(&be_context);
    iot_security_buffer_t key_buf = {0};

    // When
    iot_error_t err = iot_security_manager_get_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL, &key_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL);
}
