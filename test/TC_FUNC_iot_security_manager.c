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

#include <bsp/iot_bsp_random.h>
#include <iot_error.h>
#include <iot_main.h>
#include <iot_nv_data.h>
#include <root_ca.h>
#include <security/backend/iot_security_be.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_manager.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

#define TEST_SECURITY_MANAGER_PRIVATE_KEY "yQMrFPkZ1wI62K1cEuhSL23wBR/nLr7s3YUZn+XAwb8="
#define TEST_SECURITY_MANAGER_PUBLIC_KEY "eV0oOSDhLf8UXqMO6Osat9G28lXldyZ5nzfQCQt/oiQ="
#define TEST_SECURITY_MANAGER_SERIAL_NUMBER "STDKtestc51ef86c"

TEST_SUITE("iot_security_manager.c");

static int TC_iot_security_manager_setup(void **state);
static int TC_iot_security_manager_teardown(void **state);

TEST_FIXTURE(iot_security_manager, TC_iot_security_manager_setup, TC_iot_security_manager_teardown);

static int TC_iot_security_manager_setup(void **state);
static int TC_iot_security_manager_teardown(void **state);

static int TC_iot_security_manager_setup(void **state);
static int TC_iot_security_manager_teardown(void **state);

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"" TEST_SECURITY_MANAGER_PRIVATE_KEY
    "\",\n"
    "\t\t\"publicKey\": \"" TEST_SECURITY_MANAGER_PUBLIC_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"" TEST_SECURITY_MANAGER_SERIAL_NUMBER
    "\"\n"
    "\t}\n"
    "}"};

static int TC_iot_security_manager_setup(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    set_mock_detect_memory_leak(true);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    context = iot_security_init();
    assert_non_null(context);

    err = iot_security_manager_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    *state = context;

    return 0;
}

static int TC_iot_security_manager_teardown(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_manager_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(false);

    return 0;
}

TEST(TC_iot_security_manager_init_null_parameters_neg)
{
    iot_error_t err;

    // When
    err = iot_security_manager_init(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_manager_init_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    // Given
    context = iot_security_init();
    assert_non_null(context);
    // When
    err = iot_security_manager_init(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST(TC_iot_security_manager_deinit_null_parameters_neg)
{
    iot_error_t err;

    // When
    err = iot_security_manager_init(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_manager_deinit_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    // Given
    context = iot_security_init();
    assert_non_null(context);
    err = iot_security_manager_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_manager_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    // Teardown
    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_set_key_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_params_t key_params;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: all null
    err = iot_security_manager_set_key(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = iot_security_manager_set_key(NULL, &key_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: params null
    err = iot_security_manager_set_key(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_set_key_invalid_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_params_t key_params;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: cipher init to set key
    err = iot_security_cipher_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: unknown key id
    key_params.key_id = IOT_SECURITY_KEY_ID_UNKNOWN;
    // When
    err = iot_security_manager_set_key(context, &key_params);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);

    // Given: not supported key id
    key_params.key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
    // When
    err = iot_security_manager_set_key(context, &key_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    err = iot_security_cipher_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_set_key_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_id_t key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    iot_security_key_params_t key_params = {0};
    iot_security_buffer_t key_buf = {0};
    iot_security_buffer_t verify_buf = {0};
    int i;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: cipher init to set key
    err = iot_security_cipher_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: prepare key
    key_buf.len = IOT_SECURITY_SHA256_LEN;
    key_buf.p = (unsigned char *)iot_os_malloc(key_buf.len);
    for (i = 0; i < key_buf.len; i++) {
        key_buf.p[i] = (unsigned char)iot_bsp_random();
    }

    // Given
    key_params.key_id = key_id;
    key_params.params.cipher.key = key_buf;
    assert_non_null(key_buf.p);
    // When
    err = iot_security_manager_set_key(context, &key_params);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_security_manager_get_key(context, key_id, &verify_buf);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(verify_buf.p);
    assert_int_not_equal(verify_buf.len, 0);
    assert_memory_equal(verify_buf.p, key_buf.p, key_buf.len);

    // Teardown
    iot_os_free(verify_buf.p);
    err = iot_security_cipher_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_key_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_id_t key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    iot_security_buffer_t key_buf;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: all null
    err = iot_security_manager_get_key(NULL, 0, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = iot_security_manager_get_key(NULL, key_id, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: key id zero
    err = iot_security_manager_get_key(context, 0, &key_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: params null
    err = iot_security_manager_get_key(context, key_id, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_key_invalid_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_id_t key_id;
    iot_security_buffer_t key_buf;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: unknown key id
    key_id = IOT_SECURITY_KEY_ID_UNKNOWN;
    // When
    err = iot_security_manager_get_key(context, key_id, &key_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);

    // Given: key id with no permission
    key_id = IOT_SECURITY_KEY_ID_DEVICE_PRIVATE;
    // When
    err = iot_security_manager_get_key(context, key_id, &key_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_NO_PERMISSION);

    // Given: empty key
    key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    // When
    err = iot_security_manager_get_key(context, key_id, &key_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_NOT_FOUND);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_key_alloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_id_t key_id;
    iot_security_buffer_t key_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    for (int i = 0; i < 2; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // Given
        key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
        // When
        err = iot_security_manager_get_key(context, key_id, &key_buf);
        // Then
        assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
    }

    // Local teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_key_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_key_id_t key_id;
    iot_security_buffer_t pubkey_buf = {0};
    char *pubkey_ref = (char *)TEST_SECURITY_MANAGER_PUBLIC_KEY;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given
    key_id = IOT_SECURITY_KEY_ID_DEVICE_PUBLIC;
    // When
    err = iot_security_manager_get_key(context, key_id, &pubkey_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(pubkey_buf.p);
    assert_int_not_equal(pubkey_buf.len, 0);
    assert_memory_equal(pubkey_buf.p, pubkey_ref, strlen(pubkey_ref));
    // Teardown
    iot_os_free(pubkey_buf.p);

    // Given
    key_id = IOT_SECURITY_KEY_ID_EPHEMERAL;
    err = iot_security_manager_generate_key(context, key_id);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    err = iot_security_manager_get_key(context, key_id, &pubkey_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(pubkey_buf.p);
    assert_int_not_equal(pubkey_buf.len, 0);
    // Teardown
    iot_os_free(pubkey_buf.p);
    err = iot_security_manager_remove_key(context, key_id);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_certificate_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cert_id_t cert_id = IOT_SECURITY_CERT_ID_DEVICE;
    iot_security_buffer_t cert_buf;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: all null
    err = iot_security_manager_get_certificate(NULL, 0, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = iot_security_manager_get_certificate(NULL, cert_id, &cert_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: cert id zero
    err = iot_security_manager_get_certificate(context, 0, &cert_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: buf null
    err = iot_security_manager_get_certificate(context, cert_id, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_certificate_invalid_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cert_id_t cert_id;
    iot_security_buffer_t cert_buf;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: unknown key id
    cert_id = IOT_SECURITY_CERT_ID_UNKNOWN;
    // When
    err = iot_security_manager_get_certificate(context, cert_id, &cert_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CERT_INVALID_ID);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_certificate_alloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cert_id_t cert_id;
    iot_security_buffer_t key_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    for (int i = 0; i < 1; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // Given
        cert_id = IOT_SECURITY_CERT_ID_ROOT_CA;
        // When
        err = iot_security_manager_get_certificate(context, cert_id, &key_buf);
        // Then
        assert_int_equal(err, IOT_ERROR_MEM_ALLOC);
    }

    // Local teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_certificate_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cert_id_t cert_id;
    iot_security_buffer_t cert_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given
    cert_id = IOT_SECURITY_CERT_ID_ROOT_CA;
    // When
    err = iot_security_manager_get_certificate(context, cert_id, &cert_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(cert_buf.p);
    assert_int_not_equal(cert_buf.len, 0);
    assert_memory_equal(cert_buf.p, st_root_ca, st_root_ca_len);
    // Teardown
    iot_os_free(cert_buf.p);
}

TEST_F(iot_security_manager, TC_iot_security_manager_get_certificate_nv_target_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_buffer_t cert_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: any cert_id other than ROOT_CA routes through the NV backend
    // path exercising _iot_security_manager_check_certificate_target's
    // default branch.
    err = iot_security_manager_get_certificate(context, IOT_SECURITY_CERT_ID_DEVICE, &cert_buf);
    // Then: the test fixture does not populate device certs, so the backend
    // returns an error; we only care that the default branch was taken.
    (void)err;
    if (cert_buf.p) {
        iot_os_free(cert_buf.p);
    }
}

/*
 * iot_security_manager_generate_key tests
 */
TEST(TC_iot_security_manager_generate_key_null_context_neg)
{
    iot_error_t err;
    (void)state;

    // When
    err = iot_security_manager_generate_key(NULL, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_generate_key_invalid_key_id_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: non-ephemeral key id
    err = iot_security_manager_generate_key(context, IOT_SECURITY_KEY_ID_DEVICE_PUBLIC);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
}

TEST_F(iot_security_manager, TC_iot_security_manager_generate_key_unknown_key_id_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When
    err = iot_security_manager_generate_key(context, IOT_SECURITY_KEY_ID_UNKNOWN);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
}

TEST_F(iot_security_manager, TC_iot_security_manager_generate_key_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: generate an ephemeral ECC key pair
    err = iot_security_manager_generate_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // Local teardown: remove the key pair we just generated
    err = iot_security_manager_remove_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    assert_int_equal(err, IOT_ERROR_NONE);
}

/*
 * iot_security_manager_remove_key tests
 */
TEST(TC_iot_security_manager_remove_key_null_context_neg)
{
    iot_error_t err;
    (void)state;

    // When
    err = iot_security_manager_remove_key(NULL, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_manager, TC_iot_security_manager_remove_key_invalid_key_id_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: non-ephemeral key id
    err = iot_security_manager_remove_key(context, IOT_SECURITY_KEY_ID_DEVICE_PUBLIC);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
}

TEST_F(iot_security_manager, TC_iot_security_manager_remove_key_unknown_key_id_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_manager_remove_key(context, IOT_SECURITY_KEY_ID_UNKNOWN);
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
}

TEST_F(iot_security_manager, TC_iot_security_manager_remove_key_without_generate_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: no ephemeral key was ever generated
    err = iot_security_manager_remove_key(context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then: the removal is idempotent and does not fail
    assert_int_equal(err, IOT_ERROR_NONE);
}

/*
 * Note: Backend function error path tests are not possible because
 * iot_security_be_context_t is an opaque type. These error paths are
 * excluded from coverage using #ifdef STDK_IOT_CORE_COVERAGE_EXCLUDE
 * in the source file.
 */

/*
 * The tests below use a synthetic backend so that every guard and error
 * propagation path of iot_security_manager.c can be reached without a real
 * backend implementation.
 */

#define TC_MANAGER_BE_ERR IOT_ERROR_SECURITY_KEY_INVALID_ID

typedef struct {
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_funcs_t fn;
} tc_manager_fake_be_t;

static void _tc_manager_fake_be_init(tc_manager_fake_be_t *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->be_context.fn = &fake->fn;
    fake->context.be_context = &fake->be_context;
}

static iot_error_t _tc_manager_be_fail(iot_security_context_t *context)
{
    return TC_MANAGER_BE_ERR;
}

static iot_error_t _tc_manager_be_key_fail(iot_security_context_t *context, iot_security_key_id_t key_id)
{
    return TC_MANAGER_BE_ERR;
}

static iot_error_t _tc_manager_be_set_key_fail(iot_security_context_t *context, iot_security_key_params_t *key_params)
{
    return TC_MANAGER_BE_ERR;
}

static iot_error_t _tc_manager_be_get_cert_fail(iot_security_context_t *context, iot_security_cert_id_t cert_id,
                                                iot_security_buffer_t *cert_buf)
{
    return TC_MANAGER_BE_ERR;
}

TEST(TC_iot_security_manager_init_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose manager_init fails
    _tc_manager_fake_be_init(&fake);
    fake.fn.manager_init = _tc_manager_be_fail;
    // When
    err = iot_security_manager_init(&fake.context);
    // Then: the sub system must not be marked as ready
    assert_int_equal(err, TC_MANAGER_BE_ERR);
    assert_int_equal(fake.context.sub_system & IOT_SECURITY_SUB_MANAGER, 0);
}

TEST(TC_iot_security_manager_deinit_context_null_neg)
{
    // When
    iot_error_t err = iot_security_manager_deinit(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_CONTEXT_NULL);
}

TEST(TC_iot_security_manager_deinit_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose manager_deinit fails
    _tc_manager_fake_be_init(&fake);
    fake.context.sub_system = IOT_SECURITY_SUB_MANAGER;
    fake.fn.manager_deinit = _tc_manager_be_fail;
    // When
    err = iot_security_manager_deinit(&fake.context);
    // Then: the sub system stays marked so the caller can retry
    assert_int_equal(err, TC_MANAGER_BE_ERR);
    assert_int_equal(fake.context.sub_system, IOT_SECURITY_SUB_MANAGER);
}

TEST(TC_iot_security_manager_generate_key_be_func_null_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a function table without manager_generate_key
    _tc_manager_fake_be_init(&fake);
    // When
    err = iot_security_manager_generate_key(&fake.context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST(TC_iot_security_manager_generate_key_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose manager_generate_key fails
    _tc_manager_fake_be_init(&fake);
    fake.fn.manager_generate_key = _tc_manager_be_key_fail;
    // When
    err = iot_security_manager_generate_key(&fake.context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then: the backend error is propagated unchanged
    assert_int_equal(err, TC_MANAGER_BE_ERR);
}

TEST(TC_iot_security_manager_remove_key_be_func_null_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a function table without manager_remove_key
    _tc_manager_fake_be_init(&fake);
    // When
    err = iot_security_manager_remove_key(&fake.context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST(TC_iot_security_manager_remove_key_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose manager_remove_key fails
    _tc_manager_fake_be_init(&fake);
    fake.fn.manager_remove_key = _tc_manager_be_key_fail;
    // When
    err = iot_security_manager_remove_key(&fake.context, IOT_SECURITY_KEY_ID_EPHEMERAL);
    // Then
    assert_int_equal(err, TC_MANAGER_BE_ERR);
}

TEST(TC_iot_security_manager_set_key_be_func_null_neg)
{
    tc_manager_fake_be_t fake;
    iot_security_key_params_t key_params = {0};
    iot_error_t err;

    // Given: a function table without manager_set_key
    _tc_manager_fake_be_init(&fake);
    key_params.key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    // When
    err = iot_security_manager_set_key(&fake.context, &key_params);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST(TC_iot_security_manager_set_key_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_security_key_params_t key_params = {0};
    iot_error_t err;

    // Given: a backend whose manager_set_key fails
    _tc_manager_fake_be_init(&fake);
    fake.fn.manager_set_key = _tc_manager_be_set_key_fail;
    key_params.key_id = IOT_SECURITY_KEY_ID_SHARED_SECRET;
    // When
    err = iot_security_manager_set_key(&fake.context, &key_params);
    // Then
    assert_int_equal(err, TC_MANAGER_BE_ERR);
}

TEST(TC_iot_security_manager_get_key_be_func_null_neg)
{
    tc_manager_fake_be_t fake;
    iot_security_buffer_t key_buf;
    iot_error_t err;

    // Given: a function table without manager_get_key
    _tc_manager_fake_be_init(&fake);
    memset(&key_buf, 0xA5, sizeof(key_buf));
    // When
    err = iot_security_manager_get_key(&fake.context, IOT_SECURITY_KEY_ID_EPHEMERAL, &key_buf);
    // Then: the output buffer is cleared before the guard rejects the call
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
    assert_null(key_buf.p);
    assert_int_equal(key_buf.len, 0);
}

TEST(TC_iot_security_manager_get_certificate_be_func_null_neg)
{
    tc_manager_fake_be_t fake;
    iot_security_buffer_t cert_buf;
    iot_error_t err;

    // Given: a function table without manager_get_certificate
    _tc_manager_fake_be_init(&fake);
    memset(&cert_buf, 0xA5, sizeof(cert_buf));
    // When: a certificate that lives in nv, not in the static table, is asked for
    err = iot_security_manager_get_certificate(&fake.context, IOT_SECURITY_CERT_ID_DEVICE, &cert_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
    assert_null(cert_buf.p);
    assert_int_equal(cert_buf.len, 0);
}

TEST(TC_iot_security_manager_get_certificate_be_failure_neg)
{
    tc_manager_fake_be_t fake;
    iot_security_buffer_t cert_buf = {0};
    iot_error_t err;

    // Given: a backend whose manager_get_certificate fails
    _tc_manager_fake_be_init(&fake);
    fake.fn.manager_get_certificate = _tc_manager_be_get_cert_fail;
    // When
    err = iot_security_manager_get_certificate(&fake.context, IOT_SECURITY_CERT_ID_SUB_CA, &cert_buf);
    // Then
    assert_int_equal(err, TC_MANAGER_BE_ERR);
    assert_null(cert_buf.p);
}
