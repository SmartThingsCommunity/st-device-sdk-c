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
#include <security/backend/iot_security_be.h>
#include <security/iot_security_crypto.h>
#include <security/iot_security_ecdh.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

TEST_SUITE("iot_security_ecdh.c");

static int TC_iot_security_ecdh_init_setup(void **state);
static int TC_iot_security_ecdh_init_teardown(void **state);
static int TC_iot_security_ecdh_setup(void **state);
static int TC_iot_security_ecdh_teardown(void **state);

TEST_FIXTURE(iot_security_ecdh, TC_iot_security_ecdh_setup, TC_iot_security_ecdh_teardown);
TEST_FIXTURE(iot_security_ecdh_init, TC_iot_security_ecdh_init_setup, TC_iot_security_ecdh_init_teardown);

static int TC_iot_security_ecdh_init_setup(void **state);
static int TC_iot_security_ecdh_init_teardown(void **state);
static int TC_iot_security_ecdh_setup(void **state);
static int TC_iot_security_ecdh_teardown(void **state);

static int TC_iot_security_ecdh_init_setup(void **state);
static int TC_iot_security_ecdh_init_teardown(void **state);
static int TC_iot_security_ecdh_setup(void **state);
static int TC_iot_security_ecdh_teardown(void **state);

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI=\",\n"
    "\t\t\"publicKey\": \"Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw=\",\n"
    "\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
    "\t}\n"
    "}"};

static int TC_iot_security_ecdh_init_setup(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    context = iot_security_init();
    assert_non_null(context);

    *state = context;

    return 0;
}

static int TC_iot_security_ecdh_init_teardown(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);

    return 0;
}

static int TC_iot_security_ecdh_setup(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    /*
     * set_mock_detect_memory_leak are not available by set_params
     */

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    context = iot_security_init();
    assert_non_null(context);

    err = iot_security_ecdh_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    *state = context;

    return 0;
}

static int TC_iot_security_ecdh_teardown(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    err = iot_security_ecdh_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_security_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    return 0;
}

TEST(TC_iot_security_ecdh_init_null_parameters_neg)
{
    iot_error_t err;

    // When
    err = iot_security_ecdh_init(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_security_ecdh_deinit(NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh_init, TC_iot_security_ecdh_init_malloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    do_not_use_mock_iot_os_malloc_failure();

    // Given
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    err = iot_security_ecdh_init(context);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_ecdh_init, TC_iot_security_ecdh_init_success_pos)
{
    iot_error_t err;
    iot_security_context_t *context;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When
    err = iot_security_ecdh_init(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_security_ecdh_deinit(context);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_set_params_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: all null
    err = iot_security_ecdh_set_params(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = iot_security_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: params null
    err = iot_security_ecdh_set_params(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_set_params_invalid_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};
    unsigned char buf[IOT_SECURITY_SECRET_LEN];

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: ecdh params doesn't have data
    err = iot_security_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: t_seckey len zero
    ecdh_params.t_seckey.p = buf;
    ecdh_params.t_seckey.len = 0;
    ecdh_params.c_pubkey.p = buf;
    ecdh_params.c_pubkey.len = sizeof(buf);
    ecdh_params.salt.p = buf;
    ecdh_params.salt.len = sizeof(buf);
    // When: ecdh params doesn't have data
    err = iot_security_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: c_pubkey len zero
    ecdh_params.t_seckey.p = buf;
    ecdh_params.t_seckey.len = sizeof(buf);
    ecdh_params.c_pubkey.p = buf;
    ecdh_params.c_pubkey.len = 0;
    ecdh_params.salt.p = buf;
    ecdh_params.salt.len = sizeof(buf);
    // When: ecdh params doesn't have data
    err = iot_security_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: salt len zero
    ecdh_params.t_seckey.p = buf;
    ecdh_params.t_seckey.len = sizeof(buf);
    ecdh_params.c_pubkey.p = buf;
    ecdh_params.c_pubkey.len = sizeof(buf);
    ecdh_params.salt.p = buf;
    ecdh_params.salt.len = 0;
    // When: ecdh params doesn't have data
    err = iot_security_ecdh_set_params(NULL, &ecdh_params);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_set_params_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};
    unsigned char seckey[IOT_SECURITY_SECRET_LEN];
    unsigned char pubkey[IOT_SECURITY_SECRET_LEN];
    unsigned char salt[IOT_SECURITY_SECRET_LEN];

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: things seckey is in nv
    ecdh_params.t_seckey.p = seckey;
    ecdh_params.t_seckey.len = sizeof(seckey);
    ecdh_params.c_pubkey.p = pubkey;
    ecdh_params.c_pubkey.len = sizeof(pubkey);
    ecdh_params.salt.p = salt;
    ecdh_params.salt.len = sizeof(salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_compute_shared_secret_null_parameters_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_buffer_t secret_buf;

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: all null
    err = iot_security_ecdh_compute_shared_secret(context, &secret_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: context null
    err = iot_security_ecdh_compute_shared_secret(NULL, &secret_buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: output buffer null
    err = iot_security_ecdh_compute_shared_secret(context, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static unsigned char things_seckey_curve25519[] = {
    /*
     * 04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI=
     */
    0x58, 0xc3, 0x53, 0x1f, 0x36, 0x27, 0xee, 0x3a, 0x25, 0x92, 0x2e, 0x4f, 0x71, 0x84, 0x7d, 0x24,
    0xd1, 0x36, 0x76, 0x5c, 0x43, 0x20, 0x1f, 0x42, 0x73, 0x34, 0x4d, 0x97, 0x63, 0x27, 0xf3, 0x53,
};

static unsigned char cloud_pubkey_curve25519[] = {
    0x6e, 0xc7, 0x18, 0xce, 0x29, 0x4e, 0xcb, 0x76, 0xb4, 0x50, 0xa9, 0x48, 0xce, 0x24, 0x87, 0x02,
    0xdc, 0xcf, 0x4f, 0xb2, 0x91, 0x12, 0x15, 0x67, 0x21, 0xa0, 0x8d, 0xf8, 0x36, 0x13, 0xde, 0x25,
};

static unsigned char ecdh_salt[] = {
    0xd0, 0xdf, 0x40, 0xee, 0x8c, 0x54, 0x25, 0xba, 0x46, 0x74, 0xf3, 0x4a, 0x33, 0x95, 0xde, 0xc6,
    0xec, 0xe9, 0xe1, 0xd6, 0x60, 0x50, 0x1e, 0xd5, 0x16, 0xbe, 0xaf, 0xce, 0x1c, 0x24, 0x49, 0x4c,
};

static unsigned char ecdh_shared_secret_expected[] = {
    0xa7, 0x5e, 0xfc, 0x97, 0x24, 0xe2, 0x31, 0x67, 0x0a, 0xf3, 0x10, 0xa2, 0xf8, 0x5a, 0x07, 0xd1,
    0xd1, 0x4d, 0xfa, 0x07, 0xdf, 0xab, 0x09, 0xb4, 0x56, 0xa6, 0xf7, 0x89, 0xef, 0xcf, 0x84, 0x6a,
};

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_compute_shared_secret_malloc_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};
    iot_security_buffer_t secret_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: things seckey is in nv
    ecdh_params.c_pubkey.p = cloud_pubkey_curve25519;
    ecdh_params.c_pubkey.len = sizeof(cloud_pubkey_curve25519);
    ecdh_params.salt.p = ecdh_salt;
    ecdh_params.salt.len = sizeof(ecdh_salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    for (int i = 0; i < 6; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When
        err = iot_security_ecdh_compute_shared_secret(context, &secret_buf);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }

    // Local teardown
    do_not_use_mock_iot_os_malloc_failure();
}

TEST_F(iot_security_ecdh_init, TC_iot_security_ecdh_compute_shared_secret_failure_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_buffer_t buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // When: compute without ecdh_init
    err = iot_security_ecdh_compute_shared_secret(context, &buf);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

static void TC_iot_security_ecdh_compute_shared_secret_general_neg(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};
    iot_security_buffer_t secret_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: things seckey is in nv
    ecdh_params.c_pubkey.p = cloud_pubkey_curve25519;
    ecdh_params.c_pubkey.len = sizeof(cloud_pubkey_curve25519);
    ecdh_params.salt.p = ecdh_salt;
    ecdh_params.salt.len = sizeof(ecdh_salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_security_ecdh_compute_shared_secret(context, &secret_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(secret_buf.p);
    assert_int_not_equal(secret_buf.len, 0);
    iot_os_free(secret_buf.p);
}

static void TC_iot_security_ecdh_compute_shared_secret_expected_neg(void **state)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_ecdh_params_t ecdh_params = {0};
    iot_security_buffer_t shared_secret = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: set things seckey to get expected shared secret
    ecdh_params.t_seckey.p = things_seckey_curve25519;
    ecdh_params.t_seckey.len = sizeof(things_seckey_curve25519);
    ecdh_params.c_pubkey.p = cloud_pubkey_curve25519;
    ecdh_params.c_pubkey.len = sizeof(cloud_pubkey_curve25519);
    ecdh_params.salt.p = ecdh_salt;
    ecdh_params.salt.len = sizeof(ecdh_salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    err = iot_security_ecdh_compute_shared_secret(context, &shared_secret);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(shared_secret.p);
    assert_int_not_equal(shared_secret.len, 0);
    assert_memory_equal(shared_secret.p, ecdh_shared_secret_expected, shared_secret.len);
    // Local teardown
    iot_os_free(shared_secret.p);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_compute_shared_secret_neg)
{
    TC_iot_security_ecdh_compute_shared_secret_general_neg(state);
    TC_iot_security_ecdh_compute_shared_secret_expected_neg(state);

    assert_true(true);
}

static unsigned char sample_iv[IOT_SECURITY_IV_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

static unsigned char sample_plain[] = {
    0xd0, 0xdf, 0x40, 0xee, 0x8c, 0x54, 0x25, 0xba, 0x46, 0x74, 0xf3, 0x4a, 0x33, 0x95, 0xde, 0xc6,
    0xec, 0xe9, 0xe1, 0xd6, 0x60, 0x50, 0x1e, 0xd5, 0x16, 0xbe, 0xaf, 0xce, 0x1c, 0x24, 0x49, 0x4c,
    0x6c, 0x61, 0xcc, 0x93, 0x50, 0xbf, 0x87, 0xe1, 0x3c, 0x0d, 0xc8, 0x60, 0xbd, 0xfd, 0xfc, 0x58,
    0xab, 0xc7, 0x9f, 0xe7, 0x0f, 0x35, 0x3a, 0x33, 0xd3, 0x11, 0xc4, 0x36, 0x1b, 0x32, 0x53, 0xe8,
};

static unsigned char sample_encrypt_expected[] = {
    0xda, 0x95, 0x0b, 0xbd, 0xa1, 0x61, 0xfb, 0x21, 0x3a, 0x09, 0xdd, 0xcc, 0xdd, 0x00, 0xe0, 0x28,
    0x20, 0xc9, 0x78, 0xa6, 0x60, 0x70, 0x8e, 0xd7, 0xe8, 0xff, 0xbd, 0x95, 0x7c, 0x3d, 0xf2, 0x85,
    0xce, 0x12, 0x2b, 0x7c, 0x84, 0x8d, 0x49, 0x18, 0x3d, 0xb7, 0xa2, 0x37, 0x86, 0xa8, 0x35, 0x05,
    0x6b, 0x8a, 0x7f, 0x68, 0x94, 0x96, 0xa7, 0x17, 0xce, 0x29, 0xfd, 0x66, 0xd9, 0x91, 0x5b, 0x1f,
    0x71, 0x8c, 0xfe, 0x1f, 0x88, 0xf1, 0x7d, 0x3e, 0xe6, 0xb6, 0xc0, 0xc0, 0x06, 0x22, 0x7d, 0xc4,
};

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_and_dynamic_cipher_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cipher_params_t aes_params = {0};
    iot_security_ecdh_params_t ecdh_params = {0};
    iot_security_buffer_t plain_buf = {0};
    iot_security_buffer_t encrypt_buf = {0};
    iot_security_buffer_t decrypt_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: to save shared secret
    err = iot_security_cipher_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: set params for ecdh
    ecdh_params.c_pubkey.p = cloud_pubkey_curve25519;
    ecdh_params.c_pubkey.len = sizeof(cloud_pubkey_curve25519);
    ecdh_params.salt.p = ecdh_salt;
    ecdh_params.salt.len = sizeof(ecdh_salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);
    // Given: set shared secret in security context
    err = iot_security_ecdh_compute_shared_secret(context, NULL);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: set iv
    aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
    aes_params.iv.p = sample_iv;
    aes_params.iv.len = sizeof(sample_iv);
    err = iot_security_cipher_set_params(context, &aes_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: encryption
    plain_buf.p = sample_plain;
    plain_buf.len = sizeof(sample_plain);
    // When
    err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(encrypt_buf.p);
    assert_int_not_equal(encrypt_buf.len, 0);
    assert_memory_equal(encrypt_buf.p, sample_encrypt_expected, encrypt_buf.len);

    // When: decryption
    err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(decrypt_buf.p);
    assert_int_not_equal(decrypt_buf.len, 0);
    assert_int_equal(decrypt_buf.len, plain_buf.len);
    assert_memory_equal(decrypt_buf.p, plain_buf.p, plain_buf.len);

    // Local teardown
    err = iot_security_cipher_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_security_ecdh, TC_iot_security_ecdh_and_static_cipher_neg)
{
    iot_error_t err;
    iot_security_context_t *context;
    iot_security_cipher_params_t aes_params = {0};
    iot_security_ecdh_params_t ecdh_params = {0};
    iot_security_buffer_t shared_secret = {0};
    iot_security_buffer_t plain_buf = {0};
    iot_security_buffer_t encrypt_buf = {0};
    iot_security_buffer_t decrypt_buf = {0};

    context = (iot_security_context_t *)*state;
    assert_non_null(context);

    // Given: set params for ecdh
    ecdh_params.c_pubkey.p = cloud_pubkey_curve25519;
    ecdh_params.c_pubkey.len = sizeof(cloud_pubkey_curve25519);
    ecdh_params.salt.p = ecdh_salt;
    ecdh_params.salt.len = sizeof(ecdh_salt);
    err = iot_security_ecdh_set_params(context, &ecdh_params);
    assert_int_equal(err, IOT_ERROR_NONE);
    // Given: get shared secret
    err = iot_security_ecdh_compute_shared_secret(context, &shared_secret);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(shared_secret.p);
    assert_int_not_equal(shared_secret.len, 0);

    // Given: set key with shared secret
    err = iot_security_cipher_init(context);
    assert_int_equal(err, IOT_ERROR_NONE);
    aes_params.type = IOT_SECURITY_KEY_TYPE_AES256;
    aes_params.key = shared_secret;
    aes_params.iv.p = sample_iv;
    aes_params.iv.len = sizeof(sample_iv);
    err = iot_security_cipher_set_params(context, &aes_params);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: encryption
    plain_buf.p = sample_plain;
    plain_buf.len = sizeof(sample_plain);
    // When
    err = iot_security_cipher_aes_encrypt(context, &plain_buf, &encrypt_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(encrypt_buf.p);
    assert_int_not_equal(encrypt_buf.len, 0);
    assert_memory_equal(encrypt_buf.p, sample_encrypt_expected, encrypt_buf.len);

    // When: decryption
    err = iot_security_cipher_aes_decrypt(context, &encrypt_buf, &decrypt_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(decrypt_buf.p);
    assert_int_not_equal(decrypt_buf.len, 0);
    assert_int_equal(decrypt_buf.len, plain_buf.len);
    assert_memory_equal(decrypt_buf.p, plain_buf.p, plain_buf.len);
    // Local teardown
    iot_os_free(encrypt_buf.p);
    iot_os_free(decrypt_buf.p);

    // Local teardown
    err = iot_security_cipher_deinit(context);
    assert_int_equal(err, IOT_ERROR_NONE);
}

/*
 * The tests below use a synthetic backend so the guard paths of
 * iot_security_ecdh.c can be reached without a real backend.
 */

typedef struct {
    iot_security_context_t context;
    iot_security_be_context_t be_context;
    iot_security_be_funcs_t fn;
    iot_security_ecdh_params_t ecdh_params;
} tc_ecdh_fake_be_t;

static iot_error_t _tc_ecdh_be_fail(iot_security_context_t *context)
{
    return IOT_ERROR_SECURITY_KEY_INVALID_ID;
}

static void _tc_ecdh_fake_be_init(tc_ecdh_fake_be_t *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->be_context.fn = &fake->fn;
    fake->context.be_context = &fake->be_context;
    fake->context.ecdh_params = &fake->ecdh_params;
}

TEST(TC_iot_security_ecdh_init_be_failure_rollback_neg)
{
    tc_ecdh_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose ecdh_init fails
    _tc_ecdh_fake_be_init(&fake);
    fake.context.ecdh_params = NULL;
    fake.fn.ecdh_init = _tc_ecdh_be_fail;
    // When
    err = iot_security_ecdh_init(&fake.context);
    // Then: the params allocated by init must be rolled back
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
    assert_null(fake.context.ecdh_params);
    assert_int_equal(fake.context.sub_system & IOT_SECURITY_SUB_ECDH, 0);
}

TEST(TC_iot_security_ecdh_deinit_be_failure_neg)
{
    tc_ecdh_fake_be_t fake;
    iot_error_t err;

    // Given: a backend whose ecdh_deinit fails
    _tc_ecdh_fake_be_init(&fake);
    fake.context.sub_system = IOT_SECURITY_SUB_ECDH;
    fake.fn.ecdh_deinit = _tc_ecdh_be_fail;
    // When
    err = iot_security_ecdh_deinit(&fake.context);
    // Then: the params must be kept so the caller can retry
    assert_int_equal(err, IOT_ERROR_SECURITY_KEY_INVALID_ID);
    assert_non_null(fake.context.ecdh_params);
    assert_int_equal(fake.context.sub_system, IOT_SECURITY_SUB_ECDH);
}

TEST(TC_iot_security_ecdh_set_params_be_func_null_neg)
{
    tc_ecdh_fake_be_t fake;
    iot_security_ecdh_params_t ecdh_set_params = {0};
    iot_error_t err;

    // Given: a function table without ecdh_set_params
    _tc_ecdh_fake_be_init(&fake);
    // When
    err = iot_security_ecdh_set_params(&fake.context, &ecdh_set_params);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
}

TEST(TC_iot_security_ecdh_compute_shared_secret_be_func_null_neg)
{
    tc_ecdh_fake_be_t fake;
    iot_security_buffer_t secret_buf = {0};
    iot_error_t err;

    // Given: a function table without ecdh_compute_shared_secret
    _tc_ecdh_fake_be_init(&fake);
    // When
    err = iot_security_ecdh_compute_shared_secret(&fake.context, &secret_buf);
    // Then
    assert_int_equal(err, IOT_ERROR_SECURITY_BE_FUNC_NULL);
    assert_null(secret_buf.p);
}
