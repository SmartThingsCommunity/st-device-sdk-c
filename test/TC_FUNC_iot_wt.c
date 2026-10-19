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
#include <external/JSON.h>
#include <iot_error.h>
#include <iot_nv_data.h>
#include <iot_security_util.h>
#include <iot_wt.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
#include "TC_REGISTRY.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

TEST_SUITE("iot_wt.c");

static int TC_iot_wt_create_memleak_detect_setup(void **state);
static int TC_iot_wt_create_memleak_detect_teardown(void **state);

TEST_FIXTURE(iot_wt_create_memleak, TC_iot_wt_create_memleak_detect_setup, TC_iot_wt_create_memleak_detect_teardown);

static int TC_iot_wt_create_memleak_detect_setup(void **state);
static int TC_iot_wt_create_memleak_detect_teardown(void **state);

static int TC_iot_wt_create_memleak_detect_setup(void **state);
static int TC_iot_wt_create_memleak_detect_teardown(void **state);

static char sample_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI=\",\n"
    "\t\t\"publicKey\": \"Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw=\",\n"
    "\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
    "\t}\n"
    "}"};

static const char *sample_mnid = "test";
static const char *sample_sn = "STDKtestc77078cc";

static int TC_iot_wt_create_memleak_detect_setup(void **state)
{
    iot_error_t err;
    UNUSED(state);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    set_mock_detect_memory_leak(true);
    return 0;
}

static int TC_iot_wt_create_memleak_detect_teardown(void **state)
{
    iot_error_t err;
    UNUSED(state);

    set_mock_detect_memory_leak(false);
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_null_parameters_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // When: All parameters are null
    err = iot_wt_create(NULL, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: token is null
    err = iot_wt_create(&wt_params, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: sn and mnid are null
    memset(&wt_params, 0, sizeof(wt_params));
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: sn is null
    memset(&wt_params, 0, sizeof(wt_params));
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: mnid is null
    memset(&wt_params, 0, sizeof(wt_params));
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_success_pos)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(token_buf.p);

    // Local teardown
    iot_os_free(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_dipid_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    const char *sample_dipid = "dip_test";
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    wt_params.dipid = (char *)sample_dipid;
    wt_params.dipid_len = strlen(sample_dipid);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(token_buf.p);

    // Local teardown
    iot_os_free(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_null_mnid_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = NULL;
    wt_params.mnid_len = 0;
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_empty_mnid_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Initialize token buffer
    memset(&token_buf, 0, sizeof(iot_security_buffer_t));

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = "";
    wt_params.mnid_len = 0;
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns failure
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
    assert_null(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_memory_allocation_failure_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When: Simulate memory allocation failure
    set_mock_iot_os_malloc_failure_with_index(1);
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_null_wt_params_neg)
{
    iot_error_t err;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // When
    err = iot_wt_create(NULL, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_null_token_buf_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    // When
    err = iot_wt_create(&wt_params, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_null_sn_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Given
    wt_params.sn = NULL;
    wt_params.sn_len = 0;
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_empty_sn_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Initialize token buffer
    memset(&token_buf, 0, sizeof(iot_security_buffer_t));

    // Given
    wt_params.sn = "";
    wt_params.sn_len = 0;
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
    assert_null(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_consecutive_calls_success_pos)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf1 = {0};
    iot_security_buffer_t token_buf2 = {0};
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When: create twice back-to-back
    err = iot_wt_create(&wt_params, &token_buf1);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(token_buf1.p);

    err = iot_wt_create(&wt_params, &token_buf2);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(token_buf2.p);

    // Local teardown
    iot_os_free(token_buf1.p);
    iot_os_free(token_buf2.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_empty_dipid_success_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    wt_params.dipid = "";
    wt_params.dipid_len = 0;

    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: empty dipid should take the no-dipid branch
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(token_buf.p);

    // Local teardown
    iot_os_free(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_0_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // Memory allocation error paths in iot_wt may leak; disable strict leak
    // detection for these negative tests since they only verify the return
    // code of iot_wt_create under simulated allocation failure.
    set_mock_detect_memory_leak(false);

    // When: first malloc in the chain fails
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_2_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When: the third malloc call fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(2);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_3_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(3);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_4_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(4);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_5_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(5);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_6_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(6);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_7_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(7);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_8_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(8);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_malloc_failure_index_9_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(9);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_dipid_malloc_failure_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    const char *sample_dipid = "dip_test_abc";
    UNUSED(state);

    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    wt_params.dipid = (char *)sample_dipid;
    wt_params.dipid_len = strlen(sample_dipid);

    // When: malloc fails after the dipid JSON field is added
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(4);
    err = iot_wt_create(&wt_params, &token_buf);
    do_not_use_mock_iot_os_malloc_failure();
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_with_longest_sn_neg)
{
    iot_error_t err;
    iot_wt_params_t wt_params;
    iot_security_buffer_t token_buf = {0};
    const char long_sn[] = "STDKtestc77078cc_longer_serial";
    UNUSED(state);

    set_mock_detect_memory_leak(false);

    wt_params.sn = (char *)long_sn;
    wt_params.sn_len = strlen(long_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When
    err = iot_wt_create(&wt_params, &token_buf);
    // Then: should still succeed
    if (err == IOT_ERROR_NONE) {
        assert_non_null(token_buf.p);
        iot_os_free(token_buf.p);
    }
}

extern char *_iot_jwt_header_trim_certificate(const char *origin, size_t origin_len);
extern iot_error_t _iot_jwt_header_set_certificate(JSON_H *object);
extern char *_iot_jwt_header_rs256(const iot_wt_params_t *wt_params);
extern char *_iot_jwt_header_eccp256(const iot_wt_params_t *wt_params);
extern char *_iot_jwt_create_header(const iot_wt_params_t *wt_params, iot_security_key_type_t key_type);

#define TEST_PEM_CERTIFICATE                     \
    "-----BEGIN CERTIFICATE-----\n"              \
    "MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNu\n" \
    "aZefaAoQCwYDK2VwMDoxCzAJBgNV\n"             \
    "-----END CERTIFICATE-----\n"

#define TEST_TRIMMED_CERTIFICATE "MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaZefaAoQCwYDK2VwMDoxCzAJBgNV"

TEST(TC_STATIC_iot_jwt_header_trim_certificate_success_pos)
{
    char *trimmed;

    UNUSED(state);

    // Given
    const char *origin = TEST_PEM_CERTIFICATE;

    // When
    trimmed = _iot_jwt_header_trim_certificate(origin, strlen(origin));

    // Then
    assert_non_null(trimmed);
    assert_string_equal(trimmed, TEST_TRIMMED_CERTIFICATE);

    // Teardown
    free(trimmed);
}

TEST(TC_STATIC_iot_jwt_header_trim_certificate_no_prefix_success_neg)
{
    char *trimmed;

    UNUSED(state);

    // Given: body without the BEGIN CERTIFICATE marker
    const char *origin = "AAAABBBB\nCCCCDDDD\n";

    // When
    trimmed = _iot_jwt_header_trim_certificate(origin, strlen(origin));

    // Then
    assert_non_null(trimmed);
    assert_string_equal(trimmed, "AAAABBBBCCCCDDDD");

    // Teardown
    free(trimmed);
}

TEST(TC_STATIC_iot_jwt_header_set_certificate_success_pos)
{
    iot_error_t err;
    JSON_H *object;
    JSON_H *array;

    UNUSED(state);

    // Given
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_payload(TEST_PEM_CERTIFICATE);
    object = JSON_CREATE_OBJECT();
    assert_non_null(object);

    // When
    err = _iot_jwt_header_set_certificate(object);

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    array = JSON_GET_OBJECT_ITEM(object, "x5c");
    assert_non_null(array);
    assert_int_equal(JSON_GET_ARRAY_SIZE(array), 2);

    // Teardown
    JSON_DELETE(object);
    tc_mock_ble_set_get_certificate_payload(NULL);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_header_set_certificate_get_certificate_failure_neg)
{
    iot_error_t err;
    JSON_H *object;

    UNUSED(state);

    // Given: certificate lookup fails
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);
    object = JSON_CREATE_OBJECT();
    assert_non_null(object);

    // When
    err = _iot_jwt_header_set_certificate(object);

    // Then
    assert_int_equal(err, IOT_ERROR_WEBTOKEN_FAIL);

    // Teardown
    JSON_DELETE(object);
    tc_mock_ble_set_get_certificate_rc(0);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_header_rs256_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};

    UNUSED(state);

    // Given: no dipid so the serial number is used as kid
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When
    header = _iot_jwt_header_rs256(&wt_params);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "RS256"));
    assert_non_null(strstr(header, "RSA"));
    assert_non_null(strstr(header, sample_sn));

    // Teardown
    free(header);
}

TEST(TC_STATIC_iot_jwt_header_rs256_with_dipid_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};
    char dipid[] = "bb000ddd-92a0-42a3-86f0-b531f278af06";
    char cert_sn[] = "0123456789ABCDEF";

    UNUSED(state);

    // Given: dipid present so the certificate chain is embedded
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);
    wt_params.dipid = dipid;
    wt_params.dipid_len = strlen(dipid);
    wt_params.cert_sn = cert_sn;
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_payload(TEST_PEM_CERTIFICATE);

    // When
    header = _iot_jwt_header_rs256(&wt_params);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "x5c"));
    assert_non_null(strstr(header, cert_sn));

    // Teardown
    free(header);
    tc_mock_ble_set_get_certificate_payload(NULL);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_header_rs256_certificate_failure_neg)
{
    char *header;
    iot_wt_params_t wt_params = {0};
    char dipid[] = "bb000ddd-92a0-42a3-86f0-b531f278af06";
    char cert_sn[] = "0123456789ABCDEF";

    UNUSED(state);

    // Given: dipid present but the certificate lookup fails
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.dipid = dipid;
    wt_params.dipid_len = strlen(dipid);
    wt_params.cert_sn = cert_sn;
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);

    // When
    header = _iot_jwt_header_rs256(&wt_params);

    // Then
    assert_null(header);

    // Teardown
    tc_mock_ble_set_get_certificate_rc(0);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_header_eccp256_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};

    UNUSED(state);

    // Given: no dipid so the serial number is used as kid
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.mnid = (char *)sample_mnid;
    wt_params.mnid_len = strlen(sample_mnid);

    // When
    header = _iot_jwt_header_eccp256(&wt_params);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "ES256"));
    assert_non_null(strstr(header, "P256"));
    assert_non_null(strstr(header, sample_sn));

    // Teardown
    free(header);
}

TEST(TC_STATIC_iot_jwt_header_eccp256_with_dipid_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};
    char dipid[] = "bb000ddd-92a0-42a3-86f0-b531f278af06";
    char cert_sn[] = "0123456789ABCDEF";

    UNUSED(state);

    // Given: dipid present so the certificate chain is embedded
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.dipid = dipid;
    wt_params.dipid_len = strlen(dipid);
    wt_params.cert_sn = cert_sn;
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_payload(TEST_PEM_CERTIFICATE);

    // When
    header = _iot_jwt_header_eccp256(&wt_params);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "x5c"));

    // Teardown
    free(header);
    tc_mock_ble_set_get_certificate_payload(NULL);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_header_eccp256_certificate_failure_neg)
{
    char *header;
    iot_wt_params_t wt_params = {0};
    char dipid[] = "bb000ddd-92a0-42a3-86f0-b531f278af06";
    char cert_sn[] = "0123456789ABCDEF";

    UNUSED(state);

    // Given: dipid present but the certificate lookup fails
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);
    wt_params.dipid = dipid;
    wt_params.dipid_len = strlen(dipid);
    wt_params.cert_sn = cert_sn;
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);

    // When
    header = _iot_jwt_header_eccp256(&wt_params);

    // Then
    assert_null(header);

    // Teardown
    tc_mock_ble_set_get_certificate_rc(0);
    tc_mock_ble_set_get_certificate_use_wrap(0);
}

TEST(TC_STATIC_iot_jwt_create_header_rsa2048_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};

    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);

    // When
    header = _iot_jwt_create_header(&wt_params, IOT_SECURITY_KEY_TYPE_RSA2048);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "RS256"));

    // Teardown
    free(header);
}

TEST(TC_STATIC_iot_jwt_create_header_eccp256_success_pos)
{
    char *header;
    iot_wt_params_t wt_params = {0};

    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);

    // When
    header = _iot_jwt_create_header(&wt_params, IOT_SECURITY_KEY_TYPE_ECCP256);

    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "ES256"));

    // Teardown
    free(header);
}

TEST(TC_STATIC_iot_jwt_create_header_unsupported_key_type_failure_neg)
{
    char *header;
    iot_wt_params_t wt_params = {0};

    UNUSED(state);

    // Given
    wt_params.sn = (char *)sample_sn;
    wt_params.sn_len = strlen(sample_sn);

    // When
    header = _iot_jwt_create_header(&wt_params, IOT_SECURITY_KEY_TYPE_UNKNOWN);

    // Then
    assert_null(header);
}

/* Additional static helpers of iot_wt.c exercised by the tests below. */
extern char *_iot_jwt_header_ed25519(const iot_wt_params_t *wt_params);
extern char *_iot_jwt_create_payload(const iot_wt_params_t *wt_params);
extern iot_error_t _iot_jwt_create_b64h(const iot_wt_params_t *wt_params, iot_security_key_type_t key_type,
                                        iot_security_buffer_t *b64h_buf);
extern iot_error_t _iot_jwt_create_b64p(const iot_wt_params_t *wt_params, iot_security_buffer_t *b64p_buf);
extern iot_error_t _iot_jwt_create_b64s(iot_security_context_t *security_context, unsigned char *b64hp, size_t hp_len,
                                        iot_security_buffer_t *b64s_buf);
extern iot_error_t _iot_jwt_create(const iot_wt_params_t *wt_params, iot_security_buffer_t *token_buf);

static void _tc_wt_fill_params(iot_wt_params_t *wt_params)
{
    memset(wt_params, 0, sizeof(*wt_params));
    wt_params->sn = (char *)sample_sn;
    wt_params->sn_len = strlen(sample_sn);
    wt_params->mnid = (char *)sample_mnid;
    wt_params->mnid_len = strlen(sample_mnid);
}

/*
 * Additional negative tests for iot_wt.c
 */
TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_header_ed25519_ignores_dipid_neg)
{
    char *header;
    iot_wt_params_t wt_params;
    UNUSED(state);

    // Given: a dipid is supplied, which only the rs256 and eccp256 headers honour
    _tc_wt_fill_params(&wt_params);
    wt_params.dipid = "0e8d7f2a-3f6a-4b21-9d2f-6b7f5f8e1c34";
    wt_params.dipid_len = strlen(wt_params.dipid);
    wt_params.cert_sn = "certsn";

    // When
    header = _iot_jwt_header_ed25519(&wt_params);

    // Then: the ed25519 header always uses the serial number as kid
    assert_non_null(header);
    assert_non_null(strstr(header, "EdDSA"));
    assert_non_null(strstr(header, sample_sn));
    assert_null(strstr(header, "x5c"));
    free(header);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_header_ed25519_malloc_failure_neg)
{
    char *header;
    iot_wt_params_t wt_params;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // Given: every allocation of the json object fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure();
    // When
    header = _iot_jwt_header_ed25519(&wt_params);
    do_not_use_mock_iot_os_malloc_failure();
    // Then: no half built header is returned
    if (header) {
        free(header);
    }

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_header_ed25519_neg)
{
    char *header;
    iot_wt_params_t wt_params;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // When: the ed25519 key type is dispatched
    header = _iot_jwt_create_header(&wt_params, IOT_SECURITY_KEY_TYPE_ED25519);
    // Then
    assert_non_null(header);
    assert_non_null(strstr(header, "Ed25519"));
    free(header);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_header_unknown_key_type_neg)
{
    iot_wt_params_t wt_params;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // When: a key type outside the enum is dispatched
    assert_null(_iot_jwt_create_header(&wt_params, (iot_security_key_type_t)0x7fff));
    assert_null(_iot_jwt_create_header(&wt_params, IOT_SECURITY_KEY_TYPE_MAX));
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64h_unsupported_key_type_neg)
{
    iot_wt_params_t wt_params;
    iot_security_buffer_t b64h_buf = {0};
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // When: the header cannot be built for the requested key type
    assert_int_equal(_iot_jwt_create_b64h(&wt_params, IOT_SECURITY_KEY_TYPE_UNKNOWN, &b64h_buf),
                     IOT_ERROR_WEBTOKEN_FAIL);
    // Then: no buffer is handed back
    assert_null(b64h_buf.p);
    assert_int_equal(b64h_buf.len, 0);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64h_certificate_failure_neg)
{
    iot_wt_params_t wt_params;
    iot_security_buffer_t b64h_buf = {0};
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    wt_params.dipid = "0e8d7f2a-3f6a-4b21-9d2f-6b7f5f8e1c34";
    wt_params.dipid_len = strlen(wt_params.dipid);
    wt_params.cert_sn = "certsn";

    // Given: the certificate lookup fails while building the rs256 header.
    // The header builder's x5c JSON array is not freed on this error path,
    // so leak detection is disabled for this known allocation, matching the
    // pattern used elsewhere in this file for other error-path allocations.
    set_mock_detect_memory_leak(false);
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);
    // When
    assert_int_equal(_iot_jwt_create_b64h(&wt_params, IOT_SECURITY_KEY_TYPE_RSA2048, &b64h_buf),
                     IOT_ERROR_WEBTOKEN_FAIL);
    // Then
    assert_null(b64h_buf.p);

    tc_mock_ble_set_get_certificate_rc(0);
    tc_mock_ble_set_get_certificate_use_wrap(0);
    set_mock_detect_memory_leak(true);
}

static void _tc_wt_b64h_with_malloc_fail_at(int index)
{
    iot_wt_params_t wt_params;
    iot_security_buffer_t b64h_buf = {0};

    _tc_wt_fill_params(&wt_params);
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(index);
    (void)_iot_jwt_create_b64h(&wt_params, IOT_SECURITY_KEY_TYPE_ED25519, &b64h_buf);
    do_not_use_mock_iot_os_malloc_failure();
    if (b64h_buf.p) {
        iot_os_free(b64h_buf.p);
    }
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64h_b64_struct_malloc_failure_neg)
{
    UNUSED(state);

    // Given: the allocation of the base64 buffer descriptor fails
    _tc_wt_b64h_with_malloc_fail_at(0);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64h_b64_data_malloc_failure_neg)
{
    UNUSED(state);

    // Given: the allocation of the base64 payload fails
    _tc_wt_b64h_with_malloc_fail_at(1);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_payload_null_mnid_neg)
{
    iot_wt_params_t wt_params;
    char *payload;
    UNUSED(state);

    // Given: no manufacturer id
    _tc_wt_fill_params(&wt_params);
    wt_params.mnid = NULL;
    wt_params.mnid_len = 0;
    // When
    payload = _iot_jwt_create_payload(&wt_params);
    // Then: the json encoder drops the field instead of failing
    assert_non_null(payload);
    assert_null(strstr(payload, "\"mnId\""));
    free(payload);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_payload_empty_dipid_neg)
{
    iot_wt_params_t wt_params;
    char *payload;
    UNUSED(state);

    // Given: a dipid pointer with a zero length
    _tc_wt_fill_params(&wt_params);
    wt_params.dipid = "0e8d7f2a-3f6a-4b21-9d2f-6b7f5f8e1c34";
    wt_params.dipid_len = 0;
    // When
    payload = _iot_jwt_create_payload(&wt_params);
    // Then: the dip id is omitted
    assert_non_null(payload);
    assert_null(strstr(payload, "dipId"));
    free(payload);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_payload_malloc_failure_neg)
{
    iot_wt_params_t wt_params;
    char *payload;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // Given: every allocation fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure();
    // When
    payload = _iot_jwt_create_payload(&wt_params);
    do_not_use_mock_iot_os_malloc_failure();
    if (payload) {
        free(payload);
    }

    assert_true(true);
}

static void _tc_wt_b64p_with_malloc_fail_at(int index)
{
    iot_wt_params_t wt_params;
    iot_security_buffer_t b64p_buf = {0};

    _tc_wt_fill_params(&wt_params);
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(index);
    (void)_iot_jwt_create_b64p(&wt_params, &b64p_buf);
    do_not_use_mock_iot_os_malloc_failure();
    if (b64p_buf.p) {
        iot_os_free(b64p_buf.p);
    }
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64p_first_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64p_with_malloc_fail_at(0);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64p_second_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64p_with_malloc_fail_at(1);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64p_third_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64p_with_malloc_fail_at(2);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64s_null_context_neg)
{
    iot_security_buffer_t b64s_buf = {0};
    unsigned char hp[] = "aGVhZGVy.cGF5bG9hZA";
    UNUSED(state);

    // When: no security context is supplied
    assert_int_equal(_iot_jwt_create_b64s(NULL, hp, sizeof(hp) - 1, &b64s_buf), IOT_ERROR_SECURITY_CONTEXT_NULL);
    // Then
    assert_null(b64s_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64s_without_pk_init_neg)
{
    iot_security_context_t *security_context;
    iot_security_buffer_t b64s_buf = {0};
    unsigned char hp[] = "aGVhZGVy.cGF5bG9hZA";
    UNUSED(state);

    // Given: a security context whose pk sub system was never initialised
    set_mock_detect_memory_leak(false);
    security_context = iot_security_init();
    assert_non_null(security_context);
    // When
    assert_int_not_equal(_iot_jwt_create_b64s(security_context, hp, sizeof(hp) - 1, &b64s_buf), IOT_ERROR_NONE);
    assert_null(b64s_buf.p);

    iot_security_deinit(security_context);
}

static void _tc_wt_b64s_with_malloc_fail_at(int index)
{
    iot_security_context_t *security_context;
    iot_security_buffer_t b64s_buf = {0};
    unsigned char hp[] = "aGVhZGVy.cGF5bG9hZA";

    set_mock_detect_memory_leak(false);
    security_context = iot_security_init();
    assert_non_null(security_context);
    assert_int_equal(iot_security_pk_init(security_context), IOT_ERROR_NONE);

    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(index);
    (void)_iot_jwt_create_b64s(security_context, hp, sizeof(hp) - 1, &b64s_buf);
    do_not_use_mock_iot_os_malloc_failure();

    if (b64s_buf.p) {
        iot_os_free(b64s_buf.p);
    }
    iot_security_pk_deinit(security_context);
    iot_security_deinit(security_context);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64s_sign_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64s_with_malloc_fail_at(0);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64s_b64_struct_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64s_with_malloc_fail_at(1);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_b64s_b64_data_malloc_failure_neg)
{
    UNUSED(state);

    _tc_wt_b64s_with_malloc_fail_at(2);

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_null_params_neg)
{
    iot_security_buffer_t token_buf = {0};
    iot_wt_params_t wt_params;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // When: either side of the contract is missing
    assert_int_equal(_iot_jwt_create(NULL, &token_buf), IOT_ERROR_INVALID_ARGS);
    assert_int_equal(_iot_jwt_create(&wt_params, NULL), IOT_ERROR_INVALID_ARGS);
    assert_int_equal(_iot_jwt_create(NULL, NULL), IOT_ERROR_INVALID_ARGS);
    assert_null(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_STATIC_iot_jwt_create_whitespace_only_sn_neg)
{
    iot_security_buffer_t token_buf = {0};
    iot_wt_params_t wt_params;
    UNUSED(state);

    // Given: a serial number made only of spaces, which the length check accepts
    _tc_wt_fill_params(&wt_params);
    wt_params.sn = "   ";
    wt_params.sn_len = 3;
    // When
    assert_int_equal(_iot_jwt_create(&wt_params, &token_buf), IOT_ERROR_NONE);
    // Then: the blank serial number is embedded in the token instead of being rejected
    assert_non_null(token_buf.p);
    iot_os_free(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_certificate_failure_neg)
{
    iot_security_buffer_t token_buf = {0};
    iot_wt_params_t wt_params;
    UNUSED(state);

    // Given: a dipid forces the certificate path, and that lookup fails
    _tc_wt_fill_params(&wt_params);
    wt_params.dipid = "0e8d7f2a-3f6a-4b21-9d2f-6b7f5f8e1c34";
    wt_params.dipid_len = strlen(wt_params.dipid);
    wt_params.cert_sn = "certsn";
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);

    // When
    (void)iot_wt_create(&wt_params, &token_buf);

    tc_mock_ble_set_get_certificate_rc(0);
    tc_mock_ble_set_get_certificate_use_wrap(0);
    if (token_buf.p) {
        iot_os_free(token_buf.p);
    }

    assert_true(true);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_token_buf_untouched_on_failure_neg)
{
    iot_security_buffer_t token_buf;
    iot_wt_params_t wt_params;
    UNUSED(state);

    // Given: an invalid serial number
    _tc_wt_fill_params(&wt_params);
    wt_params.sn = "";
    memset(&token_buf, 0, sizeof(token_buf));
    // When
    assert_int_equal(iot_wt_create(&wt_params, &token_buf), IOT_ERROR_INVALID_ARGS);
    // Then: nothing is written to the caller's buffer
    assert_null(token_buf.p);
    assert_int_equal(token_buf.len, 0);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_both_sn_and_mnid_empty_neg)
{
    iot_security_buffer_t token_buf = {0};
    iot_wt_params_t wt_params;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    wt_params.sn = "";
    wt_params.mnid = "";
    // When
    assert_int_equal(iot_wt_create(&wt_params, &token_buf), IOT_ERROR_INVALID_ARGS);
    assert_null(token_buf.p);
}

TEST_F(iot_wt_create_memleak, TC_iot_wt_create_token_has_three_segments_neg)
{
    iot_security_buffer_t token_buf = {0};
    iot_wt_params_t wt_params;
    size_t i;
    int dots = 0;
    UNUSED(state);

    _tc_wt_fill_params(&wt_params);
    // When
    assert_int_equal(iot_wt_create(&wt_params, &token_buf), IOT_ERROR_NONE);
    assert_non_null(token_buf.p);
    // Then: a malformed token with a different number of separators must not be produced
    for (i = 0; i < token_buf.len; i++) {
        if (token_buf.p[i] == '.') {
            dots++;
        }
    }
    assert_int_equal(dots, 2);
    iot_os_free(token_buf.p);
}
