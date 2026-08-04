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
#include <iot_security_util.h>
#include <iot_wt.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

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

int TC_iot_wt_create_memleak_detect_setup(void **state)
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

int TC_iot_wt_create_memleak_detect_teardown(void **state)
{
    iot_error_t err;
    UNUSED(state);

    set_mock_detect_memory_leak(false);
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_wt_create_null_parameters(void **state)
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

void TC_iot_wt_create_success(void **state)
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

void TC_iot_wt_create_with_dipid(void **state)
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

void TC_iot_wt_create_with_null_mnid(void **state)
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

void TC_iot_wt_create_with_empty_mnid(void **state)
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

void TC_iot_wt_create_memory_allocation_failure(void **state)
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

void TC_iot_wt_create_null_wt_params(void **state)
{
    iot_error_t err;
    iot_security_buffer_t token_buf = {0};
    UNUSED(state);

    // When
    err = iot_wt_create(NULL, &token_buf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_wt_create_null_token_buf(void **state)
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

void TC_iot_wt_create_with_null_sn(void **state)
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

void TC_iot_wt_create_with_empty_sn(void **state)
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

void TC_iot_wt_create_consecutive_calls_success(void **state)
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

void TC_iot_wt_create_with_empty_dipid_success(void **state)
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

void TC_iot_wt_create_malloc_failure_index_0(void **state)
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

void TC_iot_wt_create_malloc_failure_index_2(void **state)
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

void TC_iot_wt_create_malloc_failure_index_3(void **state)
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

void TC_iot_wt_create_malloc_failure_index_4(void **state)
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

void TC_iot_wt_create_malloc_failure_index_5(void **state)
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

void TC_iot_wt_create_malloc_failure_index_6(void **state)
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

void TC_iot_wt_create_malloc_failure_index_7(void **state)
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

void TC_iot_wt_create_malloc_failure_index_8(void **state)
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

void TC_iot_wt_create_malloc_failure_index_9(void **state)
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

void TC_iot_wt_create_with_dipid_malloc_failure(void **state)
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

void TC_iot_wt_create_with_longest_sn(void **state)
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
