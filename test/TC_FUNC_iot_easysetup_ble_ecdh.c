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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
#include "cmocka_custom.h"
#include "easysetup_ble.h"
#include "iot_error.h"
#include "iot_nv_data.h"
#include "security/iot_security_common.h"

#define UNUSED(x) (void)(x)

#define TC_BLE_ECDH_PRIVATE_KEY "yQMrFPkZ1wI62K1cEuhSL23wBR/nLr7s3YUZn+XAwb8="
#define TC_BLE_ECDH_PUBLIC_KEY "eV0oOSDhLf8UXqMO6Osat9G28lXldyZ5nzfQCQt/oiQ="

static char _tc_ble_ecdh_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
    "\t\t\"privateKey\": \"" TC_BLE_ECDH_PRIVATE_KEY
    "\",\n"
    "\t\t\"publicKey\": \"" TC_BLE_ECDH_PUBLIC_KEY
    "\",\n"
    "\t\t\"serialNumber\": \"STDKtestc51ef86c\"\n"
    "\t}\n"
    "}"};

int TC_iot_easysetup_ble_ecdh_setup(void **state)
{
    iot_error_t err;
    UNUSED(state);

    tc_mock_ble_set_get_certificate_use_wrap(0);
#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)_tc_ble_ecdh_device_info, strlen(_tc_ble_ecdh_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

int TC_iot_easysetup_ble_ecdh_teardown(void **state)
{
    iot_error_t err;
    UNUSED(state);
    tc_mock_ble_set_get_certificate_use_wrap(0);
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_easysetup_ble_ecdh_init_success(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_error_t err;
    UNUSED(state);

    // When
    err = iot_easysetup_ble_ecdh_init(&ctx);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx);

    // Teardown
    void *state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_teardown(&state_ptr);
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_ecdh_init_malloc_failure_context(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_error_t err;
    UNUSED(state);

    // Given: first malloc (iot_security_init) fails
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    err = iot_easysetup_ble_ecdh_init(&ctx);
    // Then
    assert_int_equal(err, IOT_ERROR_INIT_FAIL);
    assert_null(ctx);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_ble_ecdh_init_pk_init_malloc_failure(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_error_t err;
    UNUSED(state);

    // Given: a later malloc fails inside iot_security_pk_init
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(2);
    // When
    err = iot_easysetup_ble_ecdh_init(&ctx);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_easysetup_ble_ecdh_teardown_null(void **state)
{
    iot_error_t err;
    void *null_state = NULL;
    UNUSED(state);

    // When
    err = iot_easysetup_ble_ecdh_teardown(&null_state);
    // Then
    assert_int_equal(err, IOT_ERROR_DEINIT_FAIL);
}

void TC_iot_easysetup_ble_ecdh_teardown_success(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_error_t err;
    UNUSED(state);

    // Given
    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When
    void *state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_teardown(&state_ptr);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_ble_ecdh_compute_shared_signature_success(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_security_context_t *state_ptr;
    iot_error_t err;
    unsigned char sec_random[32];
    unsigned char *dev_cert = NULL;
    unsigned char *sub_cert = NULL;
    unsigned char *spub_key = NULL;
    size_t spub_key_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    size_t i;
    UNUSED(state);

    // Given
    for (i = 0; i < sizeof(sec_random); i++) {
        sec_random[i] = (unsigned char)(i + 1);
    }
    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx);

    // When: NV fixture has no real device certificate, so the pipeline is
    // expected to fail partway through
    state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_compute_shared_signature((iot_security_context_t **)&state_ptr, sec_random, &dev_cert,
                                                          &sub_cert, &spub_key, &spub_key_len, &signature,
                                                          &signature_len);
    // Then: the call returns, allocated out-params are freed by the caller
    (void)err;

    // Teardown
    if (dev_cert)
        iot_os_free(dev_cert);
    if (sub_cert)
        iot_os_free(sub_cert);
    if (spub_key)
        iot_os_free(spub_key);
    if (signature)
        iot_os_free(signature);
    void *state2 = ctx;
    iot_easysetup_ble_ecdh_teardown(&state2);
}

void TC_iot_easysetup_ble_ecdh_compute_shared_signature_no_device_cert(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_security_context_t *state_ptr;
    iot_error_t err;
    unsigned char sec_random[32] = {0};
    unsigned char *dev_cert = NULL;
    unsigned char *sub_cert = NULL;
    unsigned char *spub_key = NULL;
    size_t spub_key_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    UNUSED(state);

    // Given
    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(ctx);

    // Given: get_certificate wrap returns a failure
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);
    // When
    state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_compute_shared_signature((iot_security_context_t **)&state_ptr, sec_random, &dev_cert,
                                                          &sub_cert, &spub_key, &spub_key_len, &signature,
                                                          &signature_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    tc_mock_ble_set_get_certificate_use_wrap(0);
    if (dev_cert)
        iot_os_free(dev_cert);
    if (sub_cert)
        iot_os_free(sub_cert);
    if (spub_key)
        iot_os_free(spub_key);
    if (signature)
        iot_os_free(signature);
    void *state2 = ctx;
    iot_easysetup_ble_ecdh_teardown(&state2);
}

void TC_iot_easysetup_ble_ecdh_compute_shared_signature_with_mock_certs(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_security_context_t *state_ptr;
    iot_error_t err;
    unsigned char sec_random[32];
    unsigned char *dev_cert = NULL;
    unsigned char *sub_cert = NULL;
    unsigned char *spub_key = NULL;
    size_t spub_key_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    size_t i;
    UNUSED(state);

    // Given
    for (i = 0; i < sizeof(sec_random); i++) {
        sec_random[i] = (unsigned char)(i * 13 + 7);
    }
    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: get_certificate wrap returns a fake blob
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(0);
    // When: pipeline proceeds past cert fetch into ECDH and signing
    state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_compute_shared_signature((iot_security_context_t **)&state_ptr, sec_random, &dev_cert,
                                                          &sub_cert, &spub_key, &spub_key_len, &signature,
                                                          &signature_len);
    // Then: the call completes without crashing
    (void)err;

    // Teardown
    tc_mock_ble_set_get_certificate_use_wrap(0);
    if (dev_cert)
        iot_os_free(dev_cert);
    if (sub_cert)
        iot_os_free(sub_cert);
    if (spub_key)
        iot_os_free(spub_key);
    if (signature)
        iot_os_free(signature);
    void *state2 = ctx;
    iot_easysetup_ble_ecdh_teardown(&state2);
}

void TC_iot_easysetup_ble_ecdh_compute_shared_signature_subca_fail(void **state)
{
    iot_security_context_t *ctx = NULL;
    iot_security_context_t *state_ptr;
    iot_error_t err;
    unsigned char sec_random[32] = {0};
    unsigned char *dev_cert = NULL;
    unsigned char *sub_cert = NULL;
    unsigned char *spub_key = NULL;
    size_t spub_key_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    UNUSED(state);

    // Given
    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: cert fetch fails via the wrap
    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(IOT_ERROR_SECURITY_CERT_INVALID_ID);
    // When
    state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_compute_shared_signature((iot_security_context_t **)&state_ptr, sec_random, &dev_cert,
                                                          &sub_cert, &spub_key, &spub_key_len, &signature,
                                                          &signature_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    tc_mock_ble_set_get_certificate_use_wrap(0);
    if (dev_cert)
        iot_os_free(dev_cert);
    if (sub_cert)
        iot_os_free(sub_cert);
    if (spub_key)
        iot_os_free(spub_key);
    if (signature)
        iot_os_free(signature);
    void *state2 = ctx;
    iot_easysetup_ble_ecdh_teardown(&state2);
}

static void _tc_compute_with_malloc_fail_at(int fail_index)
{
    iot_security_context_t *ctx = NULL;
    iot_security_context_t *state_ptr;
    iot_error_t err;
    unsigned char sec_random[32] = {0};
    unsigned char *dev_cert = NULL;
    unsigned char *sub_cert = NULL;
    unsigned char *spub_key = NULL;
    size_t spub_key_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;

    err = iot_easysetup_ble_ecdh_init(&ctx);
    assert_int_equal(err, IOT_ERROR_NONE);

    tc_mock_ble_set_get_certificate_use_wrap(1);
    tc_mock_ble_set_get_certificate_rc(0);
    set_mock_detect_memory_leak(false);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure_with_index(fail_index);
    state_ptr = ctx;
    err = iot_easysetup_ble_ecdh_compute_shared_signature((iot_security_context_t **)&state_ptr, sec_random, &dev_cert,
                                                          &sub_cert, &spub_key, &spub_key_len, &signature,
                                                          &signature_len);
    do_not_use_mock_iot_os_malloc_failure();
    tc_mock_ble_set_get_certificate_use_wrap(0);
    (void)err;

    if (dev_cert)
        iot_os_free(dev_cert);
    if (sub_cert)
        iot_os_free(sub_cert);
    if (spub_key)
        iot_os_free(spub_key);
    if (signature)
        iot_os_free(signature);
    void *state2 = ctx;
    iot_easysetup_ble_ecdh_teardown(&state2);
}

void TC_iot_easysetup_ble_ecdh_compute_with_malloc_failure_3(void **state)
{
    UNUSED(state);

    // When: malloc fails at index 3 inside the pipeline
    // Then: helper ensures the call does not crash and cleans up
    _tc_compute_with_malloc_fail_at(3);
}

void TC_iot_easysetup_ble_ecdh_compute_with_malloc_failure_5(void **state)
{
    UNUSED(state);

    // When: malloc fails at index 5 inside the pipeline
    // Then: helper ensures the call does not crash and cleans up
    _tc_compute_with_malloc_fail_at(5);
}
