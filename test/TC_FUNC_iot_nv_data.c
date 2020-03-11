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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <iot_nv_data.h>
#include <certs/root_ca.h>
#include <string.h>
#include "TC_MOCK_functions.h"

static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
        "\t\t\"privateKey\": \"ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8=\",\n"
        "\t\t\"publicKey\": \"BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk=\",\n"
        "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
        "\t}\n"
        "}"
};

int TC_iot_nv_data_setup(void **state)
{
    iot_error_t err;
#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

int TC_iot_nv_data_teardown(void **state)
{
    iot_error_t err;

    do_not_use_mock_iot_os_malloc_failure();
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_nv_get_root_certificate_success(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    unsigned int root_cert_len = 0;

    // When
    err = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(root_cert, st_root_ca, st_root_ca_len);
    assert_int_equal(root_cert_len, st_root_ca_len);

    // Local teardown
    free(root_cert);
}

void TC_iot_nv_get_root_certificate_null_parameters(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    unsigned int root_cert_len = 0;

    // When: All null parameters
    err = iot_nv_get_root_certificate(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: len is null
    err = iot_nv_get_root_certificate(&root_cert, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_null(root_cert);

    // When: cert is null
    err = iot_nv_get_root_certificate(NULL, &root_cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(root_cert_len, 0);
}

void TC_iot_nv_get_root_certificate_internal_failure(void **state)
{
    iot_error_t err;
    char *root_cert = NULL;
    unsigned int root_cert_len = 0;

    // Given: malloc failed
    set_mock_iot_os_malloc_failure();
    // When
    err = iot_nv_get_root_certificate(&root_cert, &root_cert_len);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    free(root_cert);
}

void TC_iot_nv_get_public_key_success(void **state)
{
    iot_error_t err;
    char *public_key = NULL;
    unsigned int public_key_len = 0;
    const char *sample_public_key = "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk=";

    // When
    err = iot_nv_get_public_key(&public_key, &public_key_len);
    //Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(public_key, sample_public_key, strlen(sample_public_key));
    assert_int_equal(public_key_len, strlen(sample_public_key));

    // Local teardown
    free(public_key);
}

void TC_iot_nv_get_public_key_null_parameters(void **state)
{
    iot_error_t err;
    char *public_key = NULL;
    unsigned int public_key_len = 0;

    // When: All parameters null
    err = iot_nv_get_public_key(NULL, NULL);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: Key is null
    err = iot_nv_get_public_key(NULL, &public_key_len);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(public_key_len, 0);

    // When: Len is null
    err = iot_nv_get_public_key(&public_key, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(public_key_len, 0);
    assert_null(public_key);
}

void TC_iot_nv_get_serial_number_success(void **state)
{
    iot_error_t err;
    char *serial_number = NULL;
    unsigned int serial_number_len = 0;
    const char *sample_serial_number = "STDKtESt7968d226";

    // When
    err = iot_nv_get_serial_number(&serial_number, &serial_number_len);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(serial_number, sample_serial_number, strlen(sample_serial_number));
    assert_int_equal(serial_number_len, strlen(sample_serial_number));

    // Local teardown
    free(serial_number);
}

void TC_iot_nv_get_serial_number_null_parameters(void **state)
{
    iot_error_t err;
    char *serial_number = NULL;
    unsigned int serial_number_len = 0;

    // When: All parameters null
    err = iot_nv_get_serial_number(NULL, NULL);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: Key is null
    err = iot_nv_get_serial_number(NULL, &serial_number_len);
    //Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(serial_number_len, 0);

    // When: Len is null
    err = iot_nv_get_serial_number(&serial_number, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    assert_int_equal(serial_number_len, 0);
    assert_null(serial_number);
}

