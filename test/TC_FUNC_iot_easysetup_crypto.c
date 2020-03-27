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
#include <string.h>
#include <iot_error.h>
#include <iot_internal.h>
#include <iot_nv_data.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x)   (void**)(x)

#define SAMPLE_PRIVATE_KEY  "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define SAMPLE_PUBLIC_KEY   "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="

static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
        "\t\t\"privateKey\": \""SAMPLE_PRIVATE_KEY"\",\n"
        "\t\t\"publicKey\": \""SAMPLE_PUBLIC_KEY"\",\n"
        "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
        "\t}\n"
        "}"
};

int TC_iot_easysetup_crypto_setup(void **state)
{
    iot_error_t err;
    UNUSED(state);
#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

int TC_iot_easysetup_crypto_teardown(void **state)
{
    iot_error_t err;
    UNUSED(state);

    do_not_use_mock_iot_os_malloc_failure();
    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_es_crypto_load_pk_success(void** state)
{
    iot_error_t err;
    iot_crypto_pk_info_t pk_info;
    UNUSED(state);

    // Given
    memset(&pk_info, '\0', sizeof(iot_crypto_pk_info_t));
    iot_es_crypto_init_pk(&pk_info, IOT_CRYPTO_PK_ED25519);
    // When
    err = iot_es_crypto_load_pk(&pk_info);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_non_null(pk_info.seckey);
    assert_non_null(pk_info.pubkey);
    assert_true(pk_info.seckey_len > 0);
    assert_true(pk_info.pubkey_len > 0);

    // Teardown
    iot_es_crypto_free_pk(&pk_info);
}

void TC_iot_es_crypto_load_pk_invalid_parameters(void **state)
{
    iot_error_t err;
    iot_crypto_pk_info_t *pk_info;
    UNUSED(state);

    // Given: null parameter
    pk_info = NULL;
    // When
    err = iot_es_crypto_load_pk(pk_info);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: unknown type
    pk_info = malloc(sizeof(iot_crypto_pk_info_t));
    assert_non_null(pk_info);
    pk_info->type = 0x77;
    // When
    err = iot_es_crypto_load_pk(pk_info);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_es_crypto_init_pk(void **state)
{
    iot_crypto_pk_info_t pk_info;
    iot_crypto_pk_type_t type;
    UNUSED(state);

    // Given
    pk_info.pubkey_len = 100;
    pk_info.seckey_len = 100;
    type = IOT_CRYPTO_PK_RSA;
    // When
    iot_es_crypto_init_pk(&pk_info, type);
    // Then
    assert_int_equal(pk_info.type, IOT_CRYPTO_PK_RSA);
    assert_int_equal(pk_info.pubkey_len, 0);
    assert_int_equal(pk_info.seckey_len, 0);

    // Given
    pk_info.pubkey_len = 100;
    pk_info.seckey_len = 100;
    type = IOT_CRYPTO_PK_ED25519;
    // When
    iot_es_crypto_init_pk(&pk_info, type);
    // Then
    assert_int_equal(pk_info.type, IOT_CRYPTO_PK_ED25519);
    assert_int_equal(pk_info.pubkey_len, 0);
    assert_int_equal(pk_info.seckey_len, 0);
}