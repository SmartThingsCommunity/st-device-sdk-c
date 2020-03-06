/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include <iot_util.h>
#define UNUSED(x) (void**)(x)

void TC_iot_util_get_random_uuid_success(void **state)
{
    iot_error_t err;
    struct iot_uuid test_uuid_1;
    struct iot_uuid test_uuid_2;
    UNUSED(state);

    // Given: memset-ed argument
    memset(&test_uuid_1, '\0', sizeof(struct iot_uuid));
    memset(&test_uuid_2, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_get_random_uuid(&test_uuid_1);
    // Then: should success, shouldn't be memset-ed output
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&test_uuid_1, &test_uuid_2, sizeof(struct iot_uuid));

    // When
    err = iot_util_get_random_uuid(&test_uuid_2);
    // Then: shouldn't be same during multiple calling
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&test_uuid_1, &test_uuid_2, sizeof(struct iot_uuid));
}

void TC_iot_util_get_random_uuid_null_parameter(void **state)
{
    iot_error_t err;
    UNUSED(state);

    //When: null argument
    err = iot_util_get_random_uuid(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_util_convert_str_mac_success(void **state)
{
    iot_error_t err;
    char mac_addr_str[] = "02:43:4e:59:25:7d";
    struct iot_mac mac;
    struct iot_mac mac_empty;
    UNUSED(state);

    // Given
    memset(&mac, '\0', sizeof(struct iot_mac));
    memset(&mac_empty, '\0', sizeof(struct iot_mac));
    assert_memory_equal(&mac, &mac_empty, sizeof(struct iot_mac));
    // When
    err = iot_util_convert_str_mac(mac_addr_str, &mac);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&mac, &mac_empty, sizeof(struct iot_mac));
}

void TC_iot_util_convert_str_mac_invalid_parameters(void **state)
{
    iot_error_t err;
    struct iot_mac mac;
    UNUSED(state);

    // When: null parameters
    err = iot_util_convert_str_mac(NULL, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Given: non mac address string
    char wrong_string[] = "this is wrong";
    // When
    err = iot_util_convert_str_mac(wrong_string, &mac);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_util_convert_str_uuid_success(void **state)
{
    iot_error_t err;
    const char *sample_uuid_str = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    struct iot_uuid sample_uuid = {
            .id[0] = 0xc2,
            .id[1] = 0x36,
            .id[2] = 0xf5,
            .id[3] = 0x27,
            .id[4] = 0x5d,
            .id[5] = 0x8d,
            .id[6] = 0x4d,
            .id[7] = 0x0b,
            .id[8] = 0x86,
            .id[9] = 0xf6,
            .id[10] = 0x0a,
            .id[11] = 0xdd,
            .id[12] = 0x22,
            .id[13] = 0x71,
            .id[14] = 0x7f,
            .id[15] = 0x0e,
    };
    struct iot_uuid uuid;
    UNUSED(state);

    // Given
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(sample_uuid_str, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &sample_uuid, sizeof(struct iot_uuid));
}

void TC_iot_util_convert_str_uuid_null_parameters(void **state)
{
    iot_error_t err;
    const char *sample_uuid_str = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    struct iot_uuid uuid;
    UNUSED(state);

    // When: all parameters null
    err = iot_util_convert_str_uuid(NULL, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: str is null
    err = iot_util_convert_str_uuid(NULL, &uuid);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: uuid is null
    err = iot_util_convert_str_uuid(sample_uuid_str, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}