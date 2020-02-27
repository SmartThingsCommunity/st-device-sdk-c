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

void TC_iot_util_get_random_uuid(void **state)
{
    iot_error_t err;
    struct iot_uuid test_uuid_1;
    struct iot_uuid test_uuid_2;

    //When: null argument
    err = iot_util_get_random_uuid(NULL);
    // Then
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

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

void TC_iot_util_convert_str_mac(void **state)
{
    iot_error_t err;
    char mac_addr_str[] = "02:43:4e:59:25:7d";
    struct iot_mac mac;
    struct iot_mac mac_empty;

    // When: null parameters
    err = iot_util_convert_str_mac(NULL, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    // Given
    memset(&mac, '\0', sizeof(struct iot_mac));
    memset(&mac_empty, '\0', sizeof(struct iot_mac));
    assert_memory_equal(&mac, &mac_empty, sizeof(struct iot_mac));
    // When
    err = iot_util_convert_str_mac(mac_addr_str, &mac);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&mac, &mac_empty, sizeof(struct iot_mac));

    // Given
    char wrong_string[] = "this is wrong";
    // When
    err = iot_util_convert_str_mac(wrong_string, &mac);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}