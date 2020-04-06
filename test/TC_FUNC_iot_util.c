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
    char mac_addr_str[] = "a2:b3:fe:c9:8e:7d";
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
    char invalid_mac[11][20] = {
            "a2:b3:fe:c9:8e:d", // short length
            "a2:b3:fe:c9:8e:7d1", // long length
            " a2:b3:fe:c9:8e:7d", // start with space
            "a2:b3:fe:c9:8e:7d ", // end with space
            "a2:b3:fe c9:8e:7d ", // space in the middle
            "a2:b3:fe:c9:8e;7d", // invalid delimiter ';'
            "a2:b3:fg:c9:8e:7d", // non hex char 'g'
            "a2b:3:fe:c9:8e:7d", // 3-1-2-2-2-2
            "a2:b3f:e:c9:8e:7d", // 2-3-1-2-2-2
            "a2:b3:fec:9:8e:7d", // 2-2-3-1-2-2
            "a2:b3:fe:c9:8e7:d", // 2-2-2-2-3-1
    };
    UNUSED(state);

    // When: null parameters
    err = iot_util_convert_str_mac(NULL, NULL);
    // Then: should return error
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

    for (int i = 0; i < 11; i++) {
        // When: invalid mac format
        err = iot_util_convert_str_mac(invalid_mac[i], &mac);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_util_convert_str_uuid_success(void **state)
{
    iot_error_t err;
    const char *sample_uuid_lower = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    const char *sample_uuid_upper = "C236F527-5d8D-4D0B-86F6-0ADD22717F0E";
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

    // Given: lower case uuid string
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(sample_uuid_lower, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &sample_uuid, sizeof(struct iot_uuid));

    // Given: upper case uuid string
    memset(&uuid, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_util_convert_str_uuid(sample_uuid_upper, &uuid);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&uuid, &sample_uuid, sizeof(struct iot_uuid));
}

void TC_iot_util_convert_str_uuid_invalid_parameters(void **state)
{
    iot_error_t err;
    const char *valid_uuid_str = "c236f527-5d8d-4d0b-86f6-0add22717f0e";
    const char invalid_uuid_str[10][39] = {
            "c236f527-5d8d-4d0b-86f6-0add22717f e", // space at middle
            "c236f527_5d8d_4d0b_86f6_0add22717f0e", // invalid delimiter '_'
            "c236f527-5d8d-4d0b-86f6-0add2271", // short length
            "c236f527-5d8d-4d0b-86f6-0add22717f0e8", // long length
            "c236f527-5d8d-4d0b-86f6-0add22717f0z", // invalid character 'z'
            "c236f527-5d8d-4d0b-86f6-0add22717f0e ", // space at last
            " c236f527-5d8d-4d0b-86f6-0add22717f0e", // space at first
            "c236f52-75d8d-4d0b-86f6-0add22717f0e", // 7-5-4-4-12 format
            "c236f527-5d8-d4d0b-86f6-0add22717f0e", // 8-3-5-4-12 format
            "c236f527-5d8d-4d0-b86f6-0add22717f0e", // 8-4-3-5-12 format
    };
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
    err = iot_util_convert_str_uuid(valid_uuid_str, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    for (int i = 0; i < 10; i++) {
        // When: invalid uuid
        err = iot_util_convert_str_uuid(invalid_uuid_str[i], &uuid);
        // Then
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

struct _wifi_channel_map {
    uint8_t ch;
    uint16_t freq;
};

void TC_iot_util_convert_channel_freq(void **state)
{
    UNUSED(state);
    // Given
    struct _wifi_channel_map channel_map[] = {
            {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427},
            {5, 2432}, {6, 2437}, {7, 2442}, {8, 2447},
            {9, 2452}, {10,2457}, {11, 2462}, {12, 2467},
            {13, 2472}, {14, 2484}, {32, 5160}, {34, 5170},
            {36, 5180}, {42, 5210}, {120, 5600}, {165, 5825},
            {174, 0}, {31, 0}, {183, 0}, {196, 0},
            {0xff, 0}, {0, 0}

    };
    // When, Then
    for (int i = 0; i < (sizeof(channel_map) / sizeof(struct _wifi_channel_map)); i++) {
        assert_int_equal(iot_util_convert_channel_freq(channel_map[i].ch), channel_map[i].freq);
    }
}

void TC_iot_util_convert_mac_str_invalid_parameters(void **state)
{
    iot_error_t err;
    struct iot_mac* mac;
    char out_buffer[32];
    UNUSED(state);

    // Given: null mac
    mac = NULL;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, sizeof(out_buffer));
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: null mac, str
    mac = NULL;
    // When
    err = iot_util_convert_mac_str(mac, NULL, 16);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Given: null str
    mac = (struct iot_mac*) calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, NULL, 16);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(mac);

    // Given: short buffer length
    mac = (struct iot_mac*) calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, 5);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    free(mac);
}

void TC_iot_util_convert_mac_str_success(void **state)
{
    iot_error_t err;
    struct iot_mac* mac;
    char out_buffer[32];
    UNUSED(state);

    // Given
    mac = (struct iot_mac*) calloc(1, sizeof(struct iot_mac));
    mac->addr[0] = 0x0a;
    mac->addr[1] = 0x0b;
    mac->addr[2] = 0x11;
    mac->addr[3] = 0x22;
    mac->addr[4] = 0x33;
    mac->addr[5] = 0x44;
    // When
    err = iot_util_convert_mac_str(mac, out_buffer, sizeof(out_buffer));
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("0a:0b:11:22:33:44", out_buffer);
    // Teardown
    free(mac);
}

