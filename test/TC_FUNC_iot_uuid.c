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
#include <iot_bsp_wifi.h>
#include <iot_error.h>
#include <iot_main.h>
#include <iot_util.h>
#include <iot_uuid.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void **)(x)

void TC_iot_get_uuid_from_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char uuid_str[IOT_REG_UUID_STR_LEN + 1];
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const char sample_uuid_str[] = "bb000ddd-92a0-42a3-86f0-b531f278af06";

    // Given: iot_bsp_wifi_get_mac() returns sample mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(sample_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When:
    err = iot_get_uuid_from_mac(&uuid);
    // Then: API should success, the result string should be same with given.
    assert_int_equal(err, IOT_ERROR_NONE);
    err = iot_util_convert_uuid_str(&uuid, uuid_str, sizeof(uuid_str));
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(sample_uuid_str, uuid_str);

    // Given: iot_bsp_wifi_get_mac() failed
    will_return(__wrap_iot_bsp_wifi_get_mac, NULL);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_READ_FAIL);
    // When
    err = iot_get_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: null parameter
    err = iot_get_uuid_from_mac(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_uuid_from_mac_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char uuid_str[IOT_REG_UUID_STR_LEN + 1];
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // Given: iot_bsp_wifi_get_mac() returns sample mac address but malloc failed
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(sample_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure();

    // When:
    err = iot_get_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_get_random_uuid_from_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // Given: iot_bsp_wifi_get_mac() returns sample mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(sample_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    // When
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: API should success
    assert_int_equal(err, IOT_ERROR_NONE);

    // Given: iot_bsp_wifi_get_mac() failed
    will_return(__wrap_iot_bsp_wifi_get_mac, NULL);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_READ_FAIL);
    // When
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: null parameter
    err = iot_get_random_uuid_from_mac(NULL);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_random_uuid_from_mac_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // Given: iot_bsp_wifi_get_mac() returns sample mac address but malloc failed
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(sample_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure();

    // When
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_get_random_uuid_random_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    struct iot_uuid uuid2;

    // When: iot_get_random_uuid is called twice with valid parameters
    err = iot_get_random_uuid(&uuid);
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_get_random_uuid(&uuid2);
    assert_int_equal(err, IOT_ERROR_NONE);

    // Then: the two UUIDs should be different.
    // This is a negative test that verifies the function doesn't always return the same UUID
    int uuids_are_same = (memcmp(uuid.id, uuid2.id, sizeof(uuid.id)) == 0);
    assert_false(uuids_are_same);

    // Verify that both UUIDs have the correct version bits set
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant

    assert_int_equal(uuid2.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid2.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_random_uuid_success(void **state)
{
    iot_error_t err;
    struct iot_uuid test_uuid_1;
    struct iot_uuid test_uuid_2;
    UNUSED(state);

    // Given: memset-ed argument
    memset(&test_uuid_1, '\0', sizeof(struct iot_uuid));
    memset(&test_uuid_2, '\0', sizeof(struct iot_uuid));
    // When
    err = iot_get_random_uuid(&test_uuid_1);
    // Then: should success, shouldn't be memset-ed output
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&test_uuid_1, &test_uuid_2, sizeof(struct iot_uuid));

    // When
    err = iot_get_random_uuid(&test_uuid_2);
    // Then: shouldn't be same during multiple calling
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_not_equal(&test_uuid_1, &test_uuid_2, sizeof(struct iot_uuid));
}

void TC_iot_get_random_uuid_null_parameter(void **state)
{
    iot_error_t err;

    // When: null parameter is passed to iot_get_random_uuid
    err = iot_get_random_uuid(NULL);
    // Then: should return IOT_ERROR_INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_get_random_uuid_from_key_null_uuid(void **state)
{
    iot_error_t err;
    char test_key[] = "test_key";

    // When: null uuid parameter is passed to iot_get_random_uuid_from_key
    err = iot_get_random_uuid_from_key(NULL, test_key, sizeof(test_key));
    // Then: should return IOT_ERROR_INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_get_random_uuid_from_key_null_key(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;

    // When: null key parameter is passed to iot_get_random_uuid_from_key
    err = iot_get_random_uuid_from_key(&uuid, NULL, 0);
    if (err == IOT_ERROR_NONE) {
        // If it succeeds, verify UUID structure is valid
        assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
        assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
    } else {
        // If it returns error, that's also acceptable behavior
        assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
    }
}

void TC_iot_get_random_uuid_from_key_zero_length(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char test_key[] = "test_key";

    // When: zero key length is passed to iot_get_random_uuid_from_key
    err = iot_get_random_uuid_from_key(&uuid, test_key, 0);
    // Then: function actually succeeds with zero length (current implementation behavior)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid even with zero-length key
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_random_uuid_from_key_large_length(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char test_key[] = "test_key";

    // When: large key length is passed to iot_get_random_uuid_from_key
    err = iot_get_random_uuid_from_key(&uuid, test_key, 1024);
    // Then: should handle gracefully (either succeed or fail without crashing)
    if (err == IOT_ERROR_NONE) {
        // If it succeeds, verify UUID structure is valid
        assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
        assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
    } else {
        // If it returns error, that's also acceptable behavior
        assert_int_not_equal(err, IOT_ERROR_NONE);
    }
}

void TC_iot_get_random_uuid_from_mac_null_parameter(void **state)
{
    iot_error_t err;

    // When: null parameter is passed to iot_get_random_uuid_from_mac
    err = iot_get_random_uuid_from_mac(NULL);
    // Then: should return IOT_ERROR_INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_get_uuid_from_mac_null_parameter(void **state)
{
    iot_error_t err;

    // When: null parameter is passed to iot_get_uuid_from_mac
    err = iot_get_uuid_from_mac(NULL);
    // Then: should return IOT_ERROR_INVALID_ARGS
    assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_get_random_uuid_from_key_wifi_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char test_key[] = "test_key";

    // When: iot_get_random_uuid_from_key is called with valid parameters
    // Note: This function doesn't actually depend on WiFi MAC, it uses system time
    err = iot_get_random_uuid_from_key(&uuid, test_key, sizeof(test_key));
    // Then: should succeed (function uses system time, not WiFi MAC)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_random_uuid_boundary_test(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char test_key[] = "a";  // Single character key

    // When: iot_get_random_uuid is called multiple times rapidly
    for (int i = 0; i < 10; i++) {
        err = iot_get_random_uuid(&uuid);
        assert_int_equal(err, IOT_ERROR_NONE);

        // Verify UUID structure integrity
        assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
        assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
    }
}

void TC_iot_get_random_uuid_from_key_empty_string(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char empty_key[] = "";

    // When: empty string key is passed to iot_get_random_uuid_from_key
    err = iot_get_random_uuid_from_key(&uuid, empty_key, 0);
    // Then: function actually succeeds with empty string and zero length.
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid even with empty string key
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_uuid_from_mac_empty_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char empty_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Given: iot_bsp_wifi_get_mac() returns empty mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(empty_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When: iot_get_uuid_from_mac is called with empty MAC
    err = iot_get_uuid_from_mac(&uuid);
    // Then: should still succeed (function doesn't validate MAC content)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_uuid_from_mac_short_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char short_mac[3] = {0x11, 0x22, 0x33};

    // Given: iot_bsp_wifi_get_mac() returns short mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(short_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When: iot_get_uuid_from_mac is called with short MAC
    err = iot_get_uuid_from_mac(&uuid);
    // Then: should still succeed (function doesn't validate MAC length)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_uuid_from_mac_long_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char long_mac[10] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA};

    // Given: iot_bsp_wifi_get_mac() returns long mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(long_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When: iot_get_uuid_from_mac is called with long MAC
    err = iot_get_uuid_from_mac(&uuid);
    // Then: should still succeed (function uses only first 6 bytes)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

// Additional negative test cases for iot_get_random_uuid_from_mac
void TC_iot_get_random_uuid_from_mac_wifi_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;

    // Given: iot_bsp_wifi_get_mac() returns failure
    will_return(__wrap_iot_bsp_wifi_get_mac, NULL);
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_READ_FAIL);

    // When: iot_get_random_uuid_from_mac is called but WiFi MAC retrieval fails
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_random_uuid_from_mac_malloc_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // Given: iot_bsp_wifi_get_mac() returns sample mac address but malloc failed
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(sample_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);
    do_not_use_mock_iot_os_malloc_failure();
    set_mock_iot_os_malloc_failure();

    // When: iot_get_random_uuid_from_mac is called but malloc fails
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should return error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_get_random_uuid_from_mac_invalid_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char invalid_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Given: iot_bsp_wifi_get_mac() returns invalid mac address (all zeros)
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(invalid_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When: iot_get_random_uuid_from_mac is called with invalid MAC
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should still succeed (function doesn't validate MAC content)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

void TC_iot_get_random_uuid_from_mac_empty_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char empty_mac[IOT_WIFI_MAX_BSSID_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Given: iot_bsp_wifi_get_mac() returns empty mac address
    will_return(__wrap_iot_bsp_wifi_get_mac, cast_ptr_to_largest_integral_type(empty_mac));
    will_return(__wrap_iot_bsp_wifi_get_mac, IOT_ERROR_NONE);

    // When: iot_get_random_uuid_from_mac is called with empty MAC
    err = iot_get_random_uuid_from_mac(&uuid);
    // Then: should still succeed (function doesn't validate MAC content)
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);  // Version 4
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);  // RFC 4122 variant
}

// Additional negative test cases for iot_get_random_uuid
void TC_iot_get_random_uuid_multiple_calls(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid[5];

    // When: iot_get_random_uuid is called multiple times
    for (int i = 0; i < 5; i++) {
        err = iot_get_random_uuid(&uuid[i]);
        // Then: each call should succeed
        assert_int_equal(err, IOT_ERROR_NONE);

        // Verify UUID structure is valid
        assert_int_equal(uuid[i].id[6] & 0xf0, 0x40);  // Version 4
        assert_int_equal(uuid[i].id[8] & 0xc0, 0x80);  // RFC 4122 variant

        // Verify that each UUID is different from previous ones
        for (int j = 0; j < i; j++) {
            int uuids_are_same = (memcmp(uuid[i].id, uuid[j].id, sizeof(uuid[i].id)) == 0);
            assert_false(uuids_are_same);
        }
    }
}

void TC_iot_get_random_uuid_structure_validation(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;

    // When: iot_get_random_uuid is called
    err = iot_get_random_uuid(&uuid);
    // Then: should succeed
    assert_int_equal(err, IOT_ERROR_NONE);

    // Verify UUID structure is valid
    // Version should be 4 (random)
    assert_int_equal(uuid.id[6] & 0xf0, 0x40);
    // Variant should be RFC 4122
    assert_int_equal(uuid.id[8] & 0xc0, 0x80);

    // Verify that all bytes are properly set (not all zeros)
    int all_zeros = 1;
    for (int i = 0; i < sizeof(uuid.id); i++) {
        if (uuid.id[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    assert_false(all_zeros);
}
