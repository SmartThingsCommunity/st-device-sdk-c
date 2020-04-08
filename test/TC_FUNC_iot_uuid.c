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
#include <iot_main.h>
#include <iot_error.h>
#include <iot_bsp_wifi.h>
#include <iot_uuid.h>
#include <iot_util.h>
#include "TC_MOCK_functions.h"

void TC_iot_uuid_from_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char uuid_str[IOT_REG_UUID_STR_LEN + 1];
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
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

void TC_iot_uuid_from_mac_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    char uuid_str[IOT_REG_UUID_STR_LEN + 1];
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

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

void TC_iot_random_uuid_from_mac(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

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

void TC_iot_random_uuid_from_mac_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_uuid uuid;
    unsigned char sample_mac[IOT_WIFI_MAX_BSSID_LEN] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

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