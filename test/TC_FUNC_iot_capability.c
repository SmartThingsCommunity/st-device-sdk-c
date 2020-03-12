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
#include <st_dev.h>
#include <iot_capability.h>
#include "TC_MOCK_functions.h"

int TC_iot_capability_teardown(void **state)
{
    iot_cap_evt_data_t* event_data = (iot_cap_evt_data_t*) *state;
    IOT_EVENT* event = (IOT_EVENT*) event_data;

    if (event != NULL)
        st_cap_attr_free(event);

    do_not_use_mock_iot_os_malloc_failure();

    return 0;
}

void TC_st_cap_attr_create_int_null_attribute(void **state)
{
    IOT_EVENT* event;

    // When: all null parameters
    event = st_cap_attr_create_int(NULL, 10, NULL);
    // Then: return null
    assert_null(event);

    // When: attribute is null
    event = st_cap_attr_create_int(NULL, 10, "F");
    // Then: return null
    assert_null(event);

    *state = NULL;
}

void TC_st_cap_attr_create_int_null_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is null
    event = st_cap_attr_create_int("temperature", 10, NULL);
    // Then: return proper event data with unit type unused
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_INTEGER);
    assert_string_equal("temperature", event_data->evt_type);

    *state = event_data;
}

void TC_st_cap_attr_create_int_with_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is "F"
    event = st_cap_attr_create_int("temperature", 10, "C");
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal("C", event_data->evt_unit.string);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_INTEGER);
    assert_string_equal("temperature", event_data->evt_type);

    *state = event_data;
}

void TC_st_cap_attr_create_int_internal_failure(void **state)
{
    IOT_EVENT* event;

    // Given: malloc will fail
    set_mock_iot_os_malloc_failure();
    // When
    event = st_cap_attr_create_int("temperature", 10, "C");
    // Then: return null
    assert_null(event);
    *state = NULL;
}

void TC_st_cap_attr_create_number_null_attribute(void **state)
{
    IOT_EVENT* event;

    // When: all null parameters
    event = st_cap_attr_create_number(NULL, 56.7, NULL);
    // Then: return null
    assert_null(event);

    // When: attribute is null
    event = st_cap_attr_create_number(NULL, 56.7, "kg");
    // Then: return null
    assert_null(event);

    *state = NULL;
}

void TC_st_cap_attr_create_number_null_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is null
    event = st_cap_attr_create_number("bodyWeightMeasurement", 56.7, NULL);
    // Then: return proper event data with unit type unused
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_NUMBER);
    assert_float_equal(event_data->evt_value.number, 56.7, 0);
    assert_string_equal(event_data->evt_type, "bodyWeightMeasurement");

    *state = event_data;
}

void TC_st_cap_attr_create_number_with_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is null
    event = st_cap_attr_create_number("bodyWeightMeasurement", 56.7, "kg");
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal(event_data->evt_unit.string, "kg");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_NUMBER);
    assert_float_equal(event_data->evt_value.number, 56.7, 0);
    assert_string_equal(event_data->evt_type, "bodyWeightMeasurement");

    *state = event_data;
}

void TC_st_cap_attr_create_number_internal_failure(void **state)
{
    IOT_EVENT* event;

    // Given: malloc will fail
    set_mock_iot_os_malloc_failure();
    // When
    event = st_cap_attr_create_number("bodyWeightMeasurement", 56.7, "kg");
    // Then: return null
    assert_null(event);

    *state = NULL;
}

void TC_st_cap_attr_create_string_null_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is null
    event = st_cap_attr_create_string("powerSource", "battery", NULL);
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_STRING);
    assert_string_equal(event_data->evt_value.string, "battery");
    assert_string_equal(event_data->evt_type, "powerSource");

    *state = event_data;
}

void TC_st_cap_attr_create_string_with_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;

    // When: unit is null
    event = st_cap_attr_create_string("fakeAttribute", "fakeValue", "fakeUnit");
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal(event_data->evt_unit.string, "fakeUnit");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_STRING);
    assert_string_equal(event_data->evt_value.string, "fakeValue");
    assert_string_equal(event_data->evt_type, "fakeAttribute");

    *state = event_data;
}

void TC_st_cap_attr_create_string_internal_failure(void **state)
{
    IOT_EVENT* event;

    // Given: malloc will fail
    set_mock_iot_os_malloc_failure();
    // When
    event = st_cap_attr_create_string("fakeAttribute", "fakeValue", "fakeUnit");
    // Then: return null
    assert_null(event);
    *state = NULL;
}

void TC_st_cap_attr_create_string_null_parameters(void **state)
{
    IOT_EVENT* event;

    // When: all null parameters
    event = st_cap_attr_create_string(NULL, "fakeValue", NULL);
    // Then: return null
    assert_null(event);

    // When: attribute is null
    event = st_cap_attr_create_string(NULL, "fakeValue", "fakeUnit");
    // Then: return null
    assert_null(event);

    // When: value is null
    event = st_cap_attr_create_string("fakeAttribute", NULL, "fakeUnit");
    // Then: return null
    assert_null(event);

    // When: all null
    event = st_cap_attr_create_string(NULL, NULL, NULL);
    // Then: return null
    assert_null(event);

    *state = NULL;
}