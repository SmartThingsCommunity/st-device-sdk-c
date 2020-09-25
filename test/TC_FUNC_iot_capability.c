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
#include <string.h>
#include <iot_capability.h>
#include <iot_internal.h>
#include <external/JSON.h>
#include <mqtt/iot_mqtt_client.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void*)(x)

int TC_iot_capability_setup(void **state)
{
    UNUSED(*state);

    set_mock_detect_memory_leak(true);

    return 0;
}

int TC_iot_capability_teardown(void **state)
{
    UNUSED(*state);

    do_not_use_mock_iot_os_malloc_failure();
    set_mock_detect_memory_leak(false);

    return 0;
}

void TC_st_cap_create_attr_number_with_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    // When: number with unit
    value.type = IOT_CAP_VAL_TYPE_NUMBER;
    value.number = 56.7;
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "bodyWeightMeasurement", &value, "kg", NULL);
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal(event_data->evt_unit.string, "kg");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_NUMBER);
    assert_float_equal(event_data->evt_value.number, 56.7, 0);
    assert_string_equal(event_data->evt_type, "bodyWeightMeasurement");

    // Teardown
    st_cap_free_attr(event);
}

void TC_st_cap_create_attr_string_with_unit(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    // When: string with unit
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "fakeValue";
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "fakeAttribute", &value, "fakeUnit", NULL);
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t*) event;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal(event_data->evt_unit.string, "fakeUnit");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_STRING);
    assert_string_equal(event_data->evt_value.string, "fakeValue");
    assert_string_equal(event_data->evt_type, "fakeAttribute");

    // Teardown
    st_cap_free_attr(event);
}

void TC_st_cap_create_attr_with_unit_and_data(void **state)
{
    IOT_EVENT* event;
    iot_cap_evt_data_t* event_data = NULL;
    iot_cap_val_t fakeValue;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    fakeValue.type = IOT_CAP_VAL_TYPE_NUMBER;
    fakeValue.number = 4;
    // When: correct parameters are passed.
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "fakeAttribute", &fakeValue, "fakeUnit", "{\"method\":\"fake\"}");
    // Then: return proper event data.
    event_data = (iot_cap_evt_data_t*) event;
    assert_non_null(event_data);
    assert_string_equal(event_data->evt_type, "fakeAttribute");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_NUMBER);
    assert_int_equal(event_data->evt_value.number, 4);
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_string_equal(event_data->evt_unit.string, "fakeUnit");
    assert_string_equal(event_data->evt_value_data, "{\"method\":\"fake\"}");

    // Teardown
    st_cap_free_attr(event);
}

void test_cap_init_callback(IOT_CAP_HANDLE *handle, void *usr_data)
{
    assert_non_null(handle);
    UNUSED(usr_data);
}

void TC_st_cap_handle_init_invalid_argument(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    char *usr_data;
    UNUSED(*state);

    // Given
    usr_data = strdup("UserString");
    // When: IOT_CTX null
    cap_handle = st_cap_handle_init(NULL, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);

    // Given
    usr_data = strdup("UserString");
    // When: IOT_CTX, capability null
    cap_handle = st_cap_handle_init(NULL, "main", NULL, test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);

    // Given
    usr_data = strdup("UserString");
    // When: IOT_CTX, component and capability null
    cap_handle = st_cap_handle_init(NULL, NULL, NULL, test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);

    // Given
    usr_data = strdup("UserString");
    // When: IOT_CTX, component,capability and init_cb null
    cap_handle = st_cap_handle_init(NULL, NULL, NULL, NULL, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);

    // When: all null
    cap_handle = st_cap_handle_init(NULL, NULL, NULL, NULL, NULL);
    // Then
    assert_null(cap_handle);
}

void TC_st_cap_handle_init_internal_failure(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    IOT_CTX *context;
    char *usr_data;
    UNUSED(*state);

    for (int i = 0; i < 2; i++) {
        // Given: valid parameters but n-th malloc failure
        usr_data = strdup("UserString");
        context = (IOT_CTX*) malloc(sizeof(struct iot_context));
        memset(context, 0, sizeof(struct iot_context));
        set_mock_iot_os_malloc_failure_with_index(i);
        // When
        cap_handle = st_cap_handle_init(context, "main", "switch", test_cap_init_callback, usr_data);
        // Then
        assert_null(cap_handle);
        // Teardown
        free(context);
        free(usr_data);
        do_not_use_mock_iot_os_malloc_failure();
    }
}

void TC_st_cap_handle_init_success(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    struct iot_cap_handle *handle;
    struct iot_context *ctx = NULL;
    IOT_CTX *context;
    char *usr_data;
    UNUSED(*state);


    // Given
    usr_data = strdup("UserString");
    context = (IOT_CTX*)malloc(sizeof(struct iot_context));
    memset(context, 0, sizeof(struct iot_context));
    // When
    cap_handle = st_cap_handle_init(context, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle*)cap_handle;
    ctx = (struct iot_context*) context;
    assert_non_null(cap_handle);
    assert_ptr_equal(ctx->cap_handle_list->handle, handle);
    assert_null(ctx->cap_handle_list->next);
    assert_null(handle->cmd_list);
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->capability, "switch");
    assert_ptr_equal(handle->init_cb, test_cap_init_callback);
    assert_ptr_equal(handle->init_usr_data, usr_data);
    assert_ptr_equal(handle->ctx, ctx);
    // Teardown
    if (handle->capability) {
        iot_os_free((void*)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void*)handle->component);
    }
    if (ctx->cap_handle_list) {
        iot_os_free(ctx->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(context);
    free(usr_data);

    // Given: Already existing handle in conext
    usr_data = strdup("UserString");
    context = (IOT_CTX*) malloc(sizeof(struct iot_context));
    memset(context, 0, sizeof(struct iot_context));
    ctx = (struct iot_context*) context;
    ctx->cap_handle_list = malloc(sizeof(iot_cap_handle_list_t));
    ctx->cap_handle_list->next = NULL;
    // When
    cap_handle = st_cap_handle_init(context, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle*)cap_handle;
    assert_non_null(cap_handle);
    assert_non_null(ctx->cap_handle_list->next);
    assert_ptr_equal(ctx->cap_handle_list->next->handle, handle);
    assert_null(ctx->cap_handle_list->next->next);
    assert_null(handle->cmd_list);
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->capability, "switch");
    assert_ptr_equal(handle->init_cb, test_cap_init_callback);
    assert_ptr_equal(handle->init_usr_data, usr_data);
    assert_ptr_equal(handle->ctx, ctx);
    // Teardown
    if (handle->capability) {
        iot_os_free((void*)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void*)handle->component);
    }
    if (ctx->cap_handle_list->next) {
        iot_os_free(ctx->cap_handle_list->next);
    }
    if (ctx->cap_handle_list) {
        free(ctx->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(context);
    free(usr_data);
}

static void test_st_cap_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    assert_non_null(noti_data);
    UNUSED(noti_usr_data);
}

void TC_st_conn_set_noti_cb_null_parameters(void **state)
{
    int ret;
    IOT_CTX* context;
    struct iot_context *internal_context;
    char *user_data;
    UNUSED(*state);

    // When: all parameters null
    ret = st_conn_set_noti_cb(NULL, NULL, NULL);
    // Then
    assert_int_not_equal(ret, 0);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, 0, sizeof(struct iot_context));
    context = (IOT_CTX*) internal_context;
    // When: notification callback null
    ret = st_conn_set_noti_cb(context, NULL, NULL);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(context);

    // When: context null
    ret = st_conn_set_noti_cb(NULL, test_st_cap_noti_cb, NULL);
    // Then
    assert_int_not_equal(ret, 0);

    // Given
    user_data = strdup("fakeData");
    // When: context, notification callback null
    ret = st_conn_set_noti_cb(NULL, NULL, (void*)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(user_data);
}

void TC_st_conn_set_noti_cb_success(void **state)
{
    int ret;
    IOT_CTX* context;
    struct iot_context *internal_context;
    char *user_data;
    UNUSED(*state);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, 0, sizeof(struct iot_context));
    context = (IOT_CTX*) internal_context;
    user_data = strdup("fakeData");
    // When: notification callback null
    ret = st_conn_set_noti_cb(context, test_st_cap_noti_cb, (void*)user_data);
    // Then
    assert_int_equal(ret, 0);
    assert_ptr_equal(internal_context->noti_cb, test_st_cap_noti_cb);
    assert_ptr_equal(internal_context->noti_usr_data, user_data);
    // Teardown
    free(context);
    free(user_data);
}

static void test_cap_cmd_cb(IOT_CAP_HANDLE *cap_handle,
                      iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    assert_non_null(cap_handle);
    UNUSED(cmd_data);
    UNUSED(usr_data);
}

void TC_st_cap_cmd_set_cb_invalid_parameters(void **state)
{
    int ret;
    struct iot_cap_handle *internal_handle;
    IOT_CAP_HANDLE* handle;
    char *user_data;
    UNUSED(state);

    // When: all null
    ret = st_cap_cmd_set_cb(NULL, NULL, NULL, NULL);
    // Then
    assert_int_not_equal(ret, 0);

    // Given
    user_data = strdup("fakeData");
    // When: null handle
    ret = st_cap_cmd_set_cb(NULL, "fakeCommand", test_cap_cmd_cb, (void*)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(user_data);

    // Given
    internal_handle = (struct iot_cap_handle*) malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE*) internal_handle;
    user_data = strdup("fakeData");
    // When: cmd_type null
    ret = st_cap_cmd_set_cb(handle, NULL, test_cap_cmd_cb, (void*)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    assert_null(internal_handle->cmd_list);
    // Teardown
    free(user_data);
    free(internal_handle);

    // Given
    internal_handle = (struct iot_cap_handle*) malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE*) internal_handle;
    user_data = strdup("fakeData");
    // When: cmd_cb null
    ret = st_cap_cmd_set_cb(handle, "fakeCommand", NULL, (void*)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    assert_null(internal_handle->cmd_list);
    // Teardown
    free(user_data);
    free(internal_handle);
}

void TC_st_cap_cmd_set_cb_success(void **state)
{
    int ret;
    struct iot_cap_handle *internal_handle;
    IOT_CAP_HANDLE* handle;
    char *user_data;
    UNUSED(state);

    // Given
    internal_handle = (struct iot_cap_handle*) malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE*) internal_handle;
    user_data = strdup("fakeData");
    // When
    ret = st_cap_cmd_set_cb(handle, "fakeCommand", test_cap_cmd_cb, (void*)user_data);
    // Then
    assert_int_equal(ret, 0);
    assert_non_null(internal_handle->cmd_list);
    assert_non_null(internal_handle->cmd_list->command);
    assert_null(internal_handle->cmd_list->next);
    assert_string_equal(internal_handle->cmd_list->command->cmd_type, "fakeCommand");
    assert_ptr_equal(internal_handle->cmd_list->command->cmd_cb, test_cap_cmd_cb);
    assert_ptr_equal(internal_handle->cmd_list->command->usr_data, user_data);
    // Teardown
    free(user_data);
    iot_os_free((void*)internal_handle->cmd_list->command->cmd_type);
    iot_os_free(internal_handle->cmd_list->command);
    iot_os_free(internal_handle->cmd_list);
    free(internal_handle);
}

static void assert_st_cap_attr_send(char *message, char *expected_component, char *expected_capability,
                                IOT_EVENT *expected_event, int expected_sequence_number)
{
    JSON_H *root;
    JSON_H *event_array;
    iot_cap_evt_data_t* internal_event = (iot_cap_evt_data_t*) expected_event;
    assert_non_null(message);

    root = JSON_PARSE(message);
    assert_non_null(root);

    event_array = JSON_GET_OBJECT_ITEM(root, "deviceEvents");
    assert_non_null(event_array);
    for (int i = 0; i < JSON_GET_ARRAY_SIZE(event_array); i++) {
        JSON_H *event;
        JSON_H *item;

        event = JSON_GET_ARRAY_ITEM(event_array, i);
        assert_non_null(event);

        item = JSON_GET_OBJECT_ITEM(event, "component");
        assert_non_null(item);
        assert_string_equal(JSON_GET_STRING_VALUE(item), expected_component);

        item = JSON_GET_OBJECT_ITEM(event, "capability");
        assert_non_null(item);
        assert_string_equal(JSON_GET_STRING_VALUE(item), expected_capability);

        item = JSON_GET_OBJECT_ITEM(event, "attribute");
        assert_non_null(item);
        assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event->evt_type);

        item = JSON_GET_OBJECT_ITEM(event, "value");
        assert_non_null(item);
        switch (internal_event->evt_value.type)
        {
            case IOT_CAP_VAL_TYPE_INTEGER:
                assert_int_equal(item->valueint, internal_event->evt_value.integer);
                break;
            case IOT_CAP_VAL_TYPE_NUMBER:
                assert_int_equal(item->valuedouble, internal_event->evt_value.number);
                break;
            case IOT_CAP_VAL_TYPE_STRING:
                assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event->evt_value.string);
                break;
            case IOT_CAP_VAL_TYPE_INT_OR_NUM:
            case IOT_CAP_VAL_TYPE_STR_ARRAY:
            case IOT_CAP_VAL_TYPE_JSON_OBJECT:
                // TODO: validate value for these type
                break;
            default:
                assert_false(1);
                break;
        }

        if (internal_event->evt_unit.type == IOT_CAP_UNIT_TYPE_STRING) {
            item = JSON_GET_OBJECT_ITEM(event, "unit");
            assert_non_null(item);
            assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event->evt_unit.string);
        }

        item = JSON_GET_OBJECT_ITEM(event, "providerData");
        assert_non_null(item);
        assert_int_equal(JSON_GET_OBJECT_ITEM(item, "sequenceNumber")->valueint, expected_sequence_number);
    }

    JSON_DELETE(root);
}

static void dummy_mqtt_callback(st_mqtt_event event, void *event_data, void *user_data)
{
    return;
}

void TC_st_cap_send_attr_success(void **state)
{
    int sequence_number;
    IOT_CTX *context;
    IOT_CAP_HANDLE* cap_handle;
    IOT_EVENT* event;
    struct iot_cap_handle *internal_handle;
    struct iot_context *internal_context;
    iot_mqtt_packet_chunk_t *final_chunk;
    MQTTClient *c;
    UNUSED(state);

    // Given
    internal_context = (struct iot_context*) malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX*) internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->iot_events = iot_os_eventgroup_create();
    internal_context->mqtt_event_topic = "TCtest";
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL);
    cap_handle = st_cap_handle_init(context, "main", "testCap", test_cap_init_callback, NULL);
    assert_non_null(cap_handle);
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 10, "testUnit", NULL, event);
    assert_non_null(event);
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number > 0);
    c = internal_context->evt_mqttcli;
    final_chunk = c->write_pending_queue.head;
    /* packet header(2bytes) + MQTTTopiclength(2bytes) + MQTTTopicstring("TCTEST", 6bytes) + packetId(2bytes) = 12 */
    assert_st_cap_attr_send(final_chunk->chunk_data + 12, "main", "testCap", event, sequence_number);
    // Teardown
    st_cap_free_attr(event);
    internal_handle = (struct iot_cap_handle*) cap_handle;
    if (internal_handle->capability) {
        iot_os_free((void*)internal_handle->capability);
    }
    if (internal_handle->component) {
        iot_os_free((void*)internal_handle->component);
    }
    st_mqtt_destroy(internal_context->evt_mqttcli);
    if (internal_context->cap_handle_list->next) {
        iot_os_free(internal_context->cap_handle_list->next);
    }
    if (internal_context->cap_handle_list) {
        iot_os_free(internal_context->cap_handle_list);
    }
    iot_os_free(cap_handle);
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(context);
}

void TC_st_cap_send_attr_invalid_parameter(void **state)
{
    int sequence_number;
    IOT_CAP_HANDLE* cap_handle;
    IOT_EVENT* event;
    struct iot_cap_handle *internal_handle;
    struct iot_context *internal_context;
    UNUSED(state);

    // Given: cap_handle, event null
    cap_handle = NULL;
    event = NULL;
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number < 0);

    // Given: empty cap_handle
    internal_handle = (struct iot_cap_handle*) malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    cap_handle = (IOT_CAP_HANDLE*) internal_handle;
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 100, "testUnit", NULL, event);
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number < 0);
    // Teardown
    st_cap_free_attr(event);
    free(internal_handle);

    // Given: invalid context state
    internal_handle = (struct iot_cap_handle*) malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    internal_handle->component = strdup("main");
    internal_handle->capability = strdup("testCaps");
    cap_handle = (IOT_CAP_HANDLE*) internal_handle;
    internal_context = (struct iot_context*) malloc(sizeof(struct iot_context));
    internal_handle->ctx = internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_REGISTERING;
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 100, "testUnit", NULL, event);
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number < 0);
    // Teardown
    st_cap_free_attr(event);
    free((void*)internal_handle->capability);
    free((void*)internal_handle->component);
    free(internal_handle);
    free(internal_context);
}

bool test_cap_sub_switch_on_called;
static void test_cap_sub_switch_on(IOT_CAP_HANDLE *HANDLE,
                          iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    struct iot_cap_handle *handle = (struct iot_cap_handle *)HANDLE;
    test_cap_sub_switch_on_called = true;

    assert_string_equal(handle->capability, "switch");
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->cmd_list->command->cmd_type, "on");
    assert_int_equal(cmd_data->num_args, 0);
}

void TC_iot_cap_sub_cb_success(void **state)
{
    // Given: typical payload and handle lists
    iot_cap_handle_list_t cap_handle_list;
    char *payload = "{\"commands\":[{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[]}]}";

    cap_handle_list.next = NULL;
    cap_handle_list.handle = malloc(sizeof(struct iot_cap_handle));

    cap_handle_list.handle->capability = "switch";
    cap_handle_list.handle->component = "main";
    cap_handle_list.handle->ctx = NULL;
    cap_handle_list.handle->init_cb = NULL;
    cap_handle_list.handle->init_usr_data = NULL;
    cap_handle_list.handle->cmd_list = malloc(sizeof(struct iot_cap_cmd_set_list));

    cap_handle_list.handle->cmd_list->next = NULL;
    cap_handle_list.handle->cmd_list->command = malloc(sizeof(struct iot_cap_cmd_set));

    cap_handle_list.handle->cmd_list->command->cmd_type = "on";
    cap_handle_list.handle->cmd_list->command->cmd_cb = test_cap_sub_switch_on;
    cap_handle_list.handle->cmd_list->command->usr_data = NULL;
    // When
    iot_cap_sub_cb(&cap_handle_list, payload);
    // Then
    assert_true(test_cap_sub_switch_on_called);
    // Teardown
    free(cap_handle_list.handle->cmd_list->command);
    free(cap_handle_list.handle->cmd_list);
    free(cap_handle_list.handle);
}

void TC_iot_noti_sub_cb_rate_limit_reached_SUCCESS(void **state)
{
    IOT_CTX *context;
    iot_error_t err;
    struct iot_context *internal_context;
    struct iot_command noti_cmd;
    iot_noti_data_t *noti_data;
    char *payload = "{\"target\":\"test-target\",\"count\":51,\"threshold\":50,\"remainingTime\":3990,\"sequenceNumber\":72,\"event\":\"rate.limit.reached\",\"deviceId\":\"test-deviceId\"}";
    UNUSED(state);

    // Given
    internal_context = (struct iot_context*) malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX*) internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    internal_context->iot_events = iot_os_eventgroup_create();
    err = iot_os_timer_init(&internal_context->rate_limit_timeout);
    assert_int_equal(err, IOT_ERROR_NONE);
    // When
    iot_noti_sub_cb(internal_context, payload);
    // Then
    assert_int_equal(iot_os_queue_receive(internal_context->cmd_queue, &noti_cmd, 0), IOT_OS_TRUE);
    noti_data = noti_cmd.param;
    assert_int_equal(noti_data->type, _IOT_NOTI_TYPE_RATE_LIMIT);
    assert_int_equal(noti_data->raw.rate_limit.count, 51);
    assert_int_equal(noti_data->raw.rate_limit.threshold, 50);
    assert_int_equal(noti_data->raw.rate_limit.remainingTime, 3990);
    assert_int_equal(noti_data->raw.rate_limit.sequenceNumber, 72);
    // Teardown
    if (noti_cmd.param)
        free(noti_cmd.param);
    iot_os_timer_destroy(&internal_context->rate_limit_timeout);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_queue_delete(internal_context->cmd_queue);
    free(context);
}

extern iot_error_t _iot_parse_noti_data(void *data, iot_noti_data_t *noti_data);
#define NOTI_TEST_UUID  "123e4567-e89b-12d3-a456-426614174000"
#define NOTI_TEST_TIME  "1591326145"
struct parse_noti_test_data {
    char *payload;
    int expected_result;
    iot_noti_type_t type;
    noti_data_raw_t raw;
};

void TC_iot_parse_noti_data_device_deleted(void** state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct parse_noti_test_data test_data[4] = {
            {"{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"device.deleted\",\"deviceId\":\""NOTI_TEST_UUID"\"}",
                    IOT_ERROR_NONE, _IOT_NOTI_TYPE_DEV_DELETED, 0, },
            {"{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"device.deleting\",\"deviceId\":\""NOTI_TEST_UUID"\"}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_DEV_DELETED, 0, },
            {"{\"target\":\""NOTI_TEST_UUID"\",\"deviceId\":\""NOTI_TEST_UUID"\"}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_DEV_DELETED, 0, },
            {"This is not json data",IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_DEV_DELETED, 0, }
    };

    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When
        err = _iot_parse_noti_data((void*)test_data[i].payload, &notification);
        // Then
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
        }
    }
}

void TC_iot_parse_noti_data_expired_jwt(void** state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct parse_noti_test_data test_data[3] = {
        { "{\"event\":\"expired.jwt\",\"deviceId\":\""NOTI_TEST_UUID"\",\"currentTime\":"NOTI_TEST_TIME"}",
          IOT_ERROR_NONE, _IOT_NOTI_TYPE_JWT_EXPIRED, 0,},
        { "{\"event\":\"expired.JavaWebToken\",\"deviceId\":\""NOTI_TEST_UUID"\",\"currentTime\":"NOTI_TEST_TIME"}",
                IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_JWT_EXPIRED, 0,},
        { "{\"event\":\"expired.jwt\",\"deviceId\":\""NOTI_TEST_UUID"\"}",
                IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_JWT_EXPIRED, 0,},
    };

    UNUSED(state);

    for (int i = 0; i < 3; i++) {
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            expect_string(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, NOTI_TEST_TIME);
        }
        err = _iot_parse_noti_data((void*)test_data[i].payload, &notification);
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
        }
    }
}

void TC_iot_parse_noti_data_quota_reached(void** state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct parse_noti_test_data test_data[4] = {
            { "{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"quota.reached\",\"limit\":500,\"used\":501}",
                    IOT_ERROR_NONE, _IOT_NOTI_TYPE_QUOTA_REACHED, {.quota = {501, 500}}},
            { "{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"quota.done\",\"limit\":500,\"used\":501}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_QUOTA_REACHED, {.quota = {501, 500}}},
            { "{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"quota.reached\",\"used\":501}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_QUOTA_REACHED, {.quota = {501, 0}}},
            { "{\"target\":\""NOTI_TEST_UUID"\",\"event\":\"quota.reached\",\"limit\":500}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_QUOTA_REACHED, {.quota = {0, 500}}},
    };
    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When
        err = _iot_parse_noti_data((void*)test_data[i].payload, &notification);
        // Then
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
            assert_int_equal(notification.raw.quota.limit, test_data[i].raw.quota.limit);
            assert_int_equal(notification.raw.quota.used, test_data[i].raw.quota.used);
        }
    }
}

void TC_iot_parse_noti_data_rate_limit(void** state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct parse_noti_test_data test_data[6] = {
            { "{\"event\":\"rate.limit.reached\",\"deviceId\":\""NOTI_TEST_UUID"\",\"count\":7,"
                        "\"threshold\":30,\"remainingTime\":60,\"eventId\":\"\",\"sequenceNumber\":128}",
                    IOT_ERROR_NONE, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {7, 30, 60, 128}}},
            { "{\"event\":\"rate.limit.reach\",\"deviceId\":\""NOTI_TEST_UUID"\",\"count\":7,"
              "\"threshold\":30,\"remainingTime\":60,\"eventId\":\"\",\"sequenceNumber\":128}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {7, 30, 60, 128}}},
            { "{\"event\":\"rate.limit.reached\",\"deviceId\":\""NOTI_TEST_UUID"\","
              "\"threshold\":30,\"remainingTime\":60,\"eventId\":\"\",\"sequenceNumber\":128}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {0, 30, 60, 128}}},
            { "{\"event\":\"rate.limit.reached\",\"deviceId\":\""NOTI_TEST_UUID"\",\"count\":7,"
              "\"remainingTime\":60,\"eventId\":\"\",\"sequenceNumber\":128}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {7, 0, 60, 128}}},
            { "{\"event\":\"rate.limit.reached\",\"deviceId\":\""NOTI_TEST_UUID"\",\"count\":7,"
              "\"threshold\":30,\"eventId\":\"\",\"sequenceNumber\":128}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {7, 30, 0, 128}}},
            { "{\"event\":\"rate.limit.reached\",\"deviceId\":\""NOTI_TEST_UUID"\",\"count\":7,"
              "\"threshold\":30,\"remainingTime\":60,\"eventId\":\"\"}",
                    IOT_ERROR_BAD_REQ, _IOT_NOTI_TYPE_RATE_LIMIT,
                    {.rate_limit = {7, 30, 60, 0}}},
    };
    UNUSED(state);

    for (int i = 0; i < 6; i++) {
        // When
        err = _iot_parse_noti_data((void*)test_data[i].payload, &notification);
        // Then
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
            assert_int_equal(notification.raw.rate_limit.count, test_data[i].raw.rate_limit.count);
            assert_int_equal(notification.raw.rate_limit.remainingTime, test_data[i].raw.rate_limit.remainingTime);
            assert_int_equal(notification.raw.rate_limit.sequenceNumber, test_data[i].raw.rate_limit.sequenceNumber);
            assert_int_equal(notification.raw.rate_limit.threshold, test_data[i].raw.rate_limit.threshold);
        }
    }
}
