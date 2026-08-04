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

#include <external/JSON.h>
#include <iot_capability.h>
#include <iot_internal.h>
#include <iot_mqtt_client.h>
#include <st_dev.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "cmocka_custom.h"

#define UNUSED(x) (void *)(x)
#define NUM_OF_IOT_EVENTS 6

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
    IOT_EVENT *event;
    iot_cap_evt_data_t *event_data = NULL;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    // When: number with unit
    value.type = IOT_CAP_VAL_TYPE_NUMBER;
    value.number = 56.7;
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "bodyWeightMeasurement", &value, "kg", NULL);
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t *)event;
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
    IOT_EVENT *event;
    iot_cap_evt_data_t *event_data = NULL;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    // When: string with unit
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "fakeValue";
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "fakeAttribute", &value, "fakeUnit", NULL);
    // Then: return proper event data with unit type string
    event_data = (iot_cap_evt_data_t *)event;
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
    IOT_EVENT *event;
    iot_cap_evt_data_t *event_data = NULL;
    iot_cap_val_t fakeValue;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    fakeValue.type = IOT_CAP_VAL_TYPE_NUMBER;
    fakeValue.number = 4;
    // When: correct parameters are passed.
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "fakeAttribute", &fakeValue, "fakeUnit",
                               "{\"method\":\"fake\"}");
    // Then: return proper event data.
    event_data = (iot_cap_evt_data_t *)event;
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
        context = (IOT_CTX *)malloc(sizeof(struct iot_context));
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
    context = (IOT_CTX *)malloc(sizeof(struct iot_context));
    memset(context, 0, sizeof(struct iot_context));
    // When
    cap_handle = st_cap_handle_init(context, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle *)cap_handle;
    ctx = (struct iot_context *)context;
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
        iot_os_free((void *)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void *)handle->component);
    }
    if (ctx->cap_handle_list) {
        iot_os_free(ctx->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(context);
    free(usr_data);

    // Given: Already existing handle in conext
    usr_data = strdup("UserString");
    context = (IOT_CTX *)malloc(sizeof(struct iot_context));
    memset(context, 0, sizeof(struct iot_context));
    ctx = (struct iot_context *)context;
    ctx->cap_handle_list = malloc(sizeof(iot_cap_handle_list_t));
    ctx->cap_handle_list->next = NULL;
    // When
    cap_handle = st_cap_handle_init(context, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle *)cap_handle;
    assert_non_null(cap_handle);
    assert_non_null(ctx->cap_handle_list->next);
    assert_ptr_equal(ctx->cap_handle_list->handle, handle);
    assert_null(ctx->cap_handle_list->next->next);
    assert_null(handle->cmd_list);
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->capability, "switch");
    assert_ptr_equal(handle->init_cb, test_cap_init_callback);
    assert_ptr_equal(handle->init_usr_data, usr_data);
    assert_ptr_equal(handle->ctx, ctx);
    // Teardown
    if (handle->capability) {
        iot_os_free((void *)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void *)handle->component);
    }
    if (ctx->cap_handle_list->next) {
        free(ctx->cap_handle_list->next);
    }
    if (ctx->cap_handle_list) {
        iot_os_free(ctx->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(context);
    free(usr_data);
}

bool test_st_cap_noti_cb_called;
static void test_st_cap_noti_cb(iot_noti_data_t *noti_data, void *noti_usr_data)
{
    assert_non_null(noti_data);
    UNUSED(noti_usr_data);
    test_st_cap_noti_cb_called = true;
}

void TC_st_conn_set_noti_cb_null_parameters(void **state)
{
    int ret;
    IOT_CTX *context;
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
    context = (IOT_CTX *)internal_context;
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
    ret = st_conn_set_noti_cb(NULL, NULL, (void *)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(user_data);
}

void TC_st_conn_set_noti_cb_success(void **state)
{
    int ret;
    IOT_CTX *context;
    struct iot_context *internal_context;
    char *user_data;
    UNUSED(*state);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(internal_context, 0, sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    user_data = strdup("fakeData");
    // When: notification callback null
    ret = st_conn_set_noti_cb(context, test_st_cap_noti_cb, (void *)user_data);
    // Then
    assert_int_equal(ret, 0);
    assert_ptr_equal(internal_context->noti_cb, test_st_cap_noti_cb);
    assert_ptr_equal(internal_context->noti_usr_data, user_data);
    // Teardown
    free(context);
    free(user_data);
}

static void test_cap_cmd_cb(IOT_CAP_HANDLE *cap_handle, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    assert_non_null(cap_handle);
    UNUSED(cmd_data);
    UNUSED(usr_data);
}

void TC_st_cap_cmd_set_cb_invalid_parameters(void **state)
{
    int ret;
    struct iot_cap_handle *internal_handle;
    IOT_CAP_HANDLE *handle;
    char *user_data;
    UNUSED(state);

    // When: all null
    ret = st_cap_cmd_set_cb(NULL, NULL, NULL, NULL);
    // Then
    assert_int_not_equal(ret, 0);

    // Given
    user_data = strdup("fakeData");
    // When: null handle
    ret = st_cap_cmd_set_cb(NULL, "fakeCommand", test_cap_cmd_cb, (void *)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(user_data);

    // Given
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE *)internal_handle;
    user_data = strdup("fakeData");
    // When: cmd_type null
    ret = st_cap_cmd_set_cb(handle, NULL, test_cap_cmd_cb, (void *)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    assert_null(internal_handle->cmd_list);
    // Teardown
    free(user_data);
    free(internal_handle);

    // Given
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE *)internal_handle;
    user_data = strdup("fakeData");
    // When: cmd_cb null
    ret = st_cap_cmd_set_cb(handle, "fakeCommand", NULL, (void *)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    assert_null(internal_handle->cmd_list);
    // Teardown
    free(user_data);
    free(internal_handle);

    // Given
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE *)internal_handle;
    user_data = strdup("fakeData");
    internal_handle->cmd_list = malloc(sizeof(struct iot_cap_cmd_set_list));
    internal_handle->cmd_list->next = NULL;
    internal_handle->cmd_list->command = malloc(sizeof(struct iot_cap_cmd_set));

    internal_handle->cmd_list->command->cmd_type = "fakeCommand";

    // When: cmd_cb null
    ret = st_cap_cmd_set_cb(handle, "fakeCommand", NULL, (void *)user_data);
    // Then
    assert_int_not_equal(ret, 0);
    // Teardown
    free(user_data);
    free(internal_handle->cmd_list->command);
    free(internal_handle->cmd_list);
    free(internal_handle);
}

void TC_st_cap_cmd_set_cb_internal_failure(void **state)
{
    int ret;
    struct iot_cap_handle *internal_handle;
    IOT_CAP_HANDLE *handle;
    char *user_data;
    UNUSED(state);

    // Given
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE *)internal_handle;
    user_data = strdup("fakeData");

    // When
    for (unsigned int i = 0; i < 2; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid input
        ret = st_cap_cmd_set_cb(handle, "fakeCommand", test_cap_cmd_cb, (void *)user_data);
        // Then: success
        assert_int_not_equal(ret, 0);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
    free(internal_handle);
    free(user_data);
}

void TC_st_cap_cmd_set_cb_success(void **state)
{
    int ret;
    struct iot_cap_handle *internal_handle;
    IOT_CAP_HANDLE *handle;
    char *user_data;
    UNUSED(state);

    // Given
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    handle = (IOT_CAP_HANDLE *)internal_handle;
    user_data = strdup("fakeData");
    // When
    ret = st_cap_cmd_set_cb(handle, "fakeCommand", test_cap_cmd_cb, (void *)user_data);
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
    iot_os_free((void *)internal_handle->cmd_list->command->cmd_type);
    iot_os_free(internal_handle->cmd_list->command);
    iot_os_free(internal_handle->cmd_list);
    free(internal_handle);
}

static void assert_st_cap_attr_send(char *message, char *expected_component, char *expected_capability,
                                    IOT_EVENT *expected_event[])
{
    JSON_H *root;
    JSON_H *event_array;
    iot_cap_evt_data_t **internal_event = (iot_cap_evt_data_t **)expected_event;
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
        assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event[i]->evt_type);

        item = JSON_GET_OBJECT_ITEM(event, "value");
        assert_non_null(item);
        switch (internal_event[i]->evt_value.type) {
            case IOT_CAP_VAL_TYPE_BOOLEAN:
                assert_true(internal_event[i]->evt_value.boolean);
                assert_string_equal(internal_event[i]->options.command_id, "test_cmd_id");
                break;
            case IOT_CAP_VAL_TYPE_INTEGER:
                assert_int_equal(item->valueint, internal_event[i]->evt_value.integer);
                break;
            case IOT_CAP_VAL_TYPE_NUMBER:
                assert_int_equal(item->valuedouble, internal_event[i]->evt_value.number);
                break;
            case IOT_CAP_VAL_TYPE_STRING:
                assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event[i]->evt_value.string);
                break;
            case IOT_CAP_VAL_TYPE_INT_OR_NUM:
            case IOT_CAP_VAL_TYPE_STR_ARRAY:
                assert_int_equal(JSON_GET_ARRAY_SIZE(item), internal_event[i]->evt_value.str_num);
                break;
            case IOT_CAP_VAL_TYPE_JSON_OBJECT:
                // TODO: validate value for these type
                assert_string_equal(JSON_PRINT(item), internal_event[i]->evt_value.json_object);
                break;
            default:
                assert_false(1);
                break;
        }

        if (internal_event[i]->evt_unit.type == IOT_CAP_UNIT_TYPE_STRING) {
            item = JSON_GET_OBJECT_ITEM(event, "unit");
            assert_non_null(item);
            assert_string_equal(JSON_GET_STRING_VALUE(item), internal_event[i]->evt_unit.string);
        }

        item = JSON_GET_OBJECT_ITEM(event, "providerData");
        assert_non_null(item);
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
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event[NUM_OF_IOT_EVENTS];
    struct iot_cap_handle *internal_handle;
    struct iot_context *internal_context;
    iot_mqtt_packet_chunk_t *final_chunk;
    MQTTClient *c;
    iot_cap_val_t value;
    iot_cap_attr_option_t opt;
    UNUSED(state);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->iot_events = iot_os_eventgroup_create();
    internal_context->mqtt_event_topic = "TCtest";
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);
    cap_handle = st_cap_handle_init(context, "main", "testCap", test_cap_init_callback, NULL);
    assert_non_null(cap_handle);
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 10, "testUnit", NULL, event[0]);
    assert_non_null(event[0]);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "testAttr", "abc", "testUnit", NULL, event[1]);
    assert_non_null(event[1]);
    char **str_arr = iot_os_malloc(2 * sizeof(char *));
    str_arr[0] = "abc";
    str_arr[1] = "xyz";
    ST_CAP_CREATE_ATTR_STRINGS_ARRAY(cap_handle, "testAttr", str_arr, 2, "testUnit", NULL, event[2]);
    assert_non_null(event[2]);
    // Value type is boolean
    opt.command_id = "test_cmd_id";
    opt.state_change = 2;
    opt.displayed = (bool *)iot_os_malloc(sizeof(bool));
    memset(opt.displayed, true, sizeof(bool));
    value.type = IOT_CAP_VAL_TYPE_BOOLEAN;
    value.boolean = true;
    event[3] = st_cap_create_attr_with_option(cap_handle, "testAttr", &value, "testUnit", NULL, &opt);
    assert_non_null(event[3]);

    // Value type is integer
    value.type = IOT_CAP_VAL_TYPE_INTEGER;
    value.integer = 12;
    event[4] = st_cap_create_attr(cap_handle, "testAttr", &value, "testUnit", NULL);
    assert_non_null(event[4]);

    // Value type is json object
    value.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;
    value.json_object = "{\"key1\":2,\"key2\":5}";
    event[5] = st_cap_create_attr(cap_handle, "testAttr", &value, "testUnit", NULL);
    assert_non_null(event[5]);

    // When
    sequence_number = st_cap_send_attr(event, NUM_OF_IOT_EVENTS);
    // Then
    assert_true(sequence_number > 0);
    c = internal_context->evt_mqttcli;
    final_chunk = c->write_pending_queue.head;
    /* packet header(2bytes) + MQTTTopiclength(2bytes) + MQTTTopicstring("TCTEST", 6bytes) + packetId(2bytes) = 12 */
    assert_st_cap_attr_send(final_chunk->chunk_data + 12, "main", "testCap", event);
    assert_int_equal(final_chunk->chunk_id, sequence_number);
    // Teardown
    for (int i = 0; i < NUM_OF_IOT_EVENTS; i++)
        st_cap_free_attr(event[i]);
    internal_handle = (struct iot_cap_handle *)cap_handle;
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE)
    {
        iot_cap_last_val_t *node = internal_handle->last_val_list;
        while (node != NULL) {
            iot_cap_last_val_t *next = node->next;
            if (node->attr_type) {
                iot_os_free(node->attr_type);
            }
            _iot_free_val(&node->value);
            iot_os_free(node);
            node = next;
        }
    }
#endif
    if (internal_handle->capability) {
        iot_os_free((void *)internal_handle->capability);
    }
    if (internal_handle->component) {
        iot_os_free((void *)internal_handle->component);
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
    iot_os_free(str_arr);
    iot_os_free(opt.displayed);
}

void TC_st_cap_send_attr_invalid_parameter(void **state)
{
    int sequence_number;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event;
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
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    cap_handle = (IOT_CAP_HANDLE *)internal_handle;
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 100, "testUnit", NULL, event);
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number < 0);
    // Teardown
    st_cap_free_attr(event);
    free(internal_handle);

    // Given: invalid context state
    internal_handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    memset(internal_handle, '\0', sizeof(struct iot_cap_handle));
    internal_handle->component = strdup("main");
    internal_handle->capability = strdup("testCaps");
    cap_handle = (IOT_CAP_HANDLE *)internal_handle;
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    internal_handle->ctx = internal_context;
    internal_context->curr_state = IOT_STATE_PROV_DONE;
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "testAttr", 100, "testUnit", NULL, event);
    // When
    sequence_number = st_cap_send_attr(&event, 1);
    // Then
    assert_true(sequence_number < 0);
    // Teardown
    st_cap_free_attr(event);
    free((void *)internal_handle->capability);
    free((void *)internal_handle->component);
    free(internal_handle);
    free(internal_context);
}

bool test_cap_sub_switch_on_called;
static void test_cap_sub_switch_on(IOT_CAP_HANDLE *HANDLE, iot_cap_cmd_data_t *cmd_data, void *usr_data)
{
    struct iot_cap_handle *handle = (struct iot_cap_handle *)HANDLE;
    test_cap_sub_switch_on_called = true;

    assert_string_equal(handle->capability, "switch");
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->cmd_list->command->cmd_type, "on");
    assert_int_equal(cmd_data->num_args, 5);
}

void TC_iot_cap_sub_cb_success(void **state)
{
    // Given: typical payload and handle lists
    iot_cap_handle_list_t cap_handle_list;
    char *payload =
        "{\"commands\":[{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":\
                    [true,123,\"xyz\",{\"ab\":\"xy\"},[21,22]]}]}";

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
    struct iot_command *noti_cmd;
    device_work_data_t work_data;
    iot_noti_data_t *noti_data;
    char *payload =
        "{\"target\":\"test-target\",\"count\":51,\"threshold\":50,\"remainingTime\":3990,\"sequenceNumber\":72,"
        "\"event\":\"rate.limit.reached\",\"deviceId\":\"test-deviceId\"}";
    UNUSED(state);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    internal_context->work_queue_signal = iot_os_eventgroup_create();
    internal_context->rate_limit_timeout = iot_os_timer_create(NULL, 60000, NULL);
    // When
    iot_noti_sub_cb(internal_context, payload);
    // Then
    err = iot_util_queue_receive(internal_context->work_queue, &work_data);
    assert_int_equal(err, IOT_ERROR_NONE);
    noti_cmd = (struct iot_command *)(work_data.param);
    noti_data = noti_cmd->param;
    assert_int_equal(noti_data->type, _IOT_NOTI_TYPE_RATE_LIMIT);
    // Teardown
    if (noti_cmd->param)
        iot_os_free(noti_cmd->param);
    iot_os_free(noti_cmd);
    iot_os_timer_delete(internal_context->rate_limit_timeout);
    iot_os_eventgroup_delete(internal_context->work_queue_signal);
    iot_util_queue_delete(internal_context->work_queue);
    free(context);
}

extern iot_error_t _iot_parse_noti_data(struct iot_context *ctx, void *data, iot_noti_data_t *noti_data);
extern iot_error_t _iot_subscribe_child_devices_command(struct iot_context *ctx, JSON_H *child_devices_array);
extern iot_error_t _iot_notify_child_devices_cloud_connected(struct iot_context *ctx, JSON_H *child_devices_array);
extern iot_error_t _iot_parse_cmd_data_v2(JSON_H *cmditem, st_command_data *cmd_data);
extern void _iot_free_cmd_data_v2(st_command_data *cmd_data);
extern iot_error_t _iot_parse_cmd_data(JSON_H *cmditem, char **component, char **capability, char **command,
                                       iot_cap_cmd_data_t *cmd_data);
extern void _iot_free_val(iot_cap_val_t *val);
extern void _iot_free_unit(iot_cap_unit_t *unit);
extern void _iot_free_cmd_data(iot_cap_cmd_data_t *cmd_data);
extern void _iot_free_evt_data(iot_cap_evt_data_t *evt_data);
#define NOTI_TEST_UUID "123e4567-e89b-12d3-a456-426614174000"
#define NOTI_TEST_TIME "1591326145"
#define NOTI_TEST_TIME_IN_INT 1591326145
struct parse_noti_test_data {
    char *payload;
    int expected_result;
    iot_noti_type_t type;
    noti_data_raw_t raw;
};

void TC_iot_parse_noti_data_device_deleted(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    struct parse_noti_test_data test_data[4] = {
        {
            "{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"device.deleted\",\"deviceId\":\"" NOTI_TEST_UUID "\"}",
            IOT_ERROR_NONE,
            _IOT_NOTI_TYPE_DEV_DELETED,
            0,
        },
        {
            "{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"device.deleting\",\"deviceId\":\"" NOTI_TEST_UUID "\"}",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_DEV_DELETED,
            0,
        },
        {
            "{\"target\":\"" NOTI_TEST_UUID "\",\"deviceId\":\"" NOTI_TEST_UUID "\"}",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_DEV_DELETED,
            0,
        },
        {
            "This is not json data",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_DEV_DELETED,
            0,
        }};

    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When
        err = _iot_parse_noti_data(fake_ctx, (void *)test_data[i].payload, &notification);
        // Then
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
        }
    }

    free(fake_ctx);
}

void TC_iot_parse_noti_data_expired_jwt(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));
    /* expired.jwt is handled internally (time sync + reconnection trigger),
     * so it is not exposed as a notification and parser returns IOT_ERROR_BAD_REQ
     */
    struct parse_noti_test_data test_data[3] = {
        {
            "{\"event\":\"expired.jwt\",\"deviceId\":\"" NOTI_TEST_UUID "\",\"currentTime\":" NOTI_TEST_TIME "}",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_UNKNOWN,
            0,
        },
        {
            "{\"event\":\"expired.JavaWebToken\",\"deviceId\":\"" NOTI_TEST_UUID "\",\"currentTime\":" NOTI_TEST_TIME
            "}",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_UNKNOWN,
            0,
        },
        {
            "{\"event\":\"expired.jwt\",\"deviceId\":\"" NOTI_TEST_UUID "\"}",
            IOT_ERROR_BAD_REQ,
            _IOT_NOTI_TYPE_UNKNOWN,
            0,
        },
    };

    UNUSED(state);

    /* Only the first payload is a valid expired.jwt with currentTime,
     * which triggers SNTP time set with the server-given time
     */
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, NOTI_TEST_TIME_IN_INT);
    for (int i = 0; i < 3; i++) {
        err = _iot_parse_noti_data(fake_ctx, (void *)test_data[i].payload, &notification);
        assert_int_equal(err, test_data[i].expected_result);
    }

    free(fake_ctx);
}

void TC_iot_parse_noti_data_quota_reached(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    struct parse_noti_test_data test_data[4] = {
        {"{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"quota.reached\",\"limit\":500,\"used\":501}",
         IOT_ERROR_NONE,
         _IOT_NOTI_TYPE_QUOTA_REACHED,
         {.quota = {501, 500}}},
        {"{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"quota.done\",\"limit\":500,\"used\":501}",
         IOT_ERROR_BAD_REQ,
         _IOT_NOTI_TYPE_QUOTA_REACHED,
         {.quota = {501, 500}}},
        {"{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"quota.reached\",\"used\":501}",
         IOT_ERROR_BAD_REQ,
         _IOT_NOTI_TYPE_QUOTA_REACHED,
         {.quota = {501, 0}}},
        {"{\"target\":\"" NOTI_TEST_UUID "\",\"event\":\"quota.reached\",\"limit\":500}",
         IOT_ERROR_BAD_REQ,
         _IOT_NOTI_TYPE_QUOTA_REACHED,
         {.quota = {0, 500}}},
    };
    UNUSED(state);

    for (int i = 0; i < 4; i++) {
        // When
        err = _iot_parse_noti_data(fake_ctx, (void *)test_data[i].payload, &notification);
        // Then
        assert_int_equal(err, test_data[i].expected_result);
        if (test_data[i].expected_result == IOT_ERROR_NONE) {
            assert_int_equal(notification.type, test_data[i].type);
            assert_int_equal(notification.raw.quota.limit, test_data[i].raw.quota.limit);
            assert_int_equal(notification.raw.quota.used, test_data[i].raw.quota.used);
        }
    }

    free(fake_ctx);
}

void TC_st_cap_create_attr_with_id_success(void **state)
{
    IOT_EVENT *evt;
    iot_cap_evt_data_t *event_data = NULL;
    IOT_CAP_HANDLE cap_handle;
    iot_cap_val_t value;
    UNUSED(state);

    // when : atribute with id
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "testValue";

    evt = st_cap_create_attr_with_id(&cap_handle, "testIdAttr", &value, NULL, NULL, "test_cmd_id");
    // Then : return proper event data
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_string_equal(event_data->evt_value.string, "testValue");
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_STRING);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "testIdAttr");
}

void TC_st_cap_create_attr_with_option_null_parameter(void **state)
{
    IOT_EVENT *evt;
    iot_cap_val_t value;
    IOT_CAP_HANDLE cap_handle;
    UNUSED(state);

    // Given:
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "testValue";

    // When cap handle is null
    evt = st_cap_create_attr_with_option(NULL, "testIdAttr", &value, NULL, NULL, NULL);
    // Then: returns null
    assert_null(evt);

    // When: attribute is null
    evt = st_cap_create_attr_with_option(&cap_handle, NULL, &value, NULL, NULL, NULL);
    // Then: returns null
    assert_null(evt);

    // When: value is null
    evt = st_cap_create_attr_with_option(&cap_handle, "testIdAttr", NULL, NULL, NULL, NULL);
    // Then: returns null
    assert_null(evt);
}

void TC_st_cap_create_attr_with_option_failure(void **state)
{
    IOT_EVENT *evt;
    iot_cap_evt_data_t *event_data = NULL;
    IOT_CAP_HANDLE cap_handle;
    iot_cap_val_t value;
    iot_cap_attr_option_t opt;
    JSON_H *root;
    UNUSED(state);

    opt.command_id = "test_cmd_id";
    opt.state_change = 2;

    // when: string value is null
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = NULL;
    evt = st_cap_create_attr_with_option(&cap_handle, "bodyWeightMeasurement", &value, NULL, NULL, &opt);
    // Then: returns null
    assert_null(evt);

    // When: string array value is null
    value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
    value.str_num = 3;
    value.strings = iot_os_malloc(value.str_num * sizeof(char *));
    memset(value.strings, '\0', value.str_num * sizeof(char *));
    evt = st_cap_create_attr_with_option(&cap_handle, "testAttribute", &value, NULL, NULL, &opt);
    // Then: returns null
    assert_null(evt);
    // Teardown
    iot_os_free(value.strings);

    // When: unknown attribute type
    value.type = IOT_CAP_VAL_TYPE_UNKNOWN;
    evt = st_cap_create_attr_with_option(&cap_handle, "testAttribute", &value, NULL, NULL, &opt);
    // Then: returns null
    assert_null(evt);
}

void TC_st_cap_create_attr_with_option_internal_failure(void **state)
{
    IOT_EVENT *evt;
    iot_cap_evt_data_t *event_data = NULL;
    IOT_CAP_HANDLE cap_handle;
    iot_cap_val_t value;
    iot_cap_attr_option_t opt;
    JSON_H *root;
    UNUSED(state);

    // Given
    value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
    value.str_num = 3;
    value.strings = iot_os_malloc(value.str_num * sizeof(char *));
    value.strings[0] = "str1";
    value.strings[1] = "str2";
    value.strings[2] = "str3";
    opt.command_id = "test_cmd_id";
    opt.state_change = 2;

    opt.displayed = (bool *)iot_os_malloc(sizeof(bool));
    memset(opt.displayed, true, sizeof(bool));
    for (unsigned int i = 0; i < 3; i++) {
        // Given: i-th malloc failure
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid input
        evt = st_cap_create_attr_with_option(&cap_handle, "testAttribute", &value, NULL, NULL, &opt);
        // Then: success
        assert_null(evt);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
    iot_os_free(value.strings);
    iot_os_free(opt.displayed);
}

void TC_st_cap_create_attr_with_option_success(void **state)
{
    IOT_EVENT *evt;
    iot_cap_evt_data_t *event_data = NULL;
    IOT_CAP_HANDLE cap_handle;
    iot_cap_val_t value;
    iot_cap_attr_option_t opt;
    JSON_H *root;
    UNUSED(state);

    // when: value type is number
    value.type = IOT_CAP_VAL_TYPE_NUMBER;
    value.number = 56.7;
    opt.command_id = "test_cmd_id";
    opt.state_change = 2;

    opt.displayed = (bool *)iot_os_malloc(sizeof(bool));
    memset(opt.displayed, true, sizeof(bool));

    evt = st_cap_create_attr_with_option(&cap_handle, "bodyWeightMeasurement", &value, "kg", "tempdata", &opt);
    // Then: return non null
    assert_non_null(evt);
    // Then : return proper event data
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_STRING);
    assert_int_equal(event_data->evt_value.number, 56.7);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_NUMBER);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "bodyWeightMeasurement");
    assert_string_equal(event_data->evt_value_data, "tempdata");
    // Teardown
    st_cap_free_attr(evt);

    // When: value type is integer
    value.type = IOT_CAP_VAL_TYPE_INTEGER;
    value.integer = 5;
    evt = st_cap_create_attr_with_option(&cap_handle, "data", &value, NULL, NULL, &opt);
    event_data = (iot_cap_evt_data_t *)evt;
    // Then: return non null
    assert_non_null(evt);
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.integer, 5);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_INTEGER);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "data");
    // Teardown
    st_cap_free_attr(evt);

    // When value type is boolean
    value.type = IOT_CAP_VAL_TYPE_BOOLEAN;
    value.boolean = true;
    evt = st_cap_create_attr_with_option(&cap_handle, "on", &value, NULL, NULL, &opt);
    event_data = (iot_cap_evt_data_t *)evt;
    // Then: return non null
    assert_non_null(evt);
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.boolean, true);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_BOOLEAN);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "on");
    // Teardown
    st_cap_free_attr(evt);

    // When value type is string array
    value.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
    value.str_num = 3;
    value.strings = iot_os_malloc(value.str_num * sizeof(char *));
    value.strings[0] = "str1";
    value.strings[1] = "str2";
    value.strings[2] = "str3";
    evt = st_cap_create_attr_with_option(&cap_handle, "testAttribute", &value, NULL, NULL, &opt);
    event_data = (iot_cap_evt_data_t *)evt;
    // Then: return non null
    assert_non_null(evt);
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.str_num, 3);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_STR_ARRAY);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "testAttribute");
    // Teardown
    st_cap_free_attr(evt);
    iot_os_free(value.strings);

    // When: value type is object
    root = JSON_CREATE_OBJECT();
    assert_non_null(root);
    JSON_ADD_ITEM_TO_OBJECT(root, "key1", JSON_CREATE_STRING("val1"));
    JSON_ADD_ITEM_TO_OBJECT(root, "key2", JSON_CREATE_STRING("val2"));
    value.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;
    value.json_object = JSON_PRINT(root);
    // Then: returns non null
    evt = st_cap_create_attr_with_option(&cap_handle, "testAttribute", &value, NULL, NULL, &opt);
    event_data = (iot_cap_evt_data_t *)evt;
    // Then: return non null
    assert_non_null(evt);
    event_data = (iot_cap_evt_data_t *)evt;
    assert_int_equal(event_data->evt_unit.type, IOT_CAP_UNIT_TYPE_UNUSED);
    assert_int_equal(event_data->evt_value.type, IOT_CAP_VAL_TYPE_JSON_OBJECT);
    assert_string_equal(event_data->evt_value.json_object, value.json_object);
    assert_string_equal(event_data->options.command_id, "test_cmd_id");
    assert_string_equal(event_data->evt_type, "testAttribute");

    // Teardown
    st_cap_free_attr(evt);
    JSON_FREE(root);
    iot_os_free(opt.displayed);
}

void TC_iot_cap_commands_cb_failure(void **state)
{
    UNUSED(state);
    struct iot_context *context;

    // Given
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    // When payload is null
    iot_cap_commands_cb(context, NULL);

    // Teardown
    free(context);
}

void TC_iot_cap_commands_cb_success(void **state)
{
    UNUSED(state);
    struct iot_context *context;
    char *payload = NULL;
    JSON_H *json = NULL;
    JSON_H *item = NULL;
    JSON_H *sub_item = NULL;
    JSON_H *arr = NULL;
    int ret;

    // Given
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    payload =
        "{\"commands\":[{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\","
        "\"arguments\":[true,123,\"xyz\",{\"ab\":\"xy\"}, [31,21]],\"id\":\"test_id\"}]}";
    // Then
    // assert_int_equal(ret, 0);
    context->noti_cb = test_st_cap_noti_cb;
    // When
    iot_cap_commands_cb(context, payload);
    assert_ptr_equal(context->noti_cb, test_st_cap_noti_cb);
    assert_true(test_st_cap_noti_cb_called);

    // Teardown
    free(context);
}

void TC_iot_parse_noti_data_presference_updated(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    char *payload = NULL;
    struct iot_context *fake_ctx = NULL;

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    UNUSED(state);

    struct parse_noti_test_data test_data = {"{\"target\":\"" NOTI_TEST_UUID
                                             "\",\"event\":\"device.preferences\",\"values\":[\
                    {\"preferenceType\":\"string\",\"value\":\"testValue\"},\
                    {\"preferenceType\":\"number\",\"value\":123.0},\
                    {\"preferenceType\":\"boolean\",\"value\":true},\
                    {\"preferenceType\":\"integer\",\"value\":40}]}",
                                             IOT_ERROR_NONE, _IOT_NOTI_TYPE_PREFERENCE_UPDATED, 0};
    // When
    err = _iot_parse_noti_data(fake_ctx, (void *)test_data.payload, &notification);
    // Then
    assert_int_equal(err, test_data.expected_result);
    if (test_data.expected_result == IOT_ERROR_NONE) {
        assert_int_equal(notification.type, test_data.type);
    }

    // Teardown
    if (notification.raw.preferences.preferences_data->preference_name)
        iot_os_free(notification.raw.preferences.preferences_data->preference_name);
    iot_os_free(notification.raw.preferences.preferences_data->preference_data.string);
    iot_os_free(notification.raw.preferences.preferences_data);
    free(fake_ctx);
}

void TC_iot_cap_call_init_cb_null_parameteer(void **state)
{
    UNUSED(state);

    // When handle is null
    iot_cap_call_init_cb(NULL);
}

void TC_iot_cap_call_init_cb_success(void **state)
{
    struct iot_cap_handle_list *cap_handle_list;

    UNUSED(state);

    // Given
    cap_handle_list = (struct iot_cap_handle_list *)malloc(sizeof(struct iot_cap_handle_list));
    cap_handle_list->handle = (struct iot_cap_handle *)malloc(sizeof(struct iot_cap_handle));
    cap_handle_list->handle->init_cb = test_cap_init_callback;
    cap_handle_list->handle->capability = iot_os_strdup("main");
    cap_handle_list->next = NULL;

    // When:
    iot_cap_call_init_cb(cap_handle_list);

    // Teardown
    iot_os_free((void *)cap_handle_list->handle->capability);
    free(cap_handle_list->handle);
    free(cap_handle_list);
}

static void assert_st_cap_attr_v2_send(char *message, char *expected_component, char *expected_capability,
                                       st_attr_data *attr_data[], int expected_sequence_number)
{
    JSON_H *root;
    JSON_H *attr_array;
    assert_non_null(message);

    root = JSON_PARSE(message);
    assert_non_null(root);

    attr_array = JSON_GET_OBJECT_ITEM(root, "deviceEvents");
    assert_non_null(attr_array);
    for (int i = 0; i < JSON_GET_ARRAY_SIZE(attr_array); i++) {
        JSON_H *attr;
        JSON_H *item;

        attr = JSON_GET_ARRAY_ITEM(attr_array, i);
        assert_non_null(attr);

        item = JSON_GET_OBJECT_ITEM(attr, "component");
        assert_non_null(item);
        assert_string_equal(JSON_GET_STRING_VALUE(item), expected_component);

        item = JSON_GET_OBJECT_ITEM(attr, "capability");
        assert_non_null(item);
        assert_string_equal(JSON_GET_STRING_VALUE(item), expected_capability);

        item = JSON_GET_OBJECT_ITEM(attr, "attribute");
        assert_non_null(item);

        item = JSON_GET_OBJECT_ITEM(attr, "value");
        assert_non_null(item);
        switch (attr_data[i]->value.data_type) {
            case ST_DATA_TYPE_BOOLEAN:
                assert_true(attr_data[i]->value.data_type);
                break;
            case ST_DATA_TYPE_NUMBER:
                assert_int_equal(item->valueint, attr_data[i]->value.data.number);
                break;
            case ST_DATA_TYPE_STRING:
                assert_string_equal(JSON_GET_STRING_VALUE(item), attr_data[i]->value.data.string);
                break;
            case ST_DATA_TYPE_RAW_JSON:
                // TODO: validate value for these type
                assert_string_equal(JSON_PRINT(item), attr_data[i]->value.data.raw_json);
                break;
            default:
                assert_false(1);
                break;
        }

        item = JSON_GET_OBJECT_ITEM(attr, "providerData");
        assert_non_null(item);

        assert_int_equal(JSON_GET_OBJECT_ITEM(item, "sequenceNumber")->valueint, expected_sequence_number);
    }

    JSON_DELETE(root);
}

void TC_st_cap_send_attr_v2_null_parameter(void **state)
{
    UNUSED(state);
    st_attr_data *attr[5];
    IOT_CTX *context;
    int ret;

    context = (IOT_CTX *)malloc(sizeof(struct iot_context));

    // When context is null
    ret = st_cap_send_attr_v2(NULL, attr, 5);
    assert_int_equal(ret, IOT_ERROR_INVALID_ARGS);

    // When number of attribute is 0
    ret = st_cap_send_attr_v2(context, attr, 0);
    assert_int_equal(ret, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

void TC_st_cap_send_attr_v2_failure(void **state)
{
    UNUSED(state);
    st_attr_data *attr[5];
    IOT_CTX *context;
    struct iot_context *internal_context;
    int ret;

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_DISCONNECTED;

    // When not connected to cloud
    ret = st_cap_send_attr_v2(context, attr, 5);
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;

    // When attr is null
    attr[0] = NULL;
    ret = st_cap_send_attr_v2(context, attr, 1);
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);

    // When invalid attribute component type
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);
    attr[0] = (st_attr_data *)malloc(sizeof(st_attr_data));
    assert_non_null(attr[0]);
    attr[0]->component_type = 2;
    ret = st_cap_send_attr_v2(context, attr, 1);
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);

    // Teardown
    free(attr[0]);
    st_mqtt_destroy(internal_context->evt_mqttcli);
    free(context);
}

void TC_st_cap_send_attr_v2_success(void **state)
{
    UNUSED(state);
    int sequence_number;
    IOT_CTX *context;
    st_attr_data *attr[5];
    struct iot_context *internal_context;
    iot_mqtt_packet_chunk_t *final_chunk;
    MQTTClient *c;
    UNUSED(state);

    // Given
    internal_context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->mqtt_event_topic = "TCtest";
    internal_context->event_sequence_num = 0;
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);

    // attr type is number
    attr[0] = (st_attr_data *)malloc(sizeof(st_attr_data));
    assert_non_null(attr[0]);
    attr[0]->component_type = ST_COMPONENT_DEFULAT;
    attr[0]->attr_type = ST_ATTR_CUSTOM;
    attr[0]->custom_attr_name = strdup("testAttr");
    attr[0]->custom_cap_name = strdup("testCap");
    attr[0]->value.data_type = ST_DATA_TYPE_NUMBER;
    attr[0]->value.data.number = 5.0;
    attr[0]->unit = strdup("testUnit");
    attr[0]->data = strdup("testData");
    attr[0]->state_change = true;
    attr[0]->related_command_id = NULL;

    // attr type is string
    attr[1] = (st_attr_data *)malloc(sizeof(st_attr_data));
    assert_non_null(attr[1]);
    attr[1]->component_type = ST_COMPONENT_DEFULAT;
    attr[1]->attr_type = ST_ATTR_CUSTOM;
    attr[1]->custom_attr_name = strdup("testAttr");
    attr[1]->custom_cap_name = strdup("testCap");
    attr[1]->value.data_type = ST_DATA_TYPE_STRING;
    attr[1]->value.data.string = "tempVal";
    attr[1]->unit = strdup("testUnit");
    attr[1]->data = strdup("testData");
    attr[1]->state_change = true;
    attr[1]->related_command_id = NULL;

    // attr type is raw json
    attr[2] = (st_attr_data *)malloc(sizeof(st_attr_data));
    assert_non_null(attr[2]);
    attr[2]->component_type = ST_COMPONENT_DEFULAT;
    attr[2]->attr_type = ST_ATTR_CUSTOM;
    attr[2]->custom_attr_name = strdup("testAttr");
    attr[2]->custom_cap_name = strdup("testCap");
    attr[2]->value.data_type = ST_DATA_TYPE_RAW_JSON;
    attr[2]->value.data.raw_json = "{\"key1\":2,\"key2\":5}";
    attr[2]->unit = strdup("testUnit");
    attr[2]->data = strdup("testData");
    attr[2]->state_change = true;
    attr[2]->related_command_id = NULL;

    // attr type is boolean json
    attr[3] = (st_attr_data *)malloc(sizeof(st_attr_data));
    assert_non_null(attr[3]);
    attr[3]->component_type = ST_COMPONENT_DEFULAT;
    attr[3]->attr_type = ST_ATTR_CUSTOM;
    attr[3]->custom_attr_name = strdup("testAttr");
    attr[3]->custom_cap_name = strdup("testCap");
    attr[3]->value.data_type = ST_DATA_TYPE_BOOLEAN;
    attr[3]->value.data.boolean = true;
    attr[3]->unit = strdup("testUnit");
    attr[3]->data = strdup("testData");
    attr[3]->state_change = true;
    attr[3]->related_command_id = NULL;

    // When
    sequence_number = st_cap_send_attr_v2(context, attr, 4);
    // Then
    assert_true(sequence_number > 0);
    c = internal_context->evt_mqttcli;
    final_chunk = c->write_pending_queue.head;
    /* packet header(2bytes) + MQTTTopiclength(2bytes) + MQTTTopicstring("TCTEST", 6bytes) + packetId(2bytes) = 12 */
    assert_st_cap_attr_v2_send(final_chunk->chunk_data + 12, "main", "testCap", attr, sequence_number);

    // Teardown
    for (int i = 0; i < 4; i++) {
        free(attr[i]->custom_attr_name);
        free(attr[i]->custom_cap_name);
    }
    st_mqtt_destroy(internal_context->evt_mqttcli);

    free(context);
}

void TC_st_child_dev_cap_handle_init_null_parameters(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    char *usr_data;
    UNUSED(*state);

    // When: all parameters null
    cap_handle = st_child_dev_cap_handle_init(NULL, NULL, NULL, NULL, NULL);
    // Then
    assert_null(cap_handle);

    // Given
    usr_data = strdup("UserString");
    // When: child_dev null
    cap_handle = st_child_dev_cap_handle_init(NULL, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);

    // Given
    usr_data = strdup("UserString");
    // When: capability null
    cap_handle = st_child_dev_cap_handle_init((IOT_CHILD_DEV)0x1234, "main", NULL, test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    free(usr_data);
}

void TC_st_child_dev_cap_handle_init_internal_failure(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    IOT_CHILD_DEV child_dev;
    char *usr_data;
    iot_child_device *child_dev_internal;
    UNUSED(*state);

    // Given: valid parameters but malloc failure
    usr_data = iot_os_strdup("UserString");
    child_dev_internal = (iot_child_device *)iot_os_malloc(sizeof(iot_child_device));
    memset(child_dev_internal, 0, sizeof(iot_child_device));
    child_dev = (IOT_CHILD_DEV)child_dev_internal;

    set_mock_iot_os_malloc_failure_with_index(0);
    // When
    cap_handle = st_child_dev_cap_handle_init(child_dev, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    iot_os_free(child_dev_internal);
    iot_os_free(usr_data);
    do_not_use_mock_iot_os_malloc_failure();

    // Given: valid parameters but second malloc failure
    usr_data = iot_os_strdup("UserString");
    child_dev_internal = (iot_child_device *)iot_os_malloc(sizeof(iot_child_device));
    memset(child_dev_internal, 0, sizeof(iot_child_device));
    child_dev = (IOT_CHILD_DEV)child_dev_internal;

    set_mock_iot_os_malloc_failure_with_index(1);
    // When
    cap_handle = st_child_dev_cap_handle_init(child_dev, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    assert_null(cap_handle);
    // Teardown
    iot_os_free(child_dev_internal);
    iot_os_free(usr_data);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_st_child_dev_cap_handle_init_success(void **state)
{
    IOT_CAP_HANDLE *cap_handle;
    struct iot_cap_handle *handle;
    iot_child_device *child_dev_internal;
    IOT_CHILD_DEV child_dev;
    char *usr_data;
    UNUSED(*state);

    // Given
    usr_data = strdup("UserString");
    child_dev_internal = (iot_child_device *)malloc(sizeof(iot_child_device));
    memset(child_dev_internal, 0, sizeof(iot_child_device));
    child_dev = (IOT_CHILD_DEV)child_dev_internal;

    // When
    cap_handle = st_child_dev_cap_handle_init(child_dev, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle *)cap_handle;
    assert_non_null(cap_handle);
    assert_null(child_dev_internal->cap_handle_list->next);
    assert_null(handle->cmd_list);
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->capability, "switch");
    assert_ptr_equal(handle->init_cb, test_cap_init_callback);
    assert_ptr_equal(handle->init_usr_data, usr_data);
    assert_ptr_equal(handle->ctx, child_dev_internal->ctx);
    assert_ptr_equal(handle->child_dev, child_dev_internal);
    // Teardown
    if (handle->capability) {
        iot_os_free((void *)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void *)handle->component);
    }
    if (child_dev_internal->cap_handle_list) {
        iot_os_free(child_dev_internal->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(child_dev_internal);
    free(usr_data);

    // Given: Already existing handle in child device
    usr_data = strdup("UserString");
    child_dev_internal = (iot_child_device *)malloc(sizeof(iot_child_device));
    memset(child_dev_internal, 0, sizeof(iot_child_device));
    child_dev_internal->cap_handle_list = malloc(sizeof(iot_cap_handle_list_t));
    child_dev_internal->cap_handle_list->next = NULL;
    child_dev = (IOT_CHILD_DEV)child_dev_internal;

    // When
    cap_handle = st_child_dev_cap_handle_init(child_dev, "main", "switch", test_cap_init_callback, usr_data);
    // Then
    handle = (struct iot_cap_handle *)cap_handle;
    assert_non_null(cap_handle);
    assert_non_null(child_dev_internal->cap_handle_list->next);
    assert_ptr_equal(child_dev_internal->cap_handle_list->handle, handle);
    assert_null(child_dev_internal->cap_handle_list->next->next);
    assert_null(handle->cmd_list);
    assert_string_equal(handle->component, "main");
    assert_string_equal(handle->capability, "switch");
    assert_ptr_equal(handle->init_cb, test_cap_init_callback);
    assert_ptr_equal(handle->init_usr_data, usr_data);
    assert_ptr_equal(handle->ctx, child_dev_internal->ctx);
    assert_ptr_equal(handle->child_dev, child_dev_internal);
    // Teardown
    if (handle->capability) {
        iot_os_free((void *)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void *)handle->component);
    }
    if (child_dev_internal->cap_handle_list->next) {
        free(child_dev_internal->cap_handle_list->next);
    }
    if (child_dev_internal->cap_handle_list) {
        iot_os_free(child_dev_internal->cap_handle_list);
    }
    iot_os_free(cap_handle);
    free(child_dev_internal);
    free(usr_data);
}

void TC_iot_subscribe_child_devices_command_null_parameters(void **state)
{
    iot_error_t ret;
    UNUSED(*state);

    // When: context null
    ret = _iot_subscribe_child_devices_command(NULL, NULL);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
}

void TC_iot_subscribe_child_devices_command_empty_array(void **state)
{
    iot_error_t ret;
    JSON_H *empty_array;
    struct iot_context *ctx;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    empty_array = JSON_CREATE_ARRAY();

    // When
    ret = _iot_subscribe_child_devices_command(ctx, empty_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);

    // Teardown
    JSON_DELETE(empty_array);
    free(ctx);
}

void TC_iot_subscribe_child_devices_command_malloc_failure(void **state)
{
    iot_error_t ret;
    JSON_H *child_array;
    struct iot_context *ctx;
    JSON_H *child_item;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("test_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When: malloc failure for subscribe_topic_list
    set_mock_iot_os_malloc_failure_with_index(0);
    ret = _iot_subscribe_child_devices_command(ctx, child_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    JSON_DELETE(child_array);
    free(ctx);
    do_not_use_mock_iot_os_malloc_failure();

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("test_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When: malloc failure for qos
    set_mock_iot_os_malloc_failure_with_index(1);
    ret = _iot_subscribe_child_devices_command(ctx, child_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    JSON_DELETE(child_array);
    free(ctx);
    do_not_use_mock_iot_os_malloc_failure();

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("test_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When: malloc failure for subscribe_topic_list[i]
    set_mock_iot_os_malloc_failure_with_index(2);
    ret = _iot_subscribe_child_devices_command(ctx, child_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    JSON_DELETE(child_array);
    free(ctx);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_subscribe_child_devices_command_success(void **state)
{
    iot_error_t ret;
    JSON_H *child_array;
    struct iot_context *ctx;
    JSON_H *child_item;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    st_mqtt_create(&ctx->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);
    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("test_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When
    ret = _iot_subscribe_child_devices_command(ctx, child_array);
    // Then
    // Should return IOT_ERROR_BAD_REQ because st_mqtt_subscribe will fail in mock
    assert_int_not_equal(ret, IOT_ERROR_NONE);

    // Teardown
    JSON_DELETE(child_array);
    st_mqtt_destroy(ctx->evt_mqttcli);
    free(ctx);
}

void TC_iot_parse_cmd_data_v2_null_parameters(void **state)
{
    iot_error_t ret;
    st_command_data cmd_data;
    UNUSED(*state);

    // When: cmditem null
    ret = _iot_parse_cmd_data_v2(NULL, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
}

void TC_iot_parse_cmd_data_v2_missing_fields(void **state)
{
    iot_error_t ret;
    st_command_data cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Given: missing component
    cmditem = JSON_PARSE("{\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing capability
    cmditem = JSON_PARSE("{\"component\":\"main\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing command
    cmditem = JSON_PARSE("{\"component\":\"main\",\"capability\":\"switch\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing arguments
    cmditem = JSON_PARSE("{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing id
    cmditem = JSON_PARSE("{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true]}");
    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);
}

void TC_iot_parse_cmd_data_v2_malloc_failure(void **state)
{
    iot_error_t ret;
    st_command_data cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Given
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");

    // When: malloc failure for param_list
    set_mock_iot_os_malloc_failure_with_index(0);
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    JSON_DELETE(cmditem);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_parse_cmd_data_v2_success(void **state)
{
    iot_error_t ret;
    st_command_data cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Given: boolean argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");

    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(cmd_data.custom_component_name, "main");
    assert_string_equal(cmd_data.custom_cap_name, "switch");
    assert_string_equal(cmd_data.custom_command_name, "on");
    assert_string_equal(cmd_data.command_id, "test_id");
    assert_int_equal(cmd_data.param_num, 1);
    assert_int_equal(cmd_data.param_list[0].data_type, ST_DATA_TYPE_BOOLEAN);
    assert_true(cmd_data.param_list[0].data.boolean);

    // Teardown
    _iot_free_cmd_data_v2(&cmd_data);
    JSON_DELETE(cmditem);

    // Given: number argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switchLevel\",\"command\":\"setLevel\",\"arguments\":[50],\"id\":"
        "\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(cmd_data.custom_component_name, "main");
    assert_string_equal(cmd_data.custom_cap_name, "switchLevel");
    assert_string_equal(cmd_data.custom_command_name, "setLevel");
    assert_string_equal(cmd_data.command_id, "test_id");
    assert_int_equal(cmd_data.param_num, 1);
    assert_int_equal(cmd_data.param_list[0].data_type, ST_DATA_TYPE_NUMBER);
    assert_int_equal(cmd_data.param_list[0].data.number, 50);

    // Teardown
    _iot_free_cmd_data_v2(&cmd_data);
    JSON_DELETE(cmditem);

    // Given: string argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"setColor\",\"arguments\":[\"red\"],\"id\":"
        "\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(cmd_data.custom_component_name, "main");
    assert_string_equal(cmd_data.custom_cap_name, "switch");
    assert_string_equal(cmd_data.custom_command_name, "setColor");
    assert_string_equal(cmd_data.command_id, "test_id");
    assert_int_equal(cmd_data.param_num, 1);
    assert_int_equal(cmd_data.param_list[0].data_type, ST_DATA_TYPE_STRING);
    assert_string_equal(cmd_data.param_list[0].data.string, "red");

    // Teardown
    _iot_free_cmd_data_v2(&cmd_data);
    JSON_DELETE(cmditem);

    // Given: json object argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"setColor\",\"arguments\":[{\"hue\": 100, "
        "\"saturation\": 50}],\"id\":\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(cmd_data.custom_component_name, "main");
    assert_string_equal(cmd_data.custom_cap_name, "switch");
    assert_string_equal(cmd_data.custom_command_name, "setColor");
    assert_string_equal(cmd_data.command_id, "test_id");
    assert_int_equal(cmd_data.param_num, 1);
    assert_int_equal(cmd_data.param_list[0].data_type, ST_DATA_TYPE_RAW_JSON);
    assert_non_null(cmd_data.param_list[0].data.raw_json);

    // Teardown
    _iot_free_cmd_data_v2(&cmd_data);
    JSON_DELETE(cmditem);
}

void TC_iot_free_cmd_data_v2_null_parameter(void **state)
{
    UNUSED(*state);

    // When: cmd_data null
    _iot_free_cmd_data_v2(NULL);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_cmd_data_v2_success(void **state)
{
    st_command_data cmd_data;
    JSON_H *cmditem;
    iot_error_t ret;
    UNUSED(*state);

    // Given
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");
    ret = _iot_parse_cmd_data_v2(cmditem, &cmd_data);
    assert_int_equal(ret, IOT_ERROR_NONE);

    // When: free cmd_data
    _iot_free_cmd_data_v2(&cmd_data);
    // Then: should not crash
    assert_true(1);

    // Teardown
    JSON_DELETE(cmditem);
}

void TC_iot_parse_cmd_data_null_parameters(void **state)
{
    iot_error_t ret;
    char *component = NULL;
    char *capability = NULL;
    char *command = NULL;
    iot_cap_cmd_data_t cmd_data;
    UNUSED(*state);

    // When: cmditem null
    ret = _iot_parse_cmd_data(NULL, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
}

void TC_iot_parse_cmd_data_missing_fields(void **state)
{
    iot_error_t ret;
    char *component = NULL;
    char *capability = NULL;
    char *command = NULL;
    iot_cap_cmd_data_t cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Given: missing component
    cmditem = JSON_PARSE("{\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing capability
    cmditem = JSON_PARSE("{\"component\":\"main\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);

    // Given: missing command
    cmditem = JSON_PARSE("{\"component\":\"main\",\"capability\":\"switch\",\"arguments\":[true],\"id\":\"test_id\"}");
    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);
    JSON_DELETE(cmditem);
}

void TC_iot_parse_cmd_data_malloc_failure(void **state)
{
    iot_error_t ret;
    char *component = NULL;
    char *capability = NULL;
    char *command = NULL;
    iot_cap_cmd_data_t cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Given
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");

    // When: malloc failure for args_str
    set_mock_iot_os_malloc_failure_with_index(0);
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    JSON_DELETE(cmditem);
    do_not_use_mock_iot_os_malloc_failure();

    // Given
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");

    // When: malloc failure for cmd_data
    set_mock_iot_os_malloc_failure_with_index(1);
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_MEM_ALLOC);

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    JSON_DELETE(cmditem);
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_iot_parse_cmd_data_success(void **state)
{
    iot_error_t ret;
    char *component = NULL;
    char *capability = NULL;
    char *command = NULL;
    iot_cap_cmd_data_t cmd_data;
    JSON_H *cmditem;
    UNUSED(*state);

    // Initialize cmd_data structure
    memset(&cmd_data, 0, sizeof(cmd_data));

    // Given: boolean argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[true],\"id\":\"test_"
        "id\"}");

    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(component, "main");
    assert_string_equal(capability, "switch");
    assert_string_equal(command, "on");
    assert_int_equal(cmd_data.num_args, 1);
    assert_int_equal(cmd_data.cmd_data[0].type, IOT_CAP_VAL_TYPE_BOOLEAN);
    assert_true(cmd_data.cmd_data[0].boolean);
    assert_string_equal(cmd_data.command_id, "test_id");

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    _iot_free_cmd_data(&cmd_data);
    if (cmd_data.command_id)
        iot_os_free(cmd_data.command_id);
    JSON_DELETE(cmditem);
    component = NULL;
    capability = NULL;
    command = NULL;
    memset(&cmd_data, 0, sizeof(cmd_data));

    // Given: number argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switchLevel\",\"command\":\"setLevel\",\"arguments\":[50],\"id\":"
        "\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(component, "main");
    assert_string_equal(capability, "switchLevel");
    assert_string_equal(command, "setLevel");
    assert_int_equal(cmd_data.num_args, 1);
    assert_int_equal(cmd_data.cmd_data[0].type, IOT_CAP_VAL_TYPE_INT_OR_NUM);
    assert_int_equal(cmd_data.cmd_data[0].integer, 50);
    assert_string_equal(cmd_data.command_id, "test_id");

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    _iot_free_cmd_data(&cmd_data);
    if (cmd_data.command_id)
        iot_os_free(cmd_data.command_id);
    JSON_DELETE(cmditem);
    component = NULL;
    capability = NULL;
    command = NULL;
    memset(&cmd_data, 0, sizeof(cmd_data));

    // Given: string argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"setColor\",\"arguments\":[\"red\"],\"id\":"
        "\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(component, "main");
    assert_string_equal(capability, "switch");
    assert_string_equal(command, "setColor");
    assert_int_equal(cmd_data.num_args, 1);
    assert_int_equal(cmd_data.cmd_data[0].type, IOT_CAP_VAL_TYPE_STRING);
    assert_string_equal(cmd_data.cmd_data[0].string, "red");
    assert_string_equal(cmd_data.command_id, "test_id");

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    _iot_free_cmd_data(&cmd_data);
    if (cmd_data.command_id)
        iot_os_free(cmd_data.command_id);
    JSON_DELETE(cmditem);
    component = NULL;
    capability = NULL;
    command = NULL;
    memset(&cmd_data, 0, sizeof(cmd_data));

    // Given: json object argument
    cmditem = JSON_PARSE(
        "{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"setColor\",\"arguments\":[{\"hue\": 100, "
        "\"saturation\": 50}],\"id\":\"test_id\"}");

    // When
    ret = _iot_parse_cmd_data(cmditem, &component, &capability, &command, &cmd_data);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
    assert_string_equal(component, "main");
    assert_string_equal(capability, "switch");
    assert_string_equal(command, "setColor");
    assert_int_equal(cmd_data.num_args, 1);
    assert_int_equal(cmd_data.cmd_data[0].type, IOT_CAP_VAL_TYPE_JSON_OBJECT);
    assert_non_null(cmd_data.cmd_data[0].json_object);
    assert_string_equal(cmd_data.command_id, "test_id");

    // Teardown
    if (component)
        iot_os_free(component);
    if (capability)
        iot_os_free(capability);
    if (command)
        iot_os_free(command);
    _iot_free_cmd_data(&cmd_data);
    if (cmd_data.command_id)
        iot_os_free(cmd_data.command_id);
    JSON_DELETE(cmditem);
}

void TC_iot_free_val_null_parameter(void **state)
{
    UNUSED(*state);

    // When: val null
    _iot_free_val(NULL);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_val_string_type(void **state)
{
    iot_cap_val_t val;
    UNUSED(*state);

    // Given
    val.type = IOT_CAP_VAL_TYPE_STRING;
    val.string = iot_os_strdup("test_string");

    // When: free val
    _iot_free_val(&val);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_val_str_array_type(void **state)
{
    iot_cap_val_t val;
    UNUSED(*state);

    // Given
    val.type = IOT_CAP_VAL_TYPE_STR_ARRAY;
    val.str_num = 2;
    val.strings = iot_os_malloc(2 * sizeof(char *));
    val.strings[0] = iot_os_strdup("string1");
    val.strings[1] = iot_os_strdup("string2");

    // When: free val
    _iot_free_val(&val);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_val_json_object_type(void **state)
{
    iot_cap_val_t val;
    UNUSED(*state);

    // Given
    val.type = IOT_CAP_VAL_TYPE_JSON_OBJECT;
    val.json_object = iot_os_strdup("{\"key\":\"value\"}");

    // When: free val
    _iot_free_val(&val);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_unit_null_parameter(void **state)
{
    UNUSED(*state);

    // When: unit null
    _iot_free_unit(NULL);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_unit_string_type(void **state)
{
    iot_cap_unit_t unit;
    UNUSED(*state);

    // Given
    unit.type = IOT_CAP_UNIT_TYPE_STRING;
    unit.string = iot_os_strdup("test_unit");

    // When: free unit
    _iot_free_unit(&unit);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_cmd_data_null_parameter(void **state)
{
    UNUSED(*state);

    // When: cmd_data null
    _iot_free_cmd_data(NULL);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_cmd_data_success(void **state)
{
    iot_cap_cmd_data_t cmd_data;
    UNUSED(*state);

    // Given
    memset(&cmd_data, 0, sizeof(iot_cap_cmd_data_t));
    cmd_data.num_args = 1;
    cmd_data.args_str = iot_os_malloc(sizeof(char *));
    cmd_data.args_str[0] = iot_os_strdup("arg1");
    cmd_data.cmd_data = iot_os_malloc(sizeof(iot_cap_val_t));
    cmd_data.cmd_data[0].type = IOT_CAP_VAL_TYPE_STRING;
    cmd_data.cmd_data[0].string = iot_os_strdup("value1");

    // When: free cmd_data
    _iot_free_cmd_data(&cmd_data);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_evt_data_null_parameter(void **state)
{
    UNUSED(*state);

    // When: evt_data null
    _iot_free_evt_data(NULL);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_free_evt_data_success(void **state)
{
    iot_cap_evt_data_t evt_data;
    UNUSED(*state);

    // Given
    memset(&evt_data, 0, sizeof(iot_cap_evt_data_t));
    evt_data.evt_type = iot_os_strdup("test_event");
    evt_data.evt_value.type = IOT_CAP_VAL_TYPE_STRING;
    evt_data.evt_value.string = iot_os_strdup("test_value");
    evt_data.evt_unit.type = IOT_CAP_UNIT_TYPE_STRING;
    evt_data.evt_unit.string = iot_os_strdup("test_unit");
    evt_data.evt_value_data = iot_os_strdup("{\"key\":\"data\"}");
    evt_data.options.command_id = iot_os_strdup("test_cmd_id");
    evt_data.options.displayed = iot_os_malloc(sizeof(bool));
    *(evt_data.options.displayed) = true;

    // When: free evt_data
    _iot_free_evt_data(&evt_data);
    // Then: should not crash
    assert_true(1);
}

void TC_iot_notify_child_devices_cloud_connected_null_parameters(void **state)
{
    iot_error_t ret;
    UNUSED(*state);

    // When: context null
    ret = _iot_notify_child_devices_cloud_connected(NULL, NULL);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);
}

void TC_iot_notify_child_devices_cloud_connected_empty_array(void **state)
{
    iot_error_t ret;
    JSON_H *empty_array;
    struct iot_context *ctx;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    empty_array = JSON_CREATE_ARRAY();

    // When
    ret = _iot_notify_child_devices_cloud_connected(ctx, empty_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);

    // Teardown
    JSON_DELETE(empty_array);
    free(ctx);
}

void TC_iot_notify_child_devices_cloud_connected_invalid_child_device(void **state)
{
    iot_error_t ret;
    JSON_H *child_array;
    struct iot_context *ctx;
    JSON_H *child_item;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));
    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("invalid_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When
    ret = _iot_notify_child_devices_cloud_connected(ctx, child_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);

    // Teardown
    JSON_DELETE(child_array);
    free(ctx);
}

void TC_iot_notify_child_devices_cloud_connected_success(void **state)
{
    iot_error_t ret;
    JSON_H *child_array;
    struct iot_context *ctx;
    JSON_H *child_item;
    iot_child_device *child_dev;
    UNUSED(*state);

    // Given
    ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(ctx, 0, sizeof(struct iot_context));

    // Create a child device
    child_dev = (iot_child_device *)malloc(sizeof(iot_child_device));
    memset(child_dev, 0, sizeof(iot_child_device));
    strncpy(child_dev->deviceId, "test_device_id", IOT_REG_UUID_STR_LEN);
    child_dev->next = NULL;
    ctx->child_device_list = child_dev;

    child_array = JSON_CREATE_ARRAY();
    child_item = JSON_CREATE_STRING("test_device_id");
    JSON_ADD_ITEM_TO_ARRAY(child_array, child_item);

    // When
    ret = _iot_notify_child_devices_cloud_connected(ctx, child_array);
    // Then
    assert_int_equal(ret, IOT_ERROR_NONE);

    // Teardown
    JSON_DELETE(child_array);
    free(child_dev);
    free(ctx);
}

void TC_iot_parse_noti_data_invalid_json(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: invalid JSON data
    err = _iot_parse_noti_data(fake_ctx, (void *)"invalid json", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_no_event_field(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: JSON without event field
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"target\":\"test\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_null_event_type(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: JSON with null event type
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":null}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_unknown_event_type(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: JSON with unknown event type
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"unknown.event.type\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_expired_jwt_no_current_time(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: expired.jwt event without currentTime
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"expired.jwt\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_quota_reached_no_limit(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: quota.reached event without limit
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"quota.reached\",\"used\":5}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_quota_reached_no_used(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: quota.reached event without used
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"quota.reached\",\"limit\":10}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_rate_limit_no_count(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: rate.limit.reached event without count
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"rate.limit.reached\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_rate_limit_no_threshold(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: rate.limit.reached event without threshold
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"rate.limit.reached\",\"count\":5}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_rate_limit_no_remaining_time(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: rate.limit.reached event without remainingTime
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"rate.limit.reached\",\"count\":5,\"threshold\":10}",
                               &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_rate_limit_no_sequence_number(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: rate.limit.reached event without sequenceNumber
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"rate.limit.reached\",\"count\":5,\"threshold\":10,\"remainingTime\":300}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_preference_updated_no_values(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.preferences event without values
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.preferences\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_preference_updated_empty_values(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.preferences event with empty values
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.preferences\",\"values\":[]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_updated_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.updated event
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.updated\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);  // Expected to return IOT_ERROR_BAD_REQ

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_response(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without response
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_device_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without deviceId
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_metadata(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without metadata
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\"}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_mn_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without mnId
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{}}}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_serial_number(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without serialNumber
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{\"mnId\":\"test_mn_id\"}}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_dip(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without DIP
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\"}}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_dip_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without DIP id
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\"},\"deviceIntegrationProfileKey\":{}}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_no_dip_major_version(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event without DIP majorVersion
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\"},\"deviceIntegrationProfileKey\":{\"id\":\"test_dip_id\"}}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_created_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    iot_child_device *child_dev = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.created event with all required fields
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"secondary.device.created\",\"response\":{\"deviceId\":\"test_id\",\"metadata\":{\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\"},\"deviceIntegrationProfileKey\":{\"id\":\"test_dip_id\",\"majorVersion\":1,\"minorVersion\":0}}}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(notification.type, _IOT_NOTI_TYPE_CHILD_DEVICE_REGISTERED);
    assert_string_equal(notification.raw.child_device_registered.mnId, "test_mn_id");
    assert_string_equal(notification.raw.child_device_registered.serial_number, "test_serial");

    // Teardown
    child_dev = (iot_child_device *)notification.raw.child_device_registered.child_dev;
    // Properly clean up the allocated child device
    if (child_dev) {
        if (child_dev->mnId) {
            iot_os_free(child_dev->mnId);
        }
        if (child_dev->serial_number) {
            iot_os_free(child_dev->serial_number);
        }
        if (child_dev->mqtt_event_topic) {
            iot_os_free(child_dev->mqtt_event_topic);
        }
        iot_os_free(child_dev);
    }
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_child_devices(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without childDevices
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_device_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without deviceId in child info
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{}]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_mn_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without mnId in child info
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{\"id\":\"test_id\"}]}",
                               &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_serial_number(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without serialNumber in child info
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{\"id\":\"test_id\",\"mnId\":\"test_mn_id\"}]}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_dip(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without DIP in child info
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{\"id\":\"test_id\",\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\"}]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_dip_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without DIP id in child info
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{\"id\":\"test_id\",\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\",\"deviceIntegrationProfileKey\":{}}]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_device_get_no_dip_major_version(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: device.get event without DIP majorVersion in child info
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"device.get\",\"childDevices\":[{\"id\":\"test_id\",\"mnId\":\"test_mn_id\",\"serialNumber\":\"test_serial\",\"deviceIntegrationProfileKey\":{\"id\":\"test_dip_id\"}}]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_child_device_health_response_no_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: child.device.health.response event without success array
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"child.device.health.response\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    free(fake_ctx);
}

void TC_iot_parse_noti_data_child_device_health_response_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));

    // When: child.device.health.response event with success array
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"child.device.health.response\",\"success\":[\"device1\", \"device2\"]}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);  // The function returns IOT_ERROR_BAD_REQ for this case

    // Teardown
    free(fake_ctx);
}

#if defined(CONFIG_STDK_IOT_CORE_PUBLISH_RATE_LIMIT)
void TC_st_cap_send_attr_publish_rate_limit_blocked(void **state)
{
    int ret;
    struct iot_context *fake_ctx = NULL;
    iot_cap_evt_data_t *evt_data = NULL;
    IOT_EVENT *event;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));
    fake_ctx->curr_state = IOT_STATE_CLOUD_CONNECTED;

    cap_handle.ctx = fake_ctx;
    cap_handle.component = "main";
    cap_handle.capability = "switch";
    cap_handle.child_dev = NULL;

    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "on";
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "switch", &value, NULL, NULL);

    // When: fill the circular buffer with timestamps within the window
    // Set all slots to current time to simulate rate limit exceeded
    {
        time_t now;
        iot_bsp_system_get_time_in_sec(&now);
        for (int i = 0; i < IOT_PUBLISH_RATE_LIMIT_COUNT; i++) {
            fake_ctx->publish_timestamps[i] = now;
        }
        fake_ctx->publish_timestamp_offset = IOT_PUBLISH_RATE_LIMIT_COUNT - 1;
    }

    // Then: st_cap_send_attr should return IOT_ERROR_MQTT_RATE_LIMIT
    ret = st_cap_send_attr(&event, 1);
    assert_int_equal(ret, IOT_ERROR_MQTT_RATE_LIMIT);

    // Teardown
    st_cap_free_attr(event);
    free(fake_ctx);
}

void TC_st_cap_send_attr_publish_rate_limit_allowed(void **state)
{
    int ret;
    struct iot_context *fake_ctx = NULL;
    IOT_EVENT *event;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));
    fake_ctx->curr_state = IOT_STATE_CLOUD_CONNECTED;

    cap_handle.ctx = fake_ctx;
    cap_handle.component = "main";
    cap_handle.capability = "switch";
    cap_handle.child_dev = NULL;

    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "on";
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "switch", &value, NULL, NULL);

    // When: timestamps are old (outside the window), rate limit should not block
    {
        time_t old_time;
        iot_bsp_system_get_time_in_sec(&old_time);
        old_time -= IOT_PUBLISH_RATE_LIMIT_WINDOW_SEC + 10;
        for (int i = 0; i < IOT_PUBLISH_RATE_LIMIT_COUNT; i++) {
            fake_ctx->publish_timestamps[i] = old_time;
        }
        fake_ctx->publish_timestamp_offset = IOT_PUBLISH_RATE_LIMIT_COUNT - 1;
    }

    // Then: st_cap_send_attr should NOT return rate limit error
    // (it may fail for other reasons like no mqtt client, but not rate limit)
    ret = st_cap_send_attr(&event, 1);
    assert_int_not_equal(ret, IOT_ERROR_MQTT_RATE_LIMIT);

    // Teardown
    st_cap_free_attr(event);
    free(fake_ctx);
}

void TC_st_cap_send_attr_publish_rate_limit_empty_buffer(void **state)
{
    int ret;
    struct iot_context *fake_ctx = NULL;
    IOT_EVENT *event;
    iot_cap_val_t value;
    struct iot_cap_handle cap_handle;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));
    fake_ctx->curr_state = IOT_STATE_CLOUD_CONNECTED;

    cap_handle.ctx = fake_ctx;
    cap_handle.component = "main";
    cap_handle.capability = "switch";
    cap_handle.child_dev = NULL;

    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "on";
    event = st_cap_create_attr((IOT_CAP_HANDLE *)&cap_handle, "switch", &value, NULL, NULL);

    // When: buffer is empty (all zeros), rate limit should not block
    // publish_timestamps are all 0, publish_timestamp_offset is 0

    // Then: st_cap_send_attr should NOT return rate limit error
    ret = st_cap_send_attr(&event, 1);
    assert_int_not_equal(ret, IOT_ERROR_MQTT_RATE_LIMIT);

    // Teardown
    st_cap_free_attr(event);
    free(fake_ctx);
}

void TC_st_cap_send_attr_v2_publish_rate_limit_blocked(void **state)
{
    int ret;
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(fake_ctx, 0, sizeof(struct iot_context));
    fake_ctx->curr_state = IOT_STATE_CLOUD_CONNECTED;

    // When: fill the circular buffer with timestamps within the window
    {
        time_t now;
        iot_bsp_system_get_time_in_sec(&now);
        for (int i = 0; i < IOT_PUBLISH_RATE_LIMIT_COUNT; i++) {
            fake_ctx->publish_timestamps[i] = now;
        }
        fake_ctx->publish_timestamp_offset = IOT_PUBLISH_RATE_LIMIT_COUNT - 1;
    }

    // Then: st_cap_send_attr_v2 should return IOT_ERROR_MQTT_RATE_LIMIT
    ret = st_cap_send_attr_v2((IOT_CTX *)fake_ctx, NULL, 0);
    assert_int_equal(ret, IOT_ERROR_MQTT_RATE_LIMIT);

    // Teardown
    free(fake_ctx);
}
#endif

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE)
/* simulates the publish acknowledgement that the MQTT layer would deliver */
extern void _iot_cap_mark_chunk_synced(struct iot_context *ctx, int chunk_id);

static struct iot_context *_attr_cache_tc_setup(IOT_CAP_HANDLE **out_cap_handle)
{
    struct iot_context *ic;

    ic = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(ic);
    memset(ic, 0, sizeof(struct iot_context));
    ic->curr_state = IOT_STATE_CLOUD_CONNECTED;
    ic->iot_events = iot_os_eventgroup_create();
    ic->mqtt_event_topic = "TCtest";
    st_mqtt_create(&ic->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);

    *out_cap_handle = st_cap_handle_init((IOT_CTX *)ic, "main", "testCap", test_cap_init_callback, NULL);
    assert_non_null(*out_cap_handle);
    return ic;
}

static void _attr_cache_tc_teardown(struct iot_context *ic, IOT_CAP_HANDLE *cap_handle)
{
    struct iot_cap_handle *handle = (struct iot_cap_handle *)cap_handle;
    iot_cap_last_val_t *node;
    iot_cap_handle_list_t *list;

    node = handle->last_val_list;
    while (node != NULL) {
        iot_cap_last_val_t *next = node->next;
        if (node->attr_type) {
            iot_os_free(node->attr_type);
        }
        _iot_free_val(&node->value);
        iot_os_free(node);
        node = next;
    }
    if (handle->capability) {
        iot_os_free((void *)handle->capability);
    }
    if (handle->component) {
        iot_os_free((void *)handle->component);
    }
    st_mqtt_destroy(ic->evt_mqttcli);
    list = ic->cap_handle_list;
    while (list != NULL) {
        iot_cap_handle_list_t *next = list->next;
        iot_os_free(list);
        list = next;
    }
    iot_os_free(cap_handle);
    iot_os_eventgroup_delete(ic->iot_events);
    free(ic);
}

/* A value identical to the one already synced is not published again. */
void TC_st_cap_send_attr_dedup_skip_duplicate(void **state)
{
    struct iot_context *ic;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event;
    int ret;
    UNUSED(state);

    // Given: a value has been sent and acknowledged (SYNCED)
    ic = _attr_cache_tc_setup(&cap_handle);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);
    assert_true(ret > 0);
    _iot_cap_mark_chunk_synced(ic, ret);
    st_cap_free_attr(event);

    // When: the same value is sent again
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);

    // Then: it is de-duplicated and 0 (not an error) is returned
    assert_int_equal(ret, 0);

    // Teardown
    st_cap_free_attr(event);
    _attr_cache_tc_teardown(ic, cap_handle);
}

/* A changed value is published even if the attribute was previously synced. */
void TC_st_cap_send_attr_dedup_send_changed_value(void **state)
{
    struct iot_context *ic;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event;
    int ret;
    UNUSED(state);

    // Given: "on" has been sent and acknowledged
    ic = _attr_cache_tc_setup(&cap_handle);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);
    assert_true(ret > 0);
    _iot_cap_mark_chunk_synced(ic, ret);
    st_cap_free_attr(event);

    // When: a different value is sent
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "off", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);

    // Then: it is published (positive sequence number)
    assert_true(ret > 0);

    // Teardown
    st_cap_free_attr(event);
    _attr_cache_tc_teardown(ic, cap_handle);
}

/* While a value is still in flight (UPDATING, not yet acknowledged), an identical
 * value is not de-duplicated and is published again. */
void TC_st_cap_send_attr_dedup_updating_not_skipped(void **state)
{
    struct iot_context *ic;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event;
    int ret;
    UNUSED(state);

    // Given: a value has been sent but NOT acknowledged (stays UPDATING)
    ic = _attr_cache_tc_setup(&cap_handle);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);
    assert_true(ret > 0);
    st_cap_free_attr(event);

    // When: the same value is sent again before the acknowledgement
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);

    // Then: it is published again (not de-duplicated)
    assert_true(ret > 0);

    // Teardown
    st_cap_free_attr(event);
    _attr_cache_tc_teardown(ic, cap_handle);
}

/* The stateChange option forces publishing even for a duplicate value. */
void TC_st_cap_send_attr_dedup_state_change_forced(void **state)
{
    struct iot_context *ic;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *event;
    iot_cap_val_t value;
    iot_cap_attr_option_t opt = {0};
    int ret;
    UNUSED(state);

    // Given: "pushed" has been sent and acknowledged
    ic = _attr_cache_tc_setup(&cap_handle);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "button", "pushed", NULL, NULL, event);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);
    assert_true(ret > 0);
    _iot_cap_mark_chunk_synced(ic, ret);
    st_cap_free_attr(event);

    // When: the same value is sent again, but with stateChange forced
    value.type = IOT_CAP_VAL_TYPE_STRING;
    value.string = "pushed";
    opt.state_change = true;
    event = st_cap_create_attr_with_option(cap_handle, "button", &value, NULL, NULL, &opt);
    assert_non_null(event);
    ret = st_cap_send_attr(&event, 1);

    // Then: it is published despite being a duplicate
    assert_true(ret > 0);

    // Teardown
    st_cap_free_attr(event);
    _attr_cache_tc_teardown(ic, cap_handle);
}

/* In an array, only the attributes carrying a new value are published; when every
 * attribute is a duplicate, nothing is published and 0 is returned. */
void TC_st_cap_send_attr_dedup_array_partial(void **state)
{
    struct iot_context *ic;
    IOT_CAP_HANDLE *cap_handle;
    IOT_EVENT *events[2];
    int ret;
    UNUSED(state);

    // Given: two attributes have been sent and acknowledged
    ic = _attr_cache_tc_setup(&cap_handle);
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, events[0]);
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "level", 10, NULL, NULL, events[1]);
    assert_non_null(events[0]);
    assert_non_null(events[1]);
    ret = st_cap_send_attr(events, 2);
    assert_true(ret > 0);
    _iot_cap_mark_chunk_synced(ic, ret);
    st_cap_free_attr(events[0]);
    st_cap_free_attr(events[1]);

    // When: one attribute is unchanged and the other carries a new value
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, events[0]);
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "level", 20, NULL, NULL, events[1]);
    ret = st_cap_send_attr(events, 2);

    // Then: the new one is published (positive sequence number)
    assert_true(ret > 0);
    _iot_cap_mark_chunk_synced(ic, ret);
    st_cap_free_attr(events[0]);
    st_cap_free_attr(events[1]);

    // When: both attributes are now duplicates of the synced values
    ST_CAP_CREATE_ATTR_STRING(cap_handle, "switch", "on", NULL, NULL, events[0]);
    ST_CAP_CREATE_ATTR_NUMBER(cap_handle, "level", 20, NULL, NULL, events[1]);
    ret = st_cap_send_attr(events, 2);

    // Then: nothing is published and 0 is returned
    assert_int_equal(ret, 0);

    // Teardown
    st_cap_free_attr(events[0]);
    st_cap_free_attr(events[1]);
    _attr_cache_tc_teardown(ic, cap_handle);
}
#endif /* CONFIG_STDK_IOT_CORE_SUPPORT_ATTR_CACHE */
void TC_iot_parse_noti_data_secondary_device_created_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    iot_child_device *child_dev = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: secondary.device.created event with full response payload
    err = _iot_parse_noti_data(
        fake_ctx,
        (void *)"{\"event\":\"secondary.device.created\",\"response\":{\"deviceId\":\"" NOTI_TEST_UUID
                "\",\"metadata\":{\"mnId\":\"mn1\",\"serialNumber\":\"sn1\"},"
                "\"deviceIntegrationProfileKey\":{\"id\":\"" NOTI_TEST_UUID
                "\",\"majorVersion\":1,\"minorVersion\":2}}}",
        &notification);
    // Then: returns success and links a new child device
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(notification.type, _IOT_NOTI_TYPE_CHILD_DEVICE_REGISTERED);
    assert_non_null(fake_ctx->child_device_list);

    // Teardown
    child_dev = fake_ctx->child_device_list;
    iot_os_free(child_dev->mnId);
    iot_os_free(child_dev->serial_number);
    iot_os_free(child_dev->mqtt_event_topic);
    iot_os_free(child_dev);
    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_device_created_no_response(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: secondary.device.created event without response
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"secondary.device.created\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_device_created_no_device_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: response object lacks deviceId
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"secondary.device.created\",\"response\":{}}",
                               &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_device_created_no_metadata(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: response has deviceId but no metadata
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"secondary.device.created\",\"response\":{\"deviceId\":\"" NOTI_TEST_UUID "\"}}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_device_created_no_serial(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: metadata lacks serialNumber
    err = _iot_parse_noti_data(
        fake_ctx,
        (void *)"{\"event\":\"secondary.device.created\",\"response\":{\"deviceId\":\"" NOTI_TEST_UUID
                "\",\"metadata\":{\"mnId\":\"mn1\"}}}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_device_created_no_dip(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    iot_child_device *child_dev;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: response lacks deviceIntegrationProfileKey
    err = _iot_parse_noti_data(
        fake_ctx,
        (void *)"{\"event\":\"secondary.device.created\",\"response\":{\"deviceId\":\"" NOTI_TEST_UUID
                "\",\"metadata\":{\"mnId\":\"mn1\",\"serialNumber\":\"sn1\"}}}",
        &notification);
    // Then: error returned, but the child device entry was already linked into ctx
    assert_int_equal(err, IOT_ERROR_BAD_REQ);
    assert_non_null(fake_ctx->child_device_list);

    // Teardown
    child_dev = fake_ctx->child_device_list;
    iot_os_free(child_dev->mnId);
    iot_os_free(child_dev->serial_number);
    iot_os_free(child_dev->mqtt_event_topic);
    iot_os_free(child_dev);
    free(fake_ctx);
}

void TC_iot_parse_noti_data_devices_get_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    iot_child_device *child_dev = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    fake_ctx->curr_state = IOT_STATE_PROV_DONE; /* iot_update_child_devices_health early-returns */

    // When: devices.get with one valid child entry
    err = _iot_parse_noti_data(fake_ctx,
                               (void *)"{\"event\":\"devices.get\",\"childDevices\":[{\"id\":\"" NOTI_TEST_UUID
                                       "\",\"mnId\":\"mn1\",\"serialNumber\":\"sn1\","
                                       "\"deviceIntegrationProfileKey\":{\"id\":\"" NOTI_TEST_UUID
                                       "\",\"majorVersion\":1}}]}",
                               &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(notification.type, _IOT_NOTI_TYPE_CHILD_DEVICE_SYNCED);
    assert_non_null(fake_ctx->child_device_list);

    // Teardown
    child_dev = fake_ctx->child_device_list;
    iot_os_free(child_dev->mnId);
    iot_os_free(child_dev->serial_number);
    iot_os_free(child_dev->mqtt_event_topic);
    iot_os_free(child_dev);
    free(fake_ctx);
}

void TC_iot_parse_noti_data_devices_get_no_child_devices(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: devices.get without childDevices array
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"devices.get\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_devices_get_no_id(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: devices.get with item missing the id field
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"devices.get\",\"childDevices\":[{}]}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_devices_get_missing_dip(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    iot_child_device *child_dev;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: childDevices entry lacks deviceIntegrationProfileKey
    err = _iot_parse_noti_data(fake_ctx,
                               (void *)"{\"event\":\"devices.get\",\"childDevices\":[{\"id\":\"" NOTI_TEST_UUID
                                       "\",\"mnId\":\"mn1\",\"serialNumber\":\"sn1\"}]}",
                               &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    // Teardown
    child_dev = fake_ctx->child_device_list;
    if (child_dev) {
        iot_os_free(child_dev->mnId);
        iot_os_free(child_dev->serial_number);
        iot_os_free(child_dev->mqtt_event_topic);
        iot_os_free(child_dev);
    }
    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_health_response_no_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: secondary.health.response without success array
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"secondary.health.response\"}", &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_secondary_health_response_with_success(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: secondary.health.response with empty success array exercises both helper calls
    err = _iot_parse_noti_data(fake_ctx, (void *)"{\"event\":\"secondary.health.response\",\"success\":[]}",
                               &notification);
    // Then: this branch always returns BAD_REQ at the end
    assert_int_equal(err, IOT_ERROR_BAD_REQ);

    free(fake_ctx);
}

void TC_iot_parse_noti_data_preference_updated_unknown_type(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: preferenceType is not one of string/number/boolean/integer
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"device.preferences\",\"values\":[{\"preferenceType\":\"weird\",\"value\":1}]}",
        &notification);
    // Then: still parses successfully but marks the entry as UNKNOWN
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(notification.raw.preferences.preferences_data[0].preference_data.type, IOT_CAP_VAL_TYPE_UNKNOWN);

    // Teardown
    iot_os_free(notification.raw.preferences.preferences_data);
    free(fake_ctx);
}

void TC_iot_parse_noti_data_preference_updated_null_value(void **state)
{
    iot_error_t err;
    iot_noti_data_t notification = {0};
    struct iot_context *fake_ctx = NULL;
    UNUSED(*state);

    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: preference value is missing entirely (null branch)
    err = _iot_parse_noti_data(
        fake_ctx, (void *)"{\"event\":\"device.preferences\",\"values\":[{\"preferenceType\":\"string\"}]}",
        &notification);
    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(notification.raw.preferences.preferences_data[0].preference_data.type, IOT_CAP_VAL_TYPE_NULL);

    // Teardown
    iot_os_free(notification.raw.preferences.preferences_data);
    free(fake_ctx);
}

void TC_iot_noti_sub_cb_null_args(void **state)
{
    UNUSED(*state);
    /* Both null and either-null return early without crashing */
    iot_noti_sub_cb(NULL, NULL);
    iot_noti_sub_cb(NULL, "{}");
    /* with a ctx but a null payload */
    {
        struct iot_context *fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));
        iot_noti_sub_cb(fake_ctx, NULL);
        free(fake_ctx);
    }
}

void TC_iot_noti_sub_cb_unparseable_payload(void **state)
{
    struct iot_context *fake_ctx;
    UNUSED(*state);

    // Given
    fake_ctx = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    // When: invalid json -> _iot_parse_noti_data fails -> early return without command_send
    iot_noti_sub_cb(fake_ctx, "not json");
    // Then: nothing crashes

    // Teardown
    free(fake_ctx);
}

void TC_iot_cap_sub_cb_null_args(void **state)
{
    UNUSED(*state);
    iot_cap_sub_cb(NULL, NULL);
    iot_cap_sub_cb(NULL, "{}");
}

void TC_iot_cap_sub_cb_invalid_json(void **state)
{
    iot_cap_handle_list_t list = {0};
    UNUSED(*state);

    // When: payload is not valid json -> goes to "out:" via JSON_PARSE failure
    iot_cap_sub_cb(&list, "not json");
}

void TC_iot_cap_sub_cb_no_commands(void **state)
{
    iot_cap_handle_list_t list = {0};
    UNUSED(*state);

    // When: no commands array
    iot_cap_sub_cb(&list, "{}");
}

void TC_iot_cap_sub_cb_empty_commands(void **state)
{
    iot_cap_handle_list_t list = {0};
    UNUSED(*state);

    // When: commands array is empty
    iot_cap_sub_cb(&list, "{\"commands\":[]}");
}

void TC_iot_cap_sub_cb_command_unmatched_handle(void **state)
{
    iot_cap_handle_list_t list = {0};
    UNUSED(*state);

    // When: command targets an unknown component+capability+command
    iot_cap_sub_cb(
        &list,
        "{\"commands\":[{\"component\":\"main\",\"capability\":\"switch\",\"command\":\"on\",\"arguments\":[]}]}");
    // Then: _iot_process_cmd takes the "Cannot find handle" branch; no crash
}

void TC_iot_cap_commands_cb_null_payload(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    iot_cap_commands_cb(&fake_ctx, NULL);
}

void TC_iot_cap_commands_cb_invalid_json(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    iot_cap_commands_cb(&fake_ctx, "not json");
}

void TC_iot_cap_commands_cb_no_commands(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    iot_cap_commands_cb(&fake_ctx, "{}");
}

void TC_iot_cap_commands_cb_empty_commands(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    iot_cap_commands_cb(&fake_ctx, "{\"commands\":[]}");
}

void TC_iot_cap_commands_cb_missing_fields(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    /* parse_cmd_data_v2 returns BAD_REQ when any of component/capability/command/arguments/id is missing */
    iot_cap_commands_cb(&fake_ctx, "{\"commands\":[{\"component\":\"main\"}]}");
}

void TC_iot_cap_commands_cb_full_payload(void **state)
{
    struct iot_context fake_ctx = {0};
    UNUSED(*state);

    /* exercises every argument-type branch in _iot_parse_cmd_data_v2 (bool, number, string, object, array) */
    iot_cap_commands_cb(&fake_ctx,
                        "{\"commands\":[{\"id\":\"cmd1\",\"component\":\"main\",\"capability\":\"switch\","
                        "\"command\":\"setValue\","
                        "\"arguments\":[true,1.5,\"hello\",{\"k\":1},[1,2,3]]}]}");
}

void TC_st_cap_send_attr_v2_custom_component_no_name(void **state)
{
    int ret;
    IOT_CTX *context;
    struct iot_context *internal_context;
    st_attr_data *attr[1];
    UNUSED(*state);

    // Given
    internal_context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);

    attr[0] = (st_attr_data *)calloc(1, sizeof(st_attr_data));
    attr[0]->component_type = ST_COMPONENT_CUSTOM; /* custom component without name => err_make_evt_item */
    attr[0]->attr_type = ST_ATTR_CUSTOM;

    // When
    ret = st_cap_send_attr_v2(context, attr, 1);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);

    // Teardown
    free(attr[0]);
    st_mqtt_destroy(internal_context->evt_mqttcli);
    free(internal_context);
}

void TC_st_cap_send_attr_v2_custom_component_with_name(void **state)
{
    int sequence_number;
    IOT_CTX *context;
    struct iot_context *internal_context;
    st_attr_data *attr[1];
    UNUSED(*state);

    // Given
    internal_context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    internal_context->mqtt_event_topic = "TCtest";
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);

    attr[0] = (st_attr_data *)calloc(1, sizeof(st_attr_data));
    attr[0]->component_type = ST_COMPONENT_CUSTOM;
    attr[0]->custom_component_name = strdup("customMain");
    attr[0]->attr_type = ST_ATTR_CUSTOM;
    attr[0]->custom_attr_name = strdup("attr");
    attr[0]->custom_cap_name = strdup("cap");
    attr[0]->value.data_type = ST_DATA_TYPE_NULL; /* exercises the NULL value-type branch */
    attr[0]->state_change = false;                /* skips stateChange */
    attr[0]->related_command_id = strdup("cmd-id-1");

    // When
    sequence_number = st_cap_send_attr_v2(context, attr, 1);
    // Then
    assert_true(sequence_number > 0);

    // Teardown
    free(attr[0]->custom_component_name);
    free(attr[0]->custom_attr_name);
    free(attr[0]->custom_cap_name);
    free(attr[0]->related_command_id);
    free(attr[0]);
    st_mqtt_destroy(internal_context->evt_mqttcli);
    free(internal_context);
}

void TC_st_cap_send_attr_v2_custom_attribute_missing_names(void **state)
{
    int ret;
    IOT_CTX *context;
    struct iot_context *internal_context;
    st_attr_data *attr[1];
    UNUSED(*state);

    // Given: attr_type CUSTOM but missing capability/attribute names
    internal_context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context = (IOT_CTX *)internal_context;
    internal_context->curr_state = IOT_STATE_CLOUD_CONNECTED;
    st_mqtt_create(&internal_context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);

    attr[0] = (st_attr_data *)calloc(1, sizeof(st_attr_data));
    attr[0]->component_type = ST_COMPONENT_DEFULAT;
    attr[0]->attr_type = ST_ATTR_CUSTOM; /* but no custom_cap_name/custom_attr_name */

    // When
    ret = st_cap_send_attr_v2(context, attr, 1);
    // Then
    assert_int_equal(ret, IOT_ERROR_BAD_REQ);

    // Teardown
    free(attr[0]);
    st_mqtt_destroy(internal_context->evt_mqttcli);
    free(internal_context);
}
